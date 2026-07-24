package authz

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/manchtools/power-manage/sdk/validate"
)

const (
	maxRoleNameBytes = 64
	maxScopeIDs      = 1000
)

var (
	// ErrInvalidRole identifies role data that cannot enter authorization state.
	ErrInvalidRole = errors.New("authz: invalid role")
	// ErrInvalidGrant identifies grant data that cannot enter authorization state.
	ErrInvalidGrant = errors.New("authz: invalid grant")
)

// PrincipalType is the actor class reached by a grant.
type PrincipalType string

const (
	PrincipalUser      PrincipalType = "user"
	PrincipalUserGroup PrincipalType = "user-group"
)

// ScopeKind selects the resource reach contributed by one grant.
type ScopeKind string

const (
	ScopeGlobal       ScopeKind = "global"
	ScopeDeviceGroups ScopeKind = "device-groups"
	ScopeUserGroups   ScopeKind = "user-groups"
	ScopeSelf         ScopeKind = "self"
)

// Scope is one normalized grant scope.
type Scope struct {
	Kind ScopeKind
	IDs  []string
}

// Role is one named permission set.
type Role struct {
	ID          string
	Name        string
	Permissions []Permission
}

// Grant is one resolved (principal, role, scope) tuple.
type Grant struct {
	ID            string
	PrincipalType PrincipalType
	PrincipalID   string
	RoleID        string
	Permissions   []Permission
	Scope         Scope
}

// GrantAccess makes partial activation of a scoped role visible.
type GrantAccess struct {
	GrantID             string
	ActivePermissions   []Permission
	StrippedPermissions []Permission
}

// Reach is the union of scopes that contribute one permission.
type Reach struct {
	Global         bool
	DeviceGroupIDs []string
	UserGroupIDs   []string
	Self           bool
}

// EffectiveAccess is deterministic per-grant activation and per-permission reach.
type EffectiveAccess struct {
	Grants      []GrantAccess
	Permissions map[Permission]Reach
}

// NormalizeRole validates and canonicalizes a role without mutating the input.
func NormalizeRole(role Role) (Role, error) {
	id, err := canonicalULID(role.ID)
	if err != nil {
		return Role{}, fmt.Errorf("%w: ID: %v", ErrInvalidRole, err)
	}
	if !validRoleName(role.Name) {
		return Role{}, fmt.Errorf("%w: name", ErrInvalidRole)
	}
	permissions, err := normalizePermissions(role.Permissions)
	if err != nil {
		return Role{}, fmt.Errorf("%w: %v", ErrInvalidRole, err)
	}
	return Role{ID: id, Name: role.Name, Permissions: permissions}, nil
}

// NormalizePrincipal validates one grant principal and canonicalizes its ID.
func NormalizePrincipal(kind PrincipalType, id string) (string, error) {
	switch kind {
	case PrincipalUser, PrincipalUserGroup:
	default:
		return "", fmt.Errorf("%w: principal type %q", ErrInvalidGrant, kind)
	}
	id, err := canonicalULID(id)
	if err != nil {
		return "", fmt.Errorf("%w: principal ID: %v", ErrInvalidGrant, err)
	}
	return id, nil
}

// NormalizeScope validates one grant scope and canonicalizes its IDs.
func NormalizeScope(scope Scope) (Scope, error) {
	switch scope.Kind {
	case ScopeGlobal, ScopeSelf:
		if len(scope.IDs) != 0 {
			return Scope{}, fmt.Errorf("%w: %s scope carries IDs", ErrInvalidGrant, scope.Kind)
		}
		return Scope{Kind: scope.Kind, IDs: []string{}}, nil
	case ScopeDeviceGroups, ScopeUserGroups:
		if len(scope.IDs) == 0 || len(scope.IDs) > maxScopeIDs {
			return Scope{}, fmt.Errorf(
				"%w: %s scope must carry 1..%d IDs",
				ErrInvalidGrant,
				scope.Kind,
				maxScopeIDs,
			)
		}
	default:
		return Scope{}, fmt.Errorf("%w: scope kind %q", ErrInvalidGrant, scope.Kind)
	}

	ids := make([]string, len(scope.IDs))
	for index, id := range scope.IDs {
		canonical, err := canonicalULID(id)
		if err != nil {
			return Scope{}, fmt.Errorf("%w: scope ID: %v", ErrInvalidGrant, err)
		}
		ids[index] = canonical
	}
	slices.Sort(ids)
	for index := 1; index < len(ids); index++ {
		if ids[index] == ids[index-1] {
			return Scope{}, fmt.Errorf("%w: duplicate scope ID", ErrInvalidGrant)
		}
	}
	return Scope{Kind: scope.Kind, IDs: ids}, nil
}

// NormalizeGrant validates and canonicalizes persisted grant and role data.
func NormalizeGrant(grant Grant) (Grant, error) {
	id, err := canonicalULID(grant.ID)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: ID: %v", ErrInvalidGrant, err)
	}
	principalID, err := NormalizePrincipal(grant.PrincipalType, grant.PrincipalID)
	if err != nil {
		return Grant{}, err
	}
	roleID, err := canonicalULID(grant.RoleID)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: role ID: %v", ErrInvalidGrant, err)
	}
	permissions, err := normalizePermissions(grant.Permissions)
	if err != nil {
		return Grant{}, fmt.Errorf("%w: %v", ErrInvalidGrant, err)
	}
	scope, err := NormalizeScope(grant.Scope)
	if err != nil {
		return Grant{}, err
	}
	return Grant{
		ID:            id,
		PrincipalType: grant.PrincipalType,
		PrincipalID:   principalID,
		RoleID:        roleID,
		Permissions:   permissions,
		Scope:         scope,
	}, nil
}

// Resolve composes additive grants into deterministic effective access.
func Resolve(grants []Grant) (EffectiveAccess, error) {
	normalized := make([]Grant, len(grants))
	for index, grant := range grants {
		value, err := NormalizeGrant(grant)
		if err != nil {
			return EffectiveAccess{}, err
		}
		normalized[index] = value
	}
	slices.SortFunc(normalized, func(left, right Grant) int {
		return strings.Compare(left.ID, right.ID)
	})

	effective := EffectiveAccess{
		Grants:      make([]GrantAccess, 0, len(normalized)),
		Permissions: make(map[Permission]Reach),
	}
	for _, grant := range normalized {
		access := GrantAccess{GrantID: grant.ID}
		for _, permission := range grant.Permissions {
			entry, _ := Lookup(permission)
			if grant.Scope.Kind != ScopeGlobal && entry.Class == GlobalOnly {
				access.StrippedPermissions = append(access.StrippedPermissions, permission)
				continue
			}
			access.ActivePermissions = append(access.ActivePermissions, permission)
			reach := effective.Permissions[permission]
			switch grant.Scope.Kind {
			case ScopeGlobal:
				reach = Reach{Global: true}
			case ScopeDeviceGroups:
				if !reach.Global {
					reach.DeviceGroupIDs = unionStrings(reach.DeviceGroupIDs, grant.Scope.IDs)
				}
			case ScopeUserGroups:
				if !reach.Global {
					reach.UserGroupIDs = unionStrings(reach.UserGroupIDs, grant.Scope.IDs)
				}
			case ScopeSelf:
				if !reach.Global {
					reach.Self = true
				}
			}
			effective.Permissions[permission] = reach
		}
		effective.Grants = append(effective.Grants, access)
	}
	return effective, nil
}

func normalizePermissions(permissions []Permission) ([]Permission, error) {
	if len(permissions) == 0 {
		return nil, errors.New("permission set is empty")
	}
	normalized := slices.Clone(permissions)
	slices.Sort(normalized)
	for index, permission := range normalized {
		if _, ok := Lookup(permission); !ok {
			return nil, fmt.Errorf("unknown permission %q", permission)
		}
		if index > 0 && permission == normalized[index-1] {
			return nil, fmt.Errorf("duplicate permission %q", permission)
		}
	}
	return normalized, nil
}

func canonicalULID(value string) (string, error) {
	if err := validate.ULIDPathID(value); err != nil {
		return "", err
	}
	return strings.ToUpper(value), nil
}

func validRoleName(name string) bool {
	if name == "" || name != strings.TrimSpace(name) || len(name) > maxRoleNameBytes ||
		name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, character := range []byte(name[1:]) {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func unionStrings(existing, additions []string) []string {
	values := append(slices.Clone(existing), additions...)
	slices.Sort(values)
	return slices.Compact(values)
}
