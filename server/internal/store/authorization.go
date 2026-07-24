package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	authorizationRoleStreamType   = "authorization-role"
	authorizationGrantStreamType  = "authorization-grant"
	authorizationRoleCreatedType  = "AuthorizationRoleCreated"
	authorizationGrantCreatedType = "AuthorizationGrantCreated"
	authorizationPayloadVersion   = 1
	AuthorizationRebuildTarget    = "authorization"
)

var (
	// ErrUserDisabled identifies an account that must contribute no authorization.
	ErrUserDisabled                  = errors.New("store: user is disabled")
	errAuthorizationRoleMissing      = errors.New("store: authorization role is missing")
	errAuthorizationPrincipalMissing = errors.New(
		"store: authorization principal is missing",
	)
)

type authorizationRoleCreatedPayload struct {
	Name        string             `json:"name"`
	Permissions []authz.Permission `json:"permissions"`
}

type authorizationGrantCreatedPayload struct {
	PrincipalType authz.PrincipalType `json:"principal_type"`
	PrincipalID   string              `json:"principal_id"`
	RoleID        string              `json:"role_id"`
	ScopeKind     authz.ScopeKind     `json:"scope_kind"`
	ScopeIDs      []string            `json:"scope_ids"`
}

// AuthorizationRoleCreatedEvent records one immutable named permission set.
func AuthorizationRoleCreatedEvent(
	roleID string,
	name string,
	permissions []authz.Permission,
) (Event, error) {
	role, err := authz.NormalizeRole(authz.Role{
		ID:          roleID,
		Name:        name,
		Permissions: permissions,
	})
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(authorizationRoleCreatedPayload{
		Name:        role.Name,
		Permissions: role.Permissions,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode authorization role creation: %w", err)
	}
	return Event{
		StreamType:     authorizationRoleStreamType,
		StreamID:       role.ID,
		EventType:      authorizationRoleCreatedType,
		PayloadVersion: authorizationPayloadVersion,
		Payload:        payload,
	}, nil
}

// AuthorizationGrantCreatedEvent records one immutable principal-role-scope tuple.
func AuthorizationGrantCreatedEvent(
	grantID string,
	principalType authz.PrincipalType,
	principalID string,
	roleID string,
	scope authz.Scope,
) (Event, error) {
	grantID, err := canonicalAuthorizationID(grantID)
	if err != nil {
		return Event{}, fmt.Errorf("%w: ID: %v", authz.ErrInvalidGrant, err)
	}
	principalID, err = authz.NormalizePrincipal(principalType, principalID)
	if err != nil {
		return Event{}, err
	}
	roleID, err = canonicalAuthorizationID(roleID)
	if err != nil {
		return Event{}, fmt.Errorf("%w: role ID: %v", authz.ErrInvalidGrant, err)
	}
	scope, err = authz.NormalizeScope(scope)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(authorizationGrantCreatedPayload{
		PrincipalType: principalType,
		PrincipalID:   principalID,
		RoleID:        roleID,
		ScopeKind:     scope.Kind,
		ScopeIDs:      scope.IDs,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode authorization grant creation: %w", err)
	}
	return Event{
		StreamType:     authorizationGrantStreamType,
		StreamID:       grantID,
		EventType:      authorizationGrantCreatedType,
		PayloadVersion: authorizationPayloadVersion,
		Payload:        payload,
	}, nil
}

// ResolveEffectiveAccess loads all direct and group-inherited grants for an enabled user.
func (s *Store) ResolveEffectiveAccess(
	ctx context.Context,
	userID string,
) (authz.EffectiveAccess, error) {
	if s == nil || s.pool == nil {
		return authz.EffectiveAccess{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return authz.EffectiveAccess{}, errors.New("store: nil authorization context")
	}
	user, err := s.UserByID(ctx, userID)
	if err != nil {
		return authz.EffectiveAccess{}, err
	}
	if user.Disabled {
		return authz.EffectiveAccess{}, ErrUserDisabled
	}
	rows, err := generated.New(s.pool).ListResolvedAuthorizationGrants(ctx, user.UserID)
	if err != nil {
		return authz.EffectiveAccess{}, fmt.Errorf("store: list resolved authorization grants: %w", err)
	}
	grants := make([]authz.Grant, 0, len(rows))
	for _, row := range rows {
		permissions := make([]authz.Permission, len(row.Permissions))
		for index, permission := range row.Permissions {
			permissions[index] = authz.Permission(permission)
		}
		grants = append(grants, authz.Grant{
			ID:            row.GrantID,
			PrincipalType: authz.PrincipalType(row.PrincipalType),
			PrincipalID:   row.PrincipalID,
			RoleID:        row.RoleID,
			Permissions:   permissions,
			Scope: authz.Scope{
				Kind: authz.ScopeKind(row.ScopeKind),
				IDs:  row.ScopeIds,
			},
		})
	}
	effective, err := authz.Resolve(grants)
	if err != nil {
		return authz.EffectiveAccess{}, fmt.Errorf("store: resolve authorization grants: %w", err)
	}
	return effective, nil
}

func authorizationEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		authorizationRoleCreatedType: {
			PayloadVersion: authorizationPayloadVersion,
			PayloadType:    authorizationRoleCreatedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(authorizationRoleCreatedPayload{
					Name:        "operators",
					Permissions: []authz.Permission{"devices.manage", "roles.manage"},
				})
			},
			Projector: projectAuthorizationRoleCreated,
		},
		authorizationGrantCreatedType: {
			PayloadVersion: authorizationPayloadVersion,
			PayloadType:    authorizationGrantCreatedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(authorizationGrantCreatedPayload{
					PrincipalType: authz.PrincipalUser,
					PrincipalID:   "01J00000000000000000000001",
					RoleID:        "01J00000000000000000000002",
					ScopeKind:     authz.ScopeDeviceGroups,
					ScopeIDs:      []string{"01J00000000000000000000003"},
				})
			},
			Projector: projectAuthorizationGrantCreated,
		},
	}
}

func authorizationGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		authorizationRoleCreatedType: {
			PayloadVersion: authorizationPayloadVersion,
			Payload: []byte(
				`{"name":"operators","permissions":["devices.manage","roles.manage"]}`,
			),
		},
		authorizationGrantCreatedType: {
			PayloadVersion: authorizationPayloadVersion,
			Payload: []byte(
				`{"principal_type":"user","principal_id":"01J00000000000000000000001","role_id":"01J00000000000000000000002","scope_kind":"device-groups","scope_ids":["01J00000000000000000000003"]}`,
			),
		},
	}
}

func projectAuthorizationRoleCreated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errors.New("store: authorization role creation must be stream version one")
	}
	payload, err := decodeEventPayload[authorizationRoleCreatedPayload](
		event,
		authorizationPayloadVersion,
	)
	if err != nil {
		return err
	}
	role, err := authz.NormalizeRole(authz.Role{
		ID:          event.StreamID,
		Name:        payload.Name,
		Permissions: payload.Permissions,
	})
	if err != nil || role.ID != event.StreamID || role.Name != payload.Name ||
		!slices.Equal(role.Permissions, payload.Permissions) {
		return errors.New("store: authorization role payload is invalid")
	}
	permissions := make([]string, len(role.Permissions))
	for index, permission := range role.Permissions {
		permissions[index] = string(permission)
	}
	affected, err := generated.New(tx).InsertAuthorizationRole(
		ctx,
		generated.InsertAuthorizationRoleParams{
			RoleID:            role.ID,
			Name:              role.Name,
			Permissions:       permissions,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project authorization role creation: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: authorization role creation affected %d rows; want one", affected)
	}
	return nil
}

func projectAuthorizationGrantCreated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errors.New("store: authorization grant creation must be stream version one")
	}
	grantID, err := canonicalAuthorizationID(event.StreamID)
	if err != nil || grantID != event.StreamID {
		return errors.New("store: authorization grant stream ID is invalid")
	}
	payload, err := decodeEventPayload[authorizationGrantCreatedPayload](
		event,
		authorizationPayloadVersion,
	)
	if err != nil {
		return err
	}
	principalID, err := authz.NormalizePrincipal(payload.PrincipalType, payload.PrincipalID)
	if err != nil || principalID != payload.PrincipalID {
		return errors.New("store: authorization grant principal is invalid")
	}
	roleID, err := canonicalAuthorizationID(payload.RoleID)
	if err != nil || roleID != payload.RoleID {
		return errors.New("store: authorization grant role ID is invalid")
	}
	scope, err := authz.NormalizeScope(authz.Scope{
		Kind: payload.ScopeKind,
		IDs:  payload.ScopeIDs,
	})
	if err != nil || scope.Kind != payload.ScopeKind ||
		!slices.Equal(scope.IDs, payload.ScopeIDs) {
		return errors.New("store: authorization grant scope is invalid")
	}

	queries := generated.New(tx)
	rebuilding, isRebuild := tx.(projectionTx)
	if !isRebuild || !rebuilding.skipWork {
		if _, err := queries.GetAuthorizationRole(ctx, roleID); err != nil {
			return fmt.Errorf("%w: %v", errAuthorizationRoleMissing, err)
		}
	}
	exists, err := queries.AuthorizationPrincipalExists(
		ctx,
		generated.AuthorizationPrincipalExistsParams{
			PrincipalType: string(payload.PrincipalType),
			PrincipalID:   principalID,
		},
	)
	if err != nil {
		return fmt.Errorf("store: inspect authorization grant principal: %w", err)
	}
	if !exists {
		if !isRebuild || !rebuilding.skipWork {
			return errAuthorizationPrincipalMissing
		}
	}
	affected, err := queries.InsertAuthorizationGrant(
		ctx,
		generated.InsertAuthorizationGrantParams{
			GrantID:           grantID,
			PrincipalType:     string(payload.PrincipalType),
			PrincipalID:       principalID,
			RoleID:            roleID,
			ScopeKind:         string(scope.Kind),
			ScopeIds:          scope.IDs,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project authorization grant creation: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: authorization grant creation affected %d rows; want one", affected)
	}
	return nil
}

func resetAuthorization(ctx context.Context, tx ProjectionTx) error {
	queries := generated.New(tx)
	if err := queries.ResetAuthorizationGrants(ctx); err != nil {
		return fmt.Errorf("store: reset authorization grants: %w", err)
	}
	if err := queries.ResetAuthorizationRoles(ctx); err != nil {
		return fmt.Errorf("store: reset authorization roles: %w", err)
	}
	return nil
}

func canonicalAuthorizationID(value string) (string, error) {
	if err := validate.ULIDPathID(value); err != nil {
		return "", err
	}
	return strings.ToUpper(value), nil
}
