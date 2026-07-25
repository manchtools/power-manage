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
	authorizationRoleUpdatedType  = "AuthorizationRoleUpdated"
	authorizationRoleDeletedType  = "AuthorizationRoleDeleted"
	authorizationGrantCreatedType = "AuthorizationGrantCreated"
	authorizationGrantUpdatedType = "AuthorizationGrantUpdated"
	authorizationGrantDeletedType = "AuthorizationGrantDeleted"
	authorizationPayloadVersion   = 1
	AuthorizationRebuildTarget    = "authorization"
)

var (
	// ErrUserDisabled identifies an account that must contribute no authorization.
	ErrUserDisabled                  = errors.New("store: user is disabled")
	errAuthorizationRoleExists       = errors.New("store: authorization role already exists")
	errAuthorizationGrantExists      = errors.New("store: authorization grant already exists")
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

type authorizationDeletedPayload struct{}

// AuthorizationRole is one event-derived role projection.
type AuthorizationRole struct {
	ID                string
	Name              string
	Permissions       []authz.Permission
	ProjectionVersion int64
}

// AuthorizationGrant is one event-derived principal-role-scope projection.
type AuthorizationGrant struct {
	ID                string
	PrincipalType     authz.PrincipalType
	PrincipalID       string
	RoleID            string
	Scope             authz.Scope
	ProjectionVersion int64
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

// AuthorizationRoleUpdatedEvent records full replacement of one role.
func AuthorizationRoleUpdatedEvent(
	roleID string,
	name string,
	permissions []authz.Permission,
) (Event, error) {
	event, err := AuthorizationRoleCreatedEvent(roleID, name, permissions)
	if err != nil {
		return Event{}, err
	}
	event.EventType = authorizationRoleUpdatedType
	return event, nil
}

// AuthorizationRoleDeletedEvent removes one role projection.
func AuthorizationRoleDeletedEvent(roleID string) (Event, error) {
	roleID, err := canonicalAuthorizationID(roleID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(authorizationDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode authorization role deletion: %w", err)
	}
	return Event{
		StreamType:     authorizationRoleStreamType,
		StreamID:       roleID,
		EventType:      authorizationRoleDeletedType,
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

// AuthorizationGrantUpdatedEvent records full replacement of one grant.
func AuthorizationGrantUpdatedEvent(
	grantID string,
	principalType authz.PrincipalType,
	principalID string,
	roleID string,
	scope authz.Scope,
) (Event, error) {
	event, err := AuthorizationGrantCreatedEvent(
		grantID,
		principalType,
		principalID,
		roleID,
		scope,
	)
	if err != nil {
		return Event{}, err
	}
	event.EventType = authorizationGrantUpdatedType
	return event, nil
}

// AuthorizationGrantDeletedEvent removes one grant projection.
func AuthorizationGrantDeletedEvent(grantID string) (Event, error) {
	grantID, err := canonicalAuthorizationID(grantID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(authorizationDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode authorization grant deletion: %w", err)
	}
	return Event{
		StreamType:     authorizationGrantStreamType,
		StreamID:       grantID,
		EventType:      authorizationGrantDeletedType,
		PayloadVersion: authorizationPayloadVersion,
		Payload:        payload,
	}, nil
}

// AuthorizationRoleByID reads one role projection.
func (s *Store) AuthorizationRoleByID(
	ctx context.Context,
	roleID string,
) (AuthorizationRole, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return AuthorizationRole{}, errors.New("store: invalid authorization role lookup")
	}
	roleID, err := canonicalAuthorizationID(roleID)
	if err != nil {
		return AuthorizationRole{}, err
	}
	row, err := generated.New(s.pool).GetAuthorizationRole(ctx, roleID)
	if err != nil {
		return AuthorizationRole{}, fmt.Errorf("store: read authorization role: %w", err)
	}
	return validateAuthorizationRoleProjection(
		row.RoleID,
		row.Name,
		row.Permissions,
		row.ProjectionVersion,
	)
}

// ListAuthorizationRoles returns one bounded role page.
func (s *Store) ListAuthorizationRoles(
	ctx context.Context,
	limit int32,
) ([]AuthorizationRole, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid authorization role list")
	}
	rows, err := generated.New(s.pool).ListAuthorizationRoles(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list authorization roles: %w", err)
	}
	roles := make([]AuthorizationRole, len(rows))
	for index, row := range rows {
		roles[index], err = validateAuthorizationRoleProjection(
			row.RoleID,
			row.Name,
			row.Permissions,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return roles, nil
}

// AuthorizationGrantByID reads one grant projection.
func (s *Store) AuthorizationGrantByID(
	ctx context.Context,
	grantID string,
) (AuthorizationGrant, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return AuthorizationGrant{}, errors.New("store: invalid authorization grant lookup")
	}
	grantID, err := canonicalAuthorizationID(grantID)
	if err != nil {
		return AuthorizationGrant{}, err
	}
	row, err := generated.New(s.pool).GetAuthorizationGrant(ctx, grantID)
	if err != nil {
		return AuthorizationGrant{}, fmt.Errorf("store: read authorization grant: %w", err)
	}
	return validateAuthorizationGrantProjection(
		row.GrantID,
		row.PrincipalType,
		row.PrincipalID,
		row.RoleID,
		row.ScopeKind,
		row.ScopeIds,
		row.ProjectionVersion,
	)
}

// ListAuthorizationGrants returns one bounded grant page.
func (s *Store) ListAuthorizationGrants(
	ctx context.Context,
	limit int32,
) ([]AuthorizationGrant, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid authorization grant list")
	}
	rows, err := generated.New(s.pool).ListAuthorizationGrants(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list authorization grants: %w", err)
	}
	grants := make([]AuthorizationGrant, len(rows))
	for index, row := range rows {
		grants[index], err = validateAuthorizationGrantProjection(
			row.GrantID,
			row.PrincipalType,
			row.PrincipalID,
			row.RoleID,
			row.ScopeKind,
			row.ScopeIds,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return grants, nil
}

// IsAuthorizationRoleExists recognizes duplicate role creation.
func IsAuthorizationRoleExists(err error) bool {
	return errors.Is(err, errAuthorizationRoleExists)
}

// IsAuthorizationGrantExists recognizes duplicate grant creation.
func IsAuthorizationGrantExists(err error) bool {
	return errors.Is(err, errAuthorizationGrantExists)
}

// AuthorizationRoleEventTypes returns the role CRUD event set.
func AuthorizationRoleEventTypes() []string {
	return []string{
		authorizationRoleCreatedType,
		authorizationRoleUpdatedType,
		authorizationRoleDeletedType,
	}
}

// AuthorizationGrantEventTypes returns the grant CRUD event set.
func AuthorizationGrantEventTypes() []string {
	return []string{
		authorizationGrantCreatedType,
		authorizationGrantUpdatedType,
		authorizationGrantDeletedType,
	}
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
			PayloadVersion:  authorizationPayloadVersion,
			PayloadType:     authorizationRoleCreatedPayload{},
			LastAdminEffect: lastAdminUnaffected,
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(authorizationRoleCreatedPayload{
					Name:        "operators",
					Permissions: []authz.Permission{"devices.manage", "roles.manage"},
				})
			},
			Projector: projectAuthorizationRoleCreated,
		},
		authorizationRoleUpdatedType: {
			PayloadVersion:  authorizationPayloadVersion,
			PayloadType:     authorizationRoleCreatedPayload{},
			LastAdminEffect: lastAdminMayReduce,
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(authorizationRoleCreatedPayload{
					Name:        "updated-operators",
					Permissions: []authz.Permission{"devices.manage"},
				})
			},
			Projector: projectAuthorizationRoleUpdated,
		},
		authorizationRoleDeletedType: {
			PayloadVersion:  authorizationPayloadVersion,
			PayloadType:     authorizationDeletedPayload{},
			LastAdminEffect: lastAdminMayReduce,
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(authorizationDeletedPayload{})
			},
			Projector: projectAuthorizationRoleDeleted,
		},
		authorizationGrantCreatedType: {
			PayloadVersion:  authorizationPayloadVersion,
			PayloadType:     authorizationGrantCreatedPayload{},
			LastAdminEffect: lastAdminUnaffected,
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
		authorizationGrantUpdatedType: {
			PayloadVersion:  authorizationPayloadVersion,
			PayloadType:     authorizationGrantCreatedPayload{},
			LastAdminEffect: lastAdminMayReduce,
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(authorizationGrantCreatedPayload{
					PrincipalType: authz.PrincipalUser,
					PrincipalID:   "01J00000000000000000000001",
					RoleID:        "01J00000000000000000000002",
					ScopeKind:     authz.ScopeGlobal,
					ScopeIDs:      []string{},
				})
			},
			Projector: projectAuthorizationGrantUpdated,
		},
		authorizationGrantDeletedType: {
			PayloadVersion:  authorizationPayloadVersion,
			PayloadType:     authorizationDeletedPayload{},
			LastAdminEffect: lastAdminMayReduce,
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(authorizationDeletedPayload{})
			},
			Projector: projectAuthorizationGrantDeleted,
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
		authorizationRoleUpdatedType: {
			PayloadVersion: authorizationPayloadVersion,
			Payload: []byte(
				`{"name":"updated-operators","permissions":["devices.manage"]}`,
			),
		},
		authorizationRoleDeletedType: {
			PayloadVersion: authorizationPayloadVersion,
			Payload:        []byte(`{}`),
		},
		authorizationGrantCreatedType: {
			PayloadVersion: authorizationPayloadVersion,
			Payload: []byte(
				`{"principal_type":"user","principal_id":"01J00000000000000000000001","role_id":"01J00000000000000000000002","scope_kind":"device-groups","scope_ids":["01J00000000000000000000003"]}`,
			),
		},
		authorizationGrantUpdatedType: {
			PayloadVersion: authorizationPayloadVersion,
			Payload: []byte(
				`{"principal_type":"user","principal_id":"01J00000000000000000000001","role_id":"01J00000000000000000000002","scope_kind":"global","scope_ids":[]}`,
			),
		},
		authorizationGrantDeletedType: {
			PayloadVersion: authorizationPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectAuthorizationRoleCreated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errAuthorizationRoleExists
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
		return errAuthorizationRoleExists
	}
	return nil
}

func projectAuthorizationGrantCreated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errAuthorizationGrantExists
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
		return errAuthorizationGrantExists
	}
	return nil
}

func projectAuthorizationRoleUpdated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: authorization role update version is invalid")
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
	affected, err := generated.New(tx).ReplaceAuthorizationRole(
		ctx,
		generated.ReplaceAuthorizationRoleParams{
			Name:                      role.Name,
			Permissions:               permissions,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			RoleID:                    role.ID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project authorization role update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: authorization role update projection version mismatch")
	}
	return nil
}

func projectAuthorizationRoleDeleted(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: authorization role deletion version is invalid")
	}
	if _, err := decodeEventPayload[authorizationDeletedPayload](
		event,
		authorizationPayloadVersion,
	); err != nil {
		return err
	}
	roleID, err := canonicalAuthorizationID(event.StreamID)
	if err != nil || roleID != event.StreamID {
		return errors.New("store: authorization role stream ID is invalid")
	}
	affected, err := generated.New(tx).DeleteAuthorizationRole(
		ctx,
		generated.DeleteAuthorizationRoleParams{
			RoleID:            roleID,
			ProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project authorization role deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: authorization role deletion projection version mismatch")
	}
	return nil
}

func projectAuthorizationGrantUpdated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: authorization grant update version is invalid")
	}
	payload, err := decodeEventPayload[authorizationGrantCreatedPayload](
		event,
		authorizationPayloadVersion,
	)
	if err != nil {
		return err
	}
	grant, err := validateAuthorizationGrantProjection(
		event.StreamID,
		string(payload.PrincipalType),
		payload.PrincipalID,
		payload.RoleID,
		string(payload.ScopeKind),
		payload.ScopeIDs,
		event.StreamVersion,
	)
	if err != nil {
		return err
	}
	queries := generated.New(tx)
	rebuilding, isRebuild := tx.(projectionTx)
	if !isRebuild || !rebuilding.skipWork {
		if _, err := queries.GetAuthorizationRole(ctx, grant.RoleID); err != nil {
			return fmt.Errorf("%w: %v", errAuthorizationRoleMissing, err)
		}
		exists, err := queries.AuthorizationPrincipalExists(
			ctx,
			generated.AuthorizationPrincipalExistsParams{
				PrincipalType: string(grant.PrincipalType),
				PrincipalID:   grant.PrincipalID,
			},
		)
		if err != nil {
			return fmt.Errorf("store: inspect authorization grant principal: %w", err)
		}
		if !exists {
			return errAuthorizationPrincipalMissing
		}
	}
	affected, err := queries.ReplaceAuthorizationGrant(
		ctx,
		generated.ReplaceAuthorizationGrantParams{
			PrincipalType:             string(grant.PrincipalType),
			PrincipalID:               grant.PrincipalID,
			RoleID:                    grant.RoleID,
			ScopeKind:                 string(grant.Scope.Kind),
			ScopeIds:                  grant.Scope.IDs,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			GrantID:                   grant.ID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project authorization grant update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: authorization grant update projection version mismatch")
	}
	return nil
}

func projectAuthorizationGrantDeleted(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: authorization grant deletion version is invalid")
	}
	if _, err := decodeEventPayload[authorizationDeletedPayload](
		event,
		authorizationPayloadVersion,
	); err != nil {
		return err
	}
	grantID, err := canonicalAuthorizationID(event.StreamID)
	if err != nil || grantID != event.StreamID {
		return errors.New("store: authorization grant stream ID is invalid")
	}
	affected, err := generated.New(tx).DeleteAuthorizationGrant(
		ctx,
		generated.DeleteAuthorizationGrantParams{
			GrantID:           grantID,
			ProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project authorization grant deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: authorization grant deletion projection version mismatch")
	}
	return nil
}

func validateAuthorizationRoleProjection(
	id string,
	name string,
	permissionNames []string,
	version int64,
) (AuthorizationRole, error) {
	permissions := make([]authz.Permission, len(permissionNames))
	for index, permission := range permissionNames {
		permissions[index] = authz.Permission(permission)
	}
	role, err := authz.NormalizeRole(authz.Role{
		ID:          id,
		Name:        name,
		Permissions: permissions,
	})
	if err != nil || role.ID != id || role.Name != name ||
		!slices.Equal(role.Permissions, permissions) || version < 1 {
		return AuthorizationRole{}, errors.New("store: authorization role projection is invalid")
	}
	return AuthorizationRole{
		ID:                role.ID,
		Name:              role.Name,
		Permissions:       role.Permissions,
		ProjectionVersion: version,
	}, nil
}

func validateAuthorizationGrantProjection(
	id string,
	principalType string,
	principalID string,
	roleID string,
	scopeKind string,
	scopeIDs []string,
	version int64,
) (AuthorizationGrant, error) {
	canonicalID, err := canonicalAuthorizationID(id)
	if err != nil || canonicalID != id {
		return AuthorizationGrant{}, errors.New("store: authorization grant projection ID is invalid")
	}
	principal := authz.PrincipalType(principalType)
	normalizedPrincipalID, err := authz.NormalizePrincipal(principal, principalID)
	if err != nil || normalizedPrincipalID != principalID {
		return AuthorizationGrant{}, errors.New("store: authorization grant projection principal is invalid")
	}
	canonicalRoleID, err := canonicalAuthorizationID(roleID)
	if err != nil || canonicalRoleID != roleID {
		return AuthorizationGrant{}, errors.New("store: authorization grant projection role ID is invalid")
	}
	scope, err := authz.NormalizeScope(authz.Scope{
		Kind: authz.ScopeKind(scopeKind),
		IDs:  scopeIDs,
	})
	if err != nil ||
		scope.Kind != authz.ScopeKind(scopeKind) ||
		!slices.Equal(scope.IDs, scopeIDs) {
		return AuthorizationGrant{}, errors.New("store: authorization grant projection scope is invalid")
	}
	if version < 1 {
		return AuthorizationGrant{}, errors.New("store: authorization grant projection version is invalid")
	}
	return AuthorizationGrant{
		ID:                canonicalID,
		PrincipalType:     principal,
		PrincipalID:       normalizedPrincipalID,
		RoleID:            canonicalRoleID,
		Scope:             scope,
		ProjectionVersion: version,
	}, nil
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
