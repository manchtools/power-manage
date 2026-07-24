package control

import (
	"context"
	"testing"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	identityAdminID        = "01J00000000000000000000121"
	identityScopedID       = "01J00000000000000000000122"
	identitySelfID         = "01J00000000000000000000123"
	identityInScopeID      = "01J00000000000000000000124"
	identityOutOfScopeID   = "01J00000000000000000000125"
	identityCreatedUserID  = "01J00000000000000000000126"
	identityGroupID        = "01J00000000000000000000127"
	identityCreatedGroupID = "01J00000000000000000000128"
	identityAdminRoleID    = "01J00000000000000000000129"
	identityScopedRoleID   = "01J00000000000000000000130"
	identitySelfRoleID     = "01J00000000000000000000131"
	identityAdminGrantID   = "01J00000000000000000000132"
	identityScopedGrantID  = "01J00000000000000000000133"
	identitySelfGrantID    = "01J00000000000000000000134"
	identityCreatedRoleID  = "01J00000000000000000000135"
	identityCreatedGrantID = "01J00000000000000000000136"
	identityDeviceID       = "01J00000000000000000000137"
	identityDeviceGroupID  = "01J00000000000000000000138"
	identityDeviceGrantID  = "01J00000000000000000000139"
)

func TestIdentityHandlers_CRUDAndScopeConfinement(t *testing.T) {
	eventStore, service := identityManagementService(t)
	admin := identityContext(t, identityAdminID)
	scoped := identityContext(t, identityScopedID)
	self := identityContext(t, identitySelfID)

	created, err := service.CreateUser(admin, connect.NewRequest(
		&powermanagev1.CreateUserRequest{
			Id:    identityCreatedUserID,
			Email: "created@example.test",
		},
	))
	if err != nil || created.Msg.GetUser().GetVersion() != 1 {
		t.Fatalf("create user = (%#v, %v); want version one", created, err)
	}
	updated, err := service.UpdateUser(admin, connect.NewRequest(
		&powermanagev1.UpdateUserRequest{
			Id:              identityCreatedUserID,
			Email:           "updated@example.test",
			ExpectedVersion: 1,
		},
	))
	if err != nil || updated.Msg.GetUser().GetEmail() != "updated@example.test" ||
		updated.Msg.GetUser().GetVersion() != 2 {
		t.Fatalf("update user = (%#v, %v); want updated version two", updated, err)
	}
	if _, err := service.DeleteUser(admin, connect.NewRequest(
		&powermanagev1.DeleteUserRequest{
			Id:              identityCreatedUserID,
			ExpectedVersion: 1,
		},
	)); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale user delete code = %v; want Aborted", connect.CodeOf(err))
	}
	if _, err := service.DeleteUser(admin, connect.NewRequest(
		&powermanagev1.DeleteUserRequest{
			Id:              identityCreatedUserID,
			ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	scopedUsers, err := service.ListUsers(scoped, connect.NewRequest(
		&powermanagev1.ListUsersRequest{Limit: 100},
	))
	if err != nil || len(scopedUsers.Msg.GetUsers()) != 1 ||
		scopedUsers.Msg.GetUsers()[0].GetId() != identityInScopeID {
		t.Fatalf("scoped users = (%#v, %v); want only in-scope user", scopedUsers, err)
	}
	if _, err := service.GetUser(scoped, connect.NewRequest(
		&powermanagev1.GetUserRequest{Id: identityOutOfScopeID},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope user code = %v; want NotFound", connect.CodeOf(err))
	}
	if _, err := service.UpdateUser(scoped, connect.NewRequest(
		&powermanagev1.UpdateUserRequest{
			Id:              identityOutOfScopeID,
			Email:           "forbidden@example.test",
			ExpectedVersion: 1,
		},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope update code = %v; want NotFound", connect.CodeOf(err))
	}
	selfUsers, err := service.ListUsers(self, connect.NewRequest(
		&powermanagev1.ListUsersRequest{Limit: 100},
	))
	if err != nil || len(selfUsers.Msg.GetUsers()) != 1 ||
		selfUsers.Msg.GetUsers()[0].GetId() != identitySelfID {
		t.Fatalf("self users = (%#v, %v); want only self", selfUsers, err)
	}

	group, err := service.GetUserGroup(scoped, connect.NewRequest(
		&powermanagev1.GetUserGroupRequest{Id: identityGroupID},
	))
	if err != nil || group.Msg.GetUserGroup().GetName() != "operators" {
		t.Fatalf("scoped group = (%#v, %v); want operators", group, err)
	}
	if _, err := service.GetUserGroup(self, connect.NewRequest(
		&powermanagev1.GetUserGroupRequest{Id: identityGroupID},
	)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("group without permission code = %v; want PermissionDenied", connect.CodeOf(err))
	}
	if _, err := service.CreateUserGroup(admin, connect.NewRequest(
		&powermanagev1.CreateUserGroupRequest{
			Id:   identityCreatedGroupID,
			Name: "temporary",
		},
	)); err != nil {
		t.Fatalf("create user group: %v", err)
	}
	groupUpdate, err := service.UpdateUserGroup(admin, connect.NewRequest(
		&powermanagev1.UpdateUserGroupRequest{
			Id:              identityCreatedGroupID,
			Name:            "renamed",
			ExpectedVersion: 1,
		},
	))
	if err != nil || groupUpdate.Msg.GetUserGroup().GetVersion() != 2 {
		t.Fatalf("update user group = (%#v, %v); want version two", groupUpdate, err)
	}
	if _, err := service.DeleteUserGroup(admin, connect.NewRequest(
		&powermanagev1.DeleteUserGroupRequest{
			Id:              identityCreatedGroupID,
			ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete user group: %v", err)
	}

	role, err := service.CreateRole(admin, connect.NewRequest(
		&powermanagev1.CreateRoleRequest{
			Id:          identityCreatedRoleID,
			Name:        "auditors",
			Permissions: []string{"audit.read"},
		},
	))
	if err != nil || role.Msg.GetRole().GetVersion() != 1 {
		t.Fatalf("create role = (%#v, %v); want version one", role, err)
	}
	grant, err := service.CreateGrant(admin, connect.NewRequest(
		&powermanagev1.CreateGrantRequest{
			Id:            identityCreatedGrantID,
			PrincipalType: powermanagev1.AuthorizationPrincipalType_AUTHORIZATION_PRINCIPAL_TYPE_USER,
			PrincipalId:   identityOutOfScopeID,
			RoleId:        identityCreatedRoleID,
			Scope: &powermanagev1.GrantScope{
				Kind: powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_GLOBAL,
			},
		},
	))
	if err != nil || len(grant.Msg.GetGrant().GetActivePermissions()) != 1 ||
		grant.Msg.GetGrant().GetProjectionVersion() != 1 {
		t.Fatalf("create grant = (%#v, %v); want one active permission", grant, err)
	}
	if _, err := service.UpdateGrant(admin, connect.NewRequest(
		&powermanagev1.UpdateGrantRequest{
			Id:              identityCreatedGrantID,
			PrincipalType:   powermanagev1.AuthorizationPrincipalType_AUTHORIZATION_PRINCIPAL_TYPE_USER,
			PrincipalId:     identityInScopeID,
			RoleId:          identityCreatedRoleID,
			Scope:           &powermanagev1.GrantScope{Kind: powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_SELF},
			ExpectedVersion: 1,
		},
	)); err != nil {
		t.Fatalf("update grant: %v", err)
	}
	if _, err := service.UpdateRole(admin, connect.NewRequest(
		&powermanagev1.UpdateRoleRequest{
			Id:              identityCreatedRoleID,
			Name:            "device-auditors",
			Permissions:     []string{"devices.manage"},
			ExpectedVersion: 1,
		},
	)); err != nil {
		t.Fatalf("update role: %v", err)
	}
	if _, err := service.DeleteGrant(admin, connect.NewRequest(
		&powermanagev1.DeleteGrantRequest{
			Id:              identityCreatedGrantID,
			ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete grant: %v", err)
	}
	if _, err := service.DeleteRole(admin, connect.NewRequest(
		&powermanagev1.DeleteRoleRequest{
			Id:              identityCreatedRoleID,
			ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete role: %v", err)
	}

	if err := eventStore.RebuildAll(t.Context(), store.UserGroupRebuildTarget); err != nil {
		t.Fatalf("rebuild user groups after handler mutations: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), store.AuthorizationRebuildTarget); err != nil {
		t.Fatalf("rebuild authorization after handler mutations: %v", err)
	}
}

func identityManagementService(t *testing.T) (*store.Store, *ManagementService) {
	t.Helper()
	pool := crlRotationPostgres.Database(t, store.Migrate)
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	appendIdentityAuthorizationFixtures(t, eventStore)
	gate, err := auth.NewAuthorizationGate(eventStore)
	if err != nil {
		t.Fatalf("create authorization gate: %v", err)
	}
	service, err := NewManagementService(eventStore, gate)
	if err != nil {
		t.Fatalf("create management service: %v", err)
	}
	return eventStore, service
}

func appendIdentityAuthorizationFixtures(t *testing.T, eventStore *store.Store) {
	t.Helper()
	users := []struct {
		id    string
		email string
	}{
		{identityAdminID, "identity-admin@example.test"},
		{identityScopedID, "identity-scoped@example.test"},
		{identitySelfID, "identity-self@example.test"},
		{identityInScopeID, "identity-in-scope@example.test"},
		{identityOutOfScopeID, "identity-out-of-scope@example.test"},
	}
	events := make([]store.Event, 0, len(users)+7)
	for _, user := range users {
		event, err := store.UserCreatedEvent(user.id, user.email)
		if err != nil {
			t.Fatalf("create user fixture: %v", err)
		}
		events = append(events, event)
	}
	group, err := store.UserGroupCreatedEvent(
		identityGroupID,
		"operators",
		[]string{identityInScopeID},
	)
	if err != nil {
		t.Fatalf("create group fixture: %v", err)
	}
	events = append(events, group)
	deviceGroup, err := store.DeviceGroupCreatedWithMembersEvent(
		identityDeviceGroupID,
		"managed-devices",
		"",
		[]string{identityDeviceID},
	)
	if err != nil {
		t.Fatalf("create device-group fixture: %v", err)
	}
	events = append(events, deviceGroup)
	roles := []struct {
		id          string
		name        string
		permissions []authz.Permission
	}{
		{
			identityAdminRoleID,
			"identity-admins",
			[]authz.Permission{
				"action_sets.manage",
				"actions.manage",
				"audit.read",
				"devices.manage",
				"executions.read",
				"identity_providers.manage",
				"pki.manage",
				"roles.manage",
				"scim_configuration.manage",
				"server_settings.manage",
				"user_groups.manage",
				"users.manage",
			},
		},
		{
			identityScopedRoleID,
			"identity-scoped",
			[]authz.Permission{
				"action_sets.manage",
				"actions.manage",
				"audit.read",
				"devices.manage",
				"executions.read",
				"user_groups.manage",
				"users.manage",
			},
		},
		{identitySelfRoleID, "identity-self", []authz.Permission{"users.manage"}},
	}
	for _, role := range roles {
		event, err := store.AuthorizationRoleCreatedEvent(role.id, role.name, role.permissions)
		if err != nil {
			t.Fatalf("create role fixture: %v", err)
		}
		events = append(events, event)
	}
	grants := []struct {
		id        string
		principal string
		role      string
		scope     authz.Scope
	}{
		{
			identityAdminGrantID,
			identityAdminID,
			identityAdminRoleID,
			authz.Scope{Kind: authz.ScopeGlobal},
		},
		{
			identityScopedGrantID,
			identityScopedID,
			identityScopedRoleID,
			authz.Scope{Kind: authz.ScopeUserGroups, IDs: []string{identityGroupID}},
		},
		{
			identityDeviceGrantID,
			identityScopedID,
			identityScopedRoleID,
			authz.Scope{Kind: authz.ScopeDeviceGroups, IDs: []string{identityDeviceGroupID}},
		},
		{
			identitySelfGrantID,
			identitySelfID,
			identitySelfRoleID,
			authz.Scope{Kind: authz.ScopeSelf},
		},
	}
	for _, grant := range grants {
		event, err := store.AuthorizationGrantCreatedEvent(
			grant.id,
			authz.PrincipalUser,
			grant.principal,
			grant.role,
			grant.scope,
		)
		if err != nil {
			t.Fatalf("create grant fixture: %v", err)
		}
		events = append(events, event)
	}
	if err := eventStore.AppendEvents(t.Context(), events); err != nil {
		t.Fatalf("append identity fixtures: %v", err)
	}
}

func identityContext(t *testing.T, subject string) context.Context {
	t.Helper()
	ctx, err := auth.ContextWithSessionClaims(t.Context(), auth.Claims{
		Subject:        subject,
		SessionVersion: 1,
	})
	if err != nil {
		t.Fatalf("attach session claims: %v", err)
	}
	return ctx
}
