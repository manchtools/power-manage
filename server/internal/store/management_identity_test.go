package store

import (
	"slices"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/server/internal/authz"
)

const (
	managementUserOne  = "01J00000000000000000000101"
	managementUserTwo  = "01J00000000000000000000102"
	managementGroupID  = "01J00000000000000000000103"
	managementRoleID   = "01J00000000000000000000104"
	managementGrantID  = "01J00000000000000000000105"
	managementScopeID  = "01J00000000000000000000106"
	managementScopeID2 = "01J00000000000000000000107"
	managementAbsentID = "01J00000000000000000000108"
)

func TestManagedUsers_ProjectScopeUpdateDeleteAndRebuild(t *testing.T) {
	eventStore, err := NewProduction(testPostgres(t))
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	first, err := UserCreatedEvent(managementUserOne, "first@example.test")
	if err != nil {
		t.Fatalf("create first user: %v", err)
	}
	second, err := UserCreatedEvent(managementUserTwo, "second@example.test")
	if err != nil {
		t.Fatalf("create second user: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{first, second}); err != nil {
		t.Fatalf("append users: %v", err)
	}
	group, err := UserGroupCreatedEvent(
		managementGroupID,
		"operators",
		[]string{managementUserOne},
	)
	if err != nil {
		t.Fatalf("create user group: %v", err)
	}
	if err := eventStore.AppendEvent(t.Context(), group); err != nil {
		t.Fatalf("append user group: %v", err)
	}

	if _, err := eventStore.ScopedUserByID(
		t.Context(),
		managementUserOne,
		false,
		[]string{managementGroupID},
		"",
	); err != nil {
		t.Fatalf("read user through group scope: %v", err)
	}
	if _, err := eventStore.ScopedUserByID(
		t.Context(),
		managementUserTwo,
		false,
		[]string{managementGroupID},
		"",
	); !IsNotFound(err) {
		t.Fatalf("out-of-scope user error = %v; want not found", err)
	}
	self, err := eventStore.ListScopedUsers(
		t.Context(),
		false,
		nil,
		managementUserTwo,
		100,
	)
	if err != nil || len(self) != 1 || self[0].UserID != managementUserTwo {
		t.Fatalf("self-scoped users = (%#v, %v); want second user", self, err)
	}

	updated, err := UserManagedUpdatedEvent(managementUserOne, "updated@example.test")
	if err != nil {
		t.Fatalf("create user update: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), updated, 1); err != nil {
		t.Fatalf("append user update: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), UserRebuildTarget); err != nil {
		t.Fatalf("rebuild users: %v", err)
	}
	user, err := eventStore.UserByID(t.Context(), managementUserOne)
	if err != nil || user.Email != "updated@example.test" || user.ProjectionVersion != 2 {
		t.Fatalf("rebuilt user = (%#v, %v); want updated version two", user, err)
	}

	deleted, err := UserManagedDeletedEvent(managementUserOne)
	if err != nil {
		t.Fatalf("create user deletion: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), deleted, 2); err != nil {
		t.Fatalf("append user deletion: %v", err)
	}
	if _, err := eventStore.UserByID(t.Context(), managementUserOne); !IsNotFound(err) {
		t.Fatalf("deleted user error = %v; want not found", err)
	}
	if _, err := eventStore.ResolveEffectiveAccess(
		t.Context(),
		managementUserOne,
	); !IsNotFound(err) {
		t.Fatalf("deleted user's authorization error = %v; want not found", err)
	}
	if err := eventStore.RebuildAll(t.Context(), UserRebuildTarget); err != nil {
		t.Fatalf("rebuild deleted user: %v", err)
	}
	if _, err := eventStore.ResolveEffectiveAccess(
		t.Context(),
		managementUserOne,
	); !IsNotFound(err) {
		t.Fatalf("rebuilt deleted user's authorization error = %v; want not found", err)
	}
}

func TestManagedIdentityProjectors_RejectNoncanonicalFacts(t *testing.T) {
	lowerUserID := strings.ToLower(managementUserOne)
	lowerRoleID := strings.ToLower(managementRoleID)
	lowerGrantID := strings.ToLower(managementGrantID)
	tests := map[string]func() error{
		"user update stream": func() error {
			return projectManagedUserUpdate(t.Context(), nil, PersistedEvent{
				Event: Event{
					StreamID:       lowerUserID,
					PayloadVersion: userPayloadVersion,
					Payload:        []byte(`{"email":"updated@example.test"}`),
				},
				StreamVersion: 2,
			})
		},
		"user deletion stream": func() error {
			return projectManagedUserDeletion(t.Context(), nil, PersistedEvent{
				Event: Event{
					StreamID:       lowerUserID,
					PayloadVersion: userPayloadVersion,
					Payload:        []byte(`{}`),
				},
				StreamVersion: 2,
			})
		},
		"role update stream": func() error {
			return projectAuthorizationRoleUpdated(t.Context(), nil, PersistedEvent{
				Event: Event{
					StreamID:       lowerRoleID,
					PayloadVersion: authorizationPayloadVersion,
					Payload: []byte(
						`{"name":"operators","permissions":["devices.manage"]}`,
					),
				},
				StreamVersion: 2,
			})
		},
		"role update permission order": func() error {
			return projectAuthorizationRoleUpdated(t.Context(), nil, PersistedEvent{
				Event: Event{
					StreamID:       managementRoleID,
					PayloadVersion: authorizationPayloadVersion,
					Payload: []byte(
						`{"name":"operators","permissions":["roles.manage","devices.manage"]}`,
					),
				},
				StreamVersion: 2,
			})
		},
		"role deletion stream": func() error {
			return projectAuthorizationRoleDeleted(t.Context(), nil, PersistedEvent{
				Event: Event{
					StreamID:       lowerRoleID,
					PayloadVersion: authorizationPayloadVersion,
					Payload:        []byte(`{}`),
				},
				StreamVersion: 2,
			})
		},
		"grant deletion stream": func() error {
			return projectAuthorizationGrantDeleted(t.Context(), nil, PersistedEvent{
				Event: Event{
					StreamID:       lowerGrantID,
					PayloadVersion: authorizationPayloadVersion,
					Payload:        []byte(`{}`),
				},
				StreamVersion: 2,
			})
		},
	}
	wants := map[string]string{
		"user update stream":           "store: managed user update stream ID is not canonical",
		"user deletion stream":         "store: managed user deletion stream ID is not canonical",
		"role update stream":           "store: authorization role payload is invalid",
		"role update permission order": "store: authorization role payload is invalid",
		"role deletion stream":         "store: authorization role stream ID is invalid",
		"grant deletion stream":        "store: authorization grant stream ID is invalid",
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil || err.Error() != wants[name] {
				t.Fatalf("noncanonical fact error = %v; want %q", err, wants[name])
			}
		})
	}

	grantWants := map[string]string{
		"grant ID":     "store: authorization grant projection ID is invalid",
		"principal ID": "store: authorization grant projection principal is invalid",
		"role ID":      "store: authorization grant projection role ID is invalid",
		"scope ID":     "store: authorization grant projection scope is invalid",
	}
	for name, values := range map[string]struct {
		grantID     string
		principalID string
		roleID      string
		scopeID     string
	}{
		"grant ID": {
			grantID:     lowerGrantID,
			principalID: managementUserOne,
			roleID:      managementRoleID,
			scopeID:     managementScopeID,
		},
		"principal ID": {
			grantID:     managementGrantID,
			principalID: lowerUserID,
			roleID:      managementRoleID,
			scopeID:     managementScopeID,
		},
		"role ID": {
			grantID:     managementGrantID,
			principalID: managementUserOne,
			roleID:      lowerRoleID,
			scopeID:     managementScopeID,
		},
		"scope ID": {
			grantID:     managementGrantID,
			principalID: managementUserOne,
			roleID:      managementRoleID,
			scopeID:     strings.ToLower(managementScopeID),
		},
	} {
		t.Run("grant projection "+name, func(t *testing.T) {
			if _, err := validateAuthorizationGrantProjection(
				values.grantID,
				string(authz.PrincipalUser),
				values.principalID,
				values.roleID,
				string(authz.ScopeDeviceGroups),
				[]string{values.scopeID},
				1,
			); err == nil || err.Error() != grantWants[name] {
				t.Fatalf(
					"noncanonical authorization grant projection error = %v; want %q",
					err,
					grantWants[name],
				)
			}
		})
	}
}

func TestManagedUserGroups_ProjectReplaceScopeDeleteAndRebuild(t *testing.T) {
	wantEventTypes := []string{
		userGroupCreatedEventType,
		userGroupUpdatedEventType,
		userGroupMetadataUpdatedEventType,
		userGroupDeletedEventType,
	}
	if got := UserGroupEventTypes(); !slices.Equal(got, wantEventTypes) {
		t.Fatalf("managed user-group event types = %v; want %v", got, wantEventTypes)
	}
	eventStore, err := NewProduction(testPostgres(t))
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	appendManagementUsers(t, eventStore)
	created, err := UserGroupCreatedEvent(
		managementGroupID,
		"operators",
		[]string{managementUserOne},
	)
	if err != nil {
		t.Fatalf("create user-group event: %v", err)
	}
	if err := eventStore.AppendEvent(t.Context(), created); err != nil {
		t.Fatalf("append user-group creation: %v", err)
	}
	if _, err := eventStore.UserGroupByID(
		t.Context(),
		managementGroupID,
		false,
		nil,
	); !IsNotFound(err) {
		t.Fatalf("empty-scope group error = %v; want not found", err)
	}
	group, err := eventStore.UserGroupByID(
		t.Context(),
		managementGroupID,
		false,
		[]string{managementGroupID},
	)
	if err != nil || len(group.MemberUserIDs) != 1 ||
		group.MemberUserIDs[0] != managementUserOne {
		t.Fatalf("scoped group = (%#v, %v); want first member", group, err)
	}
	groups, err := eventStore.ListUserGroups(t.Context(), true, nil, 100)
	if err != nil || len(groups) != 1 ||
		!slices.Equal(groups[0].MemberUserIDs, []string{managementUserOne}) {
		t.Fatalf("listed groups = (%#v, %v); want first group with its member", groups, err)
	}

	updated, err := UserGroupUpdatedEvent(
		managementGroupID,
		"platform-operators",
		[]string{managementUserTwo},
	)
	if err != nil {
		t.Fatalf("create user-group update: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), updated, 1); err != nil {
		t.Fatalf("append user-group update: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), UserGroupRebuildTarget); err != nil {
		t.Fatalf("rebuild user groups: %v", err)
	}
	group, err = eventStore.UserGroupByID(t.Context(), managementGroupID, true, nil)
	if err != nil || group.Name != "platform-operators" ||
		len(group.MemberUserIDs) != 1 || group.MemberUserIDs[0] != managementUserTwo ||
		group.ProjectionVersion != 2 {
		t.Fatalf("rebuilt group = (%#v, %v); want replacement at version two", group, err)
	}

	deleted, err := UserGroupDeletedEvent(managementGroupID)
	if err != nil {
		t.Fatalf("create user-group deletion: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), deleted, 2); err != nil {
		t.Fatalf("append user-group deletion: %v", err)
	}
	if _, err := eventStore.UserGroupByID(
		t.Context(),
		managementGroupID,
		true,
		nil,
	); !IsNotFound(err) {
		t.Fatalf("deleted group error = %v; want not found", err)
	}
}

func TestManagedAuthorization_ProjectReplaceDeleteAndRebuild(t *testing.T) {
	eventStore, err := NewProduction(testPostgres(t))
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	appendManagementUsers(t, eventStore)
	role, err := AuthorizationRoleCreatedEvent(
		managementRoleID,
		"operators",
		[]authz.Permission{"devices.manage"},
	)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	grant, err := AuthorizationGrantCreatedEvent(
		managementGrantID,
		authz.PrincipalUser,
		managementUserOne,
		managementRoleID,
		authz.Scope{Kind: authz.ScopeDeviceGroups, IDs: []string{managementScopeID}},
	)
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{role, grant}); err != nil {
		t.Fatalf("append authorization fixtures: %v", err)
	}

	roleUpdate, err := AuthorizationRoleUpdatedEvent(
		managementRoleID,
		"auditors",
		[]authz.Permission{"audit.read"},
	)
	if err != nil {
		t.Fatalf("create role update: %v", err)
	}
	grantUpdate, err := AuthorizationGrantUpdatedEvent(
		managementGrantID,
		authz.PrincipalUser,
		managementUserTwo,
		managementRoleID,
		authz.Scope{
			Kind: authz.ScopeDeviceGroups,
			IDs:  []string{managementScopeID, managementScopeID2},
		},
	)
	if err != nil {
		t.Fatalf("create grant update: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), roleUpdate, 1); err != nil {
		t.Fatalf("append role update: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), grantUpdate, 1); err != nil {
		t.Fatalf("append grant update: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), AuthorizationRebuildTarget); err != nil {
		t.Fatalf("rebuild authorization: %v", err)
	}
	gotRole, err := eventStore.AuthorizationRoleByID(t.Context(), managementRoleID)
	if err != nil || gotRole.Name != "auditors" || gotRole.ProjectionVersion != 2 {
		t.Fatalf("rebuilt role = (%#v, %v); want auditors version two", gotRole, err)
	}
	gotGrant, err := eventStore.AuthorizationGrantByID(t.Context(), managementGrantID)
	if err != nil || gotGrant.PrincipalID != managementUserTwo ||
		len(gotGrant.Scope.IDs) != 2 || gotGrant.ProjectionVersion != 2 {
		t.Fatalf("rebuilt grant = (%#v, %v); want replacement version two", gotGrant, err)
	}

	grantDelete, err := AuthorizationGrantDeletedEvent(managementGrantID)
	if err != nil {
		t.Fatalf("create grant deletion: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), grantDelete, 2); err != nil {
		t.Fatalf("append grant deletion: %v", err)
	}
	roleDelete, err := AuthorizationRoleDeletedEvent(managementRoleID)
	if err != nil {
		t.Fatalf("create role deletion: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), roleDelete, 2); err != nil {
		t.Fatalf("append role deletion: %v", err)
	}
	if _, err := eventStore.AuthorizationGrantByID(
		t.Context(),
		managementGrantID,
	); !IsNotFound(err) {
		t.Fatalf("deleted grant error = %v; want not found", err)
	}
	if _, err := eventStore.AuthorizationRoleByID(
		t.Context(),
		managementRoleID,
	); !IsNotFound(err) {
		t.Fatalf("deleted role error = %v; want not found", err)
	}
}

func appendManagementUsers(t *testing.T, eventStore *Store) {
	t.Helper()
	first, err := UserCreatedEvent(managementUserOne, "first@example.test")
	if err != nil {
		t.Fatalf("create first user: %v", err)
	}
	second, err := UserCreatedEvent(managementUserTwo, "second@example.test")
	if err != nil {
		t.Fatalf("create second user: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{first, second}); err != nil {
		t.Fatalf("append management users: %v", err)
	}
}
