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
	scopeOutDeviceGroupID      = "01J00000000000000000000193"
	scopeOutUserGroupID        = "01J00000000000000000000194"
	scopeActionID              = "01J00000000000000000000195"
	scopeActionSetID           = "01J00000000000000000000196"
	scopeActionAssignmentID    = "01J00000000000000000000197"
	scopeActionSetAssignmentID = "01J00000000000000000000198"
	scopeInExecutionID         = "01J00000000000000000000199"
	scopeOutExecutionID        = "01J00000000000000000000200"
	scopeMissingID             = "01J00000000000000000000201"
	scopeOutExecutionDeviceID  = "01J00000000000000000000202"
)

type authorizationScopeFixture struct {
	service *ManagementService
	admin   context.Context
	scoped  context.Context
	self    context.Context
	params  *powermanagev1.ActionParams
}

type authorizationScopeCase struct {
	permission authz.Permission
	exercise   func(*testing.T, *authorizationScopeFixture)
}

func TestAuthorizationScopeBehavior(t *testing.T) {
	fixture := newAuthorizationScopeFixture(t)
	for _, test := range authorizationScopeCases() {
		t.Run(string(test.permission), func(t *testing.T) {
			test.exercise(t, fixture)
		})
	}
}

func TestAuthorizationDenialParityAndExecutionException(t *testing.T) {
	fixture := newAuthorizationScopeFixture(t)
	_, absentErr := fixture.service.GetUser(fixture.scoped, connect.NewRequest(
		&powermanagev1.GetUserRequest{Id: scopeMissingID},
	))
	_, outOfScopeErr := fixture.service.GetUser(fixture.scoped, connect.NewRequest(
		&powermanagev1.GetUserRequest{Id: identityOutOfScopeID},
	))
	if absentErr == nil || outOfScopeErr == nil ||
		connect.CodeOf(absentErr) != connect.CodeNotFound ||
		connect.CodeOf(outOfScopeErr) != connect.CodeNotFound ||
		absentErr.Error() != outOfScopeErr.Error() ||
		absentErr.Error() != notFoundCRUD().Error() {
		t.Fatalf(
			"ordinary denial parity = (absent %v, out-of-scope %v); want identical static NotFound",
			absentErr,
			outOfScopeErr,
		)
	}

	_, scopedExecutionErr := fixture.service.GetExecution(
		fixture.scoped,
		connect.NewRequest(&powermanagev1.GetExecutionRequest{
			Id: scopeOutExecutionID,
		}),
	)
	wantPermissionDenied := permissionDeniedCRUD()
	if scopedExecutionErr == nil ||
		connect.CodeOf(scopedExecutionErr) != connect.CodePermissionDenied ||
		scopedExecutionErr.Error() != wantPermissionDenied.Error() {
		t.Fatalf(
			"scoped execution denial = %v; want static PermissionDenied",
			scopedExecutionErr,
		)
	}

	_, globalMissingErr := fixture.service.GetExecution(
		fixture.admin,
		connect.NewRequest(&powermanagev1.GetExecutionRequest{Id: scopeMissingID}),
	)
	if globalMissingErr == nil ||
		connect.CodeOf(globalMissingErr) != connect.CodeNotFound ||
		globalMissingErr.Error() != notFoundCRUD().Error() {
		t.Fatalf(
			"global missing execution error = %v; want static NotFound",
			globalMissingErr,
		)
	}
}

func authorizationScopeCases() []authorizationScopeCase {
	return []authorizationScopeCase{
		{
			permission: "action_sets.manage",
			exercise: func(t *testing.T, fixture *authorizationScopeFixture) {
				got, err := fixture.service.GetActionSet(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetActionSetRequest{
						Id: scopeActionSetID,
					}),
				)
				if err != nil || got.Msg.GetActionSet().GetId() != scopeActionSetID {
					t.Fatalf("transitive action-set read = (%#v, %v); want assigned set", got, err)
				}
				list, err := fixture.service.ListActionSets(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.ListActionSetsRequest{Limit: 100}),
				)
				if err != nil || len(list.Msg.GetActionSets()) != 1 ||
					list.Msg.GetActionSets()[0].GetId() != scopeActionSetID {
					t.Fatalf("scoped action-set list = (%#v, %v); want assigned set", list, err)
				}
				_, err = fixture.service.UpdateActionSet(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.UpdateActionSetRequest{
						Id:              scopeActionSetID,
						Name:            "forbidden",
						ExpectedVersion: 1,
					}),
				)
				requireScopeError(t, err, notFoundCRUD())
			},
		},
		{
			permission: "actions.manage",
			exercise: func(t *testing.T, fixture *authorizationScopeFixture) {
				got, err := fixture.service.GetAction(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetActionRequest{
						Id: scopeActionID,
					}),
				)
				if err != nil ||
					got.Msg.GetManagedAction().GetAction().GetId() != scopeActionID {
					t.Fatalf("transitive action read = (%#v, %v); want assigned action", got, err)
				}
				list, err := fixture.service.ListActions(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.ListActionsRequest{Limit: 100}),
				)
				if err != nil || len(list.Msg.GetManagedActions()) != 1 ||
					list.Msg.GetManagedActions()[0].GetAction().GetId() != scopeActionID {
					t.Fatalf("scoped action list = (%#v, %v); want assigned action", list, err)
				}
				_, err = fixture.service.UpdateAction(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.UpdateActionRequest{
						Action: &powermanagev1.Action{
							Id: scopeActionID, Name: "forbidden", Params: fixture.params,
						},
						ExpectedVersion: 1,
					}),
				)
				requireScopeError(t, err, notFoundCRUD())
			},
		},
		{
			permission: "audit.read",
			exercise: func(t *testing.T, fixture *authorizationScopeFixture) {
				list, err := fixture.service.ListAuditEvents(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.ListAuditEventsRequest{Limit: 200}),
				)
				if err != nil {
					t.Fatalf("list scoped audit events: %v", err)
				}
				var sawInScope, sawOutOfScope bool
				for _, event := range list.Msg.GetAuditEvents() {
					if event.GetStreamType() != "user" {
						continue
					}
					sawInScope = sawInScope || event.GetStreamId() == identityInScopeID
					sawOutOfScope = sawOutOfScope ||
						event.GetStreamId() == identityOutOfScopeID
				}
				if !sawInScope || sawOutOfScope {
					t.Fatalf(
						"scoped audit users = (in %t, out %t); want (true, false)",
						sawInScope,
						sawOutOfScope,
					)
				}
			},
		},
		{
			permission: "devices.manage",
			exercise: func(t *testing.T, fixture *authorizationScopeFixture) {
				got, err := fixture.service.GetDeviceGroup(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetDeviceGroupRequest{
						Id: identityDeviceGroupID,
					}),
				)
				if err != nil || got.Msg.GetDeviceGroup().GetId() != identityDeviceGroupID {
					t.Fatalf("scoped device-group read = (%#v, %v); want managed group", got, err)
				}
				_, err = fixture.service.GetDeviceGroup(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetDeviceGroupRequest{
						Id: scopeOutDeviceGroupID,
					}),
				)
				requireScopeError(t, err, notFoundCRUD())
				list, err := fixture.service.ListDeviceGroups(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.ListDeviceGroupsRequest{Limit: 100}),
				)
				if err != nil || len(list.Msg.GetDeviceGroups()) != 1 ||
					list.Msg.GetDeviceGroups()[0].GetId() != identityDeviceGroupID {
					t.Fatalf("scoped device-group list = (%#v, %v); want managed group", list, err)
				}
				_, err = fixture.service.UpdateDeviceGroup(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.UpdateDeviceGroupRequest{
						Id:              scopeOutDeviceGroupID,
						Name:            "forbidden",
						ExpectedVersion: 1,
					}),
				)
				requireScopeError(t, err, notFoundCRUD())
			},
		},
		{
			permission: "executions.read",
			exercise: func(t *testing.T, fixture *authorizationScopeFixture) {
				got, err := fixture.service.GetExecution(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetExecutionRequest{
						Id: scopeInExecutionID,
					}),
				)
				if err != nil || got.Msg.GetExecution().GetId() != scopeInExecutionID {
					t.Fatalf("scoped execution read = (%#v, %v); want in-scope execution", got, err)
				}
				list, err := fixture.service.ListExecutions(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.ListExecutionsRequest{Limit: 100}),
				)
				if err != nil || len(list.Msg.GetExecutions()) != 1 ||
					list.Msg.GetExecutions()[0].GetId() != scopeInExecutionID {
					t.Fatalf("scoped execution list = (%#v, %v); want one execution", list, err)
				}
				_, err = fixture.service.GetExecution(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetExecutionRequest{
						Id: scopeOutExecutionID,
					}),
				)
				requireScopeError(t, err, permissionDeniedCRUD())
			},
		},
		{
			permission: "user_groups.manage",
			exercise: func(t *testing.T, fixture *authorizationScopeFixture) {
				got, err := fixture.service.GetUserGroup(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetUserGroupRequest{
						Id: identityGroupID,
					}),
				)
				if err != nil || got.Msg.GetUserGroup().GetId() != identityGroupID {
					t.Fatalf("scoped user-group read = (%#v, %v); want operators", got, err)
				}
				_, err = fixture.service.GetUserGroup(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetUserGroupRequest{
						Id: scopeOutUserGroupID,
					}),
				)
				requireScopeError(t, err, notFoundCRUD())
				list, err := fixture.service.ListUserGroups(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.ListUserGroupsRequest{Limit: 100}),
				)
				if err != nil || len(list.Msg.GetUserGroups()) != 1 ||
					list.Msg.GetUserGroups()[0].GetId() != identityGroupID {
					t.Fatalf("scoped user-group list = (%#v, %v); want operators", list, err)
				}
			},
		},
		{
			permission: "users.manage",
			exercise: func(t *testing.T, fixture *authorizationScopeFixture) {
				got, err := fixture.service.GetUser(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetUserRequest{
						Id: identityInScopeID,
					}),
				)
				if err != nil || got.Msg.GetUser().GetId() != identityInScopeID {
					t.Fatalf("scoped user read = (%#v, %v); want group member", got, err)
				}
				_, err = fixture.service.GetUser(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.GetUserRequest{
						Id: identityOutOfScopeID,
					}),
				)
				requireScopeError(t, err, notFoundCRUD())
				list, err := fixture.service.ListUsers(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.ListUsersRequest{Limit: 100}),
				)
				if err != nil || len(list.Msg.GetUsers()) != 1 ||
					list.Msg.GetUsers()[0].GetId() != identityInScopeID {
					t.Fatalf("scoped user list = (%#v, %v); want group member", list, err)
				}
				_, err = fixture.service.UpdateUser(
					fixture.scoped,
					connect.NewRequest(&powermanagev1.UpdateUserRequest{
						Id:              identityOutOfScopeID,
						Email:           "forbidden@example.test",
						ExpectedVersion: 1,
					}),
				)
				requireScopeError(t, err, notFoundCRUD())

				self, err := fixture.service.GetUser(
					fixture.self,
					connect.NewRequest(&powermanagev1.GetUserRequest{Id: identitySelfID}),
				)
				if err != nil || self.Msg.GetUser().GetId() != identitySelfID {
					t.Fatalf("self user read = (%#v, %v); want caller", self, err)
				}
				_, err = fixture.service.GetUser(
					fixture.self,
					connect.NewRequest(&powermanagev1.GetUserRequest{
						Id: identityInScopeID,
					}),
				)
				requireScopeError(t, err, notFoundCRUD())
				_, err = fixture.service.GetUser(
					fixture.self,
					connect.NewRequest(&powermanagev1.GetUserRequest{}),
				)
				requireScopeError(t, err, invalidCRUDRequest())
			},
		},
	}
}

func newAuthorizationScopeFixture(t *testing.T) *authorizationScopeFixture {
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
	fixture := &authorizationScopeFixture{
		service: service,
		admin:   identityContext(t, identityAdminID),
		scoped:  identityContext(t, identityScopedID),
		self:    identityContext(t, identitySelfID),
		params: &powermanagev1.ActionParams{
			Params: &powermanagev1.ActionParams_Package{
				Package: &powermanagev1.PackageParams{},
			},
		},
	}
	if _, err := service.CreateDeviceGroup(fixture.admin, connect.NewRequest(
		&powermanagev1.CreateDeviceGroupRequest{
			Id: scopeOutDeviceGroupID, Name: "outside devices",
		},
	)); err != nil {
		t.Fatalf("create out-of-scope device group: %v", err)
	}
	if _, err := service.CreateUserGroup(fixture.admin, connect.NewRequest(
		&powermanagev1.CreateUserGroupRequest{
			Id: scopeOutUserGroupID, Name: "outside users",
		},
	)); err != nil {
		t.Fatalf("create out-of-scope user group: %v", err)
	}
	if _, err := service.CreateAction(fixture.admin, connect.NewRequest(
		&powermanagev1.CreateActionRequest{Action: &powermanagev1.Action{
			Id: scopeActionID, Name: "scope action", Params: fixture.params,
		}},
	)); err != nil {
		t.Fatalf("create scope action: %v", err)
	}
	if _, err := service.CreateActionSet(fixture.admin, connect.NewRequest(
		&powermanagev1.CreateActionSetRequest{
			Id: scopeActionSetID, Name: "scope set",
		},
	)); err != nil {
		t.Fatalf("create scope action set: %v", err)
	}
	for _, request := range []*powermanagev1.CreateAssignmentRequest{
		{
			Id:         scopeActionAssignmentID,
			SourceKind: powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION,
			SourceId:   scopeActionID,
			TargetKind: powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER_GROUP,
			TargetId:   identityGroupID,
			Mode:       powermanagev1.AssignmentMode_ASSIGNMENT_MODE_APPLY,
		},
		{
			Id:         scopeActionSetAssignmentID,
			SourceKind: powermanagev1.AssignmentSourceKind_ASSIGNMENT_SOURCE_KIND_ACTION_SET,
			SourceId:   scopeActionSetID,
			TargetKind: powermanagev1.AssignmentTargetKind_ASSIGNMENT_TARGET_KIND_USER_GROUP,
			TargetId:   identityGroupID,
			Mode:       powermanagev1.AssignmentMode_ASSIGNMENT_MODE_APPLY,
		},
	} {
		if _, err := service.CreateAssignment(
			fixture.admin,
			connect.NewRequest(request),
		); err != nil {
			t.Fatalf("create scope assignment %s: %v", request.GetId(), err)
		}
	}
	telemetry, err := store.NewTelemetryStore(pool)
	if err != nil {
		t.Fatalf("create telemetry store: %v", err)
	}
	for _, binding := range []struct {
		executionID string
		deviceID    string
	}{
		{scopeInExecutionID, identityDeviceID},
		{scopeOutExecutionID, scopeOutExecutionDeviceID},
	} {
		if err := telemetry.BindExecutionOutputToDevice(
			t.Context(),
			binding.executionID,
			binding.deviceID,
		); err != nil {
			t.Fatalf("bind scope execution %s: %v", binding.executionID, err)
		}
	}
	return fixture
}

func requireScopeError(t *testing.T, err, want error) {
	t.Helper()
	if err == nil ||
		connect.CodeOf(err) != connect.CodeOf(want) ||
		err.Error() != want.Error() {
		t.Fatalf("scope error = %v; want %v", err, want)
	}
}
