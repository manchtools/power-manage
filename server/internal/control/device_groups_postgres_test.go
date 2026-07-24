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
	deviceGroupAdminID    = "01J00000000000000000000091"
	deviceGroupScopedID   = "01J00000000000000000000092"
	deviceGroupRoleID     = "01J00000000000000000000093"
	deviceGroupAdminGrant = "01J00000000000000000000094"
	deviceGroupScopeGrant = "01J00000000000000000000095"
	deviceGroupInScope    = "01J00000000000000000000096"
	deviceGroupOutOfScope = "01J00000000000000000000097"
)

func TestDeviceGroupHandlers_CRUDScopeOCCAndDelete(t *testing.T) {
	pool := crlRotationPostgres.Database(t, store.Migrate)
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	appendDeviceGroupAuthorizationFixtures(t, eventStore)
	gate, err := auth.NewAuthorizationGate(eventStore)
	if err != nil {
		t.Fatalf("create authorization gate: %v", err)
	}
	service, err := NewManagementService(eventStore, gate)
	if err != nil {
		t.Fatalf("create management service: %v", err)
	}
	admin := deviceGroupContext(t, deviceGroupAdminID)
	scoped := deviceGroupContext(t, deviceGroupScopedID)

	created, err := service.CreateDeviceGroup(admin, connect.NewRequest(
		&powermanagev1.CreateDeviceGroupRequest{
			Id:           deviceGroupInScope,
			Name:         "production",
			DynamicQuery: "platform = 'linux'",
		},
	))
	if err != nil {
		t.Fatalf("create in-scope device group: %v", err)
	}
	if got := created.Msg.GetDeviceGroup(); got.GetId() != deviceGroupInScope ||
		got.GetName() != "production" ||
		got.GetDynamicQuery() != "platform = 'linux'" ||
		got.GetVersion() != 1 {
		t.Fatalf("created device group = %#v; want exact version-one projection", got)
	}
	if _, err := service.CreateDeviceGroup(admin, connect.NewRequest(
		&powermanagev1.CreateDeviceGroupRequest{
			Id:   deviceGroupInScope,
			Name: "duplicate",
		},
	)); connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("duplicate create code = %v; want AlreadyExists", connect.CodeOf(err))
	}
	if _, err := service.CreateDeviceGroup(admin, connect.NewRequest(
		&powermanagev1.CreateDeviceGroupRequest{
			Id:   deviceGroupOutOfScope,
			Name: "staging",
		},
	)); err != nil {
		t.Fatalf("create out-of-scope fixture as global admin: %v", err)
	}
	if _, err := service.CreateDeviceGroup(scoped, connect.NewRequest(
		&powermanagev1.CreateDeviceGroupRequest{
			Id:   "01J00000000000000000000098",
			Name: "forbidden-create",
		},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope create code = %v; want NotFound", connect.CodeOf(err))
	}
	adminList, err := service.ListDeviceGroups(admin, connect.NewRequest(
		&powermanagev1.ListDeviceGroupsRequest{Limit: 100},
	))
	if err != nil || len(adminList.Msg.GetDeviceGroups()) != 2 {
		t.Fatalf("global list = (%#v, %v); want both device groups", adminList, err)
	}

	got, err := service.GetDeviceGroup(scoped, connect.NewRequest(
		&powermanagev1.GetDeviceGroupRequest{Id: deviceGroupInScope},
	))
	if err != nil || got.Msg.GetDeviceGroup().GetVersion() != 1 {
		t.Fatalf("scoped get = (%#v, %v); want visible version one", got, err)
	}
	listed, err := service.ListDeviceGroups(scoped, connect.NewRequest(
		&powermanagev1.ListDeviceGroupsRequest{Limit: 100},
	))
	if err != nil {
		t.Fatalf("scoped list: %v", err)
	}
	if groups := listed.Msg.GetDeviceGroups(); len(groups) != 1 ||
		groups[0].GetId() != deviceGroupInScope {
		t.Fatalf("scoped list = %#v; want only %s", groups, deviceGroupInScope)
	}
	if _, err := service.GetDeviceGroup(scoped, connect.NewRequest(
		&powermanagev1.GetDeviceGroupRequest{Id: deviceGroupOutOfScope},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope get code = %v; want NotFound", connect.CodeOf(err))
	}

	updated, err := service.UpdateDeviceGroup(scoped, connect.NewRequest(
		&powermanagev1.UpdateDeviceGroupRequest{
			Id:              deviceGroupInScope,
			Name:            "production-linux",
			DynamicQuery:    "platform = 'linux' AND environment = 'production'",
			ExpectedVersion: 1,
		},
	))
	if err != nil {
		t.Fatalf("update in-scope device group: %v", err)
	}
	if group := updated.Msg.GetDeviceGroup(); group.GetVersion() != 2 ||
		group.GetName() != "production-linux" ||
		group.GetDynamicQuery() != "platform = 'linux' AND environment = 'production'" {
		t.Fatalf("updated device group = %#v; want full replacement at version two", group)
	}
	if _, err := service.UpdateDeviceGroup(scoped, connect.NewRequest(
		&powermanagev1.UpdateDeviceGroupRequest{
			Id:              deviceGroupInScope,
			Name:            "stale",
			ExpectedVersion: 1,
		},
	)); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale update code = %v; want Aborted", connect.CodeOf(err))
	}
	if _, err := service.UpdateDeviceGroup(scoped, connect.NewRequest(
		&powermanagev1.UpdateDeviceGroupRequest{
			Id:              deviceGroupOutOfScope,
			Name:            "forbidden",
			ExpectedVersion: 1,
		},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope update code = %v; want NotFound", connect.CodeOf(err))
	}

	if _, err := service.DeleteDeviceGroup(scoped, connect.NewRequest(
		&powermanagev1.DeleteDeviceGroupRequest{
			Id:              deviceGroupInScope,
			ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete in-scope device group: %v", err)
	}
	if _, err := service.GetDeviceGroup(scoped, connect.NewRequest(
		&powermanagev1.GetDeviceGroupRequest{Id: deviceGroupInScope},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("deleted get code = %v; want NotFound", connect.CodeOf(err))
	}
}

func appendDeviceGroupAuthorizationFixtures(t *testing.T, eventStore *store.Store) {
	t.Helper()
	admin, err := store.UserCreatedEvent(deviceGroupAdminID, "crud-admin@example.test")
	if err != nil {
		t.Fatalf("create admin fixture: %v", err)
	}
	scoped, err := store.UserCreatedEvent(deviceGroupScopedID, "crud-scoped@example.test")
	if err != nil {
		t.Fatalf("create scoped fixture: %v", err)
	}
	role, err := store.AuthorizationRoleCreatedEvent(
		deviceGroupRoleID,
		"crud-device-group-managers",
		[]authz.Permission{"devices.manage"},
	)
	if err != nil {
		t.Fatalf("create role fixture: %v", err)
	}
	adminGrant, err := store.AuthorizationGrantCreatedEvent(
		deviceGroupAdminGrant,
		authz.PrincipalUser,
		deviceGroupAdminID,
		deviceGroupRoleID,
		authz.Scope{Kind: authz.ScopeGlobal},
	)
	if err != nil {
		t.Fatalf("create global grant fixture: %v", err)
	}
	scopedGrant, err := store.AuthorizationGrantCreatedEvent(
		deviceGroupScopeGrant,
		authz.PrincipalUser,
		deviceGroupScopedID,
		deviceGroupRoleID,
		authz.Scope{
			Kind: authz.ScopeDeviceGroups,
			IDs:  []string{deviceGroupInScope},
		},
	)
	if err != nil {
		t.Fatalf("create scoped grant fixture: %v", err)
	}
	if err := eventStore.AppendEvents(
		t.Context(),
		[]store.Event{admin, scoped, role, adminGrant, scopedGrant},
	); err != nil {
		t.Fatalf("append authorization fixtures: %v", err)
	}
}

func deviceGroupContext(t *testing.T, subject string) context.Context {
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
