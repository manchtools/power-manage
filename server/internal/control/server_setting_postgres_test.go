package control

import (
	"testing"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

const managementServerSettingID = "01J00000000000000000000151"

func TestServerSettingHandlers_CRUDConflictAndRebuild(t *testing.T) {
	eventStore, service := identityManagementService(t)
	admin := identityContext(t, identityAdminID)

	created, err := service.CreateServerSetting(admin, connect.NewRequest(
		&powermanagev1.CreateServerSettingRequest{
			Id:    managementServerSettingID,
			Name:  "display-name",
			Value: "Power Manage",
		},
	))
	if err != nil || created.Msg.GetServerSetting().GetVersion() != 1 {
		t.Fatalf("create server setting = (%#v, %v); want version one", created, err)
	}
	listed, err := service.ListServerSettings(admin, connect.NewRequest(
		&powermanagev1.ListServerSettingsRequest{Limit: 100},
	))
	if err != nil || len(listed.Msg.GetServerSettings()) != 1 ||
		listed.Msg.GetServerSettings()[0].GetId() != managementServerSettingID {
		t.Fatalf("server-setting list = (%#v, %v); want created setting", listed, err)
	}
	updated, err := service.UpdateServerSetting(admin, connect.NewRequest(
		&powermanagev1.UpdateServerSettingRequest{
			Id:              managementServerSettingID,
			Name:            "display-name",
			Value:           "Managed Fleet",
			ExpectedVersion: 1,
		},
	))
	if err != nil || updated.Msg.GetServerSetting().GetValue() != "Managed Fleet" ||
		updated.Msg.GetServerSetting().GetVersion() != 2 {
		t.Fatalf("update server setting = (%#v, %v); want version-two value", updated, err)
	}
	if _, err := service.DeleteServerSetting(admin, connect.NewRequest(
		&powermanagev1.DeleteServerSettingRequest{
			Id:              managementServerSettingID,
			ExpectedVersion: 1,
		},
	)); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale server-setting delete code = %v; want Aborted", connect.CodeOf(err))
	}
	if _, err := service.DeleteServerSetting(admin, connect.NewRequest(
		&powermanagev1.DeleteServerSettingRequest{
			Id:              managementServerSettingID,
			ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete server setting: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), store.ServerSettingRebuildTarget); err != nil {
		t.Fatalf("rebuild server settings: %v", err)
	}
	if _, err := eventStore.ServerSettingByID(
		t.Context(),
		managementServerSettingID,
	); !store.IsNotFound(err) {
		t.Fatalf("rebuilt deleted server setting error = %v; want not found", err)
	}
}
