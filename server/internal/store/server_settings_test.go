package store

import "testing"

const testServerSettingID = "01J00000000000000000000150"

func TestServerSetting_CRUDAndRebuild(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	created, err := ServerSettingCreatedEvent(
		testServerSettingID,
		"display-name",
		"Power Manage",
	)
	if err != nil {
		t.Fatalf("create server-setting event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), created, 0); err != nil {
		t.Fatalf("append server-setting creation: %v", err)
	}
	settings, err := eventStore.ListServerSettings(t.Context(), 100)
	if err != nil || len(settings) != 1 ||
		settings[0].ID != testServerSettingID ||
		settings[0].ProjectionVersion != 1 {
		t.Fatalf("server-setting list = (%#v, %v); want version-one setting", settings, err)
	}

	updated, err := ServerSettingUpdatedEvent(
		testServerSettingID,
		"display-name",
		"Managed Fleet",
	)
	if err != nil {
		t.Fatalf("create server-setting update: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), updated, 1); err != nil {
		t.Fatalf("append server-setting update: %v", err)
	}
	if _, err := pool.Exec(
		t.Context(),
		`UPDATE server_settings
		 SET value = 'corrupt'
		 WHERE setting_id = $1`,
		testServerSettingID,
	); err != nil {
		t.Fatalf("corrupt server-setting projection: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), ServerSettingRebuildTarget); err != nil {
		t.Fatalf("rebuild server settings: %v", err)
	}
	setting, err := eventStore.ServerSettingByID(t.Context(), testServerSettingID)
	if err != nil || setting.Value != "Managed Fleet" ||
		setting.ProjectionVersion != 2 {
		t.Fatalf("rebuilt server setting = (%#v, %v); want version-two value", setting, err)
	}

	deleted, err := ServerSettingDeletedEvent(testServerSettingID)
	if err != nil {
		t.Fatalf("create server-setting deletion: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), deleted, 2); err != nil {
		t.Fatalf("append server-setting deletion: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), ServerSettingRebuildTarget); err != nil {
		t.Fatalf("rebuild deleted server setting: %v", err)
	}
	if _, err := eventStore.ServerSettingByID(
		t.Context(),
		testServerSettingID,
	); !IsNotFound(err) {
		t.Fatalf("rebuilt deleted server setting error = %v; want not found", err)
	}
}
