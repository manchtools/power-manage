package store

import "testing"

const (
	testDeviceGroupID = "01J00000000000000000000071"
)

func TestDeviceGroupEvents_ProjectUpdateDeleteAndRebuild(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	created, err := DeviceGroupCreatedEvent(testDeviceGroupID, "production", "platform = 'linux'")
	if err != nil {
		t.Fatalf("create device-group event: %v", err)
	}
	if err := eventStore.AppendEvent(t.Context(), created); err != nil {
		t.Fatalf("append device-group creation: %v", err)
	}
	group, err := eventStore.DeviceGroupByID(
		t.Context(),
		testDeviceGroupID,
		true,
		nil,
	)
	if err != nil || group.Name != "production" || group.ProjectionVersion != 1 {
		t.Fatalf("created projection = (%#v, %v); want production version one", group, err)
	}

	updated, err := DeviceGroupUpdatedEvent(testDeviceGroupID, "linux-production", "")
	if err != nil {
		t.Fatalf("create device-group update: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), updated, 1); err != nil {
		t.Fatalf("append device-group update: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), updated, 1); !IsVersionConflict(err) {
		t.Fatalf("stale update error = %v; want version conflict", err)
	}
	group, err = eventStore.DeviceGroupByID(t.Context(), testDeviceGroupID, true, nil)
	if err != nil || group.Name != "linux-production" ||
		group.DynamicQuery != "" || group.ProjectionVersion != 2 {
		t.Fatalf("updated projection = (%#v, %v); want full replacement version two", group, err)
	}

	if err := eventStore.RebuildAll(t.Context(), DeviceGroupRebuildTarget); err != nil {
		t.Fatalf("rebuild device groups: %v", err)
	}
	group, err = eventStore.DeviceGroupByID(t.Context(), testDeviceGroupID, true, nil)
	if err != nil || group.Name != "linux-production" || group.ProjectionVersion != 2 {
		t.Fatalf("rebuilt projection = (%#v, %v); want updated version two", group, err)
	}

	deleted, err := DeviceGroupDeletedEvent(testDeviceGroupID)
	if err != nil {
		t.Fatalf("create device-group deletion: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), deleted, 2); err != nil {
		t.Fatalf("append device-group deletion: %v", err)
	}
	if _, err := eventStore.DeviceGroupByID(t.Context(), testDeviceGroupID, true, nil); !IsNotFound(err) {
		t.Fatalf("deleted projection error = %v; want not found", err)
	}
	if err := eventStore.RebuildAll(t.Context(), DeviceGroupRebuildTarget); err != nil {
		t.Fatalf("rebuild deleted device group: %v", err)
	}
	if _, err := eventStore.DeviceGroupByID(t.Context(), testDeviceGroupID, true, nil); !IsNotFound(err) {
		t.Fatalf("rebuilt deletion error = %v; want not found", err)
	}
}

func TestDeviceGroupReads_RequireExplicitScope(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	created, err := DeviceGroupCreatedEvent(testDeviceGroupID, "production", "")
	if err != nil {
		t.Fatalf("create device-group event: %v", err)
	}
	if err := eventStore.AppendEvent(t.Context(), created); err != nil {
		t.Fatalf("append device-group creation: %v", err)
	}
	if _, err := eventStore.DeviceGroupByID(t.Context(), testDeviceGroupID, false, nil); !IsNotFound(err) {
		t.Fatalf("empty-scope detail error = %v; want not found", err)
	}
	groups, err := eventStore.ListDeviceGroups(t.Context(), false, nil, 100)
	if err != nil || len(groups) != 0 {
		t.Fatalf("empty-scope list = (%#v, %v); want empty", groups, err)
	}
}
