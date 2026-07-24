package control

import (
	"bytes"
	"testing"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	managementOutOfScopeDeviceID    = "01J00000000000000000000171"
	managementExecutionID           = "01J00000000000000000000172"
	managementOutOfScopeExecutionID = "01J00000000000000000000173"
	managementGatewayID             = "01J00000000000000000000174"
	managementGatewayTokenID        = "01J00000000000000000000175"
)

func TestOperationalReadHandlers_RealViewsAndScope(t *testing.T) {
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
	admin := identityContext(t, identityAdminID)
	scoped := identityContext(t, identityScopedID)

	for _, snapshot := range []struct {
		id   string
		body string
	}{
		{identityDeviceID, `{"hostname":"managed"}`},
		{managementOutOfScopeDeviceID, `{"hostname":"other"}`},
	} {
		event, err := store.InventorySnapshotEvent(snapshot.id, []byte(snapshot.body))
		if err != nil {
			t.Fatalf("create inventory event %s: %v", snapshot.id, err)
		}
		if err := eventStore.AppendEvent(t.Context(), event); err != nil {
			t.Fatalf("append inventory event %s: %v", snapshot.id, err)
		}
	}
	telemetry, err := store.NewTelemetryStore(pool)
	if err != nil {
		t.Fatalf("create telemetry store: %v", err)
	}
	for _, execution := range []struct {
		id       string
		deviceID string
	}{
		{managementExecutionID, identityDeviceID},
		{managementOutOfScopeExecutionID, managementOutOfScopeDeviceID},
	} {
		if err := telemetry.BindExecutionOutputToDevice(
			t.Context(),
			execution.id,
			execution.deviceID,
		); err != nil {
			t.Fatalf("bind execution %s: %v", execution.id, err)
		}
		if _, err := telemetry.AppendExecutionOutput(
			t.Context(),
			execution.id,
			[]byte("output"),
		); err != nil {
			t.Fatalf("append execution output %s: %v", execution.id, err)
		}
	}
	if _, err := pool.Exec(
		t.Context(),
		`INSERT INTO gateways (
			gateway_id, projection_version, certificate_der,
			certificate_fingerprint, registration_token_id, owner, dns_names,
			lifecycle_state, updated_at
		) VALUES ($1, 1, $2, $3, $4, $5, $6, 'active', clock_timestamp())`,
		managementGatewayID,
		[]byte{1},
		bytes.Repeat([]byte{2}, 32),
		managementGatewayTokenID,
		"gateway-owner@example.test",
		[]string{"gateway.example.test"},
	); err != nil {
		t.Fatalf("seed gateway projection: %v", err)
	}

	scopedInventory, err := service.ListInventorySnapshots(scoped, connect.NewRequest(
		&powermanagev1.ListInventorySnapshotsRequest{Limit: 100},
	))
	if err != nil || len(scopedInventory.Msg.GetInventorySnapshots()) != 1 ||
		scopedInventory.Msg.GetInventorySnapshots()[0].GetAgentId() != identityDeviceID {
		t.Fatalf("scoped inventory = (%#v, %v); want managed device", scopedInventory, err)
	}
	if _, err := service.GetInventorySnapshot(scoped, connect.NewRequest(
		&powermanagev1.GetInventorySnapshotRequest{Id: managementOutOfScopeDeviceID},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope inventory code = %v; want NotFound", connect.CodeOf(err))
	}

	scopedExecutions, err := service.ListExecutions(scoped, connect.NewRequest(
		&powermanagev1.ListExecutionsRequest{Limit: 100},
	))
	if err != nil || len(scopedExecutions.Msg.GetExecutions()) != 1 ||
		scopedExecutions.Msg.GetExecutions()[0].GetId() != managementExecutionID ||
		scopedExecutions.Msg.GetExecutions()[0].GetOutputChunks() != 1 {
		t.Fatalf("scoped executions = (%#v, %v); want managed execution", scopedExecutions, err)
	}
	if _, err := service.GetExecution(scoped, connect.NewRequest(
		&powermanagev1.GetExecutionRequest{Id: managementOutOfScopeExecutionID},
	)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf(
			"out-of-scope execution code = %v; want PermissionDenied",
			connect.CodeOf(err),
		)
	}

	audit, err := service.ListAuditEvents(scoped, connect.NewRequest(
		&powermanagev1.ListAuditEventsRequest{Limit: 200},
	))
	if err != nil {
		t.Fatalf("list scoped audit: %v", err)
	}
	var sawManagedInventory, sawOtherInventory bool
	for _, event := range audit.Msg.GetAuditEvents() {
		if event.GetStreamType() != "inventory" {
			continue
		}
		sawManagedInventory = sawManagedInventory || event.GetStreamId() == identityDeviceID
		sawOtherInventory = sawOtherInventory ||
			event.GetStreamId() == managementOutOfScopeDeviceID
	}
	if !sawManagedInventory || sawOtherInventory {
		t.Fatalf(
			"scoped audit inventory visibility = (managed %t, other %t); want (true, false)",
			sawManagedInventory,
			sawOtherInventory,
		)
	}

	gateway, err := service.GetGateway(admin, connect.NewRequest(
		&powermanagev1.GetGatewayRequest{Id: managementGatewayID},
	))
	if err != nil || gateway.Msg.GetGateway().GetId() != managementGatewayID ||
		len(gateway.Msg.GetGateway().GetCertificateFingerprint()) != 32 {
		t.Fatalf("gateway detail = (%#v, %v); want safe metadata", gateway, err)
	}
	gateways, err := service.ListGateways(admin, connect.NewRequest(
		&powermanagev1.ListGatewaysRequest{Limit: 100},
	))
	if err != nil || len(gateways.Msg.GetGateways()) != 1 {
		t.Fatalf("gateway list = (%#v, %v); want one gateway", gateways, err)
	}
	if _, err := service.ListGateways(scoped, connect.NewRequest(
		&powermanagev1.ListGatewaysRequest{Limit: 100},
	)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("gateway list without PKI permission code = %v; want PermissionDenied", connect.CodeOf(err))
	}
}
