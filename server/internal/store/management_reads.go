package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const maxManagementReadPageSize int32 = 200

// AuditEventMetadata is the payload-free audit-list view. Payload redaction and
// export remain owned by SPEC-011.
type AuditEventMetadata struct {
	StreamType     string
	StreamID       string
	StreamVersion  int64
	EventType      string
	PayloadVersion int32
	CreatedAt      time.Time
	GlobalPosition int64
}

// Execution is the bounded operational metadata for one execution output.
type Execution struct {
	ExecutionID  string
	DeviceID     string
	OutputBytes  int64
	OutputChunks int32
	Truncated    bool
	UpdatedAt    time.Time
}

// InventorySnapshot is one latest non-deleted agent inventory projection.
type InventorySnapshot struct {
	AgentID           string
	ProjectionVersion int64
	PayloadVersion    int32
	Snapshot          []byte
	UpdatedAt         time.Time
}

// GatewaySummary omits certificate DER while retaining its integrity identity.
type GatewaySummary struct {
	GatewayID              string
	ProjectionVersion      int64
	CertificateFingerprint []byte
	RegistrationTokenID    string
	Owner                  string
	DNSNames               []string
	LifecycleState         GatewayLifecycleState
	UpdatedAt              time.Time
}

// ListAuditEvents returns payload-free events through the caller's scope.
func (s *Store) ListAuditEvents(
	ctx context.Context,
	global bool,
	deviceGroupIDs []string,
	userGroupIDs []string,
	selfID string,
	limit int32,
) ([]AuditEventMetadata, error) {
	if err := validateManagementRead(s, ctx, limit); err != nil {
		return nil, err
	}
	deviceGroupIDs, err := normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return nil, err
	}
	userGroupIDs, err = normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return nil, err
	}
	if selfID != "" {
		selfID, err = canonicalUserID(selfID)
		if err != nil {
			return nil, err
		}
	}
	rows, err := generated.New(s.pool).ListScopedAuditEvents(
		ctx,
		generated.ListScopedAuditEventsParams{
			GlobalScope:    global,
			SelfID:         selfID,
			DeviceGroupIds: deviceGroupIDs,
			UserGroupIds:   userGroupIDs,
			PageLimit:      limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list audit events: %w", err)
	}
	events := make([]AuditEventMetadata, len(rows))
	for index, row := range rows {
		if strings.TrimSpace(row.StreamType) == "" ||
			strings.TrimSpace(row.StreamID) == "" ||
			row.StreamVersion <= 0 ||
			strings.TrimSpace(row.EventType) == "" ||
			row.PayloadVersion <= 0 ||
			row.CreatedAt.IsZero() ||
			row.GlobalPosition <= 0 {
			return nil, errors.New("store: invalid audit event metadata")
		}
		events[index] = AuditEventMetadata{
			StreamType: row.StreamType, StreamID: row.StreamID,
			StreamVersion: row.StreamVersion, EventType: row.EventType,
			PayloadVersion: row.PayloadVersion, CreatedAt: row.CreatedAt,
			GlobalPosition: row.GlobalPosition,
		}
	}
	return events, nil
}

// ExecutionByID returns one execution through its target-device relation.
func (s *Store) ExecutionByID(
	ctx context.Context,
	executionID string,
	global bool,
	deviceGroupIDs []string,
) (Execution, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return Execution{}, errors.New("store: execution read is not wired")
	}
	id, err := canonicalManagementReadID(executionID, "execution")
	if err != nil {
		return Execution{}, err
	}
	deviceGroupIDs, err = normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return Execution{}, err
	}
	row, err := generated.New(s.pool).GetScopedExecution(
		ctx,
		generated.GetScopedExecutionParams{
			ExecutionID:    id,
			GlobalScope:    global,
			DeviceGroupIds: deviceGroupIDs,
		},
	)
	if err != nil {
		return Execution{}, fmt.Errorf("store: read execution: %w", err)
	}
	return executionFromRow(
		row.ExecutionID,
		row.DeviceID,
		row.OutputBytes,
		row.OutputChunks,
		row.Truncated,
		row.UpdatedAt,
	)
}

// ListExecutions returns execution metadata through target-device reach.
func (s *Store) ListExecutions(
	ctx context.Context,
	global bool,
	deviceGroupIDs []string,
	limit int32,
) ([]Execution, error) {
	if err := validateManagementRead(s, ctx, limit); err != nil {
		return nil, err
	}
	deviceGroupIDs, err := normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return nil, err
	}
	rows, err := generated.New(s.pool).ListScopedExecutions(
		ctx,
		generated.ListScopedExecutionsParams{
			GlobalScope: global, DeviceGroupIds: deviceGroupIDs, PageLimit: limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list executions: %w", err)
	}
	executions := make([]Execution, len(rows))
	for index, row := range rows {
		executions[index], err = executionFromRow(
			row.ExecutionID,
			row.DeviceID,
			row.OutputBytes,
			row.OutputChunks,
			row.Truncated,
			row.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
	}
	return executions, nil
}

func executionFromRow(
	executionID string,
	deviceID string,
	outputBytes int64,
	outputChunks int32,
	truncated bool,
	updatedAt time.Time,
) (Execution, error) {
	id, err := canonicalManagementReadID(executionID, "execution")
	if err != nil ||
		outputBytes < 0 ||
		outputBytes > maxExecutionOutputBytes ||
		outputChunks < 0 ||
		outputChunks > maxExecutionOutputChunks ||
		updatedAt.IsZero() {
		return Execution{}, errors.New("store: invalid execution projection")
	}
	deviceID, err = canonicalDeviceID(deviceID)
	if err != nil {
		return Execution{}, errors.New("store: invalid execution target")
	}
	return Execution{
		ExecutionID: id, DeviceID: deviceID, OutputBytes: outputBytes,
		OutputChunks: outputChunks, Truncated: truncated, UpdatedAt: updatedAt,
	}, nil
}

// InventorySnapshotByID reads one live snapshot through device-group reach.
func (s *Store) InventorySnapshotByID(
	ctx context.Context,
	agentID string,
	global bool,
	deviceGroupIDs []string,
) (InventorySnapshot, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return InventorySnapshot{}, errors.New("store: inventory read is not wired")
	}
	id, err := canonicalDeviceID(agentID)
	if err != nil {
		return InventorySnapshot{}, err
	}
	deviceGroupIDs, err = normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return InventorySnapshot{}, err
	}
	row, err := generated.New(s.pool).GetScopedInventorySnapshot(
		ctx,
		generated.GetScopedInventorySnapshotParams{
			AgentID: id, GlobalScope: global, DeviceGroupIds: deviceGroupIDs,
		},
	)
	if err != nil {
		return InventorySnapshot{}, fmt.Errorf("store: read inventory snapshot: %w", err)
	}
	return inventorySnapshotFromRow(
		row.AgentID,
		row.ProjectionVersion,
		row.PayloadVersion,
		row.Snapshot,
		row.UpdatedAt,
	)
}

// ListInventorySnapshots returns live latest-state inventory through scope.
func (s *Store) ListInventorySnapshots(
	ctx context.Context,
	global bool,
	deviceGroupIDs []string,
	limit int32,
) ([]InventorySnapshot, error) {
	if err := validateManagementRead(s, ctx, limit); err != nil {
		return nil, err
	}
	deviceGroupIDs, err := normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return nil, err
	}
	rows, err := generated.New(s.pool).ListScopedInventorySnapshots(
		ctx,
		generated.ListScopedInventorySnapshotsParams{
			GlobalScope: global, DeviceGroupIds: deviceGroupIDs, PageLimit: limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list inventory snapshots: %w", err)
	}
	snapshots := make([]InventorySnapshot, len(rows))
	for index, row := range rows {
		snapshots[index], err = inventorySnapshotFromRow(
			row.AgentID,
			row.ProjectionVersion,
			row.PayloadVersion,
			row.Snapshot,
			row.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
	}
	return snapshots, nil
}

func inventorySnapshotFromRow(
	agentID string,
	projectionVersion int64,
	payloadVersion int32,
	snapshot []byte,
	updatedAt time.Time,
) (InventorySnapshot, error) {
	id, err := canonicalDeviceID(agentID)
	if err != nil ||
		projectionVersion <= 0 ||
		payloadVersion <= 0 ||
		len(snapshot) == 0 ||
		len(snapshot) > maxInventorySnapshotBytes ||
		updatedAt.IsZero() {
		return InventorySnapshot{}, errors.New("store: invalid inventory projection")
	}
	return InventorySnapshot{
		AgentID: id, ProjectionVersion: projectionVersion,
		PayloadVersion: payloadVersion, Snapshot: bytes.Clone(snapshot),
		UpdatedAt: updatedAt,
	}, nil
}

// GatewaySummaryByID reads one gateway only under global reach.
func (s *Store) GatewaySummaryByID(
	ctx context.Context,
	gatewayID string,
	global bool,
) (GatewaySummary, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return GatewaySummary{}, errors.New("store: gateway read is not wired")
	}
	id, err := canonicalGatewayID(gatewayID)
	if err != nil {
		return GatewaySummary{}, err
	}
	row, err := generated.New(s.pool).GetGlobalGateway(
		ctx,
		generated.GetGlobalGatewayParams{GatewayID: id, GlobalScope: global},
	)
	if err != nil {
		return GatewaySummary{}, fmt.Errorf("store: read gateway summary: %w", err)
	}
	return gatewaySummaryFromFields(
		row.GatewayID,
		row.ProjectionVersion,
		row.CertificateFingerprint,
		row.RegistrationTokenID,
		row.Owner,
		row.DnsNames,
		row.LifecycleState,
		row.UpdatedAt,
	)
}

// ListGatewaySummaries returns gateway metadata only under global reach.
func (s *Store) ListGatewaySummaries(
	ctx context.Context,
	global bool,
	limit int32,
) ([]GatewaySummary, error) {
	if err := validateManagementRead(s, ctx, limit); err != nil {
		return nil, err
	}
	rows, err := generated.New(s.pool).ListGlobalGateways(
		ctx,
		generated.ListGlobalGatewaysParams{GlobalScope: global, PageLimit: limit},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list gateway summaries: %w", err)
	}
	gateways := make([]GatewaySummary, len(rows))
	for index, row := range rows {
		gateways[index], err = gatewaySummaryFromFields(
			row.GatewayID,
			row.ProjectionVersion,
			row.CertificateFingerprint,
			row.RegistrationTokenID,
			row.Owner,
			row.DnsNames,
			row.LifecycleState,
			row.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
	}
	return gateways, nil
}

func gatewaySummaryFromFields(
	gatewayID string,
	projectionVersion int64,
	fingerprint []byte,
	registrationTokenID string,
	owner string,
	dnsNames []string,
	lifecycleState string,
	updatedAt time.Time,
) (GatewaySummary, error) {
	id, err := canonicalGatewayID(gatewayID)
	if err != nil ||
		projectionVersion <= 0 ||
		len(fingerprint) != sha256.Size ||
		updatedAt.IsZero() {
		return GatewaySummary{}, errors.New("store: invalid gateway summary projection")
	}
	tokenID, err := canonicalRegistrationTokenID(registrationTokenID)
	if err != nil ||
		!utf8.ValidString(owner) ||
		len(owner) > maxRegistrationTokenOwnerBytes {
		return GatewaySummary{}, errors.New("store: invalid gateway summary metadata")
	}
	dnsNames, err = validateRegistrationTokenPurpose(
		RegistrationTokenPurposeGateway,
		dnsNames,
	)
	if err != nil {
		return GatewaySummary{}, errors.New("store: invalid gateway summary metadata")
	}
	state := GatewayLifecycleState(lifecycleState)
	if state != GatewayLifecycleActive && state != GatewayLifecycleRevoked {
		return GatewaySummary{}, errors.New("store: invalid gateway summary state")
	}
	return GatewaySummary{
		GatewayID: id, ProjectionVersion: projectionVersion,
		CertificateFingerprint: bytes.Clone(fingerprint),
		RegistrationTokenID:    tokenID, Owner: owner,
		DNSNames: slices.Clone(dnsNames), LifecycleState: state,
		UpdatedAt: updatedAt,
	}, nil
}

func validateManagementRead(s *Store, ctx context.Context, limit int32) error {
	if s == nil || s.pool == nil || ctx == nil {
		return errors.New("store: management read is not wired")
	}
	if limit <= 0 || limit > maxManagementReadPageSize {
		return errors.New("store: management read limit is invalid")
	}
	return nil
}

func canonicalManagementReadID(value string, kind string) (string, error) {
	if err := validate.ULIDPathID(value); err != nil {
		return "", fmt.Errorf("store: invalid %s ID: %w", kind, err)
	}
	return strings.ToUpper(value), nil
}
