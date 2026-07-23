package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	inventoryStreamType         = "inventory"
	inventorySnapshotEventType  = "InventorySnapshotReplaced"
	inventoryTombstoneEventType = "InventorySnapshotDeleted"
	inventoryPayloadVersion     = 1
	maxInventorySnapshotBytes   = 2 << 20
)

// InventoryRebuildTarget is the CLI-only production inventory recovery target.
const InventoryRebuildTarget = "inventory"

type inventorySnapshotPayload struct {
	Snapshot []byte `json:"snapshot"`
}

type inventoryTombstonePayload struct{}

type eventDefinition struct {
	PayloadVersion int32
	PayloadType    any
	GoldenPayload  func() ([]byte, error)
	Projector      Projector
}

type goldenEvent struct {
	PayloadVersion int32
	Payload        []byte
}

// NewProduction returns the production event-store registry.
func NewProduction(pool *pgxpool.Pool) (*Store, error) {
	definitions := productionEventDefinitions()
	if err := validateGoldenEventCorpus(definitions, goldenEventCorpus()); err != nil {
		return nil, err
	}
	if err := validateEventPayloadTypes(definitions); err != nil {
		return nil, err
	}
	projectors := make(map[string]Projector, len(definitions))
	for eventType, definition := range definitions {
		if definition.Projector == nil {
			return nil, fmt.Errorf("store: production event type %q has a nil projector", eventType)
		}
		projectors[eventType] = definition.Projector
	}
	return New(pool, projectors, productionRebuildTargets())
}

// ProductionRebuildTargetNames returns the exact CLI recovery-target set.
func ProductionRebuildTargetNames() []string {
	return slices.Sorted(maps.Keys(productionRebuildTargets()))
}

func productionRebuildTargets() map[string]RebuildTarget {
	return map[string]RebuildTarget{
		InventoryRebuildTarget: {
			Tables:      []string{"inventory_snapshots"},
			StreamTypes: []string{inventoryStreamType},
			EventTypes:  []string{inventorySnapshotEventType, inventoryTombstoneEventType},
			Reset:       resetInventorySnapshots,
		},
		PersonalAccessTokenRebuildTarget: {
			Tables:      []string{"personal_access_tokens"},
			StreamTypes: []string{personalAccessTokenStreamType},
			EventTypes: []string{
				personalAccessTokenMintedEventType,
				personalAccessTokenRevokedEventType,
			},
			Reset: resetPersonalAccessTokens,
		},
		UserRebuildTarget: {
			Tables:      []string{"users", "oidc_identities"},
			StreamTypes: []string{userStreamType},
			EventTypes: []string{
				userCreatedEventType,
				oidcIdentityLinkedEventType,
			},
			Reset: resetUsers,
		},
		RegistrationTokenRebuildTarget: {
			Tables:      []string{"registration_tokens"},
			StreamTypes: []string{registrationTokenStreamType},
			EventTypes: []string{
				registrationTokenMintedEventType,
				gatewayTokenMintedEventType,
				registrationTokenConsumedEventType,
				registrationTokenDisabledEventType,
			},
			Reset: resetRegistrationTokens,
		},
		RefreshFamilyRebuildTarget: {
			Tables:      []string{"refresh_families", "refresh_tokens"},
			StreamTypes: []string{refreshFamilyStreamType},
			EventTypes: []string{
				refreshFamilyStartedEventType,
				refreshTokenRotatedEventType,
				refreshFamilyRevokedEventType,
			},
			Reset: resetRefreshFamilies,
		},
		DeviceRebuildTarget: {
			Tables:       []string{"devices"},
			SharedTables: []string{"certificate_revocations"},
			StreamTypes:  []string{deviceStreamType},
			EventTypes: []string{
				agentEnrolledEventType,
				agentCertificateRenewedEventType,
				agentCertificateRevokedEventType,
				agentForceRenewalRequiredEventType,
			},
			Reset: resetDevices,
		},
		GatewayRebuildTarget: {
			Tables:       []string{"gateways"},
			SharedTables: []string{"certificate_revocations"},
			StreamTypes:  []string{gatewayStreamType},
			EventTypes: []string{
				gatewayEnrolledEventType,
				gatewayCertificateRenewedEventType,
				gatewayCertificateRevokedEventType,
			},
			Reset: resetGateways,
		},
		CARotationRebuildTarget: {
			Tables:      []string{"ca_rotation_state"},
			StreamTypes: []string{caRotationStreamType, caTrustConfirmationStreamType},
			EventTypes: []string{
				caRotationTrustBegunEventType,
				caRotationAbortedEventType,
				caRotationMigrationBegunEventType,
				caRotationRetiredEventType,
				caRotationNormalizedEventType,
				agentLeafTrustConfirmedEventType,
				agentConsumerTrustConfirmedEventType,
				gatewayLeafTrustConfirmedEventType,
				gatewayConsumerTrustConfirmedEventType,
				controlTrustStateRecordedEventType,
			},
			Reset: resetCARotationState,
		},
	}
}

// InventorySnapshotEvent returns a latest-state inventory event.
func InventorySnapshotEvent(agentID string, snapshot []byte) (Event, error) {
	if err := validate.ULIDPathID(agentID); err != nil {
		return Event{}, fmt.Errorf("store: invalid inventory agent ID: %w", err)
	}
	agentID = strings.ToUpper(agentID)
	if snapshot == nil {
		return Event{}, errors.New("store: inventory snapshot is nil")
	}
	if len(snapshot) > maxInventorySnapshotBytes {
		return Event{}, fmt.Errorf(
			"store: inventory snapshot exceeds %d bytes",
			maxInventorySnapshotBytes,
		)
	}
	payload, err := json.Marshal(inventorySnapshotPayload{Snapshot: snapshot})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode inventory snapshot: %w", err)
	}
	return Event{
		StreamType:     inventoryStreamType,
		StreamID:       agentID,
		EventType:      inventorySnapshotEventType,
		PayloadVersion: inventoryPayloadVersion,
		Payload:        payload,
	}, nil
}

// InventoryTombstoneEvent returns an inventory deletion event.
func InventoryTombstoneEvent(agentID string) (Event, error) {
	if err := validate.ULIDPathID(agentID); err != nil {
		return Event{}, fmt.Errorf("store: invalid inventory agent ID: %w", err)
	}
	agentID = strings.ToUpper(agentID)
	payload, err := json.Marshal(inventoryTombstonePayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode inventory tombstone: %w", err)
	}
	return Event{
		StreamType:     inventoryStreamType,
		StreamID:       agentID,
		EventType:      inventoryTombstoneEventType,
		PayloadVersion: inventoryPayloadVersion,
		Payload:        payload,
	}, nil
}

func productionEventDefinitions() map[string]eventDefinition {
	definitions := map[string]eventDefinition{
		inventorySnapshotEventType: {
			PayloadVersion: inventoryPayloadVersion,
			PayloadType:    inventorySnapshotPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(inventorySnapshotPayload{Snapshot: []byte{1, 2, 3}})
			},
			Projector: projectInventorySnapshot,
		},
		inventoryTombstoneEventType: {
			PayloadVersion: inventoryPayloadVersion,
			PayloadType:    inventoryTombstonePayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(inventoryTombstonePayload{})
			},
			Projector: projectInventoryTombstone,
		},
	}
	for eventType, definition := range registrationTokenEventDefinitions() {
		definitions[eventType] = definition
	}
	for eventType, definition := range personalAccessTokenEventDefinitions() {
		definitions[eventType] = definition
	}
	for eventType, definition := range userEventDefinitions() {
		definitions[eventType] = definition
	}
	for eventType, definition := range refreshFamilyEventDefinitions() {
		definitions[eventType] = definition
	}
	for eventType, definition := range deviceEventDefinitions() {
		definitions[eventType] = definition
	}
	for eventType, definition := range gatewayEventDefinitions() {
		definitions[eventType] = definition
	}
	for eventType, definition := range caRotationEventDefinitions() {
		definitions[eventType] = definition
	}
	return definitions
}

func goldenEventCorpus() map[string]goldenEvent {
	corpus := map[string]goldenEvent{
		inventorySnapshotEventType: {
			PayloadVersion: inventoryPayloadVersion,
			Payload:        []byte(`{"snapshot":"AQID"}`),
		},
		inventoryTombstoneEventType: {
			PayloadVersion: inventoryPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
	for eventType, event := range registrationTokenGoldenCorpus() {
		corpus[eventType] = event
	}
	for eventType, event := range personalAccessTokenGoldenCorpus() {
		corpus[eventType] = event
	}
	for eventType, event := range userGoldenCorpus() {
		corpus[eventType] = event
	}
	for eventType, event := range refreshFamilyGoldenCorpus() {
		corpus[eventType] = event
	}
	for eventType, event := range deviceGoldenCorpus() {
		corpus[eventType] = event
	}
	for eventType, event := range gatewayGoldenCorpus() {
		corpus[eventType] = event
	}
	for eventType, event := range caRotationGoldenCorpus() {
		corpus[eventType] = event
	}
	return corpus
}

func validateGoldenEventCorpus(
	definitions map[string]eventDefinition,
	corpus map[string]goldenEvent,
) error {
	if len(definitions) == 0 {
		return errors.New("store: event definition registry is empty")
	}
	if len(corpus) == 0 {
		return errors.New("store: golden event corpus is empty")
	}
	for _, eventType := range slices.Sorted(maps.Keys(definitions)) {
		definition := definitions[eventType]
		entry, ok := corpus[eventType]
		if !ok {
			return fmt.Errorf("store: event type %q has no golden corpus entry", eventType)
		}
		if definition.PayloadVersion <= 0 || definition.GoldenPayload == nil {
			return fmt.Errorf("store: event type %q has an invalid definition", eventType)
		}
		if entry.PayloadVersion != definition.PayloadVersion {
			return fmt.Errorf(
				"store: event type %q golden payload version is %d; want %d",
				eventType,
				entry.PayloadVersion,
				definition.PayloadVersion,
			)
		}
		payload, err := definition.GoldenPayload()
		if err != nil {
			return fmt.Errorf("store: encode golden event type %q: %w", eventType, err)
		}
		if !bytes.Equal(entry.Payload, payload) {
			return fmt.Errorf(
				"store: event type %q serialized form differs from its golden corpus",
				eventType,
			)
		}
	}
	for _, eventType := range slices.Sorted(maps.Keys(corpus)) {
		if _, ok := definitions[eventType]; !ok {
			return fmt.Errorf("store: golden corpus event type %q is not registered", eventType)
		}
	}
	return nil
}

func validateEventPayloadTypes(definitions map[string]eventDefinition) error {
	if len(definitions) == 0 {
		return errors.New("store: event definition registry is empty")
	}
	discoveredFields := 0
	for _, eventType := range slices.Sorted(maps.Keys(definitions)) {
		definition := definitions[eventType]
		if definition.PayloadType == nil {
			return fmt.Errorf("store: event type %q payload type is nil", eventType)
		}
		fields, forbidden := inspectEventPayloadType(reflect.TypeOf(definition.PayloadType))
		discoveredFields += fields
		if forbidden != "" {
			return fmt.Errorf(
				"store: event type %q contains forbidden payload field %q",
				eventType,
				forbidden,
			)
		}
	}
	if discoveredFields == 0 {
		return errors.New("store: event payload guard discovered zero fields")
	}
	return nil
}

func projectInventorySnapshot(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	payload, err := decodeEventPayload[inventorySnapshotPayload](event, inventoryPayloadVersion)
	if err != nil {
		return err
	}
	if payload.Snapshot == nil {
		return errors.New("store: inventory snapshot payload is nil")
	}
	if len(payload.Snapshot) > maxInventorySnapshotBytes {
		return fmt.Errorf(
			"store: inventory snapshot payload exceeds %d bytes",
			maxInventorySnapshotBytes,
		)
	}
	if _, err := generated.New(tx).UpsertInventorySnapshot(ctx, generated.UpsertInventorySnapshotParams{
		AgentID:           event.StreamID,
		ProjectionVersion: event.StreamVersion,
		PayloadVersion:    event.PayloadVersion,
		Snapshot:          payload.Snapshot,
		UpdatedAt:         event.CreatedAt,
	}); err != nil {
		return fmt.Errorf("store: project inventory snapshot: %w", err)
	}
	return nil
}

func projectInventoryTombstone(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if _, err := decodeEventPayload[inventoryTombstonePayload](event, inventoryPayloadVersion); err != nil {
		return err
	}
	if _, err := generated.New(tx).UpsertInventoryTombstone(ctx, generated.UpsertInventoryTombstoneParams{
		AgentID:           event.StreamID,
		ProjectionVersion: event.StreamVersion,
		PayloadVersion:    event.PayloadVersion,
		UpdatedAt:         event.CreatedAt,
	}); err != nil {
		return fmt.Errorf("store: project inventory tombstone: %w", err)
	}
	return nil
}

func resetInventorySnapshots(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetInventorySnapshots(ctx); err != nil {
		return fmt.Errorf("store: reset inventory snapshots: %w", err)
	}
	return nil
}

func decodeEventPayload[T any](event PersistedEvent, payloadVersion int32) (T, error) {
	var payload T
	if event.PayloadVersion != payloadVersion {
		return payload, fmt.Errorf(
			"store: event type %q payload version is %d; want %d",
			event.EventType,
			event.PayloadVersion,
			payloadVersion,
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(event.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return payload, fmt.Errorf("store: decode event type %q payload: %w", event.EventType, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return payload, fmt.Errorf("store: event type %q payload has trailing data", event.EventType)
	}
	return payload, nil
}

func inspectEventPayloadType(typ reflect.Type) (fields int, forbidden string) {
	return inspectEventPayloadTypeActive(typ, make(map[reflect.Type]bool))
}

func inspectEventPayloadTypeActive(
	typ reflect.Type,
	active map[reflect.Type]bool,
) (fields int, forbidden string) {
	if typ == nil {
		return 0, ""
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if active[typ] {
		return 0, ""
	}
	switch typ.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.Struct:
	default:
		return 0, ""
	}
	active[typ] = true
	defer delete(active, typ)
	if typ.Kind() != reflect.Struct {
		return inspectEventPayloadTypeActive(typ.Elem(), active)
	}
	for index := range typ.NumField() {
		field := typ.Field(index)
		fields++
		name := field.Name
		if tag := strings.Split(field.Tag.Get("json"), ",")[0]; tag != "" && tag != "-" {
			name = tag
		}
		normalized := strings.ToLower(name)
		if (strings.Contains(normalized, "output") || strings.Contains(normalized, "recording")) &&
			strings.Contains(normalized, "body") {
			return fields, name
		}
		nestedFields, nestedForbidden := inspectEventPayloadTypeActive(field.Type, active)
		fields += nestedFields
		if nestedForbidden != "" {
			return fields, name + "." + nestedForbidden
		}
	}
	return fields, ""
}
