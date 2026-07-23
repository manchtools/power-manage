package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestInventorySnapshot_ReplacesAndRebuildsLatestState(t *testing.T) {
	pool := testPostgres(t)
	store, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	ctx := context.Background()
	first, err := InventorySnapshotEvent(testStreamID, []byte("first"))
	if err != nil {
		t.Fatalf("create first inventory event: %v", err)
	}
	second, err := InventorySnapshotEvent(testStreamID, []byte("second"))
	if err != nil {
		t.Fatalf("create second inventory event: %v", err)
	}
	if err := store.AppendEvents(ctx, []Event{first, second}); err != nil {
		t.Fatalf("append inventory events: %v", err)
	}

	want := inventoryProjection{version: 2, snapshot: []byte("second")}
	assertInventoryProjection(t, pool, testStreamID, want)
	if _, err := pool.Exec(ctx, `
		UPDATE inventory_snapshots
		SET snapshot = 'corrupt'
		WHERE agent_id = $1`, testStreamID); err != nil {
		t.Fatalf("corrupt inventory projection: %v", err)
	}
	if err := store.RebuildAll(ctx, InventoryRebuildTarget); err != nil {
		t.Fatalf("rebuild inventory: %v", err)
	}
	assertInventoryProjection(t, pool, testStreamID, want)
}

func TestInventorySnapshot_OlderSnapshotLeavesNewerProjectionUntouched(t *testing.T) {
	pool := testPostgres(t)
	store := seededInventoryStore(t, pool, 3)

	older, err := InventorySnapshotEvent(testStreamID, []byte("older"))
	if err != nil {
		t.Fatalf("create older inventory event: %v", err)
	}
	projectInventoryOutOfOrder(t, pool, store, PersistedEvent{
		Event:         older,
		StreamVersion: 2,
		CreatedAt:     time.Now(),
	})

	assertInventoryProjection(t, pool, testStreamID, inventoryProjection{
		version:  3,
		snapshot: []byte("snapshot-3"),
	})
}

func TestInventorySnapshot_OlderTombstoneLeavesNewerProjectionUntouched(t *testing.T) {
	pool := testPostgres(t)
	store := seededInventoryStore(t, pool, 3)

	older, err := InventoryTombstoneEvent(testStreamID)
	if err != nil {
		t.Fatalf("create older inventory tombstone: %v", err)
	}
	projectInventoryOutOfOrder(t, pool, store, PersistedEvent{
		Event:         older,
		StreamVersion: 2,
		CreatedAt:     time.Now(),
	})
	assertInventoryProjection(t, pool, testStreamID, inventoryProjection{
		version:  3,
		snapshot: []byte("snapshot-3"),
	})

	fresh, err := InventoryTombstoneEvent(testStreamID)
	if err != nil {
		t.Fatalf("create fresh inventory tombstone: %v", err)
	}
	if err := store.AppendEvent(context.Background(), fresh); err != nil {
		t.Fatalf("append fresh inventory tombstone: %v", err)
	}
	assertInventoryProjection(t, pool, testStreamID, inventoryProjection{
		version: 4,
		deleted: true,
	})
}

func TestInventoryEvents_CanonicalizeAgentID(t *testing.T) {
	lowercaseID := strings.ToLower(testStreamID)
	snapshot, err := InventorySnapshotEvent(lowercaseID, []byte("snapshot"))
	if err != nil {
		t.Fatalf("create lowercase inventory snapshot: %v", err)
	}
	tombstone, err := InventoryTombstoneEvent(lowercaseID)
	if err != nil {
		t.Fatalf("create lowercase inventory tombstone: %v", err)
	}
	if snapshot.StreamID != testStreamID || tombstone.StreamID != testStreamID {
		t.Fatalf(
			"canonical inventory IDs = (%q, %q); want %q",
			snapshot.StreamID,
			tombstone.StreamID,
			testStreamID,
		)
	}
}

// Guards: INV-12.
func TestGuard_GoldenEventCorpus(t *testing.T) {
	definitions := productionEventDefinitions()
	guardtest.Discover(t, "production event types", 13, func() ([]string, error) {
		return slices.Sorted(maps.Keys(definitions)), nil
	})
	if err := validateGoldenEventCorpus(definitions, goldenEventCorpus()); err != nil {
		t.Fatalf("validate golden event corpus: %v", err)
	}
}

func TestGoldenEventCorpusGuard_RejectsMissingEntry(t *testing.T) {
	definitions := productionEventDefinitions()
	definitions["MissingCorpusEvent"] = eventDefinition{
		PayloadVersion: 1,
		GoldenPayload: func() ([]byte, error) {
			return []byte(`{}`), nil
		},
	}
	err := validateGoldenEventCorpus(definitions, goldenEventCorpus())
	if err == nil || !strings.Contains(err.Error(), "MissingCorpusEvent") {
		t.Fatalf("missing-corpus error = %v; want missing event type", err)
	}
}

func TestGoldenEventCorpusGuard_RejectsChangedSerialization(t *testing.T) {
	corpus := goldenEventCorpus()
	entry := corpus[inventorySnapshotEventType]
	entry.Payload = append(entry.Payload, ' ')
	corpus[inventorySnapshotEventType] = entry
	err := validateGoldenEventCorpus(productionEventDefinitions(), corpus)
	if err == nil || !strings.Contains(err.Error(), inventorySnapshotEventType) {
		t.Fatalf("changed-corpus error = %v; want event type", err)
	}
}

func TestGuard_EventPayloadBodiesExcluded(t *testing.T) {
	definitions := productionEventDefinitions()
	guardtest.Discover(t, "production event payload types", 13, func() ([]string, error) {
		return slices.Sorted(maps.Keys(definitions)), nil
	})
	if err := validateEventPayloadTypes(definitions); err != nil {
		t.Fatalf("validate production event payload types: %v", err)
	}
	type forbiddenPayload struct {
		ExecutionOutputBody []byte `json:"execution_output_body"`
	}
	definitions["ForbiddenBodyEvent"] = eventDefinition{
		PayloadVersion: 1,
		PayloadType:    forbiddenPayload{},
		GoldenPayload: func() ([]byte, error) {
			return []byte(`{"execution_output_body":""}`), nil
		},
	}
	err := validateEventPayloadTypes(definitions)
	if err == nil || !strings.Contains(err.Error(), "execution_output_body") {
		t.Fatalf("forbidden-payload error = %v; want forbidden field", err)
	}
}

func TestEventPayloadBodyGuard_RejectsNestedContainers(t *testing.T) {
	type nestedItem struct {
		RecordingBody []byte `json:"recording_body"`
	}
	tests := map[string]any{
		"array": struct {
			Items [1]nestedItem `json:"items"`
		}{},
		"map": struct {
			Items map[string]nestedItem `json:"items"`
		}{},
		"slice": struct {
			Items []nestedItem `json:"items"`
		}{},
	}
	for name, payloadType := range tests {
		t.Run(name, func(t *testing.T) {
			definitions := productionEventDefinitions()
			definitions["NestedBodyEvent"] = eventDefinition{
				PayloadVersion: 1,
				PayloadType:    payloadType,
				GoldenPayload: func() ([]byte, error) {
					return []byte(`{"items":[]}`), nil
				},
			}
			err := validateEventPayloadTypes(definitions)
			if err == nil || !strings.Contains(err.Error(), "items.recording_body") {
				t.Fatalf("nested forbidden-payload error = %v; want nested field path", err)
			}
		})
	}
}

type inventoryProjection struct {
	version  int64
	snapshot []byte
	deleted  bool
}

func seededInventoryStore(t *testing.T, pool *pgxpool.Pool, count int) *Store {
	t.Helper()
	store, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	for version := 1; version <= count; version++ {
		event, err := InventorySnapshotEvent(
			testStreamID,
			[]byte(fmt.Sprintf("snapshot-%d", version)),
		)
		if err != nil {
			t.Fatalf("create inventory event %d: %v", version, err)
		}
		if err := store.AppendEvent(context.Background(), event); err != nil {
			t.Fatalf("append inventory event %d: %v", version, err)
		}
	}
	return store
}

func projectInventoryOutOfOrder(
	t *testing.T,
	pool *pgxpool.Pool,
	store *Store,
	event PersistedEvent,
) {
	t.Helper()
	projector := store.projectors[event.EventType]
	if projector == nil {
		t.Fatalf("projector for %q is not registered", event.EventType)
	}
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin out-of-order projection: %v", err)
	}
	defer func() {
		if err := tx.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("roll back out-of-order projection: %v", err)
		}
	}()
	if err := projector(context.Background(), projectionTx{DBTX: tx}, event); err != nil {
		t.Fatalf("project out-of-order inventory event: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit out-of-order projection: %v", err)
	}
}

func assertInventoryProjection(
	t *testing.T,
	pool *pgxpool.Pool,
	agentID string,
	want inventoryProjection,
) {
	t.Helper()
	var got inventoryProjection
	if err := pool.QueryRow(context.Background(), `
		SELECT projection_version, snapshot, deleted
		FROM inventory_snapshots
		WHERE agent_id = $1`, agentID).Scan(&got.version, &got.snapshot, &got.deleted); err != nil {
		t.Fatalf("read inventory projection: %v", err)
	}
	if got.version != want.version || got.deleted != want.deleted ||
		!bytes.Equal(got.snapshot, want.snapshot) {
		t.Fatalf("inventory projection = %+v; want %+v", got, want)
	}
}
