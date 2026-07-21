package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	testStreamType = "test"
	testStreamID   = "01J00000000000000000000001"
	testEventType  = "FactRecorded"
)

func TestEventsUniqueStreamVersion_ConcurrentConflict(t *testing.T) {
	pool := testPostgres(t)
	ctx := context.Background()

	start := make(chan struct{})
	errorsByWriter := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := pool.Exec(ctx, `
				INSERT INTO events (
					stream_type, stream_id, stream_version,
					event_type, payload_version, payload
				) VALUES ($1, $2, $3, $4, $5, $6)`,
				testStreamType, testStreamID, int64(1), testEventType, int32(1), []byte{1})
			errorsByWriter <- err
		}()
	}
	close(start)

	var successes, conflicts int
	for range 2 {
		err := <-errorsByWriter
		if err == nil {
			successes++
			continue
		}
		var postgresError *pgconn.PgError
		if !errors.As(err, &postgresError) || postgresError.Code != "23505" {
			t.Fatalf("concurrent insert returned %v; want SQLSTATE 23505", err)
		}
		conflicts++
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent same-version inserts: successes=%d conflicts=%d; want 1 each", successes, conflicts)
	}

	for _, key := range []struct {
		streamType string
		streamID   string
	}{
		{streamType: "other", streamID: testStreamID},
		{streamType: testStreamType, streamID: "01J00000000000000000000002"},
	} {
		_, err := pool.Exec(ctx, `
			INSERT INTO events (
				stream_type, stream_id, stream_version,
				event_type, payload_version, payload
			) VALUES ($1, $2, $3, $4, $5, $6)`,
			key.streamType, key.streamID, int64(1), testEventType, int32(1), []byte{1})
		if err != nil {
			t.Fatalf("insert distinct composite stream key: %v", err)
		}
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events`).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 3 {
		t.Fatalf("events count = %d; want 3 distinct composite keys", count)
	}
}

func TestAppendEvent_AutoVersionsConcurrentFacts(t *testing.T) {
	pool := testPostgres(t)
	ctx := context.Background()
	createCounterProjection(t, pool)

	store, err := New(pool, map[string]Projector{
		testEventType: incrementCounter,
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	const appendCount = 8
	start := make(chan struct{})
	results := make(chan error, appendCount)
	for i := range appendCount {
		go func(payload byte) {
			<-start
			results <- store.AppendEvent(ctx, event(testEventType, []byte{payload}))
		}(byte(i))
	}
	close(start)
	for range appendCount {
		if err := <-results; err != nil {
			t.Fatalf("concurrent AppendEvent: %v", err)
		}
	}

	rows, err := pool.Query(ctx, `
		SELECT stream_version
		FROM events
		WHERE stream_type = $1 AND stream_id = $2
		ORDER BY stream_version`, testStreamType, testStreamID)
	if err != nil {
		t.Fatalf("query stream versions: %v", err)
	}
	defer rows.Close()
	for want := int64(1); want <= appendCount; want++ {
		if !rows.Next() {
			t.Fatalf("stream ended before version %d", want)
		}
		var got int64
		if err := rows.Scan(&got); err != nil {
			t.Fatalf("scan stream version: %v", err)
		}
		if got != want {
			t.Fatalf("stream version = %d; want %d", got, want)
		}
	}
	if rows.Next() {
		t.Fatal("stream contains more events than successful appends")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate stream versions: %v", err)
	}

	if got := projectionCount(t, pool); got != appendCount {
		t.Fatalf("projected fact count = %d; want %d", got, appendCount)
	}
}

func TestAppendEvent_UnregisteredTypeWritesNothing(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	store, err := New(pool, map[string]Projector{
		testEventType: incrementCounter,
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	err = store.AppendEvent(context.Background(), event("UnknownEvent", []byte{1}))
	if err == nil {
		t.Fatal("AppendEvent returned nil for an unregistered event type")
	}
	if !strings.Contains(err.Error(), "UnknownEvent") {
		t.Fatalf("AppendEvent error = %q; want it to identify UnknownEvent", err)
	}
	assertNoEvents(t, pool)
	if got := projectionRowCount(t, pool); got != 0 {
		t.Fatalf("projection row count = %d; want 0", got)
	}
}

func TestAppendEvent_ProjectorFailureRollsBack(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	wantErr := errors.New("projector failed")
	store, err := New(pool, map[string]Projector{
		testEventType: func(ctx context.Context, tx ProjectionTx, persisted PersistedEvent) error {
			if _, err := tx.Exec(ctx, `
				INSERT INTO test_projection (stream_id, fact_count)
				VALUES ($1, 1)`, persisted.StreamID); err != nil {
				return fmt.Errorf("write projection: %w", err)
			}
			return wantErr
		},
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	err = store.AppendEvent(context.Background(), event(testEventType, []byte{1}))
	if !errors.Is(err, wantErr) {
		t.Fatalf("AppendEvent error = %v; want projector error", err)
	}
	assertNoEvents(t, pool)
	if got := projectionRowCount(t, pool); got != 0 {
		t.Fatalf("projection row count = %d; want 0", got)
	}
}

func TestAppendEvent_ReadAfterWriteProjection(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)

	var (
		observedMu sync.Mutex
		observed   int
	)
	projector := func(ctx context.Context, tx ProjectionTx, persisted PersistedEvent) error {
		if err := incrementCounter(ctx, tx, persisted); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `
			SELECT fact_count FROM test_projection WHERE stream_id = $1`,
			persisted.StreamID).Scan(&count); err != nil {
			return fmt.Errorf("read projection in append transaction: %w", err)
		}
		observedMu.Lock()
		observed = count
		observedMu.Unlock()
		return nil
	}
	store, err := New(pool, map[string]Projector{testEventType: projector})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	if err := store.AppendEvent(context.Background(), event(testEventType, []byte{1})); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	observedMu.Lock()
	inTransaction := observed
	observedMu.Unlock()
	if inTransaction != 1 {
		t.Fatalf("projection count in append transaction = %d; want 1", inTransaction)
	}
	if got := projectionCount(t, pool); got != 1 {
		t.Fatalf("projection count after commit = %d; want 1", got)
	}
}

func TestAppendEvent_ProjectorTransactionIsCapabilityLimited(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)

	var exposesPGXTx, exposesCommit, exposesRollback bool
	projector := func(ctx context.Context, tx ProjectionTx, persisted PersistedEvent) error {
		_, exposesPGXTx = any(tx).(pgx.Tx)
		_, exposesCommit = any(tx).(interface {
			Commit(context.Context) error
		})
		_, exposesRollback = any(tx).(interface {
			Rollback(context.Context) error
		})

		if err := incrementCounter(ctx, tx, persisted); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `
			SELECT fact_count FROM test_projection WHERE stream_id = $1`,
			persisted.StreamID).Scan(&count); err != nil {
			return fmt.Errorf("read through projection handle: %w", err)
		}
		if count != 1 {
			return fmt.Errorf("projection count through handle = %d; want 1", count)
		}
		return nil
	}
	store, err := New(pool, map[string]Projector{testEventType: projector})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	if err := store.AppendEvent(context.Background(), event(testEventType, []byte{1})); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	if exposesPGXTx {
		t.Error("projector transaction exposes pgx.Tx; want only projection query capabilities")
	}
	if exposesCommit {
		t.Error("projector transaction exposes Commit")
	}
	if exposesRollback {
		t.Error("projector transaction exposes Rollback")
	}
	if got := projectionCount(t, pool); got != 1 {
		t.Fatalf("projection count after capability-limited write = %d; want 1", got)
	}
}

func TestAppendEvent_LowercaseULIDPersistsCanonicalID(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	store, err := New(pool, map[string]Projector{testEventType: incrementCounter})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	lowercaseID := "01arz3ndektsv4rrffq69g5fav"
	canonicalID := strings.ToUpper(lowercaseID)
	lowercaseEvent := event(testEventType, []byte{1})
	lowercaseEvent.StreamID = lowercaseID
	if err := store.AppendEvent(context.Background(), lowercaseEvent); err != nil {
		t.Fatalf("AppendEvent with lowercase Crockford ULID: %v", err)
	}

	var eventID string
	if err := pool.QueryRow(context.Background(), `SELECT stream_id FROM events`).Scan(&eventID); err != nil {
		t.Fatalf("read persisted event ID: %v", err)
	}
	if eventID != canonicalID {
		t.Fatalf("persisted event ID = %q; want canonical %q", eventID, canonicalID)
	}
	var projectionID string
	if err := pool.QueryRow(context.Background(), `SELECT stream_id FROM test_projection`).Scan(&projectionID); err != nil {
		t.Fatalf("read projected stream ID: %v", err)
	}
	if projectionID != canonicalID {
		t.Fatalf("projected stream ID = %q; want canonical %q", projectionID, canonicalID)
	}
}

func TestIsStreamVersionConflict_ExactPostgresError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "matching state and constraint",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: eventsStreamVersionConstraint,
			},
			want: true,
		},
		{
			name: "wrapped matching error",
			err: fmt.Errorf("insert event: %w", &pgconn.PgError{
				Code:           "23505",
				ConstraintName: eventsStreamVersionConstraint,
			}),
			want: true,
		},
		{
			name: "different unique constraint",
			err: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "other_unique_key",
			},
		},
		{
			name: "different SQLSTATE",
			err: &pgconn.PgError{
				Code:           "40001",
				ConstraintName: eventsStreamVersionConstraint,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isStreamVersionConflict(test.err); got != test.want {
				t.Fatalf("isStreamVersionConflict() = %t; want %t", got, test.want)
			}
		})
	}
}

func TestWaitAppendRetry_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := waitAppendRetry(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitAppendRetry() error = %v; want context.Canceled", err)
	}
}

func event(eventType string, payload []byte) Event {
	return Event{
		StreamType:     testStreamType,
		StreamID:       testStreamID,
		EventType:      eventType,
		PayloadVersion: 1,
		Payload:        payload,
	}
}

func createCounterProjection(t *testing.T, pool interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		CREATE TABLE test_projection (
			stream_id text PRIMARY KEY,
			fact_count integer NOT NULL
		)`); err != nil {
		t.Fatalf("create test projection: %v", err)
	}
}

func incrementCounter(ctx context.Context, tx ProjectionTx, persisted PersistedEvent) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO test_projection (stream_id, fact_count)
		VALUES ($1, 1)
		ON CONFLICT (stream_id) DO UPDATE
		SET fact_count = test_projection.fact_count + 1`, persisted.StreamID)
	return err
}

func assertNoEvents(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM events`).Scan(&count); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if count != 0 {
		t.Fatalf("events count = %d; want 0", count)
	}
}

func projectionCount(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `
		SELECT fact_count FROM test_projection WHERE stream_id = $1`, testStreamID).Scan(&count); err != nil {
		t.Fatalf("read projection: %v", err)
	}
	return count
}

func projectionRowCount(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM test_projection`).Scan(&count); err != nil {
		t.Fatalf("count projection rows: %v", err)
	}
	return count
}
