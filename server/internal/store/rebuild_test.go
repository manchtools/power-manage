package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRebuildAll_ReproducesProjection(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	store, err := newTestStore(pool, map[string]Projector{testEventType: incrementCounter})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	ctx := context.Background()
	secondStreamID := "01J00000000000000000000002"
	facts := make([]Event, int(replayPageSize)+1)
	for i := range facts {
		facts[i] = event(testEventType, []byte{byte(i)})
		if i == len(facts)-1 {
			facts[i].StreamID = secondStreamID
		}
	}
	if err := store.AppendEvents(ctx, facts); err != nil {
		t.Fatalf("append events: %v", err)
	}

	want := projectionRows(t, pool)
	if _, err := pool.Exec(ctx, `
		UPDATE test_projection SET fact_count = 99 WHERE stream_id = $1`, testStreamID); err != nil {
		t.Fatalf("corrupt existing projection row: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO test_projection (stream_id, fact_count)
		VALUES ('01J00000000000000000000003', 77)`); err != nil {
		t.Fatalf("insert spurious projection row: %v", err)
	}

	if err := store.RebuildAll(ctx, "test"); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	got := projectionRows(t, pool)
	if len(got) != len(want) {
		t.Fatalf("rebuilt row count = %d; want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rebuilt row %d = %+v; want %+v", i, got[i], want[i])
		}
	}
	if gotEvents := eventCount(t, pool); gotEvents != len(facts) {
		t.Fatalf("event count after rebuild = %d; want unchanged count %d", gotEvents, len(facts))
	}
}

func TestRebuildAll_FKDependentRefused(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		CREATE TABLE test_projection_child (
			stream_id text PRIMARY KEY REFERENCES test_projection(stream_id) ON DELETE CASCADE
		)`); err != nil {
		t.Fatalf("create dependent projection table: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TABLE test_projection_grandchild (
			stream_id text PRIMARY KEY REFERENCES test_projection_child(stream_id) ON DELETE CASCADE
		)`); err != nil {
		t.Fatalf("create transitive dependent projection table: %v", err)
	}

	resetCalled := false
	store, err := New(pool, map[string]Projector{testEventType: incrementCounter}, map[string]RebuildTarget{
		"test": {
			Tables:      []string{"test_projection"},
			StreamTypes: []string{testStreamType},
			EventTypes:  []string{testEventType},
			Reset: func(ctx context.Context, tx ProjectionTx) error {
				resetCalled = true
				_, err := tx.Exec(ctx, `DELETE FROM test_projection`)
				return err
			},
		},
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := store.AppendEvent(ctx, event(testEventType, []byte{1})); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO test_projection_child (stream_id) VALUES ($1)`, testStreamID); err != nil {
		t.Fatalf("insert dependent row: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO test_projection_grandchild (stream_id) VALUES ($1)`, testStreamID); err != nil {
		t.Fatalf("insert transitive dependent row: %v", err)
	}

	err = store.RebuildAll(ctx, "test")
	if err == nil {
		t.Fatal("RebuildAll returned nil with an excluded FK-dependent table")
	}
	if !strings.Contains(err.Error(), "test_projection_child") {
		t.Fatalf("RebuildAll error = %q; want dependent table name", err)
	}
	if !strings.Contains(err.Error(), "test_projection_grandchild") {
		t.Fatalf("RebuildAll error = %q; want transitive dependent table name", err)
	}
	if resetCalled {
		t.Fatal("RebuildAll invoked reset before refusing the incomplete FK closure")
	}
	var childCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM test_projection_child`).Scan(&childCount); err != nil {
		t.Fatalf("count dependent rows: %v", err)
	}
	if childCount != 1 {
		t.Fatalf("dependent row count = %d; want 1 after refused rebuild", childCount)
	}
	var grandchildCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM test_projection_grandchild`).Scan(&grandchildCount); err != nil {
		t.Fatalf("count transitive dependent rows: %v", err)
	}
	if grandchildCount != 1 {
		t.Fatalf("transitive dependent row count = %d; want 1 after refused rebuild", grandchildCount)
	}
}

func TestRebuildAll_DoesNotBlockConcurrentAppend(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resetEntered := make(chan struct{})
	continueReset := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-continueReset:
		default:
			close(continueReset)
		}
	})
	store, err := New(pool, map[string]Projector{testEventType: incrementCounter}, map[string]RebuildTarget{
		"test": {
			Tables:      []string{"test_projection"},
			StreamTypes: []string{testStreamType},
			EventTypes:  []string{testEventType},
			Reset: func(ctx context.Context, tx ProjectionTx) error {
				if _, err := tx.Exec(ctx, `DELETE FROM test_projection`); err != nil {
					return err
				}
				close(resetEntered)
				select {
				case <-continueReset:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
		},
	})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := store.AppendEvent(ctx, event(testEventType, []byte{1})); err != nil {
		t.Fatalf("append initial event: %v", err)
	}

	rebuildResult := make(chan error, 1)
	go func() {
		rebuildResult <- store.RebuildAll(ctx, "test")
	}()
	select {
	case <-resetEntered:
	case <-ctx.Done():
		t.Fatalf("wait for rebuild reset: %v", ctx.Err())
	}

	concurrent := event(testEventType, []byte{2})
	concurrent.StreamID = "01J00000000000000000000002"
	appendCtx, cancelAppend := context.WithTimeout(ctx, 2*time.Second)
	defer cancelAppend()
	appendResult := make(chan error, 1)
	go func() {
		appendResult <- store.AppendEvent(appendCtx, concurrent)
	}()
	appendErr := <-appendResult
	close(continueReset)

	if err := <-rebuildResult; err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	if appendErr != nil {
		t.Fatalf("concurrent AppendEvent was blocked by rebuild: %v", appendErr)
	}
	rows := projectionRows(t, pool)
	if len(rows) != 2 {
		t.Fatalf("projection row count = %d; want 2", len(rows))
	}
	for i, row := range rows {
		if row.count != 1 {
			t.Fatalf("projection row %d count = %d; want exactly 1", i, row.count)
		}
	}
	if got := eventCount(t, pool); got != 2 {
		t.Fatalf("event count = %d; want 2", got)
	}
}

func TestRebuildAll_ProjectorFailureRollsBackReset(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	wantErr := errors.New("replay failed")
	fail := false
	projector := func(ctx context.Context, tx ProjectionTx, persisted PersistedEvent) error {
		if fail {
			return wantErr
		}
		return incrementCounter(ctx, tx, persisted)
	}
	store, err := newTestStore(pool, map[string]Projector{testEventType: projector})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	ctx := context.Background()
	if err := store.AppendEvent(ctx, event(testEventType, []byte{1})); err != nil {
		t.Fatalf("append event: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE test_projection SET fact_count = 99`); err != nil {
		t.Fatalf("corrupt projection: %v", err)
	}

	fail = true
	err = store.RebuildAll(ctx, "test")
	if !errors.Is(err, wantErr) {
		t.Fatalf("RebuildAll error = %v; want projector error", err)
	}
	if got := projectionCount(t, pool); got != 99 {
		t.Fatalf("projection count = %d; want pre-rebuild value 99 after rollback", got)
	}
	if got := eventCount(t, pool); got != 1 {
		t.Fatalf("event count = %d; want unchanged count 1", got)
	}
}

func TestNew_ProjectorWithoutRebuildTargetRejected(t *testing.T) {
	pool := testPostgres(t)
	_, err := New(pool, map[string]Projector{testEventType: incrementCounter}, nil)
	if err == nil {
		t.Fatal("New returned nil error for a projector without a rebuild target")
	}
	if !strings.Contains(err.Error(), testEventType) {
		t.Fatalf("New error = %q; want missing event type", err)
	}
}

func TestAppendEvent_StreamOutsideRebuildTargetWritesNothing(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	store, err := newTestStore(pool, map[string]Projector{testEventType: incrementCounter})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	fact := event(testEventType, []byte{1})
	fact.StreamType = "outside-target"
	err = store.AppendEvent(context.Background(), fact)
	if err == nil {
		t.Fatal("AppendEvent returned nil for a stream outside the event's rebuild target")
	}
	if !strings.Contains(err.Error(), "outside-target") {
		t.Fatalf("AppendEvent error = %q; want rejected stream type", err)
	}
	assertNoEvents(t, pool)
	if got := projectionRowCount(t, pool); got != 0 {
		t.Fatalf("projection row count = %d; want 0", got)
	}
}

func TestNew_RebuildTargetWithoutProjectorRejected(t *testing.T) {
	pool := testPostgres(t)
	_, err := New(pool, map[string]Projector{testEventType: incrementCounter}, map[string]RebuildTarget{
		"test": {
			Tables:      []string{"test_projection"},
			StreamTypes: []string{testStreamType},
			EventTypes:  []string{testEventType, "UnknownEvent"},
			Reset:       func(context.Context, ProjectionTx) error { return nil },
		},
	})
	if err == nil {
		t.Fatal("New returned nil error for a rebuild target without a projector")
	}
	if !strings.Contains(err.Error(), "UnknownEvent") {
		t.Fatalf("New error = %q; want unknown event type", err)
	}
}

func TestNew_RebuildTargetsDefensivelyCopied(t *testing.T) {
	pool := testPostgres(t)
	target := RebuildTarget{
		Tables:      []string{"test_projection"},
		StreamTypes: []string{testStreamType},
		EventTypes:  []string{testEventType},
		Reset:       func(context.Context, ProjectionTx) error { return nil },
	}
	targets := map[string]RebuildTarget{"test": target}
	store, err := New(pool, map[string]Projector{testEventType: incrementCounter}, targets)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	target.Tables[0] = "changed_table"
	target.StreamTypes[0] = "changed_stream"
	target.EventTypes[0] = "ChangedEvent"
	delete(targets, "test")
	stored, ok := store.rebuildTargets["test"]
	if !ok {
		t.Fatal("stored rebuild target changed when the caller's map changed")
	}
	if stored.Tables[0] != "test_projection" ||
		stored.StreamTypes[0] != testStreamType ||
		stored.EventTypes[0] != testEventType {
		t.Fatalf("stored rebuild target changed with caller slices: %+v", stored)
	}
}

func TestNew_DuplicateRebuildOwnershipRejected(t *testing.T) {
	pool := testPostgres(t)
	projector := func(context.Context, ProjectionTx, PersistedEvent) error { return nil }
	_, err := New(pool, map[string]Projector{
		"FirstEvent":  projector,
		"SecondEvent": projector,
	}, map[string]RebuildTarget{
		"first": {
			Tables:      []string{"shared_projection"},
			StreamTypes: []string{"first"},
			EventTypes:  []string{"FirstEvent"},
			Reset:       func(context.Context, ProjectionTx) error { return nil },
		},
		"second": {
			Tables:      []string{"shared_projection"},
			StreamTypes: []string{"second"},
			EventTypes:  []string{"SecondEvent"},
			Reset:       func(context.Context, ProjectionTx) error { return nil },
		},
	})
	if err == nil {
		t.Fatal("New returned nil error for duplicate rebuild table ownership")
	}
	if !strings.Contains(err.Error(), "shared_projection") {
		t.Fatalf("New error = %q; want duplicate table name", err)
	}
}

type projectionRow struct {
	streamID string
	count    int
}

func projectionRows(t *testing.T, pool *pgxpool.Pool) []projectionRow {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT stream_id, fact_count FROM test_projection ORDER BY stream_id`)
	if err != nil {
		t.Fatalf("query projection rows: %v", err)
	}
	defer rows.Close()

	var result []projectionRow
	for rows.Next() {
		var row projectionRow
		if err := rows.Scan(&row.streamID, &row.count); err != nil {
			t.Fatalf("scan projection row: %v", err)
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate projection rows: %v", err)
	}
	return result
}
