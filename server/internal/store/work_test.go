package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testWorkKind = "test-control-job"

func TestNewWorkQueue_InvalidRegistryRejected(t *testing.T) {
	pool := testPostgres(t)
	handler := func(context.Context, WorkItem) error { return nil }
	tests := []struct {
		name     string
		pool     *pgxpool.Pool
		handlers map[string]WorkHandler
		want     string
	}{
		{name: "nil pool", handlers: map[string]WorkHandler{testWorkKind: handler}, want: "store: nil Postgres pool"},
		{name: "empty registry", pool: pool, handlers: nil, want: "store: work handler registry is empty"},
		{name: "empty kind", pool: pool, handlers: map[string]WorkHandler{" ": handler}, want: "store: work kind is empty"},
		{name: "oversized kind", pool: pool, handlers: map[string]WorkHandler{strings.Repeat("k", maxWorkKindBytes+1): handler}, want: "store: work kind exceeds 128 bytes"},
		{name: "invalid UTF-8 kind", pool: pool, handlers: map[string]WorkHandler{string([]byte{0xff}): handler}, want: "store: work kind is not valid UTF-8"},
		{name: "nil handler", pool: pool, handlers: map[string]WorkHandler{testWorkKind: nil}, want: `store: work handler for kind "test-control-job" is nil`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewWorkQueue(test.pool, test.handlers)
			if err == nil {
				t.Fatal("NewWorkQueue returned nil error for an invalid registry")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("NewWorkQueue error = %q; want it to contain %q", err, test.want)
			}
		})
	}
}

func TestNewWorkQueue_HandlerRegistryDefensivelyCopied(t *testing.T) {
	pool := testPostgres(t)
	handler := func(context.Context, WorkItem) error { return nil }
	handlers := map[string]WorkHandler{testWorkKind: handler}
	queue, err := NewWorkQueue(pool, handlers)
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}
	delete(handlers, testWorkKind)
	if queue.handlers[testWorkKind] == nil {
		t.Fatal("stored handler registry changed when the caller's map changed")
	}
}

func TestAppendEvent_InvalidWorkWritesNothing(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	tests := []struct {
		name string
		work Work
		want string
	}{
		{name: "empty kind", work: Work{PayloadVersion: 1, Payload: []byte{1}, RunAt: time.Now(), MaxAttempts: 1}, want: "store: work kind is empty"},
		{name: "oversized kind", work: Work{Kind: strings.Repeat("k", maxWorkKindBytes+1), PayloadVersion: 1, Payload: []byte{1}, RunAt: time.Now(), MaxAttempts: 1}, want: "store: work kind exceeds 128 bytes"},
		{name: "invalid UTF-8 kind", work: Work{Kind: string([]byte{0xff}), PayloadVersion: 1, Payload: []byte{1}, RunAt: time.Now(), MaxAttempts: 1}, want: "store: work kind is not valid UTF-8"},
		{name: "zero payload version", work: Work{Kind: testWorkKind, Payload: []byte{1}, RunAt: time.Now(), MaxAttempts: 1}, want: "store: work payload version must be positive"},
		{name: "nil payload", work: Work{Kind: testWorkKind, PayloadVersion: 1, RunAt: time.Now(), MaxAttempts: 1}, want: "store: work payload is nil"},
		{name: "oversized payload", work: Work{Kind: testWorkKind, PayloadVersion: 1, Payload: make([]byte, maxWorkPayloadBytes+1), RunAt: time.Now(), MaxAttempts: 1}, want: "store: work payload exceeds 2097152 bytes"},
		{name: "zero run time", work: Work{Kind: testWorkKind, PayloadVersion: 1, Payload: []byte{1}, MaxAttempts: 1}, want: "store: work run time is zero"},
		{name: "zero attempts", work: Work{Kind: testWorkKind, PayloadVersion: 1, Payload: []byte{1}, RunAt: time.Now()}, want: "store: work maximum attempts must be between 1 and 100"},
		{name: "too many attempts", work: Work{Kind: testWorkKind, PayloadVersion: 1, Payload: []byte{1}, RunAt: time.Now(), MaxAttempts: maxWorkAttempts + 1}, want: "store: work maximum attempts must be between 1 and 100"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := testStoreEnqueuingWork(t, pool, test.work, nil)
			err := store.AppendEvent(context.Background(), event(testEventType, []byte{1}))
			if err == nil {
				t.Fatal("AppendEvent returned nil error for invalid work")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("AppendEvent error = %q; want it to contain %q", err, test.want)
			}
			assertNoEvents(t, pool)
			if got := projectionRowCount(t, pool); got != 0 {
				t.Fatalf("projection row count = %d; want 0", got)
			}
			if got := workItemCount(t, pool); got != 0 {
				t.Fatalf("work item count = %d; want 0", got)
			}
		})
	}
}

func TestWorkItems_SizeConstraints(t *testing.T) {
	pool := testPostgres(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO events (
			stream_type, stream_id, stream_version,
			event_type, payload_version, payload
		) VALUES ($1, $2, 1, $3, 1, $4)`,
		testStreamType,
		testStreamID,
		testEventType,
		[]byte{1},
	); err != nil {
		t.Fatalf("insert source event: %v", err)
	}
	tests := []struct {
		name    string
		kind    string
		payload []byte
	}{
		{name: "oversized kind", kind: strings.Repeat("k", maxWorkKindBytes+1), payload: []byte{1}},
		{name: "oversized payload", kind: testWorkKind, payload: make([]byte, maxWorkPayloadBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, `
				INSERT INTO work_items (
					source_stream_type, source_stream_id, source_stream_version,
					work_kind, payload_version, payload, run_at, max_attempts
				) VALUES ($1, $2, 1, $3, 1, $4, clock_timestamp(), 1)`,
				testStreamType,
				testStreamID,
				test.kind,
				test.payload,
			)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "23514" {
				t.Fatalf("oversized work insert error = %v; want SQLSTATE 23514", err)
			}
			if got := workItemCount(t, pool); got != 0 {
				t.Fatalf("work item count = %d; want 0", got)
			}
		})
	}
}

func TestAppendEvent_EnqueuesWorkAtomically(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	runAt := time.Now().UTC().Add(time.Minute).Truncate(time.Microsecond)
	wantWork := Work{
		Kind:           testWorkKind,
		PayloadVersion: 1,
		Payload:        []byte("intent"),
		RunAt:          runAt,
		MaxAttempts:    3,
	}
	store := testStoreEnqueuingWork(t, pool, wantWork, nil)

	if err := store.AppendEvent(context.Background(), event(testEventType, []byte{1})); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	if got := eventCount(t, pool); got != 1 {
		t.Fatalf("event count = %d; want 1", got)
	}
	if got := projectionCount(t, pool); got != 1 {
		t.Fatalf("projection count = %d; want 1", got)
	}

	var got struct {
		streamType     string
		streamID       string
		streamVersion  int64
		kind           string
		payloadVersion int32
		payload        []byte
		runAt          time.Time
		attempts       int32
		maxAttempts    int32
	}
	if err := pool.QueryRow(context.Background(), `
		SELECT source_stream_type, source_stream_id, source_stream_version,
		       work_kind, payload_version, payload, run_at, attempts, max_attempts
		FROM work_items`).Scan(
		&got.streamType,
		&got.streamID,
		&got.streamVersion,
		&got.kind,
		&got.payloadVersion,
		&got.payload,
		&got.runAt,
		&got.attempts,
		&got.maxAttempts,
	); err != nil {
		t.Fatalf("read enqueued work: %v", err)
	}
	if got.streamType != testStreamType || got.streamID != testStreamID || got.streamVersion != 1 {
		t.Fatalf("work source = (%q, %q, %d); want motivating event", got.streamType, got.streamID, got.streamVersion)
	}
	if got.kind != wantWork.Kind || got.payloadVersion != wantWork.PayloadVersion ||
		!bytes.Equal(got.payload, wantWork.Payload) || !got.runAt.Equal(wantWork.RunAt) ||
		got.attempts != 0 || got.maxAttempts != wantWork.MaxAttempts {
		t.Fatalf("enqueued work = %+v; want %+v with zero attempts", got, wantWork)
	}
}

func TestAppendEvent_EnqueueThenProjectorFailureRollsBack(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	wantErr := errors.New("projector failed after enqueue")
	store := testStoreEnqueuingWork(t, pool, dueTestWork(3), wantErr)

	err := store.AppendEvent(context.Background(), event(testEventType, []byte{1}))
	if !errors.Is(err, wantErr) {
		t.Fatalf("AppendEvent error = %v; want projector failure", err)
	}
	assertNoEvents(t, pool)
	if got := projectionRowCount(t, pool); got != 0 {
		t.Fatalf("projection row count = %d; want 0", got)
	}
	if got := workItemCount(t, pool); got != 0 {
		t.Fatalf("work item count = %d; want 0", got)
	}
}

func TestWorkQueue_ConcurrentWorkersProcessOnce(t *testing.T) {
	pool := testPostgres(t)
	enqueueTestWork(t, pool, dueTestWork(3))

	var calls atomic.Int32
	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	var startedOnce sync.Once
	handler := func(ctx context.Context, _ WorkItem) error {
		calls.Add(1)
		startedOnce.Do(func() { close(handlerStarted) })
		select {
		case <-releaseHandler:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	queue, err := NewWorkQueue(pool, map[string]WorkHandler{testWorkKind: handler})
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	type result struct {
		processed bool
		err       error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			processed, err := queue.RunOnce(ctx)
			results <- result{processed: processed, err: err}
		}()
	}
	close(start)
	select {
	case <-handlerStarted:
	case <-ctx.Done():
		t.Fatalf("wait for claimed work handler: %v", ctx.Err())
	}
	close(releaseHandler)

	processed := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("RunOnce: %v", result.err)
		}
		if result.processed {
			processed++
		}
	}
	if processed != 1 {
		t.Fatalf("workers reporting processed work = %d; want 1", processed)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("handler calls = %d; want 1", got)
	}
	if got := workItemCount(t, pool); got != 0 {
		t.Fatalf("work item count = %d; want 0 after success", got)
	}
}

func TestWorkQueue_AdvisoryLockSerializesQueue(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	store := testStoreEnqueuingWork(t, pool, dueTestWork(3), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := store.AppendEvent(ctx, event(testEventType, []byte{1})); err != nil {
		t.Fatalf("append first work event: %v", err)
	}
	second := event(testEventType, []byte{2})
	second.StreamID = "01J00000000000000000000002"
	if err := store.AppendEvent(ctx, second); err != nil {
		t.Fatalf("append second work event: %v", err)
	}

	var calls atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	handler := func(ctx context.Context, _ WorkItem) error {
		if calls.Add(1) == 1 {
			close(firstStarted)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	queue, err := NewWorkQueue(pool, map[string]WorkHandler{testWorkKind: handler})
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}
	firstResult := make(chan error, 1)
	go func() {
		processed, err := queue.RunOnce(ctx)
		if !processed && err == nil {
			err = errors.New("first RunOnce did not process due work")
		}
		firstResult <- err
	}()
	select {
	case <-firstStarted:
	case <-ctx.Done():
		t.Fatalf("wait for first work handler: %v", ctx.Err())
	}

	processed, secondErr := queue.RunOnce(ctx)
	close(releaseFirst)
	select {
	case err := <-firstResult:
		if err != nil {
			t.Fatalf("first RunOnce: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("wait for first RunOnce: %v", ctx.Err())
	}
	if secondErr != nil || processed {
		t.Fatalf("second RunOnce while advisory lock held = (%t, %v); want no work", processed, secondErr)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("handler calls while advisory lock held = %d; want 1", got)
	}
	if got := workItemCount(t, pool); got != 1 {
		t.Fatalf("work item count = %d; want second item left queued", got)
	}
}

func TestWorkQueue_SkipLockedProcessesAnotherRow(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	store := testStoreEnqueuingWork(t, pool, dueTestWork(3), nil)
	ctx := context.Background()
	if err := store.AppendEvent(ctx, event(testEventType, []byte{1})); err != nil {
		t.Fatalf("append first work event: %v", err)
	}
	second := event(testEventType, []byte{2})
	second.StreamID = "01J00000000000000000000002"
	if err := store.AppendEvent(ctx, second); err != nil {
		t.Fatalf("append second work event: %v", err)
	}

	locker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin row-lock transaction: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := locker.Rollback(cleanupCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("roll back row-lock transaction: %v", err)
		}
	})
	var lockedStreamID string
	if err := locker.QueryRow(ctx, `
		SELECT source_stream_id
		FROM work_items
		ORDER BY source_stream_id
		LIMIT 1
		FOR UPDATE`).Scan(&lockedStreamID); err != nil {
		t.Fatalf("lock first work item: %v", err)
	}

	var handledStreamID string
	queue, err := NewWorkQueue(pool, map[string]WorkHandler{
		testWorkKind: func(_ context.Context, item WorkItem) error {
			handledStreamID = item.SourceStreamID
			return nil
		},
	})
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}
	processed, err := queue.RunOnce(ctx)
	if err != nil || !processed {
		t.Fatalf("RunOnce with first row locked = (%t, %v); want another row processed", processed, err)
	}
	if handledStreamID == "" || handledStreamID == lockedStreamID {
		t.Fatalf("handled stream ID = %q; want row other than locked %q", handledStreamID, lockedStreamID)
	}
	if got := workItemCount(t, pool); got != 1 {
		t.Fatalf("work item count = %d; want locked row to remain", got)
	}
}

func TestWorkQueue_HonorsRunAtAndRetryBackoff(t *testing.T) {
	pool := testPostgres(t)
	work := dueTestWork(3)
	work.RunAt = time.Now().UTC().Add(time.Hour)
	enqueueTestWork(t, pool, work)

	wantErr := errors.New("transient failure")
	var calls atomic.Int32
	handler := func(context.Context, WorkItem) error {
		if calls.Add(1) == 1 {
			return wantErr
		}
		return nil
	}
	queue, err := NewWorkQueue(pool, map[string]WorkHandler{testWorkKind: handler})
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}
	ctx := context.Background()

	processed, err := queue.RunOnce(ctx)
	if err != nil || processed {
		t.Fatalf("future RunOnce = (%t, %v); want no work", processed, err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("future handler calls = %d; want 0", got)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE work_items SET run_at = clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatalf("make work due: %v", err)
	}

	processed, err = queue.RunOnce(ctx)
	if !processed || !errors.Is(err, wantErr) {
		t.Fatalf("failed RunOnce = (%t, %v); want processed transient failure", processed, err)
	}
	var attempts int32
	var nextAttemptAt time.Time
	var retryPending bool
	if err := pool.QueryRow(ctx, `
		SELECT attempts, next_attempt_at, next_attempt_at > clock_timestamp()
		FROM work_items`).Scan(&attempts, &nextAttemptAt, &retryPending); err != nil {
		t.Fatalf("read retry state: %v", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d; want 1", attempts)
	}
	if !retryPending {
		t.Fatalf("next attempt = %s; want future backoff", nextAttemptAt)
	}
	processed, err = queue.RunOnce(ctx)
	if err != nil || processed {
		t.Fatalf("backed-off RunOnce = (%t, %v); want no work", processed, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE work_items SET next_attempt_at = clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatalf("make retry due: %v", err)
	}

	processed, err = queue.RunOnce(ctx)
	if err != nil || !processed {
		t.Fatalf("successful retry RunOnce = (%t, %v); want processed success", processed, err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("handler calls = %d; want 2", got)
	}
	if got := workItemCount(t, pool); got != 0 {
		t.Fatalf("work item count = %d; want 0 after successful retry", got)
	}
}

func TestWorkQueue_PostEffectFailureRedeliversStableSource(t *testing.T) {
	pool := testPostgres(t)
	enqueueTestWork(t, pool, dueTestWork(3))

	wantErr := errors.New("commit acknowledgement lost")
	var (
		calls       int
		sideEffects int
		firstSource string
		seenSources = make(map[string]struct{})
	)
	handler := func(_ context.Context, item WorkItem) error {
		calls++
		source := fmt.Sprintf(
			"%s:%s:%d:%s",
			item.SourceStreamType,
			item.SourceStreamID,
			item.SourceStreamVersion,
			item.Kind,
		)
		if _, seen := seenSources[source]; !seen {
			seenSources[source] = struct{}{}
			sideEffects++
		}
		if calls == 1 {
			firstSource = source
			return wantErr
		}
		if source != firstSource {
			return fmt.Errorf("redelivery source = %q; want stable %q", source, firstSource)
		}
		return nil
	}
	queue, err := NewWorkQueue(pool, map[string]WorkHandler{testWorkKind: handler})
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}
	ctx := context.Background()
	processed, err := queue.RunOnce(ctx)
	if !processed || !errors.Is(err, wantErr) {
		t.Fatalf("first RunOnce = (%t, %v); want recorded post-effect failure", processed, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE work_items SET next_attempt_at = clock_timestamp() - interval '1 second'`); err != nil {
		t.Fatalf("make redelivery due: %v", err)
	}
	processed, err = queue.RunOnce(ctx)
	if err != nil || !processed {
		t.Fatalf("redelivery RunOnce = (%t, %v); want processed success", processed, err)
	}
	if calls != 2 || sideEffects != 1 {
		t.Fatalf("redelivery calls=%d side effects=%d; want 2 calls and 1 idempotent effect", calls, sideEffects)
	}
	if got := workItemCount(t, pool); got != 0 {
		t.Fatalf("work item count = %d; want 0 after acknowledged redelivery", got)
	}
}

func TestWorkQueue_ExhaustedRemainsVisible(t *testing.T) {
	pool := testPostgres(t)
	enqueueTestWork(t, pool, dueTestWork(1))

	wantErr := errors.New("permanent failure")
	var calls atomic.Int32
	queue, err := NewWorkQueue(pool, map[string]WorkHandler{
		testWorkKind: func(context.Context, WorkItem) error {
			calls.Add(1)
			return wantErr
		},
	})
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}
	processed, err := queue.RunOnce(context.Background())
	if !processed || !errors.Is(err, wantErr) {
		t.Fatalf("RunOnce = (%t, %v); want processed permanent failure", processed, err)
	}

	stats, err := queue.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.Depth != 1 || stats.Exhausted != 1 {
		t.Fatalf("work stats = %+v; want depth 1, exhausted 1", stats)
	}
	processed, err = queue.RunOnce(context.Background())
	if err != nil || processed {
		t.Fatalf("exhausted RunOnce = (%t, %v); want no work", processed, err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("handler calls = %d; want 1", got)
	}
}

func TestWorkQueue_HandlerPanicRecovered(t *testing.T) {
	pool := testPostgres(t)
	enqueueTestWork(t, pool, dueTestWork(1))
	queue, err := NewWorkQueue(pool, map[string]WorkHandler{
		testWorkKind: func(context.Context, WorkItem) error {
			panic("handler panic")
		},
	})
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}

	processed, err := queue.RunOnce(context.Background())
	if !processed || err == nil || !strings.Contains(err.Error(), "handler panicked") {
		t.Fatalf("RunOnce = (%t, %v); want recovered panic failure", processed, err)
	}
	stats, statsErr := queue.Stats(context.Background())
	if statsErr != nil {
		t.Fatalf("Stats: %v", statsErr)
	}
	if stats.Exhausted != 1 {
		t.Fatalf("exhausted work count = %d; want 1", stats.Exhausted)
	}
}

func TestWorkQueue_HandlerTimeoutRecorded(t *testing.T) {
	pool := testPostgres(t)
	enqueueTestWork(t, pool, dueTestWork(1))
	queue, err := NewWorkQueue(pool, map[string]WorkHandler{
		testWorkKind: func(ctx context.Context, _ WorkItem) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}
	queue.handlerTimeout = 20 * time.Millisecond

	processed, err := queue.RunOnce(context.Background())
	if !processed || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunOnce = (%t, %v); want recorded handler deadline", processed, err)
	}
	stats, statsErr := queue.Stats(context.Background())
	if statsErr != nil {
		t.Fatalf("Stats: %v", statsErr)
	}
	if stats.Exhausted != 1 {
		t.Fatalf("exhausted work count = %d; want 1", stats.Exhausted)
	}
}

func TestWorkQueue_HandlerFinishesAfterCallerCancellation(t *testing.T) {
	pool := testPostgres(t)
	enqueueTestWork(t, pool, dueTestWork(1))
	handlerStarted := make(chan struct{})
	callerCancelled := make(chan struct{})
	queue, err := NewWorkQueue(pool, map[string]WorkHandler{
		testWorkKind: func(ctx context.Context, _ WorkItem) error {
			close(handlerStarted)
			<-callerCancelled
			select {
			case <-ctx.Done():
				return errors.New("detached handler context was cancelled with caller")
			default:
				return nil
			}
		},
	})
	if err != nil {
		t.Fatalf("create work queue: %v", err)
	}
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelWait()
	callerCtx, cancel := context.WithCancel(waitCtx)
	result := make(chan error, 1)
	go func() {
		processed, err := queue.RunOnce(callerCtx)
		if !processed && err == nil {
			err = errors.New("RunOnce did not process due work")
		}
		result <- err
	}()
	select {
	case <-handlerStarted:
	case <-waitCtx.Done():
		t.Fatalf("wait for detached work handler: %v", waitCtx.Err())
	}
	cancel()
	close(callerCancelled)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("RunOnce after caller cancellation: %v", err)
		}
	case <-waitCtx.Done():
		t.Fatalf("wait for detached RunOnce completion: %v", waitCtx.Err())
	}
	if got := workItemCount(t, pool); got != 0 {
		t.Fatalf("work item count = %d; want 0 after detached completion", got)
	}
}

func TestRebuildAll_DoesNotReenqueueWork(t *testing.T) {
	pool := testPostgres(t)
	createCounterProjection(t, pool)
	store := testStoreEnqueuingWork(t, pool, dueTestWork(3), nil)
	ctx := context.Background()
	if err := store.AppendEvent(ctx, event(testEventType, []byte{1})); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}
	secondStreamID := "01J00000000000000000000002"
	second := event(testEventType, []byte{2})
	second.StreamID = secondStreamID
	if err := store.AppendEvent(ctx, second); err != nil {
		t.Fatalf("append second event: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE work_items
		SET attempts = max_attempts,
		    next_attempt_at = clock_timestamp() + interval '1 hour',
		    last_error = 'redacted failure'
		WHERE source_stream_id = $1`, testStreamID); err != nil {
		t.Fatalf("seed exhausted work state: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		DELETE FROM work_items WHERE source_stream_id = $1`, secondStreamID); err != nil {
		t.Fatalf("simulate completed work: %v", err)
	}
	type runtimeState struct {
		payload       []byte
		attempts      int32
		nextAttemptAt time.Time
		lastError     string
	}
	var before runtimeState
	if err := pool.QueryRow(ctx, `
		SELECT payload, attempts, next_attempt_at, last_error
		FROM work_items
		WHERE source_stream_id = $1`, testStreamID).Scan(
		&before.payload,
		&before.attempts,
		&before.nextAttemptAt,
		&before.lastError,
	); err != nil {
		t.Fatalf("read work state before rebuild: %v", err)
	}

	if err := store.RebuildAll(ctx, "test"); err != nil {
		t.Fatalf("RebuildAll: %v", err)
	}
	projection := projectionRows(t, pool)
	if len(projection) != 2 || projection[0].count != 1 || projection[1].count != 1 {
		t.Fatalf("rebuilt projection rows = %+v; want two one-event rows", projection)
	}
	if got := workItemCount(t, pool); got != 1 {
		t.Fatalf("work item count = %d; want one exhausted row and no resurrected row", got)
	}
	var after runtimeState
	if err := pool.QueryRow(ctx, `
		SELECT payload, attempts, next_attempt_at, last_error
		FROM work_items
		WHERE source_stream_id = $1`, testStreamID).Scan(
		&after.payload,
		&after.attempts,
		&after.nextAttemptAt,
		&after.lastError,
	); err != nil {
		t.Fatalf("read work state after rebuild: %v", err)
	}
	if !bytes.Equal(before.payload, after.payload) || before.attempts != after.attempts ||
		!before.nextAttemptAt.Equal(after.nextAttemptAt) || before.lastError != after.lastError {
		t.Fatalf("work runtime state changed across rebuild: before=%+v after=%+v", before, after)
	}
}

func dueTestWork(maxAttempts int32) Work {
	return Work{
		Kind:           testWorkKind,
		PayloadVersion: 1,
		Payload:        []byte("intent"),
		RunAt:          time.Now().UTC().Add(-time.Minute),
		MaxAttempts:    maxAttempts,
	}
}

func enqueueTestWork(t *testing.T, pool *pgxpool.Pool, work Work) {
	t.Helper()
	createCounterProjection(t, pool)
	store := testStoreEnqueuingWork(t, pool, work, nil)
	if err := store.AppendEvent(context.Background(), event(testEventType, []byte{1})); err != nil {
		t.Fatalf("append event with work: %v", err)
	}
}

func testStoreEnqueuingWork(
	t *testing.T,
	pool *pgxpool.Pool,
	work Work,
	afterEnqueue error,
) *Store {
	t.Helper()
	projector := func(ctx context.Context, tx ProjectionTx, persisted PersistedEvent) error {
		if err := incrementCounter(ctx, tx, persisted); err != nil {
			return err
		}
		if err := tx.EnqueueWork(ctx, work); err != nil {
			return err
		}
		return afterEnqueue
	}
	store, err := newTestStore(pool, map[string]Projector{testEventType: projector})
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	return store
}

func workItemCount(t *testing.T, pool interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM work_items`).Scan(&count); err != nil {
		t.Fatalf("count work items: %v", err)
	}
	return count
}
