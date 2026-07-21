package store

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	workQueueAdvisoryLock int64 = 0x706d776f726b
	workHandlerTimeout          = 30 * time.Second
	workFinalizeTimeout         = 5 * time.Second
	workRetryBaseDelay          = 5 * time.Second
	workRetryMaxDelay           = time.Hour
	maxWorkAttempts       int32 = 100
	maxWorkKindBytes            = 128
	maxWorkPayloadBytes         = 2 << 20
	maxWorkErrorBytes           = 4096
)

// Work is durable control-plane work derived from one motivating event.
type Work struct {
	Kind           string
	PayloadVersion int32
	Payload        []byte
	RunAt          time.Time
	MaxAttempts    int32
}

// WorkItem is the persisted work shape passed to a handler.
type WorkItem struct {
	Work
	SourceStreamType    string
	SourceStreamID      string
	SourceStreamVersion int64
	Attempts            int32
	NextAttemptAt       *time.Time
	CreatedAt           time.Time
}

// WorkHandler processes one claimed work item with at-least-once delivery. It
// must use the source event tuple plus work kind as an idempotency key and
// promptly honor context cancellation. Returned errors may be persisted for
// operator triage and therefore must not contain secrets.
type WorkHandler func(context.Context, WorkItem) error

// WorkStats is the doctor-facing work-queue health summary.
type WorkStats struct {
	Depth     int64
	Exhausted int64
}

// WorkQueue drains durable work from Postgres.
type WorkQueue struct {
	pool           *pgxpool.Pool
	handlers       map[string]WorkHandler
	handlerTimeout time.Duration
}

// NewWorkQueue returns a work queue with a defensive handler registry.
func NewWorkQueue(pool *pgxpool.Pool, handlers map[string]WorkHandler) (*WorkQueue, error) {
	if pool == nil {
		return nil, errors.New("store: nil Postgres pool")
	}
	if len(handlers) == 0 {
		return nil, errors.New("store: work handler registry is empty")
	}
	registry := make(map[string]WorkHandler, len(handlers))
	for _, kind := range slices.Sorted(maps.Keys(handlers)) {
		handler := handlers[kind]
		if err := validateWorkKind(kind); err != nil {
			return nil, fmt.Errorf("store: invalid work handler kind: %w", err)
		}
		if handler == nil {
			return nil, fmt.Errorf("store: work handler for kind %q is nil", kind)
		}
		registry[kind] = handler
	}
	return &WorkQueue{
		pool:           pool,
		handlers:       registry,
		handlerTimeout: workHandlerTimeout,
	}, nil
}

// EnqueueWork writes work in the projector's append transaction.
func (tx projectionTx) EnqueueWork(ctx context.Context, work Work) error {
	if ctx == nil {
		return errors.New("store: nil enqueue-work context")
	}
	if tx.skipWork {
		return nil
	}
	if tx.DBTX == nil || tx.sourceEvent == nil {
		return errors.New("store: work enqueue is outside an event projector")
	}
	if err := validateWork(work); err != nil {
		return err
	}
	event := tx.sourceEvent
	if err := generated.New(tx.DBTX).InsertWork(ctx, generated.InsertWorkParams{
		SourceStreamType:    event.StreamType,
		SourceStreamID:      event.StreamID,
		SourceStreamVersion: event.StreamVersion,
		WorkKind:            work.Kind,
		PayloadVersion:      work.PayloadVersion,
		Payload:             work.Payload,
		RunAt:               work.RunAt,
		MaxAttempts:         work.MaxAttempts,
	}); err != nil {
		return fmt.Errorf("store: enqueue work kind %q: %w", work.Kind, err)
	}
	return nil
}

// RunOnce claims and handles at most one due work item.
func (q *WorkQueue) RunOnce(ctx context.Context) (processed bool, retErr error) {
	if q == nil || q.pool == nil {
		return false, errors.New("store: nil work queue")
	}
	if ctx == nil {
		return false, errors.New("store: nil work-queue context")
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("store: work-queue context: %w", err)
	}

	runCtx, cancelRun := context.WithTimeout(
		context.WithoutCancel(ctx),
		q.handlerTimeout+workFinalizeTimeout,
	)
	defer cancelRun()
	tx, err := q.pool.Begin(runCtx)
	if err != nil {
		return false, fmt.Errorf("store: begin work transaction: %w", err)
	}
	defer func() {
		if err := rollbackTx(runCtx, tx); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	queries := generated.New(tx)

	locked, err := queries.TryWorkQueueLock(runCtx, workQueueAdvisoryLock)
	if err != nil {
		return false, fmt.Errorf("store: acquire work-queue advisory lock: %w", err)
	}
	if !locked {
		return false, nil
	}
	row, err := queries.ClaimDueWork(runCtx)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: claim due work: %w", err)
	}
	item := workItem(row)
	processed = true

	handler, ok := q.handlers[item.Kind]
	var handlerErr error
	if !ok {
		handlerErr = fmt.Errorf("store: no work handler registered for kind %q", item.Kind)
	} else {
		handlerCtx, cancelHandler := context.WithTimeout(runCtx, q.handlerTimeout)
		handlerErr = invokeWorkHandler(handlerCtx, handler, item)
		cancelHandler()
	}
	if handlerErr != nil {
		retryDelaySeconds := int64(workRetryDelay(item.Attempts+1) / time.Second)
		attempts, recordErr := queries.RecordWorkFailure(runCtx, generated.RecordWorkFailureParams{
			RetryDelaySeconds:   retryDelaySeconds,
			LastError:           boundedWorkError(handlerErr),
			SourceStreamType:    item.SourceStreamType,
			SourceStreamID:      item.SourceStreamID,
			SourceStreamVersion: item.SourceStreamVersion,
			WorkKind:            item.Kind,
		})
		if recordErr != nil {
			return true, errors.Join(
				fmt.Errorf("store: process work kind %q: %w", item.Kind, handlerErr),
				fmt.Errorf("store: record work failure: %w", recordErr),
			)
		}
		if attempts != item.Attempts+1 {
			return true, fmt.Errorf(
				"store: record work failure advanced attempts to %d; want %d",
				attempts,
				item.Attempts+1,
			)
		}
		if err := tx.Commit(runCtx); err != nil {
			return true, errors.Join(
				fmt.Errorf("store: process work kind %q: %w", item.Kind, handlerErr),
				fmt.Errorf("store: commit work failure: %w", err),
			)
		}
		return true, fmt.Errorf("store: process work kind %q: %w", item.Kind, handlerErr)
	}

	deleted, err := queries.CompleteWork(runCtx, generated.CompleteWorkParams{
		SourceStreamType:    item.SourceStreamType,
		SourceStreamID:      item.SourceStreamID,
		SourceStreamVersion: item.SourceStreamVersion,
		WorkKind:            item.Kind,
	})
	if err != nil {
		return true, fmt.Errorf("store: complete work kind %q: %w", item.Kind, err)
	}
	if deleted != 1 {
		return true, fmt.Errorf("store: complete work kind %q deleted %d rows; want 1", item.Kind, deleted)
	}
	if err := tx.Commit(runCtx); err != nil {
		return true, fmt.Errorf("store: commit completed work kind %q: %w", item.Kind, err)
	}
	return true, nil
}

// Stats returns the total and exhausted work-item counts.
func (q *WorkQueue) Stats(ctx context.Context) (WorkStats, error) {
	if q == nil || q.pool == nil {
		return WorkStats{}, errors.New("store: nil work queue")
	}
	if ctx == nil {
		return WorkStats{}, errors.New("store: nil work-stats context")
	}
	row, err := generated.New(q.pool).WorkStats(ctx)
	if err != nil {
		return WorkStats{}, fmt.Errorf("store: read work stats: %w", err)
	}
	return WorkStats{Depth: row.Depth, Exhausted: row.Exhausted}, nil
}

func validateWork(work Work) error {
	if err := validateWorkKind(work.Kind); err != nil {
		return err
	}
	if work.PayloadVersion <= 0 {
		return errors.New("store: work payload version must be positive")
	}
	if work.Payload == nil {
		return errors.New("store: work payload is nil")
	}
	if len(work.Payload) > maxWorkPayloadBytes {
		return fmt.Errorf("store: work payload exceeds %d bytes", maxWorkPayloadBytes)
	}
	if work.RunAt.IsZero() {
		return errors.New("store: work run time is zero")
	}
	if work.MaxAttempts <= 0 || work.MaxAttempts > maxWorkAttempts {
		return fmt.Errorf("store: work maximum attempts must be between 1 and %d", maxWorkAttempts)
	}
	return nil
}

func validateWorkKind(kind string) error {
	if strings.TrimSpace(kind) == "" {
		return errors.New("store: work kind is empty")
	}
	if len(kind) > maxWorkKindBytes {
		return fmt.Errorf("store: work kind exceeds %d bytes", maxWorkKindBytes)
	}
	if !utf8.ValidString(kind) {
		return errors.New("store: work kind is not valid UTF-8")
	}
	return nil
}

func workItem(row generated.ClaimDueWorkRow) WorkItem {
	var nextAttemptAt *time.Time
	if row.NextAttemptAt.Valid {
		next := row.NextAttemptAt.Time
		nextAttemptAt = &next
	}
	return WorkItem{
		Work: Work{
			Kind:           row.WorkKind,
			PayloadVersion: row.PayloadVersion,
			Payload:        row.Payload,
			RunAt:          row.RunAt,
			MaxAttempts:    row.MaxAttempts,
		},
		SourceStreamType:    row.SourceStreamType,
		SourceStreamID:      row.SourceStreamID,
		SourceStreamVersion: row.SourceStreamVersion,
		Attempts:            row.Attempts,
		NextAttemptAt:       nextAttemptAt,
		CreatedAt:           row.CreatedAt,
	}
}

func invokeWorkHandler(ctx context.Context, handler WorkHandler, item WorkItem) (retErr error) {
	defer func() {
		if recover() != nil {
			retErr = errors.New("work handler panicked")
		}
	}()
	return handler(ctx, item)
}

func workRetryDelay(attempt int32) time.Duration {
	delay := workRetryBaseDelay
	for current := int32(1); current < attempt && delay < workRetryMaxDelay; current++ {
		delay *= 2
		if delay > workRetryMaxDelay {
			return workRetryMaxDelay
		}
	}
	return delay
}

func boundedWorkError(err error) string {
	message := strings.ToValidUTF8(err.Error(), "�")
	if len(message) <= maxWorkErrorBytes {
		return message
	}
	message = message[:maxWorkErrorBytes]
	for !utf8.ValidString(message) {
		message = message[:len(message)-1]
	}
	return message
}
