// Package store provides the Postgres-backed event store.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
	"github.com/manchtools/power-manage/server/internal/store/migrations"
)

const (
	eventsStreamVersionConstraint = "events_stream_version_key"
	rollbackTimeout               = 5 * time.Second
	appendRetryBaseDelay          = time.Millisecond
	appendRetryMaxDelay           = 50 * time.Millisecond
)

var errVersionConflict = errors.New("store: version conflict")

// Event is an unpersisted, versioned domain event payload.
type Event struct {
	StreamType     string
	StreamID       string
	EventType      string
	PayloadVersion int32
	Payload        []byte
}

// PersistedEvent is the event shape passed to an in-transaction projector.
type PersistedEvent struct {
	Event
	StreamVersion int64
	CreatedAt     time.Time
}

// ProjectionTx is the query capability exposed to projectors. It deliberately
// omits transaction control so a projector cannot commit or roll back the
// append transaction independently.
type ProjectionTx interface {
	generated.DBTX
}

type projectionTx struct {
	generated.DBTX
}

type preparedEvent struct {
	Event
	projector Projector
}

// Projector updates a read model using the same transaction as its event.
type Projector func(context.Context, ProjectionTx, PersistedEvent) error

// Store appends events and invokes their registered projectors atomically.
type Store struct {
	pool       *pgxpool.Pool
	projectors map[string]Projector
}

// New returns a Store with a defensive copy of the projector registry.
func New(pool *pgxpool.Pool, projectors map[string]Projector) (*Store, error) {
	if pool == nil {
		return nil, errors.New("store: nil Postgres pool")
	}

	registry := make(map[string]Projector, len(projectors))
	for eventType, projector := range projectors {
		if strings.TrimSpace(eventType) == "" {
			return nil, errors.New("store: projector event type is empty")
		}
		if projector == nil {
			return nil, fmt.Errorf("store: projector for event type %q is nil", eventType)
		}
		registry[eventType] = projector
	}

	return &Store{pool: pool, projectors: registry}, nil
}

// Migrate applies the embedded server migrations to dsn.
func Migrate(ctx context.Context, dsn string) (retErr error) {
	if ctx == nil {
		return errors.New("store: nil migration context")
	}
	if strings.TrimSpace(dsn) == "" {
		return errors.New("store: empty Postgres DSN")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("store: open migration database: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("store: close migration database: %w", err))
		}
	}()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("store: ping migration database: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("store: create migration provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("store: apply migrations: %w", err)
	}
	return nil
}

// AppendEvent assigns the next stream version, persists event, and runs its
// projector before commit. Composite-key conflicts are retried for independent
// facts; bounded-use consumers use AppendEventWithVersion instead.
func (s *Store) AppendEvent(ctx context.Context, event Event) error {
	if err := s.validateAppendCall(ctx); err != nil {
		return err
	}
	prepared, err := s.prepareEvent(event)
	if err != nil {
		return err
	}

	for attempt := 0; ; attempt++ {
		retry, err := s.appendAutoBatchOnce(ctx, []preparedEvent{prepared})
		if err != nil {
			return fmt.Errorf("store: append event: %w", err)
		}
		if !retry {
			return nil
		}
		// Each exact conflict proves another writer progressed. Back off to avoid
		// a hot retry loop, while the caller's context remains the total bound
		// required by AppendEvent's auto-retry contract.
		if err := waitAppendRetry(ctx, attempt); err != nil {
			return fmt.Errorf("store: wait to retry stream-version conflict: %w", err)
		}
	}
}

// AppendEventWithVersion appends at expectedVersion+1 only when the stream is
// still at expectedVersion. A conflict is returned without retrying.
func (s *Store) AppendEventWithVersion(ctx context.Context, event Event, expectedVersion int64) (retErr error) {
	if err := s.validateAppendCall(ctx); err != nil {
		return err
	}
	if expectedVersion < 0 {
		return errors.New("store: expected version must not be negative")
	}
	prepared, err := s.prepareEvent(event)
	if err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin version-pinned append transaction: %w", err)
	}
	defer func() {
		if err := rollbackTx(ctx, tx); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	queries := generated.New(tx)

	currentVersion, err := queries.CurrentStreamVersion(ctx, generated.CurrentStreamVersionParams{
		StreamType: prepared.StreamType,
		StreamID:   prepared.StreamID,
	})
	if err != nil {
		return fmt.Errorf("store: read stream version: %w", err)
	}
	if currentVersion != expectedVersion {
		return fmt.Errorf("%w: expected %d, current %d", errVersionConflict, expectedVersion, currentVersion)
	}
	if err := appendPrepared(ctx, tx, queries, prepared, expectedVersion+1); err != nil {
		if isStreamVersionConflict(err) {
			return fmt.Errorf("%w: expected %d", errVersionConflict, expectedVersion)
		}
		return fmt.Errorf("store: version-pinned append: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit version-pinned append transaction: %w", err)
	}
	return nil
}

// AppendEvents appends and projects the ordered batch in one transaction.
func (s *Store) AppendEvents(ctx context.Context, events []Event) error {
	if err := s.validateAppendCall(ctx); err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}

	prepared := make([]preparedEvent, len(events))
	for i, event := range events {
		var err error
		prepared[i], err = s.prepareEvent(event)
		if err != nil {
			return fmt.Errorf("store: prepare batch event %d: %w", i, err)
		}
	}

	retry, err := s.appendAutoBatchOnce(ctx, prepared)
	if err != nil {
		return fmt.Errorf("store: append events: %w", err)
	}
	if retry {
		return fmt.Errorf("%w: batch stream changed concurrently", errVersionConflict)
	}
	return nil
}

// IsVersionConflict recognizes the stable error returned by version-pinned appends.
func IsVersionConflict(err error) bool {
	return errors.Is(err, errVersionConflict)
}

func (s *Store) validateAppendCall(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("store: nil store")
	}
	if ctx == nil {
		return errors.New("store: nil append context")
	}
	return nil
}

func (s *Store) prepareEvent(event Event) (preparedEvent, error) {
	if err := validateEvent(event); err != nil {
		return preparedEvent{}, err
	}
	event.StreamID = strings.ToUpper(event.StreamID)
	projector, ok := s.projectors[event.EventType]
	if !ok {
		return preparedEvent{}, fmt.Errorf("store: no projector registered for event type %q", event.EventType)
	}
	return preparedEvent{Event: event, projector: projector}, nil
}

func (s *Store) appendAutoBatchOnce(ctx context.Context, events []preparedEvent) (retry bool, retErr error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin append transaction: %w", err)
	}
	defer func() {
		if err := rollbackTx(ctx, tx); err != nil {
			retry = false
			retErr = errors.Join(retErr, err)
		}
	}()
	queries := generated.New(tx)

	for i, event := range events {
		currentVersion, err := queries.CurrentStreamVersion(ctx, generated.CurrentStreamVersionParams{
			StreamType: event.StreamType,
			StreamID:   event.StreamID,
		})
		if err != nil {
			return false, fmt.Errorf("event %d: read stream version: %w", i, err)
		}
		if err := appendPrepared(ctx, tx, queries, event, currentVersion+1); err != nil {
			if isStreamVersionConflict(err) {
				return true, nil
			}
			return false, fmt.Errorf("event %d: %w", i, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit append transaction: %w", err)
	}
	return false, nil
}

func appendPrepared(
	ctx context.Context,
	tx pgx.Tx,
	queries *generated.Queries,
	event preparedEvent,
	streamVersion int64,
) error {
	row, err := queries.InsertEvent(ctx, generated.InsertEventParams{
		StreamType:     event.StreamType,
		StreamID:       event.StreamID,
		StreamVersion:  streamVersion,
		EventType:      event.EventType,
		PayloadVersion: event.PayloadVersion,
		Payload:        event.Payload,
	})
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	persisted := PersistedEvent{
		Event: Event{
			StreamType:     row.StreamType,
			StreamID:       row.StreamID,
			EventType:      row.EventType,
			PayloadVersion: row.PayloadVersion,
			Payload:        row.Payload,
		},
		StreamVersion: row.StreamVersion,
		CreatedAt:     row.CreatedAt,
	}
	if err := event.projector(ctx, projectionTx{DBTX: tx}, persisted); err != nil {
		return fmt.Errorf("project event %q: %w", event.EventType, err)
	}
	return nil
}

func validateEvent(event Event) error {
	if strings.TrimSpace(event.StreamType) == "" {
		return errors.New("store: stream type is empty")
	}
	if err := validate.ULIDPathID(event.StreamID); err != nil {
		return fmt.Errorf("store: invalid stream ID: %w", err)
	}
	if strings.TrimSpace(event.EventType) == "" {
		return errors.New("store: event type is empty")
	}
	if event.PayloadVersion <= 0 {
		return errors.New("store: payload version must be positive")
	}
	if event.Payload == nil {
		return errors.New("store: payload is nil")
	}
	return nil
}

func isStreamVersionConflict(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) &&
		postgresError.Code == "23505" &&
		postgresError.ConstraintName == eventsStreamVersionConstraint
}

func waitAppendRetry(ctx context.Context, attempt int) error {
	steps := min(max(attempt, 0), 6)
	delay := appendRetryBaseDelay
	for range steps {
		delay *= 2
	}
	if delay > appendRetryMaxDelay {
		delay = appendRetryMaxDelay
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func rollbackTx(ctx context.Context, tx pgx.Tx) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if err := tx.Rollback(rollbackCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("store: roll back append transaction: %w", err)
	}
	return nil
}
