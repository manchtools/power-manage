package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// DeviceLifecycle is the transaction-limited capability passed while one
// device's Postgres advisory lock is held. It exposes neither transaction
// control nor arbitrary projection mutation.
type DeviceLifecycle struct {
	store    *Store
	tx       pgx.Tx
	queries  *generated.Queries
	deviceID string
	active   bool
	appended bool
}

// WithDeviceLifecycleLock serializes one device's certificate lifecycle and
// commits the callback's version-pinned event append in the same transaction.
func (s *Store) WithDeviceLifecycleLock(
	ctx context.Context,
	deviceID string,
	operation func(*DeviceLifecycle) error,
) (retErr error) {
	if err := s.validateAppendCall(ctx); err != nil {
		return err
	}
	if operation == nil {
		return errors.New("store: nil device lifecycle operation")
	}
	deviceID, err := canonicalDeviceID(deviceID)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("store: begin device lifecycle transaction: %w", err)
	}
	defer func() {
		if err := rollbackTx(ctx, tx); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	queries := generated.New(tx)
	if err := queries.AcquireDeviceLifecycleLock(ctx, deviceID); err != nil {
		return fmt.Errorf("store: acquire device lifecycle lock: %w", err)
	}
	lifecycle := &DeviceLifecycle{
		store:    s,
		tx:       tx,
		queries:  queries,
		deviceID: deviceID,
		active:   true,
	}
	if err := operation(lifecycle); err != nil {
		lifecycle.active = false
		return err
	}
	lifecycle.active = false
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit device lifecycle transaction: %w", err)
	}
	return nil
}

// Device reads the authoritative projection inside the held lifecycle lock.
func (l *DeviceLifecycle) Device(ctx context.Context) (Device, error) {
	if err := l.validate(ctx); err != nil {
		return Device{}, err
	}
	row, err := l.queries.GetDevice(ctx, l.deviceID)
	if err != nil {
		return Device{}, fmt.Errorf("store: read locked device: %w", err)
	}
	return deviceFromRowWithFingerprintPolicy(l.deviceID, row, false)
}

// Gateway reads the authoritative gateway projection inside the held lock.
func (l *DeviceLifecycle) Gateway(ctx context.Context) (Gateway, error) {
	if err := l.validate(ctx); err != nil {
		return Gateway{}, err
	}
	row, err := l.queries.GetGateway(ctx, l.deviceID)
	if err != nil {
		return Gateway{}, fmt.Errorf("store: read locked gateway: %w", err)
	}
	return gatewayFromRow(l.deviceID, row, false)
}

// AppendEvent performs one expected-version append inside the held lifecycle
// transaction. Only events owned by the device rebuild target are accepted.
func (l *DeviceLifecycle) AppendEvent(ctx context.Context, event Event, expectedVersion int64) error {
	return l.appendEventFor(ctx, event, expectedVersion, deviceStreamType, DeviceRebuildTarget)
}

// AppendGatewayEvent appends one gateway lifecycle event under the same
// transaction-limited advisory-lock capability.
func (l *DeviceLifecycle) AppendGatewayEvent(ctx context.Context, event Event, expectedVersion int64) error {
	return l.appendEventFor(ctx, event, expectedVersion, gatewayStreamType, GatewayRebuildTarget)
}

func (l *DeviceLifecycle) appendEventFor(
	ctx context.Context,
	event Event,
	expectedVersion int64,
	streamType string,
	rebuildTarget string,
) error {
	if err := l.validate(ctx); err != nil {
		return err
	}
	if l.appended {
		return errors.New("store: device lifecycle already appended an event")
	}
	if expectedVersion < 0 {
		return errors.New("store: expected version must not be negative")
	}
	prepared, err := l.store.prepareEvent(event)
	if err != nil {
		return err
	}
	if prepared.StreamType != streamType || prepared.StreamID != l.deviceID ||
		l.store.eventTargets[prepared.EventType] != rebuildTarget {
		return errors.New("store: device lifecycle event does not belong to the locked device")
	}
	currentVersion, err := l.queries.CurrentStreamVersion(ctx, generated.CurrentStreamVersionParams{
		StreamType: streamType,
		StreamID:   l.deviceID,
	})
	if err != nil {
		return fmt.Errorf("store: read locked device stream version: %w", err)
	}
	if currentVersion != expectedVersion {
		return fmt.Errorf("%w: expected %d, current %d", errVersionConflict, expectedVersion, currentVersion)
	}
	if err := appendPrepared(ctx, l.tx, l.queries, prepared, expectedVersion+1); err != nil {
		if isStreamVersionConflict(err) {
			return fmt.Errorf("%w: expected %d", errVersionConflict, expectedVersion)
		}
		return fmt.Errorf("store: append locked device lifecycle event: %w", err)
	}
	l.appended = true
	return nil
}

func (l *DeviceLifecycle) validate(ctx context.Context) error {
	if l == nil || l.store == nil || l.tx == nil || l.queries == nil || !l.active || l.deviceID == "" {
		return errors.New("store: device lifecycle is not active")
	}
	if ctx == nil {
		return errors.New("store: nil device lifecycle context")
	}
	return ctx.Err()
}
