package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const replayPageSize int32 = 100

// RebuildAll resets and replays one registered projection target.
func (s *Store) RebuildAll(ctx context.Context, targetName string) (retErr error) {
	if s == nil || s.pool == nil {
		return errors.New("store: nil store")
	}
	if ctx == nil {
		return errors.New("store: nil rebuild context")
	}
	if strings.TrimSpace(targetName) == "" {
		return errors.New("store: rebuild target name is empty")
	}
	target, ok := s.rebuildTargets[targetName]
	if !ok {
		return fmt.Errorf("store: rebuild target %q is not registered", targetName)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return fmt.Errorf("store: begin rebuild transaction: %w", err)
	}
	defer func() {
		if err := rollbackTx(ctx, tx); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	queries := generated.New(tx)

	closure, err := queries.RebuildTableClosure(ctx, target.Tables)
	if err != nil {
		return fmt.Errorf("store: inspect rebuild target %q FK closure: %w", targetName, err)
	}
	if err := validateRebuildClosure(targetName, target.Tables, closure); err != nil {
		return err
	}
	if err := target.Reset(ctx, projectionTx{DBTX: tx, skipWork: true}); err != nil {
		return fmt.Errorf("store: reset rebuild target %q: %w", targetName, err)
	}

	var (
		afterStreamType    string
		afterStreamID      string
		afterStreamVersion int64
		replayed           int
	)
	for {
		events, err := queries.ListEventsForReplayPage(ctx, generated.ListEventsForReplayPageParams{
			StreamTypes:        target.StreamTypes,
			AfterStreamType:    afterStreamType,
			AfterStreamID:      afterStreamID,
			AfterStreamVersion: afterStreamVersion,
			PageSize:           replayPageSize,
		})
		if err != nil {
			return fmt.Errorf("store: load events for rebuild target %q: %w", targetName, err)
		}
		for _, row := range events {
			if err := s.replayEvent(
				ctx,
				projectionTx{DBTX: tx, skipWork: true},
				targetName,
				target,
				replayed,
				row,
			); err != nil {
				return err
			}
			replayed++
		}
		if len(events) < int(replayPageSize) {
			break
		}
		last := events[len(events)-1]
		afterStreamType = last.StreamType
		afterStreamID = last.StreamID
		afterStreamVersion = last.StreamVersion
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("store: commit rebuild target %q: %w", targetName, err)
	}
	return nil
}

func (s *Store) replayEvent(
	ctx context.Context,
	tx ProjectionTx,
	targetName string,
	target RebuildTarget,
	index int,
	row generated.Event,
) error {
	if !slices.Contains(target.EventTypes, row.EventType) {
		return fmt.Errorf(
			"store: replay event %d type %q is outside rebuild target %q",
			index,
			row.EventType,
			targetName,
		)
	}
	projector, ok := s.projectors[row.EventType]
	if !ok {
		return fmt.Errorf(
			"store: replay event %d type %q has no registered projector",
			index,
			row.EventType,
		)
	}
	if err := projector(ctx, tx, persistedEvent(row)); err != nil {
		return fmt.Errorf(
			"store: replay event %d type %q for target %q: %w",
			index,
			row.EventType,
			targetName,
			err,
		)
	}
	return nil
}

func validateRebuildClosure(targetName string, targetTables, closure []string) error {
	owned := make(map[string]struct{}, len(targetTables))
	for _, table := range targetTables {
		owned[table] = struct{}{}
	}
	found := make(map[string]struct{}, len(closure))
	var dependents []string
	for _, table := range closure {
		found[table] = struct{}{}
		if _, ok := owned[table]; !ok {
			dependents = append(dependents, table)
		}
	}
	if len(dependents) > 0 {
		slices.Sort(dependents)
		return fmt.Errorf(
			"store: rebuild target %q excludes FK-dependent tables: %s",
			targetName,
			strings.Join(dependents, ", "),
		)
	}

	var missing []string
	for _, table := range targetTables {
		if _, ok := found[table]; !ok {
			missing = append(missing, table)
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf(
			"store: rebuild target %q references missing tables: %s",
			targetName,
			strings.Join(missing, ", "),
		)
	}
	return nil
}
