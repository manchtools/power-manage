package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	maxExecutionOutputBytes      int64 = 10 << 20
	maxExecutionOutputChunks     int32 = 1024
	maxExecutionOutputChunkBytes       = 64 << 10
	maxExecutionOutputReadChunks int32 = 100
)

// OutputWriteResult reports whether a chunk was stored and the resulting cap state.
type OutputWriteResult struct {
	Stored       bool
	Truncated    bool
	OutputBytes  int64
	OutputChunks int32
}

// OutputChunk is one bounded execution-output chunk.
type OutputChunk struct {
	Index int32
	Body  []byte
}

// TelemetryStore stores bounded operational execution output.
type TelemetryStore struct {
	pool *pgxpool.Pool
}

// NewTelemetryStore returns an operational telemetry store.
func NewTelemetryStore(pool *pgxpool.Pool) (*TelemetryStore, error) {
	if pool == nil {
		return nil, errors.New("store: nil Postgres pool")
	}
	return &TelemetryStore{pool: pool}, nil
}

// AppendExecutionOutput appends one bounded output chunk.
func (s *TelemetryStore) AppendExecutionOutput(
	ctx context.Context,
	executionID string,
	body []byte,
) (result OutputWriteResult, retErr error) {
	if s == nil || s.pool == nil {
		return result, errors.New("store: nil telemetry store")
	}
	if ctx == nil {
		return result, errors.New("store: nil execution-output context")
	}
	if err := validate.ULIDPathID(executionID); err != nil {
		return result, fmt.Errorf("store: invalid execution ID: %w", err)
	}
	executionID = strings.ToUpper(executionID)
	if len(body) == 0 {
		return result, errors.New("store: execution-output chunk is empty")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, fmt.Errorf("store: begin execution-output transaction: %w", err)
	}
	defer func() {
		if err := rollbackTx(ctx, tx); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()
	queries := generated.New(tx)
	if err := queries.EnsureExecutionOutput(ctx, executionID); err != nil {
		return result, fmt.Errorf("store: ensure execution-output state: %w", err)
	}
	state, err := queries.GetExecutionOutputForUpdate(ctx, executionID)
	if err != nil {
		return result, fmt.Errorf("store: lock execution-output state: %w", err)
	}
	result = OutputWriteResult{
		Truncated:    state.Truncated,
		OutputBytes:  state.OutputBytes,
		OutputChunks: state.OutputChunks,
	}
	if state.Truncated {
		return result, nil
	}
	if len(body) > maxExecutionOutputChunkBytes ||
		state.OutputBytes > maxExecutionOutputBytes-int64(len(body)) ||
		state.OutputChunks >= maxExecutionOutputChunks {
		truncated, err := queries.MarkExecutionOutputTruncated(ctx, executionID)
		if err != nil {
			return result, fmt.Errorf("store: mark execution output truncated: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return result, fmt.Errorf("store: commit execution-output truncation: %w", err)
		}
		return OutputWriteResult{
			Truncated:    truncated.Truncated,
			OutputBytes:  truncated.OutputBytes,
			OutputChunks: truncated.OutputChunks,
		}, nil
	}
	if err := queries.InsertExecutionOutputChunk(ctx, generated.InsertExecutionOutputChunkParams{
		ExecutionID: executionID,
		ChunkIndex:  state.OutputChunks,
		Body:        body,
	}); err != nil {
		return result, fmt.Errorf("store: insert execution-output chunk: %w", err)
	}
	advanced, err := queries.AdvanceExecutionOutput(ctx, generated.AdvanceExecutionOutputParams{
		ChunkBytes:  int64(len(body)),
		ExecutionID: executionID,
	})
	if err != nil {
		return result, fmt.Errorf("store: advance execution-output state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("store: commit execution-output chunk: %w", err)
	}
	return OutputWriteResult{
		Stored:       true,
		Truncated:    advanced.Truncated,
		OutputBytes:  advanced.OutputBytes,
		OutputChunks: advanced.OutputChunks,
	}, nil
}

// ReadExecutionOutput reads a bounded page of output chunks.
func (s *TelemetryStore) ReadExecutionOutput(
	ctx context.Context,
	executionID string,
	afterChunk int32,
	limit int32,
) ([]OutputChunk, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil telemetry store")
	}
	if ctx == nil {
		return nil, errors.New("store: nil execution-output read context")
	}
	if err := validate.ULIDPathID(executionID); err != nil {
		return nil, fmt.Errorf("store: invalid execution ID: %w", err)
	}
	executionID = strings.ToUpper(executionID)
	if afterChunk < -1 {
		return nil, errors.New("store: execution-output cursor is below -1")
	}
	if limit <= 0 || limit > maxExecutionOutputReadChunks {
		return nil, fmt.Errorf(
			"store: execution-output read limit must be between 1 and %d",
			maxExecutionOutputReadChunks,
		)
	}
	rows, err := generated.New(s.pool).ReadExecutionOutput(ctx, generated.ReadExecutionOutputParams{
		ExecutionID: executionID,
		AfterChunk:  afterChunk,
		PageSize:    limit,
	})
	if err != nil {
		return nil, fmt.Errorf("store: read execution-output chunks: %w", err)
	}
	chunks := make([]OutputChunk, len(rows))
	for index, row := range rows {
		chunks[index] = OutputChunk{Index: row.ChunkIndex, Body: bytes.Clone(row.Body)}
	}
	return chunks, nil
}
