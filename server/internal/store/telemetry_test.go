package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestExecutionOutput_OversizedChunkMarksTruncated(t *testing.T) {
	pool := testPostgres(t)
	telemetry, err := NewTelemetryStore(pool)
	if err != nil {
		t.Fatalf("create telemetry store: %v", err)
	}
	result, err := telemetry.AppendExecutionOutput(
		context.Background(),
		testStreamID,
		make([]byte, maxExecutionOutputChunkBytes+1),
	)
	if err != nil {
		t.Fatalf("append oversized output chunk: %v", err)
	}
	if result.Stored || !result.Truncated || result.OutputBytes != 0 || result.OutputChunks != 0 {
		t.Fatalf("oversized output result = %+v; want unstored truncation", result)
	}
	assertExecutionOutputState(t, pool, testStreamID, executionOutputState{truncated: true})
}

func TestExecutionOutput_ByteCapMarksTruncated(t *testing.T) {
	pool := testPostgres(t)
	seedExecutionOutputState(t, pool, testStreamID, maxExecutionOutputBytes-1, 0)
	telemetry, err := NewTelemetryStore(pool)
	if err != nil {
		t.Fatalf("create telemetry store: %v", err)
	}
	result, err := telemetry.AppendExecutionOutput(context.Background(), testStreamID, []byte{1, 2})
	if err != nil {
		t.Fatalf("append over byte cap: %v", err)
	}
	if result.Stored || !result.Truncated || result.OutputBytes != maxExecutionOutputBytes-1 {
		t.Fatalf("over-byte-cap result = %+v; want unchanged bytes and truncation", result)
	}
}

func TestExecutionOutput_ChunkCapMarksTruncated(t *testing.T) {
	pool := testPostgres(t)
	seedExecutionOutputState(t, pool, testStreamID, 0, maxExecutionOutputChunks)
	telemetry, err := NewTelemetryStore(pool)
	if err != nil {
		t.Fatalf("create telemetry store: %v", err)
	}
	result, err := telemetry.AppendExecutionOutput(context.Background(), testStreamID, []byte{1})
	if err != nil {
		t.Fatalf("append over chunk cap: %v", err)
	}
	if result.Stored || !result.Truncated || result.OutputChunks != maxExecutionOutputChunks {
		t.Fatalf("over-chunk-cap result = %+v; want unchanged chunks and truncation", result)
	}
}

func TestExecutionOutput_ConcurrentWritersRespectCaps(t *testing.T) {
	pool := testPostgres(t)
	seedExecutionOutputState(t, pool, testStreamID, maxExecutionOutputBytes-3, 0)
	telemetry, err := NewTelemetryStore(pool)
	if err != nil {
		t.Fatalf("create telemetry store: %v", err)
	}

	const writers = 8
	var stored atomic.Int32
	errCh := make(chan error, writers)
	var group sync.WaitGroup
	for range writers {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := telemetry.AppendExecutionOutput(context.Background(), testStreamID, []byte{1})
			if err != nil {
				errCh <- err
				return
			}
			if result.Stored {
				stored.Add(1)
			}
		}()
	}
	group.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent output append: %v", err)
	}
	if got := stored.Load(); got != 3 {
		t.Fatalf("stored concurrent chunks = %d; want exactly 3 remaining bytes", got)
	}
	assertExecutionOutputState(t, pool, testStreamID, executionOutputState{
		bytes:     maxExecutionOutputBytes,
		chunks:    3,
		truncated: true,
	})
}

func TestExecutionOutput_LowercaseIDCanonicalized(t *testing.T) {
	pool := testPostgres(t)
	telemetry, err := NewTelemetryStore(pool)
	if err != nil {
		t.Fatalf("create telemetry store: %v", err)
	}
	lowercaseID := strings.ToLower(testStreamID)
	if _, err := telemetry.AppendExecutionOutput(
		context.Background(),
		lowercaseID,
		[]byte("output"),
	); err != nil {
		t.Fatalf("append output with lowercase execution ID: %v", err)
	}
	chunks, err := telemetry.ReadExecutionOutput(context.Background(), lowercaseID, -1, 1)
	if err != nil {
		t.Fatalf("read output with lowercase execution ID: %v", err)
	}
	if len(chunks) != 1 || !bytes.Equal(chunks[0].Body, []byte("output")) {
		t.Fatalf("lowercase-ID output chunks = %+v; want one canonicalized chunk", chunks)
	}
	assertExecutionOutputState(t, pool, testStreamID, executionOutputState{bytes: 6, chunks: 1})
}

func TestExecutionOutput_ReadIsLimitBounded(t *testing.T) {
	pool := testPostgres(t)
	telemetry, err := NewTelemetryStore(pool)
	if err != nil {
		t.Fatalf("create telemetry store: %v", err)
	}
	for _, body := range [][]byte{[]byte("one"), []byte("two"), []byte("three")} {
		if _, err := telemetry.AppendExecutionOutput(context.Background(), testStreamID, body); err != nil {
			t.Fatalf("append output chunk %q: %v", body, err)
		}
	}
	chunks, err := telemetry.ReadExecutionOutput(context.Background(), testStreamID, -1, 2)
	if err != nil {
		t.Fatalf("read output chunks: %v", err)
	}
	if len(chunks) != 2 || chunks[0].Index != 0 || !bytes.Equal(chunks[0].Body, []byte("one")) ||
		chunks[1].Index != 1 || !bytes.Equal(chunks[1].Body, []byte("two")) {
		t.Fatalf("bounded output chunks = %+v; want first two chunks", chunks)
	}
	_, err = telemetry.ReadExecutionOutput(
		context.Background(),
		testStreamID,
		-1,
		maxExecutionOutputReadChunks+1,
	)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized read limit error = %v; want limit validation", err)
	}
}

func TestExecutionOutput_SchemaRejectsOversizedChunk(t *testing.T) {
	pool := testPostgres(t)
	seedExecutionOutputState(t, pool, testStreamID, 0, 0)
	_, err := pool.Exec(context.Background(), `
		INSERT INTO execution_output_chunks (execution_id, chunk_index, body)
		VALUES ($1, 0, $2)`, testStreamID, make([]byte, maxExecutionOutputChunkBytes+1))
	var postgresError *pgconn.PgError
	if err == nil || !errors.As(err, &postgresError) || postgresError.Code != "23514" {
		t.Fatalf("oversized raw chunk error = %v; want SQLSTATE 23514", err)
	}
}

type executionOutputState struct {
	bytes     int64
	chunks    int32
	truncated bool
}

func seedExecutionOutputState(
	t *testing.T,
	pool *pgxpool.Pool,
	executionID string,
	bytes int64,
	chunks int32,
) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO execution_outputs (
			execution_id, output_bytes, output_chunks, truncated, updated_at
		) VALUES ($1, $2, $3, false, clock_timestamp())`, executionID, bytes, chunks); err != nil {
		t.Fatalf("seed execution output state: %v", err)
	}
}

func assertExecutionOutputState(
	t *testing.T,
	pool *pgxpool.Pool,
	executionID string,
	want executionOutputState,
) {
	t.Helper()
	var got executionOutputState
	if err := pool.QueryRow(context.Background(), `
		SELECT output_bytes, output_chunks, truncated
		FROM execution_outputs
		WHERE execution_id = $1`, executionID).Scan(&got.bytes, &got.chunks, &got.truncated); err != nil {
		t.Fatalf("read execution output state: %v", err)
	}
	if got != want {
		t.Fatalf("execution output state = %+v; want %+v", got, want)
	}
}
