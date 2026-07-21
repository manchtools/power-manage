-- name: EnsureExecutionOutput :exec
INSERT INTO execution_outputs (
    execution_id,
    output_bytes,
    output_chunks,
    truncated,
    updated_at
) VALUES ($1, 0, 0, false, clock_timestamp())
ON CONFLICT (execution_id) DO NOTHING;

-- name: GetExecutionOutputForUpdate :one
SELECT output_bytes, output_chunks, truncated
FROM execution_outputs
WHERE execution_id = $1
FOR UPDATE;

-- name: MarkExecutionOutputTruncated :one
UPDATE execution_outputs
SET truncated = true,
    updated_at = clock_timestamp()
WHERE execution_id = $1
RETURNING output_bytes, output_chunks, truncated;

-- name: InsertExecutionOutputChunk :exec
INSERT INTO execution_output_chunks (
    execution_id,
    chunk_index,
    body
) VALUES ($1, $2, $3);

-- name: AdvanceExecutionOutput :one
UPDATE execution_outputs
SET output_bytes = output_bytes + sqlc.arg(chunk_bytes)::bigint,
    output_chunks = output_chunks + 1,
    updated_at = clock_timestamp()
WHERE execution_id = sqlc.arg(execution_id)
RETURNING output_bytes, output_chunks, truncated;

-- name: ReadExecutionOutput :many
SELECT chunk_index, body
FROM execution_output_chunks
WHERE execution_id = sqlc.arg(execution_id)
  AND chunk_index > sqlc.arg(after_chunk)::integer
ORDER BY chunk_index
LIMIT sqlc.arg(page_size)::integer;
