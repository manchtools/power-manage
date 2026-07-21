-- name: InsertWork :exec
INSERT INTO work_items (
    source_stream_type,
    source_stream_id,
    source_stream_version,
    work_kind,
    payload_version,
    payload,
    run_at,
    max_attempts
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: TryWorkQueueLock :one
SELECT pg_try_advisory_xact_lock(sqlc.arg(lock_key)::bigint);

-- name: ClaimDueWork :one
SELECT source_stream_type, source_stream_id, source_stream_version,
       work_kind, payload_version, payload, run_at, attempts, max_attempts,
       next_attempt_at, created_at
FROM work_items
WHERE attempts < max_attempts
  AND run_at <= clock_timestamp()
  AND (next_attempt_at IS NULL OR next_attempt_at <= clock_timestamp())
ORDER BY COALESCE(next_attempt_at, run_at), created_at,
         source_stream_type, source_stream_id, source_stream_version, work_kind
LIMIT 1
FOR UPDATE SKIP LOCKED;

-- name: CompleteWork :execrows
DELETE FROM work_items
WHERE source_stream_type = $1
  AND source_stream_id = $2
  AND source_stream_version = $3
  AND work_kind = $4;

-- name: RecordWorkFailure :one
UPDATE work_items
SET attempts = attempts + 1,
    next_attempt_at = clock_timestamp()
        + (sqlc.arg(retry_delay_seconds)::bigint * interval '1 second'),
    last_error = sqlc.arg(last_error)::text
WHERE source_stream_type = sqlc.arg(source_stream_type)
  AND source_stream_id = sqlc.arg(source_stream_id)
  AND source_stream_version = sqlc.arg(source_stream_version)
  AND work_kind = sqlc.arg(work_kind)
RETURNING attempts;

-- name: WorkStats :one
SELECT count(*)::bigint AS depth,
       count(*) FILTER (WHERE attempts >= max_attempts)::bigint AS exhausted
FROM work_items;
