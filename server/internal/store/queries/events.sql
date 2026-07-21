-- name: CurrentStreamVersion :one
SELECT COALESCE(MAX(stream_version), 0)::bigint AS stream_version
FROM events
WHERE stream_type = $1 AND stream_id = $2;

-- name: InsertEvent :one
INSERT INTO events (
    stream_type,
    stream_id,
    stream_version,
    event_type,
    payload_version,
    payload
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING stream_type, stream_id, stream_version, event_type,
          payload_version, payload, created_at;
