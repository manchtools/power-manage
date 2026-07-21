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

-- name: ListEventsForReplayPage :many
SELECT stream_type, stream_id, stream_version, event_type,
       payload_version, payload, created_at
FROM events
WHERE stream_type = ANY(sqlc.arg(stream_types)::text[])
  AND (stream_type, stream_id, stream_version) > (
      sqlc.arg(after_stream_type)::text,
      sqlc.arg(after_stream_id)::text,
      sqlc.arg(after_stream_version)::bigint
  )
ORDER BY stream_type, stream_id, stream_version
LIMIT sqlc.arg(page_size)::integer;

-- name: RebuildTableClosure :many
WITH RECURSIVE target_tables AS (
    SELECT class.oid, class.relname::text AS table_name
    FROM pg_catalog.pg_class AS class
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relkind IN ('r', 'p')
      AND class.relname = ANY(sqlc.arg(table_names)::text[])
), fk_closure AS (
    SELECT oid, table_name
    FROM target_tables
    UNION
    SELECT child.oid, child.relname::text AS table_name
    FROM fk_closure AS parent
    JOIN pg_catalog.pg_constraint AS fk
      ON fk.contype = 'f'
     AND fk.confrelid = parent.oid
    JOIN pg_catalog.pg_class AS child
      ON child.oid = fk.conrelid
    JOIN pg_catalog.pg_namespace AS child_namespace
      ON child_namespace.oid = child.relnamespace
     AND child_namespace.nspname = 'public'
)
SELECT table_name
FROM fk_closure
ORDER BY table_name;
