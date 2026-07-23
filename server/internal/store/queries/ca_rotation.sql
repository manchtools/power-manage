-- name: GetCARotationState :one
SELECT projection_version, state_json
FROM ca_rotation_state
WHERE certificate_class = $1;

-- name: GetLifecycleEventGlobalPosition :one
SELECT global_position
FROM events
WHERE stream_type = $1 AND stream_id = $2 AND stream_version = $3;

-- name: GetLatestCARotationEventAtPosition :one
SELECT payload, stream_version
FROM events
WHERE stream_type = 'ca-rotation'
  AND stream_id = $1
  AND global_position <= $2
ORDER BY global_position DESC
LIMIT 1;

-- name: GetFirstCARotationEventAfterPosition :one
SELECT payload
FROM events
WHERE stream_type = 'ca-rotation'
  AND stream_id = $1
  AND global_position > $2
ORDER BY global_position
LIMIT 1;

-- name: ListActiveTrustConsumers :many
SELECT 'gateway'::text AS reporter_class,
       gateway_id AS reporter_id,
       certificate_der
FROM gateways
WHERE sqlc.arg(claimed_class)::text = 'agent'
  AND lifecycle_state <> 'revoked'
UNION ALL
SELECT 'agent'::text AS reporter_class,
       device_id AS reporter_id,
       certificate_der
FROM devices
WHERE sqlc.arg(claimed_class)::text = 'gateway'
  AND lifecycle_state <> 'revoked'
ORDER BY reporter_id;

-- name: ListTrustConfirmationPayloads :many
SELECT payload
FROM events
WHERE stream_type = 'ca-trust-confirmation'
  AND stream_id = $1
  AND event_type = $2
ORDER BY stream_version;

-- name: TrustConfirmationEventExists :one
SELECT EXISTS (
    SELECT 1
    FROM events
    WHERE stream_type = 'ca-trust-confirmation'
      AND stream_id = $1
      AND event_type = $2
      AND payload = $3
);

-- name: ListCAMigrationReportEntries :many
SELECT device_id AS reporter_id,
       certificate_der,
       lifecycle_state::text AS lifecycle_state
FROM devices
WHERE sqlc.arg(certificate_class)::text = 'agent'
  AND device_id > sqlc.arg(cursor)::text
UNION ALL
SELECT gateway_id AS reporter_id,
       certificate_der,
       lifecycle_state::text AS lifecycle_state
FROM gateways
WHERE sqlc.arg(certificate_class)::text = 'gateway'
  AND gateway_id > sqlc.arg(cursor)::text
ORDER BY reporter_id
LIMIT sqlc.arg(page_size)::integer;

-- name: UpsertCARotationState :execrows
INSERT INTO ca_rotation_state (
    certificate_class,
    projection_version,
    state_json,
    updated_at
) VALUES ($1, $2, $3, $4)
ON CONFLICT (certificate_class) DO UPDATE
SET projection_version = EXCLUDED.projection_version,
    state_json = EXCLUDED.state_json,
    updated_at = EXCLUDED.updated_at
WHERE ca_rotation_state.projection_version = EXCLUDED.projection_version - 1;

-- name: ResetCARotationState :exec
DELETE FROM ca_rotation_state;
