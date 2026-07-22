-- name: UpsertDeviceEnrollment :execrows
INSERT INTO devices (
    device_id,
    projection_version,
    certificate_der,
    certificate_fingerprint,
    sealing_public_key,
    registration_token_id,
    owner,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (device_id) DO NOTHING;

-- name: GetDevice :one
SELECT device_id, projection_version, certificate_der,
       certificate_fingerprint, sealing_public_key,
       registration_token_id, owner, lifecycle_state, updated_at,
       previous_certificate_der
FROM devices
WHERE device_id = $1;

-- name: AcquireDeviceLifecycleLock :exec
SELECT pg_advisory_xact_lock(hashtextextended('device:' || sqlc.arg(device_id)::text, 0));

-- name: UpdateDeviceRenewal :execrows
UPDATE devices
SET projection_version = sqlc.arg(projection_version),
    certificate_der = sqlc.arg(certificate_der),
    certificate_fingerprint = sqlc.arg(certificate_fingerprint),
    sealing_public_key = sqlc.arg(sealing_public_key),
    previous_certificate_der = sqlc.arg(superseded_certificate_der),
    lifecycle_state = 'active',
    updated_at = sqlc.arg(updated_at)
WHERE device_id = sqlc.arg(device_id)
  AND projection_version = sqlc.arg(previous_projection_version)
  AND certificate_der = sqlc.arg(superseded_certificate_der)
  AND lifecycle_state IN ('active', 'force_renewal');

-- name: UpdateDeviceLifecycleState :execrows
UPDATE devices
SET projection_version = sqlc.arg(projection_version),
    lifecycle_state = sqlc.arg(lifecycle_state),
    updated_at = sqlc.arg(updated_at)
WHERE device_id = sqlc.arg(device_id)
  AND projection_version = sqlc.arg(previous_projection_version)
  AND certificate_der = sqlc.arg(certificate_der)
  AND (
      lifecycle_state = sqlc.arg(previous_lifecycle_state)
      OR (
          sqlc.arg(allow_force_renewal)::boolean
          AND lifecycle_state = 'force_renewal'
      )
  );

-- name: ResetDevices :exec
DELETE FROM devices;
