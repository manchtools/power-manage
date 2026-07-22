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
       registration_token_id, owner, updated_at
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
    updated_at = sqlc.arg(updated_at)
WHERE device_id = sqlc.arg(device_id)
  AND projection_version = sqlc.arg(previous_projection_version)
  AND certificate_der = sqlc.arg(superseded_certificate_der);

-- name: ResetDevices :exec
DELETE FROM devices;
