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

-- name: ResetDevices :exec
DELETE FROM devices;
