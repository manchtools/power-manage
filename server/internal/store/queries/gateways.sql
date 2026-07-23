-- name: UpsertGatewayEnrollment :execrows
INSERT INTO gateways (
    gateway_id,
    projection_version,
    certificate_der,
    certificate_fingerprint,
    registration_token_id,
    owner,
    dns_names,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (gateway_id) DO NOTHING;

-- name: GetGateway :one
SELECT gateway_id, projection_version, certificate_der,
       certificate_fingerprint, previous_certificate_der,
       registration_token_id, owner, dns_names, lifecycle_state, updated_at
FROM gateways
WHERE gateway_id = $1;

-- name: UpdateGatewayRenewal :execrows
UPDATE gateways
SET projection_version = sqlc.arg(projection_version),
    certificate_der = sqlc.arg(certificate_der),
    certificate_fingerprint = sqlc.arg(certificate_fingerprint),
    previous_certificate_der = sqlc.arg(superseded_certificate_der),
    updated_at = sqlc.arg(updated_at)
WHERE gateway_id = sqlc.arg(gateway_id)
  AND projection_version = sqlc.arg(previous_projection_version)
  AND certificate_der = sqlc.arg(superseded_certificate_der)
  AND lifecycle_state = 'active';

-- name: UpdateGatewayLifecycleState :execrows
UPDATE gateways
SET projection_version = sqlc.arg(projection_version),
    lifecycle_state = 'revoked',
    updated_at = sqlc.arg(updated_at)
WHERE gateway_id = sqlc.arg(gateway_id)
  AND projection_version = sqlc.arg(previous_projection_version)
  AND certificate_der = sqlc.arg(certificate_der)
  AND lifecycle_state = 'active';

-- name: ResetGateways :exec
DELETE FROM gateways;
