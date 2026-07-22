-- name: InsertCertificateRevocation :execrows
INSERT INTO certificate_revocations (
    certificate_class,
    certificate_fingerprint,
    certificate_der,
    serial_number,
    revoked_at,
    reason_code,
    source_stream_type,
    source_stream_id,
    source_stream_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (certificate_class, certificate_fingerprint) DO NOTHING;

-- name: GetCertificateRevocation :one
SELECT certificate_class, certificate_fingerprint, certificate_der,
       serial_number, revoked_at, reason_code,
       source_stream_type, source_stream_id, source_stream_version
FROM certificate_revocations
WHERE certificate_class = $1 AND certificate_fingerprint = $2;

-- name: ListCertificateRevocations :many
SELECT certificate_class, certificate_fingerprint, certificate_der,
       serial_number, revoked_at, reason_code,
       source_stream_type, source_stream_id, source_stream_version
FROM certificate_revocations
WHERE certificate_class = $1
ORDER BY revoked_at, certificate_fingerprint;

-- name: ResetAgentCertificateRevocations :exec
DELETE FROM certificate_revocations
WHERE certificate_class = 'agent';

-- name: GetCRLState :one
SELECT certificate_class, sequence, crl_der, issued_at,
       source_stream_type, source_stream_id, source_stream_version
FROM crl_state
WHERE certificate_class = $1;

-- name: CompareAndSwapCRLState :execrows
UPDATE crl_state
SET sequence = sqlc.arg(next_sequence),
    crl_der = sqlc.arg(crl_der),
    issued_at = sqlc.arg(issued_at),
    source_stream_type = sqlc.narg(source_stream_type),
    source_stream_id = sqlc.narg(source_stream_id),
    source_stream_version = sqlc.narg(source_stream_version)
WHERE certificate_class = sqlc.arg(certificate_class)
  AND sequence = sqlc.arg(expected_sequence);

-- name: CompareAndSwapCRLStateForWork :execrows
WITH advanced AS (
    UPDATE crl_state
    SET sequence = sqlc.arg(next_sequence),
        crl_der = sqlc.arg(crl_der),
        issued_at = sqlc.arg(issued_at),
        source_stream_type = sqlc.arg(source_stream_type),
        source_stream_id = sqlc.arg(source_stream_id),
        source_stream_version = sqlc.arg(source_stream_version)
    WHERE certificate_class = sqlc.arg(certificate_class)
      AND sequence = sqlc.arg(expected_sequence)
    RETURNING sequence
)
INSERT INTO crl_work_receipts (
    certificate_class,
    source_stream_type,
    source_stream_id,
    source_stream_version,
    publication_sequence
)
SELECT sqlc.arg(certificate_class),
       sqlc.arg(source_stream_type),
       sqlc.arg(source_stream_id),
       sqlc.arg(source_stream_version),
       advanced.sequence
FROM advanced;

-- name: GetCRLWorkReceipt :one
SELECT publication_sequence
FROM crl_work_receipts
WHERE certificate_class = $1
  AND source_stream_type = $2
  AND source_stream_id = $3
  AND source_stream_version = $4;
