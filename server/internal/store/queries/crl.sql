-- name: InsertCertificateRevocation :execrows
INSERT INTO certificate_revocations (
    certificate_class,
    certificate_fingerprint,
    certificate_der,
    issuer_identifier,
    serial_number,
    revoked_at,
    reason_code,
    source_stream_type,
    source_stream_id,
    source_stream_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (certificate_class, certificate_fingerprint) DO NOTHING;

-- name: GetCertificateRevocation :one
SELECT certificate_class, certificate_fingerprint, certificate_der,
       serial_number, revoked_at, reason_code,
       source_stream_type, source_stream_id, source_stream_version,
       issuer_identifier
FROM certificate_revocations
WHERE certificate_class = $1 AND certificate_fingerprint = $2;

-- name: ListCertificateRevocations :many
SELECT certificate_class, certificate_fingerprint, certificate_der,
       serial_number, revoked_at, reason_code,
       source_stream_type, source_stream_id, source_stream_version,
       issuer_identifier
FROM certificate_revocations
WHERE certificate_class = $1
ORDER BY revoked_at, certificate_fingerprint;

-- name: ResetAgentCertificateRevocations :exec
DELETE FROM certificate_revocations
WHERE certificate_class = 'agent';

-- name: ResetGatewayCertificateRevocations :exec
DELETE FROM certificate_revocations
WHERE certificate_class = 'gateway';

-- name: GetCRLState :one
SELECT certificate_class, sequence, crl_der, issued_at,
       source_stream_type, source_stream_id, source_stream_version,
       issuer_fingerprint
FROM crl_state
WHERE certificate_class = $1 AND issuer_fingerprint = $2;

-- name: ListCurrentCRLIssuers :many
SELECT issuer_fingerprint
FROM crl_state
WHERE certificate_class = $1 AND sequence > 0
ORDER BY issuer_fingerprint;

-- name: CompareAndSwapCRLState :execrows
INSERT INTO crl_state (
    certificate_class, issuer_fingerprint, sequence, crl_der, issued_at,
    source_stream_type, source_stream_id, source_stream_version
)
SELECT sqlc.arg(certificate_class), sqlc.arg(issuer_fingerprint),
       sqlc.arg(next_sequence), sqlc.arg(crl_der), sqlc.arg(issued_at),
       sqlc.narg(source_stream_type), sqlc.narg(source_stream_id),
       sqlc.narg(source_stream_version)
WHERE sqlc.arg(expected_sequence)::bigint = 0
   OR EXISTS (
       SELECT 1 FROM crl_state
       WHERE certificate_class = sqlc.arg(certificate_class)
         AND issuer_fingerprint = sqlc.arg(issuer_fingerprint)
   )
ON CONFLICT (certificate_class, issuer_fingerprint) DO UPDATE
SET sequence = EXCLUDED.sequence,
    crl_der = EXCLUDED.crl_der,
    issued_at = EXCLUDED.issued_at,
    source_stream_type = EXCLUDED.source_stream_type,
    source_stream_id = EXCLUDED.source_stream_id,
    source_stream_version = EXCLUDED.source_stream_version
WHERE crl_state.sequence = sqlc.arg(expected_sequence);

-- name: CompareAndSwapCRLStateForWork :execrows
WITH advanced AS (
    INSERT INTO crl_state (
        certificate_class, issuer_fingerprint, sequence, crl_der, issued_at,
        source_stream_type, source_stream_id, source_stream_version
    )
    SELECT sqlc.arg(certificate_class), sqlc.arg(issuer_fingerprint),
           sqlc.arg(next_sequence), sqlc.arg(crl_der), sqlc.arg(issued_at),
           sqlc.arg(source_stream_type), sqlc.arg(source_stream_id),
           sqlc.arg(source_stream_version)
    WHERE sqlc.arg(expected_sequence)::bigint = 0
       OR EXISTS (
           SELECT 1 FROM crl_state
           WHERE certificate_class = sqlc.arg(certificate_class)
             AND issuer_fingerprint = sqlc.arg(issuer_fingerprint)
       )
    ON CONFLICT (certificate_class, issuer_fingerprint) DO UPDATE
    SET sequence = EXCLUDED.sequence,
        crl_der = EXCLUDED.crl_der,
        issued_at = EXCLUDED.issued_at,
        source_stream_type = EXCLUDED.source_stream_type,
        source_stream_id = EXCLUDED.source_stream_id,
        source_stream_version = EXCLUDED.source_stream_version
    WHERE crl_state.sequence = sqlc.arg(expected_sequence)
    RETURNING sequence
)
INSERT INTO crl_work_receipts (
    certificate_class,
    issuer_fingerprint,
    source_stream_type,
    source_stream_id,
    source_stream_version,
    publication_sequence
)
SELECT sqlc.arg(certificate_class),
       sqlc.arg(issuer_fingerprint),
       sqlc.arg(source_stream_type),
       sqlc.arg(source_stream_id),
       sqlc.arg(source_stream_version),
       advanced.sequence
FROM advanced;

-- name: GetCRLWorkReceipt :one
SELECT publication_sequence
FROM crl_work_receipts
WHERE certificate_class = $1
  AND issuer_fingerprint = $2
  AND source_stream_type = $3
  AND source_stream_id = $4
  AND source_stream_version = $5;

-- name: RecordCoveredCRLWorkReceipt :execrows
INSERT INTO crl_work_receipts (
    certificate_class,
    issuer_fingerprint,
    source_stream_type,
    source_stream_id,
    source_stream_version,
    publication_sequence
)
SELECT sqlc.arg(certificate_class),
       sqlc.arg(issuer_fingerprint),
       sqlc.arg(source_stream_type),
       sqlc.arg(source_stream_id),
       sqlc.arg(source_stream_version),
       sqlc.arg(publication_sequence)
FROM crl_state
WHERE certificate_class = sqlc.arg(certificate_class)
  AND issuer_fingerprint = sqlc.arg(issuer_fingerprint)
  AND sequence >= sqlc.arg(publication_sequence)
ON CONFLICT (
    certificate_class,
    issuer_fingerprint,
    source_stream_type,
    source_stream_id,
    source_stream_version
) DO NOTHING;
