-- name: InsertPersonalAccessToken :execrows
INSERT INTO personal_access_tokens (
    token_id,
    subject,
    scopes,
    token_hash,
    expires_at,
    revoked,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(token_id),
    sqlc.arg(subject),
    sqlc.arg(scopes),
    sqlc.arg(token_hash),
    sqlc.arg(expires_at),
    false,
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
);

-- name: ProjectPersonalAccessTokenRevocation :execrows
UPDATE personal_access_tokens
SET revoked = true,
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE token_id = sqlc.arg(token_id)
  AND projection_version < sqlc.arg(projection_version)
  AND NOT revoked;

-- name: GetPersonalAccessTokenByHash :one
SELECT
    token_id,
    subject,
    scopes,
    token_hash,
    expires_at,
    revoked,
    projection_version
FROM personal_access_tokens
WHERE token_hash = sqlc.arg(token_hash);

-- name: GetPersonalAccessTokenByID :one
SELECT
    token_id,
    subject,
    scopes,
    token_hash,
    expires_at,
    revoked,
    projection_version
FROM personal_access_tokens
WHERE token_id = sqlc.arg(token_id);

-- name: ResetPersonalAccessTokens :exec
DELETE FROM personal_access_tokens;
