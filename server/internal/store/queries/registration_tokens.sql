-- name: UpsertRegistrationToken :execrows
INSERT INTO registration_tokens (
    token_id,
    projection_version,
    token_hash,
    max_uses,
    uses,
    expires_at,
    owner,
    disabled,
    updated_at
) VALUES ($1, $2, $3, $4, 0, $5, $6, false, $7)
ON CONFLICT (token_id) DO UPDATE SET
    projection_version = EXCLUDED.projection_version,
    token_hash = EXCLUDED.token_hash,
    max_uses = EXCLUDED.max_uses,
    uses = 0,
    expires_at = EXCLUDED.expires_at,
    owner = EXCLUDED.owner,
    disabled = false,
    updated_at = EXCLUDED.updated_at
WHERE registration_tokens.projection_version < EXCLUDED.projection_version;

-- name: ProjectRegistrationTokenConsume :execrows
UPDATE registration_tokens
SET projection_version = $2,
    uses = uses + 1,
    updated_at = $3
WHERE token_id = $1
  AND projection_version < $2
  AND NOT disabled
  AND uses < max_uses;

-- name: ProjectRegistrationTokenDisable :execrows
UPDATE registration_tokens
SET projection_version = $2,
    disabled = true,
    updated_at = $3
WHERE token_id = $1
  AND projection_version < $2
  AND NOT disabled;

-- name: GetRegistrationToken :one
SELECT token_id, projection_version, token_hash, max_uses, uses,
       expires_at, owner, disabled, updated_at
FROM registration_tokens
WHERE token_id = $1;

-- name: ResetRegistrationTokens :exec
DELETE FROM registration_tokens;
