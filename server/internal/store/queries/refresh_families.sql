-- name: InsertRefreshFamily :execrows
INSERT INTO refresh_families (
    family_id,
    subject,
    projection_version,
    active_token_hash,
    revoked,
    updated_at
) VALUES (
    sqlc.arg(family_id),
    sqlc.arg(subject),
    sqlc.arg(projection_version),
    sqlc.arg(active_token_hash),
    false,
    sqlc.arg(updated_at)
);

-- name: InsertRefreshToken :execrows
INSERT INTO refresh_tokens (
    token_hash,
    family_id,
    expires_at,
    superseded
) VALUES (
    sqlc.arg(token_hash),
    sqlc.arg(family_id),
    sqlc.arg(expires_at),
    false
);

-- name: ProjectRefreshFamilyRotation :execrows
UPDATE refresh_families
SET projection_version = sqlc.arg(projection_version),
    active_token_hash = sqlc.arg(next_token_hash),
    updated_at = sqlc.arg(updated_at)
WHERE family_id = sqlc.arg(family_id)
  AND projection_version < sqlc.arg(projection_version)
  AND active_token_hash = sqlc.arg(previous_token_hash)
  AND NOT revoked;

-- name: ProjectRefreshTokenSuperseded :execrows
UPDATE refresh_tokens
SET superseded = true
WHERE family_id = sqlc.arg(family_id)
  AND token_hash = sqlc.arg(token_hash)
  AND NOT superseded;

-- name: ProjectRefreshFamilyRevocation :execrows
UPDATE refresh_families
SET projection_version = sqlc.arg(projection_version),
    revoked = true,
    updated_at = sqlc.arg(updated_at)
WHERE family_id = sqlc.arg(family_id)
  AND projection_version < sqlc.arg(projection_version)
  AND NOT revoked;

-- name: GetRefreshFamily :one
SELECT family_id, subject, projection_version, active_token_hash, revoked, updated_at
FROM refresh_families
WHERE family_id = sqlc.arg(family_id);

-- name: GetRefreshFamilyToken :one
SELECT
    refresh_families.family_id,
    refresh_families.subject,
    refresh_families.projection_version,
    refresh_families.active_token_hash,
    refresh_families.revoked,
    refresh_tokens.token_hash,
    refresh_tokens.expires_at,
    refresh_tokens.superseded
FROM refresh_tokens
JOIN refresh_families USING (family_id)
WHERE refresh_tokens.token_hash = sqlc.arg(token_hash);

-- name: ResetRefreshFamilies :exec
DELETE FROM refresh_families;
