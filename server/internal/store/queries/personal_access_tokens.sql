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

-- name: GetScopedPersonalAccessToken :one
SELECT
    p.token_id,
    p.subject,
    p.scopes,
    p.expires_at,
    p.revoked,
    p.projection_version
FROM personal_access_tokens AS p
WHERE p.token_id = sqlc.arg(token_id)
  AND (
      sqlc.arg(global_scope)::boolean
      OR p.subject = sqlc.arg(self_id)
      OR EXISTS (
          SELECT 1
          FROM managed_user_group_members AS m
          WHERE m.group_id = ANY(sqlc.arg(user_group_ids)::text[])
            AND m.user_id = p.subject
      )
      OR EXISTS (
          SELECT 1
          FROM scim_group_members AS m
          WHERE m.group_id = ANY(sqlc.arg(user_group_ids)::text[])
            AND m.user_id = p.subject
      )
  );

-- name: ListScopedPersonalAccessTokens :many
SELECT
    p.token_id,
    p.subject,
    p.scopes,
    p.expires_at,
    p.revoked,
    p.projection_version
FROM personal_access_tokens AS p
WHERE sqlc.arg(global_scope)::boolean
   OR p.subject = sqlc.arg(self_id)
   OR EXISTS (
       SELECT 1
       FROM managed_user_group_members AS m
       WHERE m.group_id = ANY(sqlc.arg(user_group_ids)::text[])
         AND m.user_id = p.subject
   )
   OR EXISTS (
       SELECT 1
       FROM scim_group_members AS m
       WHERE m.group_id = ANY(sqlc.arg(user_group_ids)::text[])
         AND m.user_id = p.subject
   )
ORDER BY p.token_id
LIMIT sqlc.arg(page_limit);

-- name: ReplacePersonalAccessTokenMetadata :execrows
UPDATE personal_access_tokens
SET scopes = sqlc.arg(scopes),
    expires_at = sqlc.arg(expires_at),
    revoked = revoked OR sqlc.arg(revoked)::boolean,
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE token_id = sqlc.arg(token_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeletePersonalAccessTokenProjection :execrows
DELETE FROM personal_access_tokens
WHERE token_id = sqlc.arg(token_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: ResetPersonalAccessTokens :exec
DELETE FROM personal_access_tokens;
