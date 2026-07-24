-- name: InvalidateUserSession :execrows
UPDATE users
SET session_version = session_version + 1,
    disabled = disabled OR sqlc.arg(disable_user)::boolean,
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE user_id = sqlc.arg(user_id)
  AND projection_version = sqlc.arg(previous_projection_version)
  AND session_version < 9223372036854775807;

-- name: DeleteOIDCIdentityForInvalidation :execrows
DELETE FROM oidc_identities
WHERE issuer = sqlc.arg(issuer)
  AND external_subject = sqlc.arg(external_subject)
  AND provider_slug = sqlc.arg(provider_slug)
  AND user_id = sqlc.arg(user_id);

-- name: DeleteUserProjectionAfterInvalidation :execrows
DELETE FROM users
WHERE user_id = sqlc.arg(user_id)
  AND projection_version = sqlc.arg(projection_version);
