-- name: InsertUser :execrows
INSERT INTO users (
    user_id,
    email,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(user_id),
    sqlc.arg(email),
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
);

-- name: InsertOIDCIdentity :execrows
INSERT INTO oidc_identities (
    issuer,
    external_subject,
    provider_slug,
    user_id,
    email,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(issuer),
    sqlc.arg(external_subject),
    sqlc.arg(provider_slug),
    sqlc.arg(user_id),
    sqlc.arg(email),
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
);

-- name: AdvanceUserProjectionVersion :execrows
UPDATE users
SET projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE user_id = sqlc.arg(user_id)
  AND email = sqlc.arg(email)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: GetUserByID :one
SELECT user_id, email, projection_version
FROM users
WHERE user_id = sqlc.arg(user_id);

-- name: GetUserByEmail :one
SELECT user_id, email, projection_version
FROM users
WHERE email = sqlc.arg(email);

-- name: GetUserByOIDCIdentity :one
SELECT users.user_id, users.email, users.projection_version
FROM oidc_identities
JOIN users ON users.user_id = oidc_identities.user_id
WHERE oidc_identities.issuer = sqlc.arg(issuer)
  AND oidc_identities.external_subject = sqlc.arg(external_subject);

-- name: CountUserOIDCIdentities :one
SELECT count(*)::bigint
FROM oidc_identities
WHERE user_id = sqlc.arg(user_id);

-- name: ResetOIDCIdentities :exec
DELETE FROM oidc_identities;

-- name: ResetUsers :exec
DELETE FROM users;

-- name: InsertOIDCLoginState :execrows
INSERT INTO oidc_login_states (
    state_hash,
    provider_slug,
    redirect_uri,
    nonce,
    code_verifier,
    expires_at
) VALUES (
    sqlc.arg(state_hash),
    sqlc.arg(provider_slug),
    sqlc.arg(redirect_uri),
    sqlc.arg(nonce),
    sqlc.arg(code_verifier),
    sqlc.arg(expires_at)
);

-- name: ConsumeOIDCLoginState :one
DELETE FROM oidc_login_states
WHERE state_hash = sqlc.arg(state_hash)
RETURNING provider_slug, redirect_uri, nonce, code_verifier, expires_at;

-- name: DeleteExpiredOIDCLoginStates :execrows
DELETE FROM oidc_login_states
WHERE expires_at <= sqlc.arg(now);
