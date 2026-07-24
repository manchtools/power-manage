-- name: InsertBootstrapLogin :execrows
INSERT INTO bootstrap_logins (
    login_id,
    token_hash,
    user_id,
    expires_at,
    consumed,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(login_id),
    sqlc.arg(token_hash),
    sqlc.arg(user_id),
    sqlc.arg(expires_at),
    false,
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
);

-- name: GetBootstrapLoginByHash :one
SELECT
    login_id,
    token_hash,
    user_id,
    expires_at,
    consumed,
    projection_version
FROM bootstrap_logins
WHERE token_hash = sqlc.arg(token_hash);

-- name: GetBootstrapLoginByID :one
SELECT
    login_id,
    token_hash,
    user_id,
    expires_at,
    consumed,
    projection_version
FROM bootstrap_logins
WHERE login_id = sqlc.arg(login_id);

-- name: ConsumeBootstrapLogin :execrows
UPDATE bootstrap_logins
SET consumed = true,
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE login_id = sqlc.arg(login_id)
  AND consumed = false
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: ResetBootstrapLogins :exec
DELETE FROM bootstrap_logins;

-- name: AdvanceUserProjectionVersionForBootstrapAdmin :execrows
UPDATE users
SET projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE user_id = sqlc.arg(user_id)
  AND projection_version = sqlc.arg(previous_projection_version);
