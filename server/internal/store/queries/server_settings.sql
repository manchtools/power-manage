-- name: InsertServerSetting :execrows
INSERT INTO server_settings (
    setting_id,
    name,
    value,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(setting_id),
    sqlc.arg(name),
    sqlc.arg(value),
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
)
ON CONFLICT (setting_id) DO NOTHING;

-- name: ReplaceServerSetting :execrows
UPDATE server_settings
SET name = sqlc.arg(name),
    value = sqlc.arg(value),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE setting_id = sqlc.arg(setting_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteServerSetting :execrows
DELETE FROM server_settings
WHERE setting_id = sqlc.arg(setting_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: GetServerSetting :one
SELECT setting_id, name, value, projection_version
FROM server_settings
WHERE setting_id = sqlc.arg(setting_id);

-- name: ListServerSettings :many
SELECT setting_id, name, value, projection_version
FROM server_settings
ORDER BY setting_id
LIMIT sqlc.arg(page_limit);

-- name: ResetServerSettings :exec
DELETE FROM server_settings;
