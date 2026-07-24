-- name: InsertDeviceGroup :execrows
INSERT INTO device_groups (
    device_group_id,
    name,
    dynamic_query,
    static_device_ids,
    projection_version,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (device_group_id) DO NOTHING;

-- name: ReplaceDeviceGroup :execrows
UPDATE device_groups
SET name = $1,
    dynamic_query = $2,
    static_device_ids = $3,
    projection_version = $4,
    updated_at = $5
WHERE device_group_id = $6
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteDeviceGroup :execrows
DELETE FROM device_groups
WHERE device_group_id = $1
  AND projection_version = $2;

-- name: GetScopedDeviceGroup :one
SELECT device_group_id, name, dynamic_query, static_device_ids,
       projection_version, updated_at
FROM device_groups
WHERE device_group_id = sqlc.arg(device_group_id)
  AND (
      sqlc.arg(global_scope)::boolean
      OR device_group_id = ANY(sqlc.arg(device_group_ids)::text[])
  );

-- name: ListScopedDeviceGroups :many
SELECT device_group_id, name, dynamic_query, static_device_ids,
       projection_version, updated_at
FROM device_groups
WHERE sqlc.arg(global_scope)::boolean
   OR device_group_id = ANY(sqlc.arg(device_group_ids)::text[])
ORDER BY name, device_group_id
LIMIT sqlc.arg(page_limit);

-- name: ResetDeviceGroups :exec
DELETE FROM device_groups;
