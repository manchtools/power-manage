-- name: InsertManagedUserGroup :execrows
INSERT INTO managed_user_groups (
    group_id,
    name,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(group_id),
    sqlc.arg(name),
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
);

-- name: ReplaceManagedUserGroup :execrows
UPDATE managed_user_groups
SET name = sqlc.arg(name),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE group_id = sqlc.arg(group_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteManagedUserGroup :execrows
DELETE FROM managed_user_groups
WHERE group_id = sqlc.arg(group_id)
  AND projection_version = sqlc.arg(projection_version);

-- name: DeleteManagedUserGroupMembers :exec
DELETE FROM managed_user_group_members
WHERE group_id = sqlc.arg(group_id);

-- name: DeleteManagedUserGroupMembershipsForUser :exec
DELETE FROM managed_user_group_members
WHERE user_id = sqlc.arg(user_id);

-- name: InsertManagedUserGroupMember :execrows
INSERT INTO managed_user_group_members (
    group_id,
    user_id,
    projection_version
) SELECT
    sqlc.arg(group_id),
    users.user_id,
    sqlc.arg(projection_version)
FROM users
WHERE users.user_id = sqlc.arg(user_id);

-- name: GetScopedManagedUserGroup :one
SELECT group_id, name, projection_version
FROM managed_user_groups
WHERE group_id = sqlc.arg(group_id)
  AND (
    sqlc.arg(global_scope)::boolean
    OR group_id = ANY(sqlc.arg(user_group_ids)::text[])
  );

-- name: ListScopedManagedUserGroups :many
SELECT group_id, name, projection_version
FROM managed_user_groups
WHERE sqlc.arg(global_scope)::boolean
   OR group_id = ANY(sqlc.arg(user_group_ids)::text[])
ORDER BY group_id
LIMIT sqlc.arg(page_limit);

-- name: ListManagedUserGroupMembers :many
SELECT user_id
FROM managed_user_group_members
WHERE group_id = sqlc.arg(group_id)
ORDER BY user_id;

-- name: ListManagedUserGroupMembersForGroups :many
SELECT group_id, user_id
FROM managed_user_group_members
WHERE group_id = ANY(sqlc.arg(group_ids)::text[])
ORDER BY group_id, user_id;

-- name: ResetManagedUserGroupMembers :exec
DELETE FROM managed_user_group_members;

-- name: ResetManagedUserGroups :exec
DELETE FROM managed_user_groups;
