-- name: InsertAuthorizationRole :execrows
INSERT INTO authorization_roles (
    role_id,
    name,
    permissions,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(role_id),
    sqlc.arg(name),
    sqlc.arg(permissions),
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
);

-- name: GetAuthorizationRole :one
SELECT role_id, name, permissions, projection_version
FROM authorization_roles
WHERE role_id = sqlc.arg(role_id);

-- name: InsertAuthorizationGrant :execrows
INSERT INTO authorization_grants (
    grant_id,
    principal_type,
    principal_id,
    role_id,
    scope_kind,
    scope_ids,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(grant_id),
    sqlc.arg(principal_type),
    sqlc.arg(principal_id),
    sqlc.arg(role_id),
    sqlc.arg(scope_kind),
    sqlc.arg(scope_ids),
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
);

-- name: AuthorizationPrincipalExists :one
SELECT CASE sqlc.arg(principal_type)::text
    WHEN 'user' THEN EXISTS (
        SELECT 1
        FROM users
        WHERE user_id = sqlc.arg(principal_id)
    )
    WHEN 'user-group' THEN EXISTS (
        SELECT 1
        FROM scim_groups
        WHERE group_id = sqlc.arg(principal_id)
    )
    ELSE false
END;

-- name: ListResolvedAuthorizationGrants :many
SELECT
    grants.grant_id,
    grants.principal_type,
    grants.principal_id,
    grants.role_id,
    roles.permissions,
    grants.scope_kind,
    grants.scope_ids
FROM authorization_grants AS grants
JOIN authorization_roles AS roles ON roles.role_id = grants.role_id
WHERE (
    grants.principal_type = 'user'
    AND grants.principal_id = sqlc.arg(user_id)
) OR (
    grants.principal_type = 'user-group'
    AND EXISTS (
        SELECT 1
        FROM scim_group_members
        WHERE scim_group_members.group_id = grants.principal_id
          AND scim_group_members.user_id = sqlc.arg(user_id)
    )
)
ORDER BY grants.grant_id;

-- name: ResetAuthorizationGrants :exec
DELETE FROM authorization_grants;

-- name: ResetAuthorizationRoles :exec
DELETE FROM authorization_roles;
