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

-- name: ListAuthorizationRoles :many
SELECT role_id, name, permissions, projection_version
FROM authorization_roles
ORDER BY role_id
LIMIT sqlc.arg(page_limit);

-- name: ReplaceAuthorizationRole :execrows
UPDATE authorization_roles
SET name = sqlc.arg(name),
    permissions = sqlc.arg(permissions),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE role_id = sqlc.arg(role_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteAuthorizationRole :execrows
DELETE FROM authorization_roles
WHERE role_id = sqlc.arg(role_id)
  AND projection_version = sqlc.arg(projection_version);

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

-- name: GetAuthorizationGrant :one
SELECT grant_id, principal_type, principal_id, role_id, scope_kind, scope_ids,
       projection_version
FROM authorization_grants
WHERE grant_id = sqlc.arg(grant_id);

-- name: ListAuthorizationGrants :many
SELECT grant_id, principal_type, principal_id, role_id, scope_kind, scope_ids,
       projection_version
FROM authorization_grants
ORDER BY grant_id
LIMIT sqlc.arg(page_limit);

-- name: ReplaceAuthorizationGrant :execrows
UPDATE authorization_grants
SET principal_type = sqlc.arg(principal_type),
    principal_id = sqlc.arg(principal_id),
    role_id = sqlc.arg(role_id),
    scope_kind = sqlc.arg(scope_kind),
    scope_ids = sqlc.arg(scope_ids),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE grant_id = sqlc.arg(grant_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteAuthorizationGrant :execrows
DELETE FROM authorization_grants
WHERE grant_id = sqlc.arg(grant_id)
  AND projection_version = sqlc.arg(projection_version);

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
    ) OR EXISTS (
        SELECT 1
        FROM managed_user_groups
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
        FROM (
            SELECT group_id, user_id FROM scim_group_members
            UNION ALL
            SELECT group_id, user_id FROM managed_user_group_members
        ) AS memberships
        WHERE memberships.group_id = grants.principal_id
          AND memberships.user_id = sqlc.arg(user_id)
    )
)
ORDER BY grants.grant_id;

-- name: AcquireLastAdminMutationLock :exec
-- One global key intentionally serializes the cross-aggregate admin count.
SELECT pg_advisory_xact_lock(
    hashtextextended('power-manage:last-admin', 0)
);

-- name: CountEnabledAdmins :one
WITH memberships AS (
    SELECT group_id, user_id FROM scim_group_members
    UNION ALL
    SELECT group_id, user_id FROM managed_user_group_members
),
dynamic_admins AS (
    SELECT users.user_id
    FROM users
    WHERE NOT users.disabled
      AND EXISTS (
          SELECT 1
          FROM authorization_grants AS grants
          JOIN authorization_roles AS roles ON roles.role_id = grants.role_id
          WHERE grants.scope_kind = 'global'
            AND sqlc.arg(admin_permission)::text = ANY(roles.permissions)
            AND (
                (
                    grants.principal_type = 'user'
                    AND grants.principal_id = users.user_id
                )
                OR (
                    grants.principal_type = 'user-group'
                    AND EXISTS (
                        SELECT 1
                        FROM memberships
                        WHERE memberships.group_id = grants.principal_id
                          AND memberships.user_id = users.user_id
                    )
                )
            )
      )
),
bootstrap_admins AS (
    SELECT users.user_id
    FROM users
    WHERE NOT users.disabled
      AND EXISTS (
          -- events_stream_version_key supports this stream-prefix lookup.
          -- Compare canonical bytes so malformed historical payloads cannot
          -- make the correctness-critical count query fail.
          SELECT 1
          FROM events AS granted
          WHERE granted.stream_type = 'user'
            AND granted.stream_id = users.user_id
            AND granted.event_type = 'BootstrapAdminRoleGranted'
            AND NOT EXISTS (
                SELECT 1
                FROM events AS revoked
                WHERE revoked.stream_type = granted.stream_type
                  AND revoked.stream_id = granted.stream_id
                  AND revoked.stream_version > granted.stream_version
                  AND revoked.event_type = 'RoleRevoked'
                  AND revoked.payload = convert_to('{"role":"admin"}', 'UTF8')
            )
      )
)
SELECT count(*)::bigint
FROM (
    SELECT user_id FROM dynamic_admins
    UNION
    SELECT user_id FROM bootstrap_admins
) AS enabled_admins;

-- name: ResetAuthorizationGrants :exec
DELETE FROM authorization_grants;

-- name: ResetAuthorizationRoles :exec
DELETE FROM authorization_roles;
