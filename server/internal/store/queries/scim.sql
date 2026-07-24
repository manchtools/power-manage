-- name: InsertSCIMProvider :execrows
INSERT INTO scim_providers (
    provider_slug,
    token_hash,
    disabled,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(provider_slug),
    sqlc.arg(token_hash),
    false,
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
)
ON CONFLICT (provider_slug) DO NOTHING;

-- name: RotateSCIMProviderToken :execrows
UPDATE scim_providers
SET token_hash = sqlc.arg(token_hash),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE provider_slug = sqlc.arg(provider_slug)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DisableSCIMProvider :execrows
UPDATE scim_providers
SET disabled = true,
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE provider_slug = sqlc.arg(provider_slug)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: GetSCIMProvider :one
SELECT provider_slug, token_hash, disabled, projection_version
FROM scim_providers
WHERE provider_slug = sqlc.arg(provider_slug);

-- name: GetSCIMProviderMetadata :one
SELECT provider_slug, disabled, projection_version
FROM scim_providers
WHERE provider_slug = sqlc.arg(provider_slug);

-- name: ListSCIMProviders :many
SELECT provider_slug, disabled, projection_version
FROM scim_providers
ORDER BY provider_slug
LIMIT sqlc.arg(page_limit);

-- name: DeleteSCIMProvider :execrows
DELETE FROM scim_providers
WHERE provider_slug = sqlc.arg(provider_slug)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: ResetSCIMProviders :exec
DELETE FROM scim_providers;

-- name: InsertSCIMIdentity :execrows
INSERT INTO scim_identities (
    provider_slug,
    external_id,
    user_id,
    email,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(provider_slug),
    sqlc.arg(external_id),
    sqlc.arg(user_id),
    sqlc.arg(email),
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
);

-- name: DeleteSCIMIdentity :execrows
DELETE FROM scim_identities
WHERE provider_slug = sqlc.arg(provider_slug)
  AND external_id = sqlc.arg(external_id)
  AND user_id = sqlc.arg(user_id);

-- name: GetSCIMIdentity :one
SELECT provider_slug, external_id, user_id, email, projection_version
FROM scim_identities
WHERE provider_slug = sqlc.arg(provider_slug)
  AND external_id = sqlc.arg(external_id);

-- name: GetSCIMIdentityByUser :one
SELECT provider_slug, external_id, user_id, email, projection_version
FROM scim_identities
WHERE provider_slug = sqlc.arg(provider_slug)
  AND user_id = sqlc.arg(user_id);

-- name: ReplaceSCIMIdentityEmailsForManagedUser :exec
UPDATE scim_identities
SET email = sqlc.arg(email),
    updated_at = sqlc.arg(updated_at)
WHERE user_id = sqlc.arg(user_id);

-- name: ListSCIMUsers :many
SELECT
    scim_identities.provider_slug,
    scim_identities.external_id,
    users.user_id,
    users.email,
    users.projection_version
FROM scim_identities
JOIN users ON users.user_id = scim_identities.user_id
WHERE scim_identities.provider_slug = sqlc.arg(provider_slug)
  AND (sqlc.arg(email)::text = '' OR users.email = sqlc.arg(email))
ORDER BY users.user_id
LIMIT sqlc.arg(page_size);

-- name: CountUserIdentityLinks :one
SELECT (
    (SELECT count(*) FROM oidc_identities WHERE oidc_identities.user_id = sqlc.arg(lookup_user_id)) +
    (SELECT count(*) FROM scim_identities WHERE scim_identities.user_id = sqlc.arg(lookup_user_id))
)::bigint;

-- name: AdvanceUserProjectionVersionForSCIM :execrows
UPDATE users
SET projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE user_id = sqlc.arg(user_id)
  AND email = sqlc.arg(email)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteSCIMGroupMembershipsForUser :exec
DELETE FROM scim_group_members
WHERE user_id = sqlc.arg(user_id);

-- name: ResetSCIMIdentities :exec
DELETE FROM scim_identities;

-- name: InsertSCIMGroup :execrows
INSERT INTO scim_groups (
    group_id,
    provider_slug,
    external_id,
    display_name,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(group_id),
    sqlc.arg(provider_slug),
    sqlc.arg(external_id),
    sqlc.arg(display_name),
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
);

-- name: UpdateSCIMGroup :execrows
UPDATE scim_groups
SET external_id = sqlc.arg(external_id),
    display_name = sqlc.arg(display_name),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE group_id = sqlc.arg(group_id)
  AND provider_slug = sqlc.arg(provider_slug)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: AdvanceSCIMGroupProjectionVersion :execrows
UPDATE scim_groups
SET projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE group_id = sqlc.arg(group_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteSCIMGroup :execrows
DELETE FROM scim_groups
WHERE group_id = sqlc.arg(group_id)
  AND provider_slug = sqlc.arg(provider_slug)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteSCIMGroupMembers :exec
DELETE FROM scim_group_members
WHERE group_id = sqlc.arg(group_id);

-- name: InsertSCIMGroupMember :execrows
INSERT INTO scim_group_members (group_id, user_id, projection_version)
SELECT sqlc.arg(group_id), users.user_id, sqlc.arg(projection_version)
FROM users
WHERE users.user_id = sqlc.arg(user_id);

-- name: GetSCIMGroup :one
SELECT group_id, provider_slug, external_id, display_name, projection_version
FROM scim_groups
WHERE provider_slug = sqlc.arg(provider_slug)
  AND group_id = sqlc.arg(group_id);

-- name: ListSCIMGroups :many
SELECT group_id, provider_slug, external_id, display_name, projection_version
FROM scim_groups
WHERE provider_slug = sqlc.arg(provider_slug)
ORDER BY group_id
LIMIT sqlc.arg(page_size);

-- name: ListSCIMGroupMembers :many
SELECT user_id
FROM scim_group_members
WHERE group_id = sqlc.arg(group_id)
ORDER BY user_id;

-- name: ResetSCIMGroupMembers :exec
DELETE FROM scim_group_members;

-- name: ResetSCIMGroups :exec
DELETE FROM scim_groups;
