-- name: InsertOIDCProviderConfig :execrows
INSERT INTO oidc_providers (
    provider_slug,
    issuer,
    client_id,
    authorization_endpoint,
    token_url,
    jwks_uri,
    redirect_uris,
    trust_email_assertions,
    disabled,
    projection_version,
    updated_at
) VALUES (
    sqlc.arg(provider_slug),
    sqlc.arg(issuer),
    sqlc.arg(client_id),
    sqlc.arg(authorization_endpoint),
    sqlc.arg(token_url),
    sqlc.arg(jwks_uri),
    sqlc.arg(redirect_uris),
    sqlc.arg(trust_email_assertions),
    sqlc.arg(disabled),
    sqlc.arg(projection_version),
    sqlc.arg(updated_at)
)
ON CONFLICT (provider_slug) DO NOTHING;

-- name: ReplaceOIDCProviderConfig :execrows
UPDATE oidc_providers
SET issuer = sqlc.arg(issuer),
    client_id = sqlc.arg(client_id),
    authorization_endpoint = sqlc.arg(authorization_endpoint),
    token_url = sqlc.arg(token_url),
    jwks_uri = sqlc.arg(jwks_uri),
    redirect_uris = sqlc.arg(redirect_uris),
    trust_email_assertions = sqlc.arg(trust_email_assertions),
    disabled = sqlc.arg(disabled),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE provider_slug = sqlc.arg(provider_slug)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteOIDCProviderConfig :execrows
DELETE FROM oidc_providers
WHERE provider_slug = sqlc.arg(provider_slug)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: GetOIDCProviderConfig :one
SELECT provider_slug, issuer, client_id, authorization_endpoint,
       token_url, jwks_uri, redirect_uris, trust_email_assertions,
       disabled, projection_version, updated_at
FROM oidc_providers
WHERE provider_slug = sqlc.arg(provider_slug);

-- name: ListOIDCProviderConfigs :many
SELECT provider_slug, issuer, client_id, authorization_endpoint,
       token_url, jwks_uri, redirect_uris, trust_email_assertions,
       disabled, projection_version, updated_at
FROM oidc_providers
ORDER BY provider_slug
LIMIT sqlc.arg(page_limit);

-- name: ResetOIDCProviderConfigs :exec
DELETE FROM oidc_providers;
