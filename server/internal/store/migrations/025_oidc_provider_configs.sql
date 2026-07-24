-- +goose Up

CREATE TABLE oidc_providers (
    provider_slug text PRIMARY KEY,
    issuer text NOT NULL,
    client_id text NOT NULL,
    authorization_endpoint text NOT NULL,
    token_url text NOT NULL,
    jwks_uri text NOT NULL,
    redirect_uris text[] NOT NULL,
    trust_email_assertions boolean NOT NULL,
    disabled boolean NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT oidc_providers_slug_check
        CHECK (provider_slug ~ '^[a-z][a-z0-9-]{0,63}$'),
    CONSTRAINT oidc_providers_redirect_limit_check
        CHECK (cardinality(redirect_uris) BETWEEN 1 AND 32),
    CONSTRAINT oidc_providers_projection_version_check
        CHECK (projection_version > 0)
);

-- +goose Down

DROP TABLE oidc_providers;
