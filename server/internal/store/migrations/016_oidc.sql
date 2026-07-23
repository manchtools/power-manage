-- +goose Up

-- docref: begin oidc-schema
-- +goose StatementBegin
CREATE TABLE users (
    user_id text NOT NULL,
    email text NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT users_pkey PRIMARY KEY (user_id),
    CONSTRAINT users_user_id_ulid_check
        CHECK (user_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT users_email_key UNIQUE (email),
    CONSTRAINT users_email_len_check
        CHECK (octet_length(email) BETWEEN 3 AND 320),
    CONSTRAINT users_projection_version_check
        CHECK (projection_version > 0)
);

CREATE TABLE oidc_identities (
    issuer text NOT NULL,
    external_subject text NOT NULL,
    provider_slug text NOT NULL,
    user_id text NOT NULL,
    email text NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT oidc_identities_pkey PRIMARY KEY (issuer, external_subject),
    CONSTRAINT oidc_identities_user_provider_key UNIQUE (user_id, provider_slug),
    CONSTRAINT oidc_identities_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
    CONSTRAINT oidc_identities_issuer_len_check
        CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    CONSTRAINT oidc_identities_subject_len_check
        CHECK (octet_length(external_subject) BETWEEN 1 AND 1024),
    CONSTRAINT oidc_identities_provider_slug_check
        CHECK (provider_slug ~ '^[a-z][a-z0-9-]{0,63}$'),
    CONSTRAINT oidc_identities_email_len_check
        CHECK (octet_length(email) BETWEEN 3 AND 320),
    CONSTRAINT oidc_identities_projection_version_check
        CHECK (projection_version > 1)
);

CREATE TABLE oidc_login_states (
    state_hash bytea NOT NULL,
    provider_slug text NOT NULL,
    redirect_uri text NOT NULL,
    nonce text NOT NULL,
    code_verifier text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT oidc_login_states_pkey PRIMARY KEY (state_hash),
    CONSTRAINT oidc_login_states_hash_len_check
        CHECK (octet_length(state_hash) = 32),
    CONSTRAINT oidc_login_states_provider_slug_check
        CHECK (provider_slug ~ '^[a-z][a-z0-9-]{0,63}$'),
    CONSTRAINT oidc_login_states_redirect_uri_len_check
        CHECK (octet_length(redirect_uri) BETWEEN 1 AND 2048),
    CONSTRAINT oidc_login_states_nonce_len_check
        CHECK (octet_length(nonce) BETWEEN 1 AND 256),
    CONSTRAINT oidc_login_states_code_verifier_len_check
        CHECK (octet_length(code_verifier) BETWEEN 43 AND 128)
);

CREATE INDEX oidc_login_states_expires_at_idx
    ON oidc_login_states (expires_at);
-- +goose StatementEnd
-- docref: end oidc-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE oidc_login_states;
DROP TABLE oidc_identities;
DROP TABLE users;
-- +goose StatementEnd
