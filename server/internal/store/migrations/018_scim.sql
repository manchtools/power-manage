-- +goose Up

-- +goose StatementBegin
CREATE TABLE scim_providers (
    provider_slug text NOT NULL,
    token_hash bytea NOT NULL,
    disabled boolean NOT NULL DEFAULT false,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT scim_providers_pkey PRIMARY KEY (provider_slug),
    CONSTRAINT scim_providers_slug_check
        CHECK (provider_slug ~ '^[a-z][a-z0-9-]{0,63}$'),
    CONSTRAINT scim_providers_token_hash_len_check
        CHECK (octet_length(token_hash) = 60),
    CONSTRAINT scim_providers_projection_version_check
        CHECK (projection_version > 0)
);

CREATE TABLE scim_identities (
    provider_slug text NOT NULL,
    external_id text NOT NULL,
    user_id text NOT NULL,
    email text NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT scim_identities_pkey PRIMARY KEY (provider_slug, external_id),
    CONSTRAINT scim_identities_user_provider_key UNIQUE (user_id, provider_slug),
    CONSTRAINT scim_identities_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
    CONSTRAINT scim_identities_slug_check
        CHECK (provider_slug ~ '^[a-z][a-z0-9-]{0,63}$'),
    CONSTRAINT scim_identities_external_id_len_check
        CHECK (octet_length(external_id) BETWEEN 1 AND 1024),
    CONSTRAINT scim_identities_email_len_check
        CHECK (octet_length(email) BETWEEN 3 AND 320),
    CONSTRAINT scim_identities_projection_version_check
        CHECK (projection_version > 1)
);

CREATE TABLE scim_groups (
    group_id text NOT NULL,
    provider_slug text NOT NULL,
    external_id text NOT NULL,
    display_name text NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT scim_groups_pkey PRIMARY KEY (group_id),
    CONSTRAINT scim_groups_provider_external_key UNIQUE (provider_slug, external_id),
    CONSTRAINT scim_groups_group_id_ulid_check
        CHECK (group_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT scim_groups_slug_check
        CHECK (provider_slug ~ '^[a-z][a-z0-9-]{0,63}$'),
    CONSTRAINT scim_groups_external_id_len_check
        CHECK (octet_length(external_id) BETWEEN 1 AND 1024),
    CONSTRAINT scim_groups_display_name_len_check
        CHECK (octet_length(display_name) BETWEEN 1 AND 512),
    CONSTRAINT scim_groups_projection_version_check
        CHECK (projection_version > 0)
);

CREATE TABLE scim_group_members (
    group_id text NOT NULL,
    user_id text NOT NULL,
    projection_version bigint NOT NULL,
    CONSTRAINT scim_group_members_pkey PRIMARY KEY (group_id, user_id),
    CONSTRAINT scim_group_members_group_id_fkey
        FOREIGN KEY (group_id) REFERENCES scim_groups (group_id) ON DELETE CASCADE,
    CONSTRAINT scim_group_members_user_id_ulid_check
        CHECK (user_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT scim_group_members_projection_version_check
        CHECK (projection_version > 0)
);
-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin
DROP TABLE scim_group_members;
DROP TABLE scim_groups;
DROP TABLE scim_identities;
DROP TABLE scim_providers;
-- +goose StatementEnd
