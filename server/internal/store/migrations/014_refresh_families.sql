-- +goose Up

-- docref: begin refresh-family-schema
-- +goose StatementBegin
CREATE TABLE refresh_families (
    family_id text NOT NULL,
    subject text NOT NULL,
    projection_version bigint NOT NULL,
    active_token_hash bytea NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT refresh_families_pkey PRIMARY KEY (family_id),
    CONSTRAINT refresh_families_family_id_ulid_check
        CHECK (family_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT refresh_families_subject_len_check
        CHECK (octet_length(subject) BETWEEN 1 AND 1024),
    CONSTRAINT refresh_families_projection_version_check
        CHECK (projection_version > 0),
    CONSTRAINT refresh_families_active_token_hash_key UNIQUE (active_token_hash),
    CONSTRAINT refresh_families_active_token_hash_len_check
        CHECK (octet_length(active_token_hash) = 32)
);

CREATE TABLE refresh_tokens (
    token_hash bytea NOT NULL,
    family_id text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    superseded boolean NOT NULL DEFAULT false,
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (token_hash),
    CONSTRAINT refresh_tokens_token_hash_len_check
        CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_tokens_family_id_fkey
        FOREIGN KEY (family_id)
        REFERENCES refresh_families(family_id)
        ON DELETE CASCADE
);

CREATE INDEX refresh_tokens_family_id_idx ON refresh_tokens(family_id);
-- +goose StatementEnd
-- docref: end refresh-family-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE refresh_tokens;
DROP TABLE refresh_families;
-- +goose StatementEnd
