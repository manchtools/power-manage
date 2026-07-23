-- +goose Up

-- docref: begin personal-access-token-schema
-- +goose StatementBegin
CREATE TABLE personal_access_tokens (
    token_id text NOT NULL,
    subject text NOT NULL,
    scopes text[] NOT NULL,
    token_hash bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT personal_access_tokens_pkey PRIMARY KEY (token_id),
    CONSTRAINT personal_access_tokens_token_id_ulid_check
        CHECK (token_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT personal_access_tokens_subject_len_check
        CHECK (octet_length(subject) BETWEEN 1 AND 1024),
    CONSTRAINT personal_access_tokens_scopes_count_check
        CHECK (cardinality(scopes) BETWEEN 1 AND 64),
    CONSTRAINT personal_access_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT personal_access_tokens_token_hash_len_check
        CHECK (octet_length(token_hash) = 32),
    CONSTRAINT personal_access_tokens_projection_version_check
        CHECK (projection_version > 0)
);
-- +goose StatementEnd
-- docref: end personal-access-token-schema

-- +goose Down

DROP TABLE personal_access_tokens;
