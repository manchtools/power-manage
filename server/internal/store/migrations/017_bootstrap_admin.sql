-- +goose Up

-- docref: begin bootstrap-admin-schema
-- +goose StatementBegin
CREATE TABLE bootstrap_logins (
    login_id text NOT NULL,
    token_hash bytea NOT NULL,
    user_id text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed boolean NOT NULL DEFAULT false,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT bootstrap_logins_pkey PRIMARY KEY (login_id),
    CONSTRAINT bootstrap_logins_token_hash_key UNIQUE (token_hash),
    CONSTRAINT bootstrap_logins_login_id_ulid_check
        CHECK (login_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT bootstrap_logins_user_id_ulid_check
        CHECK (user_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT bootstrap_logins_token_hash_len_check
        CHECK (octet_length(token_hash) = 32),
    CONSTRAINT bootstrap_logins_projection_version_check
        CHECK (projection_version > 0)
);
-- +goose StatementEnd
-- docref: end bootstrap-admin-schema

-- +goose Down

DROP TABLE bootstrap_logins;
