-- +goose Up

-- docref: begin registration-tokens-schema
-- +goose StatementBegin
CREATE TABLE registration_tokens (
    token_id text PRIMARY KEY CHECK (token_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    projection_version bigint NOT NULL CHECK (projection_version > 0),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    max_uses integer NOT NULL CHECK (max_uses > 0),
    uses integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
    expires_at timestamp with time zone NOT NULL,
    owner text NOT NULL DEFAULT '' CHECK (octet_length(owner) <= 256),
    disabled boolean NOT NULL DEFAULT false,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT registration_tokens_use_bound_check CHECK (uses <= max_uses)
);
-- +goose StatementEnd
-- docref: end registration-tokens-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE registration_tokens;
-- +goose StatementEnd
