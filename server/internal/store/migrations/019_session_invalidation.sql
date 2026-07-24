-- +goose Up

-- docref: begin session-invalidation-schema
-- +goose StatementBegin
ALTER TABLE users
    ADD COLUMN session_version bigint NOT NULL DEFAULT 1,
    ADD COLUMN disabled boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT users_session_version_check
        CHECK (session_version > 0);
-- +goose StatementEnd
-- docref: end session-invalidation-schema

-- +goose Down

-- +goose StatementBegin
ALTER TABLE users
    DROP CONSTRAINT users_session_version_check,
    DROP COLUMN disabled,
    DROP COLUMN session_version;
-- +goose StatementEnd
