-- +goose Up

-- docref: begin user-session-version-constraint-validation
ALTER TABLE users
VALIDATE CONSTRAINT users_session_version_check;
-- docref: end user-session-version-constraint-validation

-- +goose Down

-- +goose StatementBegin
ALTER TABLE users
DROP CONSTRAINT users_session_version_check;

ALTER TABLE users
ADD CONSTRAINT users_session_version_check
    CHECK (session_version > 0) NOT VALID;
-- +goose StatementEnd
