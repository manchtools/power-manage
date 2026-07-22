-- +goose Up

-- docref: begin devices-schema
-- +goose StatementBegin
CREATE TABLE devices (
    device_id text PRIMARY KEY CHECK (device_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    projection_version bigint NOT NULL CHECK (projection_version > 0),
    certificate_der bytea NOT NULL CHECK (
        octet_length(certificate_der) BETWEEN 1 AND 65536
    ),
    certificate_fingerprint bytea NOT NULL CHECK (
        octet_length(certificate_fingerprint) = 32
    ),
    sealing_public_key bytea NOT NULL CHECK (
        octet_length(sealing_public_key) = 32
    ),
    registration_token_id text NOT NULL CHECK (
        registration_token_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    owner text NOT NULL DEFAULT '' CHECK (octet_length(owner) <= 256),
    updated_at timestamp with time zone NOT NULL
);
-- +goose StatementEnd
-- docref: end devices-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE devices;
-- +goose StatementEnd
