-- +goose Up

CREATE TABLE server_settings (
    setting_id text PRIMARY KEY,
    name text NOT NULL,
    value text NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT server_settings_id_ulid_check
        CHECK (setting_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT server_settings_name_length_check
        CHECK (octet_length(name) BETWEEN 1 AND 128),
    CONSTRAINT server_settings_value_length_check
        CHECK (octet_length(value) <= 4096),
    CONSTRAINT server_settings_projection_version_check
        CHECK (projection_version > 0)
);

-- +goose Down

DROP TABLE server_settings;
