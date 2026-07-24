-- +goose Up

-- +goose StatementBegin
CREATE TABLE device_groups (
    device_group_id text NOT NULL,
    name text NOT NULL,
    dynamic_query text NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT device_groups_pkey PRIMARY KEY (device_group_id),
    CONSTRAINT device_groups_device_group_id_ulid_check
        CHECK (device_group_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT device_groups_name_length_check
        CHECK (char_length(name) BETWEEN 1 AND 200),
    CONSTRAINT device_groups_dynamic_query_length_check
        CHECK (char_length(dynamic_query) <= 4096),
    CONSTRAINT device_groups_projection_version_check
        CHECK (projection_version > 0)
);
-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin
DROP TABLE device_groups;
-- +goose StatementEnd
