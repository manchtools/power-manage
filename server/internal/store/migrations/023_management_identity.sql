-- +goose Up

-- +goose StatementBegin
ALTER TABLE authorization_roles
    DROP CONSTRAINT authorization_roles_projection_version_check,
    ADD CONSTRAINT authorization_roles_projection_version_check
        CHECK (projection_version > 0);

ALTER TABLE authorization_grants
    DROP CONSTRAINT authorization_grants_projection_version_check,
    ADD CONSTRAINT authorization_grants_projection_version_check
        CHECK (projection_version > 0);

CREATE TABLE managed_user_groups (
    group_id text NOT NULL,
    name text NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT managed_user_groups_pkey PRIMARY KEY (group_id),
    CONSTRAINT managed_user_groups_name_key UNIQUE (name),
    CONSTRAINT managed_user_groups_group_id_ulid_check
        CHECK (group_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT managed_user_groups_name_len_check
        CHECK (octet_length(name) BETWEEN 1 AND 512),
    CONSTRAINT managed_user_groups_projection_version_check
        CHECK (projection_version > 0)
);

CREATE TABLE managed_user_group_members (
    group_id text NOT NULL,
    user_id text NOT NULL,
    projection_version bigint NOT NULL,
    CONSTRAINT managed_user_group_members_pkey PRIMARY KEY (group_id, user_id),
    CONSTRAINT managed_user_group_members_group_id_fkey
        FOREIGN KEY (group_id) REFERENCES managed_user_groups (group_id) ON DELETE CASCADE,
    CONSTRAINT managed_user_group_members_projection_version_check
        CHECK (projection_version > 0)
);
-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin
DROP TABLE managed_user_group_members;
DROP TABLE managed_user_groups;

ALTER TABLE authorization_grants
    DROP CONSTRAINT authorization_grants_projection_version_check,
    ADD CONSTRAINT authorization_grants_projection_version_check
        CHECK (projection_version = 1);

ALTER TABLE authorization_roles
    DROP CONSTRAINT authorization_roles_projection_version_check,
    ADD CONSTRAINT authorization_roles_projection_version_check
        CHECK (projection_version = 1);
-- +goose StatementEnd
