-- +goose Up

-- +goose StatementBegin
CREATE TABLE authorization_roles (
    role_id text NOT NULL,
    name text NOT NULL,
    permissions text[] NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT authorization_roles_pkey PRIMARY KEY (role_id),
    CONSTRAINT authorization_roles_name_key UNIQUE (name),
    CONSTRAINT authorization_roles_role_id_ulid_check
        CHECK (role_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT authorization_roles_name_check
        CHECK (name ~ '^[a-z][a-z0-9_.-]{0,63}$'),
    CONSTRAINT authorization_roles_permissions_check
        CHECK (
            cardinality(permissions) BETWEEN 1 AND 256
            AND array_position(permissions, NULL) IS NULL
        ),
    CONSTRAINT authorization_roles_projection_version_check
        CHECK (projection_version = 1)
);

CREATE TABLE authorization_grants (
    grant_id text NOT NULL,
    principal_type text NOT NULL,
    principal_id text NOT NULL,
    role_id text NOT NULL,
    scope_kind text NOT NULL,
    scope_ids text[] NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT authorization_grants_pkey PRIMARY KEY (grant_id),
    CONSTRAINT authorization_grants_role_id_fkey
        FOREIGN KEY (role_id) REFERENCES authorization_roles (role_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT authorization_grants_grant_id_ulid_check
        CHECK (grant_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT authorization_grants_principal_type_check
        CHECK (principal_type IN ('user', 'user-group')),
    CONSTRAINT authorization_grants_principal_id_ulid_check
        CHECK (principal_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT authorization_grants_scope_kind_check
        CHECK (scope_kind IN ('global', 'device-groups', 'user-groups', 'self')),
    CONSTRAINT authorization_grants_scope_shape_check
        CHECK (
            array_position(scope_ids, NULL) IS NULL
            AND (
                (scope_kind IN ('global', 'self') AND cardinality(scope_ids) = 0)
                OR (
                    scope_kind IN ('device-groups', 'user-groups')
                    AND cardinality(scope_ids) BETWEEN 1 AND 1000
                )
            )
        ),
    CONSTRAINT authorization_grants_projection_version_check
        CHECK (projection_version = 1)
);

CREATE INDEX authorization_grants_principal_idx
    ON authorization_grants (principal_type, principal_id);
-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin
DROP TABLE authorization_grants;
DROP TABLE authorization_roles;
-- +goose StatementEnd
