-- +goose Up

CREATE TABLE managed_actions (
    action_id text PRIMARY KEY,
    name text NOT NULL,
    params bytea NOT NULL,
    system_managed boolean NOT NULL DEFAULT false,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT managed_actions_id_ulid_check
        CHECK (action_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT managed_actions_name_length_check
        CHECK (octet_length(name) BETWEEN 1 AND 200),
    CONSTRAINT managed_actions_params_length_check
        CHECK (octet_length(params) BETWEEN 1 AND 2097152),
    CONSTRAINT managed_actions_projection_version_check
        CHECK (projection_version > 0)
);

CREATE TABLE managed_action_sets (
    action_set_id text PRIMARY KEY,
    name text NOT NULL,
    system_managed boolean NOT NULL DEFAULT false,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT managed_action_sets_id_ulid_check
        CHECK (action_set_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT managed_action_sets_name_length_check
        CHECK (octet_length(name) BETWEEN 1 AND 200),
    CONSTRAINT managed_action_sets_projection_version_check
        CHECK (projection_version > 0)
);

CREATE TABLE assignments (
    assignment_id text PRIMARY KEY,
    source_kind text NOT NULL,
    source_id text NOT NULL,
    target_kind text NOT NULL,
    target_id text NOT NULL,
    mode text NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT assignments_id_ulid_check
        CHECK (assignment_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT assignments_source_id_ulid_check
        CHECK (source_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT assignments_target_id_ulid_check
        CHECK (target_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT assignments_source_kind_check
        CHECK (source_kind IN ('action', 'action_set')),
    CONSTRAINT assignments_target_kind_check
        CHECK (target_kind IN ('device', 'user', 'device_group', 'user_group')),
    CONSTRAINT assignments_mode_check
        CHECK (mode IN ('apply', 'uninstall')),
    CONSTRAINT assignments_projection_version_check
        CHECK (projection_version > 0)
);

CREATE TABLE compliance_policies (
    policy_id text PRIMARY KEY,
    name text NOT NULL,
    rule_action_ids text[] NOT NULL,
    grace_hours integer NOT NULL,
    projection_version bigint NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT compliance_policies_id_ulid_check
        CHECK (policy_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT compliance_policies_name_length_check
        CHECK (octet_length(name) BETWEEN 1 AND 200),
    CONSTRAINT compliance_policies_rule_count_check
        CHECK (cardinality(rule_action_ids) BETWEEN 1 AND 256),
    CONSTRAINT compliance_policies_rule_action_ids_ulid_check
        CHECK (power_manage_all_ulids(rule_action_ids)),
    CONSTRAINT compliance_policies_grace_hours_check
        CHECK (grace_hours BETWEEN 0 AND 8760),
    CONSTRAINT compliance_policies_projection_version_check
        CHECK (projection_version > 0)
);

-- +goose Down

DROP TABLE compliance_policies;
DROP TABLE assignments;
DROP TABLE managed_action_sets;
DROP TABLE managed_actions;
