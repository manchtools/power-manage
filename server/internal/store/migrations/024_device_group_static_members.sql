-- +goose Up

CREATE FUNCTION power_manage_all_ulids(candidate_values text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT NOT EXISTS (
        SELECT 1
        FROM unnest(candidate_values) AS candidate(value)
        WHERE candidate.value IS NULL
           OR candidate.value !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    )
$$;

ALTER TABLE device_groups
ADD COLUMN static_device_ids text[] NOT NULL DEFAULT '{}',
ADD CONSTRAINT device_groups_static_device_ids_limit_check
    CHECK (cardinality(static_device_ids) <= 1000),
ADD CONSTRAINT device_groups_static_device_ids_ulid_check
    CHECK (power_manage_all_ulids(static_device_ids));

-- +goose Down

ALTER TABLE device_groups
DROP CONSTRAINT device_groups_static_device_ids_ulid_check,
DROP CONSTRAINT device_groups_static_device_ids_limit_check,
DROP COLUMN static_device_ids;

DROP FUNCTION power_manage_all_ulids(text[]);
