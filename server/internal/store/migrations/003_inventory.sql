-- +goose Up

-- docref: begin inventory-snapshots-schema
-- +goose StatementBegin
CREATE TABLE inventory_snapshots (
    agent_id text PRIMARY KEY CHECK (agent_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    projection_version bigint NOT NULL CHECK (projection_version > 0),
    payload_version integer NOT NULL CHECK (payload_version > 0),
    snapshot bytea CHECK (snapshot IS NULL OR octet_length(snapshot) <= 2097152),
    deleted boolean NOT NULL DEFAULT false,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT inventory_snapshots_state_check CHECK (
        (deleted AND snapshot IS NULL) OR (NOT deleted AND snapshot IS NOT NULL)
    )
);
-- +goose StatementEnd
-- docref: end inventory-snapshots-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE inventory_snapshots;
-- +goose StatementEnd
