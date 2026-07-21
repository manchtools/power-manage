-- +goose Up

-- docref: begin events-schema
-- +goose StatementBegin
CREATE TABLE events (
    stream_type text NOT NULL CHECK (stream_type <> ''),
    stream_id text NOT NULL CHECK (stream_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    stream_version bigint NOT NULL CHECK (stream_version > 0),
    event_type text NOT NULL CHECK (event_type <> ''),
    payload_version integer NOT NULL CHECK (payload_version > 0),
    payload bytea NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT events_stream_version_key
        UNIQUE (stream_type, stream_id, stream_version)
);
-- +goose StatementEnd
-- docref: end events-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE events;
-- +goose StatementEnd
