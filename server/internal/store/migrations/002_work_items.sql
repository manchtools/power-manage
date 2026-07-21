-- +goose Up

-- docref: begin work-items-schema
-- +goose StatementBegin
CREATE TABLE work_items (
    source_stream_type text NOT NULL,
    source_stream_id text NOT NULL,
    source_stream_version bigint NOT NULL,
    work_kind text NOT NULL CHECK (
        work_kind !~ '^[[:space:]]*$' AND octet_length(work_kind) <= 128
    ),
    payload_version integer NOT NULL CHECK (payload_version > 0),
    payload bytea NOT NULL CHECK (octet_length(payload) <= 2097152),
    run_at timestamp with time zone NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL,
    next_attempt_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (
        source_stream_type,
        source_stream_id,
        source_stream_version,
        work_kind
    ),
    CONSTRAINT work_items_source_event_fkey FOREIGN KEY (
        source_stream_type,
        source_stream_id,
        source_stream_version
    ) REFERENCES events (stream_type, stream_id, stream_version),
    CONSTRAINT work_items_attempts_check CHECK (
        attempts >= 0 AND attempts <= max_attempts
    ),
    CONSTRAINT work_items_max_attempts_check CHECK (
        max_attempts BETWEEN 1 AND 100
    ),
    CONSTRAINT work_items_last_error_check CHECK (
        last_error IS NULL OR octet_length(last_error) <= 4096
    )
);

CREATE INDEX work_items_due_idx
    ON work_items (COALESCE(next_attempt_at, run_at), created_at)
    WHERE attempts < max_attempts;
-- +goose StatementEnd
-- docref: end work-items-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE work_items;
-- +goose StatementEnd
