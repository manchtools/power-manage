-- +goose Up

-- docref: begin execution-output-schema
-- +goose StatementBegin
CREATE TABLE execution_outputs (
    execution_id text PRIMARY KEY CHECK (execution_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    output_bytes bigint NOT NULL DEFAULT 0 CHECK (
        output_bytes BETWEEN 0 AND 10485760
    ),
    output_chunks integer NOT NULL DEFAULT 0 CHECK (
        output_chunks BETWEEN 0 AND 1024
    ),
    truncated boolean NOT NULL DEFAULT false,
    updated_at timestamp with time zone NOT NULL
);

CREATE TABLE execution_output_chunks (
    execution_id text NOT NULL REFERENCES execution_outputs(execution_id) ON DELETE CASCADE,
    chunk_index integer NOT NULL CHECK (chunk_index BETWEEN 0 AND 1023),
    body bytea NOT NULL CHECK (
        octet_length(body) BETWEEN 1 AND 65536
    ),
    created_at timestamp with time zone NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (execution_id, chunk_index)
);
-- +goose StatementEnd
-- docref: end execution-output-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE execution_output_chunks;
DROP TABLE execution_outputs;
-- +goose StatementEnd
