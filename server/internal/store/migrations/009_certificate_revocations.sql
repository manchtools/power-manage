-- +goose Up

-- docref: begin certificate-revocations-schema
-- +goose StatementBegin
ALTER TABLE devices
ADD COLUMN lifecycle_state text NOT NULL DEFAULT 'active';

ALTER TABLE devices
ADD CONSTRAINT devices_lifecycle_state_check
CHECK (lifecycle_state IN ('active', 'force_renewal', 'revoked'))
NOT VALID;

CREATE TABLE certificate_revocations (
    certificate_class text NOT NULL CHECK (
        certificate_class IN ('agent', 'gateway')
    ),
    certificate_fingerprint bytea NOT NULL CHECK (
        octet_length(certificate_fingerprint) = 32
    ),
    certificate_der bytea NOT NULL CHECK (
        octet_length(certificate_der) BETWEEN 1 AND 65536
    ),
    serial_number bytea NOT NULL CHECK (
        octet_length(serial_number) BETWEEN 1 AND 20
    ),
    revoked_at timestamp with time zone NOT NULL,
    reason_code smallint NOT NULL CHECK (
        reason_code IN (0, 1, 2, 3, 4, 5, 6, 8, 9, 10)
    ),
    source_stream_type text NOT NULL,
    source_stream_id text NOT NULL,
    source_stream_version bigint NOT NULL,
    CONSTRAINT certificate_revocations_pkey PRIMARY KEY (
        certificate_class,
        certificate_fingerprint
    ),
    CONSTRAINT certificate_revocations_class_serial_key UNIQUE (
        certificate_class,
        serial_number
    ),
    CONSTRAINT certificate_revocations_source_event_key UNIQUE (
        source_stream_type,
        source_stream_id,
        source_stream_version
    ),
    CONSTRAINT certificate_revocations_source_event_fkey FOREIGN KEY (
        source_stream_type,
        source_stream_id,
        source_stream_version
    ) REFERENCES events (stream_type, stream_id, stream_version)
);

CREATE INDEX certificate_revocations_class_scan_idx
ON certificate_revocations (
    certificate_class,
    revoked_at,
    certificate_fingerprint
);

CREATE TABLE crl_state (
    certificate_class text PRIMARY KEY CHECK (
        certificate_class IN ('agent', 'gateway')
    ),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    crl_der bytea,
    issued_at timestamp with time zone,
    source_stream_type text,
    source_stream_id text,
    source_stream_version bigint,
    CONSTRAINT crl_state_publication_material_check CHECK (
        (
            sequence = 0
            AND crl_der IS NULL
            AND issued_at IS NULL
            AND source_stream_type IS NULL
            AND source_stream_id IS NULL
            AND source_stream_version IS NULL
        )
        OR
        (
            sequence > 0
            AND crl_der IS NOT NULL
            AND octet_length(crl_der) > 0
            AND issued_at IS NOT NULL
        )
    ),
    CONSTRAINT crl_state_source_tuple_check CHECK (
        (
            source_stream_type IS NULL
            AND source_stream_id IS NULL
            AND source_stream_version IS NULL
        )
        OR
        (
            source_stream_type IS NOT NULL
            AND source_stream_id IS NOT NULL
            AND source_stream_version IS NOT NULL
            AND source_stream_type <> ''
            AND source_stream_id <> ''
            AND source_stream_version > 0
        )
    ),
    CONSTRAINT crl_state_source_event_fkey FOREIGN KEY (
        source_stream_type,
        source_stream_id,
        source_stream_version
    ) REFERENCES events (stream_type, stream_id, stream_version)
);

CREATE TABLE crl_work_receipts (
    certificate_class text NOT NULL CHECK (
        certificate_class IN ('agent', 'gateway')
    ),
    source_stream_type text NOT NULL,
    source_stream_id text NOT NULL,
    source_stream_version bigint NOT NULL CHECK (source_stream_version > 0),
    publication_sequence bigint NOT NULL CHECK (publication_sequence > 0),
    CONSTRAINT crl_work_receipts_pkey PRIMARY KEY (
        certificate_class,
        source_stream_type,
        source_stream_id,
        source_stream_version
    ),
    CONSTRAINT crl_work_receipts_class_sequence_key UNIQUE (
        certificate_class,
        publication_sequence
    ),
    CONSTRAINT crl_work_receipts_source_event_fkey FOREIGN KEY (
        source_stream_type,
        source_stream_id,
        source_stream_version
    ) REFERENCES events (stream_type, stream_id, stream_version)
);

INSERT INTO crl_state (certificate_class, sequence)
VALUES ('agent', 0), ('gateway', 0);
-- +goose StatementEnd
-- docref: end certificate-revocations-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE crl_work_receipts;
DROP TABLE crl_state;
DROP TABLE certificate_revocations;
ALTER TABLE devices DROP COLUMN lifecycle_state;
-- +goose StatementEnd
