-- +goose Up

-- SPEC-006 M8: issuer-scoped revocation state and durable CA rotation.

-- +goose StatementBegin
-- docref: begin issuer-scoped-revocation-schema
ALTER TABLE certificate_revocations
DROP CONSTRAINT certificate_revocations_class_serial_key;

ALTER TABLE certificate_revocations
ADD COLUMN issuer_identifier bytea NOT NULL DEFAULT '\x00';

ALTER TABLE certificate_revocations
ADD CONSTRAINT certificate_revocations_issuer_identifier_length_check CHECK (
    octet_length(issuer_identifier) BETWEEN 1 AND 64
);

ALTER TABLE certificate_revocations
ADD CONSTRAINT certificate_revocations_issuer_serial_key UNIQUE (
    certificate_class,
    issuer_identifier,
    serial_number
);

ALTER TABLE events DROP CONSTRAINT events_stream_id_check;
ALTER TABLE events ADD CONSTRAINT events_stream_id_check CHECK (
    stream_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    OR (stream_type = 'ca-rotation' AND stream_id IN ('agent', 'gateway'))
);

CREATE SEQUENCE events_global_position_seq AS bigint;
ALTER TABLE events ADD COLUMN global_position bigint;
WITH ordered_events AS (
    SELECT ctid, row_number() OVER (
        ORDER BY created_at, stream_type, stream_id, stream_version
    ) AS global_position
    FROM events
)
UPDATE events
SET global_position = ordered_events.global_position
FROM ordered_events
WHERE events.ctid = ordered_events.ctid;
SELECT setval(
    'events_global_position_seq',
    COALESCE((SELECT max(global_position) + 1 FROM events), 1),
    false
);
ALTER SEQUENCE events_global_position_seq OWNED BY events.global_position;
ALTER TABLE events ALTER COLUMN global_position SET DEFAULT nextval('events_global_position_seq');
ALTER TABLE events ALTER COLUMN global_position SET NOT NULL;
ALTER TABLE events ADD CONSTRAINT events_global_position_key UNIQUE (global_position);

ALTER TABLE crl_work_receipts
DROP CONSTRAINT crl_work_receipts_class_sequence_key;

ALTER TABLE crl_work_receipts
DROP CONSTRAINT crl_work_receipts_pkey;

ALTER TABLE crl_state
DROP CONSTRAINT crl_state_pkey;

ALTER TABLE crl_state
ADD COLUMN issuer_fingerprint bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex');

ALTER TABLE crl_state
ADD CONSTRAINT crl_state_issuer_fingerprint_length_check CHECK (
    octet_length(issuer_fingerprint) = 32
);

ALTER TABLE crl_work_receipts
ADD COLUMN issuer_fingerprint bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex');

ALTER TABLE crl_work_receipts
ADD CONSTRAINT crl_work_receipts_issuer_fingerprint_length_check CHECK (
    octet_length(issuer_fingerprint) = 32
);

ALTER TABLE crl_state
ADD CONSTRAINT crl_state_pkey PRIMARY KEY (certificate_class, issuer_fingerprint);

ALTER TABLE crl_work_receipts
ADD CONSTRAINT crl_work_receipts_pkey PRIMARY KEY (
    certificate_class,
    issuer_fingerprint,
    source_stream_type,
    source_stream_id,
    source_stream_version
);

-- One cumulative CRL publication deliberately covers multiple source events,
-- so publication_sequence is not unique within an issuer. Source-event
-- identity is the idempotency key; the referenced CRL state owns monotonicity.
-- docref: end issuer-scoped-revocation-schema

CREATE TABLE ca_rotation_state (
    certificate_class text NOT NULL,
    projection_version bigint NOT NULL,
    state_json bytea NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT ca_rotation_state_pkey PRIMARY KEY (certificate_class),
    CONSTRAINT ca_rotation_state_certificate_class_check CHECK (
        certificate_class IN ('agent', 'gateway')
    ),
    CONSTRAINT ca_rotation_state_projection_version_check CHECK (
        projection_version > 0
    ),
    CONSTRAINT ca_rotation_state_json_length_check CHECK (
        octet_length(state_json) BETWEEN 2 AND 262144
    )
);
-- +goose StatementEnd

-- +goose Down

-- +goose StatementBegin
DROP TABLE ca_rotation_state;

DELETE FROM events WHERE stream_type = 'ca-rotation';
ALTER TABLE events DROP CONSTRAINT events_global_position_key;
ALTER TABLE events ALTER COLUMN global_position DROP DEFAULT;
ALTER SEQUENCE events_global_position_seq OWNED BY NONE;
ALTER TABLE events DROP COLUMN global_position;
DROP SEQUENCE events_global_position_seq;
ALTER TABLE events DROP CONSTRAINT events_stream_id_check;
ALTER TABLE events ADD CONSTRAINT events_stream_id_check CHECK (
    stream_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
);

DELETE FROM crl_work_receipts;
DELETE FROM crl_state;

ALTER TABLE crl_work_receipts DROP CONSTRAINT crl_work_receipts_pkey;
ALTER TABLE crl_state DROP CONSTRAINT crl_state_pkey;
ALTER TABLE crl_work_receipts DROP COLUMN issuer_fingerprint;
ALTER TABLE crl_state DROP COLUMN issuer_fingerprint;

ALTER TABLE crl_state
ADD CONSTRAINT crl_state_pkey PRIMARY KEY (certificate_class);
ALTER TABLE crl_work_receipts
ADD CONSTRAINT crl_work_receipts_pkey PRIMARY KEY (
    certificate_class,
    source_stream_type,
    source_stream_id,
    source_stream_version
);
ALTER TABLE crl_work_receipts
ADD CONSTRAINT crl_work_receipts_class_sequence_key UNIQUE (
    certificate_class,
    publication_sequence
);
ALTER TABLE certificate_revocations
DROP CONSTRAINT certificate_revocations_issuer_serial_key;
ALTER TABLE certificate_revocations
DROP CONSTRAINT certificate_revocations_issuer_identifier_length_check;
ALTER TABLE certificate_revocations
DROP COLUMN issuer_identifier;
ALTER TABLE certificate_revocations
ADD CONSTRAINT certificate_revocations_class_serial_key UNIQUE (
    certificate_class,
    serial_number
);
-- +goose StatementEnd
