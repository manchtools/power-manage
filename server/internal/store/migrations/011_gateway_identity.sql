-- +goose Up

-- docref: begin gateway-identity-schema
-- +goose StatementBegin
ALTER TABLE registration_tokens
ADD COLUMN purpose text NOT NULL DEFAULT 'agent';

ALTER TABLE registration_tokens
ADD COLUMN dns_names text[] NOT NULL DEFAULT '{}';

ALTER TABLE registration_tokens
ADD CONSTRAINT registration_tokens_purpose_check CHECK (
    purpose IN ('agent', 'gateway')
) NOT VALID;

ALTER TABLE registration_tokens
ADD CONSTRAINT registration_tokens_dns_names_check CHECK (
    (purpose = 'agent' AND cardinality(dns_names) = 0)
    OR (purpose = 'gateway' AND cardinality(dns_names) > 0)
) NOT VALID;

CREATE TABLE gateways (
    gateway_id text PRIMARY KEY CHECK (
        gateway_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    projection_version bigint NOT NULL CHECK (projection_version > 0),
    certificate_der bytea NOT NULL CHECK (
        octet_length(certificate_der) BETWEEN 1 AND 65536
    ),
    certificate_fingerprint bytea NOT NULL CHECK (
        octet_length(certificate_fingerprint) = 32
    ),
    previous_certificate_der bytea CHECK (
        previous_certificate_der IS NULL
        OR octet_length(previous_certificate_der) BETWEEN 1 AND 65536
    ),
    registration_token_id text NOT NULL CHECK (
        registration_token_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    owner text NOT NULL DEFAULT '' CHECK (octet_length(owner) <= 256),
    dns_names text[] NOT NULL CHECK (cardinality(dns_names) > 0),
    lifecycle_state text NOT NULL DEFAULT 'active',
    updated_at timestamp with time zone NOT NULL,
    CONSTRAINT gateways_lifecycle_state_check CHECK (
        lifecycle_state IN ('active', 'revoked')
    )
);
-- +goose StatementEnd
-- docref: end gateway-identity-schema

-- +goose Down

-- +goose StatementBegin
DROP TABLE gateways;
ALTER TABLE registration_tokens DROP COLUMN dns_names;
ALTER TABLE registration_tokens DROP COLUMN purpose;
-- +goose StatementEnd
