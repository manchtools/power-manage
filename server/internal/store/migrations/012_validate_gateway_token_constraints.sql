-- +goose Up

-- docref: begin gateway-token-constraint-validation
ALTER TABLE registration_tokens
VALIDATE CONSTRAINT registration_tokens_purpose_check;

ALTER TABLE registration_tokens
VALIDATE CONSTRAINT registration_tokens_dns_names_check;
-- docref: end gateway-token-constraint-validation

-- +goose Down

-- +goose StatementBegin
ALTER TABLE registration_tokens
DROP CONSTRAINT registration_tokens_dns_names_check;

ALTER TABLE registration_tokens
DROP CONSTRAINT registration_tokens_purpose_check;

ALTER TABLE registration_tokens
ADD CONSTRAINT registration_tokens_purpose_check CHECK (
    purpose IN ('agent', 'gateway')
) NOT VALID;

ALTER TABLE registration_tokens
ADD CONSTRAINT registration_tokens_dns_names_check CHECK (
    (purpose = 'agent' AND cardinality(dns_names) = 0)
    OR (purpose = 'gateway' AND cardinality(dns_names) > 0)
) NOT VALID;
-- +goose StatementEnd
