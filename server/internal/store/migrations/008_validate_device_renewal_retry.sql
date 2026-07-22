-- +goose Up

-- docref: begin device-renewal-retry-validation
ALTER TABLE devices
VALIDATE CONSTRAINT devices_previous_certificate_der_check;
-- docref: end device-renewal-retry-validation

-- +goose Down

-- +goose StatementBegin
ALTER TABLE devices
DROP CONSTRAINT devices_previous_certificate_der_check;

ALTER TABLE devices
ADD CONSTRAINT devices_previous_certificate_der_check CHECK (
    previous_certificate_der IS NULL
    OR octet_length(previous_certificate_der) BETWEEN 1 AND 65536
) NOT VALID;
-- +goose StatementEnd
