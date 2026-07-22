-- +goose Up

-- docref: begin device-renewal-retry-schema
-- +goose StatementBegin
ALTER TABLE devices
ADD COLUMN previous_certificate_der bytea;

ALTER TABLE devices
ADD CONSTRAINT devices_previous_certificate_der_check CHECK (
    previous_certificate_der IS NULL
    OR octet_length(previous_certificate_der) BETWEEN 1 AND 65536
);
-- +goose StatementEnd
-- docref: end device-renewal-retry-schema

-- +goose Down

ALTER TABLE devices DROP COLUMN previous_certificate_der;
