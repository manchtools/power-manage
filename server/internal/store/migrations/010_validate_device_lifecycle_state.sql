-- +goose Up

-- docref: begin device-lifecycle-state-validation
ALTER TABLE devices
VALIDATE CONSTRAINT devices_lifecycle_state_check;
-- docref: end device-lifecycle-state-validation

-- +goose Down

-- +goose StatementBegin
ALTER TABLE devices
DROP CONSTRAINT devices_lifecycle_state_check;

ALTER TABLE devices
ADD CONSTRAINT devices_lifecycle_state_check CHECK (
    lifecycle_state IN ('active', 'force_renewal', 'revoked')
) NOT VALID;
-- +goose StatementEnd
