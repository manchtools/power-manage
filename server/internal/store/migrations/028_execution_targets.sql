-- +goose Up

LOCK TABLE execution_outputs IN ACCESS EXCLUSIVE MODE;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM execution_outputs) THEN
        RAISE EXCEPTION USING MESSAGE =
            'execution target migration requires empty execution_outputs; existing rows cannot be assigned exact device identities';
    END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE execution_outputs
ADD COLUMN device_id text NOT NULL,
ADD CONSTRAINT execution_outputs_device_id_check
    CHECK (device_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$');

-- +goose Down

ALTER TABLE execution_outputs
DROP CONSTRAINT execution_outputs_device_id_check;

ALTER TABLE execution_outputs
DROP COLUMN device_id;
