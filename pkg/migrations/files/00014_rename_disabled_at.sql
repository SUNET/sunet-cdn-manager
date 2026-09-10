-- +goose up

-- Make service disabled_at column name match the existing time_created column.
ALTER TABLE services RENAME COLUMN disabled_at TO time_disabled;
