-- +goose up
ALTER TABLE users RENAME COLUMN name TO display_name;
