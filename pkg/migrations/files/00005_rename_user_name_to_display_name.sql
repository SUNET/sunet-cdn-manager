-- +goose up
ALTER TABLE users RENAME COLUMN name TO display_name;
ALTER TABLE users RENAME CONSTRAINT non_empty_name TO non_empty_display_name;
