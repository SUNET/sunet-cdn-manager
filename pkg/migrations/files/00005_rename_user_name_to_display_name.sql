-- +goose up
ALTER TABLE users RENAME COLUMN name TO display_name;
ALTER TABLE users RENAME CONSTRAINT non_empty_name TO non_empty_display_name;
ALTER TABLE users RENAME CONSTRAINT users_name_not_null TO users_display_name_not_null;
ALTER INDEX users_name_key RENAME TO users_display_name_key;
