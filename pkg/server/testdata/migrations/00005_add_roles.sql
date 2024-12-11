-- +goose up
-- organization1, last version is active
INSERT INTO roles (id, name, superuser) VALUES ('00000005-0000-0000-0000-000000000001', 'admin', TRUE);
INSERT INTO roles (id, name) VALUES ('00000005-0000-0000-0000-000000000002', 'customer');
-- +goose down
DELETE FROM roles;
