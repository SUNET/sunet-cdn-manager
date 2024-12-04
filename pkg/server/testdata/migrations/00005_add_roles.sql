-- +goose up
-- organization1, last version is active
INSERT INTO roles (id, name, superuser) VALUES ('00000000-0000-0000-0000-000000000022', 'admin', TRUE);
INSERT INTO roles (id, name) VALUES ('00000000-0000-0000-0000-000000000023', 'customer');
-- +goose down
DELETE FROM roles;
