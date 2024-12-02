-- +goose up
-- customer1, last version is active
INSERT INTO roles (name, superuser) VALUES ('admin', TRUE);
INSERT INTO roles (name) VALUES ('customer');
-- +goose down
DELETE FROM roles;
