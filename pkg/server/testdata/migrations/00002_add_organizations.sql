-- +goose up
-- use static UUIDs to get known contents for testing
INSERT INTO organizations (id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'org1');
INSERT INTO organizations (id, name) VALUES ('00000000-0000-0000-0000-000000000002', 'org2');
INSERT INTO organizations (id, name) VALUES ('00000000-0000-0000-0000-000000000003', 'org3');
-- +goose down
DELETE FROM organizations;
