-- +goose up
INSERT INTO organizations (name) VALUES ('org1');
INSERT INTO organizations (name) VALUES ('org2');
INSERT INTO organizations (name) VALUES ('org3');
-- +goose down
DELETE FROM organizations;
