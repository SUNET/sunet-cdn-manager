-- +goose up
-- org1, last version is active
SELECT version_counter FROM services WHERE name='org1-service1' FOR UPDATE;
UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1';
INSERT INTO service_versions (service_id, version) SELECT id, version_counter FROM services WHERE name='org1-service1';

SELECT version_counter FROM services WHERE name='org1-service1' FOR UPDATE;
UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1';
INSERT INTO service_versions (service_id, version) SELECT id, version_counter FROM services WHERE name='org1-service1';

SELECT version_counter FROM services WHERE name='org1-service1' FOR UPDATE;
UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1';
INSERT INTO service_versions (service_id, version, active) SELECT id, version_counter, TRUE FROM services WHERE name='org1-service1';

-- org2, second version is active
SELECT version_counter FROM services WHERE name='org2-service1' FOR UPDATE;
UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1';
INSERT INTO service_versions (service_id, version) SELECT id, version_counter FROM services WHERE name='org2-service1';

SELECT version_counter FROM services WHERE name='org2-service1' FOR UPDATE;
UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1';
INSERT INTO service_versions (service_id, version, active) SELECT id, version_counter, TRUE FROM services WHERE name='org2-service1';

SELECT version_counter FROM services WHERE name='org2-service1' FOR UPDATE;
UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1';
INSERT INTO service_versions (service_id, version) SELECT id, version_counter FROM services WHERE name='org2-service1';

-- org3, no version is active
SELECT version_counter FROM services WHERE name='org3-service1' FOR UPDATE;
UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1';
INSERT INTO service_versions (service_id, version) SELECT id, version_counter FROM services WHERE name='org3-service1';

SELECT version_counter FROM services WHERE name='org3-service1' FOR UPDATE;
UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1';
INSERT INTO service_versions (service_id, version) SELECT id, version_counter FROM services WHERE name='org3-service1';

SELECT version_counter FROM services WHERE name='org3-service1' FOR UPDATE;
UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1';
INSERT INTO service_versions (service_id, version) SELECT id, version_counter FROM services WHERE name='org3-service1';
-- +goose down
DELETE FROM service_versions;
