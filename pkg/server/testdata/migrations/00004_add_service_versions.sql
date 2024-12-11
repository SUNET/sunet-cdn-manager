-- +goose up
-- org1, last version is active
UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000001', id, version_counter FROM services WHERE name='org1-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000002', id, version_counter FROM services WHERE name='org1-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1';
INSERT INTO service_versions (id, service_id, version, active) SELECT '00000004-0000-0000-0000-000000000003', id, version_counter, TRUE FROM services WHERE name='org1-service1';

-- org2, second version is active
UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000004', id, version_counter FROM services WHERE name='org2-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1';
INSERT INTO service_versions (id, service_id, version, active) SELECT '00000004-0000-0000-0000-000000000005', id, version_counter, TRUE FROM services WHERE name='org2-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000006', id, version_counter FROM services WHERE name='org2-service1';

-- org3, no version is active
UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000007', id, version_counter FROM services WHERE name='org3-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000008', id, version_counter FROM services WHERE name='org3-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000009', id, version_counter FROM services WHERE name='org3-service1';
-- +goose down
DELETE FROM service_versions;
