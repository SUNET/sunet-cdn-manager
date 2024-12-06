-- +goose up
-- org1, last version is active
UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000000-0000-0000-0000-000000000013', id, version_counter FROM services WHERE name='org1-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000000-0000-0000-0000-000000000014', id, version_counter FROM services WHERE name='org1-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1';
INSERT INTO service_versions (id, service_id, version, active) SELECT '00000000-0000-0000-0000-000000000015', id, version_counter, TRUE FROM services WHERE name='org1-service1';

-- org2, second version is active
UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000000-0000-0000-0000-000000000016', id, version_counter FROM services WHERE name='org2-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1';
INSERT INTO service_versions (id, service_id, version, active) SELECT '00000000-0000-0000-0000-000000000017', id, version_counter, TRUE FROM services WHERE name='org2-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000000-0000-0000-0000-000000000018', id, version_counter FROM services WHERE name='org2-service1';

-- org3, no version is active
UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000000-0000-0000-0000-000000000019', id, version_counter FROM services WHERE name='org3-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000000-0000-0000-0000-000000000020', id, version_counter FROM services WHERE name='org3-service1';

UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1';
INSERT INTO service_versions (id, service_id, version) SELECT '00000000-0000-0000-0000-000000000021', id, version_counter FROM services WHERE name='org3-service1';
-- +goose down
DELETE FROM service_versions;
