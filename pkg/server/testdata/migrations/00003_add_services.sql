-- +goose up
-- use static UUID to get known contents for testing
INSERT INTO services (id, org_id, name) SELECT '00000000-0000-0000-0000-000000000004', id, 'org1-service1' FROM organizations WHERE name='org1';
INSERT INTO services (id, org_id, name) SELECT '00000000-0000-0000-0000-000000000005', id, 'org1-service2' FROM organizations WHERE name='org1';
INSERT INTO services (id, org_id, name) SELECT '00000000-0000-0000-0000-000000000006', id, 'org1-service3' FROM organizations WHERE name='org1';
INSERT INTO services (id, org_id, name) SELECT '00000000-0000-0000-0000-000000000007', id, 'org2-service1' FROM organizations WHERE name='org2';
INSERT INTO services (id, org_id, name) SELECT '00000000-0000-0000-0000-000000000008', id, 'org2-service2' FROM organizations WHERE name='org2';
INSERT INTO services (id, org_id, name) SELECT '00000000-0000-0000-0000-000000000009', id, 'org2-service3' FROM organizations WHERE name='org2';
INSERT INTO services (id, org_id, name) SELECT '00000000-0000-0000-0000-000000000010', id, 'org3-service1' FROM organizations WHERE name='org3';
INSERT INTO services (id, org_id, name) SELECT '00000000-0000-0000-0000-000000000011', id, 'org3-service2' FROM organizations WHERE name='org3';
INSERT INTO services (id, org_id, name) SELECT '00000000-0000-0000-0000-000000000012', id, 'org3-service3' FROM organizations WHERE name='org3';
-- +goose down
DELETE FROM services;
