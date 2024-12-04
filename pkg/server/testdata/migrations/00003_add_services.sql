-- +goose up
INSERT INTO services (org_id, name) SELECT id, 'org1-service1' FROM organizations WHERE name='org1';
INSERT INTO services (org_id, name) SELECT id, 'org1-service2' FROM organizations WHERE name='org1';
INSERT INTO services (org_id, name) SELECT id, 'org1-service3' FROM organizations WHERE name='org1';
INSERT INTO services (org_id, name) SELECT id, 'org2-service1' FROM organizations WHERE name='org2';
INSERT INTO services (org_id, name) SELECT id, 'org2-service2' FROM organizations WHERE name='org2';
INSERT INTO services (org_id, name) SELECT id, 'org2-service3' FROM organizations WHERE name='org2';
INSERT INTO services (org_id, name) SELECT id, 'org3-service1' FROM organizations WHERE name='org3';
INSERT INTO services (org_id, name) SELECT id, 'org3-service2' FROM organizations WHERE name='org3';
INSERT INTO services (org_id, name) SELECT id, 'org3-service3' FROM organizations WHERE name='org3';
-- +goose down
DELETE FROM services;
