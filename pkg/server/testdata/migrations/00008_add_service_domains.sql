-- +goose up
-- organization1, last version is active
INSERT INTO service_domains (id, service_version_id, domain) VALUES ('00000000-0000-0000-0000-000000000029', '00000000-0000-0000-0000-000000000015', 'www.example.se');
INSERT INTO service_domains (id, service_version_id, domain) VALUES ('00000000-0000-0000-0000-000000000030', '00000000-0000-0000-0000-000000000015', 'www.example.com');
-- +goose down
DELETE FROM service_domains;
