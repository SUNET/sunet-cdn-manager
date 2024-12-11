-- +goose up
-- organization1, last version is active
INSERT INTO service_domains (id, service_version_id, domain) VALUES ('00000008-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', 'www.example.se');
INSERT INTO service_domains (id, service_version_id, domain) VALUES ('00000008-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', 'www.example.com');
-- +goose down
DELETE FROM service_domains;
