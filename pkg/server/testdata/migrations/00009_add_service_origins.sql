-- +goose up
-- organization1, last version is active
INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', 'srv2.example.com', 80, false);
INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', 'srv1.example.se', 443, true);
-- +goose down
DELETE FROM service_origins;
