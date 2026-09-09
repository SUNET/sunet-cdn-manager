-- +goose up

-- Soft-delete support for services. A NULL disabled_at means the service is
-- enabled; a non-NULL value records when it was disabled.
--
-- A disabled service keeps its row, uid_range, IP addresses, versions and
-- configuration, and keeps consuming its org's service_quota slot. It is
-- filtered out of the cache-node and l4lb-node config endpoints, which makes
-- the sunet-cdn-agent reconciler tear down its containers, on-disk state and
-- BGP announcements. Deletion is only permitted once a service is disabled.
--
-- Nullable with no default, so every pre-existing service stays enabled and no
-- backfill is required.
ALTER TABLE services ADD COLUMN disabled_at timestamptz;
