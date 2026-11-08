-- +goose up

-- Bounds how many versions a single service can have, and with that how much
-- version data it can accumulate. The default of 1000 is not expected to be
-- reached quickly, but a long-lived service can get there over time. Tenants
-- cannot delete service versions, so when a service reaches its quota an
-- operator raises it. The quota lives on the service rather than on orgs so
-- that raising it for the one service that reached it does not let every
-- other service in the org grow too. Existing services are not backfilled,
-- they simply get the default.
ALTER TABLE services ADD COLUMN version_quota bigint NOT NULL DEFAULT 1000;
ALTER TABLE services ADD CONSTRAINT version_quota_nonnegative CHECK (version_quota >= 0);
