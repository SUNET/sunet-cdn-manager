-- +goose up

-- Quotas are validated to be 0 or greater by the API and console, make sure
-- the database enforces this as well.
ALTER TABLE orgs ADD CONSTRAINT service_quota_nonnegative CHECK (service_quota >= 0);
ALTER TABLE orgs ADD CONSTRAINT domain_quota_nonnegative CHECK (domain_quota >= 0);
ALTER TABLE orgs ADD CONSTRAINT client_token_quota_nonnegative CHECK (client_token_quota >= 0);
