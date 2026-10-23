-- +goose up

-- A domain is in one of three states:
--   pending:    time_retired IS NULL AND NOT verified
--   verified:   time_retired IS NULL AND verified
--   retired:    time_retired IS NOT NULL (never verified, see below)
--
-- Retiring a domain releases its fqdn so another org can register it, which
-- is only safe if the retired row can no longer be mistaken for proof of
-- ownership. Forcing verified = false on retired rows guarantees that no code
-- path which checks verified (service version activation, agent config) will
-- ever treat a retired domain as owned.
ALTER TABLE domains ADD COLUMN time_retired timestamptz NULL;
ALTER TABLE domains ADD CONSTRAINT retired_not_verified CHECK (time_retired IS NULL OR NOT verified);

-- fqdn is only globally unique among live (not retired) domains. The old
-- UNIQUE was declared inline in 00001, so its index is owned by a
-- constraint and DROP INDEX is refused; drop the constraint instead. Its
-- name is domains_fqdn_key because renaming the index in 00007 renamed the
-- constraint along with it.
ALTER TABLE domains DROP CONSTRAINT domains_fqdn_key;
CREATE UNIQUE INDEX domains_fqdn_live_key ON domains (fqdn) WHERE time_retired IS NULL;

-- Within one org a fqdn still has a single row, retired or not, so
-- re-registering a retired domain means reviving its row.
ALTER TABLE domains ADD CONSTRAINT domains_org_id_fqdn_key UNIQUE (org_id, fqdn);

-- service_domains is otherwise only indexed by (service_version_id,
-- domain_id), which does not help looking up the versions that use a
-- domain. That is done per domain when listing domains, when retiring or
-- deleting one, and by the foreign key check when a domain row is deleted,
-- and versions are never removed, so the table only grows.
CREATE INDEX service_domains_domain_id_idx ON service_domains (domain_id);
