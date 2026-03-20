-- +goose up

-- is_not_uuid returns true if the input is NOT a valid UUID.
-- UUID parsing is deterministic with no side effects, so IMMUTABLE is
-- correct despite the EXCEPTION block (which prevents inlining but
-- does not affect correctness).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION is_not_uuid(val text)
RETURNS boolean AS $$
BEGIN
  PERFORM val::uuid;
  RETURN false;
EXCEPTION WHEN invalid_text_representation THEN
  RETURN true;
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;
-- +goose StatementEnd

-- is_valid_name composes DNS label validation with UUID rejection.
-- A valid name in this system is a DNS label that is not a UUID.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION is_valid_name(name text)
RETURNS boolean AS $$
BEGIN
  RETURN is_valid_dns_label(name) AND is_not_uuid(name);
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;
-- +goose StatementEnd

-- Replace is_valid_dns_label constraints with is_valid_name on all
-- 9 tables that use DNS label names.

-- Tables with constraint named "valid_dns_label":
ALTER TABLE orgs DROP CONSTRAINT valid_dns_label;
ALTER TABLE orgs ADD CONSTRAINT valid_name CHECK(is_valid_name(name));

ALTER TABLE services DROP CONSTRAINT valid_dns_label;
ALTER TABLE services ADD CONSTRAINT valid_name CHECK(is_valid_name(name));

ALTER TABLE cache_nodes DROP CONSTRAINT valid_dns_label;
ALTER TABLE cache_nodes ADD CONSTRAINT valid_name CHECK(is_valid_name(name));

ALTER TABLE l4lb_nodes DROP CONSTRAINT valid_dns_label;
ALTER TABLE l4lb_nodes ADD CONSTRAINT valid_name CHECK(is_valid_name(name));

ALTER TABLE node_groups DROP CONSTRAINT valid_dns_label;
ALTER TABLE node_groups ADD CONSTRAINT valid_name CHECK(is_valid_name(name));

ALTER TABLE service_origin_groups DROP CONSTRAINT valid_dns_label;
ALTER TABLE service_origin_groups ADD CONSTRAINT valid_name CHECK(is_valid_name(name));

ALTER TABLE org_keycloak_client_credentials DROP CONSTRAINT valid_dns_label;
ALTER TABLE org_keycloak_client_credentials ADD CONSTRAINT valid_name CHECK(is_valid_name(name));

-- Tables with constraint named "valid_dns_label_name":
ALTER TABLE roles DROP CONSTRAINT valid_dns_label_name;
ALTER TABLE roles ADD CONSTRAINT valid_name CHECK(is_valid_name(name));

ALTER TABLE auth_providers DROP CONSTRAINT valid_dns_label_name;
ALTER TABLE auth_providers ADD CONSTRAINT valid_name CHECK(is_valid_name(name));
