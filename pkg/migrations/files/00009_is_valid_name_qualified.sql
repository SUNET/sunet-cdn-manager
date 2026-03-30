-- +goose up

-- Update is_valid_name to make it reference is_valid_dns_label() and
-- is_not_uuid() qualified with the "cdn" schema. Without this restoring a
-- pg_dump file fails with errors if you do not also explicitly call
-- "SET search_path TO cdn;". Example of error seen:
-- ##########
-- ERROR:  function is_valid_dns_label(text) does not exist
-- LINE 1: is_valid_dns_label(name) AND is_not_uuid(name)
--         ^
-- HINT:  No function matches the given name and argument types. You might need to add explicit type casts.
-- QUERY:  is_valid_dns_label(name) AND is_not_uuid(name)
-- CONTEXT:  PL/pgSQL function cdn.is_valid_name(text) line 3 at RETURN
-- ##########
-- Related question: https://dba.stackexchange.com/questions/342360/postgresql-pg-dump-fails-to-correctly-pg-restore-due-to-missing-or-erroneous-cu
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION is_valid_name(name text)
RETURNS boolean AS $$
BEGIN
  RETURN cdn.is_valid_dns_label(name) AND cdn.is_not_uuid(name);
END;
$$ LANGUAGE plpgsql IMMUTABLE STRICT;
-- +goose StatementEnd
