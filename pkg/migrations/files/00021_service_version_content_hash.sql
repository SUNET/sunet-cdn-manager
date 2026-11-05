-- +goose up

-- Submitting content identical to an existing version of the same service
-- (a console clone saved unchanged, an API client posting its desired state
-- in a loop) returns that version instead of creating a new one. Each
-- version stores a hash of its content, so a match is one index lookup.
--
-- service_version_content_hash() is the only definition of content. It
-- reads the version's rows, so the backfill and the insert path agree:
--
--   * the VCL template, by its own SHA-256 (templates can be 1 MiB; this
--     keeps the hashed string short and still tells any two apart)
--   * the domain FQDNs, as a set
--   * the origin groups in position (priority) order: name, condition,
--     default flag
--   * each group's origins, as a set: host, port, tls, verify_tls
--
-- The description is not content: it describes a version, and a client
-- putting a commit id in it would otherwise never match.
--
-- quote_nullable() makes every value self-delimiting and keeps NULL apart
-- from ''. Sets are sorted, since no order is stored for them: COLLATE "C"
-- keeps the order independent of the database collation, and sorting on
-- every hashed column keeps it total without relying on UNIQUE constraints.
-- COALESCE(string_agg(...), '') writes an empty set as an empty list rather
-- than NULL. Around a group's origins it also keeps the group in the hash,
-- as string_agg would skip the group's element if it were NULL.
--
-- The hashed string for the base version in content_hash_migration_test.go.
-- It has one line per section; origin_groups is a single line, broken after
-- each group only in this comment. Run the body without the outer
-- sha256(convert_to(...)) to see it for any version.
--
--   vcl_template:'a912aa30866f4c5a0ae5748ba13178427fcc712f57131b46284e16397b298413'
--   domains:'a.example.com','b.example.com'
--   origin_groups:('api','req.url ~ "^/api"','false',origins:('x.example.net','443','true','true'),('y.example.net','80','false','false')),
--       ('img','req.url ~ "^/img"','false',origins:('i.example.net','443','true','false')),
--       ('default',NULL,'true',origins:('z.example.net','443','true','false'))
--
-- The body is SQL-standard (RETURN <expression>, not AS $$ ... $$), so it is
-- parsed once, at creation:
--
--   * tables resolve to the cdn schema (migrations run as the cdn user and
--     search_path starts with "$user"), not the caller's search_path
--   * pg_dump writes them qualified, unlike the string body 00009 fixed
--   * PostgreSQL records the columns it reads, so dropping or retyping one
--     fails until this function is dealt with
--
-- It reads only child rows, so the hash can be computed before the
-- service_versions row exists.
--
-- A migration that changes hashed content (like 00020) or this function
-- must end with a rehash, or stored hashes describe content that no longer
-- exists. Deferring the UNIQUE constraint checks only the end state:
--
--   SET CONSTRAINTS service_versions_service_id_content_hash_key DEFERRED;
--   UPDATE service_versions SET content_hash = service_version_content_hash(id);
--
-- New content columns or tables must be added here, or versions differing
-- only there count as identical. TestServiceVersionContentHashCoversEveryColumn
-- fails until each new column is hashed or listed as not content.
-- +goose StatementBegin
CREATE FUNCTION service_version_content_hash(version_id uuid)
RETURNS bytea
LANGUAGE sql STABLE STRICT
RETURN sha256(convert_to(
    'vcl_template:' || quote_nullable(encode(sha256(convert_to((
        SELECT vcl_template
        FROM service_vcls
        WHERE service_version_id = version_id
    ), 'UTF8')), 'hex')) || E'\n' ||
    'domains:' || COALESCE((
        SELECT string_agg(quote_nullable(d.fqdn), ',' ORDER BY d.fqdn COLLATE "C")
        FROM service_domains sd
        JOIN domains d ON d.id = sd.domain_id
        WHERE sd.service_version_id = version_id
    ), '') || E'\n' ||
    'origin_groups:' || COALESCE((
        SELECT string_agg(
            '(' || quote_nullable(og.name) ||
            ',' || quote_nullable(og.condition) ||
            ',' || quote_nullable(og.default_group) ||
            ',origins:' || COALESCE((
                SELECT string_agg(
                    '(' || quote_nullable(so.host) ||
                    ',' || quote_nullable(so.port) ||
                    ',' || quote_nullable(so.tls) ||
                    ',' || quote_nullable(so.verify_tls) || ')',
                    ',' ORDER BY so.host COLLATE "C", so.port, so.tls, so.verify_tls)
                FROM service_origins so
                WHERE so.origin_group_id = og.id
            ), '') || ')',
            ',' ORDER BY og.position, og.name COLLATE "C")
        FROM service_origin_groups og
        WHERE og.service_version_id = version_id
    ), ''),
    'UTF8'));
-- +goose StatementEnd

-- The insert path writes the child rows, hashes them, and only then inserts
-- the service_versions row they point to, with these foreign keys deferred.
-- INITIALLY IMMEDIATE leaves every other transaction as before.
ALTER TABLE service_domains ALTER CONSTRAINT service_domains_service_version_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE service_origin_groups ALTER CONSTRAINT service_origin_groups_service_version_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE service_origins ALTER CONSTRAINT service_origins_service_version_id_fkey DEFERRABLE INITIALLY IMMEDIATE;
ALTER TABLE service_vcls ALTER CONSTRAINT service_vcls_service_version_id_fkey DEFERRABLE INITIALLY IMMEDIATE;

-- The function finds origins by origin_group_id, which no index covered.
-- Without one each group scans all origins, in the backfill and on every
-- insert under the service row lock. Cascading group deletes use it too.
CREATE INDEX service_origins_origin_group_id_idx ON service_origins (origin_group_id);

ALTER TABLE service_versions ADD COLUMN content_hash bytea;
UPDATE service_versions SET content_hash = service_version_content_hash(id);
ALTER TABLE service_versions ALTER COLUMN content_hash SET NOT NULL;
ALTER TABLE service_versions ADD CONSTRAINT content_hash_sha256 CHECK (octet_length(content_hash) = 32);

-- Duplicate content within a service makes this fail and rolls back the
-- whole migration: change or remove duplicates by hand first. DEFERRABLE so
-- a rehash can defer it, see above.
ALTER TABLE service_versions ADD CONSTRAINT service_versions_service_id_content_hash_key UNIQUE (service_id, content_hash) DEFERRABLE INITIALLY IMMEDIATE;
