-- +goose up

ALTER TABLE service_origin_groups ADD COLUMN service_version_id uuid REFERENCES service_versions(id) ON DELETE CASCADE;
ALTER TABLE service_origin_groups ADD COLUMN condition text;
ALTER TABLE service_origin_groups ADD COLUMN position bigint;
ALTER TABLE service_origin_groups ADD COLUMN legacy_id uuid;

-- Allow the new per-version copies to carry service_id IS NULL so the
-- later DELETE/safety-check logic can tell them apart from legacy rows.
ALTER TABLE service_origin_groups ALTER COLUMN service_id DROP NOT NULL;

-- Copy every service-level origin group into every version of that
-- service. Unreferenced groups are filtered out at generation time and
-- condition-less groups never join the selection chain. Positions are
-- assigned with the default group last (regardless of name) so that DB
-- contents are tidy. Non-default groups are ordered by name. Existing
-- versions may regenerate VCL/haproxy config in a different backend
-- order than before if their group names previously sorted the default
-- group before any non-default group.
INSERT INTO service_origin_groups (service_version_id, default_group, name, position, legacy_id)
SELECT
    sv.id,
    og.default_group,
    og.name,
    row_number() OVER (PARTITION BY sv.id ORDER BY og.default_group, og.name) - 1,
    og.id
FROM service_versions sv
JOIN service_origin_groups og ON og.service_id = sv.service_id
WHERE og.service_version_id IS NULL;

-- Point origins at the copy that lives in their own service version.
UPDATE service_origins so
SET origin_group_id = new_og.id
FROM service_origin_groups new_og
WHERE new_og.legacy_id = so.origin_group_id
  AND new_og.service_version_id = so.service_version_id;

-- Safety check: no origin may still reference a legacy (service-level) group.
-- +goose StatementBegin
DO $$
DECLARE
    dangling bigint;
BEGIN
    SELECT count(*) INTO dangling
    FROM service_origins so
    JOIN service_origin_groups og ON so.origin_group_id = og.id
    WHERE og.service_id IS NOT NULL;
    IF dangling > 0 THEN
        RAISE EXCEPTION 'origin group migration left % origins pointing at legacy groups', dangling;
    END IF;
END
$$;
-- +goose StatementEnd

DELETE FROM service_origin_groups WHERE service_id IS NOT NULL;

DROP INDEX service_origin_groups_default_only_1_true;
ALTER TABLE service_origin_groups DROP COLUMN service_id;
ALTER TABLE service_origin_groups DROP COLUMN legacy_id;
ALTER TABLE service_origin_groups ALTER COLUMN service_version_id SET NOT NULL;
ALTER TABLE service_origin_groups ALTER COLUMN position SET NOT NULL;
ALTER TABLE service_origin_groups ADD CONSTRAINT service_origin_groups_version_name_unique UNIQUE (service_version_id, name);
ALTER TABLE service_origin_groups ADD CONSTRAINT service_origin_groups_version_position_unique UNIQUE (service_version_id, position) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE service_origin_groups ADD CONSTRAINT condition_non_empty_if_not_null CHECK (condition IS NULL OR length(condition) > 0);
ALTER TABLE service_origin_groups ADD CONSTRAINT default_group_has_no_condition CHECK (NOT (default_group AND condition IS NOT NULL));
CREATE UNIQUE INDEX service_origin_groups_default_only_1_true_per_version ON service_origin_groups (service_version_id, default_group) WHERE default_group;
