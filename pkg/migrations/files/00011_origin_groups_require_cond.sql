-- +goose up

-- Stop allowing legacy origin groups from before the 00010 migration where a
-- non-default group could still hold a NULL condition.
--
-- Make sure that the following query returns 0 before attempting to upgrade to
-- this version:
-- SELECT count(*) FROM service_origin_groups WHERE NOT default_group AND condition IS NULL;
ALTER TABLE service_origin_groups ADD CONSTRAINT non_default_group_has_condition CHECK (default_group OR condition IS NOT NULL);
