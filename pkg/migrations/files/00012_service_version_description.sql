-- +goose up

ALTER TABLE service_versions ADD COLUMN description text NOT NULL DEFAULT '';
ALTER TABLE service_versions ADD CONSTRAINT service_versions_description_size CHECK(length(description) <= 512);
