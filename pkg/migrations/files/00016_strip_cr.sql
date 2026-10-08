-- +goose up

-- Browsers submit textarea content with CRLF line endings, so VCL templates
-- and origin group conditions created via the console have been stored with
-- CR characters. Normalize existing content to LF (lone CR characters
-- included, matching the normalization now done before insert) and make the
-- database enforce it. Only rows containing CR characters are rewritten.
UPDATE service_vcls
SET vcl_template = replace(replace(vcl_template, E'\r\n', E'\n'), E'\r', E'\n')
WHERE strpos(vcl_template, E'\r') > 0;

ALTER TABLE service_vcls ADD CONSTRAINT vcl_template_no_cr CHECK (strpos(vcl_template, E'\r') = 0);

-- NULL conditions (default groups) are not matched by the WHERE clause and
-- pass the CHECK constraint since it evaluates to NULL for them.
UPDATE service_origin_groups
SET condition = replace(replace(condition, E'\r\n', E'\n'), E'\r', E'\n')
WHERE strpos(condition, E'\r') > 0;

ALTER TABLE service_origin_groups ADD CONSTRAINT condition_no_cr CHECK (strpos(condition, E'\r') = 0);
