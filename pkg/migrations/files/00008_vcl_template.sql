-- +goose up

ALTER TABLE service_vcls ADD COLUMN vcl_template text;

UPDATE service_vcls SET vcl_template =
    '#SUNET-CDN-MANAGER preamble' || E'\n' || E'\n' ||
    'sub vcl_recv {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_recv' || E'\n' ||
    COALESCE(vcl_recv || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_pipe {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_pipe' || E'\n' ||
    COALESCE(vcl_pipe || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_pass {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_pass' || E'\n' ||
    COALESCE(vcl_pass || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_hash {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_hash' || E'\n' ||
    COALESCE(vcl_hash || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_purge {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_purge' || E'\n' ||
    COALESCE(vcl_purge || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_miss {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_miss' || E'\n' ||
    COALESCE(vcl_miss || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_hit {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_hit' || E'\n' ||
    COALESCE(vcl_hit || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_deliver {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_deliver' || E'\n' ||
    COALESCE(vcl_deliver || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_synth {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_synth' || E'\n' ||
    COALESCE(vcl_synth || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_backend_fetch {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_backend_fetch' || E'\n' ||
    COALESCE(vcl_backend_fetch || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_backend_response {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_backend_response' || E'\n' ||
    COALESCE(vcl_backend_response || E'\n', '') ||
    '}' || E'\n' || E'\n' ||
    'sub vcl_backend_error {' || E'\n' ||
    '#SUNET-CDN-MANAGER vcl_backend_error' || E'\n' ||
    COALESCE(vcl_backend_error || E'\n', '') ||
    '}';

ALTER TABLE service_vcls ALTER COLUMN vcl_template SET NOT NULL;
ALTER TABLE service_vcls ADD CONSTRAINT vcl_template_size CHECK(octet_length(vcl_template) >= 1 AND octet_length(vcl_template) <= 1048576);

ALTER TABLE service_vcls DROP COLUMN vcl_recv;
ALTER TABLE service_vcls DROP COLUMN vcl_pipe;
ALTER TABLE service_vcls DROP COLUMN vcl_pass;
ALTER TABLE service_vcls DROP COLUMN vcl_hash;
ALTER TABLE service_vcls DROP COLUMN vcl_purge;
ALTER TABLE service_vcls DROP COLUMN vcl_miss;
ALTER TABLE service_vcls DROP COLUMN vcl_hit;
ALTER TABLE service_vcls DROP COLUMN vcl_deliver;
ALTER TABLE service_vcls DROP COLUMN vcl_synth;
ALTER TABLE service_vcls DROP COLUMN vcl_backend_fetch;
ALTER TABLE service_vcls DROP COLUMN vcl_backend_response;
ALTER TABLE service_vcls DROP COLUMN vcl_backend_error;
