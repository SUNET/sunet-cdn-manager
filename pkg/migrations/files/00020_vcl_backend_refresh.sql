-- +goose up

-- vcl_backend_refresh (called when a revalidation gets a 304 response) is a
-- new required VCL macro. Macros are validated every time VCL is generated,
-- not only when a version is saved, so every stored template, including
-- those of old and active service versions, needs the marker or it can no
-- longer be turned into VCL.
--
-- Service versions are otherwise never changed after creation. Adding the
-- sub is an exception that does not change behavior: the marker expands to
-- an empty block, and an empty vcl_backend_refresh falls through to the
-- built-in one just like a template without the sub did.
--
-- The sub is placed where the default template has it, right before
-- vcl_backend_response (matching the order Vinyl calls them in). Only the
-- marker lines are validated, the sub lines around them are free text, so
-- the opening line is matched loosely and only used when it appears exactly
-- once. A missing or ambiguous anchor appends the sub at the end instead,
-- which VCL accepts just as well since sub order does not matter and
-- multiple definitions of a built-in sub are concatenated. A template
-- that ends with a newline keeps doing so.
--
-- The 'n' flag enables newline-sensitive matching, which makes ^ match at
-- the start of every line instead of only at the start of the template.
-- Anchoring the pattern there means a "#"-commented copy of the line is not
-- mistaken for it. A copy inside a /* */ comment or a long string could
-- still be, but templates are not expected to contain one.
UPDATE service_vcls
SET vcl_template = CASE
    WHEN regexp_count(vcl_template, '^[ \t]*sub[ \t]+vcl_backend_response[ \t]*\{', 1, 'n') = 1 THEN
        regexp_replace(
            vcl_template,
            '^([ \t]*sub[ \t]+vcl_backend_response[ \t]*\{)',
            E'sub vcl_backend_refresh {\n#SUNET-CDN-MANAGER vcl_backend_refresh\n}\n\n\\1',
            'n'
        )
    WHEN right(vcl_template, 1) = E'\n' THEN
        vcl_template || E'\nsub vcl_backend_refresh {\n#SUNET-CDN-MANAGER vcl_backend_refresh\n}\n'
    ELSE
        vcl_template || E'\n\nsub vcl_backend_refresh {\n#SUNET-CDN-MANAGER vcl_backend_refresh\n}'
END;
