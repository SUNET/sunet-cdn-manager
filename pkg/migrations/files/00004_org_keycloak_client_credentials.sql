-- +goose up

-- Make it possible to track keycloak client credentials that have been created
-- for API access for an organization. The client secret is only stored in
-- keycloak and is only shown to the user once during creation.
CREATE TABLE org_keycloak_client_credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    org_id uuid NOT NULL REFERENCES orgs(id),
    name text NOT NULL CONSTRAINT valid_dns_label CHECK(is_valid_dns_label(name)),
    client_id text UNIQUE NOT NULL,
    description text NOT NULL,
    registration_access_token text NOT NULL,
    UNIQUE(org_id, name)
);

-- Add quota on number of client tokens that can be created
ALTER TABLE orgs ADD COLUMN client_token_quota bigint NOT NULL DEFAULT 10;
