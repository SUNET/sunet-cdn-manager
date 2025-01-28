-- +goose up
CREATE TABLE orgs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT non_empty CHECK(length(name)>=1 AND length(name)<=63),
    service_quota bigint NOT NULL DEFAULT 1
);

CREATE TABLE services (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    org_id uuid NOT NULL REFERENCES orgs(id),
    name text NOT NULL CONSTRAINT non_empty CHECK(length(name)>=1 AND length(name)<=63),
    version_counter bigint DEFAULT 0 NOT NULL,
    UNIQUE(org_id, name)
);

-- https://stackoverflow.com/questions/55283779/prevent-overlapping-values-on-cidr-column-in-postgresql
-- https://dba.stackexchange.com/questions/205773/how-to-find-out-what-operator-class-and-access-method-should-be-used-for-an-excl
CREATE TABLE ip_networks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    network cidr UNIQUE NOT NULL,
    EXCLUDE USING gist (network inet_ops with &&)
);

CREATE TABLE service_ip_addresses (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    network_id uuid NOT NULL REFERENCES ip_networks(id),
    service_id uuid REFERENCES services(id),
    address inet UNIQUE NOT NULL CONSTRAINT valid_address CHECK((family(address) = 4 AND masklen(address) = 32) OR (family(address) = 6 AND masklen(address) = 128))
);

-- Create trigger function for verifying an IP is contained in the network it
-- links to. Extra goose annotation needed since the statement includes
-- semicolons.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION validate_ip_in_network()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if the IPv4 or IPv6 address is contained within the referenced network
    IF NOT EXISTS (
        SELECT 1
        FROM ip_networks
        WHERE id = NEW.network_id
        AND NEW.address << network
    ) THEN
        RAISE EXCEPTION 'IP address % is not contained in ip_networks id % (or the id does not exist)', NEW.address, NEW.network_id;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- Create trigger
CREATE TRIGGER check_ip_in_network
BEFORE INSERT OR UPDATE ON service_ip_addresses
FOR EACH ROW
EXECUTE FUNCTION validate_ip_in_network();

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT non_empty CHECK(length(name)>=1 AND length(name)<=63),
    superuser boolean DEFAULT false NOT NULL
);

CREATE TABLE auth_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    org_id uuid REFERENCES orgs(id),
    role_id uuid NOT NULL REFERENCES roles(id),
    auth_provider_id uuid NOT NULL references auth_providers(id),
    name text UNIQUE NOT NULL CONSTRAINT non_empty CHECK(length(name)>=1 AND length(name)<=63)
);

CREATE TABLE gorilla_session_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    key_order bigint UNIQUE NOT NULL,
    auth_key bytea NOT NULL CONSTRAINT auth_length CHECK(length(auth_key)=32 OR length(auth_key)=64),
    enc_key bytea CONSTRAINT enc_length CHECK(length(enc_key)=16 OR length(enc_key)=24 OR length(enc_key)=32),
    UNIQUE(auth_key, enc_key)
);

CREATE TABLE auth_provider_keycloak (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    user_id uuid UNIQUE NOT NULL REFERENCES users(id),
    subject uuid UNIQUE NOT NULL
);

CREATE TABLE gorilla_csrf_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    active boolean NOT NULL,
    auth_key bytea UNIQUE NOT NULL CONSTRAINT auth_length CHECK(length(auth_key)=32)
);
CREATE UNIQUE INDEX gorilla_csrf_keys_active_only_1_true ON gorilla_csrf_keys (active) WHERE active;

CREATE TABLE user_argon2keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    user_id uuid UNIQUE NOT NULL REFERENCES users(id),
    key bytea NOT NULL CONSTRAINT non_empty_key CHECK(length(key)>0),
    salt bytea NOT NULL CONSTRAINT non_empty_salt CHECK(length(salt)>0),
    time bigint NOT NULL CONSTRAINT uint32_time CHECK(time >= 0 AND time <= 4294967295),
    memory bigint NOT NULL CONSTRAINT uint32_memory CHECK(memory >= 0 AND memory <= 4294967295),
    threads bigint NOT NULL CONSTRAINT uint8_threads CHECK(threads >= 0 AND threads <= 255),
    tag_size bigint NOT NULL CONSTRAINT uint32_tag_sizie CHECK(tag_size >= 0 AND tag_size <= 4294967295)
);

CREATE TABLE service_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    service_id uuid NOT NULL REFERENCES services(id),
    version bigint NOT NULL,
    active boolean DEFAULT false NOT NULL,
    UNIQUE(service_id, version)
);
-- https://dba.stackexchange.com/questions/197562/constraint-one-boolean-row-is-true-all-other-rows-false
CREATE UNIQUE INDEX service_versions_active_only_1_true ON service_versions (service_id, active) WHERE active;

CREATE TABLE service_domains (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid NOT NULL REFERENCES service_versions(id),
    domain text NOT NULL CONSTRAINT non_empty CHECK(length(domain)>=1 AND length(domain)<=253),
    UNIQUE(service_version_id, domain)
);

CREATE TABLE service_origins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid NOT NULL REFERENCES service_versions(id),
    host text NOT NULL CONSTRAINT non_empty CHECK(length(host)>=1 AND length(host)<=253),
    port integer NOT NULL CONSTRAINT port_range CHECK(port >= 1 AND port <= 65535),
    tls boolean DEFAULT true NOT NULL,
    UNIQUE(service_version_id, host, port)
);

CREATE TABLE service_vcl_recv (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid NOT NULL REFERENCES service_versions(id),
    content text NOT NULL CONSTRAINT non_empty CHECK(length(content)>0),
    UNIQUE(service_version_id, content)
);
