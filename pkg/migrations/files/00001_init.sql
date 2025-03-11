-- +goose up
CREATE TABLE orgs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT non_empty_dns_label CHECK(length(name)>=1 AND length(name)<=63 AND name ~ '^[a-z]([-a-z0-9]*[a-z0-9])?$'),
    service_quota bigint NOT NULL DEFAULT 1,
    domain_quota bigint NOT NULL DEFAULT 5
);

CREATE TABLE services (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    org_id uuid NOT NULL REFERENCES orgs(id),
    name text NOT NULL CONSTRAINT non_empty_dns_label CHECK(length(name)>=1 AND length(name)<=63 AND name ~ '^[a-z]([-a-z0-9]*[a-z0-9])?$'),
    version_counter bigint DEFAULT 0 NOT NULL,
    uid_range int8range NOT NULL CHECK(uid_range <@ int8range(1000010000, NULL)),
    UNIQUE(org_id, name),
    EXCLUDE USING GIST (uid_range WITH &&)
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
    service_id uuid REFERENCES services(id) ON DELETE CASCADE,
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
    name text UNIQUE NOT NULL CONSTRAINT non_empty_dns_label_name CHECK(length(name)>=1 AND length(name)<=63 AND name ~ '^[a-z]([-a-z0-9]*[a-z0-9])?$'),
    superuser boolean DEFAULT false NOT NULL
);

CREATE TABLE auth_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT non_empty_dns_label_name CHECK(length(name)>=1 AND length(name)<=63 AND name ~ '^[a-z]([-a-z0-9]*[a-z0-9])?$')
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    org_id uuid REFERENCES orgs(id),
    role_id uuid NOT NULL REFERENCES roles(id),
    auth_provider_id uuid NOT NULL references auth_providers(id),
    name text UNIQUE NOT NULL CONSTRAINT non_empty_name CHECK(length(name)>=1 AND length(name)<=63)
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
    service_id uuid NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    version bigint NOT NULL,
    active boolean DEFAULT false NOT NULL,
    sni_hostname text CONSTRAINT non_empty_sni_hostname CHECK(length(sni_hostname)>=1 AND length(sni_hostname)<=253),
    UNIQUE(service_id, version)
);
-- https://dba.stackexchange.com/questions/197562/constraint-one-boolean-row-is-true-all-other-rows-false
CREATE UNIQUE INDEX service_versions_active_only_1_true ON service_versions (service_id, active) WHERE active;

CREATE TABLE domains (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    time_created timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT non_empty_name CHECK(length(name)>=1 AND length(name)<=253),
    verified boolean DEFAULT false NOT NULL,
    verification_token text NOT NULL
);

CREATE TABLE service_domains (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid NOT NULL REFERENCES service_versions(id) ON DELETE CASCADE,
    domain_id uuid NOT NULL REFERENCES domains(id),
    UNIQUE(service_version_id, domain_id)
);

CREATE TABLE service_origins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid NOT NULL REFERENCES service_versions(id) ON DELETE CASCADE,
    host text NOT NULL CONSTRAINT non_empty_host CHECK(length(host)>=1 AND length(host)<=253),
    port integer NOT NULL CONSTRAINT port_range CHECK(port >= 1 AND port <= 65535),
    tls boolean DEFAULT true NOT NULL,
    UNIQUE(service_version_id, host, port)
);

-- The available service_vcl_* columns are based on steps for "Client side" and "Backend Side":
-- https://varnish-cache.org/docs/trunk/reference/vcl-step.html
CREATE TABLE service_vcls (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid UNIQUE NOT NULL REFERENCES service_versions(id) ON DELETE CASCADE,
    vcl_recv text CONSTRAINT vcl_recv_non_empty_if_not_null CHECK(length(vcl_recv)>0),
    vcl_pipe text CONSTRAINT vcl_pipe_non_empty_if_not_null CHECK(length(vcl_pipe)>0),
    vcl_pass text CONSTRAINT vcl_pass_non_empty_if_not_null CHECK(length(vcl_pass)>0),
    vcl_hash text CONSTRAINT vcl_hash_non_empty_if_not_null CHECK(length(vcl_hash)>0),
    vcl_purge text CONSTRAINT vcl_purge_non_empty_if_not_null CHECK(length(vcl_purge)>0),
    vcl_miss text CONSTRAINT vcl_miss_non_empty_if_not_null CHECK(length(vcl_miss)>0),
    vcl_hit text CONSTRAINT vcl_hit_non_empty_if_not_null CHECK(length(vcl_hit)>0),
    vcl_deliver text CONSTRAINT vcl_deliver_non_empty_if_not_null CHECK(length(vcl_deliver)>0),
    vcl_synth text CONSTRAINT vcl_synth_non_empty_if_not_null CHECK(length(vcl_synth)>0),
    vcl_backend_fetch text CONSTRAINT vcl_backend_fetch_non_empty_if_not_null CHECK(length(vcl_backend_fetch)>0),
    vcl_backend_response text CONSTRAINT vcl_backend_response_non_empty_if_not_null CHECK(length(vcl_backend_response)>0),
    vcl_backend_error text CONSTRAINT vcl_backend_error_non_empty_if_not_null CHECK(length(vcl_backend_error)>0)
);
