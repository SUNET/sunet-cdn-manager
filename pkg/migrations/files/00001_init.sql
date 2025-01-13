-- +goose up
CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT non_empty CHECK(length(name)>=1 AND length(name)<=63)
);

CREATE TABLE ipv4_networks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    network cidr UNIQUE NOT NULL CONSTRAINT v4 CHECK(family(network) = 4)
);

CREATE TABLE ipv6_networks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    network cidr UNIQUE NOT NULL CONSTRAINT v6 CHECK(family(network) = 6)
);

CREATE TABLE org_ipv4_addresses (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    network_id uuid NOT NULL REFERENCES ipv4_networks(id),
    org_id uuid REFERENCES organizations(id),
    address inet UNIQUE NOT NULL CONSTRAINT valid_v4 CHECK(family(address) = 4 AND address != network(address) AND address != broadcast(address))
);

CREATE TABLE org_ipv6_addresses (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    network_id uuid NOT NULL REFERENCES ipv6_networks(id),
    org_id uuid REFERENCES organizations(id),
    address inet UNIQUE NOT NULL CONSTRAINT valid_v6 CHECK(family(address) = 6 AND address != network(address) AND address != broadcast(address))
);

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT non_empty CHECK(length(name)>=1 AND length(name)<=63),
    superuser boolean DEFAULT false NOT NULL
);

CREATE TABLE auth_providers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    org_id uuid REFERENCES organizations(id),
    role_id uuid NOT NULL REFERENCES roles(id),
    auth_provider_id uuid NOT NULL references auth_providers(id),
    name text UNIQUE NOT NULL CONSTRAINT non_empty CHECK(length(name)>=1 AND length(name)<=63)
);

CREATE TABLE gorilla_session_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    key_order bigint UNIQUE NOT NULL,
    auth_key bytea NOT NULL CONSTRAINT auth_length CHECK(length(auth_key)=32 OR length(auth_key)=64),
    enc_key bytea CONSTRAINT enc_length CHECK(length(enc_key)=16 OR length(enc_key)=24 OR length(enc_key)=32),
    UNIQUE(auth_key, enc_key)
);

CREATE TABLE auth_provider_keycloak (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    user_id uuid UNIQUE NOT NULL REFERENCES users(id),
    subject uuid UNIQUE NOT NULL
);

CREATE TABLE gorilla_csrf_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    active boolean UNIQUE,
    auth_key bytea UNIQUE NOT NULL CONSTRAINT auth_length CHECK(length(auth_key)=32)
);

CREATE TABLE user_argon2keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    user_id uuid NOT NULL REFERENCES users(id),
    key bytea NOT NULL CONSTRAINT non_empty_key CHECK(length(key)>0),
    salt bytea NOT NULL CONSTRAINT non_empty_salt CHECK(length(salt)>0),
    time bigint NOT NULL CONSTRAINT uint32_time CHECK(time >= 0 AND time <= 4294967295),
    memory bigint NOT NULL CONSTRAINT uint32_memory CHECK(memory >= 0 AND memory <= 4294967295),
    threads bigint NOT NULL CONSTRAINT uint8_threads CHECK(threads >= 0 AND threads <= 255),
    tag_size bigint NOT NULL CONSTRAINT uint32_tag_sizie CHECK(tag_size >= 0 AND tag_size <= 4294967295),
    UNIQUE(user_id, key, salt)
);

CREATE TABLE services (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    org_id uuid NOT NULL REFERENCES organizations(id),
    name text NOT NULL CONSTRAINT non_empty CHECK(length(name)>=1 AND length(name)<=63),
    version_counter BIGINT DEFAULT 0 NOT NULL,
    UNIQUE(org_id, name)
);

CREATE TABLE service_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    service_id uuid NOT NULL REFERENCES services(id),
    version bigint NOT NULL,
    active boolean,
    UNIQUE(service_id, version),
    UNIQUE(service_id, active)
);

CREATE TABLE service_domains (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid NOT NULL REFERENCES service_versions(id),
    domain text NOT NULL CONSTRAINT non_empty CHECK(length(domain)>=1 AND length(domain)<=253),
    UNIQUE(service_version_id, domain)
);

CREATE TABLE service_origins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid NOT NULL REFERENCES service_versions(id),
    host text NOT NULL CONSTRAINT non_empty CHECK(length(host)>=1 AND length(host)<=253),
    port integer NOT NULL CONSTRAINT port_range CHECK(port >= 1 AND port <= 65535),
    tls boolean DEFAULT true NOT NULL,
    UNIQUE(service_version_id, host, port)
);

CREATE TABLE service_vcl_recv (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid NOT NULL REFERENCES service_versions(id),
    content text NOT NULL CONSTRAINT non_empty CHECK(length(content)>0),
    UNIQUE(service_version_id, content)
);
