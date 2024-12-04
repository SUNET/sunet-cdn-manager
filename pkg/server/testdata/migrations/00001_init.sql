-- +goose up
CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT non_empty CHECK(length(name)>0)
);

CREATE TABLE roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT non_empty CHECK(length(name)>0),
    superuser boolean DEFAULT false NOT NULL
);

CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    org_id uuid REFERENCES organizations(id),
    role_id uuid NOT NULL REFERENCES roles(id),
    name text UNIQUE NOT NULL CONSTRAINT non_empty CHECK(length(name)>0)
);

CREATE TABLE user_argon2keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    user_id uuid NOT NULL REFERENCES users(id),
    key bytea NOT NULL CONSTRAINT non_empty_key CHECK(length(key)>0),
    salt bytea NOT NULL CONSTRAINT non_empty_salt CHECK(length(salt)>0),
    time bigint NOT NULL CONSTRAINT uint32_time CHECK(time >= 0 AND time <= 4294967295),
    memory bigint NOT NULL CONSTRAINT uint32_memory CHECK(memory >= 0 AND memory <= 4294967295),
    threads bigint NOT NULL CONSTRAINT uiint8_threads CHECK(threads >= 0 AND threads <= 255),
    tag_size bigint NOT NULL CONSTRAINT uint32_tag_sizie CHECK(tag_size >= 0 AND tag_size <= 4294967295),
    UNIQUE(user_id, key, salt)
);

CREATE TABLE services (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    org_id uuid NOT NULL REFERENCES organizations(id),
    name text NOT NULL CONSTRAINT non_empty CHECK(length(name)>0),
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
    domain text NOT NULL CONSTRAINT non_empty CHECK(length(domain)>0),
    UNIQUE(service_version_id, domain)
);

CREATE TABLE service_origins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ts timestamptz NOT NULL DEFAULT now(),
    service_version_id uuid NOT NULL REFERENCES service_versions(id),
    origin text NOT NULL CONSTRAINT non_empty CHECK(length(origin)>0),
    UNIQUE(service_version_id, origin)
);
-- +goose down
DROP TABLE service_domains;
DROP TABLE service_origins;
DROP TABLE service_versions;
DROP TABLE services;
DROP TABLE user_argon2keys;
DROP TABLE users;
DROP TABLE roles;
DROP TABLE organizations;
