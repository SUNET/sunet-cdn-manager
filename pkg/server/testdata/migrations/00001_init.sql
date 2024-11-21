-- +goose up
CREATE TABLE customers (
    id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name text NOT NULL
);

CREATE TABLE services (
    id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    customer_id bigint NOT NULL REFERENCES customers(id),
    name text NOT NULL,
    version_counter BIGINT DEFAULT 0 NOT NULL,
    UNIQUE(customer_id, name)
);

CREATE TABLE service_versions (
    id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    service_id bigint NOT NULL REFERENCES services(id),
    version bigint NOT NULL,
    active boolean,
    UNIQUE(service_id, version),
    UNIQUE(service_id, active)
);

CREATE TABLE service_domains (
    id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    service_version_id bigint NOT NULL REFERENCES service_versions(id),
    domain text NOT NULL,
    UNIQUE(service_version_id, domain)
);

CREATE TABLE service_origins (
    id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    service_version_id bigint NOT NULL REFERENCES service_versions(id),
    origin text NOT NULL,
    UNIQUE(service_version_id, origin)
);
-- +goose down
DROP TABLE service_domains;
DROP TABLE service_origins;
DROP TABLE service_versions;
DROP TABLE services;
DROP TABLE customers;
