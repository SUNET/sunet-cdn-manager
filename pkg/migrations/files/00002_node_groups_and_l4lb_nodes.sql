-- +goose up

-- Make it possible to assign l4lb and cache nodes to node groups. This
-- information can be used by e.g. l4lb to only send traffic to cache nodes
-- belonging to the same group as well as making cache nodes aware of what l4lb
-- nodes should be allowed to send them tunneled traffic.
CREATE TABLE node_groups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT valid_dns_label CHECK(is_valid_dns_label(name)),
    description text NOT NULL
);

ALTER TABLE cache_nodes ADD COLUMN node_group_id uuid REFERENCES node_groups(id);

CREATE TABLE l4lb_nodes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    name text UNIQUE NOT NULL CONSTRAINT valid_dns_label CHECK(is_valid_dns_label(name)),
    description text NOT NULL,
    maintenance bool NOT NULL DEFAULT true,
    ipv4_address inet UNIQUE CONSTRAINT valid_ipv4_address CHECK(family(ipv4_address) = 4 AND masklen(ipv4_address) = 32),
    ipv6_address inet UNIQUE CONSTRAINT valid_ipv6_address CHECK(family(ipv6_address) = 6 AND masklen(ipv6_address) = 128),
    node_group_id uuid REFERENCES node_groups(id)
);
