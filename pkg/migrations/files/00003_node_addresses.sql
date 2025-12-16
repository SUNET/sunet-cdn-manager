-- +goose up

-- Make it possible for l4lb and cache nodes to have multiple addresses.
-- Currently only needed for l4lb but might as well treat cache nodes the same.
CREATE TABLE cache_node_addresses (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    node_id uuid NOT NULL REFERENCES cache_nodes(id),
    address inet UNIQUE CONSTRAINT valid_ipv4_or_ipv6_address CHECK((family(address) = 4 AND masklen(address) = 32) OR (family(address) = 6 AND masklen(address) = 128))
);

INSERT INTO cache_node_addresses (node_id, address) SELECT id, ipv4_address FROM cache_nodes ORDER BY ipv4_address;
INSERT INTO cache_node_addresses (node_id, address) SELECT id, ipv6_address FROM cache_nodes ORDER BY ipv6_address;

ALTER TABLE cache_nodes DROP COLUMN ipv4_address, DROP COLUMN ipv6_address;

CREATE TABLE l4lb_node_addresses (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    time_created timestamptz NOT NULL DEFAULT now(),
    node_id uuid NOT NULL REFERENCES l4lb_nodes(id),
    address inet UNIQUE CONSTRAINT valid_ipv4_or_ipv6_address CHECK((family(address) = 4 AND masklen(address) = 32) OR (family(address) = 6 AND masklen(address) = 128))
);

INSERT INTO l4lb_node_addresses (node_id, address) SELECT id, ipv4_address FROM l4lb_nodes ORDER BY ipv4_address;
INSERT INTO l4lb_node_addresses (node_id, address) SELECT id, ipv6_address FROM l4lb_nodes ORDER BY ipv6_address;

ALTER TABLE l4lb_nodes DROP COLUMN ipv4_address, DROP COLUMN ipv6_address;
