#!/usr/bin/env bash
set -eu

# Make it so we can run the script from anywhere
cd "$(dirname "$0")"

# Add some networks for allocating service addresses from:
curl -k -i -u admin:$admin_password -X POST -d @sample-json/add-ipv4-network.json -H "content-type: application/json" https://manager.sunet-cdn.localhost:8444/api/v1/ip-networks
curl -k -i -u admin:$admin_password -X POST -d @sample-json/add-ipv6-network.json -H "content-type: application/json" https://manager.sunet-cdn.localhost:8444/api/v1/ip-networks

# Create an organization:
curl -k -i -u admin:$admin_password -X POST -d @sample-json/create-org.json -H "content-type: application/json" https://manager.sunet-cdn.localhost:8444/api/v1/orgs

# Assign a domain to the org (this will make the manager start looking for a verification TXT record for that name):
curl -k -i -u admin:$admin_password -X POST -d @sample-json/add-domain.json -H "content-type: application/json" 'https://manager.sunet-cdn.localhost:8444/api/v1/domains?org=testorg'

# Create a service in the org
curl -k -i -u admin:$admin_password -X POST -d @sample-json/add-service.json -H "content-type: application/json" 'https://manager.sunet-cdn.localhost:8444/api/v1/services'

# Create a local "node-user-1" user with the "node" role used by nodes fetching config:
curl -k -i -u admin:$admin_password -X POST -d @sample-json/add-node-user.json -H "content-type: application/json" https://manager.sunet-cdn.localhost:8444/api/v1/users

# Set a password for the user with "node" role:
curl -k -i -u admin:$admin_password -X PUT -d @sample-json/set-node-user-password.json -H "content-type: application/json" https://manager.sunet-cdn.localhost:8444/api/v1/users/node-user-1/local-password

# Add a cache node to the system:
curl -k -i -u admin:$admin_password -X POST -d @sample-json/add-cache-node.json -H "content-type: application/json" https://manager.sunet-cdn.localhost:8444/api/v1/cache-nodes

# A cache node will be added in maintenance mode by default (can be overriden in JSON on creation), to disable maintenance mode:
curl -k -i -s -u admin:$admin_password -X PUT -d @sample-json/disable-maintenance.json -H "content-type: application/json" https://manager.sunet-cdn.localhost:8444/api/v1/cache-nodes/example-name-for-cache-node/maintenance

# Add additional origin group, this is used to be able to select different backend groups from varnish VCL
curl -k -i -s -u admin:$admin_password -X POST -d @sample-json/add-origin-group.json -H "content-type: application/json" 'https://manager.sunet-cdn.localhost:8444/api/v1/services/service1/origin-groups?org=testorg'
