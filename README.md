# sunet-cdn-manager
This is the SUNET CDN manager server which serves an API and UI for
configuring the CDN service.

## Development
### Running tests
Running tests require a local PostgreSQL 15 or newer. The need for
at least version 15 is because the database setup expects the "Constrain
ordinary users to user-private schemas" schema usage pattern as described at
https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATTERNS

If running macOS the following can be done prior to running tests:
```
brew install postgresql@17
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"
```

Some tests utilize [Testcontainers for Go](https://golang.testcontainers.org)
(specifically for running
[sunet-vcl-validator](https://github.com/SUNET/sunet-vcl-validator)). This
means you also need to be able to run containers for these tests to work.

### Setting up a local dev enviroment
Start database, keycloak and sunet-vcl-validator:
```
docker compose -p sunet-cdn-manager -f local-dev/docker-compose.yml up
```

Initialize the sunet-cdn-manager realm in keycloak:
```
local-dev/keycloak/setup.sh
```

Create a config file for connecting insecurely to the local PostgreSQL database:
```
sed -e 's/"verify-full"/"disable"/' -e 's/"password"/"cdn"/' sunet-cdn-manager.toml.sample > sunet-cdn-manager-dev.toml
```

Initialize the sunet-cdn-manager database (this will print out a superuser username and password):
```
go run . --config sunet-cdn-manager-dev.toml init
```

Start the server in development mode (disables cookie requirements for HTTPS):
```
go run . --config sunet-cdn-manager-dev.toml server --dev
```

Add some networks for allocating service addresses from:
```
curl -i -u admin:$admin_password -X POST -d @local-dev/sample-json/add-ipv4-network.json -H "content-type: application/json" http://localhost:8081/api/v1/ip-networks
curl -i -u admin:$admin_password -X POST -d @local-dev/sample-json/add-ipv6-network.json -H "content-type: application/json" http://localhost:8081/api/v1/ip-networks
```

Create an organisation:
```
curl -i -u admin:$admin_password -X POST -d @local-dev/sample-json/create-org.json -H "content-type: application/json" http://localhost:8081/api/v1/orgs
```

Assign a domain to the org (this will make the manager start looking for a verification TXT record for that name):
```
curl -i -u admin:$admin_password -X POST -d @local-dev/sample-json/add-domain.json -H "content-type: application/json" 'http://localhost:8081/api/v1/domains?org=testorg'
```

Given that a user called `testuser` exists (either a local user created via API or automatically created via keycloak login), assign it to the the org:
```
curl -s -i -u admin:$admin_password -X PUT -d @local-dev/sample-json/set-org.json -H "content-type: application/json" http://localhost:8081/api/v1/users/testuser
```

Create a local "node-user-1" user with the "node" role used by nodes fetching config:
```
curl -i -u admin:$admin_password -X POST -d @local-dev/sample-json/add-node-user.json -H "content-type: application/json" http://localhost:8081/api/v1/users
```

Set a password for the user with "node" role:
```
curl -i -u admin:$admin_password -X PUT -d @local-dev/sample-json/set-node-user-password.json -H "content-type: application/json" http://localhost:8081/api/v1/users/node-user-1/local-password
```

Add a cache node to the system:
```
curl -i -u admin:$admin_password -X POST -d @local-dev/sample-json/add-cache-node.json -H "content-type: application/json" http://localhost:8081/api/v1/cache-nodes
```

A cache node will be added in maintenance mode by default (can be overriden in JSON on creation), to disable maintenance mode:
```
curl -i -s -u admin:$admin_password -X PUT -d @local-dev/sample-json/disable-maintenance.json -H "content-type: application/json" http://localhost:8081/api/v1/cache-nodes/example-name-for-cache-node/maintenance
```

### Formatting and linting
When working with this code at least the following tools are expected to be
run at the top level directory prior to commiting:

* `gofumpt -l -w .` (see [gofumpt](https://github.com/mvdan/gofumpt))
* `go vet ./...`
* `staticcheck ./...` (see [staticcheck](https://staticcheck.io))
* `gosec ./...` (see [gosec](https://github.com/securego/gosec))
* `golangci-lint run` (see [golangci-lint](https://golangci-lint.run))
* `go test -race ./...`
