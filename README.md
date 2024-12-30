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

### Setting up a local dev enviroment
Start database and keycloak:
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

Start the server:
```
go run . --config sunet-cdn-manager-dev.toml server
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
