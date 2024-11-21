# sunet-cdn-manager
This is the SUNET CDN manager server which serves an API and UI for
configuring the CDN service.

## Development
Running tests require a local PostgreSQL 15 or newer. The need for
at least version 15 is because the database setup expects the "Constrain
ordinary users to user-private schemas" schema usage pattern as described at
https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATTERNS

If running macOS the following can be done prior to running tests:
```
brew install postgresql@17
export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"
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
