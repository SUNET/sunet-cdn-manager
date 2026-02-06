# sunet-cdn-manager
This is the SUNET CDN manager server which serves an API and UI for
configuring the CDN service.

The configuration is picked up by
[sunet-cdn-agent](https://github.com/SUNET/sunet-cdn-agent) running on actual
`l4lb` or `cache` machines.

## Development
### Updating the web console
The project uses [templ](https://templ.guide) for generating HTML.
* Install the templ CLI tool, see https://templ.guide/quick-start/installation
* Edit `pkg/components/console.templ`
* There exists `go:generate` comments in the component code, so just do `go generate ./...` to run `templ`
* Commit all the updated files.

### Running tests
Running tests require a local PostgreSQL 15 or newer. The need for
at least version 15 is because the database setup expects the "Constrain
ordinary users to user-private schemas" schema usage pattern as described at
https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATTERNS

If running macOS the following can be done prior to running tests:
```
brew install postgresql@18
export PATH="/opt/homebrew/opt/postgresql@18/bin:$PATH"
```

Some tests utilize [Testcontainers for Go](https://golang.testcontainers.org)
(specifically for running
[sunet-vcl-validator](https://github.com/SUNET/sunet-vcl-validator) and keycloak). This
means you also need to be able to run containers for these tests to work.

### Setting up a local dev enviroment
#### Initialize infrastructure
Generate SATOSA config and certs:
```
local-dev/satosa/setup.sh
```

Generate Keycloak JSON and certs:
```
local-dev/keycloak/init-files.sh
```

Start only database and keycloak to begin with (we need to configure keycloak and supply its metadata to SATOSA before SATOSA can start):
```
docker compose -p sunet-cdn-manager -f local-dev/docker-compose.yml up db keycloak
```

Initialize the sunet-cdn-manager realm and SATOSA IdP setup in keycloak:
```
local-dev/keycloak/setup.sh
```

This will output the OIDC Client ID and secret at the end, e.g.:
```
server OIDC client_id: sunet-cdn-manager-server
server OIDC client_secret: some-secret-string
```

#### Configure sunet-cdn-manager
Create a config file for connecting insecurely to the local PostgreSQL database:
```
sed -e 's/"verify-full"/"disable"/' -e 's/"password"/"cdn"/' sunet-cdn-manager.toml.sample > sunet-cdn-manager-dev.toml
```

Generate certs so you do not need to deal with ACME:
```
local-dev/setup.sh
```

Take the client_secret that was outputted above and insert it into
`sunet-cdn-manager-dev.toml`:
```
[oidc]
[...]
client_secret = "some-secret-string"
[...]
```

#### Start complete infrastructure
Now you can start the full Docker compose file, stop the running db+keycloak command and start again:
```
docker compose -p sunet-cdn-manager -f local-dev/docker-compose.yml up
```

#### SAML QA
For testing federated logins to `sunet-cdn-manager` a SAML connection to SWAMID is
needed. The login flow looks like this:
```
sunet-cdn-manager -> OIDC -> Keycloak -> SAML -> SATOSA -> SAML -> SWAMID
```

To test this locally you can upload the generated SATOSA metadata to
SWAMID QA.

Get metadata suitable for SWAMID (requires that you have `xmlstarlet` installed):
```
MAILTO=your-email@example.se local-dev/satosa/satosa-to-swamid.sh
```

Now you will get a prepared metadata file you can upload to
https://metadata.qa.swamid.se, for `Select Organization for entity` choose
`Sunet` and click `Connect`.

#### Setup sunet-cdn-manager
Initialize the sunet-cdn-manager database by supplying an init secret used for the superuser password:
```
pwgen -s 30 1 > admin.password
go run . --config sunet-cdn-manager-dev.toml init --init-password-file admin.password
```

Start the server in development mode (disables TLS validation etc) and skip
ACME so we can test things locally:
```
make run-dev
```

Use the generated password to fill in some sample entities:
```
admin_password=$(cat admin.password) ./local-dev/add-sample-entities.sh
```

At this point you can log in to the system by browsing to
https://manager.sunet-cdn.localhost:8444 choosing "Login with Keycloak" and
using user `testuser` and password `testuser`.

After logging in as `testuser` for the first time assign it to the sample organization:
```
admin_password=some-secret-string
curl -k -s -i -u admin:$admin_password -X PUT -d @local-dev/sample-json/set-org.json -H "content-type: application/json" https://manager.sunet-cdn.localhost:8444/api/v1/users/testuser
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
* `govulncheck ./...` (see [govulncheck](https://go.dev/doc/tutorial/govulncheck))
