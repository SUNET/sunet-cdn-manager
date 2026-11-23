.PHONY: all check generate test run-dev

all: lint test

generate:
	go generate ./...

lint: generate
	gofumpt -l -w .
	go vet ./...
	go fix ./...
	staticcheck ./...
	gosec ./...
	golangci-lint run
	govulncheck ./...

# pkg/server's testcontainers-backed suite takes about 10 minutes, which is
# the go test default timeout, so raise it.
test:
	go test -race -timeout 30m ./...

run-dev:
	go run . --config sunet-cdn-manager-dev.toml init --init-password-file admin.password
	go run . --config sunet-cdn-manager-dev.toml server --dev --shutdown-delay 0 --disable-acme --tls-cert-file local-dev/generated/manager/certs/manager.sunet-cdn.localhost.crt --tls-key-file local-dev/generated/manager/certs/manager.sunet-cdn.localhost.key
