.PHONY: all check generate test run-dev

all: lint test

generate:
	go generate ./...

lint: generate
	gofumpt -l -w .
	go vet ./...
	staticcheck ./...
	gosec ./...
	golangci-lint run
	govulncheck ./...

test:
	go test -race ./...

run-dev:
	go run . --config sunet-cdn-manager-dev.toml server --dev --shutdown-delay 0 --disable-acme --tls-cert-file local-dev/generated/manager/certs/manager.sunet-cdn.localhost.crt --tls-key-file local-dev/generated/manager/certs/manager.sunet-cdn.localhost.key
