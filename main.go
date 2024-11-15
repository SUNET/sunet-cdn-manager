package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/rs/zerolog"

	"github.com/SUNET/sunet-cdn-manager/cmd"
)

// version set at build time with -ldflags="-X main.version=v0.0.1"
var version = "undefined"

func main() {
	defaultHostname := "sunet-cdn-manager-hostname-unknown"
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to get hostname, using '%s'", defaultHostname)
		hostname = defaultHostname
	}

	// Logger used for all output
	logger := zerolog.New(os.Stderr).With().
		Str("service", "sunet-cdn-manager").
		Str("hostname", hostname).
		Str("server_version", version).
		Str("go_version", runtime.Version()).
		Timestamp().Logger()

	cmd.Execute(logger)
}
