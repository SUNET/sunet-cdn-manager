package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

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

	// Use short filenames for Caller() info, based on
	// https://github.com/rs/zerolog?tab=readme-ov-file#add-file-and-line-number-to-log
	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}

	// Logger used for all output
	logger := zerolog.New(os.Stderr).Level(zerolog.InfoLevel).With().
		Str("service", "sunet-cdn-manager").
		Str("hostname", hostname).
		Str("server_version", version).
		Str("go_version", runtime.Version()).
		Timestamp().Caller().Logger()

	cmd.Execute(logger)
}
