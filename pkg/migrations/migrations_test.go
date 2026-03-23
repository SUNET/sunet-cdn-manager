package migrations

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/stapelberg/postgrestest"
)

var (
	pgt    *postgrestest.Server
	logger zerolog.Logger
)

func TestMain(m *testing.M) {
	var err error
	pgt, err = postgrestest.Start(context.Background(), postgrestest.WithSQLDriver("pgx"))
	if err != nil {
		panic(err)
	}
	defer pgt.Cleanup()

	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	logger = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()

	m.Run()
}

func prepareDatabase() (*pgxpool.Config, error) {
	pgurl, err := pgt.CreateDatabase(context.Background())
	if err != nil {
		return nil, err
	}

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		return nil, errors.New("unable to parse PostgreSQL config string")
	}

	fmt.Println(pgConfig.ConnString())

	return pgConfig, nil
}

func TestUpMigrations(t *testing.T) {
	pgConfig, err := prepareDatabase()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		description string
	}{
		{
			description: "run migration",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			err := Up(context.Background(), logger, pgConfig)
			if err != nil {
				t.Fatalf("up call failed: %s", err)
			}
		})
	}
}
