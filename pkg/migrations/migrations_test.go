package migrations

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/testhelpers"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	pgContainer *postgres.PostgresContainer
	logger      zerolog.Logger
)

func TestMain(m *testing.M) {
	var err error

	ctx := context.Background()

	pgContainer, err = testhelpers.CreatePostgreSQLContainer(ctx)
	if err != nil {
		panic(err)
	}
	defer func() {
		err := testcontainers.TerminateContainer(pgContainer)
		if err != nil {
			panic(err)
		}
	}()

	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	logger = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()

	m.Run()
}

func prepareDatabase(ctx context.Context, t *testing.T) (*pgxpool.Config, error) {
	pgurl, err := testhelpers.CreateDatabase(ctx, t, pgContainer)
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
	ctx := context.Background()
	pgConfig, err := prepareDatabase(ctx, t)
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
