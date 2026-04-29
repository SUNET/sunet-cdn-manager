package testhelpers

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func CreatePostgreSQLContainer(ctx context.Context) (*postgres.PostgresContainer, error) {
	// https://golang.testcontainers.org/modules/postgres/
	pgContainer, err := postgres.Run(ctx,
		"postgres:18.3-trixie",
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		postgres.WithSQLDriver("pgx"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, err
	}

	return pgContainer, nil
}

func CreateDatabase(ctx context.Context, t *testing.T, pgContainer *postgres.PostgresContainer) (string, error) {
	t.Helper()

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return "", err
	}

	pgConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return "", err
	}
	pgConfig.MaxConns = 1

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return "", fmt.Errorf("unable to create database pool for database creation: %w", err)
	}
	defer dbPool.Close()

	name := fmt.Sprintf("test_%016x", mrand.Uint64()) // #nosec G404 -- no need for cryptographically secure randomness for database name

	quotedName := pgx.Identifier{name}.Sanitize()
	if _, err := dbPool.Exec(ctx, "CREATE DATABASE "+quotedName); err != nil {
		return "", err
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		dbPool, err := pgxpool.NewWithConfig(cleanupCtx, pgConfig)
		if err != nil {
			t.Errorf("failed to create dbPool for test database cleanup: %q: %v", name, err)
			return
		}
		defer dbPool.Close()

		if _, err := dbPool.Exec(cleanupCtx, "DROP DATABASE "+quotedName); err != nil {
			t.Errorf("failed to DROP test database %q: %v", name, err)
		}
	})

	// Create a new DSN pointing to the new database
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	return u.String(), nil
}
