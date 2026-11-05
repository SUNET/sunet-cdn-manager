package migrations

import (
	"context"
	"embed"
	"fmt"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/managerutils"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog"
)

// Make zerolog usable as a goose logger, currently the "message" will include
// a trailing '\n' but rather than doing extra work here hopefully those can be
// cleaned up upstream: https://github.com/pressly/goose/pull/878
type gooseLogger struct {
	logger zerolog.Logger
}

func (gl gooseLogger) Fatalf(format string, v ...any) {
	gl.logger.Fatal().Msgf(format, v...)
}

func (gl gooseLogger) Printf(format string, v ...any) {
	gl.logger.Info().Msgf(format, v...)
}

//go:embed files/*.sql
var embedMigrations embed.FS

// ServiceVersionForeignKeys are the foreign keys from a service version's
// rows to its service_versions row. Migration 00021 made them DEFERRABLE
// INITIALLY IMMEDIATE so that the manager can insert those rows first and
// the service_versions row, with the hash of their content, last.
var ServiceVersionForeignKeys = []string{
	"service_domains_service_version_id_fkey",
	"service_origin_groups_service_version_id_fkey",
	"service_origins_service_version_id_fkey",
	"service_vcls_service_version_id_fkey",
}

func Up(ctx context.Context, logger zerolog.Logger, pgConfig *pgxpool.Config) error {
	return upTo(ctx, logger, pgConfig, goose.MaxVersion)
}

// upTo applies migrations up to and including the given version. Only used
// by tests that need to seed data mid-migration-sequence; production
// always migrates to the latest version via Up.
func upTo(ctx context.Context, logger zerolog.Logger, pgConfig *pgxpool.Config, version int64) error {
	gl := gooseLogger{logger: logger}
	goose.SetLogger(gl)
	goose.SetBaseFS(embedMigrations)

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return fmt.Errorf("unable to create database pool: %w", err)
	}
	defer dbPool.Close()

	logger.Info().Msg("checking DB connection for migrations")
	err = managerutils.RetryWithBackoff(
		ctx,
		logger,
		time.Second*1,
		time.Second*30,
		10,
		"ping DB for migration",
		dbPool.Ping,
	)
	if err != nil {
		return fmt.Errorf("pinging database connection for migrations failed: %w", err)
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("unable to goose.SetDialect(): %w", err)
	}

	db := stdlib.OpenDBFromPool(dbPool)

	if err := goose.UpToContext(ctx, db, "files", version); err != nil {
		return err
	}

	if err := db.Close(); err != nil {
		return err
	}

	return nil
}
