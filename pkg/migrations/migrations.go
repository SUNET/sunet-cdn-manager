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

func Up(ctx context.Context, logger zerolog.Logger, pgConfig *pgxpool.Config) error {
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
		return fmt.Errorf("unable to goose.SetDialect()")
	}

	db := stdlib.OpenDBFromPool(dbPool)

	if err := goose.Up(db, "files"); err != nil {
		return err
	}

	if err := db.Close(); err != nil {
		return err
	}

	return nil
}
