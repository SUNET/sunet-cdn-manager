package migrations

import (
	"context"
	"embed"
	"fmt"

	"github.com/SUNET/sunet-cdn-manager/pkg/server"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed files/*.sql
var embedMigrations embed.FS

func Up() error {
	goose.SetBaseFS(embedMigrations)

	config, err := server.GetConfig()
	if err != nil {
		return fmt.Errorf("unable to get server config: %w", err)
	}

	pgConfig, err := config.PGConfig()
	if err != nil {
		return fmt.Errorf("unable to create pg config: %w", err)
	}

	dbPool, err := pgxpool.NewWithConfig(context.Background(), pgConfig)
	if err != nil {
		return fmt.Errorf("unable to create database pool: %w", err)
	}
	defer dbPool.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("unable to goose.SetDialect()")
	}

	db := stdlib.OpenDBFromPool(dbPool)

	if err := goose.Up(db, "files"); err != nil {
		return err
	}

	return nil
}
