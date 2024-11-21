package server

import (
	"context"
	"embed"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/rs/zerolog"
	"github.com/stapelberg/postgrestest"
)

//go:embed testdata/migrations/*.sql
var embedMigrations embed.FS

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

	logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		panic(err)
	}

	m.Run()
}

func TestGetCustomers(t *testing.T) {
	pgurl, err := pgt.CreateDatabase(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		t.Fatal("unable to parse PostgreSQL config string")
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		t.Fatal("unable to create database pool")
	}
	defer dbPool.Close()

	db := stdlib.OpenDBFromPool(dbPool)

	if err := goose.Up(db, "testdata/migrations"); err != nil {
		t.Fatal(err)
	}

	mux := newMux(ctx, logger, dbPool)

	ts := httptest.NewServer(mux)
	defer ts.Close()

	res, err := http.Get(ts.URL + "/api/v1/customers")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	jsonData, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s\n", jsonData)
}
