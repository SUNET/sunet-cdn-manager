package server

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/DataDog/jsonapi"
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

	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	logger = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()

	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		logger.Fatal().Err(err).Msg("unable to goose.SetDialect()")
	}

	m.Run()
}

func prepareServer() (*httptest.Server, *pgxpool.Pool, error) {
	pgurl, err := pgt.CreateDatabase(context.Background())
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		return nil, nil, errors.New("unable to parse PostgreSQL config string")
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return nil, nil, errors.New("unable to create database pool")
	}

	db := stdlib.OpenDBFromPool(dbPool)

	if err := goose.Up(db, "testdata/migrations"); err != nil {
		return nil, dbPool, err
	}

	mux := newMux(logger, dbPool)

	ts := httptest.NewServer(mux)

	return ts, dbPool, nil
}

func TestGetCustomers(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/customers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET customers unexpected status code: %d", resp.StatusCode)
	}

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s\n", jsonData)
}

func TestPostCustomers(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	newCustomer := customer{
		Name: "customer4",
	}

	b, err := jsonapi.Marshal(newCustomer, jsonapi.MarshalClientMode())
	if err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(b)

	resp, err := http.Post(ts.URL+"/api/v1/customers", "application/vnd.api+json", r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		r, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("POST customers unexpected status code: %d (%s)", resp.StatusCode, string(r))
	}

	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%s\n", jsonData)
}
