package server

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	_ "github.com/SUNET/sunet-cdn-manager/pkg/server/testdata/migrations" // needed to run .go migration files
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

	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
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

	fmt.Println(pgConfig.ConnString())

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return nil, nil, errors.New("unable to create database pool")
	}

	db := stdlib.OpenDBFromPool(dbPool)

	if err := goose.Up(db, "testdata/migrations"); err != nil {
		return nil, dbPool, err
	}

	router := newChiRouter(logger, dbPool)

	err = setupHumaAPI(router, dbPool)
	if err != nil {
		return nil, dbPool, err
	}

	ts := httptest.NewServer(router)

	return ts, dbPool, nil
}

func TestGetUsers(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		expectedStatus int
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "successful organization request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed organization request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/users", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s: GET users unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetUser(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		nameOrID       string
		expectedStatus int
	}{
		{
			description:    "successful superuser request with ID",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "00000006-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "username1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful user request for itself with ID",
			username:       "username1",
			password:       "password1",
			nameOrID:       "00000006-0000-0000-0000-000000000002",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful user request for itself with name",
			username:       "username1",
			password:       "password1",
			nameOrID:       "username1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed user request, bad password",
			username:       "username1",
			password:       "badpassword1",
			nameOrID:       "00000006-0000-0000-0000-000000000001",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed lookup of another user with ID",
			username:       "username2",
			password:       "password2",
			nameOrID:       "00000006-0000-0000-0000-000000000001",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed lookup of another user with name",
			username:       "username2",
			password:       "password2",
			nameOrID:       "username1",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, test := range tests {
		ident, err := parseNameOrID(test.nameOrID)
		if err != nil {
			t.Fatal(err)
		}

		if !ident.isValid() {
			t.Fatal("service ID or name is not valid")
		}

		req, err := http.NewRequest("GET", ts.URL+"/api/v1/users/"+ident.String(), nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s: GET users/%s unexpected status code: %d (%s)", test.description, ident.String(), resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostUsers(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		expectedStatus int
		addedUser      string
		addedPassword  string
		roleIDorName   string
		orgIDorName    string
	}{
		{
			description:    "successful superuser request with IDs",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedUser:      "admin-created-user-1",
			addedPassword:  "admin-created-password-1",
			roleIDorName:   "00000005-0000-0000-0000-000000000002",
			orgIDorName:    "00000002-0000-0000-0000-000000000001",
		},
		{
			description:    "successful superuser request with names",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedUser:      "admin-created-user-2",
			addedPassword:  "admin-created-password-2",
			roleIDorName:   "customer",
			orgIDorName:    "org1",
		},
		{
			description:    "successful superuser request with name right at limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedUser:      strings.Repeat("a", 63),
			addedPassword:  "admin-created-password-2",
			roleIDorName:   "customer",
			orgIDorName:    "org1",
		},
		{
			description:    "failed superuser request with name above limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			addedUser:      strings.Repeat("a", 64),
			addedPassword:  "admin-created-password-2",
			roleIDorName:   "customer",
			orgIDorName:    "org1",
		},
		{
			description:    "failed superuser request with name below limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			addedUser:      "",
			addedPassword:  "admin-created-password-2",
			roleIDorName:   "customer",
			orgIDorName:    "org1",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
			addedUser:      "user-created-user-1",
			addedPassword:  "user-created-password-1",
			roleIDorName:   "customer",
			orgIDorName:    "org1",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newUser := struct {
			Name         string `json:"name"`
			Password     string `json:"password"`
			Role         string `json:"role"`
			Organization string `json:"organization"`
		}{
			Name:         test.addedUser,
			Password:     test.addedPassword,
			Organization: test.orgIDorName,
			Role:         test.roleIDorName,
		}

		b, err := json.Marshal(newUser)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/users", r)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("Content-Type", "application/json")

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("POST users unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetOrganizations(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		expectedStatus int
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "successful organization request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed organization request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/organizations", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("GET organizations unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetOrganization(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		nameOrID       string
		expectedStatus int
	}{
		{
			description:    "successful superuser request with ID",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful organization request with ID",
			username:       "username1",
			password:       "password1",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful organization request with name",
			username:       "username1",
			password:       "password1",
			nameOrID:       "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed organization request, bad password",
			username:       "username1",
			password:       "badpassword1",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed lookup of organization you do not belong to with ID",
			username:       "username2",
			password:       "password2",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed lookup of organization you do not belong to with name",
			username:       "username2",
			password:       "password2",
			nameOrID:       "org1",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, test := range tests {
		ident, err := parseNameOrID(test.nameOrID)
		if err != nil {
			t.Fatal(err)
		}

		if !ident.isValid() {
			t.Fatal("service ID or name is not valid")
		}

		req, err := http.NewRequest("GET", ts.URL+"/api/v1/organizations/"+ident.String(), nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("GET organizations/%s unexpected status code: %d (%s)", ident.String(), resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostOrganizations(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description       string
		username          string
		password          string
		expectedStatus    int
		addedOrganization string
	}{
		{
			description:       "successful superuser request",
			username:          "admin",
			password:          "adminpass1",
			expectedStatus:    http.StatusCreated,
			addedOrganization: "adminorg",
		},
		{
			description:       "successful superuser request with max length name",
			username:          "admin",
			password:          "adminpass1",
			expectedStatus:    http.StatusCreated,
			addedOrganization: strings.Repeat("a", 63),
		},
		{
			description:       "failed superuser request with too short name",
			username:          "admin",
			password:          "adminpass1",
			expectedStatus:    http.StatusUnprocessableEntity,
			addedOrganization: "",
		},
		{
			description:       "failed superuser request with too long name",
			username:          "admin",
			password:          "adminpass1",
			expectedStatus:    http.StatusUnprocessableEntity,
			addedOrganization: strings.Repeat("a", 64),
		},
		{
			description:       "failed non-superuser request",
			username:          "username1",
			password:          "password1",
			addedOrganization: "username1org",
			expectedStatus:    http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newOrganization := struct {
			Name string `json:"name"`
		}{
			Name: test.addedOrganization,
		}

		b, err := json.Marshal(newOrganization)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/organizations", r)
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("Content-Type", "application/json")

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("POST organizations unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetServices(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		expectedStatus int
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful organization request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed organization request, bad auth",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request (not assigned to organization)",
			username:       "username3-no-org",
			password:       "password3",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/services", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("GET services unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetService(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		nameOrID       string
		expectedStatus int
	}{
		{
			description:    "successful superuser request with ID",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "00000003-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "org1-service1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful organization request with ID",
			username:       "username1",
			password:       "password1",
			nameOrID:       "00000003-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful organization request with name",
			username:       "username1",
			password:       "password1",
			nameOrID:       "org1-service1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed organization request for service belonging to other organization with ID",
			username:       "username2",
			password:       "password2",
			nameOrID:       "00000003-0000-0000-0000-000000000001",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed organization request for service belonging to other organization with name",
			username:       "username2",
			password:       "password2",
			nameOrID:       "org1-service1",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed organization request not assigned to organization with ID",
			username:       "username3-no-org",
			password:       "password3",
			nameOrID:       "00000003-0000-0000-0000-000000000001",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed organization request not assigned to organization with name",
			username:       "username3-no-org",
			password:       "password3",
			nameOrID:       "org1-service1",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, test := range tests {
		if test.nameOrID == "" {
			t.Fatal("user needs service name or ID for service test")
		}

		ident, err := parseNameOrID(test.nameOrID)
		if err != nil {
			t.Fatal(err)
		}

		if !ident.isValid() {
			t.Fatal("service name or ID is not valid")
		}

		req, err := http.NewRequest("GET", ts.URL+"/api/v1/services/"+ident.String(), nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("GET service by ID unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostServices(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		expectedStatus int
		newService     string
		organization   string
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			newService:     "new-admin-service",
			organization:   "org1",
		},
		{
			description:    "successful superuser request with name right at limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			newService:     strings.Repeat("a", 63),
			organization:   "org1",
		},
		{
			description:    "failed superuser request with name above limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     strings.Repeat("a", 64),
			organization:   "org1",
		},
		{
			description:    "failed superuser request with name below limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "",
			organization:   "org1",
		},
		{
			description:    "failed superuser request without organization",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new-admin-service",
		},
		{
			description:    "successful organization request (organization based on auth)",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusCreated,
			newService:     "new-username1-service1",
		},
		{
			description:    "failed organization request with duplciate service name",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusBadRequest,
			newService:     "new-username1-service1",
		},
		{
			description:    "successful organization request with organization matching auth",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusCreated,
			newService:     "new-username1-service2",
			organization:   "org1",
		},
		{
			description:    "failed organization request with organization not matching auth",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusForbidden,
			newService:     "new-username1-service3",
			organization:   "org2",
		},
		{
			description:    "failed organization request not assigned to organization",
			username:       "username3-no-org",
			password:       "password3",
			newService:     "new-username3-service1",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newService := struct {
			Name         string  `json:"name"`
			Organization *string `json:"organization,omitempty"`
		}{
			Name: test.newService,
		}

		if test.organization != "" {
			newService.Organization = &test.organization
		}

		b, err := json.Marshal(newService)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/services", r)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s: POST services unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s: %s", test.description, err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetServiceVersions(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		expectedStatus int
		newService     string
		organization   string
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful organization request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed organization request not assigned to organization",
			username:       "username3-no-org",
			password:       "password3",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/service-versions", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s: GET service versions unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s: %s", test.description, err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostServiceVersion(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		expectedStatus int
		newService     string
		organization   string
		serviceID      string
		domains        []string
		origins        []origin
		active         bool
	}{
		{
			description:  "successful superuser request",
			username:     "admin",
			password:     "adminpass1",
			serviceID:    "00000003-0000-0000-0000-000000000001",
			organization: "org1",
			domains:      []string{"example.com", "example.se"},
			origins: []origin{
				{
					Host: "srv1.example.com",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "srv2.example.com",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusCreated,
			active:         true,
		},
		{
			description:  "failed superuser request with too many domains",
			username:     "admin",
			password:     "adminpass1",
			serviceID:    "00000003-0000-0000-0000-000000000001",
			organization: "org1",
			domains:      []string{"1.com", "2.com", "3.com", "4.com", "5.com", "6.com", "7.com", "8.com", "9.com", "10.com", "11.com"},
			origins: []origin{
				{
					Host: "srv1.example.com",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "srv2.example.com",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
		},
		{
			description:  "failed superuser request, too long Host in origin list",
			username:     "admin",
			password:     "adminpass1",
			serviceID:    "00000003-0000-0000-0000-000000000001",
			organization: "org1",
			domains:      []string{"example.com", "example.se"},
			origins: []origin{
				{
					Host: strings.Repeat("a", 254),
					Port: 443,
					TLS:  true,
				},
				{
					Host: "srv2.example.com",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
		},
		{
			description:  "failed superuser request, too long domain in domains list",
			username:     "admin",
			password:     "adminpass1",
			serviceID:    "00000003-0000-0000-0000-000000000001",
			organization: "org1",
			domains:      []string{strings.Repeat("a", 254), "example.se"},
			origins: []origin{
				{
					Host: "srv1.example.com",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "srv2.example.com",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
		},
		{
			description:  "failed superuser request with invalid uuid (too long)",
			username:     "admin",
			password:     "adminpass1",
			serviceID:    "00000003-0000-0000-0000-0000000000001",
			organization: "org1",
			domains:      []string{"example.com", "example.se"},
			origins: []origin{
				{
					Host: "srv1.example.com",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "srv2.example.com",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
		},
		{
			description:  "failed superuser request with invalid uuid (too short)",
			username:     "admin",
			password:     "adminpass1",
			serviceID:    "00000003-0000-0000-0000-00000000001",
			organization: "org1",
			domains:      []string{"example.com", "example.se"},
			origins: []origin{
				{
					Host: "srv1.example.com",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "srv2.example.com",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
		},
		{
			description:  "failed superuser request with invalid uuid (not a UUID)",
			username:     "admin",
			password:     "adminpass1",
			serviceID:    "junk",
			organization: "org1",
			domains:      []string{"example.com", "example.se"},
			origins: []origin{
				{
					Host: "srv1.example.com",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "srv2.example.com",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
		},
		{
			description: "successful organization request",
			username:    "username1",
			password:    "password1",
			serviceID:   "00000003-0000-0000-0000-000000000001",
			domains:     []string{"example.com", "example.se"},
			origins: []origin{
				{
					Host: "srv1.example.com",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "srv2.example.com",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusCreated,
			active:         true,
		},
		{
			description: "failed organization request not assigned to organization",
			username:    "username3-no-org",
			password:    "password3",
			serviceID:   "00000003-0000-0000-0000-000000000001",
			domains:     []string{"example.com", "example.se"},
			origins: []origin{
				{
					Host: "srv1.example.com",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "srv2.example.com",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusForbidden,
			active:         true,
		},
	}

	for _, test := range tests {
		newServiceVersion := struct {
			ServiceID    string   `json:"service_id"`
			Organization string   `json:"organization,omitempty"`
			Domains      []string `json:"domains"`
			Origins      []origin `json:"origins"`
		}{
			ServiceID:    test.serviceID,
			Organization: test.organization,
			Domains:      test.domains,
			Origins:      test.origins,
		}

		b, err := json.Marshal(newServiceVersion)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(string(b))

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/service-versions", r)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s: GET service versions unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("%s: %s", test.description, err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetVcls(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description    string
		username       string
		password       string
		expectedStatus int
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "successful organization request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed organization request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/vcls", nil)
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(test.username, test.password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != test.expectedStatus {
			r, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s: GET vcls unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)

		if resp.StatusCode == http.StatusOK {
			s := []struct {
				Content string
			}{}

			err = json.Unmarshal(jsonData, &s)
			if err != nil {
				t.Fatal(err)
			}

			for _, content := range s {
				fmt.Println(content.Content)
			}
		}
	}
}
