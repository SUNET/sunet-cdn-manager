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
			description:    "successful customer request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed customer request, bad password",
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
			nameOrID:       "1",
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
			nameOrID:       "2",
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
			nameOrID:       "1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed lookup of another user with ID",
			username:       "username2",
			password:       "password2",
			nameOrID:       "1",
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
			t.Fatalf("%s: GET users/%s unexpected status code: %d (%s)", ident.String(), test.description, resp.StatusCode, string(r))
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
		description      string
		username         string
		password         string
		expectedStatus   int
		addedUser        string
		addedPassword    string
		roleIDorName     string
		customerIDorName string
	}{
		{
			description:      "successful superuser request with IDs",
			username:         "admin",
			password:         "adminpass1",
			expectedStatus:   http.StatusCreated,
			addedUser:        "admin-created-user-1",
			addedPassword:    "admin-created-password-1",
			roleIDorName:     "2",
			customerIDorName: "2",
		},
		{
			description:      "successful superuser request with names",
			username:         "admin",
			password:         "adminpass1",
			expectedStatus:   http.StatusCreated,
			addedUser:        "admin-created-user-2",
			addedPassword:    "admin-created-password-2",
			roleIDorName:     "customer",
			customerIDorName: "customer1",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
			addedUser:      "user-created-user-1",
			addedPassword:  "user-created-password-1",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newUser := struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			Role     string `json:"role"`
			Customer string `json:"customer"`
		}{
			Name:     test.addedUser,
			Password: test.addedPassword,
			Customer: test.customerIDorName,
			Role:     test.roleIDorName,
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

func TestGetCustomers(t *testing.T) {
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
			description:    "successful customer request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed customer request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/customers", nil)
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
			t.Fatalf("GET customers unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetCustomer(t *testing.T) {
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
			nameOrID:       "1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "customer1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful customer request with ID",
			username:       "username1",
			password:       "password1",
			nameOrID:       "1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful customer request with name",
			username:       "username1",
			password:       "password1",
			nameOrID:       "customer1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed customer request, bad password",
			username:       "username1",
			password:       "badpassword1",
			nameOrID:       "1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed lookup of customer you do not belong to with ID",
			username:       "username2",
			password:       "password2",
			nameOrID:       "1",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed lookup of customer you do not belong to with name",
			username:       "username2",
			password:       "password2",
			nameOrID:       "customer1",
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

		req, err := http.NewRequest("GET", ts.URL+"/api/v1/customers/"+ident.String(), nil)
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
			t.Fatalf("GET customers/%s unexpected status code: %d (%s)", ident.String(), resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
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

	tests := []struct {
		description    string
		username       string
		password       string
		expectedStatus int
		addedCustomer  string
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedCustomer:  "admincust",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
			addedCustomer:  "username1cust",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newCustomer := struct {
			Name string `json:"name"`
		}{
			Name: test.addedCustomer,
		}

		b, err := json.Marshal(newCustomer)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/customers", r)
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
			t.Fatalf("POST customers unexpected status code: %d (%s)", resp.StatusCode, string(r))
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
			description:    "successful customer request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed customer request, bad auth",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request (not assigned to customer)",
			username:       "username3-no-customer",
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
			t.Fatalf("GET customers unexpected status code: %d (%s)", resp.StatusCode, string(r))
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
			nameOrID:       "1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "customer1-service1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful customer request with ID",
			username:       "username1",
			password:       "password1",
			nameOrID:       "1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful customer request with name",
			username:       "username1",
			password:       "password1",
			nameOrID:       "customer1-service1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed customer request for service belonging to other customer with ID",
			username:       "username2",
			password:       "password2",
			nameOrID:       "1",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed customer request for service belonging to other customer with name",
			username:       "username2",
			password:       "password2",
			nameOrID:       "customer1-service1",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed customer request not assigned to customer with ID",
			username:       "username3-no-customer",
			password:       "password3",
			nameOrID:       "1",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed customer request not assigned to customer with name",
			username:       "username3-no-customer",
			password:       "password3",
			nameOrID:       "customer1-service1",
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
		customer       string
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			newService:     "new-admin-service",
			customer:       "customer1",
		},
		{
			description:    "failed superuser request without customer",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new-admin-service",
		},
		{
			description:    "successful customer request (customer based on auth)",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusCreated,
			newService:     "new-username1-service1",
		},
		{
			description:    "failed customer request with duplciate service name",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusBadRequest,
			newService:     "new-username1-service1",
		},
		{
			description:    "successful customer request with customer matching auth",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusCreated,
			newService:     "new-username1-service2",
			customer:       "customer1",
		},
		{
			description:    "failed customer request with customer not matching auth",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusForbidden,
			newService:     "new-username1-service3",
			customer:       "customer2",
		},
		{
			description:    "failed customer request not assigned to customer",
			username:       "username3-no-customer",
			password:       "password3",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newService := struct {
			Name     string  `json:"name"`
			Customer *string `json:"customer,omitempty"`
		}{
			Name: test.newService,
		}

		if test.customer != "" {
			newService.Customer = &test.customer
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
		customer       string
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful customer request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed customer request not assigned to customer",
			username:       "username3-no-customer",
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
