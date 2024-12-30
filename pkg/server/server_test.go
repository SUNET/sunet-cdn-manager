package server

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/stapelberg/postgrestest"
	"golang.org/x/crypto/argon2"
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

func populateTestData(dbPool *pgxpool.Pool) error {
	// use static UUIDs to get known contents for testing
	testData := []string{
		// Organizations
		"INSERT INTO organizations (id, name) VALUES ('00000002-0000-0000-0000-000000000001', 'org1')",
		"INSERT INTO organizations (id, name) VALUES ('00000002-0000-0000-0000-000000000002', 'org2')",
		"INSERT INTO organizations (id, name) VALUES ('00000002-0000-0000-0000-000000000003', 'org3')",

		// Services
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000001', id, 'org1-service1' FROM organizations WHERE name='org1'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000002', id, 'org1-service2' FROM organizations WHERE name='org1'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000003', id, 'org1-service3' FROM organizations WHERE name='org1'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000004', id, 'org2-service1' FROM organizations WHERE name='org2'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000005', id, 'org2-service2' FROM organizations WHERE name='org2'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000006', id, 'org2-service3' FROM organizations WHERE name='org2'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000007', id, 'org3-service1' FROM organizations WHERE name='org3'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000008', id, 'org3-service2' FROM organizations WHERE name='org3'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000009', id, 'org3-service3' FROM organizations WHERE name='org3'",

		// Service versions
		// org1, last version is active
		"UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1'",
		"INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000001', id, version_counter FROM services WHERE name='org1-service1'",

		"UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1'",
		"INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000002', id, version_counter FROM services WHERE name='org1-service1'",

		"UPDATE services SET version_counter = version_counter + 1 WHERE name='org1-service1'",
		"INSERT INTO service_versions (id, service_id, version, active) SELECT '00000004-0000-0000-0000-000000000003', id, version_counter, TRUE FROM services WHERE name='org1-service1'",

		// org2, second version is active
		"UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1'",
		"INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000004', id, version_counter FROM services WHERE name='org2-service1'",

		"UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1'",
		"INSERT INTO service_versions (id, service_id, version, active) SELECT '00000004-0000-0000-0000-000000000005', id, version_counter, TRUE FROM services WHERE name='org2-service1'",

		"UPDATE services SET version_counter = version_counter + 1 WHERE name='org2-service1'",
		"INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000006', id, version_counter FROM services WHERE name='org2-service1'",

		// org3, no version is active
		"UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1'",
		"INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000007', id, version_counter FROM services WHERE name='org3-service1'",

		"UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1'",
		"INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000008', id, version_counter FROM services WHERE name='org3-service1'",

		"UPDATE services SET version_counter = version_counter + 1 WHERE name='org3-service1'",
		"INSERT INTO service_versions (id, service_id, version) SELECT '00000004-0000-0000-0000-000000000009', id, version_counter FROM services WHERE name='org3-service1'",

		// Roles
		"INSERT INTO roles (id, name, superuser) VALUES ('00000005-0000-0000-0000-000000000001', 'admin', TRUE)",
		"INSERT INTO roles (id, name) VALUES ('00000005-0000-0000-0000-000000000002', 'customer')",

		// Domains
		"INSERT INTO service_domains (id, service_version_id, domain) VALUES ('00000008-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', 'www.example.se')",
		"INSERT INTO service_domains (id, service_version_id, domain) VALUES ('00000008-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', 'www.example.com')",

		// Origins
		"INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', 'srv2.example.com', 80, false)",
		"INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', 'srv1.example.se', 443, true)",
	}

	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		for _, sql := range testData {
			_, err := tx.Exec(context.Background(), sql)
			if err != nil {
				return err
			}
		}
		localUsers := []struct {
			name      string
			password  string
			orgName   string
			role      string
			superuser bool
			id        string
		}{
			{
				name:     "admin",
				password: "adminpass1",
				role:     "admin",
				id:       "00000006-0000-0000-0000-000000000001",
			},
			{
				name:     "username1",
				password: "password1",
				role:     "customer",
				orgName:  "org1",
				id:       "00000006-0000-0000-0000-000000000002",
			},
			{
				name:     "username2",
				password: "password2",
				role:     "customer",
				orgName:  "org2",
				id:       "00000006-0000-0000-0000-000000000003",
			},
			{
				name:     "username3-no-org",
				password: "password3",
				role:     "customer",
				id:       "00000006-0000-0000-0000-000000000004",
			},
		}

		for _, localUser := range localUsers {
			var userID pgtype.UUID
			err := userID.Scan(localUser.id)
			if err != nil {
				return err
			}

			var orgID *pgtype.UUID // may be nil

			if localUser.orgName != "" {
				err := tx.QueryRow(context.Background(), "SELECT id FROM organizations WHERE name=$1", localUser.orgName).Scan(&orgID)
				if err != nil {
					return err
				}
			}

			_, err = tx.Exec(context.Background(), "INSERT INTO users (id, org_id, name, role_id) SELECT $1, $2, $3, id FROM roles WHERE name=$4", userID, orgID, localUser.name, localUser.role)
			if err != nil {
				return err
			}

			// Generate 16 byte (128 bit) salt as
			// recommended for argon2 in RFC 9106
			salt := make([]byte, 16)
			_, err = rand.Read(salt)
			if err != nil {
				return err
			}

			timeSize := uint32(1)
			memorySize := uint32(64 * 1024)
			threads := uint8(4)
			tagSize := uint32(32)

			key := argon2.IDKey([]byte(localUser.password), salt, timeSize, memorySize, threads, tagSize)
			_, err = tx.Exec(context.Background(), "INSERT INTO user_argon2keys (user_id, key, salt, time, memory, threads, tag_size) VALUES ($1, $2, $3, $4, $5, $6, $7)", userID, key, salt, timeSize, memorySize, threads, tagSize)
			if err != nil {
				return err
			}
		}

		vclRcvs := []struct {
			id               string
			file             string
			serviceVersionID string
		}{
			{
				id:               "00000007-0000-0000-0000-000000000001",
				serviceVersionID: "00000004-0000-0000-0000-000000000003",
				file:             "testdata/vcl/vcl_recv/content1.vcl",
			},
		}

		for _, vclRcv := range vclRcvs {
			var vclID, serviceVersionID pgtype.UUID
			err := vclID.Scan(vclRcv.id)
			if err != nil {
				return err
			}

			err = serviceVersionID.Scan(vclRcv.serviceVersionID)
			if err != nil {
				return err
			}

			contentBytes, err := os.ReadFile(vclRcv.file)
			if err != nil {
				return err
			}

			_, err = tx.Exec(context.Background(), "INSERT INTO service_vcl_recv (id, service_version_id, content) VALUES($1, $2, $3)", vclID, serviceVersionID, contentBytes)
			if err != nil {
				return err
			}
		}

		gorillaAuthKey, err := generateRandomKey(32)
		if err != nil {
			return fmt.Errorf("unable to create random user session key: %w", err)
		}

		_, err = insertGorillaSessionKey(tx, gorillaAuthKey, nil)
		if err != nil {
			return fmt.Errorf("unable to INSERT user session key: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func prepareServer() (*httptest.Server, *pgxpool.Pool, error) {
	pgurl, err := pgt.CreateDatabase(context.Background())
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		return nil, nil, err
	}

	fmt.Println(pgConfig.ConnString())

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return nil, nil, errors.New("unable to create database pool")
	}

	err = migrations.Up(logger, pgConfig)
	if err != nil {
		return nil, nil, err
	}

	err = populateTestData(dbPool)
	if err != nil {
		return nil, nil, err
	}

	cookieStore, err := getSessionStore(logger, dbPool)
	if err != nil {
		return nil, nil, err
	}

	router := newChiRouter(logger, dbPool, cookieStore)

	err = setupHumaAPI(router, dbPool)
	if err != nil {
		return nil, dbPool, err
	}

	ts := httptest.NewServer(router)

	return ts, dbPool, nil
}

func TestServerInit(t *testing.T) {
	pgurl, err := pgt.CreateDatabase(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(pgConfig.ConnString())

	u, err := Init(logger, pgConfig)
	if err != nil {
		t.Fatal(err)
	}

	expectedUsername := "admin"
	expectedPasswordLength := 30

	if u.Name != expectedUsername {
		t.Fatalf("expected initial user '%s', got: '%s'", expectedUsername, u.Name)
	}

	if len(u.Password) != expectedPasswordLength {
		t.Fatalf("expected initial user password length %d, got: %d", expectedPasswordLength, len(u.Password))
	}
}

func TestSessionKeyHandlingNoEnc(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	// Try inserting additional session keys with nil encryptionKey
	numAdded := 2
	for i := 0; i < numAdded; i++ {
		gorillaAuthKey, err := generateRandomKey(32)
		if err != nil {
			t.Fatal(err)
		}
		err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			_, err = insertGorillaSessionKey(tx, gorillaAuthKey, nil)
			if err != nil {
				return err
			}

			return nil
		})
	}

	rows, err := dbPool.Query(context.Background(), "SELECT id, ts, key_order, auth_key, enc_key FROM gorilla_session_keys")
	if err != nil {
		t.Fatal(err)
	}

	var keyOrderMax int64

	var id pgtype.UUID
	var timestamp time.Time
	var keyOrder int64
	var authKey, encKey []byte
	_, err = pgx.ForEachRow(rows, []any{&id, &timestamp, &keyOrder, &authKey, &encKey}, func() error {
		fmt.Printf("id: %s, ts: %s, key_order: %d, auth_key len: %d, enc_key len: %d\n", id, timestamp, keyOrder, len(authKey), len(encKey))

		if authKey == nil {
			t.Fatal("authKey is nil")
		}

		if encKey != nil {
			t.Fatal("encKey is not nil")
		}

		if keyOrder > keyOrderMax {
			keyOrderMax = keyOrder
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The initial key starts at 0 so we expect the highest key_order counter to be the same as the number of addtional keys added here
	if keyOrderMax != int64(numAdded) {
		t.Fatalf("unexpected key_order max, have: %d, want: %d", keyOrderMax, numAdded)
	}
}

func TestSessionKeyHandlingWithEnc(t *testing.T) {
	ts, dbPool, err := prepareServer()
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	// Try inserting additional session keys with nil encryptionKey
	numAdded := 2
	for i := 0; i < numAdded; i++ {
		gorillaAuthKey, err := generateRandomKey(32)
		if err != nil {
			t.Fatal(err)
		}

		gorillaEncKey, err := generateRandomKey(32)
		if err != nil {
			t.Fatal(err)
		}
		err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			_, err = insertGorillaSessionKey(tx, gorillaAuthKey, gorillaEncKey)
			if err != nil {
				return err
			}

			return nil
		})
	}

	rows, err := dbPool.Query(context.Background(), "SELECT id, ts, key_order, auth_key, enc_key FROM gorilla_session_keys")
	if err != nil {
		t.Fatal(err)
	}

	var keyOrderMax int64

	var id pgtype.UUID
	var timestamp time.Time
	var keyOrder int64
	var authKey, encKey []byte
	_, err = pgx.ForEachRow(rows, []any{&id, &timestamp, &keyOrder, &authKey, &encKey}, func() error {
		fmt.Printf("id: %s, ts: %s, key_order: %d, auth_key len: %d, enc_key len: %d\n", id, timestamp, keyOrder, len(authKey), len(encKey))

		if authKey == nil {
			t.Fatal("authKey is nil")
		}

		if encKey == nil {
			t.Fatal("encKey is nil")
		}

		if keyOrder > keyOrderMax {
			keyOrderMax = keyOrder
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The initial key starts at 0 so we expect the highest key_order counter to be the same as the number of addtional keys added here
	if keyOrderMax != int64(numAdded) {
		t.Fatalf("unexpected key_order max, have: %d, want: %d", keyOrderMax, numAdded)
	}
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
