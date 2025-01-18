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
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/config"
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

func populateTestData(dbPool *pgxpool.Pool, encryptedSessionKey bool) error {
	// use static UUIDs to get known contents for testing
	testData := []string{
		// Organizations
		"INSERT INTO orgs (id, name) VALUES ('00000002-0000-0000-0000-000000000001', 'org1')",
		"INSERT INTO orgs (id, name) VALUES ('00000002-0000-0000-0000-000000000002', 'org2')",
		"INSERT INTO orgs (id, name) VALUES ('00000002-0000-0000-0000-000000000003', 'org3')",

		// Services
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000001', id, 'org1-service1' FROM orgs WHERE name='org1'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000002', id, 'org1-service2' FROM orgs WHERE name='org1'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000003', id, 'org1-service3' FROM orgs WHERE name='org1'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000004', id, 'org2-service1' FROM orgs WHERE name='org2'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000005', id, 'org2-service2' FROM orgs WHERE name='org2'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000006', id, 'org2-service3' FROM orgs WHERE name='org2'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000007', id, 'org3-service1' FROM orgs WHERE name='org3'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000008', id, 'org3-service2' FROM orgs WHERE name='org3'",
		"INSERT INTO services (id, org_id, name) SELECT '00000003-0000-0000-0000-000000000009', id, 'org3-service3' FROM orgs WHERE name='org3'",

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
		"INSERT INTO roles (id, name) VALUES ('00000005-0000-0000-0000-000000000002', 'user')",

		// Domains
		"INSERT INTO service_domains (id, service_version_id, domain) VALUES ('00000008-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', 'www.example.se')",
		"INSERT INTO service_domains (id, service_version_id, domain) VALUES ('00000008-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', 'www.example.com')",

		// Origins
		"INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', 'srv2.example.com', 80, false)",
		"INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', 'srv1.example.se', 443, true)",

		// Auth providers
		"INSERT INTO auth_providers (id, name) VALUES ('00000010-0000-0000-0000-000000000001', 'local')",
		"INSERT INTO auth_providers (id, name) VALUES ('00000010-0000-0000-0000-000000000002', 'keycloak')",

		// IPv4 networks
		"INSERT INTO ipv4_networks (id, network) VALUES ('00000011-0000-0000-0000-000000000001', '192.0.2.0/24')",
		"INSERT INTO ipv4_networks (id, network) VALUES ('00000011-0000-0000-0000-000000000002', '198.51.100.0/24')",

		// IPv6 networks
		"INSERT INTO ipv6_networks (id, network) VALUES ('00000012-0000-0000-0000-000000000001', '2001:db8:0::/48')",
		"INSERT INTO ipv6_networks (id, network) VALUES ('00000012-0000-0000-0000-000000000002', '3fff::/20')",

		// Allocate addresses from networks to orgs
		// org1
		"INSERT INTO org_ipv4_addresses (id, network_id, org_id, address) VALUES ('00000013-0000-0000-0000-000000000001', '00000011-0000-0000-0000-000000000001', '00000002-0000-0000-0000-000000000001', '192.0.2.1')",
		"INSERT INTO org_ipv6_addresses (id, network_id, org_id, address) VALUES ('00000013-0000-0000-0000-000000000002', '00000012-0000-0000-0000-000000000001', '00000002-0000-0000-0000-000000000001', '2001:db8:0::1')",

		// Users
		// No org, local user
		"INSERT INTO users (id, role_id, auth_provider_id, name) VALUES ('00000014-0000-0000-0000-000000000001', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000001', 'patch-user-1')",
	}

	err := pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
		for _, sql := range testData {
			_, err := tx.Exec(context.Background(), sql)
			if err != nil {
				return err
			}
		}
		localUsers := []struct {
			name         string
			password     string
			orgName      string
			role         string
			superuser    bool
			id           string
			authProvider string
		}{
			{
				name:         "admin",
				password:     "adminpass1",
				role:         "admin",
				id:           "00000006-0000-0000-0000-000000000001",
				authProvider: "local",
			},
			{
				name:         "username1",
				password:     "password1",
				role:         "user",
				orgName:      "org1",
				id:           "00000006-0000-0000-0000-000000000002",
				authProvider: "local",
			},
			{
				name:         "username2",
				password:     "password2",
				role:         "user",
				orgName:      "org2",
				id:           "00000006-0000-0000-0000-000000000003",
				authProvider: "local",
			},
			{
				name:         "username3-no-org",
				password:     "password3",
				role:         "user",
				id:           "00000006-0000-0000-0000-000000000004",
				authProvider: "local",
			},
		}

		for _, localUser := range localUsers {
			var userID pgtype.UUID
			err := userID.Scan(localUser.id)
			if err != nil {
				return err
			}

			var orgID *pgtype.UUID // may be nil
			var authProviderID pgtype.UUID

			if localUser.orgName != "" {
				err := tx.QueryRow(context.Background(), "SELECT id FROM orgs WHERE name=$1", localUser.orgName).Scan(&orgID)
				if err != nil {
					return err
				}
			}

			err = tx.QueryRow(context.Background(), "SELECT id FROM auth_providers WHERE name=$1", localUser.authProvider).Scan(&authProviderID)
			if err != nil {
				return err
			}

			_, err = tx.Exec(context.Background(), "INSERT INTO users (id, org_id, name, role_id, auth_provider_id) VALUES ($1, $2, $3, (SELECT id FROM roles WHERE name=$4), (SELECT id from auth_providers WHERE name=$5))", userID, orgID, localUser.name, localUser.role, localUser.authProvider)
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
			return fmt.Errorf("unable to create random gorilla session auth key: %w", err)
		}

		var gorillaEncKey []byte

		if encryptedSessionKey {
			gorillaEncKey, err = generateRandomKey(32)
			if err != nil {
				return fmt.Errorf("unable to create random gorilla session encryption key: %w", err)
			}
		}

		gorillaCSRFKey, err := generateRandomKey(32)
		if err != nil {
			return fmt.Errorf("unable to create random gorilla CSRF key: %w", err)
		}

		_, err = insertGorillaSessionKey(tx, gorillaAuthKey, gorillaEncKey)
		if err != nil {
			return fmt.Errorf("unable to INSERT user session key: %w", err)
		}

		_, _, err = insertGorillaCSRFKey(tx, gorillaCSRFKey, true)
		if err != nil {
			return fmt.Errorf("unable to INSERT CSRF key: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func prepareServer(encryptedSessionKey bool) (*httptest.Server, *pgxpool.Pool, error) {
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

	err = populateTestData(dbPool, encryptedSessionKey)
	if err != nil {
		return nil, nil, err
	}

	cookieStore, err := getSessionStore(logger, dbPool, true)
	if err != nil {
		return nil, nil, err
	}

	csrfMiddleware, err := getCSRFMiddleware(dbPool, false)
	if err != nil {
		logger.Fatal().Err(err).Msg("getCSRFMiddleware failed")
	}

	router := newChiRouter(config.Config{}, logger, dbPool, cookieStore, csrfMiddleware, nil)

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

	u, err := Init(logger, pgConfig, false)
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
	ts, dbPool, err := prepareServer(false)
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

	rows, err := dbPool.Query(context.Background(), "SELECT id, time_created, key_order, auth_key, enc_key FROM gorilla_session_keys")
	if err != nil {
		t.Fatal(err)
	}

	var keyOrderMax int64

	var id pgtype.UUID
	var timeCreated time.Time
	var keyOrder int64
	var authKey, encKey []byte
	_, err = pgx.ForEachRow(rows, []any{&id, &timeCreated, &keyOrder, &authKey, &encKey}, func() error {
		fmt.Printf("id: %s, time_created: %s, key_order: %d, auth_key len: %d, enc_key len: %d\n", id, timeCreated, keyOrder, len(authKey), len(encKey))

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
	ts, dbPool, err := prepareServer(true)
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

	rows, err := dbPool.Query(context.Background(), "SELECT id, time_created, key_order, auth_key, enc_key FROM gorilla_session_keys")
	if err != nil {
		t.Fatal(err)
	}

	var keyOrderMax int64

	var id pgtype.UUID
	var timeCreated time.Time
	var keyOrder int64
	var authKey, encKey []byte
	_, err = pgx.ForEachRow(rows, []any{&id, &timeCreated, &keyOrder, &authKey, &encKey}, func() error {
		fmt.Printf("id: %s, time_created: %s, key_order: %d, auth_key len: %d, enc_key len: %d\n", id, timeCreated, keyOrder, len(authKey), len(encKey))

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
	ts, dbPool, err := prepareServer(false)
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
			description:    "successful org request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request, bad password",
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
	ts, dbPool, err := prepareServer(false)
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
	ts, dbPool, err := prepareServer(false)
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
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "successful superuser request with name right at limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedUser:      strings.Repeat("a", 63),
			addedPassword:  "admin-created-password-2",
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "failed superuser request with name above limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			addedUser:      strings.Repeat("a", 64),
			addedPassword:  "admin-created-password-2",
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "failed superuser request with name below limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			addedUser:      "",
			addedPassword:  "admin-created-password-2",
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
			addedUser:      "user-created-user-1",
			addedPassword:  "user-created-password-1",
			roleIDorName:   "user",
			orgIDorName:    "org1",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newUser := struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			Role     string `json:"role"`
			Org      string `json:"org"`
		}{
			Name:     test.addedUser,
			Password: test.addedPassword,
			Org:      test.orgIDorName,
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

func TestPatchUser(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description        string
		username           string
		password           string
		expectedStatus     int
		addedUser          string
		addedPassword      string
		userIDorName       string
		roleIDorName       string
		patchedOrgIDorName *string
	}{
		{
			description:        "successful superuser request with IDs",
			username:           "admin",
			password:           "adminpass1",
			expectedStatus:     http.StatusNoContent,
			addedUser:          "admin-created-patch-user-1",
			addedPassword:      "admin-created-password-1",
			roleIDorName:       "00000005-0000-0000-0000-000000000002",
			userIDorName:       "00000014-0000-0000-0000-000000000001",
			patchedOrgIDorName: Ptr("00000002-0000-0000-0000-000000000001"),
		},
		{
			description:        "successful superuser request with names",
			username:           "admin",
			password:           "adminpass1",
			expectedStatus:     http.StatusNoContent,
			addedUser:          "admin-created-patch-user-2",
			addedPassword:      "admin-created-password-2",
			roleIDorName:       "user",
			userIDorName:       "patch-user-1",
			patchedOrgIDorName: Ptr("org2"),
		},
		{
			description:        "successful superuser request with names, null org",
			username:           "admin",
			password:           "adminpass1",
			expectedStatus:     http.StatusNoContent,
			addedUser:          "admin-created-patch-user-2",
			addedPassword:      "admin-created-password-2",
			roleIDorName:       "user",
			userIDorName:       "patch-user-1",
			patchedOrgIDorName: nil,
		},
	}

	for _, test := range tests {
		patchUser := struct {
			Org *string `json:"org"`
		}{
			Org: test.patchedOrgIDorName,
		}

		b, err := json.Marshal(patchUser)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		fmt.Println(string(b))

		req, err := http.NewRequest("PATCH", ts.URL+"/api/v1/users/"+test.userIDorName, r)
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
			t.Fatalf("PATCH users unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetOrganizations(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
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
			description:    "successful org request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/orgs", nil)
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
			t.Fatalf("%s: GET orgs unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetOrganization(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
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
			description:    "successful org request with ID",
			username:       "username1",
			password:       "password1",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with name",
			username:       "username1",
			password:       "password1",
			nameOrID:       "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request, bad password",
			username:       "username1",
			password:       "badpassword1",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed lookup of org you do not belong to with ID",
			username:       "username2",
			password:       "password2",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed lookup of org you do not belong to with name",
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

		req, err := http.NewRequest("GET", ts.URL+"/api/v1/orgs/"+ident.String(), nil)
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
			t.Fatalf("%s: GET orgs/%s unexpected status code: %d (%s)", test.description, ident.String(), resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetOrganizationIPs(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
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
			description:    "successful superuser org IPs request with ID",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser org IPs request with name",
			username:       "admin",
			password:       "adminpass1",
			nameOrID:       "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org IPs request with ID",
			username:       "username1",
			password:       "password1",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org IPs request with name",
			username:       "username1",
			password:       "password1",
			nameOrID:       "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org IPs request, bad password",
			username:       "username1",
			password:       "badpassword1",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed lookup of org IPs for org you do not belong to with ID",
			username:       "username2",
			password:       "password2",
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed lookup of org IPs for org you do not belong to with name",
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

		req, err := http.NewRequest("GET", ts.URL+"/api/v1/orgs/"+ident.String()+"/ips", nil)
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
			t.Fatalf("%s: GET orgs/%s/ips unexpected status code: %d (%s)", test.description, ident.String(), resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostOrganizations(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
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

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/orgs", r)
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
			t.Fatalf("POST orgs unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetServices(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
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
			description:    "successful org request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request, bad auth",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request (not assigned to org)",
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
	ts, dbPool, err := prepareServer(false)
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
			description:    "successful org request with ID",
			username:       "username1",
			password:       "password1",
			nameOrID:       "00000003-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with name",
			username:       "username1",
			password:       "password1",
			nameOrID:       "org1-service1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request for service belonging to other org with ID",
			username:       "username2",
			password:       "password2",
			nameOrID:       "00000003-0000-0000-0000-000000000001",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed org request for service belonging to other org with name",
			username:       "username2",
			password:       "password2",
			nameOrID:       "org1-service1",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed org request not assigned to org with ID",
			username:       "username3-no-org",
			password:       "password3",
			nameOrID:       "00000003-0000-0000-0000-000000000001",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed org request not assigned to org with name",
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
	ts, dbPool, err := prepareServer(false)
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
		org            string
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			newService:     "new-admin-service",
			org:            "org1",
		},
		{
			description:    "successful superuser request with name right at limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			newService:     strings.Repeat("a", 63),
			org:            "org1",
		},
		{
			description:    "failed superuser request with name above limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     strings.Repeat("a", 64),
			org:            "org1",
		},
		{
			description:    "failed superuser request with name below limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "",
			org:            "org1",
		},
		{
			description:    "failed superuser request without org",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new-admin-service",
		},
		{
			description:    "successful org request (org based on auth)",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusCreated,
			newService:     "new-username1-service1",
		},
		{
			description:    "failed org request with duplicate service name",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusConflict,
			newService:     "new-username1-service1",
		},
		{
			description:    "successful org request with org matching auth",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusCreated,
			newService:     "new-username1-service2",
			org:            "org1",
		},
		{
			description:    "failed org request with org not matching auth",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusForbidden,
			newService:     "new-username1-service3",
			org:            "org2",
		},
		{
			description:    "failed org request not assigned to org",
			username:       "username3-no-org",
			password:       "password3",
			newService:     "new-username3-service1",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newService := struct {
			Name string  `json:"name"`
			Org  *string `json:"org,omitempty"`
		}{
			Name: test.newService,
		}

		if test.org != "" {
			newService.Org = &test.org
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
	ts, dbPool, err := prepareServer(false)
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
		org            string
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request not assigned to org",
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
	ts, dbPool, err := prepareServer(false)
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
		org            string
		serviceID      string
		domains        []string
		origins        []origin
		active         bool
	}{
		{
			description: "successful superuser request",
			username:    "admin",
			password:    "adminpass1",
			serviceID:   "00000003-0000-0000-0000-000000000001",
			org:         "org1",
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
			description: "failed superuser request with too many domains",
			username:    "admin",
			password:    "adminpass1",
			serviceID:   "00000003-0000-0000-0000-000000000001",
			org:         "org1",
			domains:     []string{"1.com", "2.com", "3.com", "4.com", "5.com", "6.com", "7.com", "8.com", "9.com", "10.com", "11.com"},
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
			description: "failed superuser request, too long Host in origin list",
			username:    "admin",
			password:    "adminpass1",
			serviceID:   "00000003-0000-0000-0000-000000000001",
			org:         "org1",
			domains:     []string{"example.com", "example.se"},
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
			description: "failed superuser request, too long domain in domains list",
			username:    "admin",
			password:    "adminpass1",
			serviceID:   "00000003-0000-0000-0000-000000000001",
			org:         "org1",
			domains:     []string{strings.Repeat("a", 254), "example.se"},
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
			description: "failed superuser request with invalid uuid (too long)",
			username:    "admin",
			password:    "adminpass1",
			serviceID:   "00000003-0000-0000-0000-0000000000001",
			org:         "org1",
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
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
		},
		{
			description: "failed superuser request with invalid uuid (too short)",
			username:    "admin",
			password:    "adminpass1",
			serviceID:   "00000003-0000-0000-0000-00000000001",
			org:         "org1",
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
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
		},
		{
			description: "failed superuser request with invalid uuid (not a UUID)",
			username:    "admin",
			password:    "adminpass1",
			serviceID:   "junk",
			org:         "org1",
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
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
		},
		{
			description: "successful org request",
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
			description: "failed org request not assigned to org",
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
			ServiceID string   `json:"service_id"`
			Org       string   `json:"org,omitempty"`
			Domains   []string `json:"domains"`
			Origins   []origin `json:"origins"`
		}{
			ServiceID: test.serviceID,
			Org:       test.org,
			Domains:   test.domains,
			Origins:   test.origins,
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
	ts, dbPool, err := prepareServer(false)
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
			description:    "successful org request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request, bad password",
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

func TestGetIPv4Networks(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
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
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed non-superuser request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/ipv4_networks", nil)
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
			t.Fatalf("%s: GET ipv4_networks unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
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

func TestPostIPv4Networks(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
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
		addedIPv4Network netip.Prefix
	}{
		{
			description:      "successful superuser request",
			username:         "admin",
			password:         "adminpass1",
			expectedStatus:   http.StatusCreated,
			addedIPv4Network: netip.MustParsePrefix("10.0.0.0/24"),
		},
		{
			description:      "failed superuser request (network overlaps the one inserted above)",
			username:         "admin",
			password:         "adminpass1",
			expectedStatus:   http.StatusConflict,
			addedIPv4Network: netip.MustParsePrefix("10.0.0.0/25"),
		},
		{
			description:      "failed (duplicate) superuser request",
			username:         "admin",
			password:         "adminpass1",
			expectedStatus:   http.StatusConflict,
			addedIPv4Network: netip.MustParsePrefix("10.0.0.0/24"),
		},
		{
			description:      "failed IPv6 superuser request",
			username:         "admin",
			password:         "adminpass1",
			expectedStatus:   http.StatusBadRequest,
			addedIPv4Network: netip.MustParsePrefix("2001:db8:0::/32"),
		},
		{
			description:      "failed non-superuser request",
			username:         "username1",
			password:         "password1",
			addedIPv4Network: netip.MustParsePrefix("10.0.0.0/24"),
			expectedStatus:   http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newIPv4Network := struct {
			Network netip.Prefix `json:"network"`
		}{
			Network: test.addedIPv4Network,
		}

		b, err := json.Marshal(newIPv4Network)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/ipv4_networks", r)
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
			t.Fatalf("POST ipv4_networks unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetIPv6Networks(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
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
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed non-superuser request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/ipv6_networks", nil)
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
			t.Fatalf("%s: GET ipv6 networks unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
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

func TestPostIPv6Networks(t *testing.T) {
	ts, dbPool, err := prepareServer(false)
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
		addedIPv6Network netip.Prefix
	}{
		{
			description:      "successful superuser request",
			username:         "admin",
			password:         "adminpass1",
			expectedStatus:   http.StatusCreated,
			addedIPv6Network: netip.MustParsePrefix("2001:db8:1::/48"),
		},
		{
			description:      "failed superuser request (network overlaps the one inserted above)",
			username:         "admin",
			password:         "adminpass1",
			expectedStatus:   http.StatusConflict,
			addedIPv6Network: netip.MustParsePrefix("2001:db8:1::/64"),
		},
		{
			description:      "failed (duplicate) superuser request",
			username:         "admin",
			password:         "adminpass1",
			expectedStatus:   http.StatusConflict,
			addedIPv6Network: netip.MustParsePrefix("2001:db8:1::/48"),
		},
		{
			description:      "failed non-superuser request",
			username:         "username1",
			password:         "password1",
			addedIPv6Network: netip.MustParsePrefix("2001:db8:3::/64"),
			expectedStatus:   http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newIPv4Network := struct {
			Network netip.Prefix `json:"network"`
		}{
			Network: test.addedIPv6Network,
		}

		b, err := json.Marshal(newIPv4Network)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/ipv6_networks", r)
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
			t.Fatalf("POST ipv6_networks unexpected status code: %d (%s)", resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}
