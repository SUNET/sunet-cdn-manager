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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/SUNET/sunet-cdn-manager/pkg/config"
	"github.com/SUNET/sunet-cdn-manager/pkg/migrations"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/stapelberg/postgrestest"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/argon2"
)

var (
	pgt    *postgrestest.Server
	logger zerolog.Logger
)

func Ptr[T any](v T) *T {
	return &v
}

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
		"INSERT INTO orgs (id, name, service_quota, domain_quota) VALUES ('00000002-0000-0000-0000-000000000001', 'org1', 100, 100)",
		"INSERT INTO orgs (id, name) VALUES ('00000002-0000-0000-0000-000000000002', 'org2')",
		"INSERT INTO orgs (id, name) VALUES ('00000002-0000-0000-0000-000000000003', 'org3')",
		"INSERT INTO orgs (id, name) VALUES ('00000002-0000-0000-0000-000000000004', 'org4')",

		// Services
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000001', id, 'org1-service1', '(1000010000, 1000019999)' FROM orgs WHERE name='org1'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000002', id, 'org1-service2', '(1000020000, 1000029999)' FROM orgs WHERE name='org1'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000003', id, 'org1-service3', '(1000030000, 1000039999)' FROM orgs WHERE name='org1'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000010', id, 'org1-service4', '(1000040000, 1000049999)' FROM orgs WHERE name='org1'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000011', id, 'org1-service5', '(1000050000, 1000059999)' FROM orgs WHERE name='org1'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000012', id, 'org1-service6', '(1000060000, 1000069999)' FROM orgs WHERE name='org1'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000004', id, 'org2-service1', '(1000070000, 1000079999)' FROM orgs WHERE name='org2'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000005', id, 'org2-service2', '(1000080000, 1000089999)' FROM orgs WHERE name='org2'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000006', id, 'org2-service3', '(1000090000, 1000099999)' FROM orgs WHERE name='org2'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000007', id, 'org3-service1', '(1000100000, 1000109999)' FROM orgs WHERE name='org3'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000008', id, 'org3-service2', '(1000110000, 1000119999)' FROM orgs WHERE name='org3'",
		"INSERT INTO services (id, org_id, name, uid_range) SELECT '00000003-0000-0000-0000-000000000009', id, 'org3-service3', '(1000120000, 1000129999)' FROM orgs WHERE name='org3'",

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
		"INSERT INTO roles (id, name) VALUES ('00000005-0000-0000-0000-000000000003', 'node')",

		// Domains
		"INSERT INTO domains (id, org_id, name, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000001', '00000002-0000-0000-0000-000000000001', 'example.se', true, 'token1')",
		"INSERT INTO domains (id, org_id, name, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000002', '00000002-0000-0000-0000-000000000001', 'example.com', true, 'token2')",
		"INSERT INTO domains (id, org_id, name, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000003', '00000002-0000-0000-0000-000000000001', 'example.nu', false, 'token2')",
		"INSERT INTO domains (id, org_id, name, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000004', '00000002-0000-0000-0000-000000000001', 'example-delete-1.se', true, 'token-del-1')",
		"INSERT INTO domains (id, org_id, name, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000005', '00000002-0000-0000-0000-000000000001', 'example-delete-2.se', true, 'token2-del-2')",
		"INSERT INTO domains (id, org_id, name, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000006', '00000002-0000-0000-0000-000000000001', 'example-delete-3.se', false, 'token2-del-3')",
		"INSERT INTO domains (id, org_id, name, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000007', '00000002-0000-0000-0000-000000000001', 'example-delete-4.se', false, 'token2-del-4')",
		"INSERT INTO domains (id, org_id, name, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000008', '00000002-0000-0000-0000-000000000001', 'example-delete-5.se', false, 'token2-del-5')",

		// Service domain mappings (only valid if the domains-entry is verified=true)
		// org1: www.example.se
		"INSERT INTO service_domains (id, service_version_id, domain_id) VALUES ('00000008-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', '00000015-0000-0000-0000-000000000001')",
		// org1: www.example.com
		"INSERT INTO service_domains (id, service_version_id, domain_id) VALUES ('00000008-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', '00000015-0000-0000-0000-000000000002')",

		// Origins
		// org1-service3
		"INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', '198.51.100.10', 80, false)",
		"INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', '198.51.100.11', 443, true)",
		// org1-service2
		"INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000003', '00000004-0000-0000-0000-000000000002', '198.51.100.10', 80, false)",
		// org1-service1
		"INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000004', '00000004-0000-0000-0000-000000000001', '198.51.100.10', 80, false)",

		// org2-service2
		"INSERT INTO service_origins (id, service_version_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000005', '00000004-0000-0000-0000-000000000005', '198.51.100.20', 80, false)",

		// Auth providers
		"INSERT INTO auth_providers (id, name) VALUES ('00000010-0000-0000-0000-000000000001', 'local')",
		"INSERT INTO auth_providers (id, name) VALUES ('00000010-0000-0000-0000-000000000002', 'keycloak')",

		// IPv4 networks
		"INSERT INTO ip_networks (id, network) VALUES ('00000011-0000-0000-0000-000000000001', '192.0.2.0/24')",
		"INSERT INTO ip_networks (id, network) VALUES ('00000011-0000-0000-0000-000000000002', '198.51.100.0/24')",

		// IPv6 networks
		"INSERT INTO ip_networks (id, network) VALUES ('00000012-0000-0000-0000-000000000001', '2001:db8:0::/48')",
		"INSERT INTO ip_networks (id, network) VALUES ('00000012-0000-0000-0000-000000000002', '3fff::/20')",

		// Allocate addresses from networks to services
		// org1, org1-service1
		"INSERT INTO service_ip_addresses (id, network_id, service_id, address) VALUES ('00000013-0000-0000-0000-000000000001', '00000011-0000-0000-0000-000000000001', '00000003-0000-0000-0000-000000000001', '192.0.2.1')",
		"INSERT INTO service_ip_addresses (id, network_id, service_id, address) VALUES ('00000013-0000-0000-0000-000000000002', '00000012-0000-0000-0000-000000000001', '00000003-0000-0000-0000-000000000001', '2001:db8:0::1')",

		// Users
		// No org, local user
		"INSERT INTO users (id, role_id, auth_provider_id, name) VALUES ('00000014-0000-0000-0000-000000000001', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000001', 'put-user-1')",
		"INSERT INTO user_argon2keys (id, user_id, key, salt, time, memory, threads, tag_size) VALUES ('00000017-0000-0000-0000-000000000001', '00000014-0000-0000-0000-000000000001', '\\x00', '\\x00', 3, 65536, 4, 32)",
		// No org, local users, used to test DELETE
		"INSERT INTO users (id, role_id, auth_provider_id, name) VALUES ('00000014-0000-0000-0000-000000000002', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000001', 'delete-local-user-1')",
		"INSERT INTO user_argon2keys (id, user_id, key, salt, time, memory, threads, tag_size) VALUES ('00000017-0000-0000-0000-000000000002', '00000014-0000-0000-0000-000000000002', '\\x00', '\\x00', 3, 65536, 4, 32)",
		"INSERT INTO users (id, role_id, auth_provider_id, name) VALUES ('00000014-0000-0000-0000-000000000003', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000001', 'delete-local-user-2')",
		"INSERT INTO user_argon2keys (id, user_id, key, salt, time, memory, threads, tag_size) VALUES ('00000017-0000-0000-0000-000000000003', '00000014-0000-0000-0000-000000000003', '\\x00', '\\x00', 3, 65536, 4, 32)",
		// No org, keycloak users, used to test DELETE
		"INSERT INTO users (id, role_id, auth_provider_id, name) VALUES ('00000014-0000-0000-0000-000000000004', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000002', 'delete-keycloak-user-1')",
		"INSERT INTO auth_provider_keycloak (id, user_id, subject) VALUES ('00000018-0000-0000-0000-000000000001', '00000014-0000-0000-0000-000000000004', '00000019-0000-0000-0000-000000000001')",
		"INSERT INTO users (id, role_id, auth_provider_id, name) VALUES ('00000014-0000-0000-0000-000000000005', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000002', 'delete-keycloak-user-2')",
		"INSERT INTO auth_provider_keycloak (id, user_id, subject) VALUES ('00000018-0000-0000-0000-000000000002', '00000014-0000-0000-0000-000000000005', '00000019-0000-0000-0000-000000000002')",

		// Cache nodes
		"INSERT INTO cache_nodes (id, name, description, ipv4_address, ipv6_address) VALUES ('00000015-0000-0000-0000-000000000001', 'cache-node1', 'A cache node, cache-node1.example.com', '127.0.0.100', '::1337')",
		"INSERT INTO cache_nodes (id, name, description) VALUES ('00000015-0000-0000-0000-000000000002', 'cache-node2', 'A cache node, cache-node2.example.com, no addresses')",
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
			{
				name:         "username4-no-pw",
				password:     "",
				role:         "user",
				orgName:      "org1",
				id:           "00000006-0000-0000-0000-000000000005",
				authProvider: "local",
			},
			{
				name:         "username5-no-pw",
				password:     "",
				role:         "user",
				orgName:      "org1",
				id:           "00000006-0000-0000-0000-000000000006",
				authProvider: "local",
			},
			{
				name:         "username6",
				password:     "password6",
				role:         "user",
				orgName:      "org1",
				id:           "00000006-0000-0000-0000-000000000007",
				authProvider: "local",
			},
			{
				name:         "node-user-1",
				password:     "nodeuserpass1",
				role:         "node",
				id:           "00000006-0000-0000-0000-000000000008",
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

			// Set a local password for the user if not empty
			if localUser.password != "" {
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
		}

		vcls := []struct {
			id               string
			vclRecvFile      string
			serviceVersionID string
		}{
			{
				id:               "00000007-0000-0000-0000-000000000001",
				serviceVersionID: "00000004-0000-0000-0000-000000000001",
				vclRecvFile:      "testdata/vcl/vcl_recv/content1.vcl",
			},
			{
				id:               "00000007-0000-0000-0000-000000000002",
				serviceVersionID: "00000004-0000-0000-0000-000000000002",
				vclRecvFile:      "testdata/vcl/vcl_recv/content1.vcl",
			},
			{
				id:               "00000007-0000-0000-0000-000000000003",
				serviceVersionID: "00000004-0000-0000-0000-000000000003",
				vclRecvFile:      "testdata/vcl/vcl_recv/content1.vcl",
			},
		}

		for _, vcl := range vcls {
			var vclID, serviceVersionID pgtype.UUID
			err := vclID.Scan(vcl.id)
			if err != nil {
				return err
			}

			err = serviceVersionID.Scan(vcl.serviceVersionID)
			if err != nil {
				return err
			}

			var vclRecvContentBytes []byte
			if vcl.vclRecvFile != "" {
				vclRecvContentBytes, err = os.ReadFile(vcl.vclRecvFile)
				if err != nil {
					return err
				}
			}

			_, err = tx.Exec(context.Background(), "INSERT INTO service_vcls (id, service_version_id, vcl_recv) VALUES($1, $2, $3)", vclID, serviceVersionID, vclRecvContentBytes)
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

func prepareServer(encryptedSessionKey bool, vclValidator *vclValidatorClient) (*httptest.Server, *pgxpool.Pool, error) {
	pgurl, err := pgt.CreateDatabase(context.Background())
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		return nil, nil, err
	}

	// Make sure tests do not hang even if they only have access to a single db connection
	pgConfig.MaxConns = 1

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

	cookieStore, err := getSessionStore(logger, dbPool)
	if err != nil {
		return nil, nil, err
	}

	csrfMiddleware, err := getCSRFMiddleware(dbPool)
	if err != nil {
		logger.Fatal().Err(err).Msg("getCSRFMiddleware failed")
	}

	confTemplates := configTemplates{}

	confTemplates.vcl, err = template.ParseFS(templateFS, "templates/sunet-cdn.vcl")
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to create varnish template")
	}

	confTemplates.haproxy, err = template.ParseFS(templateFS, "templates/haproxy.cfg")
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to create haproxy template")
	}

	var argon2Mutex sync.Mutex

	loginCache, err := lru.New[string, struct{}](128)
	if err != nil {
		logger.Fatal().Err(err).Msg("unable to create LRU login cache")
	}

	router := newChiRouter(config.Config{}, logger, dbPool, &argon2Mutex, loginCache, cookieStore, csrfMiddleware, nil, vclValidator, confTemplates, false)

	err = setupHumaAPI(router, dbPool, &argon2Mutex, loginCache, vclValidator, confTemplates)
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

func TestGorillaCSRFKey(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description string
		active      bool
	}{
		{
			description: "insert new active key",
			active:      true,
		},
		{
			description: "insert another active key",
			active:      true,
		},
		{
			description: "insert new inactive key",
			active:      false,
		},
	}

	for _, test := range tests {
		gorillaCSRFAuthKey, err := generateRandomKey(32)
		if err != nil {
			t.Fatalf("unable to create random gorilla CSRF key: %s", err)
		}

		err = pgx.BeginFunc(context.Background(), dbPool, func(tx pgx.Tx) error {
			_, _, err = insertGorillaCSRFKey(tx, gorillaCSRFAuthKey, test.active)
			if err != nil {
				return fmt.Errorf("unable to INSERT CSRF key: %w", err)
			}

			return nil
		})
		if err != nil {
			t.Fatalf("transaction failed: %s", err)
		}
	}
}

func TestSessionKeyHandlingNoEnc(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
	ts, dbPool, err := prepareServer(true, nil)
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
	ts, dbPool, err := prepareServer(false, nil)
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
			description:    "failed user request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
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
	ts, dbPool, err := prepareServer(false, nil)
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
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			nameOrID:       "username4-no-pw",
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
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/users/"+test.nameOrID, nil)
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
			t.Fatalf("%s: GET users/%s unexpected status code: %d (%s)", test.description, test.nameOrID, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostUsers(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		roleIDorName   string
		orgIDorName    string
	}{
		{
			description:    "successful superuser request with IDs",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedUser:      "admin-created-user-1",
			roleIDorName:   "00000005-0000-0000-0000-000000000002",
			orgIDorName:    "00000002-0000-0000-0000-000000000001",
		},
		{
			description:    "successful superuser request with names",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedUser:      "admin-created-user-2",
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "successful superuser request with IDs and no org",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedUser:      "admin-created-user-3",
			roleIDorName:   "00000005-0000-0000-0000-000000000002",
			orgIDorName:    "",
		},
		{
			description:    "successful superuser request with name right at limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedUser:      strings.Repeat("a", 63),
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "failed superuser request with name above limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			addedUser:      strings.Repeat("a", 64),
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "failed superuser request with name below limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			addedUser:      "",
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
			addedUser:      "user-created-user-1",
			roleIDorName:   "user",
			orgIDorName:    "org1",
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed node user request",
			username:       "node-user-1",
			password:       "nodeuserpass1",
			addedUser:      "user-created-user-1",
			roleIDorName:   "user",
			orgIDorName:    "org1",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newUser := struct {
			Name string `json:"name"`
			Role string `json:"role"`
			Org  string `json:"org,omitempty"`
		}{
			Name: test.addedUser,
			Org:  test.orgIDorName,
			Role: test.roleIDorName,
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
			t.Fatalf("%s: POST users unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPutUser(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description         string
		username            string
		password            string
		expectedStatus      int
		targetUserIDorName  string
		updatedOrgIDorName  string
		updatedRoleIDorName string
		updatedName         string
	}{
		{
			description:         "successful superuser request with IDs",
			username:            "admin",
			password:            "adminpass1",
			expectedStatus:      http.StatusOK,
			targetUserIDorName:  "00000014-0000-0000-0000-000000000001",
			updatedOrgIDorName:  "00000002-0000-0000-0000-000000000001",
			updatedRoleIDorName: "00000005-0000-0000-0000-000000000002",
			updatedName:         "put-user-1",
		},
		{
			description:         "successful superuser request with names",
			username:            "admin",
			password:            "adminpass1",
			expectedStatus:      http.StatusOK,
			targetUserIDorName:  "put-user-1",
			updatedName:         "put-user-1",
			updatedOrgIDorName:  "org2",
			updatedRoleIDorName: "user",
		},
		{
			description:         "successful superuser request with names, null org",
			username:            "admin",
			password:            "adminpass1",
			expectedStatus:      http.StatusOK,
			targetUserIDorName:  "put-user-1",
			updatedName:         "put-user-1",
			updatedOrgIDorName:  "",
			updatedRoleIDorName: "user",
		},
		{
			description:         "failed non-superuser request with names",
			username:            "username1",
			password:            "password1",
			expectedStatus:      http.StatusForbidden,
			targetUserIDorName:  "username1",
			updatedName:         "username1",
			updatedOrgIDorName:  "org1",
			updatedRoleIDorName: "user",
		},
	}

	for _, test := range tests {
		putUser := struct {
			Org  string `json:"org,omitempty"`
			Role string `json:"role"`
			Name string `json:"name"`
		}{
			Org:  test.updatedOrgIDorName,
			Role: test.updatedRoleIDorName,
			Name: test.updatedName,
		}

		b, err := json.Marshal(putUser)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		fmt.Println(string(b))

		req, err := http.NewRequest("PUT", ts.URL+"/api/v1/users/"+test.targetUserIDorName, r)
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
			t.Fatalf("%s: PUT users unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestDeleteUser(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		targetUserIDorName string
	}{
		{
			description:        "successful superuser request with IDs",
			username:           "admin",
			password:           "adminpass1",
			expectedStatus:     http.StatusNoContent,
			targetUserIDorName: "00000014-0000-0000-0000-000000000002",
		},
		{
			description:        "successful superuser request with name",
			username:           "admin",
			password:           "adminpass1",
			expectedStatus:     http.StatusNoContent,
			targetUserIDorName: "delete-local-user-2",
		},
		{
			description:        "successful superuser request with IDs for keycloak",
			username:           "admin",
			password:           "adminpass1",
			expectedStatus:     http.StatusNoContent,
			targetUserIDorName: "00000014-0000-0000-0000-000000000004",
		},
		{
			description:        "successful superuser request with name for keycloak",
			username:           "admin",
			password:           "adminpass1",
			expectedStatus:     http.StatusNoContent,
			targetUserIDorName: "delete-keycloak-user-2",
		},
		{
			description:        "failed superuser request trying to remove itself with ID",
			username:           "admin",
			password:           "adminpass1",
			expectedStatus:     http.StatusForbidden,
			targetUserIDorName: "00000006-0000-0000-0000-000000000001",
		},
		{
			description:        "failed superuser request trying to remove itself with name",
			username:           "admin",
			password:           "adminpass1",
			expectedStatus:     http.StatusForbidden,
			targetUserIDorName: "admin",
		},
		{
			description:        "failed non-superuser request with name",
			username:           "username1",
			password:           "password1",
			expectedStatus:     http.StatusForbidden,
			targetUserIDorName: "admin",
		},
	}

	for _, test := range tests {
		// Verify uses exists prior to deletion
		var testQuery string
		if isUUID(test.targetUserIDorName) {
			testQuery = "SELECT name, id FROM users WHERE id = $1"
		} else {
			testQuery = "SELECT name, id FROM users WHERE name = $1"
		}

		var name string
		var id pgtype.UUID
		err := dbPool.QueryRow(context.Background(), testQuery, test.targetUserIDorName).Scan(&name, &id)
		if err != nil {
			t.Fatal(err)
		}

		req, err := http.NewRequest("DELETE", ts.URL+"/api/v1/users/"+test.targetUserIDorName, nil)
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
			t.Fatalf("%s: DELETE user unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)

		// Verify user is removed if a http.StatusNoContent was returned, otherwise they are expected to still exist
		err = dbPool.QueryRow(context.Background(), testQuery, test.targetUserIDorName).Scan(&name, &id)
		if err == nil {
			if test.expectedStatus == http.StatusNoContent {
				// The delete seemed successful, why are they still in the db
				t.Fatalf("user is not deleted as expected, name: '%s', id: '%s'", name, id)
			}
		} else {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("user deleted pre-check unexpected error: '%s', id: '%s', %s", name, id, err)
			}
			if test.expectedStatus != http.StatusNoContent {
				t.Fatalf("database returned no rows, but the delete should have been forbidden: '%s', id: '%s', %s", name, id, err)
			}
		}

	}
}

func TestPutPassword(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description          string
		username             string
		password             string
		expectedStatus       int
		modifiedUserIDorName string
		oldPassword          string
		newPassword          string
		shouldSucceed        bool
	}{
		{
			description:          "successful superuser request with IDs",
			username:             "admin",
			password:             "adminpass1",
			expectedStatus:       http.StatusNoContent,
			modifiedUserIDorName: "username4-no-pw",
			oldPassword:          "",
			newPassword:          "updated-password-1",
			shouldSucceed:        true,
		},
		{
			description:          "failed request for user missing password",
			username:             "username4-no-pw",
			password:             "",
			expectedStatus:       http.StatusUnauthorized,
			modifiedUserIDorName: "username5-no-pw",
			oldPassword:          "",
			newPassword:          "updated-password-2",
			shouldSucceed:        false,
		},
		{
			description:          "successful request for user changing their own password",
			username:             "username1",
			password:             "password1",
			expectedStatus:       http.StatusNoContent,
			modifiedUserIDorName: "username1",
			oldPassword:          "password1",
			newPassword:          "updated-password-3",
			shouldSucceed:        true,
		},
		{
			description:          "failed request for user changing their own password with the wrong old password",
			username:             "username6",
			password:             "password6",
			expectedStatus:       http.StatusBadRequest,
			modifiedUserIDorName: "username6",
			oldPassword:          "password6-wrong",
			newPassword:          "updated-password-4",
			shouldSucceed:        false,
		},
	}

	for _, test := range tests {
		patchUser := struct {
			Old string `json:"old,omitempty"`
			New string `json:"new,omitempty"`
		}{
			Old: test.oldPassword,
			New: test.newPassword,
		}

		b, err := json.Marshal(patchUser)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		fmt.Println(string(b))

		req, err := http.NewRequest("PUT", ts.URL+"/api/v1/users/"+test.modifiedUserIDorName+"/local-password", r)
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
			t.Fatalf("%s: PUT local-password unexpected status code: want %d, got: %d (%s)", test.description, test.expectedStatus, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)

		// Verify old password no longer works
		statusCode, err := testAuth(ts, test.modifiedUserIDorName, test.oldPassword)
		if err == nil {
			t.Fatal(errors.New("old password still works, unexpected"))
		}
		if statusCode != http.StatusUnauthorized {
			t.Fatal(fmt.Errorf("unexected status code: %d", statusCode))
		}

		// Verify new password works
		statusCode, err = testAuth(ts, test.modifiedUserIDorName, test.newPassword)
		if err != nil {
			if test.shouldSucceed {
				t.Fatal(err)
			}
		}
		if test.shouldSucceed {
			if statusCode != http.StatusOK {
				t.Fatal(fmt.Errorf("unexected status code: %d", statusCode))
			}
		} else {
			if statusCode != http.StatusUnauthorized {
				t.Fatal(fmt.Errorf("unexected status code: %d", statusCode))
			}
		}
	}
}

func testAuth(ts *httptest.Server, username string, password string) (int, error) {
	req, err := http.NewRequest("GET", ts.URL+"/api/v1/users/"+username, nil)
	if err != nil {
		return 0, err
	}

	req.SetBasicAuth(username, password)

	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("unexpected status code for test auth: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, err
	}

	fmt.Println(string(b))

	return resp.StatusCode, nil
}

func TestGetOrgs(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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

func TestGetOrg(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/orgs/"+test.nameOrID, nil)
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
			t.Fatalf("%s: GET orgs/%s unexpected status code: %d (%s)", test.description, test.nameOrID, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetDomains(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		orgNameOrID    string
		expectedStatus int
	}{
		{
			description:    "successful superuser request with ID",
			username:       "admin",
			password:       "adminpass1",
			orgNameOrID:    "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request for all orgs",
			username:       "admin",
			password:       "adminpass1",
			orgNameOrID:    "",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       "adminpass1",
			orgNameOrID:    "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with ID",
			username:       "username1",
			password:       "password1",
			orgNameOrID:    "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with name",
			username:       "username1",
			password:       "password1",
			orgNameOrID:    "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful normal user request with no org",
			username:       "username1",
			password:       "password1",
			orgNameOrID:    "",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful normal user request with no org and no domains",
			username:       "username2",
			password:       "password2",
			orgNameOrID:    "",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request, bad password",
			username:       "username1",
			password:       "badpassword1",
			orgNameOrID:    "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed lookup of org you do not belong to with ID",
			username:       "username2",
			password:       "password2",
			orgNameOrID:    "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed lookup of org you do not belong to with name",
			username:       "username2",
			password:       "password2",
			orgNameOrID:    "org1",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/domains", nil)
		if err != nil {
			t.Fatal(err)
		}

		if test.orgNameOrID != "" {
			values := req.URL.Query()
			values.Add("org", test.orgNameOrID)
			req.URL.RawQuery = values.Encode()
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
			t.Fatalf("%s: GET '%s' unexpected status code: %d (%s)", test.description, req.URL.String(), resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetServiceIPs(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description     string
		username        string
		password        string
		orgNameOrID     string
		serviceNameOrID string
		expectedStatus  int
	}{
		{
			description:     "successful superuser service IPs request with ID, no org",
			username:        "admin",
			password:        "adminpass1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful superuser service IPs request with ID, with org id",
			username:        "admin",
			password:        "adminpass1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful superuser service IPs request with names",
			username:        "admin",
			password:        "adminpass1",
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "failed service IPs request, bad password",
			username:        "username1",
			password:        "badpassword1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusUnauthorized,
		},
		{
			description:     "failed lookup of service IPs for org you do not belong to with ID",
			username:        "username2",
			password:        "password2",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusNotFound,
		},
		{
			description:     "failed lookup of service IPs for org you do not belong to with name",
			username:        "username2",
			password:        "password2",
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusNotFound,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/ips", nil)
		if err != nil {
			t.Fatal(err)
		}

		if test.orgNameOrID != "" {
			values := req.URL.Query()
			values.Add("org", test.orgNameOrID)
			req.URL.RawQuery = values.Encode()
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
			t.Fatalf("%s: unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostOrganizations(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
			description:       "failed superuser request with invalid DNS label name",
			username:          "admin",
			password:          "adminpass1",
			expectedStatus:    http.StatusUnprocessableEntity,
			addedOrganization: "admin org",
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
	ts, dbPool, err := prepareServer(false, nil)
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
			t.Fatalf("%s: GET services unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetService(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description     string
		username        string
		password        string
		serviceNameOrID string
		orgNameOrID     string
		expectedStatus  int
	}{
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        "adminpass1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        "adminpass1",
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful superuser request with name and org by id",
			username:        "admin",
			password:        "adminpass1",
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful user request with ID",
			username:        "username1",
			password:        "password1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful user request with name",
			username:        "username1",
			password:        "password1",
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "failed user request for service belonging to other org with ID",
			username:        "username2",
			password:        "password2",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusNotFound,
		},
		{
			description:     "failed org request for service belonging to other org with name",
			username:        "username2",
			password:        "password2",
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusNotFound,
		},
		{
			description:     "failed org request not assigned to org with ID",
			username:        "username3-no-org",
			password:        "password3",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusNotFound,
		},
		{
			description:     "failed org request not assigned to org with name",
			username:        "username3-no-org",
			password:        "password3",
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusNotFound,
		},
	}

	for _, test := range tests {
		if test.serviceNameOrID == "" {
			t.Fatal("user needs service name or ID for service test")
		}

		req, err := http.NewRequest("GET", ts.URL+"/api/v1/services/"+test.serviceNameOrID, nil)
		if err != nil {
			t.Fatal(err)
		}

		if test.orgNameOrID != "" {
			values := req.URL.Query()
			values.Add("org", test.orgNameOrID)
			req.URL.RawQuery = values.Encode()
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
			t.Fatalf("%s: GET service by ID unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestDeleteService(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description     string
		username        string
		password        string
		serviceNameOrID string
		orgNameOrID     string
		expectedStatus  int
	}{
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        "adminpass1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusNoContent,
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        "adminpass1",
			serviceNameOrID: "org1-service2",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusNoContent,
		},
		{
			description:     "successful superuser request with name and org by id",
			username:        "admin",
			password:        "adminpass1",
			serviceNameOrID: "org1-service3",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusNoContent,
		},
		{
			description:     "successful user request with ID",
			username:        "username1",
			password:        "password1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000010",
			expectedStatus:  http.StatusNoContent,
		},
		{
			description:     "successful user request with name",
			username:        "username1",
			password:        "password1",
			serviceNameOrID: "org1-service5",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusNoContent,
		},
		{
			description:     "failed user request for service belonging to other org with ID",
			username:        "username2",
			password:        "password2",
			serviceNameOrID: "00000003-0000-0000-0000-000000000012",
			expectedStatus:  http.StatusNotFound,
		},
		{
			description:     "failed user request for service belonging to other org with name",
			username:        "username2",
			password:        "password2",
			serviceNameOrID: "org1-service6",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusNotFound,
		},
		{
			description:     "failed user request not assigned to org with ID",
			username:        "username3-no-org",
			password:        "password3",
			serviceNameOrID: "00000003-0000-0000-0000-000000000012",
			expectedStatus:  http.StatusNotFound,
		},
		{
			description:     "failed user request not assigned to org with name",
			username:        "username3-no-org",
			password:        "password3",
			serviceNameOrID: "org1-service6",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusNotFound,
		},
	}

	for _, test := range tests {
		if test.serviceNameOrID == "" {
			t.Fatal("user needs service name or ID for service test")
		}

		req, err := http.NewRequest("DELETE", ts.URL+"/api/v1/services/"+test.serviceNameOrID, nil)
		if err != nil {
			t.Fatal(err)
		}

		if test.orgNameOrID != "" {
			values := req.URL.Query()
			values.Add("org", test.orgNameOrID)
			req.URL.RawQuery = values.Encode()
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
			t.Fatalf("%s: DELETE service by ID unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostServices(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
			description:    "failed superuser request with org as invalid DNS label",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new-admin-service",
			org:            "org 1",
		},
		{
			description:    "failed superuser request with service as invalid DNS label",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new admin-service",
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
			description:    "failed org request with org matching auth (no org supplied in request)",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new-username1-service1",
		},
		{
			description:    "successful org request with org matching auth",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusCreated,
			newService:     "new-username1-service1",
			org:            "org1",
		},
		{
			description:    "failed org request with duplicate service name",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusConflict,
			newService:     "new-username1-service1",
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
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			description:    "successful admin request inside services_limit (first service)",
			username:       "admin",
			password:       "adminpass1",
			newService:     "new-admin-org-4-service1",
			expectedStatus: http.StatusCreated,
			org:            "org4",
		},
		{
			description:    "failed admin request outside services_limit (second service)",
			username:       "admin",
			password:       "adminpass1",
			newService:     "new-admin-org-4-service2",
			expectedStatus: http.StatusConflict,
			org:            "org4",
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

func TestDeleteDomain(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		domainNameOrID string
		expectedStatus int
	}{
		{
			description:    "successful superuser request with ID",
			username:       "admin",
			password:       "adminpass1",
			domainNameOrID: "00000015-0000-0000-0000-000000000004",
			expectedStatus: http.StatusNoContent,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       "adminpass1",
			domainNameOrID: "example-delete-2.se",
			expectedStatus: http.StatusNoContent,
		},
		{
			description:    "successful user request with ID",
			username:       "username1",
			password:       "password1",
			domainNameOrID: "00000015-0000-0000-0000-000000000006",
			expectedStatus: http.StatusNoContent,
		},
		{
			description:    "successful user request with name",
			username:       "username1",
			password:       "password1",
			domainNameOrID: "example-delete-4.se",
			expectedStatus: http.StatusNoContent,
		},
		{
			description:    "failed user request for domain belonging to other org with ID",
			username:       "username2",
			password:       "password2",
			domainNameOrID: "00000015-0000-0000-0000-000000000008",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed user request for service belonging to other org with name",
			username:       "username2",
			password:       "password2",
			domainNameOrID: "example-delete-5.se",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed user request not assigned to org with ID",
			username:       "username3-no-org",
			password:       "password3",
			domainNameOrID: "00000015-0000-0000-0000-000000000008",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed user request not assigned to org with name",
			username:       "username3-no-org",
			password:       "password3",
			domainNameOrID: "example-delete-5.se",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, test := range tests {
		if test.domainNameOrID == "" {
			t.Fatal("user needs domain name or ID for domain test")
		}

		req, err := http.NewRequest("DELETE", ts.URL+"/api/v1/domains/"+test.domainNameOrID, nil)
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
			t.Fatalf("%s: DELETE service by ID unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostDomains(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		newDomain      string
		orgNameOrID    string
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			newDomain:      "example.net",
			orgNameOrID:    "org1",
		},
		{
			description:    "failed superuser request with invalid DNS name",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newDomain:      "example .nu",
			orgNameOrID:    "org1",
		},
		{
			description:    "failed superuser request, no org query param",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			newDomain:      "example.net",
			orgNameOrID:    "",
		},
	}

	for _, test := range tests {
		newDomain := struct {
			Name string `json:"name"`
		}{
			Name: test.newDomain,
		}

		b, err := json.Marshal(newDomain)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/domains", r)
		if err != nil {
			t.Fatal(err)
		}

		if test.orgNameOrID != "" {
			values := req.URL.Query()
			values.Add("org", test.orgNameOrID)
			req.URL.RawQuery = values.Encode()
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
	ts, dbPool, err := prepareServer(false, nil)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description     string
		username        string
		password        string
		expectedStatus  int
		org             string
		serviceNameOrID string
		orgNameOrID     string
	}{
		{
			description:     "successful superuser request with id",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
		},
		{
			description:     "successful user request with id",
			username:        "username1",
			password:        "password1",
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
		},
		{
			description:     "successful user request with name",
			username:        "username1",
			password:        "password1",
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
		},
		{
			description:     "failed user request not assigned to org",
			username:        "username3-no-org",
			password:        "password3",
			expectedStatus:  http.StatusForbidden,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
		},
		{
			description:     "failed user request name without org",
			username:        "username1",
			password:        "password1",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "org1-service1",
		},
		{
			description:     "failed superuser request with name, missing org",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "org1-service1",
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/service-versions", nil)
		if err != nil {
			t.Fatal(err)
		}

		if test.orgNameOrID != "" {
			values := req.URL.Query()
			values.Add("org", test.orgNameOrID)
			req.URL.RawQuery = values.Encode()
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
	req := testcontainers.ContainerRequest{
		Image:        "platform.sunet.se/sunet-cdn/sunet-vcl-validator:e46f64d255425ec1d87329b9a7246101b1416547",
		ExposedPorts: []string{"8888/tcp"},
		WaitingFor:   wait.ForLog("starting server"),
	}

	ctx := context.Background()
	validatorC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	defer testcontainers.CleanupContainer(t, validatorC)
	if err != nil {
		t.Fatal(err)
	}

	// We need to use PortEndpoint() rather than the simpler Endpoint()
	// because the varnish container used as a baseline for the validator
	// container includes "EXPOSE 80 8443" so we end up trying to use
	// 80/tcp in that case (which is not used at all for the validator
	// container). Also it is not possible to simply add our own EXPOSE in
	// the validator Dockerfile with port 8888, it is just appended to the
	// existing list rather than overriding the existing set.
	endpoint, err := validatorC.PortEndpoint(ctx, "8888/tcp", "")
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse("http://" + endpoint + "/validate-vcl")
	if err != nil {
		t.Fatal(err)
	}

	vclValidator := newVclValidator(u)

	ts, dbPool, err := prepareServer(false, vclValidator)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description     string
		username        string
		password        string
		expectedStatus  int
		newService      string
		orgNameOrID     string
		serviceNameOrID string
		domains         []string
		origins         []cdntypes.Origin
		active          bool
		vclRecvFile     string
	}{
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host:      "198.51.100.20",
					Port:      443,
					TLS:       true,
					VerifyTLS: true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusCreated,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: "198.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusCreated,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed superuser request with ID, domain not known",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"nonexistant.com"},
			origins: []cdntypes.Origin{
				{
					Host: "198.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed superuser request with ID, domain exist but not verified",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.nu"},
			origins: []cdntypes.Origin{
				{
					Host: "198.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed superuser request with ID, broken vcl_recv",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: "198.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/broken1.vcl",
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "org1",
			serviceNameOrID: "org1-service1",
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: "192.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusCreated,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed superuser request with name (name does not exist)",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "org1",
			serviceNameOrID: "does-not-exist",
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: "192.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed superuser request with too many domains",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"1.com", "2.com", "3.com", "4.com", "5.com", "6.com", "7.com", "8.com", "9.com", "10.com", "11.com"},
			origins: []cdntypes.Origin{
				{
					Host: "192.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed superuser request, too long Host in origin list",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: strings.Repeat("a", 254),
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed superuser request, too long domain in domains list",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{strings.Repeat("a", 254), "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: "192.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed superuser request with invalid service name (too long)",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "org1",
			serviceNameOrID: strings.Repeat("a", 64),
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: "192.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed superuser request with invalid uuid (too short)",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "org1",
			serviceNameOrID: "",
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: "192.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusUnprocessableEntity,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "successful user request",
			username:        "username1",
			password:        "password1",
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: "192.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusCreated,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
		{
			description:     "failed user request not assigned to org",
			username:        "username3-no-org",
			password:        "password3",
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			origins: []cdntypes.Origin{
				{
					Host: "192.51.100.20",
					Port: 443,
					TLS:  true,
				},
				{
					Host: "192.51.100.21",
					Port: 80,
					TLS:  false,
				},
			},
			expectedStatus: http.StatusForbidden,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
	}

	for _, test := range tests {
		newServiceVersion := struct {
			Org     string            `json:"org"`
			Active  bool              `json:"active"`
			Domains []string          `json:"domains"`
			Origins []cdntypes.Origin `json:"origins"`
			VclRecv string            `json:"vcl_recv"`
		}{
			Org:     test.orgNameOrID,
			Active:  test.active,
			Domains: test.domains,
			Origins: test.origins,
		}

		var vclRecvContentBytes []byte
		if test.vclRecvFile != "" {
			vclRecvContentBytes, err = os.ReadFile(test.vclRecvFile)
			if err != nil {
				t.Fatal(err)
			}
			newServiceVersion.VclRecv = string(vclRecvContentBytes)
		}

		b, err := json.Marshal(newServiceVersion)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(string(b))

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/service-versions", r)
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

func TestActivateServiceVersion(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description     string
		username        string
		password        string
		expectedStatus  int
		serviceNameOrID string
		orgNameOrID     string
		version         int64
		active          bool
	}{
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusNoContent,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         2,
			active:          true,
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusNoContent,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			version:         1,
			active:          true,
		},
		{
			description:     "failed superuser request with ID, not active",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         2,
			active:          false,
		},
		{
			description:     "failed superuser request with name, not active",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			version:         1,
			active:          false,
		},
		{
			description:     "failed superuser request with ID, non-existant version",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusNotFound,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         9999,
			active:          true,
		},
		{
			description:     "failed superuser request with ID, non-existant service ID",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-900000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         1,
			active:          true,
		},
		{
			description:     "failed superuser request with ID, non-existant org",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-900000000001",
			version:         1,
			active:          true,
		},
	}

	for _, test := range tests {
		active := struct {
			Active bool `json:"active"`
		}{
			Active: test.active,
		}

		b, err := json.Marshal(active)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(string(b))

		r := bytes.NewReader(b)

		req, err := http.NewRequest("PUT", ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/service-versions/"+strconv.FormatInt(test.version, 10)+"/active", r)
		if err != nil {
			t.Fatal(err)
		}

		values := req.URL.Query()
		values.Add("org", test.orgNameOrID)
		req.URL.RawQuery = values.Encode()

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

func TestGetServiceVersionVCL(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description     string
		username        string
		password        string
		expectedStatus  int
		serviceNameOrID string
		orgNameOrID     string
		version         int64
	}{
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         2,
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			version:         1,
		},
		{
			description:     "failed superuser request with ID, non-existant version",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusNotFound,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         9999,
		},
		{
			description:     "failed superuser request with ID, non-existant service ID",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-900000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         1,
		},
		{
			description:     "failed superuser request with ID, non-existant org",
			username:        "admin",
			password:        "adminpass1",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-900000000001",
			version:         1,
		},
		{
			description:     "successful org request",
			username:        "username1",
			password:        "password1",
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusOK,
			version:         1,
		},
		{
			description:     "failed org request, bad password",
			username:        "username1",
			password:        "badpassword1",
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusUnauthorized,
			version:         1,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/service-versions/"+strconv.FormatInt(test.version, 10)+"/vcl", nil)
		if err != nil {
			t.Fatal(err)
		}

		values := req.URL.Query()
		values.Add("org", test.orgNameOrID)
		req.URL.RawQuery = values.Encode()

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

func TestGetIPNetworks(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		family         int
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request, limit to ipv4",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
			family:         4,
		},
		{
			description:    "successful superuser request, limit to ipv6",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
			family:         6,
		},
		{
			description:    "failed superuser request, unknown family",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			family:         7,
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
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/ip-networks", nil)
		if err != nil {
			t.Fatal(err)
		}

		if test.family != 0 {
			values := req.URL.Query()
			values.Add("family", strconv.Itoa(test.family))
			req.URL.RawQuery = values.Encode()
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
			t.Fatalf("%s: GET ip-networks unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPostIPNetworks(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		addedIPNetwork netip.Prefix
	}{
		{
			description:    "successful IPv4 superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedIPNetwork: netip.MustParsePrefix("10.0.0.0/24"),
		},
		{
			description:    "failed IPv4 superuser request (network overlaps the one inserted above)",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusConflict,
			addedIPNetwork: netip.MustParsePrefix("10.0.0.0/25"),
		},
		{
			description:    "failed IPv4 (duplicate) superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusConflict,
			addedIPNetwork: netip.MustParsePrefix("10.0.0.0/24"),
		},
		{
			description:    "successful IPv6 superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			addedIPNetwork: netip.MustParsePrefix("2001:db8:1::/48"),
		},
		{
			description:    "failed IPv6 superuser request (network overlaps the one inserted above)",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusConflict,
			addedIPNetwork: netip.MustParsePrefix("2001:db8:1::/64"),
		},
		{
			description:    "failed IPv6 (duplicate) superuser request",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusConflict,
			addedIPNetwork: netip.MustParsePrefix("2001:db8:1::/48"),
		},
		{
			description:    "failed IPv6 non-superuser request",
			username:       "username1",
			password:       "password1",
			addedIPNetwork: netip.MustParsePrefix("2001:db8:3::/64"),
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed IPv4 non-superuser request",
			username:       "username1",
			password:       "password1",
			addedIPNetwork: netip.MustParsePrefix("10.0.0.0/24"),
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		newIPNetwork := struct {
			Network netip.Prefix `json:"network"`
		}{
			Network: test.addedIPNetwork,
		}

		b, err := json.Marshal(newIPNetwork)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/ip-networks", r)
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
			t.Fatalf("%s: POST ip-networks unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetCacheNodeConfigs(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
			description:    "successful user request with 'node' role",
			username:       "node-user-1",
			password:       "nodeuserpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed request, normal user not allowed to request config",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed user request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/cache-node-configs", nil)
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
			t.Fatalf("%s: GET cache-node-configs unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetL4LBNodeConfigs(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
			description:    "successful user request with 'node' role",
			username:       "node-user-1",
			password:       "nodeuserpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed request, normal user not allowed to request config",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed user request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/l4lb-node-configs", nil)
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
			t.Fatalf("%s: GET l4lb-node-configs unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestCamelCaseToSnakeCase(t *testing.T) {
	tests := []struct {
		description string
		input       string
		expected    string
	}{
		{
			description: "basic unexported",
			input:       "vclRecv",
			expected:    "vcl_recv",
		},
		{
			description: "basic exported",
			input:       "VclRecv",
			expected:    "vcl_recv",
		},
		{
			description: "all caps exported",
			input:       "VCLRecv",
			expected:    "vcl_recv",
		},
		{
			description: "all caps exported twice",
			input:       "VCLVCLRecv",
			expected:    "vcl_vcl_recv",
		},
		{
			description: "unexported backwards",
			input:       "recvVcl",
			expected:    "recv_vcl",
		},
		{
			description: "unexported backwards, all caps",
			input:       "recvVCL",
			expected:    "recv_vcl",
		},
		{
			description: "exported backwards",
			input:       "RecvVcl",
			expected:    "recv_vcl",
		},
		{
			description: "exported backwards, all caps",
			input:       "RecvVCL",
			expected:    "recv_vcl",
		},
	}

	for _, test := range tests {
		result := camelCaseToSnakeCase(test.input)
		if result != test.expected {
			t.Fatalf("%s: input '%s' resulted in '%s', expected: '%s'", test.description, test.input, result, test.expected)
		}
	}
}

func TestPostCacheNodes(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		cacheNodeDescr string
		ipv4Address    *netip.Addr
		ipv6Address    *netip.Addr
		name           string
	}{
		{
			description:    "successful superuser request with both addresses",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			cacheNodeDescr: "cache-node-post-1.example.com",
			ipv4Address:    Ptr(netip.MustParseAddr("127.0.0.1")),
			ipv6Address:    Ptr(netip.MustParseAddr("::1")),
			name:           "cache-node-post-1",
		},
		{
			description:    "successful superuser request without addresses",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			cacheNodeDescr: "cache-node-post-2-no-addrs.example.com",
			name:           "cache-node-post-2",
		},
		{
			description:    "successful superuser request with description right at limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			cacheNodeDescr: strings.Repeat("a", 100),
			ipv4Address:    Ptr(netip.MustParseAddr("127.0.0.2")),
			ipv6Address:    Ptr(netip.MustParseAddr("::2")),
			name:           "cache-node-post-3",
		},
		{
			description:    "failed superuser request with description above limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			cacheNodeDescr: strings.Repeat("a", 101),
			ipv4Address:    Ptr(netip.MustParseAddr("127.0.0.2")),
			ipv6Address:    Ptr(netip.MustParseAddr("::2")),
			name:           "cache-node-post-4",
		},
		{
			description:    "failed superuser request with description below limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			cacheNodeDescr: "",
			ipv4Address:    Ptr(netip.MustParseAddr("127.0.0.3")),
			ipv6Address:    Ptr(netip.MustParseAddr("::3")),
			name:           "cache-node-post-5",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
			cacheNodeDescr: "cache-node-post-6.example.com",
			ipv4Address:    Ptr(netip.MustParseAddr("127.0.0.4")),
			ipv6Address:    Ptr(netip.MustParseAddr("::4")),
			expectedStatus: http.StatusForbidden,
			name:           "cache-node-post-6",
		},
		{
			description:    "failed node user request",
			username:       "node-user-1",
			password:       "nodeuserpass1",
			cacheNodeDescr: "cache-node-post-user-1.example.com",
			ipv4Address:    Ptr(netip.MustParseAddr("127.0.0.5")),
			ipv6Address:    Ptr(netip.MustParseAddr("::5")),
			expectedStatus: http.StatusForbidden,
			name:           "cache-node-post-user-7",
		},
	}

	for _, test := range tests {
		newCacheNode := struct {
			Description string      `json:"description"`
			IPv4Address *netip.Addr `json:"ipv4_address,omitempty"`
			IPv6Address *netip.Addr `json:"ipv6_address,omitempty"`
			Name        string      `json:"name"`
		}{
			Description: test.cacheNodeDescr,
			IPv4Address: test.ipv4Address,
			IPv6Address: test.ipv6Address,
			Name:        test.name,
		}

		b, err := json.Marshal(newCacheNode)
		if err != nil {
			t.Fatal(err)
		}

		r := bytes.NewReader(b)

		req, err := http.NewRequest("POST", ts.URL+"/api/v1/cache-nodes", r)
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
			t.Fatalf("%s: POST cache-nodes unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestGetCacheNodes(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
			description:    "failed user request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed user request, bad password",
			username:       "username1",
			password:       "badpassword1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed node user request",
			username:       "node-user-1",
			password:       "nodeuserpass1",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		req, err := http.NewRequest("GET", ts.URL+"/api/v1/cache-nodes", nil)
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
			t.Fatalf("%s: GET cache-nodes unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}

func TestPutCacheNodeMaintenance(t *testing.T) {
	ts, dbPool, err := prepareServer(false, nil)
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
		maintenance       bool
		cacheNodeNameOrID string
		expectedStatus    int
	}{
		{
			description:       "successful superuser request with ID",
			username:          "admin",
			password:          "adminpass1",
			cacheNodeNameOrID: "00000015-0000-0000-0000-000000000001",
			maintenance:       true,
			expectedStatus:    http.StatusNoContent,
		},
		{
			description:       "successful superuser request with name",
			username:          "admin",
			password:          "adminpass1",
			cacheNodeNameOrID: "cache-node1",
			maintenance:       true,
			expectedStatus:    http.StatusNoContent,
		},
		{
			description:       "failed superuser request, bad password",
			username:          "admin",
			password:          "badadminpass1",
			cacheNodeNameOrID: "cache-node1",
			maintenance:       true,
			expectedStatus:    http.StatusUnauthorized,
		},
		{
			description:       "failed user request",
			username:          "username1",
			password:          "password1",
			cacheNodeNameOrID: "cache-node1",
			maintenance:       true,
			expectedStatus:    http.StatusForbidden,
		},
		{
			description:       "failed user request, bad password",
			username:          "username1",
			password:          "badpassword1",
			cacheNodeNameOrID: "cache-node1",
			maintenance:       true,
			expectedStatus:    http.StatusUnauthorized,
		},
		{
			description:       "failed user request, no password set",
			username:          "username4-no-pw",
			password:          "somepassword",
			cacheNodeNameOrID: "cache-node1",
			maintenance:       true,
			expectedStatus:    http.StatusUnauthorized,
		},
		{
			description:       "failed node user request",
			username:          "node-user-1",
			password:          "nodeuserpass1",
			cacheNodeNameOrID: "cache-node1",
			maintenance:       true,
			expectedStatus:    http.StatusForbidden,
		},
	}

	for _, test := range tests {
		maintenance := struct {
			Maintenance bool `json:"maintenance"`
		}{
			Maintenance: test.maintenance,
		}

		b, err := json.Marshal(maintenance)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println(string(b))

		r := bytes.NewReader(b)

		req, err := http.NewRequest("PUT", ts.URL+"/api/v1/cache-nodes/"+test.cacheNodeNameOrID+"/maintenance", r)
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
			t.Fatalf("%s: PUT cache-nodes maintenance unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
		}

		jsonData, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Printf("%s\n", jsonData)
	}
}
