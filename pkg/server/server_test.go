package server

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/SUNET/sunet-cdn-manager/pkg/config"
	"github.com/SUNET/sunet-cdn-manager/pkg/migrations"
	"github.com/SUNET/sunet-cdn-manager/pkg/testhelpers"
	"github.com/coreos/go-oidc/v3/oidc"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rs/zerolog"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Password length needs to be kept in sync with the
// /api/v1/users POST endpoint for user creation
const (
	validAdminPassword = "adminpass123456"
	validUserPassword  = "userpass1234567"

	// Constraint name from migration 00006_name_not_uuid.sql
	pgConstraintValidName = "valid_name"

	// User that connects to the database
	dbUser     = "cdn"
	dbPassword = "cdn-password"

	contentTypeJSON = "application/json"
)

var pgContainer *postgres.PostgresContainer

func TestMain(m *testing.M) {
	ctx := context.Background()
	var err error

	pgContainer, err = testhelpers.CreatePostgreSQLContainer(ctx)
	if err != nil {
		panic(err)
	}
	defer func() {
		err := testcontainers.TerminateContainer(pgContainer)
		if err != nil {
			panic(err)
		}
	}()

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		panic(err)
	}

	pgConfig, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		panic(err)
	}

	// Make sure tests do not hang even if they only have access to a single db connection
	pgConfig.MaxConns = 1

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		panic(fmt.Errorf("unable to create database pool: %w", err))
	}

	_, err = dbPool.Exec(ctx, fmt.Sprintf("CREATE USER %s WITH PASSWORD '%s'", dbUser, dbPassword))
	if err != nil {
		panic(fmt.Errorf("unable to create common 'cdn' user: %w", err))
	}

	// Each test opens its own connection
	dbPool.Close()

	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}

	m.Run()
}

func populateTestData(dbPool *pgxpool.Pool, encryptedSessionKey bool) error {
	ctx := context.Background()
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

		// Service origin groups (one default group per service version)
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000001', true, 'default', 0)",
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000002', true, 'default', 0)",
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-000000000003', '00000004-0000-0000-0000-000000000003', true, 'default', 0)",
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-000000000004', '00000004-0000-0000-0000-000000000004', true, 'default', 0)",
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-000000000005', '00000004-0000-0000-0000-000000000005', true, 'default', 0)",
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-000000000006', '00000004-0000-0000-0000-000000000006', true, 'default', 0)",
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-000000000007', '00000004-0000-0000-0000-000000000007', true, 'default', 0)",
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-000000000008', '00000004-0000-0000-0000-000000000008', true, 'default', 0)",
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-000000000009', '00000004-0000-0000-0000-000000000009', true, 'default', 0)",

		// Roles
		"INSERT INTO roles (id, name, superuser) VALUES ('00000005-0000-0000-0000-000000000001', 'admin', TRUE)",
		"INSERT INTO roles (id, name) VALUES ('00000005-0000-0000-0000-000000000002', 'user')",
		"INSERT INTO roles (id, name) VALUES ('00000005-0000-0000-0000-000000000003', 'node')",

		// Domains
		"INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000001', '00000002-0000-0000-0000-000000000001', 'example.se', true, 'token1')",
		"INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000002', '00000002-0000-0000-0000-000000000001', 'example.com', true, 'token2')",
		"INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000003', '00000002-0000-0000-0000-000000000001', 'example.nu', false, 'token2')",
		"INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000004', '00000002-0000-0000-0000-000000000001', 'example-delete-1.se', true, 'token-del-1')",
		"INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000005', '00000002-0000-0000-0000-000000000001', 'example-delete-2.se', true, 'token2-del-2')",
		"INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000006', '00000002-0000-0000-0000-000000000001', 'example-delete-3.se', false, 'token2-del-3')",
		"INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000007', '00000002-0000-0000-0000-000000000001', 'example-delete-4.se', false, 'token2-del-4')",
		"INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000008', '00000002-0000-0000-0000-000000000001', 'example-delete-5.se', false, 'token2-del-5')",

		// Service domain mappings (only valid if the domains-entry is verified=true)
		// org1: www.example.se
		"INSERT INTO service_domains (id, service_version_id, domain_id) VALUES ('00000008-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', '00000015-0000-0000-0000-000000000001')",
		// org1: www.example.com
		"INSERT INTO service_domains (id, service_version_id, domain_id) VALUES ('00000008-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', '00000015-0000-0000-0000-000000000002')",

		// Origins
		// org1-service1-version3
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', '00000020-0000-0000-0000-000000000003', '198.51.100.10', 80, false)",
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', '00000020-0000-0000-0000-000000000003', '198.51.100.11', 443, true)",
		// org1-service1-version2
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000003', '00000004-0000-0000-0000-000000000002', '00000020-0000-0000-0000-000000000002', '198.51.100.10', 80, false)",
		// org1-service1-version1
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000004', '00000004-0000-0000-0000-000000000001', '00000020-0000-0000-0000-000000000001', '198.51.100.10', 80, false)",

		// org2-service1-version2
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000005', '00000004-0000-0000-0000-000000000005', '00000020-0000-0000-0000-000000000005', '198.51.100.20', 80, false)",

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
		// org1, org1-service2
		"INSERT INTO service_ip_addresses (id, network_id, service_id, address) VALUES ('00000013-0000-0000-0000-000000000003', '00000011-0000-0000-0000-000000000001', '00000003-0000-0000-0000-000000000002', '192.0.2.2')",
		"INSERT INTO service_ip_addresses (id, network_id, service_id, address) VALUES ('00000013-0000-0000-0000-000000000004', '00000012-0000-0000-0000-000000000001', '00000003-0000-0000-0000-000000000002', '2001:db8:0::2')",

		// Users
		// No org, local user
		"INSERT INTO users (id, role_id, auth_provider_id, display_name) VALUES ('00000014-0000-0000-0000-000000000001', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000001', 'put-user-1')",
		"INSERT INTO user_argon2keys (id, user_id, key, salt, time, memory, threads, tag_size) VALUES ('00000017-0000-0000-0000-000000000001', '00000014-0000-0000-0000-000000000001', '\\x00', '\\x00', 3, 65536, 4, 32)",
		// No org, local users, used to test DELETE
		"INSERT INTO users (id, role_id, auth_provider_id, display_name) VALUES ('00000014-0000-0000-0000-000000000002', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000001', 'delete-local-user-1')",
		"INSERT INTO user_argon2keys (id, user_id, key, salt, time, memory, threads, tag_size) VALUES ('00000017-0000-0000-0000-000000000002', '00000014-0000-0000-0000-000000000002', '\\x00', '\\x00', 3, 65536, 4, 32)",
		"INSERT INTO users (id, role_id, auth_provider_id, display_name) VALUES ('00000014-0000-0000-0000-000000000003', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000001', 'delete-local-user-2')",
		"INSERT INTO user_argon2keys (id, user_id, key, salt, time, memory, threads, tag_size) VALUES ('00000017-0000-0000-0000-000000000003', '00000014-0000-0000-0000-000000000003', '\\x00', '\\x00', 3, 65536, 4, 32)",
		// No org, keycloak users, used to test DELETE
		"INSERT INTO users (id, role_id, auth_provider_id, display_name) VALUES ('00000014-0000-0000-0000-000000000004', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000002', 'delete-keycloak-user-1')",
		"INSERT INTO auth_provider_keycloak (id, user_id, subject) VALUES ('00000018-0000-0000-0000-000000000001', '00000014-0000-0000-0000-000000000004', '00000019-0000-0000-0000-000000000001')",
		"INSERT INTO users (id, role_id, auth_provider_id, display_name) VALUES ('00000014-0000-0000-0000-000000000005', '00000005-0000-0000-0000-000000000002', '00000010-0000-0000-0000-000000000002', 'delete-keycloak-user-2')",
		"INSERT INTO auth_provider_keycloak (id, user_id, subject) VALUES ('00000018-0000-0000-0000-000000000002', '00000014-0000-0000-0000-000000000005', '00000019-0000-0000-0000-000000000002')",

		// Node groups
		"INSERT INTO node_groups (id, name, description) VALUES ('00000021-0000-0000-0000-000000000001', 'node-group-1', 'A node group, number 1')",
		"INSERT INTO node_groups (id, name, description) VALUES ('00000021-0000-0000-0000-000000000002', 'node-group-2', 'A node group, number 2')",

		// Cache nodes
		"INSERT INTO cache_nodes (id, name, description) VALUES ('00000022-0000-0000-0000-000000000001', 'cache-node1', 'A cache node, cache-node1.example.com')",
		"INSERT INTO cache_node_addresses (id, node_id, address) VALUES ('00000023-0000-0000-0000-000000000001', '00000022-0000-0000-0000-000000000001', '127.0.0.100')",
		"INSERT INTO cache_node_addresses (id, node_id, address) VALUES ('00000023-0000-0000-0000-000000000002', '00000022-0000-0000-0000-000000000001', '::1337')",

		"INSERT INTO cache_nodes (id, name, description) VALUES ('00000022-0000-0000-0000-000000000002', 'cache-node2', 'A cache node, cache-node2.example.com, no addresses')",

		"INSERT INTO cache_nodes (id, name, description, node_group_id) VALUES ('00000022-0000-0000-0000-000000000003', 'cache-node3', 'A cache node, member of node-group-1', '00000021-0000-0000-0000-000000000001')",
		"INSERT INTO cache_node_addresses (id, node_id, address) VALUES ('00000023-0000-0000-0000-000000000003', '00000022-0000-0000-0000-000000000003', '127.0.0.101')",
		"INSERT INTO cache_node_addresses (id, node_id, address) VALUES ('00000023-0000-0000-0000-000000000004', '00000022-0000-0000-0000-000000000003', '::1338')",

		"INSERT INTO cache_nodes (id, name, description, node_group_id) VALUES ('00000022-0000-0000-0000-000000000004', 'cache-node4', 'A cache node, also member of node-group-1', '00000021-0000-0000-0000-000000000001')",
		"INSERT INTO cache_node_addresses (id, node_id, address) VALUES ('00000023-0000-0000-0000-000000000005', '00000022-0000-0000-0000-000000000004', '127.0.0.102')",
		"INSERT INTO cache_node_addresses (id, node_id, address) VALUES ('00000023-0000-0000-0000-000000000006', '00000022-0000-0000-0000-000000000004', '::1339')",

		"INSERT INTO cache_nodes (id, name, description) VALUES ('00000022-0000-0000-0000-000000000005', 'cache-node5-no-group', 'A cache node, not yet member of a node group')",
		"INSERT INTO cache_node_addresses (id, node_id, address) VALUES ('00000023-0000-0000-0000-000000000007', '00000022-0000-0000-0000-000000000005', '127.0.0.103')",
		"INSERT INTO cache_node_addresses (id, node_id, address) VALUES ('00000023-0000-0000-0000-000000000008', '00000022-0000-0000-0000-000000000005', '::1340')",

		// L4LB nodes
		"INSERT INTO l4lb_nodes (id, name, description) VALUES ('00000016-0000-0000-0000-000000000001', 'l4lb-node1', 'A l4lb node, l4lb-node1.example.com')",
		"INSERT INTO l4lb_node_addresses (id, node_id, address) VALUES ('00000024-0000-0000-0000-000000000001', '00000016-0000-0000-0000-000000000001', '127.0.0.200')",
		"INSERT INTO l4lb_node_addresses (id, node_id, address) VALUES ('00000024-0000-0000-0000-000000000002', '00000016-0000-0000-0000-000000000001', '::1347')",

		"INSERT INTO l4lb_nodes (id, name, description) VALUES ('00000016-0000-0000-0000-000000000002', 'l4lb-node2', 'A l4lb node, l4lb-node2.example.com, no addresses')",

		"INSERT INTO l4lb_nodes (id, name, description, node_group_id) VALUES ('00000016-0000-0000-0000-000000000003', 'l4lb-node3', 'A l4lb node, member of node-group-1', '00000021-0000-0000-0000-000000000001')",
		"INSERT INTO l4lb_node_addresses (id, node_id, address) VALUES ('00000024-0000-0000-0000-000000000003', '00000016-0000-0000-0000-000000000003', '127.0.0.201')",
		"INSERT INTO l4lb_node_addresses (id, node_id, address) VALUES ('00000024-0000-0000-0000-000000000004', '00000016-0000-0000-0000-000000000003', '::1348')",

		"INSERT INTO l4lb_nodes (id, name, description, node_group_id) VALUES ('00000016-0000-0000-0000-000000000004', 'l4lb-node4', 'A l4lb node, also member of node-group-1', '00000021-0000-0000-0000-000000000001')",
		"INSERT INTO l4lb_node_addresses (id, node_id, address) VALUES ('00000024-0000-0000-0000-000000000005', '00000016-0000-0000-0000-000000000004', '127.0.0.202')",
		"INSERT INTO l4lb_node_addresses (id, node_id, address) VALUES ('00000024-0000-0000-0000-000000000006', '00000016-0000-0000-0000-000000000004', '::1349')",

		"INSERT INTO l4lb_nodes (id, name, description) VALUES ('00000016-0000-0000-0000-000000000005', 'l4lb-node5-no-group', 'A l4lb node, not yet member of a node group')",
		"INSERT INTO l4lb_node_addresses (id, node_id, address) VALUES ('00000024-0000-0000-0000-000000000007', '00000016-0000-0000-0000-000000000005', '127.0.0.203')",
		"INSERT INTO l4lb_node_addresses (id, node_id, address) VALUES ('00000024-0000-0000-0000-000000000008', '00000016-0000-0000-0000-000000000005', '::1350')",
	}

	err := pgx.BeginFunc(ctx, dbPool, func(tx pgx.Tx) error {
		for _, sql := range testData {
			_, err := tx.Exec(ctx, sql)
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
				password:     validAdminPassword,
				role:         "admin",
				id:           "00000006-0000-0000-0000-000000000001",
				authProvider: "local",
			},
			{
				name:         "username1",
				password:     validUserPassword,
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
			{
				name:         "admin-with-org",
				password:     validAdminPassword,
				role:         "admin",
				orgName:      "org1",
				id:           "00000006-0000-0000-0000-000000000009",
				authProvider: "local",
			},
			{
				// A non-superuser, org2 member with a console-login-capable
				// (>= 15 char) password, used to prove that org1 actions are
				// refused for someone outside org1. "username2" already
				// exists for org2 but its short password only satisfies the
				// HTTP Basic Auth API tests, not the console login forms
				// stricter length validation.
				name:         "username7",
				password:     validUserPassword,
				role:         "user",
				orgName:      "org2",
				id:           "00000006-0000-0000-0000-000000000010",
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
				err := tx.QueryRow(ctx, "SELECT id FROM orgs WHERE name=$1", localUser.orgName).Scan(&orgID)
				if err != nil {
					return err
				}
			}

			err = tx.QueryRow(ctx, "SELECT id FROM auth_providers WHERE name=$1", localUser.authProvider).Scan(&authProviderID)
			if err != nil {
				return err
			}

			_, err = tx.Exec(ctx, "INSERT INTO users (id, org_id, display_name, role_id, auth_provider_id) VALUES ($1, $2, $3, (SELECT id FROM roles WHERE name=$4), (SELECT id from auth_providers WHERE name=$5))", userID, orgID, localUser.name, localUser.role, localUser.authProvider)
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
				_, err = tx.Exec(ctx, "INSERT INTO user_argon2keys (user_id, key, salt, time, memory, threads, tag_size) VALUES ($1, $2, $3, $4, $5, $6, $7)", userID, key, salt, timeSize, memorySize, threads, tagSize)
				if err != nil {
					return err
				}
			}
		}

		vcls := []struct {
			id               string
			vclTemplateFile  string
			serviceVersionID string
		}{
			{
				id:               "00000007-0000-0000-0000-000000000001",
				serviceVersionID: "00000004-0000-0000-0000-000000000001",
				vclTemplateFile:  "testdata/vcl/template1.vcl",
			},
			{
				id:               "00000007-0000-0000-0000-000000000002",
				serviceVersionID: "00000004-0000-0000-0000-000000000002",
				vclTemplateFile:  "testdata/vcl/template1.vcl",
			},
			{
				id:               "00000007-0000-0000-0000-000000000003",
				serviceVersionID: "00000004-0000-0000-0000-000000000003",
				vclTemplateFile:  "testdata/vcl/template1.vcl",
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

			var vclTemplateContentBytes []byte
			if vcl.vclTemplateFile != "" {
				vclTemplateContentBytes, err = os.ReadFile(vcl.vclTemplateFile)
				if err != nil {
					return err
				}
			}

			_, err = tx.Exec(ctx, "INSERT INTO service_vcls (id, service_version_id, vcl_template) VALUES($1, $2, $3)", vclID, serviceVersionID, vclTemplateContentBytes)
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

		_, err = insertGorillaSessionKey(ctx, tx, gorillaAuthKey, gorillaEncKey)
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

type testServerInput struct {
	encryptedSessionKey  bool
	vclValidator         *vclValidatorClient
	kcClientManager      *keycloakClientManager
	jwkCache             *jwk.Cache
	jwtIssuer            string
	oiConf               openidConfig
	encryptionPasswords  []string
	dbPool               *pgxpool.Pool
	consoleSessionMaxAge time.Duration
	consoleSessionCapAge time.Duration
}

func getTestDatabaseConfig(ctx context.Context, t *testing.T) (*pgxpool.Config, error) {
	t.Helper()

	pgurl, err := testhelpers.CreateDatabase(ctx, t, pgContainer)
	if err != nil {
		return nil, err
	}

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		return nil, err
	}

	// Make sure tests do not hang even if they only have access to a single db connection
	pgConfig.MaxConns = 1

	t.Log(pgConfig.ConnString())

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create database pool: %w", err)
	}
	defer dbPool.Close()

	// Mimic initial setup done by init-cdn-db.sh on our real database
	// servers. But instead of creating a "cdn" database we use use the randomized
	// database that was given to us by testhelpers.CreateDatabase(). Since the
	// psql test server is shared between tests it would not work if each
	// test tried to create its own "cdn" database.
	//
	// Because search_path (SHOW search_path;) starts with "$user" by
	// default this means any tables will be created in that user-specific
	// SCHEMA by default instead of falling back to "public". This follows
	// the "secure schema usage pattern" summarized as "Constrain ordinary
	// users to user-private schemas" from
	// https://www.postgresql.org/docs/current/ddl-schemas.html#DDL-SCHEMAS-PATTERNS
	//
	// "In PostgreSQL 15 and later, the default configuration supports this usage
	// pattern. In prior versions, or when using a database that has been upgraded
	// from a prior version, you will need to remove the public CREATE privilege
	// from the public schema"
	bootstrapSQLs := []string{
		fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE \"%s\" TO %s", pgConfig.ConnConfig.Database, dbUser),
		fmt.Sprintf("CREATE SCHEMA %s AUTHORIZATION %s", dbUser, dbUser),
	}

	for _, bootstrapSQL := range bootstrapSQLs {
		_, err := dbPool.Exec(ctx, bootstrapSQL)
		if err != nil {
			return nil, fmt.Errorf("unable to bootstrap cdn database: %w", err)
		}
	}

	// Switch over to the cdn user so the default search_path automatically
	// inserts things in the "cdn" ($user) schema.
	pgConfig.ConnConfig.User = dbUser
	pgConfig.ConnConfig.Password = dbPassword

	return pgConfig, nil
}

func initDatabase(ctx context.Context, t *testing.T, logger zerolog.Logger, encryptedSessionKey bool) (*pgxpool.Pool, error) {
	pgConfig, err := getTestDatabaseConfig(ctx, t)
	if err != nil {
		return nil, err
	}

	err = migrations.Up(ctx, logger, pgConfig)
	if err != nil {
		return nil, err
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create database pool for cdn user: %w", err)
	}

	err = populateTestData(dbPool, encryptedSessionKey)
	if err != nil {
		dbPool.Close()
		return nil, err
	}

	return dbPool, nil
}

func prepareServer(t *testing.T, tsi testServerInput) (*httptest.Server, *pgxpool.Pool, error) {
	ctx := context.Background()

	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Caller().Logger()

	dbPoolCreated := false

	// If no dbpool has been created ahead of time create a new one
	if tsi.dbPool == nil {
		var err error
		tsi.dbPool, err = initDatabase(ctx, t, logger, tsi.encryptedSessionKey)
		if err != nil {
			return nil, nil, err
		}
		dbPoolCreated = true
	}

	if tsi.consoleSessionMaxAge == 0 {
		tsi.consoleSessionMaxAge = 1 * time.Hour
	}

	cookieStore, err := getSessionStore(ctx, logger, tsi.dbPool, tsi.consoleSessionMaxAge)
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		return nil, nil, err
	}

	confTemplates, err := newConfigTemplates()
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		t.Fatalf("unable to create config templates: %v", err)
	}

	var argon2Mutex sync.Mutex

	loginCache, err := lru.New[string, struct{}](128)
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		t.Fatalf("unable to create LRU login cache: %v", err)
	}

	dbc, err := newDBConn(tsi.dbPool, 30*time.Second)
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		t.Fatalf("unable to create dbConn struct: %v", err)
	}

	a2Settings := newArgon2DefaultSettings()

	salt, err := saltFromHex("36023a78c7d2000ac58604da1b630a9f")
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		t.Fatalf("unable to create salt: %v", err)
	}

	if len(tsi.encryptionPasswords) == 0 {
		tsi.encryptionPasswords = []string{
			"test-encryption-password",
		}
	}

	var clientCredAEADs []cipher.AEAD

	for _, encPassword := range tsi.encryptionPasswords {
		clientCredKey := argon2.IDKey(
			[]byte(encPassword),
			salt,
			a2Settings.argonTime,
			a2Settings.argonMemory,
			a2Settings.argonThreads,
			chacha20poly1305.KeySize,
		)

		clientCredAEAD, err := chacha20poly1305.NewX(clientCredKey)
		if err != nil {
			if dbPoolCreated {
				tsi.dbPool.Close()
			}
			t.Fatalf("unable to create client cred AEAD: %v", err)
		}

		clientCredAEADs = append(clientCredAEADs, clientCredAEAD)
	}

	ts := httptest.NewUnstartedServer(nil)

	// ts.URL is not filled in until ts.Start() is called, but we need the
	// server URL to fill in the router we want to pass as the handler, so
	// extract it manually here (the same way Start() fills in the URL
	// field).
	serverURL, err := url.Parse("http://" + ts.Listener.Addr().String())
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		ts.Close()
		t.Fatalf("unable to parse testserver URL: %v", err)
	}

	if tsi.consoleSessionCapAge == 0 {
		tsi.consoleSessionCapAge = 8 * time.Hour
	}

	conf := config.Config{}
	conf.Server.ConsoleSessionCapAge = tsi.consoleSessionCapAge

	router := newChiRouter(conf, logger, dbc, &argon2Mutex, loginCache, cookieStore, nil, tsi.vclValidator, confTemplates, false, clientCredAEADs, tsi.kcClientManager, &url.URL{}, serverURL)

	ts.Config.Handler = router

	err = setupHumaAPI(router, dbc, &argon2Mutex, loginCache, tsi.vclValidator, confTemplates, tsi.kcClientManager, tsi.jwkCache, tsi.jwtIssuer, tsi.oiConf, clientCredAEADs, serverURL)
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		ts.Close()
		return nil, nil, err
	}

	ts.Start()

	// We only return the dbPool if it was created here, otherwise the
	// caller is expected to handle closing themselves
	if dbPoolCreated {
		return ts, tsi.dbPool, nil
	}
	return ts, nil, nil
}

func TestServerInit(t *testing.T) {
	ctx := context.Background()
	pgConfig, err := getTestDatabaseConfig(ctx, t)
	if err != nil {
		t.Fatal(err)
	}

	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Caller().Logger()

	initPassword := "test-server-init"

	u, err := Init(logger, pgConfig, false, initPassword)
	if err != nil {
		t.Fatal(err)
	}

	expectedUsername := "admin"

	if u.Name() != expectedUsername {
		t.Fatalf("expected initial user '%s', got: '%s'", expectedUsername, u.Name())
	}
}

func TestSessionKeyHandlingNoEnc(t *testing.T) {
	ctx := context.Background()
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	// Try inserting additional session keys with nil encryptionKey
	numAdded := 2
	for range numAdded {
		gorillaAuthKey, err := generateRandomKey(32)
		if err != nil {
			t.Fatal(err)
		}
		err = pgx.BeginFunc(ctx, dbPool, func(tx pgx.Tx) error {
			_, err = insertGorillaSessionKey(ctx, tx, gorillaAuthKey, nil)
			if err != nil {
				return err
			}

			return nil
		})
	}

	rows, err := dbPool.Query(ctx, "SELECT id, time_created, key_order, auth_key, enc_key FROM gorilla_session_keys")
	if err != nil {
		t.Fatal(err)
	}

	var keyOrderMax int64

	var id pgtype.UUID
	var timeCreated time.Time
	var keyOrder int64
	var authKey, encKey []byte
	_, err = pgx.ForEachRow(rows, []any{&id, &timeCreated, &keyOrder, &authKey, &encKey}, func() error {
		t.Logf("id: %s, time_created: %s, key_order: %d, auth_key len: %d, enc_key len: %d\n", id, timeCreated, keyOrder, len(authKey), len(encKey))

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
	ctx := context.Background()
	ts, dbPool, err := prepareServer(t, testServerInput{encryptedSessionKey: true})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	// Try inserting additional session keys with nil encryptionKey
	numAdded := 2
	for range numAdded {
		gorillaAuthKey, err := generateRandomKey(32)
		if err != nil {
			t.Fatal(err)
		}

		gorillaEncKey, err := generateRandomKey(32)
		if err != nil {
			t.Fatal(err)
		}
		err = pgx.BeginFunc(ctx, dbPool, func(tx pgx.Tx) error {
			_, err = insertGorillaSessionKey(ctx, tx, gorillaAuthKey, gorillaEncKey)
			if err != nil {
				return err
			}

			return nil
		})
	}

	rows, err := dbPool.Query(ctx, "SELECT id, time_created, key_order, auth_key, enc_key FROM gorilla_session_keys")
	if err != nil {
		t.Fatal(err)
	}

	var keyOrderMax int64

	var id pgtype.UUID
	var timeCreated time.Time
	var keyOrder int64
	var authKey, encKey []byte
	_, err = pgx.ForEachRow(rows, []any{&id, &timeCreated, &keyOrder, &authKey, &encKey}, func() error {
		t.Logf("id: %s, time_created: %s, key_order: %d, auth_key len: %d, enc_key len: %d\n", id, timeCreated, keyOrder, len(authKey), len(encKey))

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
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
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
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/users", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET users unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetUser(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		userID         string
		expectedStatus int
	}{
		{
			description:    "successful superuser request with ID",
			username:       "admin",
			password:       validAdminPassword,
			userID:         "00000006-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful user request for itself with ID",
			username:       "username1",
			password:       validUserPassword,
			userID:         "00000006-0000-0000-0000-000000000002",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed user request, bad password",
			username:       "username1",
			password:       "badpassword1",
			userID:         "00000006-0000-0000-0000-000000000001",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			userID:         "00000006-0000-0000-0000-000000000005",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed lookup of another user with ID",
			username:       "username2",
			password:       "password2",
			userID:         "00000006-0000-0000-0000-000000000001",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed request with invalid UUID",
			username:       "admin",
			password:       validAdminPassword,
			userID:         "not-a-uuid",
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/users/"+test.userID, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET users/%s unexpected status code: %d (%s)", test.userID, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPostUsers(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			addedUser:      "admin-created-user-1",
			roleIDorName:   "00000005-0000-0000-0000-000000000002",
			orgIDorName:    "00000002-0000-0000-0000-000000000001",
		},
		{
			description:    "successful superuser request with names",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			addedUser:      "admin-created-user-2",
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "successful superuser request with IDs and no org",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			addedUser:      "admin-created-user-3",
			roleIDorName:   "00000005-0000-0000-0000-000000000002",
			orgIDorName:    "",
		},
		{
			description:    "successful superuser request with name right at limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			addedUser:      strings.Repeat("a", 63),
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "failed superuser request with name above limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			addedUser:      strings.Repeat("a", 64),
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "failed superuser request with name below limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			addedUser:      "",
			roleIDorName:   "user",
			orgIDorName:    "org1",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			newUser := struct {
				DisplayName string `json:"display_name"`
				Role        string `json:"role"`
				Org         string `json:"org,omitempty"`
			}{
				DisplayName: test.addedUser,
				Org:         test.orgIDorName,
				Role:        test.roleIDorName,
			}

			b, err := json.Marshal(newUser)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/users", r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
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

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPutUser(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		targetUserID        string
		updatedOrgIDorName  string
		updatedRoleIDorName string
		updatedName         string
	}{
		{
			description:         "successful superuser request with IDs",
			username:            "admin",
			password:            validAdminPassword,
			expectedStatus:      http.StatusOK,
			targetUserID:        "00000014-0000-0000-0000-000000000001",
			updatedOrgIDorName:  "00000002-0000-0000-0000-000000000001",
			updatedRoleIDorName: "00000005-0000-0000-0000-000000000002",
			updatedName:         "put-user-1",
		},
		{
			description:         "successful superuser request with names for org and role",
			username:            "admin",
			password:            validAdminPassword,
			expectedStatus:      http.StatusOK,
			targetUserID:        "00000014-0000-0000-0000-000000000001",
			updatedName:         "put-user-1",
			updatedOrgIDorName:  "org2",
			updatedRoleIDorName: "user",
		},
		{
			description:         "successful superuser request, null org",
			username:            "admin",
			password:            validAdminPassword,
			expectedStatus:      http.StatusOK,
			targetUserID:        "00000014-0000-0000-0000-000000000001",
			updatedName:         "put-user-1",
			updatedOrgIDorName:  "",
			updatedRoleIDorName: "user",
		},
		{
			description:         "failed non-superuser request",
			username:            "username1",
			password:            validUserPassword,
			expectedStatus:      http.StatusForbidden,
			targetUserID:        "00000006-0000-0000-0000-000000000002",
			updatedName:         "username1",
			updatedOrgIDorName:  "org1",
			updatedRoleIDorName: "user",
		},
		{
			description:         "failed rename of keycloak user",
			username:            "admin",
			password:            validAdminPassword,
			expectedStatus:      http.StatusUnprocessableEntity,
			targetUserID:        "00000014-0000-0000-0000-000000000004",
			updatedName:         "renamed-keycloak-user",
			updatedOrgIDorName:  "",
			updatedRoleIDorName: "user",
		},
		{
			description:         "failed request with invalid UUID",
			username:            "admin",
			password:            validAdminPassword,
			expectedStatus:      http.StatusUnprocessableEntity,
			targetUserID:        "not-a-uuid",
			updatedName:         "some-user",
			updatedOrgIDorName:  "org1",
			updatedRoleIDorName: "user",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			putUser := struct {
				Org         string `json:"org,omitempty"`
				Role        string `json:"role"`
				DisplayName string `json:"display_name"`
			}{
				Org:         test.updatedOrgIDorName,
				Role:        test.updatedRoleIDorName,
				DisplayName: test.updatedName,
			}

			b, err := json.Marshal(putUser)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			t.Log(string(b))

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/users/"+test.targetUserID, r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT users unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestDeleteUser(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		targetUserID   string
	}{
		{
			description:    "successful superuser request for local user",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNoContent,
			targetUserID:   "00000014-0000-0000-0000-000000000002",
		},
		{
			description:    "successful superuser request for local user 2",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNoContent,
			targetUserID:   "00000014-0000-0000-0000-000000000003",
		},
		{
			description:    "successful superuser request for keycloak user",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNoContent,
			targetUserID:   "00000014-0000-0000-0000-000000000004",
		},
		{
			description:    "successful superuser request for keycloak user 2",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNoContent,
			targetUserID:   "00000014-0000-0000-0000-000000000005",
		},
		{
			description:    "failed superuser request trying to remove itself",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusForbidden,
			targetUserID:   "00000006-0000-0000-0000-000000000001",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
			targetUserID:   "00000006-0000-0000-0000-000000000001",
		},
		{
			description:    "failed request with invalid UUID",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			targetUserID:   "not-a-uuid",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ctx := context.Background()
			testQuery := "SELECT display_name, id FROM users WHERE id = $1"

			// Only verify DB state for valid UUIDs
			var checkUUID pgtype.UUID
			validUUID := checkUUID.Scan(test.targetUserID) == nil

			if validUUID {
				// Verify user exists prior to deletion
				var displayName string
				var id pgtype.UUID
				err := dbPool.QueryRow(ctx, testQuery, test.targetUserID).Scan(&displayName, &id)
				if err != nil {
					t.Fatal(err)
				}
			}

			req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/users/"+test.targetUserID, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("DELETE user unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)

			if validUUID {
				// Verify user is removed if a http.StatusNoContent was returned, otherwise they are expected to still exist
				var displayName string
				var id pgtype.UUID
				err = dbPool.QueryRow(ctx, testQuery, test.targetUserID).Scan(&displayName, &id)
				if err == nil {
					if test.expectedStatus == http.StatusNoContent {
						// The delete seemed successful, why are they still in the db
						t.Fatalf("user is not deleted as expected, display_name: '%s', id: '%s'", displayName, id)
					}
				} else {
					if !errors.Is(err, pgx.ErrNoRows) {
						t.Fatalf("user deleted pre-check unexpected error: '%s', id: '%s', %s", displayName, id, err)
					}
					if test.expectedStatus != http.StatusNoContent {
						t.Fatalf("database returned no rows, but the delete should have been forbidden: '%s', id: '%s', %s", displayName, id, err)
					}
				}
			}
		})
	}
}

func TestPutPassword(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		modifiedUserID string
		modifiedUser   string
		oldPassword    string
		newPassword    string
	}{
		{
			description:    "successful superuser request with IDs",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNoContent,
			modifiedUserID: "00000006-0000-0000-0000-000000000005",
			modifiedUser:   "username4-no-pw",
			oldPassword:    "",
			newPassword:    "updated-password-1",
		},
		{
			description:    "failed request for user missing password",
			username:       "username4-no-pw",
			password:       "",
			expectedStatus: http.StatusUnauthorized,
			modifiedUserID: "00000006-0000-0000-0000-000000000006",
			modifiedUser:   "username5-no-pw",
			oldPassword:    "",
			newPassword:    "updated-password-2",
		},
		{
			description:    "successful request for user changing their own password",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusNoContent,
			modifiedUserID: "00000006-0000-0000-0000-000000000002",
			modifiedUser:   "username1",
			oldPassword:    validUserPassword,
			newPassword:    "updated-password-3",
		},
		{
			description:    "failed request for user changing their own password with the wrong old password",
			username:       "username6",
			password:       "password6",
			expectedStatus: http.StatusBadRequest,
			modifiedUserID: "00000006-0000-0000-0000-000000000007",
			modifiedUser:   "username6",
			oldPassword:    "password6-wrong",
			newPassword:    "updated-password-4",
		},
		{
			description:    "failed request for keycloak user",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			modifiedUserID: "00000014-0000-0000-0000-000000000004",
			modifiedUser:   "delete-keycloak-user-1",
			oldPassword:    "",
			newPassword:    "keycloak-password-1",
		},
		{
			description:    "failed request with invalid UUID",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			modifiedUserID: "not-a-uuid",
			modifiedUser:   "not-a-uuid",
			oldPassword:    "",
			newPassword:    "some-new-password-1",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
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

			t.Log(string(b))

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/users/"+test.modifiedUserID+"/local-password", r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT local-password unexpected status code: want %d, got: %d (%s)", test.expectedStatus, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)

			// Verify password state is consistent with the expected outcome.
			// Only testable when the modified user has a valid UUID
			// (keycloak users and invalid UUIDs cannot be verified via
			// basic auth).
			var checkUUID pgtype.UUID
			if checkUUID.Scan(test.modifiedUserID) != nil {
				return
			}

			if test.expectedStatus == http.StatusNoContent {
				// Password was changed: new password must work
				statusCode, err := testAuth(t, ts, test.modifiedUser, test.modifiedUserID, test.newPassword)
				if err != nil {
					t.Fatal(err)
				}
				if statusCode != http.StatusOK {
					t.Fatal(fmt.Errorf("unexected status code: %d", statusCode))
				}
			} else {
				// Password was NOT changed: new password must not work
				statusCode, err := testAuth(t, ts, test.modifiedUser, test.modifiedUserID, test.newPassword)
				if err == nil {
					t.Fatal(errors.New("new password works after failed update, unexpected"))
				}
				if statusCode != http.StatusUnauthorized {
					t.Fatal(fmt.Errorf("unexected status code: %d", statusCode))
				}
			}
		})
	}
}

func testAuth(t *testing.T, ts *httptest.Server, username string, userID string, password string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/users/"+userID, nil)
	if err != nil {
		return 0, err
	}

	req.SetBasicAuth(username, password)

	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
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

	t.Log(string(b))

	return resp.StatusCode, nil
}

func TestGetOrgs(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
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
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/orgs", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET orgs unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetOrgClientCredentials(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       validAdminPassword,
			nameOrID:       "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with ID",
			username:       "username1",
			password:       validUserPassword,
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with name",
			username:       "username1",
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/orgs/"+test.nameOrID+"/client-credentials", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET orgs/%s unexpected status code: %d (%s)", test.nameOrID, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

// {"id":"1af03a7c-735a-4717-b48a-988256d5586f","username":"service-account-sunet-cdn-manager-admin-client","emailVerified":false,"createdTimestamp":1767042831875,"enabled":true,"totp":false,"disableableCredentialTypes":[],"requiredActions":[],"notBefore":0}
type keycloakServiceAccountUser struct {
	ID                         string   `json:"id"`
	Username                   string   `json:"username"`
	EmailVerified              bool     `json:"emailVerified"`
	CreatedTimestamp           int64    `json:"createdTimestamp"`
	Enabled                    bool     `json:"enabled"`
	TOTP                       bool     `json:"totp"`
	DisableableCredentialTypes []string `json:"disableableCredentialTypes"`
	RequiredActions            []string `json:"requiredActions"`
	NotBefore                  int64    `json:"notBefore"`
}

// [{"id":"a69f1222-0174-454b-9de8-0a359c063753","clientId":"realm-management","name":"${client_realm-management}","surrogateAuthRequired":false,"enabled":true,"alwaysDisplayInConsole":false,"clientAuthenticatorType":"client-secret","redirectUris":[],"webOrigins":[],"notBefore":0,"bearerOnly":true,"consentRequired":false,"standardFlowEnabled":true,"implicitFlowEnabled":false,"directAccessGrantsEnabled":false,"serviceAccountsEnabled":false,"publicClient":false,"frontchannelLogout":false,"protocol":"openid-connect","attributes":{"realm_client":"true"},"authenticationFlowBindingOverrides":{},"fullScopeAllowed":false,"nodeReRegistrationTimeout":0,"defaultClientScopes":["web-origins","acr","roles","profile","basic","email"],"optionalClientScopes":["address","phone","organization","offline_access","microprofile-jwt"],"access":{"view":true,"configure":true,"manage":true}}]
type keycloakClientInfo struct {
	ID       string `json:"id"`
	ClientID string `json:"clientId"`
	Name     string `json:"name"`
}

// {"id":"0b71362e-1d3d-433d-b14e-0a302e5f053f","name":"create-client","description":"${role_create-client}","composite":false,"clientRole":true,"containerId":"133f641d-414b-4767-9664-5e9971ba5f21","attributes":{}}
type keycloakRoleInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// [
//
//	{
//	    "id":"$create_client_role_uuid",
//	    "name":"create-client",
//	    "description":"\${role_create-client}"
//	}
//
// ]
type keycloakRoleMapping struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

//	{
//	  "name": "sunet-cdn-manager-aud",
//	  "description": "Assigned to client credentials used for authenticating to the SUNET CDN Manager API",
//	  "type": "none",
//	  "protocol": "openid-connect",
//	  "attributes": {
//	    "display.on.consent.screen": "true",
//	    "consent.screen.text": "",
//	    "include.in.token.scope": "false",
//	    "gui.order": ""
//	  }
//	}
//type keycloakClientScope struct {
//	Protocol    string                        `json:"protocol"`
//	Name        string                        `json:"name"`
//	Description string                        `json:"description"`
//	Type        string                        `json:"type"`
//	Attributes  keycloakClientScopeAttributes `json:"attributes"`
//}
//
//type keycloakClientScopeAttributes struct {
//	DisplayOnConsentScreen string `json:"display.on.consent.screen"`
//	ConsentScreenText      string `json:"consent.screen.text"`
//	IncludeInTokenScope    string `json:"include.in.token.scope"`
//	GuiOrder               string `json:"gui.order"`
//}

//	{
//	  "protocol": "openid-connect",
//	  "protocolMapper": "oidc-audience-mapper",
//	  "name": "sunet-cdn-manager-aud",
//	  "config": {
//	    "included.client.audience": "",
//	    "included.custom.audience": "sunet-cdn-manager",
//	    "id.token.claim": "false",
//	    "access.token.claim": "true",
//	    "lightweight.claim": "false",
//	    "introspection.token.claim": "true"
//	  }
//	}

type keycloakClientSecretData struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func keycloakUUIDFromLocation(resp *http.Response) (string, error) {
	locationURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", fmt.Errorf("keycloakUUIDFromLocation: unable to parse header: %w", err)
	}

	resourceUUID := path.Base(locationURL.Path)
	if resourceUUID == "." || resourceUUID == "/" {
		return "", fmt.Errorf("unable to parse resource UUID from Location URL '%s'", locationURL)
	}

	return resourceUUID, nil
}

func createKeycloakAdminClient(t *testing.T, adminClient *http.Client, baseURL string, realm string, clientName string) (string, string, error) {
	ckBody := newKeycloakClientReq(clientName, nil)

	b, err := json.Marshal(ckBody)
	if err != nil {
		return "", "", err
	}

	bodyReader := bytes.NewReader(b)

	u, err := url.Parse(baseURL)
	if err != nil {
		return "", "", err
	}
	u.Path = path.Join("admin/realms", realm, "clients")

	createResp, err := adminClient.Post(u.String(), contentTypeJSON, bodyReader)
	if err != nil {
		return "", "", err
	}
	defer func() {
		err := createResp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	respBody, err := io.ReadAll(createResp.Body)
	if err != nil {
		return "", "", err
	}

	if createResp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("unexpected status code: %d (%s)", createResp.StatusCode, string(respBody))
	}

	clientURL, err := url.Parse(createResp.Header.Get("Location"))
	if err != nil {
		return "", "", err
	}

	clientUUID, err := keycloakUUIDFromLocation(createResp)
	if err != nil {
		return "", "", err
	}

	clientSecretURL, err := url.JoinPath(clientURL.String(), "client-secret")
	if err != nil {
		return "", "", err
	}

	secretResp, err := adminClient.Get(clientSecretURL)
	if err != nil {
		return "", "", err
	}
	defer func() {
		err := secretResp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
	}()

	secretData, err := io.ReadAll(secretResp.Body)
	if err != nil {
		return "", "", err
	}

	var secretVal keycloakClientSecretData

	err = json.Unmarshal(secretData, &secretVal)
	if err != nil {
		return "", "", err
	}

	return clientUUID, secretVal.Value, nil
}

func sendKeycloakReq(t *testing.T, client *http.Client, method string, url string, reqBody []byte, queryParams url.Values, expectedStatusCode int) (respBody []byte, err error) {
	t.Log(url)
	req, err := http.NewRequest(method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	if reqBody != nil {
		req.Header.Add("Content-Type", contentTypeJSON)
	}

	if queryParams != nil {
		req.URL.RawQuery = queryParams.Encode()
	}

	resp, err := client.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		return nil, err
	}
	defer func() {
		if resp != nil {
			err = errors.Join(err, resp.Body.Close())
		}
	}()

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != expectedStatusCode {
		return nil, fmt.Errorf("sendKeycloakReq: unexpected status code for URL '%s', method '%s', want: %d, have: %d", url, method, expectedStatusCode, resp.StatusCode)
	}
	return respBody, nil
}

// {
// "name": "sunet-cdn-manager-admin-role",
// "description": "Role used for managing API client credentials",
// "attributes": {}
// }
type keycloakRole struct {
	ID          string            `json:"id,omitempty"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Attributes  map[string]string `json:"attributes"`
}

// [
//
//	{
//	  "id": "3fe577c3-2eee-4c39-8bc2-6ac66325b8f8",
//	  "name": "Allowed Client Scopes",
//	  "providerId": "allowed-client-templates",
//	  "providerType": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
//	  "parentId": "9de5b688-738d-4615-ad09-6a474f4aa74d",
//	  "subType": "authenticated",
//	  "config": {
//	    "allow-default-scopes": [
//	      "true"
//	    ]
//	  }
//	},
//	{
//	  "id": "2b2d4cd4-3838-434b-bc9d-5189564d25d4",
//	  "name": "Trusted Hosts",
//	  "providerId": "trusted-hosts",
//	  "providerType": "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
//	  "parentId": "9de5b688-738d-4615-ad09-6a474f4aa74d",
//	  "subType": "anonymous",
//	  "config": {
//	    "host-sending-registration-request-must-match": [
//	      "true"
//	    ],
//	    "client-uris-must-match": [
//	      "true"
//	    ]
//	  }
//	}
//
// ]
type keycloakComponentPolicy struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	ProviderID   string              `json:"providerId"`
	ProviderType string              `json:"providerType"`
	ParentID     string              `json:"parentId"`
	SubType      string              `json:"subType"`
	Config       map[string][]string `json:"config"`
}

// Set up keycloak similarly to the local-dev scripts in this repo
func setupKeycloak(t *testing.T, baseURL *url.URL, user string, password string, realm string) (string, string, error) {
	ctx := context.Background()
	adminIssuer, err := url.JoinPath(baseURL.String(), "realms/master")
	if err != nil {
		return "", "", err
	}

	adminProvider, err := oidc.NewProvider(ctx, adminIssuer)
	if err != nil {
		return "", "", err
	}

	// Get access token from username/password
	adminConfig := &oauth2.Config{
		ClientID: "admin-cli",
		Endpoint: adminProvider.Endpoint(),
	}

	token, err := adminConfig.PasswordCredentialsToken(ctx, user, password)
	if err != nil {
		return "", "", err
	}

	adminClient := adminConfig.Client(ctx, token)

	realmsURL, err := url.JoinPath(baseURL.String(), "admin/realms")
	if err != nil {
		return "", "", err
	}

	realmsJSON, err := json.Marshal(struct {
		Realm   string `json:"realm"`
		Enabled bool   `json:"enabled"`
	}{
		Realm:   realm,
		Enabled: true,
	})
	if err != nil {
		return "", "", err
	}

	_, err = sendKeycloakReq(t, adminClient, http.MethodPost, realmsURL, realmsJSON, nil, http.StatusCreated)
	if err != nil {
		return "", "", err
	}

	// Create oauth2 admin client used by sunet-cdn-manager service for
	// registering user facing API client credentials
	clientAdminClientID := "sunet-cdn-manager-admin-client"
	clientAdminUUID, clientAdminSecret, err := createKeycloakAdminClient(t, adminClient, baseURL.String(), realm, clientAdminClientID)
	if err != nil {
		return "", "", err
	}

	// Create role that we can assign to the admin client that grants it permissions to do client creation
	rolesURL, err := url.JoinPath(baseURL.String(), "admin/realms", realm, "roles")
	if err != nil {
		return "", "", err
	}

	roleName := "sunet-cdn-manager-admin-role"

	kcRole := keycloakRole{
		Name:        roleName,
		Description: "Role used for managing API client credentials",
		Attributes:  map[string]string{},
	}

	kcRoleJSON, err := json.Marshal(kcRole)
	if err != nil {
		return "", "", err
	}

	_, err = sendKeycloakReq(t, adminClient, http.MethodPost, rolesURL, kcRoleJSON, nil, http.StatusCreated)
	if err != nil {
		return "", "", err
	}

	// The role creation does not return any JSON with the ID, and the
	// Location header actually points to the resource by name
	// (roles/the-role-name), so we need
	// to do an additional GET to find the UUID
	getRoleURL, err := url.JoinPath(rolesURL, roleName)
	if err != nil {
		return "", "", err
	}

	roleBody, err := sendKeycloakReq(t, adminClient, http.MethodGet, getRoleURL, nil, nil, http.StatusOK)
	if err != nil {
		return "", "", err
	}

	var newRole keycloakRole

	err = json.Unmarshal(roleBody, &newRole)
	if err != nil {
		return "", "", err
	}

	// Finding related service account UUID so we can assign "create-client" admin role to it.
	serviceAccountURL, err := url.JoinPath(baseURL.String(), "admin/realms", realm, "clients", clientAdminUUID, "service-account-user")
	if err != nil {
		return "", "", err
	}

	adminClientServiceAccountBody, err := sendKeycloakReq(t, adminClient, http.MethodGet, serviceAccountURL, nil, nil, http.StatusOK)
	if err != nil {
		return "", "", err
	}

	var adminClientServiceAccount keycloakServiceAccountUser

	err = json.Unmarshal(adminClientServiceAccountBody, &adminClientServiceAccount)
	if err != nil {
		return "", "", err
	}

	// Finding realm-management client UUID, needed to find create-client role UUID
	clientsURLString, err := url.JoinPath(baseURL.String(), "admin/realms", realm, "clients")
	if err != nil {
		return "", "", err
	}

	clientsURL, err := url.Parse(clientsURLString)
	if err != nil {
		return "", "", err
	}

	realmManagementClientID := "realm-management"
	realmManagementQueryParams := url.Values{}
	realmManagementQueryParams.Set("clientId", realmManagementClientID)
	kcClientsInfoBody, err := sendKeycloakReq(t, adminClient, http.MethodGet, clientsURL.String(), nil, realmManagementQueryParams, http.StatusOK)
	if err != nil {
		return "", "", err
	}

	var kcClientsInfo []keycloakClientInfo

	err = json.Unmarshal(kcClientsInfoBody, &kcClientsInfo)
	if err != nil {
		return "", "", err
	}

	if len(kcClientsInfo) != 1 {
		return "", "", fmt.Errorf("expected exactly one match for clientId '%s': %d", realmManagementClientID, len(kcClientsInfo))
	}

	t.Log(kcClientsInfo)

	// Finding UUID for realm-management create-client role
	manageClientsRoleURL, err := url.JoinPath(clientsURL.String(), kcClientsInfo[0].ID, "roles/create-client")
	if err != nil {
		return "", "", err
	}

	kcRoleInfoBody, err := sendKeycloakReq(t, adminClient, http.MethodGet, manageClientsRoleURL, nil, nil, http.StatusOK)
	if err != nil {
		return "", "", err
	}

	var kcRoleInfo keycloakRoleInfo

	err = json.Unmarshal(kcRoleInfoBody, &kcRoleInfo)
	if err != nil {
		return "", "", err
	}

	t.Log("KC ROLE INFO: ", kcRoleInfo)

	// Apply create-client role as a composite (associated role) to
	// sunet-cdn-manager-admin-role role. For some reason the roles/
	// endpoint allows us to use the name of the role rather than the UUID
	// id (which instead uses role-by-id/)
	compositeRoleURL, err := url.JoinPath(baseURL.String(), "admin/realms", realm, "roles", roleName, "composites")
	if err != nil {
		return "", "", err
	}

	kcRoleMappings := []keycloakRoleMapping{
		{
			ID:          kcRoleInfo.ID,
			Name:        "create-client",
			Description: "${role_create-client}",
		},
	}

	roleMappingJSON, err := json.Marshal(kcRoleMappings)
	if err != nil {
		return "", "", err
	}

	_, err = sendKeycloakReq(t, adminClient, http.MethodPost, compositeRoleURL, roleMappingJSON, nil, http.StatusNoContent)
	if err != nil {
		return "", "", err
	}

	// Apply realm role to sunet-cdn-manager client service account
	serviceAccountRealmRoleMappingURL, err := url.JoinPath(baseURL.String(), "admin/realms", realm, "users", adminClientServiceAccount.ID, "role-mappings/realm")
	if err != nil {
		return "", "", err
	}

	kcRealmRoleMappings := []keycloakRoleMapping{
		{
			ID:          newRole.ID,
			Name:        roleName,
			Description: "Role used for managing API client credentials",
		},
	}

	realmRoleMappingJSON, err := json.Marshal(kcRealmRoleMappings)
	if err != nil {
		return "", "", err
	}

	_, err = sendKeycloakReq(t, adminClient, http.MethodPost, serviceAccountRealmRoleMappingURL, realmRoleMappingJSON, nil, http.StatusNoContent)
	if err != nil {
		return "", "", err
	}

	// We want to include a custom audience in the access token "aud" list
	// so we can validate that access tokens were meant for out API.
	// Create a client-scope with an audience mapper that assigns our
	// expected custom audience value. This client-scope will then be
	// assigned to the API token clients we create.
	clientScopesURL, err := url.JoinPath(baseURL.String(), "admin/realms", realm, "client-scopes")
	if err != nil {
		return "", "", err
	}

	kcClientScope := keycloakClientScope{
		Name:        "sunet-cdn-manager-aud",
		Description: "Assigned to client credentials used for authenticating to the SUNET CDN Manager API",
		Type:        "none",
		Protocol:    "openid-connect",
		Attributes: keycloakClientScopeAttributes{
			DisplayOnConsentScreen: "true",
			ConsentScreenText:      "",
			IncludeInTokenScope:    "false",
			GuiOrder:               "",
		},
		ProtocolMappers: []keycloakClientScopeMapper{
			{
				Protocol:       "openid-connect",
				ProtocolMapper: "oidc-audience-mapper",
				Name:           "sunet-cdn-manager-aud",
				Config: keycloakProtocolMapperConfig{
					IncludedClientAudience:  "",
					IncludedCustomAudience:  jwtAudience,
					IDTokenClaim:            "false",
					AccessTokenClaim:        "true",
					LightweightClaim:        "false",
					IntrospectionTokenClaim: "true",
				},
			},
		},
	}

	clientScopeJSON, err := json.Marshal(kcClientScope)
	if err != nil {
		return "", "", err
	}

	_, err = sendKeycloakReq(t, adminClient, http.MethodPost, clientScopesURL, clientScopeJSON, nil, http.StatusCreated)
	if err != nil {
		return "", "", err
	}

	// Find UUID for client registration policy that allows assigning our
	// custom client-scope that includes the audience mapper for new
	// clients at registration
	clientRegistrationPolicyURL, err := url.JoinPath(baseURL.String(), "admin/realms", realm, "components")
	if err != nil {
		return "", "", err
	}

	componentProviderType := "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
	componentPolicyQueryParams := url.Values{}
	componentPolicyQueryParams.Set("type", componentProviderType)
	componentsPolicyBody, err := sendKeycloakReq(t, adminClient, http.MethodGet, clientRegistrationPolicyURL, nil, componentPolicyQueryParams, http.StatusOK)
	if err != nil {
		return "", "", err
	}

	kcComponentPolicies := []keycloakComponentPolicy{}

	err = json.Unmarshal(componentsPolicyBody, &kcComponentPolicies)
	if err != nil {
		return "", "", err
	}

	clientScopeProviderID := "allowed-client-templates"
	expectedSubType := "authenticated"
	var modifiedKCComponentScopePolicy keycloakComponentPolicy
	for _, kcComponentPolicy := range kcComponentPolicies {
		if kcComponentPolicy.ProviderType == componentProviderType && kcComponentPolicy.ProviderID == clientScopeProviderID && kcComponentPolicy.SubType == expectedSubType {
			modifiedKCComponentScopePolicy = kcComponentPolicy
			break
		}
	}

	if modifiedKCComponentScopePolicy.ID == "" {
		return "", "", fmt.Errorf("unable to find UUID for scopeProviderID '%s'", clientScopeProviderID)
	}

	// Errors seen when trying to create clients via client registration service:
	// ==
	// 2026-01-09 13:08:33,637 WARN  [org.keycloak.services] (executor-thread-1) KC-SERVICES0099: Operation 'before register client' rejected. Policy 'Allowed Client Scopes' rejected request to client-registration service. Details: Not permitted to use specified clientScope
	// 2026-01-09 13:08:33,638 WARN  [org.keycloak.events] (executor-thread-1) type="CLIENT_REGISTER_ERROR", realmId="791a5cd3-4db7-4fce-9f28-ceffd1d93712", realmName="sunet-cdn-manager", clientId="null", userId="null", ipAddress="192.168.65.1", error="not_allowed", client_registration_policy="Allowed Client Scopes"
	// ... so add the client-scope "sunet-cdn-manager-aud"
	allowedClientScope := "sunet-cdn-manager-aud"
	modifiedKCComponentScopePolicy.Config["allowed-client-scopes"] = append(modifiedKCComponentScopePolicy.Config["allowed-client-scopes"], allowedClientScope)

	// https://keycloak.sunet-cdn.localhost:8443/admin/realms/sunet-cdn-manager/components/f28de905-7104-4189-9be4-88ca2aa9e6b1
	clientRegistrationScopePolicyUpdateURL, err := url.JoinPath(clientRegistrationPolicyURL, modifiedKCComponentScopePolicy.ID)
	if err != nil {
		return "", "", err
	}

	clientRegistrationScopePolicyUpdateJSON, err := json.Marshal(modifiedKCComponentScopePolicy)
	if err != nil {
		return "", "", err
	}

	_, err = sendKeycloakReq(t, adminClient, http.MethodPut, clientRegistrationScopePolicyUpdateURL, clientRegistrationScopePolicyUpdateJSON, componentPolicyQueryParams, http.StatusNoContent)
	if err != nil {
		return "", "", err
	}

	return clientAdminClientID, clientAdminSecret, nil
}

func createKeycloakContainer(ctx context.Context, t *testing.T) (*oidc.Provider, *keycloakClientManager, *url.URL, *jwk.Cache, openidConfig, context.CancelFunc) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:      "quay.io/keycloak/keycloak:26.0.7",
		WaitingFor: wait.ForHTTP("/realms/master"),
		Env: map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
			"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
		},
		Cmd: []string{"start-dev"},
	}

	keycloakC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	defer testcontainers.CleanupContainer(t, keycloakC)
	if err != nil {
		t.Fatal(err)
	}

	endpoint, err := keycloakC.Endpoint(ctx, "http")
	if err != nil {
		t.Fatal(err)
	}

	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Caller().Logger()

	realm := "sunet-cdn-manager"

	clientID, clientSecret, err := setupKeycloak(t, endpointURL, "admin", "admin", realm)
	if err != nil {
		t.Fatal(err)
	}

	issuerURL, err := url.Parse(endpoint + "/realms/" + realm)
	if err != nil {
		t.Fatal(err)
	}

	provider, err := oidc.NewProvider(ctx, issuerURL.String())
	if err != nil {
		t.Fatal(fmt.Errorf("setting up OIDC provider failed: %w", err))
	}

	cc := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     provider.Endpoint().TokenURL,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Client used for creating/deleting API client credentials in keycloak
	kcClientManager := newKeycloakClientManager(logger, endpointURL, realm, cc.Client(ctx), client)

	oiConf, err := fetchKeyCloakOpenIDConfig(ctx, client, issuerURL.String())
	if err != nil {
		t.Fatalf("unable to fetch openid-configuration: %v", err)
	}

	jwkCtx, jwkCancel := context.WithCancel(t.Context()) // #nosec G118 -- caller is responsible for cancelling the context

	jwkCache, err := setupJwkCache(jwkCtx, logger, client, oiConf)
	if err != nil {
		jwkCancel()
		t.Fatalf("unable to setup JWK cache: %s", err)
	}

	return provider, kcClientManager, issuerURL, jwkCache, oiConf, jwkCancel
}

func TestPostDeleteOrgClientCredentials(t *testing.T) {
	ctx := context.Background()
	provider, kcClientManager, issuerURL, jwkCache, oiConf, jwkCancelFunc := createKeycloakContainer(ctx, t)
	defer jwkCancelFunc()

	// Assign two passwords so we do not fail the test request to the
	// re-encryption endpoint (with only one password it does not accept
	// the request at all)
	encryptionPasswords := []string{
		"test-encryption-password-1",
		"test-encryption-password-2",
	}

	ts, dbPool, err := prepareServer(t, testServerInput{kcClientManager: kcClientManager, jwkCache: jwkCache, jwtIssuer: issuerURL.String(), oiConf: oiConf, encryptionPasswords: encryptionPasswords})
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
		expectedPostStatus   int
		expectedDeleteStatus int
		credName             string
		credDescription      string
		orgNameOrID          string
	}{
		{
			description:          "successful superuser request",
			username:             "admin",
			password:             validAdminPassword,
			expectedPostStatus:   http.StatusCreated,
			expectedDeleteStatus: http.StatusNoContent,
			credName:             "post-cred-1",
			credDescription:      "a description 1",
			orgNameOrID:          "org1",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			newCred := struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			}{
				Name:        test.credName,
				Description: test.credDescription,
			}

			b, err := json.Marshal(newCred)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			postReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/orgs/"+test.orgNameOrID+"/client-credentials", r)
			if err != nil {
				t.Fatal(err)
			}

			postReq.SetBasicAuth(test.username, test.password)

			postResp, err := http.DefaultClient.Do(postReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer postResp.Body.Close()

			if postResp.StatusCode != test.expectedPostStatus {
				r, err := io.ReadAll(postResp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("POST org client credentials unexpected status code: %d (%s)", postResp.StatusCode, string(r))
			}

			postJSONData, err := io.ReadAll(postResp.Body)
			if err != nil {
				t.Fatal(err)
			}

			// Try to use the new client cred if it was expected to be created
			if test.expectedPostStatus == http.StatusCreated {
				var newClientCred cdntypes.NewOrgClientCredential

				err := json.Unmarshal(postJSONData, &newClientCred)
				if err != nil {
					t.Fatalf("unable to unmarshal JSON for new cred: %s", err)
				}

				// Make sure the client_secret is set
				if newClientCred.ClientSecret == "" {
					t.Fatalf("new client cred has an empty password, that's not expected")
				}

				// Try to do requests with the new client cred, it is
				// expected to be able to to look up its own organization
				// if it has the proper Authorization header from
				// keycloak and otherwise it should fail.
				clientCredTests := []struct {
					description         string
					authorizationHeader string
					getKeycloakToken    bool
					expectedStatus      int
				}{
					{
						description:         "valid request with access token from keycloak",
						authorizationHeader: "",
						getKeycloakToken:    true,
						expectedStatus:      http.StatusOK,
					},
					{
						description:         "authorization header missing",
						authorizationHeader: "",
						getKeycloakToken:    false,
						expectedStatus:      http.StatusUnauthorized,
					},
					{
						description:         "authorization header with invalid content",
						authorizationHeader: "Invalid abcd1234",
						getKeycloakToken:    false,
						expectedStatus:      http.StatusUnauthorized,
					},
				}
				for _, clientCredTest := range clientCredTests {
					// Wrap loop body in anonymous function to properly call the deferred Body.Close()
					t.Run(clientCredTest.description, func(t *testing.T) {
						ctx := context.Background()
						clientCredGetReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/orgs/"+test.orgNameOrID, nil)
						if err != nil {
							t.Fatal(err)
						}

						client := &http.Client{
							Timeout: 10 * time.Second,
						}

						if clientCredTest.getKeycloakToken {
							apiClientCred := clientcredentials.Config{
								ClientID:     newClientCred.ClientID,
								ClientSecret: newClientCred.ClientSecret,
								TokenURL:     provider.Endpoint().TokenURL,
							}

							client = apiClientCred.Client(ctx)
						} else if clientCredTest.authorizationHeader != "" {
							clientCredGetReq.Header.Set("Authorization", clientCredTest.authorizationHeader)
						}

						clientCredResp, err := client.Do(clientCredGetReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
						if err != nil {
							t.Fatal(err)
						}
						defer func() {
							err := clientCredResp.Body.Close()
							if err != nil {
								t.Fatal(err)
							}
						}()
						t.Logf("client cred resp: %#v", clientCredResp)

						if clientCredResp.StatusCode != clientCredTest.expectedStatus {
							t.Fatalf("client cred got unexpected status code when looking up own org, want: %d, have: %d", clientCredTest.expectedStatus, clientCredResp.StatusCode)
						}
					})
				}

			}

			// Attempt re-encryption prior to DELETE
			reEncryptReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/re-encrypt-org-client-registration-tokens", nil)
			if err != nil {
				t.Fatal(err)
			}

			reEncryptReq.SetBasicAuth(test.username, test.password)

			reEncryptResp, err := http.DefaultClient.Do(reEncryptReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer reEncryptResp.Body.Close()

			if reEncryptResp.StatusCode != http.StatusOK {
				r, err := io.ReadAll(reEncryptResp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("POST org client credentials re-encryption unexpected status code: %d (%s)", reEncryptResp.StatusCode, string(r))
			}

			reEncryptBody, err := io.ReadAll(reEncryptResp.Body)
			if err != nil {
				t.Fatalf("POST org client credentials re-encryption failed to parse body: %s", err)
			}

			var reEncryptResult cdntypes.OrgClientRegistrationTokenReEncryptResult

			if err := json.Unmarshal(reEncryptBody, &reEncryptResult); err != nil {
				t.Fatalf("failed to decode re-encryption response JSON: %v (body: %s)", err, string(reEncryptBody))
			}

			// Since the token was created above (so using the last password in the list) we expect to skip it
			if reEncryptResult.TotalTokens != 1 || reEncryptResult.UpdatedTokens != 0 || reEncryptResult.SkippedTokens != 1 || reEncryptResult.FailedTokens != 0 {
				t.Fatalf("invalid re-encryption counts: TotalTokens=%d, UpdatedTokens=%d, SkippedTokens=%d, FailedTokens=%d", reEncryptResult.TotalTokens, reEncryptResult.UpdatedTokens, reEncryptResult.SkippedTokens, reEncryptResult.FailedTokens)
			}

			deleteReq, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/orgs/"+test.orgNameOrID+"/client-credentials/"+test.credName, nil)
			if err != nil {
				t.Fatal(err)
			}

			deleteReq.SetBasicAuth(test.username, test.password)

			deleteResp, err := http.DefaultClient.Do(deleteReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer deleteResp.Body.Close()

			if deleteResp.StatusCode != test.expectedDeleteStatus {
				r, err := io.ReadAll(deleteResp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("DELETE org client credentials unexpected status code: %d (%s)", deleteResp.StatusCode, string(r))
			}

			deleteJSONData, err := io.ReadAll(deleteResp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", deleteJSONData)
		})
	}
}

func TestPostOrgClientCredentialsInvalidName(t *testing.T) {
	ctx := context.Background()
	_, kcClientManager, issuerURL, jwkCache, oiConf, jwkCancelFunc := createKeycloakContainer(ctx, t)
	defer jwkCancelFunc()

	ts, dbPool, err := prepareServer(t, testServerInput{kcClientManager: kcClientManager, jwkCache: jwkCache, jwtIssuer: issuerURL.String(), oiConf: oiConf})
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
		credName       string
		orgNameOrID    string
	}{
		{
			description:    "failed superuser request with invalid DNS label name",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			credName:       "INVALID NAME",
			orgNameOrID:    "org1",
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint.
			description:    "failed superuser request with UUID name",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			credName:       "abcdef01-2345-6789-abcd-ef0123456789",
			orgNameOrID:    "org1",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			newCred := struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			}{
				Name:        test.credName,
				Description: "a description",
			}

			b, err := json.Marshal(newCred)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/orgs/"+test.orgNameOrID+"/client-credentials", r)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("POST org client credentials unexpected status code: %d (%s)", resp.StatusCode, string(body))
			}
		})
	}
}

func createCred(t *testing.T, ts *httptest.Server, username, password, org string, name string, desc string) cdntypes.NewOrgClientCredential {
	t.Helper()

	newCred := struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}{
		Name:        name,
		Description: desc,
	}

	b, err := json.Marshal(newCred)
	if err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(b)

	postReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/orgs/"+org+"/client-credentials", r)
	if err != nil {
		t.Fatal(err)
	}

	postReq.SetBasicAuth(username, password)

	postResp, err := http.DefaultClient.Do(postReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusCreated {
		r, err := io.ReadAll(postResp.Body)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("POST org client credentials unexpected status code: %d (%s)", postResp.StatusCode, string(r))
	}

	postJSONData, err := io.ReadAll(postResp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var newClientCred cdntypes.NewOrgClientCredential

	err = json.Unmarshal(postJSONData, &newClientCred)
	if err != nil {
		t.Fatalf("unable to unmarshal JSON for new cred: %s", err)
	}

	// Make sure the client_secret is set
	if newClientCred.ClientSecret == "" {
		t.Fatalf("new client cred has an empty password, that's not expected")
	}

	return newClientCred
}

func TestPostReEncryptOrgClientCredentials(t *testing.T) {
	ctx := context.Background()
	_, kcClientManager, issuerURL, jwkCache, oiConf, jwkCancelFunc := createKeycloakContainer(ctx, t)
	defer jwkCancelFunc()

	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Caller().Logger()

	// Create a free-standing dbPool here so we can start the server
	// multiple times without resetting the database for testing
	// re-encryption where the server is started with different
	// sets of passwords.
	dbPool, err := initDatabase(ctx, t, logger, false)
	if err != nil {
		t.Fatalf("unable to init re-encrypt test database: %s", err)
	}
	defer dbPool.Close()

	tsi := testServerInput{kcClientManager: kcClientManager, jwkCache: jwkCache, jwtIssuer: issuerURL.String(), oiConf: oiConf, dbPool: dbPool}

	tests := []struct {
		description          string
		username             string
		password             string
		expectedDeleteStatus int
		orgNameOrID          string
		server1Passwords     []string
		server2Passwords     []string
		server3Passwords     []string
	}{
		{
			description:          "successful superuser request",
			username:             "admin",
			password:             validAdminPassword,
			expectedDeleteStatus: http.StatusNoContent,
			orgNameOrID:          "org1",
			server1Passwords:     []string{"test-encryption-password-1"},
			server2Passwords:     []string{"test-encryption-password-1", "test-encryption-password-2"},
			server3Passwords:     []string{"test-encryption-password-2"},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			createdCredNames := []string{}

			var cred1 cdntypes.NewOrgClientCredential
			var cred1CiphertextOrig []byte
			var cred1CiphertextUpdated []byte
			var cred2 cdntypes.NewOrgClientCredential
			var cred2CiphertextOrig []byte
			var cred2CiphertextUpdated []byte
			// First server instance, run in func so we can easily defer
			// closing it at the end
			func() {
				tsi.encryptionPasswords = test.server1Passwords
				// Since we supply our own dbPool in tsi it will not be returned here
				ts1, _, err := prepareServer(t, tsi)
				if err != nil {
					t.Fatal(err)
				}
				defer ts1.Close()

				// Create first client cred
				cred1 = createCred(t, ts1, test.username, test.password, test.orgNameOrID, "re-encrypt-cred-1", "re-encrypt desc 1")
				createdCredNames = append(createdCredNames, cred1.Name)

				// Save the actual crypto data for later comparision
				err = dbPool.QueryRow(ctx, "SELECT crypt_registration_access_token FROM org_keycloak_client_credentials WHERE id = $1", cred1.ID).Scan(&cred1CiphertextOrig)
				if err != nil {
					t.Fatal(err)
				}
			}()

			// Second server instance
			func() {
				// Here we must have at least two passwords
				tsi.encryptionPasswords = test.server2Passwords
				// Since we supply our own dbPool in tsi it will not be returned here
				ts2, _, err := prepareServer(t, tsi)
				if err != nil {
					t.Fatal(err)
				}
				defer ts2.Close()

				// Create second client cred
				cred2 = createCred(t, ts2, test.username, test.password, test.orgNameOrID, "re-encrypt-cred-2", "re-encrypt desc 2")
				createdCredNames = append(createdCredNames, cred2.Name)

				err = dbPool.QueryRow(ctx, "SELECT crypt_registration_access_token FROM org_keycloak_client_credentials WHERE id = $1", cred2.ID).Scan(&cred2CiphertextOrig)
				if err != nil {
					t.Fatal(err)
				}

				// Attempt re-encryption
				reEncryptReq, err := http.NewRequest(http.MethodPost, ts2.URL+"/api/v1/re-encrypt-org-client-registration-tokens", nil)
				if err != nil {
					t.Fatal(err)
				}

				reEncryptReq.SetBasicAuth(test.username, test.password)

				reEncryptResp, err := http.DefaultClient.Do(reEncryptReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
				if err != nil {
					t.Fatal(err)
				}
				defer reEncryptResp.Body.Close()

				if reEncryptResp.StatusCode != http.StatusOK {
					r, err := io.ReadAll(reEncryptResp.Body)
					if err != nil {
						t.Fatal(err)
					}
					t.Fatalf("POST org client credentials re-encryption unexpected status code: %d (%s)", reEncryptResp.StatusCode, string(r))
				}

				reEncryptBody, err := io.ReadAll(reEncryptResp.Body)
				if err != nil {
					t.Fatalf("POST org client credentials re-encryption failed to parse body: %s", err)
				}

				var reEncryptResult cdntypes.OrgClientRegistrationTokenReEncryptResult

				if err := json.Unmarshal(reEncryptBody, &reEncryptResult); err != nil {
					t.Fatalf("failed to decode re-encryption response JSON: %v (body: %s)", err, string(reEncryptBody))
				}

				// Since the first token was created by ts1 and the second by ts2 we expect to update one and skip one
				if reEncryptResult.TotalTokens != 2 || reEncryptResult.UpdatedTokens != 1 || reEncryptResult.SkippedTokens != 1 || reEncryptResult.FailedTokens != 0 {
					t.Fatalf("invalid re-encryption counts: TotalTokens=%d, UpdatedTokens=%d, SkippedTokens=%d, FailedTokens=%d", reEncryptResult.TotalTokens, reEncryptResult.UpdatedTokens, reEncryptResult.SkippedTokens, reEncryptResult.FailedTokens)
				}
			}()

			err = dbPool.QueryRow(ctx, "SELECT crypt_registration_access_token FROM org_keycloak_client_credentials WHERE id = $1", cred1.ID).Scan(&cred1CiphertextUpdated)
			if err != nil {
				t.Fatal(err)
			}

			if len(cred1CiphertextOrig) == 0 {
				t.Fatal("expected cred1CiphertextOrig to have content")
			}

			// cred1 should have had its crypto data modified
			if bytes.Equal(cred1CiphertextOrig, cred1CiphertextUpdated) {
				t.Fatal("expected cred1CiphertextOrig to have changed")
			}

			if len(cred2CiphertextOrig) == 0 {
				t.Fatal("expected cred2CiphertextOrig to have content")
			}

			err = dbPool.QueryRow(ctx, "SELECT crypt_registration_access_token FROM org_keycloak_client_credentials WHERE id = $1", cred2.ID).Scan(&cred2CiphertextUpdated)
			if err != nil {
				t.Fatal(err)
			}

			// cred2 should NOT have had its crypto data modified (since we ran re-encryption with the same password as it was created with)
			if !bytes.Equal(cred2CiphertextOrig, cred2CiphertextUpdated) {
				t.Fatal("expected cred2CiphertextOrig to have remained the same")
			}

			// Now we only have the new password, verify we can delete both creds (e.g. we can decrypt both client reg tokens for talking to keycloak)
			tsi.encryptionPasswords = test.server3Passwords
			ts3, _, err := prepareServer(t, tsi)
			if err != nil {
				t.Fatal(err)
			}
			defer ts3.Close()

			for _, credName := range createdCredNames {
				func() {
					deleteReq, err := http.NewRequest(http.MethodDelete, ts3.URL+"/api/v1/orgs/"+test.orgNameOrID+"/client-credentials/"+credName, nil)
					if err != nil {
						t.Fatal(err)
					}

					deleteReq.SetBasicAuth(test.username, test.password)

					deleteResp, err := http.DefaultClient.Do(deleteReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
					if err != nil {
						t.Fatal(err)
					}
					defer deleteResp.Body.Close()

					if deleteResp.StatusCode != test.expectedDeleteStatus {
						r, err := io.ReadAll(deleteResp.Body)
						if err != nil {
							t.Fatal(err)
						}
						t.Fatalf("DELETE org client credentials unexpected status code: %d (%s)", deleteResp.StatusCode, string(r))
					}

					deleteJSONData, err := io.ReadAll(deleteResp.Body)
					if err != nil {
						t.Fatal(err)
					}

					t.Logf("%s\n", deleteJSONData)
				}()
			}
		})
	}
}

func TestGetOrg(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       validAdminPassword,
			nameOrID:       "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with ID",
			username:       "username1",
			password:       validUserPassword,
			nameOrID:       "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with name",
			username:       "username1",
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/orgs/"+test.nameOrID, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET orgs/%s unexpected status code: %d (%s)", test.nameOrID, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetDomains(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
			orgNameOrID:    "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request for all orgs",
			username:       "admin",
			password:       validAdminPassword,
			orgNameOrID:    "",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       validAdminPassword,
			orgNameOrID:    "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with ID",
			username:       "username1",
			password:       validUserPassword,
			orgNameOrID:    "00000002-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request with name",
			username:       "username1",
			password:       validUserPassword,
			orgNameOrID:    "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful normal user request with no org",
			username:       "username1",
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/domains", nil)
			if err != nil {
				t.Fatal(err)
			}

			if test.orgNameOrID != "" {
				values := req.URL.Query()
				values.Add("org", test.orgNameOrID)
				req.URL.RawQuery = values.Encode()
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET '%s' unexpected status code: %d (%s)", req.URL.String(), resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetServiceIPs(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful superuser service IPs request with ID, with org id",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful superuser service IPs request with names",
			username:        "admin",
			password:        validAdminPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/ips", nil)
			if err != nil {
				t.Fatal(err)
			}

			if test.orgNameOrID != "" {
				values := req.URL.Query()
				values.Add("org", test.orgNameOrID)
				req.URL.RawQuery = values.Encode()
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPostOrganizations(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:          validAdminPassword,
			expectedStatus:    http.StatusCreated,
			addedOrganization: "adminorg",
		},
		{
			description:       "successful superuser request with max length name",
			username:          "admin",
			password:          validAdminPassword,
			expectedStatus:    http.StatusCreated,
			addedOrganization: strings.Repeat("a", 63),
		},
		{
			description:       "failed superuser request with invalid DNS label name",
			username:          "admin",
			password:          validAdminPassword,
			expectedStatus:    http.StatusUnprocessableEntity,
			addedOrganization: "admin org",
		},
		{
			description:       "failed superuser request with too short name",
			username:          "admin",
			password:          validAdminPassword,
			expectedStatus:    http.StatusUnprocessableEntity,
			addedOrganization: "",
		},
		{
			description:       "failed superuser request with too long name",
			username:          "admin",
			password:          validAdminPassword,
			expectedStatus:    http.StatusUnprocessableEntity,
			addedOrganization: strings.Repeat("a", 64),
		},
		{
			description:       "failed non-superuser request",
			username:          "username1",
			password:          validUserPassword,
			addedOrganization: "username1org",
			expectedStatus:    http.StatusForbidden,
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint
			description:       "failed superuser request with UUID name",
			username:          "admin",
			password:          validAdminPassword,
			expectedStatus:    http.StatusUnprocessableEntity,
			addedOrganization: "abcdef01-2345-6789-abcd-ef0123456789",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
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

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/orgs", r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
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

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetServices(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			description:    "successful superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request for specific org",
			username:       "admin",
			password:       validAdminPassword,
			orgNameOrID:    "org2",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request for same org explicity",
			username:       "username1",
			password:       validUserPassword,
			orgNameOrID:    "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request for other org",
			username:       "username1",
			password:       validUserPassword,
			orgNameOrID:    "org2",
			expectedStatus: http.StatusForbidden,
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
		{
			description:    "failed user request (not assigned to org), asking for explicit org",
			username:       "username3-no-org",
			password:       "password3",
			orgNameOrID:    "org1",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			if test.orgNameOrID != "" {
				values := req.URL.Query()
				values.Add("org", test.orgNameOrID)
				req.URL.RawQuery = values.Encode()
			}

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
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

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetService(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful superuser request with name and org by id",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful user request with ID",
			username:        "username1",
			password:        validUserPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			expectedStatus:  http.StatusOK,
		},
		{
			description:     "successful user request with name",
			username:        "username1",
			password:        validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			if test.serviceNameOrID == "" {
				t.Fatal("user needs service name or ID for service test")
			}

			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services/"+test.serviceNameOrID, nil)
			if err != nil {
				t.Fatal(err)
			}

			if test.orgNameOrID != "" {
				values := req.URL.Query()
				values.Add("org", test.orgNameOrID)
				req.URL.RawQuery = values.Encode()
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
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

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetServicesDisabledAt(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	// Disable org1-service2 directly in the DB so this test only depends on
	// the read path, not on the disable endpoint (added in task 2).
	_, err = dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = '00000003-0000-0000-0000-000000000002'")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services?org=org1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("admin", validAdminPassword)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
	}

	var services []cdntypes.Service
	if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
		t.Fatal(err)
	}

	byName := map[string]cdntypes.Service{}
	for _, s := range services {
		byName[s.Name] = s
	}

	enabled, ok := byName["org1-service1"]
	if !ok {
		t.Fatal("org1-service1 missing from services list")
	}
	if enabled.DisabledAt != nil {
		t.Errorf("org1-service1 should be enabled, got disabled_at=%v", enabled.DisabledAt)
	}

	disabled, ok := byName["org1-service2"]
	if !ok {
		t.Fatal("org1-service2 missing from services list")
	}
	if disabled.DisabledAt == nil {
		t.Error("org1-service2 should report a disabled_at timestamp")
	}

	// Also exercise the all-services branch of selectServicesTx (superuser
	// request with no "org" query parameter), which is a separate SQL
	// string from the org-scoped branch checked above.
	allReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services", nil)
	if err != nil {
		t.Fatal(err)
	}
	allReq.SetBasicAuth("admin", validAdminPassword)

	allResp, err := http.DefaultClient.Do(allReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer allResp.Body.Close()

	if allResp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(allResp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Fatalf("unexpected status code: %d (%s)", allResp.StatusCode, string(body))
	}

	var allServices []cdntypes.Service
	if err := json.NewDecoder(allResp.Body).Decode(&allServices); err != nil {
		t.Fatal(err)
	}

	allByName := map[string]cdntypes.Service{}
	for _, s := range allServices {
		allByName[s.Name] = s
	}

	allEnabled, ok := allByName["org1-service1"]
	if !ok {
		t.Fatal("org1-service1 missing from all-services list")
	}
	if allEnabled.DisabledAt != nil {
		t.Errorf("org1-service1 should be enabled in all-services list, got disabled_at=%v", allEnabled.DisabledAt)
	}

	allDisabled, ok := allByName["org1-service2"]
	if !ok {
		t.Fatal("org1-service2 missing from all-services list")
	}
	if allDisabled.DisabledAt == nil {
		t.Error("org1-service2 should report a disabled_at timestamp in all-services list")
	}
}

func TestGetServiceDisabledAt(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	_, err = dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = '00000003-0000-0000-0000-000000000002'")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services/00000003-0000-0000-0000-000000000002", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("admin", validAdminPassword)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
	}

	var service cdntypes.Service
	if err := json.NewDecoder(resp.Body).Decode(&service); err != nil {
		t.Fatal(err)
	}

	if service.DisabledAt == nil {
		t.Error("single-service GET should report a disabled_at timestamp")
	}

	// Also exercise the NULL (enabled) case of the same selectService query,
	// using org1-service1 which is left enabled.
	enabledReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services/00000003-0000-0000-0000-000000000001", nil)
	if err != nil {
		t.Fatal(err)
	}
	enabledReq.SetBasicAuth("admin", validAdminPassword)

	enabledResp, err := http.DefaultClient.Do(enabledReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer enabledResp.Body.Close()

	if enabledResp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(enabledResp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Fatalf("unexpected status code: %d (%s)", enabledResp.StatusCode, string(body))
	}

	var enabledService cdntypes.Service
	if err := json.NewDecoder(enabledResp.Body).Decode(&enabledService); err != nil {
		t.Fatal(err)
	}

	if enabledService.DisabledAt != nil {
		t.Errorf("single-service GET for enabled service should report nil disabled_at, got %v", enabledService.DisabledAt)
	}
}

func TestPutServiceDisabled(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	tests := []struct {
		description     string
		username        string
		password        string
		serviceNameOrID string
		orgNameOrID     string
		// serviceID is the row to inspect afterwards, kept separate so the
		// assertion does not have to guess whether serviceNameOrID was a
		// name or a UUID.
		serviceID      string
		disabled       bool
		expectedStatus int
		expectDisabled bool
	}{
		{
			description:     "superuser disables by ID",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			serviceID:       "00000003-0000-0000-0000-000000000001",
			disabled:        true,
			expectedStatus:  http.StatusNoContent,
			expectDisabled:  true,
		},
		{
			description:     "superuser enables by ID again",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			serviceID:       "00000003-0000-0000-0000-000000000001",
			disabled:        false,
			expectedStatus:  http.StatusNoContent,
			expectDisabled:  false,
		},
		{
			description:     "disable again after enable",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			serviceID:       "00000003-0000-0000-0000-000000000001",
			disabled:        true,
			expectedStatus:  http.StatusNoContent,
			expectDisabled:  true,
		},
		{
			description:     "org member disables by name",
			username:        "username1",
			password:        validUserPassword,
			serviceNameOrID: "org1-service2",
			orgNameOrID:     "org1",
			serviceID:       "00000003-0000-0000-0000-000000000002",
			disabled:        true,
			expectedStatus:  http.StatusNoContent,
			expectDisabled:  true,
		},
		{
			description:     "org member enables by name",
			username:        "username1",
			password:        validUserPassword,
			serviceNameOrID: "org1-service2",
			orgNameOrID:     "org1",
			serviceID:       "00000003-0000-0000-0000-000000000002",
			disabled:        false,
			expectedStatus:  http.StatusNoContent,
			expectDisabled:  false,
		},
		{
			description:     "org member disables by name with org addressed by UUID",
			username:        "username1",
			password:        validUserPassword,
			serviceNameOrID: "org1-service4",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceID:       "00000003-0000-0000-0000-000000000010",
			disabled:        true,
			expectedStatus:  http.StatusNoContent,
			expectDisabled:  true,
		},
		{
			description:     "non-member cannot disable another org's service",
			username:        "username2",
			password:        "password2",
			serviceNameOrID: "00000003-0000-0000-0000-000000000003",
			serviceID:       "00000003-0000-0000-0000-000000000003",
			disabled:        true,
			expectedStatus:  http.StatusNotFound,
		},
		{
			description:     "user without org cannot disable",
			username:        "username3-no-org",
			password:        "password3",
			serviceNameOrID: "00000003-0000-0000-0000-000000000003",
			serviceID:       "00000003-0000-0000-0000-000000000003",
			disabled:        true,
			expectedStatus:  http.StatusNotFound,
		},
		{
			description:     "unresolvable org is unprocessable",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "org1-service3",
			orgNameOrID:     "no-such-org",
			serviceID:       "00000003-0000-0000-0000-000000000003",
			disabled:        true,
			expectedStatus:  http.StatusUnprocessableEntity,
		},
		{
			description:     "unknown service ID is not found",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-0000000000ff",
			disabled:        true,
			expectedStatus:  http.StatusNotFound,
		},
		{
			// ?org= is documented as required when the service is addressed by
			// name.
			description:     "name without org is unprocessable, not a server error",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "org1-service4",
			disabled:        true,
			expectedStatus:  http.StatusUnprocessableEntity,
		},
	}

	// disabledIDs returns every currently disabled service ID in a stable
	// order so a refusal can be proven to have changed nothing at all rather
	// than merely nothing about its own target row.
	disabledIDs := func() []string {
		t.Helper()
		rows, err := dbPool.Query(ctx, "SELECT id::text FROM services WHERE disabled_at IS NOT NULL ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()

		ids := []string{}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return ids
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			before := disabledIDs()

			body := fmt.Sprintf(`{"disabled": %t}`, test.disabled)

			req, err := http.NewRequest(
				http.MethodPut,
				ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/disabled",
				strings.NewReader(body),
			)
			if err != nil {
				t.Fatal(err)
			}

			if test.orgNameOrID != "" {
				values := req.URL.Query()
				values.Add("org", test.orgNameOrID)
				req.URL.RawQuery = values.Encode()
			}

			req.Header.Set("Content-Type", "application/json")
			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				t.Fatalf("PUT service disabled unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			// Every case checks the database, including the refusals: a
			// handler that returned 404 while disabling the row anyway
			// would otherwise pass.
			if test.expectedStatus != http.StatusNoContent {
				// A refusal must change nothing anywhere. Comparing the
				// whole set of disabled rows against the pre-request
				// snapshot works even for the unknown-ID case, where the
				// target row does not exist to be selected. A per-row
				// SELECT would hit pgx.ErrNoRows and abort the test
				// instead of proving anything.
				after := disabledIDs()
				if !slices.Equal(before, after) {
					t.Errorf("a refused request must not change any row's disabled_at: %v -> %v", before, after)
				}
				return
			}

			if test.serviceID == "" {
				t.Fatal("a success case must name the serviceID to verify")
			}

			var disabledAt *time.Time
			err = dbPool.QueryRow(ctx, "SELECT disabled_at FROM services WHERE id = $1", test.serviceID).Scan(&disabledAt)
			if err != nil {
				t.Fatal(err)
			}

			if test.expectDisabled && disabledAt == nil {
				t.Error("expected service to be disabled")
			}
			if !test.expectDisabled && disabledAt != nil {
				t.Errorf("expected service to be enabled, got disabled_at=%v", disabledAt)
			}
		})
	}
}

// TestServiceDisableIsIdempotent proves that a repeated disable does not move
// disabled_at forward. This is what the console renders as "Disabled <date>",
// and what a future retention policy would key on, so a silently-resetting
// timestamp would make both drift over time.
func TestServiceDisableIsIdempotent(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	const serviceID = "00000003-0000-0000-0000-000000000001"

	disable := func() {
		t.Helper()

		req, err := http.NewRequest(
			http.MethodPut,
			ts.URL+"/api/v1/services/"+serviceID+"/disabled",
			strings.NewReader(`{"disabled": true}`),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth("admin", validAdminPassword)

		resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
		}
	}

	readDisabledAt := func() *time.Time {
		t.Helper()
		var disabledAt *time.Time
		err := dbPool.QueryRow(ctx, "SELECT disabled_at FROM services WHERE id = $1", serviceID).Scan(&disabledAt)
		if err != nil {
			t.Fatal(err)
		}
		return disabledAt
	}

	disable()
	first := readDisabledAt()
	if first == nil {
		t.Fatal("expected service to be disabled after first disable")
	}

	disable()
	second := readDisabledAt()
	if second == nil {
		t.Fatal("expected service to be disabled after second disable")
	}

	if !first.Equal(*second) {
		t.Errorf("repeated disable moved disabled_at: %v -> %v", first, second)
	}
}

// TestServiceDisableEnableRoundTrip pins the invariants that make a mistaken
// disable recoverable: the same version stays active, and the IP addresses and
// uid range are untouched.
func TestServiceDisableEnableRoundTrip(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	const serviceID = "00000003-0000-0000-0000-000000000001"

	type snapshot struct {
		activeVersion int64
		addresses     []string
		uidFirst      int64
		uidLast       int64
	}

	takeSnapshot := func() snapshot {
		t.Helper()
		var s snapshot
		err := dbPool.QueryRow(
			ctx,
			`SELECT
			   (SELECT version FROM service_versions WHERE service_id = services.id AND active),
			   (SELECT array_agg(address::text ORDER BY address) FROM service_ip_addresses WHERE service_id = services.id),
			   lower(services.uid_range),
			   upper(services.uid_range)-1
			 FROM services WHERE id = $1`,
			serviceID,
		).Scan(&s.activeVersion, &s.addresses, &s.uidFirst, &s.uidLast)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	setDisabled := func(disabled bool) {
		t.Helper()

		req, err := http.NewRequest(
			http.MethodPut,
			ts.URL+"/api/v1/services/"+serviceID+"/disabled",
			strings.NewReader(fmt.Sprintf(`{"disabled": %t}`, disabled)),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth("admin", validAdminPassword)

		resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
		}
	}

	before := takeSnapshot()

	setDisabled(true)

	// Everything except disabled_at must survive the disable.
	during := takeSnapshot()
	if during.activeVersion != before.activeVersion {
		t.Errorf("active version changed on disable: %d -> %d", before.activeVersion, during.activeVersion)
	}

	setDisabled(false)

	after := takeSnapshot()
	if after.activeVersion != before.activeVersion {
		t.Errorf("active version changed over the round trip: %d -> %d", before.activeVersion, after.activeVersion)
	}
	if !slices.Equal(after.addresses, before.addresses) {
		t.Errorf("IP addresses changed over the round trip: %v -> %v", before.addresses, after.addresses)
	}
	if after.uidFirst != before.uidFirst || after.uidLast != before.uidLast {
		t.Errorf("uid range changed over the round trip: %d-%d -> %d-%d", before.uidFirst, before.uidLast, after.uidFirst, after.uidLast)
	}
}

func TestConsoleServicesQuotaLine(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	_, err = dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = '00000003-0000-0000-0000-000000000002'")
	if err != nil {
		t.Fatal(err)
	}

	client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)

	resp, err := client.Get(ts.URL + "/console/org/org1/services") // #nosec G704
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	text := doc.Text()

	// org1 has 6 fixture services, one of which is now disabled, against a
	// quota of 100. A tenant who hits the quota needs to see that a disabled
	// service is holding a slot.
	if !strings.Contains(text, "6 of 100 services used") {
		t.Errorf("expected quota usage line, page text was: %s", text)
	}
	if !strings.Contains(text, "1 disabled") {
		t.Errorf("expected disabled count in quota usage line, page text was: %s", text)
	}
}

// TestDisabledServiceConsumesQuota verifies the a disabled service still
// occupies a quota slot.
func TestDisabledServiceConsumesQuota(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	// org4 has no services and the default service_quota of 1.
	createService := func(name string) int {
		t.Helper()

		body := fmt.Sprintf(`{"name": %q, "org": "org4"}`, name)

		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/services", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth("admin", validAdminPassword)

		resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		return resp.StatusCode
	}

	if status := createService("org4-service1"); status != http.StatusCreated {
		t.Fatalf("expected 201 creating the first service, got %d", status)
	}

	// Disabling it must NOT free the slot.
	_, err = dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE name = 'org4-service1'")
	if err != nil {
		t.Fatal(err)
	}

	if status := createService("org4-service2"); status != http.StatusConflict {
		t.Errorf("a disabled service must still consume its quota slot, expected 409, got %d", status)
	}
}

func TestDeleteService(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	// Pre-disable the services used by the cases that are expected to get
	// past the disabled-state precondition.
	for _, id := range []string{
		"00000003-0000-0000-0000-000000000001",
		"00000003-0000-0000-0000-000000000002",
		"00000003-0000-0000-0000-000000000003",
		"00000003-0000-0000-0000-000000000010",
	} {
		_, err = dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = $1", id)
		if err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		description     string
		username        string
		password        string
		serviceNameOrID string
		orgNameOrID     string
		confirm         string
		expectedStatus  int
		// serviceID is the row to check afterwards. Every case asserts the
		// row's fate explicitly: gone when the delete was meant to succeed,
		// still present when it was meant to be refused. Without this a
		// handler that returned 409 while deleting anyway would pass.
		serviceID     string
		expectRowGone bool
		// expectVersions is how many service_versions rows must still exist
		// after a REFUSED delete, so a refusal is proven not to have
		// cascaded. Only set where the fixture gives the target versions.
		expectVersions int64
	}{
		{
			description:     "superuser deletes disabled service by ID with confirmation",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			confirm:         "org1-service1",
			expectedStatus:  http.StatusNoContent,
			serviceID:       "00000003-0000-0000-0000-000000000001",
			expectRowGone:   true,
		},
		{
			description:     "superuser deletes disabled service by name with confirmation",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "org1-service2",
			orgNameOrID:     "org1",
			confirm:         "org1-service2",
			expectedStatus:  http.StatusNoContent,
			serviceID:       "00000003-0000-0000-0000-000000000002",
			expectRowGone:   true,
		},
		{
			description:     "missing confirmation is rejected",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000003",
			confirm:         "",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceID:       "00000003-0000-0000-0000-000000000003",
			expectRowGone:   false,
		},
		{
			description:     "wrong confirmation name is rejected",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000003",
			confirm:         "org1-service9",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceID:       "00000003-0000-0000-0000-000000000003",
			expectRowGone:   false,
		},
		{
			// Deliberately targets org2-service1 rather than an empty
			// service: the fixture gives it three versions, so the
			// cascade-survival assertion below has something real to
			// check. A refusal that had already cascaded would be caught
			// here and nowhere else.
			description:     "enabled service cannot be deleted",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000004",
			confirm:         "org2-service1",
			expectedStatus:  http.StatusConflict,
			serviceID:       "00000003-0000-0000-0000-000000000004",
			expectRowGone:   false,
			expectVersions:  3,
		},
		{
			description:     "org member cannot delete their own disabled service",
			username:        "username1",
			password:        validUserPassword,
			serviceNameOrID: "00000003-0000-0000-0000-000000000010",
			confirm:         "org1-service4",
			expectedStatus:  http.StatusForbidden,
			serviceID:       "00000003-0000-0000-0000-000000000010",
			expectRowGone:   false,
		},
		{
			description:     "non-member gets forbidden, not found, so existence does not leak",
			username:        "username2",
			password:        "password2",
			serviceNameOrID: "00000003-0000-0000-0000-000000000010",
			confirm:         "org1-service4",
			expectedStatus:  http.StatusForbidden,
			serviceID:       "00000003-0000-0000-0000-000000000010",
			expectRowGone:   false,
		},
		{
			description:     "user without org is forbidden",
			username:        "username3-no-org",
			password:        "password3",
			serviceNameOrID: "00000003-0000-0000-0000-000000000010",
			confirm:         "org1-service4",
			expectedStatus:  http.StatusForbidden,
			serviceID:       "00000003-0000-0000-0000-000000000010",
			expectRowGone:   false,
		},
		{
			description:     "non-superuser is forbidden even for a service that does not exist",
			username:        "username1",
			password:        validUserPassword,
			serviceNameOrID: "00000003-0000-0000-0000-0000000000ff",
			confirm:         "whatever",
			expectedStatus:  http.StatusForbidden,
			// No serviceID: this UUID matches no row, so there is nothing to assert.
		},
		{
			description:     "superuser gets not-found for an unknown service",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "00000003-0000-0000-0000-0000000000ff",
			confirm:         "whatever",
			expectedStatus:  http.StatusNotFound,
			// No serviceID: nothing to assert.
		},
		{
			description:     "superuser gets unprocessable for an unresolvable org",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "org1-service3",
			orgNameOrID:     "no-such-org",
			confirm:         "org1-service3",
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceID:       "00000003-0000-0000-0000-000000000003",
			expectRowGone:   false,
		},
		{
			// newOrgIdentifier is exercised by name in other tables, but
			// this endpoint's own ?org=<...> parameter had never been
			// exercised with a UUID rather than a name. org1-service3 is
			// pre-disabled by this test's setup and, unlike org1-service1/2
			// above, survives every case before this one untouched.
			description:     "superuser deletes disabled service by name with org addressed by UUID",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "org1-service3",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			confirm:         "org1-service3",
			expectedStatus:  http.StatusNoContent,
			serviceID:       "00000003-0000-0000-0000-000000000003",
			expectRowGone:   true,
		},
		{
			// The endpoint documents ?org= as required when the service is
			// addressed by name. Without it the identifier lookup returns
			// ErrServiceByNameNeedsOrg, which used to reach the generic error
			// path and surface as a 500. No serviceID: the lookup fails on the
			// missing org before it queries at all, so the name need not
			// resolve and there is no row to assert.
			description:     "name without org is unprocessable, not a server error",
			username:        "admin",
			password:        validAdminPassword,
			serviceNameOrID: "org1-service4",
			confirm:         "org1-service4",
			expectedStatus:  http.StatusUnprocessableEntity,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/services/"+test.serviceNameOrID, nil)
			if err != nil {
				t.Fatal(err)
			}

			values := req.URL.Query()
			if test.orgNameOrID != "" {
				values.Add("org", test.orgNameOrID)
			}
			if test.confirm != "" {
				values.Add("confirm", test.confirm)
			}
			req.URL.RawQuery = values.Encode()

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				t.Fatalf("DELETE service unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			if test.serviceID == "" {
				return
			}

			var count int64
			err = dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM services WHERE id = $1", test.serviceID).Scan(&count)
			if err != nil {
				t.Fatal(err)
			}

			if test.expectRowGone && count != 0 {
				t.Error("service row should have been deleted")
			}
			if !test.expectRowGone && count != 1 {
				t.Errorf("service row must survive a refused delete, COUNT(*) = %d", count)
			}

			// The services row disappearing is not the whole story. The
			// reason this operation needs guarding is that it also releases
			// the service's IP addresses for reallocation and destroys every
			// version with its origins, domain bindings and VCL — the part
			// the spec calls "not easily reconstructed". Assert the cascade
			// actually fired, and conversely that a refusal left it intact.
			var ipCount, versionCount int64
			err = dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM service_ip_addresses WHERE service_id = $1", test.serviceID).Scan(&ipCount)
			if err != nil {
				t.Fatal(err)
			}
			err = dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM service_versions WHERE service_id = $1", test.serviceID).Scan(&versionCount)
			if err != nil {
				t.Fatal(err)
			}

			if test.expectRowGone {
				// The success cases target org1-service1 and org1-service2,
				// the only two services the fixture gives IP addresses, so
				// these assertions are not vacuous.
				if ipCount != 0 {
					t.Errorf("deleting a service must release its IP addresses, %d remain", ipCount)
				}
				if versionCount != 0 {
					t.Errorf("deleting a service must remove its versions, %d remain", versionCount)
				}
			} else if test.expectVersions > 0 && versionCount != test.expectVersions {
				t.Errorf("a refused delete must not cascade, expected %d versions got %d", test.expectVersions, versionCount)
			}
		})
	}
}

func TestPostServices(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			newService:     "new-admin-service",
			org:            "org1",
		},
		{
			description:    "successful superuser request with name right at limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			newService:     strings.Repeat("a", 63),
			org:            "org1",
		},
		{
			description:    "successful superuser request with org UUID",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			newService:     "new-admin-service-by-uuid",
			org:            "00000002-0000-0000-0000-000000000001",
		},
		{
			description:    "failed superuser request with org as invalid DNS label",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new-admin-service",
			org:            "org 1",
		},
		{
			description:    "failed superuser request with service as invalid DNS label",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new admin-service",
			org:            "org1",
		},
		{
			description:    "failed superuser request with name above limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     strings.Repeat("a", 64),
			org:            "org1",
		},
		{
			description:    "failed superuser request with name below limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "",
			org:            "org1",
		},
		{
			description:    "failed superuser request without org",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new-admin-service",
		},
		{
			description:    "failed org request with org matching auth (no org supplied in request)",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "new-username1-service1",
		},
		{
			description:    "successful org request with org matching auth",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusCreated,
			newService:     "new-username1-service1",
			org:            "org1",
		},
		{
			description:    "failed org request with duplicate service name",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusConflict,
			newService:     "new-username1-service1",
			org:            "org1",
		},
		{
			description:    "failed org request with org not matching auth",
			username:       "username1",
			password:       validUserPassword,
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
			password:       validAdminPassword,
			newService:     "new-admin-org-4-service1",
			expectedStatus: http.StatusCreated,
			org:            "org4",
		},
		{
			description:    "failed admin request outside services_limit (second service)",
			username:       "admin",
			password:       validAdminPassword,
			newService:     "new-admin-org-4-service2",
			expectedStatus: http.StatusConflict,
			org:            "org4",
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint
			description:    "failed superuser request with UUID name",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			newService:     "abcdef01-2345-6789-abcd-ef0123456789",
			org:            "org1",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
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

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/services", r)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("POST services unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestDeleteDomain(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
			domainNameOrID: "00000015-0000-0000-0000-000000000004",
			expectedStatus: http.StatusNoContent,
		},
		{
			description:    "successful superuser request with name",
			username:       "admin",
			password:       validAdminPassword,
			domainNameOrID: "example-delete-2.se",
			expectedStatus: http.StatusNoContent,
		},
		{
			description:    "successful user request with ID",
			username:       "username1",
			password:       validUserPassword,
			domainNameOrID: "00000015-0000-0000-0000-000000000006",
			expectedStatus: http.StatusNoContent,
		},
		{
			description:    "successful user request with name",
			username:       "username1",
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			if test.domainNameOrID == "" {
				t.Fatal("user needs domain name or ID for domain test")
			}

			req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/domains/"+test.domainNameOrID, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("DELETE service by ID unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPostDomains(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		newDomain           string
		canonicalizedDomain string
		orgNameOrID         string
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			newDomain:      "example.net",
			orgNameOrID:    "org1",
		},
		{
			description:         "successful superuser request with trailing dot",
			username:            "admin",
			password:            validAdminPassword,
			expectedStatus:      http.StatusCreated,
			newDomain:           "trailing.example.com.",
			canonicalizedDomain: "trailing.example.com",
			orgNameOrID:         "org1",
		},
		{
			description:         "successful superuser request with IDN domain",
			username:            "admin",
			password:            validAdminPassword,
			expectedStatus:      http.StatusCreated,
			newDomain:           "räksmörgås.example.com",
			canonicalizedDomain: "xn--rksmrgs-5wao1o.example.com",
			orgNameOrID:         "org1",
		},
		{
			description:    "failed superuser request with invalid DNS name",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			newDomain:      "example .nu",
			orgNameOrID:    "org1",
		},
		{
			description:    "failed superuser request, no org query param",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			newDomain:      "example.net",
			orgNameOrID:    "",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			newDomain := struct {
				FQDN string `json:"fqdn"`
			}{
				FQDN: test.newDomain,
			}

			b, err := json.Marshal(newDomain)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/domains", r)
			if err != nil {
				t.Fatal(err)
			}

			if test.orgNameOrID != "" {
				values := req.URL.Query()
				values.Add("org", test.orgNameOrID)
				req.URL.RawQuery = values.Encode()
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("POST services unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if test.expectedStatus == http.StatusCreated {
				resData := struct {
					FQDN string `json:"fqdn"`
				}{}
				err := json.Unmarshal(jsonData, &resData)
				if err != nil {
					t.Fatal(err)
				}

				expectedDomain := test.newDomain
				if test.canonicalizedDomain != "" {
					expectedDomain = test.canonicalizedDomain
				}

				if resData.FQDN != expectedDomain {
					t.Fatalf("unexpected fqdn in creation response, want: '%s', have: '%s'", expectedDomain, resData.FQDN)
				}
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetServiceVersions(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
	}{
		{
			description:     "successful superuser request with id",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
		},
		{
			description:     "successful user request with id",
			username:        "username1",
			password:        validUserPassword,
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
		},
		{
			description:     "successful user request with name",
			username:        "username1",
			password:        validUserPassword,
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
			password:        validUserPassword,
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "org1-service1",
		},
		{
			description:     "failed superuser request with name, missing org",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "org1-service1",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/service-versions", nil)
			if err != nil {
				t.Fatal(err)
			}

			if test.orgNameOrID != "" {
				values := req.URL.Query()
				values.Add("org", test.orgNameOrID)
				req.URL.RawQuery = values.Encode()
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET service versions unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
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

	ts, dbPool, err := prepareServer(t, testServerInput{vclValidator: vclValidator})
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
		newService         string
		orgNameOrID        string
		serviceNameOrID    string
		domains            []string
		conditionalGroups  []cdntypes.InputConditionalOriginGroup
		defaultGroup       cdntypes.InputDefaultOriginGroup
		active             bool
		vclTemplateFile    string
		assertOriginGroups bool
		versionDescription string
	}{
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.20", Port: 443, TLS: true, VerifyTLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:     http.StatusCreated,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			versionDescription: "first version",
		},
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusCreated,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request with ID, domain not known",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"nonexistant.com"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request with ID, domain exist but not verified",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.nu"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request with ID, broken vcl_recv",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/broken_template1.vcl",
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "org1-service1",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusCreated,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request with name (name does not exist)",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "does-not-exist",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request with too many domains",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"1.com", "2.com", "3.com", "4.com", "5.com", "6.com", "7.com", "8.com", "9.com", "10.com", "11.com"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request, too long Host in origin list",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: strings.Repeat("a", 254), Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request, too long domain in domains list",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{strings.Repeat("a", 254), "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request, too long description",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:     http.StatusUnprocessableEntity,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			versionDescription: strings.Repeat("a", 513),
		},
		{
			description:     "failed superuser request with invalid service name (too long)",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: strings.Repeat("a", 64),
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request with invalid uuid (too short)",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "successful user request",
			username:        "username1",
			password:        validUserPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusCreated,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed user request not assigned to org",
			username:        "username3-no-org",
			password:        "password3",
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusForbidden,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request, missing default group",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			defaultGroup:    cdntypes.InputDefaultOriginGroup{},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request, default group with zero origins",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			defaultGroup:    cdntypes.InputDefaultOriginGroup{},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request, conditional group with empty condition",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.30", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request, duplicate origin group names",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "default",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.30", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request, identical conditions on two groups",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "api",
					Condition: "req.url ~ \"^/api/\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.30", Port: 443, TLS: true},
					},
				},
				{
					Name:      "api2",
					Condition: "req.url ~ \"^/api/\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.31", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "failed superuser request, condition fails varnish compilation",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.nonexistent.field == true",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.30", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			description:     "successful superuser request with conditional origin group",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.30", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:     http.StatusCreated,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			assertOriginGroups: true,
		},
		{
			description:     "successful superuser request with default origin group using ipv4-mapped ipv6 address",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.30", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "::ffff:192.51.100.20", Port: 443, TLS: true},
					{Host: "::ffff:192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:     http.StatusCreated,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			assertOriginGroups: true,
		},
		{
			description:     "successful superuser request with conditional origin group using ipv4-mapped ipv6 address",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "::ffff:192.51.100.20", Port: 443, TLS: true},
						{Host: "::ffff:192.51.100.21", Port: 80, TLS: false},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.30", Port: 443, TLS: true},
				},
			},
			expectedStatus:     http.StatusCreated,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			assertOriginGroups: true,
		},
		{
			description:     "successful superuser request with conditional origin group using DNS domain",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.30", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "srv1.example.com", Port: 443, TLS: true},
					{Host: "srv1.example.com", Port: 80, TLS: false},
				},
			},
			expectedStatus:     http.StatusCreated,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			assertOriginGroups: true,
		},
		{
			description:     "successful superuser request with default origin group using IDN DNS domain",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.30", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "srv1.räksmörgås.example.com", Port: 443, TLS: true},
					{Host: "srv1.räksmörgås.example.com", Port: 80, TLS: false},
				},
			},
			expectedStatus:     http.StatusCreated,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			assertOriginGroups: true,
		},
		{
			description:     "successful superuser request with conditional origin group using IDN DNS domain",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "srv1.räksmörgås.example.com", Port: 443, TLS: true},
						{Host: "srv1.räksmörgås.example.com", Port: 80, TLS: false},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.30", Port: 443, TLS: true},
				},
			},
			expectedStatus:     http.StatusCreated,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			assertOriginGroups: true,
		},
		{
			description:     "failed superuser request with conditional origin group attempting config injection via default origin field",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.30", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "127.0.0.1:8080 resolvers mydns\nprogram scm_poc\n        command /usr/bin/touch /evidence/HAPROXY-CODE-EXECUTED\n        no option start-on-reload\n#", Port: 80, TLS: false},
				},
			},
			expectedStatus:     http.StatusUnprocessableEntity,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			assertOriginGroups: false,
		},
		{
			description:     "failed superuser request with conditional origin group attempting config injection via conditional origin field",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "127.0.0.1:8080 resolvers mydns\nprogram scm_poc\n        command /usr/bin/touch /evidence/HAPROXY-CODE-EXECUTED\n        no option start-on-reload\n#", Port: 80, TLS: false},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.30", Port: 443, TLS: true},
				},
			},
			expectedStatus:     http.StatusUnprocessableEntity,
			active:             true,
			vclTemplateFile:    "testdata/vcl/template1.vcl",
			assertOriginGroups: false,
		},
		{
			// The group name starts with a letter and only contains
			// [-a-z0-9], so it passes huma's request pattern validation,
			// but it fails the DB's valid_name/is_valid_dns_label CHECK
			// constraint since it is UUID-shaped (is_not_uuid()). This
			// exercises insertServiceVersion's pgCheckViolation mapping to
			// cdnerrors.ErrCheckViolation rather than a bare 500.
			description:     "failed superuser request, conditional group name is UUID-shaped",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "abcdef01-2345-6789-abcd-ef0123456789",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.31", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "192.51.100.20", Port: 443, TLS: true},
					{Host: "192.51.100.21", Port: 80, TLS: false},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
		{
			// The same host:port pair is used in both the conditional
			// group and the default group. Nothing at the Go validation
			// level rejects this, so it reaches the DB and trips
			// service_origins' UNIQUE(service_version_id, host, port)
			// constraint, exercising insertServiceVersion's
			// pgUniqueViolation mapping to cdnerrors.DuplicateOriginError
			// rather than a bare 500.
			description:     "failed superuser request, duplicate origin host:port across groups",
			username:        "admin",
			password:        validAdminPassword,
			orgNameOrID:     "org1",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			domains:         []string{"example.com", "example.se"},
			conditionalGroups: []cdntypes.InputConditionalOriginGroup{
				{
					Name:      "beta",
					Condition: "req.http.host == \"example.com\"",
					Origins: []cdntypes.InputOrigin{
						{Host: "198.51.100.77", Port: 443, TLS: true},
					},
				},
			},
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.77", Port: 443, TLS: true},
				},
			},
			expectedStatus:  http.StatusUnprocessableEntity,
			active:          true,
			vclTemplateFile: "testdata/vcl/template1.vcl",
		},
	}

	// This table needs to be updated as new variations on origin hosts are
	// added above to verify expected canonicalization.
	expectedCanonicalization := map[string]string{
		"srv1.räksmörgås.example.com": "srv1.xn--rksmrgs-5wao1o.example.com",
		"::ffff:192.51.100.20":        "192.51.100.20",
		"::ffff:192.51.100.21":        "192.51.100.21",
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			newServiceVersion := struct {
				Org                     string                                 `json:"org"`
				Active                  bool                                   `json:"active"`
				Domains                 []string                               `json:"domains"`
				ConditionalOriginGroups []cdntypes.InputConditionalOriginGroup `json:"conditional_origin_groups,omitempty"`
				DefaultOriginGroup      cdntypes.InputDefaultOriginGroup       `json:"default_origin_group"`
				VCLTemplate             string                                 `json:"vcl_template"`
				Description             string                                 `json:"description,omitempty"`
			}{
				Org:                     test.orgNameOrID,
				Active:                  test.active,
				Domains:                 test.domains,
				ConditionalOriginGroups: test.conditionalGroups,
				DefaultOriginGroup:      test.defaultGroup,
				Description:             test.versionDescription,
			}

			var vclTemplateContentBytes []byte
			if test.vclTemplateFile != "" {
				vclTemplateContentBytes, err = os.ReadFile(test.vclTemplateFile)
				if err != nil {
					t.Fatal(err)
				}
				newServiceVersion.VCLTemplate = string(vclTemplateContentBytes)
			}

			b, err := json.Marshal(newServiceVersion)
			if err != nil {
				t.Fatal(err)
			}

			t.Log(string(b))

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/service-versions", r)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET service versions unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)

			if test.expectedStatus == http.StatusCreated {
				var createdVersion cdntypes.ServiceVersion
				if err := json.Unmarshal(jsonData, &createdVersion); err != nil {
					t.Fatalf("unable to unmarshal created service version: %s", err)
				}
				if createdVersion.Description != test.versionDescription {
					t.Errorf("created service version description: got %q, want %q", createdVersion.Description, test.versionDescription)
				}
				var dbDescription string
				err = dbPool.QueryRow(
					ctx,
					"SELECT description FROM service_versions WHERE id = $1",
					createdVersion.ID,
				).Scan(&dbDescription)
				if err != nil {
					t.Fatalf("unable to query service_versions for description: %s", err)
				}

				if test.versionDescription != dbDescription {
					t.Fatalf("database does not contain expected description: want: %s, have: %s", test.versionDescription, dbDescription)
				}
			}

			if test.assertOriginGroups {
				var createdVersion cdntypes.ServiceVersion
				if err := json.Unmarshal(jsonData, &createdVersion); err != nil {
					t.Fatalf("unable to unmarshal created service version: %s", err)
				}

				type storedOriginGroupRow struct {
					id           pgtype.UUID
					name         string
					defaultGroup bool
					condition    *string
					position     int64
					origins      []cdntypes.InputOrigin
				}

				rows, err := dbPool.Query(
					ctx,
					"SELECT id, name, default_group, condition, position FROM service_origin_groups WHERE service_version_id = $1 ORDER BY position",
					createdVersion.ID,
				)
				if err != nil {
					t.Fatalf("unable to query service_origin_groups: %s", err)
				}

				var stored []storedOriginGroupRow
				for rows.Next() {
					var row storedOriginGroupRow
					if err := rows.Scan(&row.id, &row.name, &row.defaultGroup, &row.condition, &row.position); err != nil {
						t.Fatalf("unable to scan service_origin_groups row: %s", err)
					}
					stored = append(stored, row)
				}
				if err := rows.Err(); err != nil {
					t.Fatalf("error iterating service_origin_groups rows: %s", err)
				}

				// Build the expected rows from the submitted payload:
				// conditional groups in list order at positions 0..n-1
				// with their condition text, default group last with a
				// NULL condition.
				var expected []storedOriginGroupRow
				for _, cg := range test.conditionalGroups {
					sogr := storedOriginGroupRow{
						name:         cg.Name,
						defaultGroup: false,
						condition:    &cg.Condition,
						position:     int64(len(expected)),
					}
					for _, o := range cg.Origins {
						origHost := o.Host
						// Make sure the content in the
						// database has been
						// canonicalized to e.g.
						// punycode for hostnames or
						// unmapped ipv4 addresses.
						o.Host, err = canonicalizeOriginHost(o.Host)
						if err != nil {
							t.Fatalf("conditional group: unable to canonicalize origin host '%s'", o.Host)
						}
						sogr.origins = append(sogr.origins, o)

						if origHost != o.Host {
							t.Logf("conditional origin group host updated by canonicalization: from: '%s' to: '%s'", origHost, o.Host)
							expectedCanonRes, ok := expectedCanonicalization[origHost]
							if !ok {
								t.Fatalf("unable to look up expected canonicalization for conditional origin group host '%s'", origHost)
							} else {
								if o.Host != expectedCanonRes {
									t.Fatalf("expected conditional origin host '%s' to be modified to '%s', got '%s'", origHost, expectedCanonRes, o.Host)
								}
							}
						}
					}

					expected = append(expected, sogr)
				}

				sogr := storedOriginGroupRow{
					name:         cdntypes.DefaultOriginGroupName,
					defaultGroup: true,
					condition:    nil,
					position:     int64(len(expected)),
				}
				for _, o := range test.defaultGroup.Origins {
					origHost := o.Host
					// Make sure the content in the
					// database has been canonicalized to
					// e.g. punycode for hostnames or
					// unmapped ipv4 addresses.
					o.Host, err = canonicalizeOriginHost(o.Host)
					if err != nil {
						t.Fatalf("default group: unable to canonicalize origin host: '%s'", o.Host)
					}
					sogr.origins = append(sogr.origins, o)
					if origHost != o.Host {
						t.Logf("default origin group host updated by canonicalization: from: '%s' to: '%s'", origHost, o.Host)
						expectedCanonRes, ok := expectedCanonicalization[origHost]
						if !ok {
							t.Fatalf("unable to look up expected canonicalization for default origin host '%s'", origHost)
						} else {
							if o.Host != expectedCanonRes {
								t.Fatalf("expected default origin host '%s' to be modified to '%s', got '%s'", origHost, expectedCanonRes, o.Host)
							}
						}
					}
				}
				expected = append(expected, sogr)

				type storedOriginRow struct {
					host string
				}

				if len(stored) != len(expected) {
					t.Fatalf("service_origin_groups row count mismatch: got %d, want %d (%+v)", len(stored), len(expected), stored)
				}
				for i, want := range expected {
					got := stored[i]
					if got.name != want.name || got.defaultGroup != want.defaultGroup || got.position != want.position {
						t.Errorf("service_origin_groups row %d mismatch: got %+v, want name=%s default_group=%v position=%d", i, got, want.name, want.defaultGroup, want.position)
					}
					switch {
					case want.condition == nil && got.condition != nil:
						t.Errorf("service_origin_groups row %d: got condition %q, want NULL", i, *got.condition)
					case want.condition != nil && got.condition == nil:
						t.Errorf("service_origin_groups row %d: got NULL condition, want %q", i, *want.condition)
					case want.condition != nil && got.condition != nil && *want.condition != *got.condition:
						t.Errorf("service_origin_groups row %d: got condition %q, want %q", i, *got.condition, *want.condition)
					}

					rows, err := dbPool.Query(
						ctx,
						"SELECT host FROM service_origins WHERE service_version_id = $1 AND origin_group_id = $2 ORDER BY host",
						createdVersion.ID,
						got.id,
					)
					if err != nil {
						t.Fatalf("unable to query service_origins: %s", err)
					}

					var storedOrigins []storedOriginRow
					for rows.Next() {
						var row storedOriginRow
						if err := rows.Scan(&row.host); err != nil {
							t.Fatalf("unable to scan service_origins row: %s", err)
						}
						storedOrigins = append(storedOrigins, row)
					}
					if err := rows.Err(); err != nil {
						t.Fatalf("error iterating service_origins rows: %s", err)
					}

					if len(want.origins) != len(storedOrigins) {
						t.Fatalf("uneven origin count: got: %d, want: %d", len(want.origins), len(storedOrigins))
					}

					for _, wo := range want.origins {
						hostFound := false
						storedHosts := []string{}
						for _, so := range storedOrigins {
							storedHosts = append(storedHosts, so.host)
							if so.host == wo.Host {
								hostFound = true
								break
							}
						}
						if !hostFound {
							t.Fatalf("did not find origin host: %s, available: %s", wo.Host, &storedHosts)
						}
					}
				}

				if len(stored) != len(expected) {
					t.Fatalf("service_origin_groups row count mismatch: got %d, want %d (%+v)", len(stored), len(expected), stored)
				}
				for i, want := range expected {
					got := stored[i]
					if got.name != want.name || got.defaultGroup != want.defaultGroup || got.position != want.position {
						t.Errorf("service_origin_groups row %d mismatch: got %+v, want name=%s default_group=%v position=%d", i, got, want.name, want.defaultGroup, want.position)
					}
					switch {
					case want.condition == nil && got.condition != nil:
						t.Errorf("service_origin_groups row %d: got condition %q, want NULL", i, *got.condition)
					case want.condition != nil && got.condition == nil:
						t.Errorf("service_origin_groups row %d: got NULL condition, want %q", i, *want.condition)
					case want.condition != nil && got.condition != nil && *want.condition != *got.condition:
						t.Errorf("service_origin_groups row %d: got condition %q, want %q", i, *got.condition, *want.condition)
					}
				}

				// Additional API-side coverage: fetch the generated VCL for
				// the created version and confirm the selection chain lines
				// are present.
				vclReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/service-versions/"+strconv.FormatInt(createdVersion.Version, 10)+"/vcl", nil)
				if err != nil {
					t.Fatal(err)
				}
				vclValues := vclReq.URL.Query()
				vclValues.Add("org", test.orgNameOrID)
				vclReq.URL.RawQuery = vclValues.Encode()
				vclReq.SetBasicAuth(test.username, test.password)

				vclResp, err := http.DefaultClient.Do(vclReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
				if err != nil {
					t.Fatal(err)
				}
				defer vclResp.Body.Close()

				vclJSONData, err := io.ReadAll(vclResp.Body)
				if err != nil {
					t.Fatal(err)
				}
				if vclResp.StatusCode != http.StatusOK {
					t.Fatalf("GET service-versions/{version}/vcl unexpected status code: %d (%s)", vclResp.StatusCode, string(vclJSONData))
				}

				var vclResult cdntypes.ServiceVersionVCL
				if err := json.Unmarshal(vclJSONData, &vclResult); err != nil {
					t.Fatalf("unable to unmarshal service version VCL response: %s", err)
				}

				wantChainLine := `if (req.http.host == "example.com") { # origin group "beta" (1/1)`
				wantElseLine := `} else { # default origin group "default"`
				if !strings.Contains(vclResult.VCL, wantChainLine) {
					t.Errorf("generated VCL missing chain line %q\n---\n%s", wantChainLine, vclResult.VCL)
				}
				if !strings.Contains(vclResult.VCL, wantElseLine) {
					t.Errorf("generated VCL missing else line %q\n---\n%s", wantElseLine, vclResult.VCL)
				}
			}
		})
	}
}

func TestActivateServiceVersion(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:        validAdminPassword,
			expectedStatus:  http.StatusNoContent,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         2,
			active:          true,
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusNoContent,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			version:         1,
			active:          true,
		},
		{
			description:     "failed superuser request with ID, not active",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         2,
			active:          false,
		},
		{
			description:     "failed superuser request with name, not active",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			version:         1,
			active:          false,
		},
		{
			description:     "failed superuser request with ID, non-existant version",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusNotFound,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         9999,
			active:          true,
		},
		{
			description:     "failed superuser request with ID, non-existant service ID",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-900000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         1,
			active:          true,
		},
		{
			description:     "failed superuser request with ID, non-existant org",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-900000000001",
			version:         1,
			active:          true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			active := struct {
				Active bool `json:"active"`
			}{
				Active: test.active,
			}

			b, err := json.Marshal(active)
			if err != nil {
				t.Fatal(err)
			}

			t.Log(string(b))

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/service-versions/"+strconv.FormatInt(test.version, 10)+"/active", r)
			if err != nil {
				t.Fatal(err)
			}

			values := req.URL.Query()
			values.Add("org", test.orgNameOrID)
			req.URL.RawQuery = values.Encode()

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET service versions unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetServiceVersionVCL(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:        validAdminPassword,
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         2,
		},
		{
			description:     "successful superuser request with name",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusOK,
			serviceNameOrID: "org1-service1",
			orgNameOrID:     "org1",
			version:         1,
		},
		{
			description:     "failed superuser request with ID, non-existant version",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusNotFound,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         9999,
		},
		{
			description:     "failed superuser request with ID, non-existant service ID",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-900000000001",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			version:         1,
		},
		{
			description:     "failed superuser request with ID, non-existant org",
			username:        "admin",
			password:        validAdminPassword,
			expectedStatus:  http.StatusUnprocessableEntity,
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			orgNameOrID:     "00000002-0000-0000-0000-900000000001",
			version:         1,
		},
		{
			description:     "successful org request",
			username:        "username1",
			password:        validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/service-versions/"+strconv.FormatInt(test.version, 10)+"/vcl", nil)
			if err != nil {
				t.Fatal(err)
			}

			values := req.URL.Query()
			values.Add("org", test.orgNameOrID)
			req.URL.RawQuery = values.Encode()

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET service versions unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetIPNetworks(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request, limit to ipv4",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusOK,
			family:         4,
		},
		{
			description:    "successful superuser request, limit to ipv6",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusOK,
			family:         6,
		},
		{
			description:    "failed superuser request, unknown family",
			username:       "admin",
			password:       validAdminPassword,
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
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/ip-networks", nil)
			if err != nil {
				t.Fatal(err)
			}

			if test.family != 0 {
				values := req.URL.Query()
				values.Add("family", strconv.Itoa(test.family))
				req.URL.RawQuery = values.Encode()
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET ip-networks unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)

			// Verify allocation counts for successful requests
			if test.expectedStatus == http.StatusOK && test.family == 0 {
				var networks []ipNetworkWithAllocated
				if err := json.Unmarshal(jsonData, &networks); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				allocations := map[string]int64{}
				for _, n := range networks {
					allocations[n.Network.String()] = n.Allocated
				}

				if allocations["192.0.2.0/24"] != 2 {
					t.Fatalf("expected 2 allocations for 192.0.2.0/24, got %d", allocations["192.0.2.0/24"])
				}
				if allocations["198.51.100.0/24"] != 0 {
					t.Fatalf("expected 0 allocations for 198.51.100.0/24, got %d", allocations["198.51.100.0/24"])
				}
			}
		})
	}
}

func TestPostIPNetworks(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			addedIPNetwork: netip.MustParsePrefix("10.0.0.0/24"),
		},
		{
			description:    "failed IPv4 superuser request (network overlaps the one inserted above)",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusConflict,
			addedIPNetwork: netip.MustParsePrefix("10.0.0.0/25"),
		},
		{
			description:    "failed IPv4 (duplicate) superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusConflict,
			addedIPNetwork: netip.MustParsePrefix("10.0.0.0/24"),
		},
		{
			description:    "successful IPv6 superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			addedIPNetwork: netip.MustParsePrefix("2001:db8:1::/48"),
		},
		{
			description:    "failed IPv6 superuser request (network overlaps the one inserted above)",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusConflict,
			addedIPNetwork: netip.MustParsePrefix("2001:db8:1::/64"),
		},
		{
			description:    "failed IPv6 (duplicate) superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusConflict,
			addedIPNetwork: netip.MustParsePrefix("2001:db8:1::/48"),
		},
		{
			description:    "failed IPv6 non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			addedIPNetwork: netip.MustParsePrefix("2001:db8:3::/64"),
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed IPv4 non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			addedIPNetwork: netip.MustParsePrefix("10.0.0.0/24"),
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
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

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ip-networks", r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("POST ip-networks unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestDeleteIPNetwork(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	// First create a network we can delete (no allocated IPs)
	newNet := struct {
		Network netip.Prefix `json:"network"`
	}{
		Network: netip.MustParsePrefix("10.10.0.0/24"),
	}
	b, err := json.Marshal(newNet)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/ip-networks", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentTypeJSON)
	req.SetBasicAuth("admin", validAdminPassword)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("failed to create test network: status %d", resp.StatusCode)
	}

	var created ipNetwork
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		description    string
		username       string
		password       string
		networkID      string
		expectedStatus int
	}{
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			networkID:      created.ID.String(),
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed request, invalid network ID format",
			username:       "admin",
			password:       validAdminPassword,
			networkID:      "not-a-uuid",
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			description:    "failed request, network not found",
			username:       "admin",
			password:       validAdminPassword,
			networkID:      "00000000-0000-0000-0000-000000000099",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "failed request, network has allocated IPs",
			username:       "admin",
			password:       validAdminPassword,
			networkID:      "00000011-0000-0000-0000-000000000001",
			expectedStatus: http.StatusConflict,
		},
		{
			description:    "successful delete by UUID (created network)",
			username:       "admin",
			password:       validAdminPassword,
			networkID:      created.ID.String(),
			expectedStatus: http.StatusNoContent,
		},
		{
			description:    "successful delete by UUID (seeded network without allocations)",
			username:       "admin",
			password:       validAdminPassword,
			networkID:      "00000011-0000-0000-0000-000000000002",
			expectedStatus: http.StatusNoContent,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/ip-networks/"+test.networkID, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("DELETE ip-networks unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			// Verify successful deletes by confirming re-delete returns 404
			if test.expectedStatus == http.StatusNoContent {
				req2, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/ip-networks/"+test.networkID, nil)
				if err != nil {
					t.Fatal(err)
				}
				req2.SetBasicAuth(test.username, test.password)

				resp2, err := http.DefaultClient.Do(req2) // #nosec G704 -- filled in by test, so not susceptible to SSRF
				if err != nil {
					t.Fatal(err)
				}
				defer resp2.Body.Close()

				if resp2.StatusCode != http.StatusNotFound {
					t.Fatalf("expected 404 after deletion, got %d", resp2.StatusCode)
				}
			}
		})
	}
}

func TestGetCacheNodeConfigs(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		cacheNodeNameOrID string
		expectedStatus    int
	}{
		{
			description:       "successful superuser request with id",
			username:          "admin",
			password:          validAdminPassword,
			cacheNodeNameOrID: "00000022-0000-0000-0000-000000000001",
			expectedStatus:    http.StatusOK,
		},
		{
			description:       "successful superuser request with name",
			username:          "admin",
			password:          validAdminPassword,
			cacheNodeNameOrID: "cache-node1",
			expectedStatus:    http.StatusOK,
		},
		{
			description:       "successful superuser request with id and node group membership",
			username:          "admin",
			password:          validAdminPassword,
			cacheNodeNameOrID: "00000022-0000-0000-0000-000000000003",
			expectedStatus:    http.StatusOK,
		},
		{
			description:       "successful superuser request with name and node group membership",
			username:          "admin",
			password:          validAdminPassword,
			cacheNodeNameOrID: "cache-node3",
			expectedStatus:    http.StatusOK,
		},
		{
			description:       "successful user request with 'node' role",
			username:          "node-user-1",
			password:          "nodeuserpass1",
			cacheNodeNameOrID: "cache-node1",
			expectedStatus:    http.StatusOK,
		},
		{
			description:       "failed superuser request, bad password",
			username:          "admin",
			password:          "badadminpass1",
			cacheNodeNameOrID: "cache-node1",
			expectedStatus:    http.StatusUnauthorized,
		},
		{
			description:       "failed request, normal user not allowed to request config",
			username:          "username1",
			password:          validUserPassword,
			cacheNodeNameOrID: "cache-node1",
			expectedStatus:    http.StatusForbidden,
		},
		{
			description:       "failed user request, bad password",
			username:          "username1",
			password:          "badpassword1",
			cacheNodeNameOrID: "cache-node1",
			expectedStatus:    http.StatusUnauthorized,
		},
		{
			description:       "failed user request, no password set",
			username:          "username4-no-pw",
			password:          "somepassword",
			cacheNodeNameOrID: "cache-node1",
			expectedStatus:    http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/cache-node-configs/"+test.cacheNodeNameOrID, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET cache-node-configs unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetL4LBNodeConfigs(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		l4lbNameOrID   string
		expectedStatus int
	}{
		{
			description:    "successful superuser request, with id",
			username:       "admin",
			password:       validAdminPassword,
			l4lbNameOrID:   "00000016-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request, with id that is member of node group",
			username:       "admin",
			password:       validAdminPassword,
			l4lbNameOrID:   "00000016-0000-0000-0000-000000000003",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request, with name",
			username:       "admin",
			password:       validAdminPassword,
			l4lbNameOrID:   "l4lb-node1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request, with name that is member if node group",
			username:       "admin",
			password:       validAdminPassword,
			l4lbNameOrID:   "l4lb-node3",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful user request with 'node' role and id",
			username:       "node-user-1",
			password:       "nodeuserpass1",
			l4lbNameOrID:   "00000016-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful user request with 'node' role and name",
			username:       "node-user-1",
			password:       "nodeuserpass1",
			l4lbNameOrID:   "00000016-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			l4lbNameOrID:   "l4lb-node1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed request, normal user not allowed to request config",
			username:       "username1",
			password:       validUserPassword,
			l4lbNameOrID:   "l4lb-node1",
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed user request, bad password",
			username:       "username1",
			password:       "badpassword1",
			l4lbNameOrID:   "l4lb-node1",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			l4lbNameOrID:   "l4lb-node1",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/l4lb-node-configs/"+test.l4lbNameOrID, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET l4lb-node-configs unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestCacheNodeConfigExcludesDisabledService(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	const (
		org1ID         = "00000002-0000-0000-0000-000000000001"
		org1Service1ID = "00000003-0000-0000-0000-000000000001"
	)

	getConfig := func() cdntypes.CacheNodeConfig {
		t.Helper()

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/cache-node-configs/cache-node1", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("admin", validAdminPassword)

		resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
		}

		var cnc cdntypes.CacheNodeConfig
		if err := json.NewDecoder(resp.Body).Decode(&cnc); err != nil {
			t.Fatal(err)
		}
		return cnc
	}

	// Baseline: org1-service1 is the only service satisfying every INNER JOIN
	// in the cache node config query, so it must be present to begin with.
	cnc := getConfig()
	if _, ok := cnc.Orgs[org1ID].Services[org1Service1ID]; !ok {
		t.Fatalf("expected org1-service1 in baseline cache node config, got orgs: %+v", cnc.Orgs)
	}

	_, err = dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = $1", org1Service1ID)
	if err != nil {
		t.Fatal(err)
	}

	cnc = getConfig()

	if _, ok := cnc.Orgs[org1ID].Services[org1Service1ID]; ok {
		t.Error("disabled service must not appear in the cache node config")
	}

	// org1-service1 was org1's only config-eligible service, so the org must
	// disappear entirely. The agent's orphaned-org cleanup branch depends on
	// this: it removes the whole org directory when an org is absent.
	if _, ok := cnc.Orgs[org1ID]; ok {
		t.Error("org with no enabled config-eligible services must not appear in the cache node config")
	}
}

func TestL4LBNodeConfigExcludesDisabledService(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	const (
		org1Service1ID = "00000003-0000-0000-0000-000000000001"
		org2Service1ID = "00000003-0000-0000-0000-000000000004"
	)

	getConfig := func() cdntypes.L4LBNodeConfig {
		t.Helper()

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/l4lb-node-configs/l4lb-node1", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("admin", validAdminPassword)

		resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
		}

		var lnc cdntypes.L4LBNodeConfig
		if err := json.NewDecoder(resp.Body).Decode(&lnc); err != nil {
			t.Fatal(err)
		}
		return lnc
	}

	hasService := func(lnc cdntypes.L4LBNodeConfig, id string) bool {
		for _, svc := range lnc.Services {
			if svc.ServiceID.String() == id {
				return true
			}
		}
		return false
	}

	// Baseline: the l4lb config selects on service_versions.active, so both
	// org1-service1 and org2-service1 are present.
	lnc := getConfig()
	if !hasService(lnc, org1Service1ID) {
		t.Fatalf("expected org1-service1 in baseline l4lb node config, got: %+v", lnc.Services)
	}
	if !hasService(lnc, org2Service1ID) {
		t.Fatalf("expected org2-service1 in baseline l4lb node config, got: %+v", lnc.Services)
	}

	_, err = dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = $1", org1Service1ID)
	if err != nil {
		t.Fatal(err)
	}

	lnc = getConfig()

	if hasService(lnc, org1Service1ID) {
		t.Error("disabled service must not appear in the l4lb node config")
	}

	// The other service's announcement must be untouched.
	if !hasService(lnc, org2Service1ID) {
		t.Error("disabling one service must not remove another service from the l4lb node config")
	}
}

// TestCacheNodeConfigExcludesDisabledServiceNewVersion covers the spec's
// "editing while disabled: allowed, just not deployed" rule. A brand new,
// fully configured, active version on a disabled service must still be absent
// from the config, because the filter keys off services.disabled_at and is
// independent of version state.
func TestCacheNodeConfigExcludesDisabledServiceNewVersion(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	const (
		org1ID         = "00000002-0000-0000-0000-000000000001"
		org1Service1ID = "00000003-0000-0000-0000-000000000001"
	)

	vclTemplate, err := os.ReadFile("testdata/vcl/template1.vcl")
	if err != nil {
		t.Fatal(err)
	}

	// Disable the service, then build a complete new active version on it,
	// mirroring how populateTestData wires a version up: origin group,
	// origin, verified domain and VCL. The previously active version must be
	// deactivated first because of the
	// service_versions_active_only_1_true partial unique index.
	stmts := []struct {
		sql  string
		args []any
	}{
		{"UPDATE services SET disabled_at = now() WHERE id = $1", []any{org1Service1ID}},
		{"UPDATE service_versions SET active = false WHERE id = '00000004-0000-0000-0000-000000000003'", nil},
		{"UPDATE services SET version_counter = version_counter + 1 WHERE id = $1", []any{org1Service1ID}},
		{"INSERT INTO service_versions (id, service_id, version, active) SELECT '00000004-0000-0000-0000-0000000000f1', id, version_counter, TRUE FROM services WHERE id = $1", []any{org1Service1ID}},
		{"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('00000020-0000-0000-0000-0000000000f1', '00000004-0000-0000-0000-0000000000f1', true, 'default', 0)", nil},
		{"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-0000000000f1', '00000004-0000-0000-0000-0000000000f1', '00000020-0000-0000-0000-0000000000f1', '198.51.100.10', 80, false)", nil},
		{"INSERT INTO service_domains (id, service_version_id, domain_id) VALUES ('00000008-0000-0000-0000-0000000000f1', '00000004-0000-0000-0000-0000000000f1', '00000015-0000-0000-0000-000000000001')", nil},
		{"INSERT INTO service_vcls (id, service_version_id, vcl_template) VALUES ('00000007-0000-0000-0000-0000000000f1', '00000004-0000-0000-0000-0000000000f1', $1)", []any{vclTemplate}},
	}

	for _, stmt := range stmts {
		if _, err := dbPool.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/cache-node-configs/cache-node1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("admin", validAdminPassword)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
	}

	var cnc cdntypes.CacheNodeConfig
	if err := json.NewDecoder(resp.Body).Decode(&cnc); err != nil {
		t.Fatal(err)
	}

	if _, ok := cnc.Orgs[org1ID].Services[org1Service1ID]; ok {
		t.Error("a new active version on a disabled service must not be deployed")
	}

	// Without this second half the test could pass for the wrong reason: if the
	// fixture SQL above failed to make the new version config-eligible (a
	// missing origin, domain or VCL row), the service would be absent whether
	// or not it was disabled, and the assertion would be vacuous. Re-enabling
	// must bring the NEW version into the config, which proves the absence
	// above was caused by disabled_at and nothing else.
	if _, err := dbPool.Exec(ctx, "UPDATE services SET disabled_at = NULL WHERE id = $1", org1Service1ID); err != nil {
		t.Fatal(err)
	}

	reReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/cache-node-configs/cache-node1", nil)
	if err != nil {
		t.Fatal(err)
	}
	reReq.SetBasicAuth("admin", validAdminPassword)

	reResp, err := http.DefaultClient.Do(reReq) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer reResp.Body.Close()

	if reResp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(reResp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Fatalf("unexpected status code after re-enable: %d (%s)", reResp.StatusCode, string(body))
	}

	var reEnabled cdntypes.CacheNodeConfig
	if err := json.NewDecoder(reResp.Body).Decode(&reEnabled); err != nil {
		t.Fatal(err)
	}

	svc, ok := reEnabled.Orgs[org1ID].Services[org1Service1ID]
	if !ok {
		t.Fatal("re-enabled service should reappear in the cache node config; if it does not, the new version was never config-eligible and the assertion above proved nothing")
	}

	// The version counter started at 3, so the version built above is 4.
	if _, ok := svc.ServiceVersions[4]; !ok {
		t.Errorf("expected the newly created version 4 in the config, got versions %v", svc.ServiceVersions)
	}
}

func TestPostCacheNodes(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		addresses      []netip.Addr
		name           string
	}{
		{
			description:    "successful superuser request with both addresses",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			cacheNodeDescr: "cache-node-post-1.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
			name:           "cache-node-post-1",
		},
		{
			description:    "successful superuser request without addresses",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			cacheNodeDescr: "cache-node-post-2-no-addrs.example.com",
			name:           "cache-node-post-2",
		},
		{
			description:    "successful superuser request with description right at limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			cacheNodeDescr: strings.Repeat("a", 100),
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::2")},
			name:           "cache-node-post-3",
		},
		{
			description:    "failed superuser request with description above limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			cacheNodeDescr: strings.Repeat("a", 101),
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::2")},
			name:           "cache-node-post-4",
		},
		{
			description:    "failed superuser request with description below limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			cacheNodeDescr: "",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("::3")},
			name:           "cache-node-post-5",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			cacheNodeDescr: "cache-node-post-6.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.4"), netip.MustParseAddr("::4")},
			expectedStatus: http.StatusForbidden,
			name:           "cache-node-post-6",
		},
		{
			description:    "failed node user request",
			username:       "node-user-1",
			password:       "nodeuserpass1",
			cacheNodeDescr: "cache-node-post-user-1.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.5"), netip.MustParseAddr("::5")},
			expectedStatus: http.StatusForbidden,
			name:           "cache-node-post-user-7",
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint
			description:    "failed superuser request with UUID name",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			cacheNodeDescr: "uuid-name-test.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.50")},
			name:           "abcdef01-2345-6789-abcd-ef0123456789",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			newCacheNode := struct {
				Description string       `json:"description"`
				Addresses   []netip.Addr `json:"addresses,omitempty"`
				Name        string       `json:"name"`
			}{
				Description: test.cacheNodeDescr,
				Addresses:   test.addresses,
				Name:        test.name,
			}

			b, err := json.Marshal(newCacheNode)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/cache-nodes", r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("POST cache-nodes unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			resultData := struct {
				Name string `json:"name"`
			}{}

			if test.expectedStatus == http.StatusCreated {
				err = json.Unmarshal(jsonData, &resultData)
				if err != nil {
					t.Fatalf("POST cache-nodes unable to unmarshal response: (%s)", err)
				}

				if newCacheNode.Name != resultData.Name {
					t.Fatalf("POST cache-nodes unexpected name in response, want: '%s', have: '%s'", newCacheNode.Name, resultData.Name)
				}
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetCacheNodes(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
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
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/cache-nodes", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET cache-nodes unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if test.expectedStatus == http.StatusOK {
				var cacheNodes []cdntypes.CacheNode
				if err := json.Unmarshal(jsonData, &cacheNodes); err != nil {
					t.Fatalf("unable to unmarshal cache nodes: %s", err)
				}

				if len(cacheNodes) != 5 {
					t.Fatalf("expected 5 cache nodes (including address-less), got %d", len(cacheNodes))
				}

				idx := slices.IndexFunc(cacheNodes, func(n cdntypes.CacheNode) bool {
					return n.Name == "cache-node2"
				})
				if idx == -1 {
					t.Fatal("address-less cache-node2 not found in response")
				}

				if len(cacheNodes[idx].Addresses) != 0 {
					t.Fatalf("cache-node2 should have 0 addresses, got %d", len(cacheNodes[idx].Addresses))
				}
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPutCacheNodeMaintenance(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:          validAdminPassword,
			cacheNodeNameOrID: "00000022-0000-0000-0000-000000000001",
			maintenance:       true,
			expectedStatus:    http.StatusNoContent,
		},
		{
			description:       "successful superuser request with name",
			username:          "admin",
			password:          validAdminPassword,
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
			password:          validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			maintenance := struct {
				Maintenance bool `json:"maintenance"`
			}{
				Maintenance: test.maintenance,
			}

			b, err := json.Marshal(maintenance)
			if err != nil {
				t.Fatal(err)
			}

			t.Log(string(b))

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/cache-nodes/"+test.cacheNodeNameOrID+"/maintenance", r)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT cache-nodes maintenance unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPutCacheNodeGroup(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description            string
		username               string
		password               string
		cacheNodeNameOrID      string
		cacheNodeGroupNameOrID string
		expectedStatus         int
	}{
		{
			description:            "successful superuser request with ID",
			username:               "admin",
			password:               validAdminPassword,
			cacheNodeNameOrID:      "00000022-0000-0000-0000-000000000005",
			cacheNodeGroupNameOrID: "00000021-0000-0000-0000-000000000002",
			expectedStatus:         http.StatusNoContent,
		},
		{
			description:            "failed superuser request with nonexistent group ID",
			username:               "admin",
			password:               validAdminPassword,
			cacheNodeNameOrID:      "00000022-0000-0000-0000-000000000005",
			cacheNodeGroupNameOrID: "00000021-0001-0000-0000-000000000002",
			expectedStatus:         http.StatusUnprocessableEntity,
		},
		{
			description:            "successful superuser request with name",
			username:               "admin",
			password:               validAdminPassword,
			cacheNodeNameOrID:      "cache-node5-no-group",
			cacheNodeGroupNameOrID: "node-group-2",
			expectedStatus:         http.StatusNoContent,
		},
		{
			description:            "failed superuser request, bad password",
			username:               "admin",
			password:               "badadminpass1",
			cacheNodeNameOrID:      "cache-node5-no-group",
			cacheNodeGroupNameOrID: "node-group-2",
			expectedStatus:         http.StatusUnauthorized,
		},
		{
			description:            "failed user request",
			username:               "username1",
			password:               validUserPassword,
			cacheNodeNameOrID:      "cache-node5-no-group",
			cacheNodeGroupNameOrID: "node-group-2",
			expectedStatus:         http.StatusForbidden,
		},
		{
			description:            "failed user request, bad password",
			username:               "username1",
			password:               "badpassword1",
			cacheNodeNameOrID:      "cache-node5-no-group",
			cacheNodeGroupNameOrID: "node-group-2",
			expectedStatus:         http.StatusUnauthorized,
		},
		{
			description:            "failed user request, no password set",
			username:               "username4-no-pw",
			password:               "somepassword",
			cacheNodeNameOrID:      "cache-node5-no-group",
			cacheNodeGroupNameOrID: "node-group-2",
			expectedStatus:         http.StatusUnauthorized,
		},
		{
			description:            "failed node user request",
			username:               "node-user-1",
			password:               "nodeuserpass1",
			cacheNodeNameOrID:      "cache-node5-no-group",
			cacheNodeGroupNameOrID: "node-group-2",
			expectedStatus:         http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			maintenance := struct {
				NodeGroup string `json:"node-group"`
			}{
				NodeGroup: test.cacheNodeGroupNameOrID,
			}

			b, err := json.Marshal(maintenance)
			if err != nil {
				t.Fatal(err)
			}

			t.Log(string(b))

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/cache-nodes/"+test.cacheNodeNameOrID+"/node-group", r)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT l4lb-nodes group-node unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetL4LBNodes(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
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
			password:       validUserPassword,
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
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/l4lb-nodes", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET l4lb-nodes unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			if test.expectedStatus == http.StatusOK {
				var l4lbNodes []cdntypes.L4LBNode
				if err := json.Unmarshal(jsonData, &l4lbNodes); err != nil {
					t.Fatalf("unable to unmarshal l4lb nodes: %s", err)
				}

				if len(l4lbNodes) != 5 {
					t.Fatalf("expected 5 l4lb nodes (including address-less), got %d", len(l4lbNodes))
				}

				idx := slices.IndexFunc(l4lbNodes, func(n cdntypes.L4LBNode) bool {
					return n.Name == "l4lb-node2"
				})
				if idx == -1 {
					t.Fatal("address-less l4lb-node2 not found in response")
				}

				if len(l4lbNodes[idx].Addresses) != 0 {
					t.Fatalf("l4lb-node2 should have 0 addresses, got %d", len(l4lbNodes[idx].Addresses))
				}
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPostL4LBNodes(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		l4lbNodeDescr  string
		addresses      []netip.Addr
		name           string
	}{
		{
			description:    "successful superuser request with both addresses",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			l4lbNodeDescr:  "l4lb-node-post-1.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
			name:           "l4lb-node-post-1",
		},
		{
			description:    "successful superuser request without addresses",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			l4lbNodeDescr:  "l4lb-node-post-2-no-addrs.example.com",
			name:           "l4lb-node-post-2",
		},
		{
			description:    "successful superuser request with description right at limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusCreated,
			l4lbNodeDescr:  strings.Repeat("a", 100),
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::2")},
			name:           "l4lb-node-post-3",
		},
		{
			description:    "failed superuser request with description above limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			l4lbNodeDescr:  strings.Repeat("a", 101),
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::2")},
			name:           "l4lb-node-post-4",
		},
		{
			description:    "failed superuser request with description below limit",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			l4lbNodeDescr:  "",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("::3")},
			name:           "l4lb-node-post-5",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			l4lbNodeDescr:  "l4lb-node-post-6.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.4"), netip.MustParseAddr("::4")},
			expectedStatus: http.StatusForbidden,
			name:           "l4lb-node-post-6",
		},
		{
			description:    "failed node user request",
			username:       "node-user-1",
			password:       "nodeuserpass1",
			l4lbNodeDescr:  "l4lb-node-post-user-1.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.5"), netip.MustParseAddr("::5")},
			expectedStatus: http.StatusForbidden,
			name:           "l4lb-node-post-user-7",
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint
			description:    "failed superuser request with UUID name",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			l4lbNodeDescr:  "uuid-name-test.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.50")},
			name:           "abcdef01-2345-6789-abcd-ef0123456789",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			newCacheNode := struct {
				Description string       `json:"description"`
				Addresses   []netip.Addr `json:"addresses,omitempty"`
				Name        string       `json:"name"`
			}{
				Description: test.l4lbNodeDescr,
				Addresses:   test.addresses,
				Name:        test.name,
			}

			b, err := json.Marshal(newCacheNode)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/l4lb-nodes", r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("POST l4lb-nodes unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			resultData := struct {
				Name string `json:"name"`
			}{}

			if test.expectedStatus == http.StatusCreated {
				err = json.Unmarshal(jsonData, &resultData)
				if err != nil {
					t.Fatalf("POST l4lb-nodes unable to unmarshal response: (%s)", err)
				}

				if newCacheNode.Name != resultData.Name {
					t.Fatalf("POST l4lb-nodes unexpected name in response, want: '%s', have: '%s'", newCacheNode.Name, resultData.Name)
				}
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPutL4LBNodeMaintenance(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		maintenance      bool
		l4lbNodeNameOrID string
		expectedStatus   int
	}{
		{
			description:      "successful superuser request with ID",
			username:         "admin",
			password:         validAdminPassword,
			l4lbNodeNameOrID: "00000016-0000-0000-0000-000000000001",
			maintenance:      true,
			expectedStatus:   http.StatusNoContent,
		},
		{
			description:      "successful superuser request with name",
			username:         "admin",
			password:         validAdminPassword,
			l4lbNodeNameOrID: "l4lb-node1",
			maintenance:      true,
			expectedStatus:   http.StatusNoContent,
		},
		{
			description:      "failed superuser request, bad password",
			username:         "admin",
			password:         "badadminpass1",
			l4lbNodeNameOrID: "l4lb-node1",
			maintenance:      true,
			expectedStatus:   http.StatusUnauthorized,
		},
		{
			description:      "failed user request",
			username:         "username1",
			password:         validUserPassword,
			l4lbNodeNameOrID: "l4lb-node1",
			maintenance:      true,
			expectedStatus:   http.StatusForbidden,
		},
		{
			description:      "failed user request, bad password",
			username:         "username1",
			password:         "badpassword1",
			l4lbNodeNameOrID: "l4lb-node1",
			maintenance:      true,
			expectedStatus:   http.StatusUnauthorized,
		},
		{
			description:      "failed user request, no password set",
			username:         "username4-no-pw",
			password:         "somepassword",
			l4lbNodeNameOrID: "l4lb-node1",
			maintenance:      true,
			expectedStatus:   http.StatusUnauthorized,
		},
		{
			description:      "failed node user request",
			username:         "node-user-1",
			password:         "nodeuserpass1",
			l4lbNodeNameOrID: "l4lb-node1",
			maintenance:      true,
			expectedStatus:   http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			maintenance := struct {
				Maintenance bool `json:"maintenance"`
			}{
				Maintenance: test.maintenance,
			}

			b, err := json.Marshal(maintenance)
			if err != nil {
				t.Fatal(err)
			}

			t.Log(string(b))

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/l4lb-nodes/"+test.l4lbNodeNameOrID+"/maintenance", r)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT l4lb-nodes maintenance unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPutL4LBNodeGroup(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description           string
		username              string
		password              string
		l4lbNodeNameOrID      string
		l4lbNodeGroupNameOrID string
		expectedStatus        int
	}{
		{
			description:           "successful superuser request with ID",
			username:              "admin",
			password:              validAdminPassword,
			l4lbNodeNameOrID:      "00000016-0000-0000-0000-000000000005",
			l4lbNodeGroupNameOrID: "00000021-0000-0000-0000-000000000002",
			expectedStatus:        http.StatusNoContent,
		},
		{
			description:           "failed superuser request with nonexistent group ID",
			username:              "admin",
			password:              validAdminPassword,
			l4lbNodeNameOrID:      "00000016-0000-0000-0000-000000000005",
			l4lbNodeGroupNameOrID: "00000021-0001-0000-0000-000000000002",
			expectedStatus:        http.StatusUnprocessableEntity,
		},
		{
			description:           "successful superuser request with name",
			username:              "admin",
			password:              validAdminPassword,
			l4lbNodeNameOrID:      "l4lb-node5-no-group",
			l4lbNodeGroupNameOrID: "node-group-2",
			expectedStatus:        http.StatusNoContent,
		},
		{
			description:           "failed superuser request, bad password",
			username:              "admin",
			password:              "badadminpass1",
			l4lbNodeNameOrID:      "l4lb-node5-no-group",
			l4lbNodeGroupNameOrID: "node-group-2",
			expectedStatus:        http.StatusUnauthorized,
		},
		{
			description:           "failed user request",
			username:              "username1",
			password:              validUserPassword,
			l4lbNodeNameOrID:      "l4lb-node5-no-group",
			l4lbNodeGroupNameOrID: "node-group-2",
			expectedStatus:        http.StatusForbidden,
		},
		{
			description:           "failed user request, bad password",
			username:              "username1",
			password:              "badpassword1",
			l4lbNodeNameOrID:      "l4lb-node5-no-group",
			l4lbNodeGroupNameOrID: "node-group-2",
			expectedStatus:        http.StatusUnauthorized,
		},
		{
			description:           "failed user request, no password set",
			username:              "username4-no-pw",
			password:              "somepassword",
			l4lbNodeNameOrID:      "l4lb-node5-no-group",
			l4lbNodeGroupNameOrID: "node-group-2",
			expectedStatus:        http.StatusUnauthorized,
		},
		{
			description:           "failed node user request",
			username:              "node-user-1",
			password:              "nodeuserpass1",
			l4lbNodeNameOrID:      "l4lb-node5-no-group",
			l4lbNodeGroupNameOrID: "node-group-2",
			expectedStatus:        http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			maintenance := struct {
				NodeGroup string `json:"node-group"`
			}{
				NodeGroup: test.l4lbNodeGroupNameOrID,
			}

			b, err := json.Marshal(maintenance)
			if err != nil {
				t.Fatal(err)
			}

			t.Log(string(b))

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/l4lb-nodes/"+test.l4lbNodeNameOrID+"/node-group", r)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT l4lb-nodes group-node unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestGetNodeGroups(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			password:       validAdminPassword,
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed superuser request with wrong password",
			username:       "admin",
			password:       "adminpass1-wrong",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			description:    "failed user request (only superusers allowed)",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
		},
		{
			description:    "failed user request with wrong password",
			username:       "username1",
			password:       "password1-wrong",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/node-groups", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("GET node groups unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPostNodeGroups(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		name             string
		groupDescription string
	}{
		{
			description:      "successful superuser request with ID",
			username:         "admin",
			password:         validAdminPassword,
			name:             "node-group-new1",
			groupDescription: "some node group",
			expectedStatus:   http.StatusCreated,
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint
			description:      "failed superuser request with UUID name",
			username:         "admin",
			password:         validAdminPassword,
			name:             "abcdef01-2345-6789-abcd-ef0123456789",
			groupDescription: "uuid name test",
			expectedStatus:   http.StatusUnprocessableEntity,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			newOriginGroup := struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			}{
				Name:        test.name,
				Description: test.groupDescription,
			}

			b, err := json.Marshal(newOriginGroup)
			if err != nil {
				t.Fatal(err)
			}

			t.Log(string(b))

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/node-groups", r)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("POST node group unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		})
	}
}

func TestPutCacheNode(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		cacheNode      string
		name           string
		nodeDescr      string
		addresses      []netip.Addr
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusOK,
			cacheNode:      "cache-node1",
			name:           "cache-node1",
			nodeDescr:      "Updated cache node description",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::1")},
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
			cacheNode:      "cache-node1",
			name:           "cache-node1",
			nodeDescr:      "Should not work",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
			cacheNode:      "cache-node1",
			name:           "cache-node1",
			nodeDescr:      "Should not work",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			expectedStatus: http.StatusUnauthorized,
			cacheNode:      "cache-node1",
			name:           "cache-node1",
			nodeDescr:      "Should not work",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		},
		{
			description:    "failed superuser request, not found",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNotFound,
			cacheNode:      "nonexistent-node",
			name:           "nonexistent-node",
			nodeDescr:      "Should not work",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint
			description:    "failed superuser request, UUID name",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			cacheNode:      "cache-node1",
			name:           "abcdef01-2345-6789-abcd-ef0123456789",
			nodeDescr:      "UUID rename test",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			body := struct {
				Name        string       `json:"name"`
				Description string       `json:"description"`
				Addresses   []netip.Addr `json:"addresses"`
			}{
				Name:        test.name,
				Description: test.nodeDescr,
				Addresses:   test.addresses,
			}

			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/cache-nodes/"+test.cacheNode, r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)
			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT cache-node unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)

			if test.expectedStatus == http.StatusOK {
				var result cdntypes.CacheNode
				if err := json.Unmarshal(jsonData, &result); err != nil {
					t.Fatalf("unable to unmarshal response: %v", err)
				}
				if result.Name != test.name {
					t.Fatalf("expected name %q, got %q", test.name, result.Name)
				}
				if result.Description != test.nodeDescr {
					t.Fatalf("expected description %q, got %q", test.nodeDescr, result.Description)
				}
				expected := slices.Clone(test.addresses)
				slices.SortFunc(expected, netip.Addr.Compare)
				got := slices.Clone(result.Addresses)
				slices.SortFunc(got, netip.Addr.Compare)
				if !slices.Equal(expected, got) {
					t.Fatalf("expected addresses %v, got %v", expected, got)
				}
			}
		})
	}
}

func TestDeleteCacheNode(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		cacheNode      string
	}{
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
			cacheNode:      "cache-node1",
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
			cacheNode:      "cache-node1",
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			expectedStatus: http.StatusUnauthorized,
			cacheNode:      "cache-node1",
		},
		{
			description:    "failed superuser request, not found",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNotFound,
			cacheNode:      "nonexistent-node",
		},
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNoContent,
			cacheNode:      "cache-node1",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/cache-nodes/"+test.cacheNode, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("DELETE cache-node unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			// Verify the resource is actually gone by retrying the DELETE
			if test.expectedStatus == http.StatusNoContent {
				retryReq, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/cache-nodes/"+test.cacheNode, nil)
				if err != nil {
					t.Fatal(err)
				}
				retryReq.SetBasicAuth(test.username, test.password)
				retryResp, err := http.DefaultClient.Do(retryReq) // #nosec G704 -- filled in by test
				if err != nil {
					t.Fatal(err)
				}
				defer retryResp.Body.Close()
				if retryResp.StatusCode != http.StatusNotFound {
					t.Fatalf("expected 404 on retry DELETE, got %d", retryResp.StatusCode)
				}
			}
		})
	}
}

func TestPutL4LBNode(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		l4lbNode       string
		name           string
		nodeDescr      string
		addresses      []netip.Addr
	}{
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusOK,
			l4lbNode:       "l4lb-node1",
			name:           "l4lb-node1",
			nodeDescr:      "Updated l4lb node description",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("::2")},
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
			l4lbNode:       "l4lb-node1",
			name:           "l4lb-node1",
			nodeDescr:      "Should not work",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
			l4lbNode:       "l4lb-node1",
			name:           "l4lb-node1",
			nodeDescr:      "Should not work",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			expectedStatus: http.StatusUnauthorized,
			l4lbNode:       "l4lb-node1",
			name:           "l4lb-node1",
			nodeDescr:      "Should not work",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			description:    "failed superuser request, not found",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNotFound,
			l4lbNode:       "nonexistent-node",
			name:           "nonexistent-node",
			nodeDescr:      "Should not work",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint
			description:    "failed superuser request, UUID name",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusUnprocessableEntity,
			l4lbNode:       "l4lb-node1",
			name:           "abcdef01-2345-6789-abcd-ef0123456789",
			nodeDescr:      "UUID rename test",
			addresses:      []netip.Addr{netip.MustParseAddr("10.0.0.2")},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			body := struct {
				Name        string       `json:"name"`
				Description string       `json:"description"`
				Addresses   []netip.Addr `json:"addresses"`
			}{
				Name:        test.name,
				Description: test.nodeDescr,
				Addresses:   test.addresses,
			}

			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/l4lb-nodes/"+test.l4lbNode, r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)
			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT l4lb-node unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)

			if test.expectedStatus == http.StatusOK {
				var result cdntypes.L4LBNode
				if err := json.Unmarshal(jsonData, &result); err != nil {
					t.Fatalf("unable to unmarshal response: %v", err)
				}
				if result.Name != test.name {
					t.Fatalf("expected name %q, got %q", test.name, result.Name)
				}
				if result.Description != test.nodeDescr {
					t.Fatalf("expected description %q, got %q", test.nodeDescr, result.Description)
				}
				expected := slices.Clone(test.addresses)
				slices.SortFunc(expected, netip.Addr.Compare)
				got := slices.Clone(result.Addresses)
				slices.SortFunc(got, netip.Addr.Compare)
				if !slices.Equal(expected, got) {
					t.Fatalf("expected addresses %v, got %v", expected, got)
				}
			}
		})
	}
}

func TestDeleteL4LBNode(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		l4lbNode       string
	}{
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
			l4lbNode:       "l4lb-node2",
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
			l4lbNode:       "l4lb-node2",
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			expectedStatus: http.StatusUnauthorized,
			l4lbNode:       "l4lb-node2",
		},
		{
			description:    "failed superuser request, not found",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNotFound,
			l4lbNode:       "nonexistent-node",
		},
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNoContent,
			l4lbNode:       "l4lb-node2",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/l4lb-nodes/"+test.l4lbNode, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("DELETE l4lb-node unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			// Verify the resource is actually gone by retrying the DELETE
			if test.expectedStatus == http.StatusNoContent {
				retryReq, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/l4lb-nodes/"+test.l4lbNode, nil)
				if err != nil {
					t.Fatal(err)
				}
				retryReq.SetBasicAuth(test.username, test.password)
				retryResp, err := http.DefaultClient.Do(retryReq) // #nosec G704 -- filled in by test
				if err != nil {
					t.Fatal(err)
				}
				defer retryResp.Body.Close()
				if retryResp.StatusCode != http.StatusNotFound {
					t.Fatalf("expected 404 on retry DELETE, got %d", retryResp.StatusCode)
				}
			}
		})
	}
}

func TestPutNodeGroup(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		nodeGroup        string
		name             string
		groupDescription string
	}{
		{
			description:      "successful superuser request",
			username:         "admin",
			password:         validAdminPassword,
			expectedStatus:   http.StatusOK,
			nodeGroup:        "node-group-2",
			name:             "node-group-2",
			groupDescription: "Updated node group description",
		},
		{
			description:      "failed non-superuser request",
			username:         "username1",
			password:         validUserPassword,
			expectedStatus:   http.StatusForbidden,
			nodeGroup:        "node-group-2",
			name:             "node-group-2",
			groupDescription: "Should not work",
		},
		{
			description:      "failed superuser request, bad password",
			username:         "admin",
			password:         "badadminpass1",
			expectedStatus:   http.StatusUnauthorized,
			nodeGroup:        "node-group-2",
			name:             "node-group-2",
			groupDescription: "Should not work",
		},
		{
			description:      "failed user request, no password set",
			username:         "username4-no-pw",
			password:         "somepassword",
			expectedStatus:   http.StatusUnauthorized,
			nodeGroup:        "node-group-2",
			name:             "node-group-2",
			groupDescription: "Should not work",
		},
		{
			description:      "failed superuser request, not found",
			username:         "admin",
			password:         validAdminPassword,
			expectedStatus:   http.StatusNotFound,
			nodeGroup:        "nonexistent-group",
			name:             "nonexistent-group",
			groupDescription: "Should not work",
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint
			description:      "failed superuser request, UUID name",
			username:         "admin",
			password:         validAdminPassword,
			expectedStatus:   http.StatusUnprocessableEntity,
			nodeGroup:        "node-group-2",
			name:             "abcdef01-2345-6789-abcd-ef0123456789",
			groupDescription: "UUID rename test",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			body := struct {
				Name        string `json:"name"`
				Description string `json:"description"`
			}{
				Name:        test.name,
				Description: test.groupDescription,
			}

			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/node-groups/"+test.nodeGroup, r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)
			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT node-group unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)

			if test.expectedStatus == http.StatusOK {
				var result cdntypes.NodeGroup
				if err := json.Unmarshal(jsonData, &result); err != nil {
					t.Fatalf("unable to unmarshal response: %v", err)
				}
				if result.Name != test.name {
					t.Fatalf("expected name %q, got %q", test.name, result.Name)
				}
				if result.Description != test.groupDescription {
					t.Fatalf("expected description %q, got %q", test.groupDescription, result.Description)
				}
			}
		})
	}
}

func TestDeleteNodeGroup(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		nodeGroup      string
	}{
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
			nodeGroup:      "node-group-2",
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
			nodeGroup:      "node-group-2",
		},
		{
			description:    "failed user request, no password set",
			username:       "username4-no-pw",
			password:       "somepassword",
			expectedStatus: http.StatusUnauthorized,
			nodeGroup:      "node-group-2",
		},
		{
			description:    "failed superuser request, not found",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNotFound,
			nodeGroup:      "nonexistent-group",
		},
		{
			description:    "failed superuser request, node group has members",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusConflict,
			nodeGroup:      "node-group-1",
		},
		{
			description:    "successful superuser request",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNoContent,
			nodeGroup:      "node-group-2",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/node-groups/"+test.nodeGroup, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("DELETE node-group unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			// Verify the resource is actually gone by retrying the DELETE
			if test.expectedStatus == http.StatusNoContent {
				retryReq, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/node-groups/"+test.nodeGroup, nil)
				if err != nil {
					t.Fatal(err)
				}
				retryReq.SetBasicAuth(test.username, test.password)
				retryResp, err := http.DefaultClient.Do(retryReq) // #nosec G704 -- filled in by test
				if err != nil {
					t.Fatal(err)
				}
				defer retryResp.Body.Close()
				if retryResp.StatusCode != http.StatusNotFound {
					t.Fatalf("expected 404 on retry DELETE, got %d", retryResp.StatusCode)
				}
			}
		})
	}
}

func TestAuthChallenge(t *testing.T) {
	expectedChallenge := `Basic realm="test realm"`
	challenge := authChallenge("Basic", "test realm")
	if challenge != expectedChallenge {
		t.Fatalf("unexpected challenge string, want '%s', have: '%s'", expectedChallenge, challenge)
	}
}

func TestConsoleDashboardRedirect(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	// Verify that a superuser with org membership hitting /console
	// with no selectedOrgKey in their session gets 303-redirected to
	// their org dashboard.
	t.Run("superuser with org redirects to org dashboard", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin-with-org", validAdminPassword)

		// Disable following redirects so we can inspect each step
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// Follow the redirect to /console manually — this should trigger 303 to org dashboard
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/console", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		consoleResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		consoleResp.Body.Close()

		if consoleResp.StatusCode != http.StatusSeeOther {
			t.Fatalf("expected 303 redirect from /console, got %d", consoleResp.StatusCode)
		}

		consoleLocation := consoleResp.Header.Get("Location")
		if consoleLocation != "/console/org/org1" {
			t.Fatalf("expected redirect to /console/org/org1, got %s", consoleLocation)
		}
	})

	// Verify that a superuser with org membership GETing a specific URL
	// while unauthenticated is redirected there after login instead of
	// the default location. Login is done manually (not via consoleLogin)
	// so we can perform the initial request with our own client and
	// cookiejar.
	t.Run("superuser with org gets redirected back to requested page after auth", func(t *testing.T) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}

		client := &http.Client{
			Jar: jar,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		form := url.Values{
			"username": {"admin-with-org"},
			"password": {validAdminPassword},
		}

		origGetPath := "/console/org/sunet/domains"

		// Unauthenticated request to init session cookie
		req, err := http.NewRequest(http.MethodGet, ts.URL+origGetPath, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Initial GET returns 302 -> /auth/login
		getResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		getResp.Body.Close()

		if getResp.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 from login, got %d", getResp.StatusCode)
		}

		location := getResp.Header.Get("Location")
		if location != cdntypes.AuthLoginPath {
			t.Fatalf("expected unauth redirect to '%s', got %s", cdntypes.AuthLoginPath, location)
		}

		req, err = http.NewRequest(http.MethodPost, ts.URL+cdntypes.AuthLoginPath, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		// Login POST returns 302 -> origGetPath
		loginResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		loginResp.Body.Close()

		if loginResp.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 from login, got %d", loginResp.StatusCode)
		}

		loginLocation := loginResp.Header.Get("Location")
		if loginLocation != origGetPath {
			t.Fatalf("expected login redirect to '%s', got %s", origGetPath, loginLocation)
		}
	})

	// Verify that a GET for a specific URL while unauthenticated is
	// redirected via HX-Redirect if sending a htmx request.
	t.Run("superuser with org doing htmx request gets redirected back to requested page after auth via HX-Redirect", func(t *testing.T) {
		client := &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		origGetPath := "/console/org/sunet/domains"

		// Unauthenticated request
		req, err := http.NewRequest(http.MethodGet, ts.URL+origGetPath, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Mimic htmx request
		req.Header.Set("HX-Request", "true")

		// Initial GET returns 200 response with HX-Redirect set
		getResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		getResp.Body.Close()

		if getResp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 from login with HX-Request, got %d", getResp.StatusCode)
		}

		if getResp.Header.Get("HX-Redirect") != cdntypes.AuthLoginPath {
			t.Fatalf("expected HX-Redirect header with path '%s', got '%s'", cdntypes.AuthLoginPath, getResp.Header.Get("HX-Redirect"))
		}
	})

	// Verify that a superuser with org membership doing a non-GET of a specific URL
	// while unauthenticated is NOT redirected there after login but instead
	// being sent to the default location.
	t.Run("superuser with org gets redirected to default page after auth for non-GET", func(t *testing.T) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}

		client := &http.Client{
			Jar: jar,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		form := url.Values{
			"username": {"admin-with-org"},
			"password": {validAdminPassword},
		}

		origNonGetPath := "/console/org/sunet/domains"

		// Unauthenticated non-GET request that triggers a login redirect.
		// Non-GET requests should not set a return-to target, so after
		// login we should go to the default page.
		req, err := http.NewRequest(http.MethodPut, ts.URL+origNonGetPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Need to set Sec-Fetch-Site otherwise we get a 403 from the
		// anti CSRF middleware since we use a PUT here.
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		// Initial non-GET returns 302 -> /auth/login
		nonGetResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		nonGetResp.Body.Close()

		if nonGetResp.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 from login, got %d", nonGetResp.StatusCode)
		}

		location := nonGetResp.Header.Get("Location")
		if location != cdntypes.AuthLoginPath {
			t.Fatalf("expected unauth redirect to '%s', got %s", cdntypes.AuthLoginPath, location)
		}

		req, err = http.NewRequest(http.MethodPost, ts.URL+cdntypes.AuthLoginPath, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		// Login POST returns 302 -> default consolePath rather than origNonGetPath
		loginResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		loginResp.Body.Close()

		if loginResp.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 from login, got %d", loginResp.StatusCode)
		}

		loginLocation := loginResp.Header.Get("Location")
		if loginLocation != consolePath {
			t.Fatalf("expected login redirect to '%s', got %s", consolePath, loginLocation)
		}
	})

	// Verify that a superuser with org membership first doing a GET
	// followed by a non-GET of a specific URL while unauthenticated is NOT
	// redirected there after login but instead being sent to the default
	// location.
	t.Run("superuser with org gets redirected to default page after auth for non-GET following a GET", func(t *testing.T) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}

		client := &http.Client{
			Jar: jar,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		form := url.Values{
			"username": {"admin-with-org"},
			"password": {validAdminPassword},
		}

		origPath := "/console/org/sunet/domains"

		// Unauthenticated request to init session cookie
		req, err := http.NewRequest(http.MethodGet, ts.URL+origPath, nil)
		if err != nil {
			t.Fatal(err)
		}

		// Initial GET returns 302 -> /auth/login
		getResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		getResp.Body.Close()

		if getResp.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 from login, got %d", getResp.StatusCode)
		}

		location := getResp.Header.Get("Location")
		if location != cdntypes.AuthLoginPath {
			t.Fatalf("expected unauth redirect to '%s', got %s", cdntypes.AuthLoginPath, location)
		}

		// Follow up with unauthenticated non-GET request that triggers a login redirect.
		// Non-GET requests should not set a return-to target, so after
		// login we should go to the default page because the server
		// cleared up the data from the previous request.
		req, err = http.NewRequest(http.MethodPut, ts.URL+origPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Need to set Sec-Fetch-Site otherwise we get a 403 from the
		// anti CSRF middleware since we use a PUT here.
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		// Initial non-GET returns 302 -> /auth/login
		nonGetResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		nonGetResp.Body.Close()

		if nonGetResp.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 from login, got %d", nonGetResp.StatusCode)
		}

		location = nonGetResp.Header.Get("Location")
		if location != cdntypes.AuthLoginPath {
			t.Fatalf("expected unauth redirect for follow-up request to '%s', got %s", cdntypes.AuthLoginPath, location)
		}

		req, err = http.NewRequest(http.MethodPost, ts.URL+cdntypes.AuthLoginPath, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		// Login POST returns 302 -> default consolePath rather than origNonGetPath
		loginResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		loginResp.Body.Close()

		if loginResp.StatusCode != http.StatusFound {
			t.Fatalf("expected 302 from login, got %d", loginResp.StatusCode)
		}

		loginLocation := loginResp.Header.Get("Location")
		if loginLocation != consolePath {
			t.Fatalf("expected login redirect to '%s', got %s", consolePath, loginLocation)
		}
	})

	// Verify the redirect only fires once.
	t.Run("superuser with org subsequent visit renders dashboard", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin-with-org", validAdminPassword)

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/console", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		// This request follows the full redirect chain (login -> /console ->
		// /console/org/org1) which sets selectedOrgKey. A subsequent GET
		// /console should render the superuser dashboard directly (200), not
		// redirect.
		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatal("unexpected status code when filling in selectedOrgKey")
		}

		// Now do the subsequent lookup that should not follow redirects
		// and verify we directly get a 200
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		req, err = http.NewRequest(http.MethodGet, ts.URL+"/console", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err = client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 on subsequent visit, got %d", resp.StatusCode)
		}
	})

	// Verify existing behavior is unchanged: a superuser without org
	// membership (admin user) gets the generic dashboard (200) with
	// no redirect, since ad.OrgName is nil.
	t.Run("superuser without org sees generic dashboard", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/console", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for org-less superuser, got %d", resp.StatusCode)
		}
	})

	// Verify that a superuser with org membership can return to the
	// generic dashboard by explicitly selecting "not selected" in the
	// org switcher. After that, GET /console should render the
	// dashboard (200) and not re-redirect to the org.
	t.Run("superuser with org can unselect org and stay on generic dashboard", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin-with-org", validAdminPassword)

		// Use the org switcher to explicitly unselect
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/console/org-switcher?org="+url.QueryEscape(cdntypes.OrgNotSelected), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		// Now GET /console should NOT redirect — selectedOrgKey is
		// present (empty string) so the "never selected" condition
		// is false.
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		req, err = http.NewRequest(http.MethodGet, ts.URL+"/console", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err = client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 after explicit unselect, got %d", resp.StatusCode)
		}
	})
}

func TestConsoleServicesComponent(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	defer ts.Close()
	tests := []struct {
		description string
		username    string
		password    string
		orgNameOrID string
		serviceIPs  map[string][]netip.Addr
	}{
		{
			description: "successful superuser request with org name",
			username:    "admin",
			password:    validAdminPassword,
			orgNameOrID: "org1",
			serviceIPs: map[string][]netip.Addr{
				"org1-service1": {
					netip.MustParseAddr("192.0.2.1"),
					netip.MustParseAddr("2001:db8::1"),
				},
				"org1-service2": {
					netip.MustParseAddr("192.0.2.2"),
					netip.MustParseAddr("2001:db8::2"),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			client, _ := consoleLogin(t, ts.URL, test.username, test.password)

			req, err := http.NewRequest(http.MethodGet, ts.URL+"/console/org/"+test.orgNameOrID+"/services", nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("unexpected status code: %d", resp.StatusCode)
			}

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				t.Fatalf("failed to read template: %v", err)
			}

			seenServices := []string{}
			doc.Find("main #contents table tbody tr").Each(func(_ int, s *goquery.Selection) {
				var foundAddrs []netip.Addr
				name := strings.TrimSpace(s.Find("td.name").Text())
				seenServices = append(seenServices, name)
				s.Find("td.addresses div").Each(func(_ int, div *goquery.Selection) {
					addrStr := strings.TrimSpace(div.Text())
					if addrStr != "" {
						addr, err := netip.ParseAddr(addrStr)
						if err != nil {
							t.Fatal(err)
						}
						foundAddrs = append(foundAddrs, addr)
					}
				})

				// Verify the expected addresses are found
				if expectedAddrs, ok := test.serviceIPs[name]; ok {
					for _, expectedAddr := range expectedAddrs {
						addressPresent := slices.Contains(foundAddrs, expectedAddr)
						if !addressPresent {
							t.Fatalf("service '%s' missing expected address %s", name, expectedAddr)
						}
					}
				}
			})

			// Verify at least all expected service names was
			// present, it is OK if there are more that we do not
			// inspect.
			for serviceName := range test.serviceIPs {
				serviceFound := slices.Contains(seenServices, serviceName)
				if !serviceFound {
					t.Fatalf("unable to find a service with name '%s'", serviceName)
				}
			}
		})
	}
}

func TestConsoleServiceDisableEnable(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	disabledAt := func() *time.Time {
		t.Helper()
		var at *time.Time
		err := dbPool.QueryRow(ctx, "SELECT disabled_at FROM services WHERE id = '00000003-0000-0000-0000-000000000001'").Scan(&at)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}

	// The confirmation page must render, and must not be swallowed by the
	// /org/{org}/services/{service}/{version} route.
	t.Run("disable page renders", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)

		resp, err := client.Get(ts.URL + "/console/org/org1/services/org1-service1/disable") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		// The action is keyed on the immutable id, not the name it was
		// reached by, so a stale page cannot disable a same-named
		// replacement. See the delete equivalent for the full reasoning.
		if doc.Find("form[action='/console/org/org1/services/00000003-0000-0000-0000-000000000001/disable']").Length() == 0 {
			action, _ := doc.Find("form[method='post']").Attr("action")
			t.Errorf("disable form action should be keyed on the service UUID, got %q", action)
		}

		// The page must state what is lost, so the operator is not
		// guessing at the consequences.
		if !strings.Contains(doc.Text(), "clears its cache") {
			t.Error("disable page should say the cache is cleared")
		}

		// And what is NOT released. A tenant at their service quota might
		// otherwise disable a service expecting the slot back, which is the
		// opposite of what happens.
		if !strings.Contains(doc.Text(), "still counts against your service quota") {
			t.Error("disable page should say the service still consumes its quota slot")
		}

		// A Cancel affordance must exist, pointing where an unconfirmed POST
		// already redirects. Without it, "submit without ticking the box" is
		// the only way to back out, which reads as clicking through with no
		// effect.
		if doc.Find("a[href='/console/org/org1/services']").Length() == 0 {
			t.Error("disable page should offer a Cancel link back to the services list")
		}

		// The requirement is enforced by `required` on the checkbox -- native
		// form semantics, so it reaches keyboard and AT users rather than only
		// blocking the pointer. An earlier version relied on CSS
		// pointer-events, which left the button active in the accessibility
		// tree and silently redirected keyboard users.
		if doc.Find("input[type='checkbox']#confirmation[required]").Length() == 0 {
			t.Error("the disable confirmation checkbox must be required, so the gate is not pointer-only")
		}
		// The id is also what the CSS :has() rule keys off for the matching
		// visual state; no Go test can observe the CSS, so pin the id here.

		// The button that commits the act must read as destructive. Asserted
		// because the class was once applied to the services-row link but not
		// to the button that actually does the work.
		if doc.Find("button[type='submit'].destructive").Length() == 0 {
			t.Error("the disable submit button should carry the destructive class")
		}

		// Rendering the confirmation page must not itself disable anything.
		// The whole point of the two-step ceremony is that looking is free.
		if at := disabledAt(); at != nil {
			t.Errorf("GET of the disable page must not change disabled_at, got %v", at)
		}
	})

	t.Run("disable POST disables the service", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		form := url.Values{"confirmation": {"on"}}

		req, err := http.NewRequest(
			http.MethodPost,
			ts.URL+"/console/org/org1/services/org1-service1/disable",
			strings.NewReader(form.Encode()),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusFound {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("expected redirect (302), got %d (%s)", resp.StatusCode, string(body))
		}

		if disabledAt() == nil {
			t.Error("service should be disabled after the POST")
		}
	})

	t.Run("enable POST enables the service", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		req, err := http.NewRequest(
			http.MethodPost,
			ts.URL+"/console/org/org1/services/org1-service1/enable",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusFound {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("expected redirect (302), got %d (%s)", resp.StatusCode, string(body))
		}

		if at := disabledAt(); at != nil {
			t.Errorf("service should be enabled after the POST, got disabled_at=%v", at)
		}
	})

	// The handler treats an unticked confirmation checkbox as "cancel" and
	// redirects without disabling. That branch must be proven not to disable.
	t.Run("unticked confirmation does not disable", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// No "confirmation" field at all: the checkbox was left unticked.
		req, err := http.NewRequest(
			http.MethodPost,
			ts.URL+"/console/org/org1/services/org1-service1/disable",
			strings.NewReader(url.Values{}.Encode()),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusFound {
			t.Fatalf("expected redirect (302), got %d", resp.StatusCode)
		}

		if at := disabledAt(); at != nil {
			t.Errorf("an unconfirmed disable must not change disabled_at, got %v", at)
		}
	})

	t.Run("non-member cannot reach the disable page or enable", func(t *testing.T) {
		// username7 belongs to org2, not org1. (username2 also belongs to
		// org2, but its seeded password is too short to pass the console
		// login form's validation, so it cannot be used to log in here.)
		client, _ := consoleLogin(t, ts.URL, "username7", validUserPassword)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		resp, err := client.Get(ts.URL + "/console/org/org1/services/org1-service1/disable") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		// 200 with an in-page error, per this package's console convention.
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 with an in-page error on the disable page for a non-member, got %d", resp.StatusCode)
		}
		disableDoc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(disableDoc.Find("span.error-text").Text()); !strings.Contains(got, consoleNotAllowedDisableService) {
			t.Errorf("expected the disable refusal to be explained in-page, got %q", got)
		}

		req, err := http.NewRequest(
			http.MethodPost,
			ts.URL+"/console/org/org1/services/org1-service1/enable",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		enableResp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer enableResp.Body.Close()

		// Enable is triggered by hx-post, and htmx discards non-2xx bodies,
		// so a 403 here would swap nothing and leave the user with no
		// explanation at all. 200 plus an in-page error is what reaches them.
		if enableResp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 with an in-page error on enable for a non-member, got %d", enableResp.StatusCode)
		}
		enableDoc, err := goquery.NewDocumentFromReader(enableResp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(enableDoc.Find("span.error-text").Text()); !strings.Contains(got, consoleNotAllowedEnableService) {
			t.Errorf("expected the enable refusal to be explained in-page, got %q", got)
		}

		if at := disabledAt(); at != nil {
			t.Errorf("a refused request must not change disabled_at, got %v", at)
		}
	})

	t.Run("services page shows disabled state", func(t *testing.T) {
		_, err := dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = '00000003-0000-0000-0000-000000000001'")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, err := dbPool.Exec(ctx, "UPDATE services SET disabled_at = NULL WHERE id = '00000003-0000-0000-0000-000000000001'")
			if err != nil {
				t.Error(err)
			}
		})

		client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)

		resp, err := client.Get(ts.URL + "/console/org/org1/services") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		// Enable is a one-click mutation, so its URL must carry the immutable
		// id rather than the reusable name.
		if doc.Find("button[hx-post='/console/org/org1/services/00000003-0000-0000-0000-000000000001/enable']").Length() == 0 {
			t.Error("expected an Enable action for the disabled service")
		}

		if doc.Find("a[href='/console/org/org1/services/org1-service1/disable']").Length() != 0 {
			t.Error("disabled service should not offer a Disable action")
		}
	})

	// A stale link, a typo, or a service another operator already deleted
	// must render a readable in-page error, not a bare 500 -- the same
	// treatment consoleServiceDeleteHandler already gives the same lookup
	// failure.
	t.Run("GET of the disable page for a missing service shows an in-page error", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)

		resp, err := client.Get(ts.URL + "/console/org/org1/services/no-such-service/disable") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("expected a rendered page (200), got %d (%s)", resp.StatusCode, string(body))
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(doc.Text(), "Service not found") {
			t.Errorf("expected an in-page 'Service not found' error, body was: %s", doc.Text())
		}
	})

	// Same defect, org side: a nonexistent org in the URL must not 500 either.
	t.Run("GET of the disable page for a missing org shows an in-page error", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

		resp, err := client.Get(ts.URL + "/console/org/no-such-org/services/org1-service1/disable") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("expected a rendered page (200), got %d (%s)", resp.StatusCode, string(body))
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(doc.Text(), "Organization not found") {
			t.Errorf("expected an in-page 'Organization not found' error, body was: %s", doc.Text())
		}
	})

	// consoleServiceEnableHandler has the same defect class, but reaches it
	// through setServiceDisabled rather than validateServiceName -- that
	// function collapses a missing service into cdnerrors.ErrNotFound
	// rather than a raw pgx.ErrNoRows, so it needs its own assertion.
	t.Run("POST of enable for a missing service shows an in-page error", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		req, err := http.NewRequest(
			http.MethodPost,
			ts.URL+"/console/org/org1/services/no-such-service/enable",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("expected a rendered page (200), got %d (%s)", resp.StatusCode, string(body))
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(doc.Text(), "Service not found") {
			t.Errorf("expected an in-page 'Service not found' error, body was: %s", doc.Text())
		}
	})
}

// TestConsoleServiceEnableStaleRowCannotHitReplacement is the enable
// counterpart to the delete stale-form test. Enable is the more exposed of the
// two: it is a single click straight from the services table, with no
// confirmation page in between, so a table left open in a tab is all it takes.
// A name-keyed request could bring online a same-named REPLACEMENT that
// someone had deliberately left disabled.
func TestConsoleServiceEnableStaleRowCannotHitReplacement(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	const originalID = "00000003-0000-0000-0000-000000000002"
	const serviceName = "org1-service2"

	if _, err := dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = $1", originalID); err != nil {
		t.Fatal(err)
	}

	client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)

	// 1. Tenant loads the services table while the original is disabled.
	resp, err := client.Get(ts.URL + "/console/org/org1/services") // #nosec G704
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	enableURL := ""
	doc.Find("button[hx-post]").Each(func(_ int, sel *goquery.Selection) {
		if v, ok := sel.Attr("hx-post"); ok && strings.HasSuffix(v, "/enable") {
			enableURL = v
		}
	})
	if enableURL == "" {
		t.Fatal("no Enable action found for the disabled service")
	}
	// Non-fatal so a regression still demonstrates the consequence below.
	if !strings.Contains(enableURL, originalID) {
		t.Errorf("Enable action should be keyed on the service UUID, got %q", enableURL)
	}

	// 2. The original is deleted and a replacement takes its name, left
	//    disabled on purpose.
	if _, err := dbPool.Exec(ctx, "DELETE FROM services WHERE id = $1", originalID); err != nil {
		t.Fatal(err)
	}
	var replacementID string
	err = dbPool.QueryRow(
		ctx,
		`INSERT INTO services (org_id, name, uid_range, disabled_at)
		 VALUES ('00000002-0000-0000-0000-000000000001', $1, '(1000910000, 1000919999)', now())
		 RETURNING id::text`,
		serviceName,
	).Scan(&replacementID)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Tenant clicks Enable on the stale row.
	req, err := http.NewRequest(http.MethodPost, ts.URL+enableURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	enableResp, err := client.Do(req) // #nosec G704
	if err != nil {
		t.Fatal(err)
	}
	defer enableResp.Body.Close()

	// The replacement was deliberately left disabled and must stay that way.
	var disabledAt *time.Time
	if err := dbPool.QueryRow(ctx, "SELECT disabled_at FROM services WHERE id = $1", replacementID).Scan(&disabledAt); err != nil {
		t.Fatal(err)
	}
	if disabledAt == nil {
		t.Error("a stale Enable action must not bring a same-named replacement service online")
	}
}

// TestConsoleServiceDeleteStaleFormCannotHitReplacement covers the
// time-of-check/time-of-use window on the delete confirmation page.
//
// Service names are unique per org only at a given moment: deleting a service
// frees its name for reuse. If an operator opened the confirmation page for
// service X named "www", and X were then deleted and a replacement "www"
// created and disabled before they submitted, a name-keyed form would have
// resolved the REPLACEMENT and permanently deleted it -- while the page they
// reviewed described X, down to its addresses and uid range. The form is
// therefore keyed on the immutable UUID, which is never reused.
func TestConsoleServiceDeleteStaleFormCannotHitReplacement(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	// org1-service2 has no versions, so it is a clean delete target.
	const originalID = "00000003-0000-0000-0000-000000000002"
	const serviceName = "org1-service2"

	if _, err := dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = $1", originalID); err != nil {
		t.Fatal(err)
	}

	client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

	// 1. Operator opens the confirmation page for the original service.
	resp, err := client.Get(ts.URL + "/console/org/org1/services/" + serviceName + "/delete") // #nosec G704
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	action, ok := doc.Find("form[method='post']").Attr("action")
	if !ok {
		t.Fatal("delete confirmation form has no action")
	}
	// The action must carry the immutable id, not the reusable name.
	// Deliberately t.Errorf rather than t.Fatalf: if this regresses, the rest
	// of the test still runs and demonstrates the actual consequence -- the
	// replacement service being deleted -- rather than stopping at the symptom.
	if !strings.Contains(action, originalID) {
		t.Errorf("form action should be keyed on the service UUID, got %q", action)
	}

	// 2. Meanwhile the original is deleted and a replacement takes its name.
	if _, err := dbPool.Exec(ctx, "DELETE FROM services WHERE id = $1", originalID); err != nil {
		t.Fatal(err)
	}
	var replacementID string
	err = dbPool.QueryRow(
		ctx,
		`INSERT INTO services (org_id, name, uid_range, disabled_at)
		 VALUES ('00000002-0000-0000-0000-000000000001', $1, '(1000900000, 1000909999)', now())
		 RETURNING id::text`,
		serviceName,
	).Scan(&replacementID)
	if err != nil {
		t.Fatal(err)
	}
	if replacementID == originalID {
		t.Fatal("replacement must have a different UUID for this test to mean anything")
	}

	// 3. Operator submits the stale form, typing the name they were shown.
	form := url.Values{"confirm-name": {serviceName}}
	req, err := http.NewRequest(http.MethodPost, ts.URL+action, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	postResp, err := client.Do(req) // #nosec G704
	if err != nil {
		t.Fatal(err)
	}
	defer postResp.Body.Close()

	// The service that was reviewed no longer exists, so the submission must
	// find nothing rather than fall through to the same-named replacement.
	var replacementCount int64
	if err := dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM services WHERE id = $1", replacementID).Scan(&replacementCount); err != nil {
		t.Fatal(err)
	}
	if replacementCount != 1 {
		t.Error("a stale confirmation form must not delete the same-named replacement service")
	}
}

// TestServiceUUIDIsConstrainedToSuppliedOrg pins that a UUID from one org
// cannot be resolved while naming a different org.
//
// Without the constraint the UUID lookup ignored the supplied org, and a
// superuser request naming org1 while passing an org2 service UUID mutated the
// org2 service -- an org the request never mentioned. The console flows made it
// worse: the delete page resolved the service by UUID to render its name,
// version count, addresses and uid range, then the POST re-resolved by NAME
// within the URL's org. With the same service name present in both orgs, the
// page described one service while the POST acted on the other, and the typed
// name confirmation matched both so it confirmed the wrong target.
func TestServiceUUIDIsConstrainedToSuppliedOrg(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	// org2-service1 lives in org2; the request below claims org1.
	const org2Service1 = "00000003-0000-0000-0000-000000000004"

	disabledAt := func() *time.Time {
		t.Helper()
		var at *time.Time
		if err := dbPool.QueryRow(ctx, "SELECT disabled_at FROM services WHERE id = $1", org2Service1).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}

	if at := disabledAt(); at != nil {
		t.Fatalf("org2-service1 should start enabled, got disabled_at=%v", at)
	}

	req, err := http.NewRequest(
		http.MethodPut,
		ts.URL+"/api/v1/services/"+org2Service1+"/disabled?org=org1",
		strings.NewReader(`{"disabled": true}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Superuser: the org-membership check inside setServiceDisabled is skipped
	// for them, so nothing but the constrained lookup stops this.
	req.SetBasicAuth("admin", validAdminPassword)

	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// A cross-org UUID must be indistinguishable from an unknown one, so the
	// response does not reveal that it exists in another org.
	if resp.StatusCode != http.StatusNotFound {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Errorf("expected 404 for a UUID outside the supplied org, got %d (%s)", resp.StatusCode, string(body))
	}

	// The assertion that actually matters: the service in the org the request
	// never named must be untouched.
	if at := disabledAt(); at != nil {
		t.Errorf("a request naming org1 must not modify an org2 service, got disabled_at=%v", at)
	}
}

// TestServiceIdentifierLocking proves the row lock each identifier helper
// actually takes, rather than asserting the SQL text.
//
// It exists because resolving a service with FOR SHARE and then writing to the
// row upgrades ShareLock to ExclusiveLock: two such transactions can both hold
// the shared lock and then each wait for the other before its own upgrade,
// which PostgreSQL breaks after deadlock_timeout by aborting one with SQLSTATE
// 40P01. Every path that writes the services row must therefore resolve with
// newServiceIdentifierForUpdate. If someone switches one of them back, the
// exclusive-lock assertion below stops holding.
func TestServiceIdentifierLocking(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	// The shared test pool is deliberately capped at one connection, which
	// cannot hold two concurrent transactions. Build a second pool against the
	// same database for this test only.
	cfg := dbPool.Config().Copy()
	cfg.MaxConns = 3
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	const serviceID = "00000003-0000-0000-0000-000000000001"
	noOrg := pgtype.UUID{}

	// resolve runs one identifier lookup in its own transaction and reports
	// how long it took and whether it failed, so "blocked" can be told apart
	// from "failed instantly".
	resolve := func(t *testing.T, forUpdate bool, timeout time.Duration) (time.Duration, error) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if rbErr := tx.Rollback(context.Background()); rbErr != nil {
				// Logged rather than failed: when a query is cancelled by its
				// context deadline pgx closes the connection instead of
				// reusing one with an in-flight query, which aborts the
				// transaction server-side and makes Rollback report
				// "conn closed". That is the expected path for the blocking
				// subtest below. Anything else still shows up in the log.
				t.Logf("rollback during cleanup: %v", rbErr)
			}
		})

		callCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		start := time.Now()
		if forUpdate {
			_, err = newServiceIdentifierForUpdate(callCtx, tx, serviceID, noOrg)
		} else {
			_, err = newServiceIdentifier(callCtx, tx, serviceID, noOrg)
		}
		return time.Since(start), err
	}

	t.Run("exclusive lock blocks a second exclusive resolve", func(t *testing.T) {
		// First holder takes FOR UPDATE and keeps it for the subtest.
		if _, err := resolve(t, true, 5*time.Second); err != nil {
			t.Fatalf("first exclusive resolve should succeed, got %v", err)
		}

		const timeout = 2 * time.Second
		elapsed, err := resolve(t, true, timeout)
		if err == nil {
			t.Fatal("second exclusive resolve should have blocked on the first, but succeeded -- the lookup is not taking an exclusive lock")
		}
		// Must have blocked for the whole timeout rather than failing fast for
		// some unrelated reason.
		if elapsed < timeout-(200*time.Millisecond) {
			t.Errorf("second resolve failed after only %v, so it did not block on the lock: %v", elapsed, err)
		}
	})

	t.Run("shared lock does not block another shared resolve", func(t *testing.T) {
		// Read-only paths must stay concurrent; making the helper exclusive
		// for everyone would serialise them needlessly.
		if _, err := resolve(t, false, 5*time.Second); err != nil {
			t.Fatalf("first shared resolve should succeed, got %v", err)
		}
		elapsed, err := resolve(t, false, 2*time.Second)
		if err != nil {
			t.Errorf("a second shared resolve should not block, got %v after %v", err, elapsed)
		}
	})
}

// TestConsoleActivateServiceVersionPage covers the activate confirmation page,
// which had no console-level test before. It shares the disable page's
// confirmation shape -- an #confirmation checkbox gating the submit button via
// CSS, plus a Cancel link -- so a change to one should not silently diverge
// from the other.
func TestConsoleActivateServiceVersionPage(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)

	// org1-service1 version 1 exists and is not the active one.
	resp, err := client.Get(ts.URL + "/console/org/org1/services/org1-service1/1/activate") // #nosec G704
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if doc.Find("input[type='checkbox']#confirmation[required]").Length() == 0 {
		t.Error("the activate confirmation checkbox must be required, so the gate is not pointer-only")
	}
	// Cancel points at the service page, which is where the handler already
	// redirects an unconfirmed POST.
	if doc.Find("a[href='/console/org/org1/services/org1-service1']").Length() == 0 {
		t.Error("activate page should offer a Cancel link back to the service page")
	}

	// Deliberately NOT destructive: activating a version changes which config
	// is live and is undone by activating the previous one, so it does not
	// earn the colour reserved for disable and delete. Pinned so that
	// reddening it later has to be a conscious choice rather than a tidy-up.
	if doc.Find("button[type='submit'].destructive").Length() != 0 {
		t.Error("activate is reversible and should not use the destructive styling")
	}

	// Rendering the page must not activate anything.
	var active int64
	err = dbPool.QueryRow(ctx, "SELECT version FROM service_versions WHERE service_id = '00000003-0000-0000-0000-000000000001' AND active").Scan(&active)
	if err != nil {
		t.Fatal(err)
	}
	if active != 3 {
		t.Errorf("GET of the activate page must not change the active version, got %d", active)
	}
}

func TestConsoleServiceDelete(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	_, err = dbPool.Exec(ctx, "UPDATE services SET disabled_at = now() WHERE id = '00000003-0000-0000-0000-000000000002'")
	if err != nil {
		t.Fatal(err)
	}

	// assertServiceRowCount lets every subtest — including the ones whose
	// point is that nothing happened — verify the row's fate against the
	// database rather than inferring it from an HTTP status.
	assertServiceRowCount := func(t *testing.T, serviceID string, want int64) {
		t.Helper()
		var got int64
		if err := dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM services WHERE id = $1", serviceID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("service %s: expected COUNT(*) = %d, got %d", serviceID, want, got)
		}
	}

	t.Run("tenant sees no delete action for a disabled service", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)

		resp, err := client.Get(ts.URL + "/console/org/org1/services") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		// No working link to the delete page.
		if doc.Find("a[href='/console/org/org1/services/org1-service2/delete']").Length() != 0 {
			t.Error("non-superuser must not get a working link to the delete page")
		}

		// But the affordance must still be visible and visibly unavailable:
		// a greyed-out button, plus text saying why. A hidden button reads as
		// a missing feature rather than a policy.
		greyed := doc.Find("button[disabled]").FilterFunction(func(_ int, sel *goquery.Selection) bool {
			return strings.TrimSpace(sel.Text()) == "Delete"
		})
		if greyed.Length() == 0 {
			t.Error("non-superuser should see a disabled Delete button")
		}
		if _, ok := greyed.Attr("aria-disabled"); !ok {
			t.Error("disabled Delete button should carry aria-disabled")
		}
		if !strings.Contains(doc.Text(), "Requires superuser access") {
			t.Error("non-superuser should be told that deletion requires superuser access")
		}

		// Defence in depth: proves nothing happened to the row, not just
		// that the HTTP response looked right.
		assertServiceRowCount(t, "00000003-0000-0000-0000-000000000002", 1)
	})

	// Restores coverage deleted with the old DELETE route. A superuser
	// following a stale link, mistyping a name, or racing another operator's
	// deletion must get a readable page, not an opaque 500 — the same
	// treatment the handler already gives a nonexistent org.
	t.Run("nonexistent service shows an in-page error", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

		resp, err := client.Get(ts.URL + "/console/org/org1/services/no-such-service/delete") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("expected a rendered page (200), got %d (%s)", resp.StatusCode, string(body))
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(doc.Text(), "Service not found") {
			t.Errorf("expected an in-page 'Service not found' error, body was: %s", doc.Text())
		}
	})

	t.Run("tenant is forbidden from the delete page", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)

		resp, err := client.Get(ts.URL + "/console/org/org1/services/org1-service2/delete") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		// 200 with an in-page error, matching every other console refusal in
		// this package (see TestConsoleDeleteErrorRendering). A 403 would
		// also be discarded unrendered by htmx on the htmx-driven paths.
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 with an in-page error for a non-superuser, got %d", resp.StatusCode)
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		// Assert on span.error-text, the element ConsoleErrorContent renders
		// and the shared refusal table keys off, rather than on page text.
		errorText := strings.TrimSpace(doc.Find("span.error-text").Text())
		if !strings.Contains(errorText, consoleDeleteRequiresSuperuser) {
			t.Errorf("expected the in-page error to explain the rule, got %q", errorText)
		}
		// The confirmation form must not be offered.
		if doc.Find("input[name='confirm-name']").Length() != 0 {
			t.Error("a non-superuser must not be shown the delete confirmation form")
		}

		// Defence in depth: proves nothing happened to the row, not just
		// that the HTTP response looked right.
		assertServiceRowCount(t, "00000003-0000-0000-0000-000000000002", 1)
	})

	t.Run("superuser delete page renders", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

		resp, err := client.Get(ts.URL + "/console/org/org1/services/org1-service2/delete") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if doc.Find("input[name='confirm-name']").Length() == 0 {
			t.Error("delete page must have a confirm-name input")
		}

		// The page must list the addresses being released.
		if !strings.Contains(doc.Text(), "192.0.2.2") {
			t.Error("delete page should list the IP addresses being released")
		}

		// The most destructive button in the console must read as such. This
		// assertion exists because the destructive styling was first applied
		// only to the services-row Delete link, leaving the button that
		// actually performs the deletion looking like "Create service".
		if doc.Find("button[type='submit'].destructive").Length() == 0 {
			t.Error("the permanent-delete submit button should carry the destructive class")
		}

		// Cancel must exist: this is the one confirmation page where backing
		// out otherwise means using the browser's back button.
		if doc.Find("a[href='/console/org/org1/services']").Length() == 0 {
			t.Error("delete page should offer a Cancel link back to the services list")
		}
	})

	t.Run("wrong name is rejected and the service survives", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		form := url.Values{"confirm-name": {"not-the-name"}}

		req, err := http.NewRequest(
			http.MethodPost,
			ts.URL+"/console/org/org1/services/org1-service2/delete",
			strings.NewReader(form.Encode()),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected the page to re-render with an error (200), got %d", resp.StatusCode)
		}

		var count int64
		err = dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM services WHERE id = '00000003-0000-0000-0000-000000000002'").Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Error("service must survive a mismatched confirmation")
		}
	})

	// deleteService refuses an enabled service (ErrServiceNotDisabled). The
	// console reaches that branch too, and must not delete the row.
	t.Run("enabled service is refused and survives", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// org1-service3 is left enabled by this test.
		form := url.Values{"confirm-name": {"org1-service3"}}

		req, err := http.NewRequest(
			http.MethodPost,
			ts.URL+"/console/org/org1/services/org1-service3/delete",
			strings.NewReader(form.Encode()),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected the page to re-render with an error (200), got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		// The typed name was correct ("org1-service3"), so the refusal
		// reason is ErrServiceNotDisabled, not a name mismatch. Asserting
		// only the status code here would have missed the bug where the
		// page told the operator they had mistyped a name they typed
		// correctly.
		if strings.Contains(string(body), "did not match") {
			t.Errorf("refusal reason is that the service is enabled, not a name mismatch; body was: %s", string(body))
		}
		if !strings.Contains(string(body), "must be disabled") {
			t.Errorf("expected the page to say the service must be disabled first, body was: %s", string(body))
		}

		var count int64
		err = dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM services WHERE id = '00000003-0000-0000-0000-000000000003'").Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Error("an enabled service must survive a delete attempt")
		}
	})

	// Restores coverage for the GET branch: an enabled service must not
	// render the confirmation form at all, since deleteService can never
	// succeed against it. Before this fix the page rendered normally and
	// asserted a false "disabled service" claim.
	t.Run("GET of an enabled service shows the must-be-disabled error, not the confirm form", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

		resp, err := client.Get(ts.URL + "/console/org/org1/services/org1-service3/delete") // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("expected a rendered page (200), got %d (%s)", resp.StatusCode, string(body))
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if doc.Find("input[name='confirm-name']").Length() != 0 {
			t.Error("an enabled service's delete GET must not render the confirm-name input")
		}
		if !strings.Contains(doc.Text(), "must be disabled") {
			t.Errorf("expected an in-page 'must be disabled' error, body was: %s", doc.Text())
		}
	})

	t.Run("correct name deletes the service", func(t *testing.T) {
		client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}

		form := url.Values{"confirm-name": {"org1-service2"}}

		req, err := http.NewRequest(
			http.MethodPost,
			ts.URL+"/console/org/org1/services/org1-service2/delete",
			strings.NewReader(form.Encode()),
		)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusFound {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			t.Fatalf("expected redirect (302), got %d (%s)", resp.StatusCode, string(body))
		}

		var count int64
		err = dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM services WHERE id = '00000003-0000-0000-0000-000000000002'").Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Error("service should have been deleted")
		}
	})
}

func TestConsoleFormLimit(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	defer ts.Close()
	tests := []struct {
		description string
		username    string
		password    string
		statusCode  int
	}{
		{
			description: "failed request with too large password field",
			username:    "admin",
			password:    strings.Repeat("A", formMaxSize*2),
			statusCode:  http.StatusRequestEntityTooLarge,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}

			client := &http.Client{Jar: jar}

			form := url.Values{
				"username": {test.username},
				"password": {test.password},
			}

			req, err := http.NewRequest(http.MethodPost, ts.URL+cdntypes.AuthLoginPath, strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			// Needed to make CSRF-validation happy
			req.Header.Set("Sec-Fetch-Site", "same-origin")

			loginResp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer loginResp.Body.Close()

			if loginResp.StatusCode != test.statusCode {
				t.Fatalf("TestConsoleFormLimit: unexpected console login status code: %d, expected %d", loginResp.StatusCode, test.statusCode)
			}
		})
	}
}

func TestPutOrganization(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		org              string
		name             string
		serviceQuota     int64
		domainQuota      int64
		clientTokenQuota int64
	}{
		{
			description:      "successful superuser request",
			username:         "admin",
			password:         validAdminPassword,
			expectedStatus:   http.StatusOK,
			org:              "org4",
			name:             "org4-renamed",
			serviceQuota:     10,
			domainQuota:      20,
			clientTokenQuota: 30,
		},
		{
			description:      "successful superuser request, update quotas",
			username:         "admin",
			password:         validAdminPassword,
			expectedStatus:   http.StatusOK,
			org:              "org4-renamed",
			name:             "org4-renamed",
			serviceQuota:     50,
			domainQuota:      100,
			clientTokenQuota: 200,
		},
		{
			description:      "failed non-superuser request",
			username:         "username1",
			password:         validUserPassword,
			expectedStatus:   http.StatusForbidden,
			org:              "org1",
			name:             "org1",
			serviceQuota:     10,
			domainQuota:      20,
			clientTokenQuota: 30,
		},
		{
			description:      "failed superuser request, not found",
			username:         "admin",
			password:         validAdminPassword,
			expectedStatus:   http.StatusNotFound,
			org:              "nonexistent-org",
			name:             "nonexistent-org",
			serviceQuota:     10,
			domainQuota:      20,
			clientTokenQuota: 30,
		},
		{
			description:      "failed superuser request, conflict on rename",
			username:         "admin",
			password:         validAdminPassword,
			expectedStatus:   http.StatusConflict,
			org:              "org1",
			name:             "org2",
			serviceQuota:     10,
			domainQuota:      20,
			clientTokenQuota: 30,
		},
		{
			description:      "failed superuser request, invalid name",
			username:         "admin",
			password:         validAdminPassword,
			expectedStatus:   http.StatusUnprocessableEntity,
			org:              "org1",
			name:             "INVALID NAME",
			serviceQuota:     10,
			domainQuota:      20,
			clientTokenQuota: 30,
		},
		{
			// UUID starts with a letter to bypass Huma's DNS label pattern
			// validation — this exercises the database CHECK constraint
			description:      "failed superuser request, UUID name",
			username:         "admin",
			password:         validAdminPassword,
			expectedStatus:   http.StatusUnprocessableEntity,
			org:              "org1",
			name:             "abcdef01-2345-6789-abcd-ef0123456789",
			serviceQuota:     10,
			domainQuota:      20,
			clientTokenQuota: 30,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			body := struct {
				Name             string `json:"name"`
				ServiceQuota     int64  `json:"service_quota"`
				DomainQuota      int64  `json:"domain_quota"`
				ClientTokenQuota int64  `json:"client_token_quota"`
			}{
				Name:             test.name,
				ServiceQuota:     test.serviceQuota,
				DomainQuota:      test.domainQuota,
				ClientTokenQuota: test.clientTokenQuota,
			}

			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}

			r := bytes.NewReader(b)

			req, err := http.NewRequest(http.MethodPut, ts.URL+"/api/v1/orgs/"+test.org, r)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", contentTypeJSON)
			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("PUT org unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)

			if test.expectedStatus == http.StatusOK {
				var result cdntypes.Org
				if err := json.Unmarshal(jsonData, &result); err != nil {
					t.Fatalf("unable to unmarshal response: %v", err)
				}
				if result.Name != test.name {
					t.Fatalf("expected name %q, got %q", test.name, result.Name)
				}
				if result.ServiceQuota != test.serviceQuota {
					t.Fatalf("expected service_quota %d, got %d", test.serviceQuota, result.ServiceQuota)
				}
				if result.DomainQuota != test.domainQuota {
					t.Fatalf("expected domain_quota %d, got %d", test.domainQuota, result.DomainQuota)
				}
				if result.ClientTokenQuota != test.clientTokenQuota {
					t.Fatalf("expected client_token_quota %d, got %d", test.clientTokenQuota, result.ClientTokenQuota)
				}
			}
		})
	}
}

func TestDeleteOrganization(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		org            string
	}{
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
			org:            "org4",
		},
		{
			description:    "failed superuser request, bad password",
			username:       "admin",
			password:       "badadminpass1",
			expectedStatus: http.StatusUnauthorized,
			org:            "org4",
		},
		{
			description:    "failed superuser request, not found",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNotFound,
			org:            "nonexistent-org",
		},
		{
			description:    "failed superuser request, org has dependents",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusConflict,
			org:            "org1",
		},
		{
			description:    "successful superuser request, org with no children",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusNoContent,
			org:            "org4",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/orgs/"+test.org, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("DELETE org unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			// Verify the resource is actually gone by retrying the DELETE
			if test.expectedStatus == http.StatusNoContent {
				retryReq, err := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/orgs/"+test.org, nil)
				if err != nil {
					t.Fatal(err)
				}
				retryReq.SetBasicAuth(test.username, test.password)
				retryResp, err := http.DefaultClient.Do(retryReq) // #nosec G704 -- filled in by test
				if err != nil {
					t.Fatal(err)
				}
				defer retryResp.Body.Close()
				if retryResp.StatusCode != http.StatusNotFound {
					t.Fatalf("expected 404 on retry DELETE, got %d", retryResp.StatusCode)
				}
			}
		})
	}
}

func TestConsoleDeleteErrorRendering(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		method           string
		path             string
		formBody         string
		expectedStatus   int
		expectedErrorMsg string
	}{
		{
			description:      "delete nonexistent cache node shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodDelete,
			path:             "/console/superuser/cache-nodes/nonexistent-node",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleCacheNodeNotFound,
		},
		{
			description:      "delete nonexistent L4LB node shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodDelete,
			path:             "/console/superuser/l4lb-nodes/nonexistent-node",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleL4LBNodeNotFound,
		},
		{
			description:      "delete nonexistent node group shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodDelete,
			path:             "/console/superuser/node-groups/nonexistent-group",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: "Node group not found",
		},
		{
			description:      "delete nonexistent domain shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodDelete,
			path:             "/console/org/org1/domains/nonexistent.example.com",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: "Domain not found",
		},
		{
			description:      "toggle maintenance on nonexistent cache node shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodPut,
			path:             "/console/superuser/cache-nodes/nonexistent-node/maintenance",
			formBody:         "maintenance=on",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleCacheNodeNotFound,
		},
		{
			description:      "toggle maintenance on nonexistent L4LB node shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodPut,
			path:             "/console/superuser/l4lb-nodes/nonexistent-node/maintenance",
			formBody:         "maintenance=on",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleL4LBNodeNotFound,
		},
		{
			description:      "assign node group on nonexistent cache node shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodPut,
			path:             "/console/superuser/cache-nodes/nonexistent-node/node-group",
			formBody:         "node-group=node-group-1",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: "Cache node or node group not found",
		},
		{
			description:      "assign node group on nonexistent L4LB node shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodPut,
			path:             "/console/superuser/l4lb-nodes/nonexistent-node/node-group",
			formBody:         "node-group=node-group-1",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: "L4LB node or node group not found",
		},
		{
			description:      "delete nonexistent API token shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodDelete,
			path:             "/console/org/org1/api-tokens/nonexistent-token",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: "API token not found",
		},
		{
			description:      "org1 user deleting org2 API token shows forbidden error",
			username:         "username1",
			password:         validUserPassword,
			method:           http.MethodDelete,
			path:             "/console/org/org2/api-tokens/nonexistent-token",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleNotAllowedDeleteAPIToken,
		},
		{
			description:      "org1 user deleting org2 domain shows forbidden error",
			username:         "username1",
			password:         validUserPassword,
			method:           http.MethodDelete,
			path:             "/console/org/org2/domains/example.se",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleNotAllowedDeleteDomain,
		},
		{
			description:      "delete node group with assigned nodes shows conflict error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodDelete,
			path:             "/console/superuser/node-groups/node-group-1",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: "Cannot delete node group: nodes are still assigned to it",
		},
		{
			description:      "delete nonexistent ip network shows in-page error",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodDelete,
			path:             "/console/superuser/ip-networks/00000000-0000-0000-0000-000000000099",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleIPNetworkNotFound,
		},
		{
			// Restores the coverage deleted with the old one-click service
			// DELETE route, in this table's shape. The refusal reason
			// changed -- deletion is now superuser-only rather than
			// org-scoped -- so this case targets the caller's OWN org, to
			// prove it is the superuser rule that refuses them.
			description:      "org1 user reaching the service delete page shows forbidden error",
			username:         "username1",
			password:         validUserPassword,
			method:           http.MethodGet,
			path:             "/console/org/org1/services/org1-service1/delete",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleDeleteRequiresSuperuser,
		},
		{
			description:      "org1 user disabling an org2 service shows forbidden error",
			username:         "username1",
			password:         validUserPassword,
			method:           http.MethodGet,
			path:             "/console/org/org2/services/org2-service1/disable",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleNotAllowedDisableService,
		},
		{
			description:      "org1 user enabling an org2 service shows forbidden error",
			username:         "username1",
			password:         validUserPassword,
			method:           http.MethodPost,
			path:             "/console/org/org2/services/org2-service1/enable",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleNotAllowedEnableService,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			client, _ := consoleLogin(t, ts.URL, test.username, test.password)

			var reqBody io.Reader
			if test.formBody != "" {
				reqBody = strings.NewReader(test.formBody)
			}
			req, err := http.NewRequest(test.method, ts.URL+test.path, reqBody)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Sec-Fetch-Site", "same-origin")
			if test.formBody != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			resp, err := client.Do(req) // #nosec G704
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				body, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				t.Fatalf("unexpected status code: got %d, want %d (%s)", resp.StatusCode, test.expectedStatus, string(body))
			}

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				t.Fatalf("failed to parse response HTML: %v", err)
			}

			errorText := strings.TrimSpace(doc.Find("span.error-text").Text())
			if !strings.Contains(errorText, test.expectedErrorMsg) {
				t.Fatalf("expected error text to contain %q, got %q", test.expectedErrorMsg, errorText)
			}
		})
	}
}

func TestConsolePhase2ErrorRendering(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		method           string
		path             string
		expectedStatus   int
		expectedErrorMsg string
	}{
		{
			description:      "forbidden on domains list page for non-member",
			username:         "username1",
			password:         validUserPassword,
			method:           http.MethodGet,
			path:             "/console/org/org2/domains",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleNeedOrgMembershipMsg,
		},
		{
			description:      "forbidden on services list page for non-member",
			username:         "username1",
			password:         validUserPassword,
			method:           http.MethodGet,
			path:             "/console/org/org2/services",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleNeedOrgMembershipMsg,
		},
		{
			description:      "forbidden on api tokens list page for non-member",
			username:         "username1",
			password:         validUserPassword,
			method:           http.MethodGet,
			path:             "/console/org/org2/api-tokens",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleNeedOrgMembershipMsg,
		},
		{
			description:      "org not found on dashboard",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodGet,
			path:             "/console/org/nonexistent-org",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleOrgNotFound,
		},
		{
			description:      "org not found on create domain page",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodGet,
			path:             "/console/org/nonexistent-org/create/domain",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleOrgNotFound,
		},
		{
			description:      "org not found on edit org page",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodGet,
			path:             "/console/superuser/orgs/nonexistent-org/edit",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleOrgNotFound,
		},
		{
			description:      "cache node not found on edit page",
			username:         "admin",
			password:         validAdminPassword,
			method:           http.MethodGet,
			path:             "/console/superuser/cache-nodes/nonexistent/edit",
			expectedStatus:   http.StatusOK,
			expectedErrorMsg: consoleCacheNodeNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			client, _ := consoleLogin(t, ts.URL, test.username, test.password)

			req, err := http.NewRequest(test.method, ts.URL+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Sec-Fetch-Site", "same-origin")

			resp, err := client.Do(req) // #nosec G704
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				body, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					t.Fatal(readErr)
				}
				t.Fatalf("unexpected status code: got %d, want %d (%s)", resp.StatusCode, test.expectedStatus, string(body))
			}

			doc, err := goquery.NewDocumentFromReader(resp.Body)
			if err != nil {
				t.Fatalf("failed to parse response HTML: %v", err)
			}

			errorText := strings.TrimSpace(doc.Find("span.error-text").Text())
			if !strings.Contains(errorText, test.expectedErrorMsg) {
				t.Fatalf("expected error text to contain %q, got %q", test.expectedErrorMsg, errorText)
			}
		})
	}
}

func TestGetRoles(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
			description:    "superuser can list roles",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusOK,
		},
		{
			description:    "non-superuser gets 403",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/roles", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			resp, err := http.DefaultClient.Do(req) // #nosec G704
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				r, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(r))
			}

			if test.expectedStatus == http.StatusOK {
				var roles []cdntypes.Role
				err := json.NewDecoder(resp.Body).Decode(&roles)
				if err != nil {
					t.Fatalf("unable to decode roles response: %v", err)
				}
				if len(roles) == 0 {
					t.Fatal("expected at least one role")
				}
				roleNames := []string{}
				for _, r := range roles {
					roleNames = append(roleNames, r.Name)
				}
				for _, expected := range []string{"admin", "user", "node"} {
					if !slices.Contains(roleNames, expected) {
						t.Fatalf("expected role %q not found in %v", expected, roleNames)
					}
				}
			}
		})
	}
}

// consoleLogin is a helper that performs console login and returns an authenticated client.
func consoleLogin(t *testing.T, tsURL string, username, password string) (*http.Client, *http.Cookie) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Jar: jar,
		// Do not automatically follow redirects so when we inspect the
		// response cookies below we are sure to inspect the initial
		// response.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	form := url.Values{
		"username": {username},
		"password": {password},
	}

	u, err := url.Parse(tsURL)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, tsURL+cdntypes.AuthLoginPath, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	loginResp, err := client.Do(req) // #nosec G704
	if err != nil {
		t.Fatal(err)
	}
	defer loginResp.Body.Close()

	if loginResp.StatusCode != http.StatusFound {
		t.Fatalf("consoleLogin: unexpected console login status code: %d", loginResp.StatusCode)
	}

	loginLocation := loginResp.Header.Get("Location")
	if loginLocation != "/console" {
		t.Fatalf("expected login redirect to /console, got %s", loginLocation)
	}

	var sessionCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == cookieName {
			sessionCookie = c
		}
	}

	cookieFound := false
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == cookieName {
			cookieFound = true
			break
		}
	}
	if !cookieFound {
		t.Fatal("login failed: session cookie is missing")
	}

	// Make the client follow redirects again so downstream users work as normal clients
	client.CheckRedirect = nil

	return client, sessionCookie
}

func TestConsoleUsersList(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
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
		expectUsers    bool
	}{
		{
			description:    "superuser can list users",
			username:       "admin",
			password:       validAdminPassword,
			expectedStatus: http.StatusOK,
			expectUsers:    true,
		},
		{
			description:    "non-superuser gets 403",
			username:       "username1",
			password:       validUserPassword,
			expectedStatus: http.StatusForbidden,
			expectUsers:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			client, _ := consoleLogin(t, ts.URL, test.username, test.password)

			req, err := http.NewRequest(http.MethodGet, ts.URL+"/console/superuser/users", nil)
			if err != nil {
				t.Fatal(err)
			}

			resp, err := client.Do(req) // #nosec G704
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.expectedStatus {
				t.Fatalf("unexpected status code: %d", resp.StatusCode)
			}

			if test.expectUsers {
				doc, err := goquery.NewDocumentFromReader(resp.Body)
				if err != nil {
					t.Fatalf("failed to parse response HTML: %v", err)
				}

				rows := doc.Find("main #contents table tbody tr")
				if rows.Length() == 0 {
					t.Fatal("expected at least one user in the table")
				}

				adminFound := false
				rows.Each(func(_ int, s *goquery.Selection) {
					name := strings.TrimSpace(s.Find("td").First().Text())
					if name == "admin" {
						adminFound = true
					}
				})
				if !adminFound {
					t.Fatal("admin user not found in user list")
				}
			}
		})
	}
}

func TestConsoleCreateUser(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description      string
		formData         url.Values
		expectRedirect   bool
		expectedErrorMsg string
	}{
		{
			description: "successful user creation",
			formData: url.Values{
				"display_name":     {"test-console-user"},
				"role":             {"user"},
				"org":              {"org1"},
				"password":         {"testpassword12345"},
				"confirm-password": {"testpassword12345"},
			},
			expectRedirect: true,
		},
		{
			description: "password mismatch",
			formData: url.Values{
				"display_name":     {"test-mismatch-user"},
				"role":             {"user"},
				"org":              {cdntypes.OrgNotSelected},
				"password":         {"testpassword12345"},
				"confirm-password": {"different12345678"},
			},
			expectedErrorMsg: consolePasswordMismatch,
		},
		{
			description: "password too short",
			formData: url.Values{
				"display_name":     {"test-short-pw-user"},
				"role":             {"user"},
				"org":              {cdntypes.OrgNotSelected},
				"password":         {"short"},
				"confirm-password": {"short"},
			},
			expectedErrorMsg: consolePasswordTooShort,
		},
		{
			description: "duplicate name",
			formData: url.Values{
				"display_name":     {"admin"},
				"role":             {"admin"},
				"org":              {cdntypes.OrgNotSelected},
				"password":         {"testpassword12345"},
				"confirm-password": {"testpassword12345"},
			},
			expectedErrorMsg: consoleAlreadyExists,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

			client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/console/superuser/create/user", strings.NewReader(test.formData.Encode()))
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Sec-Fetch-Site", "same-origin")

			resp, err := client.Do(req) // #nosec G704
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if test.expectRedirect {
				if resp.StatusCode != http.StatusSeeOther {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("expected redirect (303), got %d (%s)", resp.StatusCode, string(body))
				}
				location := resp.Header.Get("Location")
				if !strings.Contains(location, "/console/superuser/users") {
					t.Fatalf("expected redirect to users list, got %s", location)
				}
			} else {
				if resp.StatusCode != http.StatusOK {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
				}

				if test.expectedErrorMsg != "" {
					doc, err := goquery.NewDocumentFromReader(resp.Body)
					if err != nil {
						t.Fatalf("failed to parse response HTML: %v", err)
					}
					errorText := strings.TrimSpace(doc.Find("span.error-text").Text())
					if !strings.Contains(errorText, test.expectedErrorMsg) {
						t.Fatalf("expected error text to contain %q, got %q", test.expectedErrorMsg, errorText)
					}
				}
			}
		})
	}
}

func TestConsoleEditUser(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description      string
		method           string
		path             string
		formData         url.Values
		expectRedirect   bool
		expectedStatus   int
		expectedErrorMsg string
	}{
		{
			description: "GET edit form for existing user",
			method:      http.MethodGet,
			path:        "/console/superuser/users/00000006-0000-0000-0000-000000000002/edit",
		},
		{
			description:      "GET edit form for non-existent user",
			method:           http.MethodGet,
			path:             "/console/superuser/users/00000000-0000-0000-0000-000000000000/edit",
			expectedErrorMsg: consoleUserNotFound,
		},
		{
			description:    "GET edit form with invalid UUID returns 400",
			method:         http.MethodGet,
			path:           "/console/superuser/users/not-a-uuid/edit",
			expectedStatus: http.StatusBadRequest,
		},
		{
			description: "POST edit to change user role",
			method:      http.MethodPost,
			path:        "/console/superuser/users/00000006-0000-0000-0000-000000000007/edit",
			formData: url.Values{
				"display_name": {"username6"},
				"role":         {"admin"},
				"org":          {cdntypes.OrgNotSelected},
			},
			expectRedirect: true,
		},
		{
			description: "POST edit non-existent user",
			method:      http.MethodPost,
			path:        "/console/superuser/users/00000000-0000-0000-0000-000000000000/edit",
			formData: url.Values{
				"display_name": {"nonexistent-user"},
				"role":         {"user"},
				"org":          {cdntypes.OrgNotSelected},
			},
			expectedErrorMsg: consoleUserNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

			client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}

			var reqBody io.Reader
			if test.formData != nil {
				reqBody = strings.NewReader(test.formData.Encode())
			}

			req, err := http.NewRequest(test.method, ts.URL+test.path, reqBody)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Sec-Fetch-Site", "same-origin")
			if test.formData != nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			resp, err := client.Do(req) // #nosec G704
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if test.expectedStatus == http.StatusBadRequest {
				if resp.StatusCode != http.StatusBadRequest {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("expected 400, got %d (%s)", resp.StatusCode, string(body))
				}
				return
			}

			if test.expectRedirect {
				if resp.StatusCode != http.StatusSeeOther {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("expected redirect (303), got %d (%s)", resp.StatusCode, string(body))
				}
			} else {
				if resp.StatusCode != http.StatusOK {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("unexpected status code: got %d (%s)", resp.StatusCode, string(body))
				}

				if test.expectedErrorMsg != "" {
					doc, err := goquery.NewDocumentFromReader(resp.Body)
					if err != nil {
						t.Fatalf("failed to parse response HTML: %v", err)
					}
					pageText := strings.TrimSpace(doc.Find("main").Text())
					if !strings.Contains(pageText, test.expectedErrorMsg) {
						t.Fatalf("expected page to contain %q, got %q", test.expectedErrorMsg, pageText)
					}
				}
			}
		})
	}
}

func TestConsoleDeleteUser(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description      string
		userToDelete     string
		expectRedirect   bool
		expectedStatus   int
		expectedErrorMsg string
	}{
		{
			description:      "self-delete is prevented",
			userToDelete:     "00000006-0000-0000-0000-000000000001",
			expectedErrorMsg: consoleNotAllowedDeleteSelf,
		},
		{
			description:      "delete non-existent user shows error",
			userToDelete:     "00000000-0000-0000-0000-000000000000",
			expectedErrorMsg: consoleUserNotFound,
		},
		{
			description:    "successful user deletion",
			userToDelete:   "00000006-0000-0000-0000-000000000006",
			expectRedirect: true,
		},
		{
			description:    "invalid UUID returns 400",
			userToDelete:   "not-a-uuid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

			client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}

			req, err := http.NewRequest(http.MethodDelete, ts.URL+"/console/superuser/users/"+test.userToDelete, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Sec-Fetch-Site", "same-origin")

			resp, err := client.Do(req) // #nosec G704
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if test.expectedStatus == http.StatusBadRequest {
				if resp.StatusCode != http.StatusBadRequest {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("expected 400, got %d (%s)", resp.StatusCode, string(body))
				}
				return
			}

			if test.expectRedirect {
				if resp.StatusCode != http.StatusSeeOther {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("expected redirect (303), got %d (%s)", resp.StatusCode, string(body))
				}
			} else {
				if resp.StatusCode != http.StatusOK {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("unexpected status code: %d (%s)", resp.StatusCode, string(body))
				}

				if test.expectedErrorMsg != "" {
					doc, err := goquery.NewDocumentFromReader(resp.Body)
					if err != nil {
						t.Fatalf("failed to parse response HTML: %v", err)
					}
					errorText := strings.TrimSpace(doc.Find("span.error-text").Text())
					if !strings.Contains(errorText, test.expectedErrorMsg) {
						t.Fatalf("expected error text to contain %q, got %q", test.expectedErrorMsg, errorText)
					}
				}
			}
		})
	}
}

func TestConsoleResetPassword(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	tests := []struct {
		description      string
		userToReset      string
		formData         url.Values
		expectRedirect   bool
		expectedErrorMsg string
	}{
		{
			description: "successful password reset for local user",
			userToReset: "00000006-0000-0000-0000-000000000002",
			formData: url.Values{
				"password":         {"newpassword12345"},
				"confirm-password": {"newpassword12345"},
			},
			expectRedirect: true,
		},
		{
			description: "password mismatch on reset",
			userToReset: "00000006-0000-0000-0000-000000000002",
			formData: url.Values{
				"password":         {"newpassword12345"},
				"confirm-password": {"differentpass1234"},
			},
			expectedErrorMsg: consolePasswordMismatch,
		},
		{
			description: "password too short on reset",
			userToReset: "00000006-0000-0000-0000-000000000002",
			formData: url.Values{
				"password":         {"short"},
				"confirm-password": {"short"},
			},
			expectedErrorMsg: consolePasswordTooShort,
		},
		{
			description: "reset password for non-existent user",
			userToReset: "00000000-0000-0000-0000-000000000000",
			formData: url.Values{
				"password":         {"newpassword12345"},
				"confirm-password": {"newpassword12345"},
			},
			expectedErrorMsg: consoleUserNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

			client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}

			req, err := http.NewRequest(http.MethodPost, ts.URL+"/console/superuser/users/"+test.userToReset+"/reset-password", strings.NewReader(test.formData.Encode()))
			if err != nil {
				t.Fatal(err)
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Sec-Fetch-Site", "same-origin")

			resp, err := client.Do(req) // #nosec G704
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if test.expectRedirect {
				if resp.StatusCode != http.StatusSeeOther {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("expected redirect (303), got %d (%s)", resp.StatusCode, string(body))
				}
			} else {
				if resp.StatusCode != http.StatusOK {
					body, readErr := io.ReadAll(resp.Body)
					if readErr != nil {
						t.Fatal(readErr)
					}
					t.Fatalf("unexpected status code: got %d (%s)", resp.StatusCode, string(body))
				}

				if test.expectedErrorMsg != "" {
					doc, err := goquery.NewDocumentFromReader(resp.Body)
					if err != nil {
						t.Fatalf("failed to parse response HTML: %v", err)
					}
					errorText := strings.TrimSpace(doc.Find("span.error-text").Text())
					if !strings.Contains(errorText, test.expectedErrorMsg) {
						t.Fatalf("expected error text to contain %q, got %q", test.expectedErrorMsg, errorText)
					}
				}
			}
		})
	}
}

func TestNameNotUUIDConstraint(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Caller().Logger()

	dbPool, err := initDatabase(ctx, t, logger, false)
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}

	// UUIDs that start with a letter (a-f) pass the is_valid_dns_label()
	// regex but should be rejected by is_valid_name() which also checks
	// is_not_uuid(). This tests the database constraint directly for
	// entities that have no API POST endpoint.
	tests := []struct {
		description string
		query       string
		uuid        string
	}{
		{
			description: "roles rejects hyphenated UUID name",
			query:       "INSERT INTO roles (name) VALUES ($1)",
			uuid:        "abcdef01-2345-6789-abcd-ef0123456789",
		},
		{
			description: "auth_providers rejects hyphenated UUID name",
			query:       "INSERT INTO auth_providers (name) VALUES ($1)",
			uuid:        "abcdef01-2345-6789-abcd-ef0123456789",
		},
		{
			description: "roles rejects non-hyphenated UUID name",
			query:       "INSERT INTO roles (name) VALUES ($1)",
			uuid:        "abcdef012345678901234567890abcde",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			_, err := dbPool.Exec(context.Background(), test.query, test.uuid)
			if err == nil {
				t.Fatal("expected INSERT to fail with check constraint violation, but it succeeded")
			}

			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("expected pgconn.PgError, got: %v", err)
			}

			if pgErr.Code != pgCheckViolation {
				t.Fatalf("expected check_violation (23514), got: %s", pgErr.Code)
			}

			if pgErr.ConstraintName != pgConstraintValidName {
				t.Fatalf("expected constraint %s, got: %s", pgConstraintValidName, pgErr.ConstraintName)
			}
		})
	}
}

func TestValidateVCLMacros(t *testing.T) {
	tests := []struct {
		description string
		template    string
		expectErr   bool
		errContains string
	}{
		{
			description: "valid default template",
			template:    cdntypes.DefaultVCLTemplate,
			expectErr:   false,
		},
		{
			description: "missing preamble macro",
			template: `sub vcl_recv {
  #SUNET-CDN-MANAGER vcl_recv
}

sub vcl_pipe {
  #SUNET-CDN-MANAGER vcl_pipe
}

sub vcl_pass {
  #SUNET-CDN-MANAGER vcl_pass
}

sub vcl_hash {
  #SUNET-CDN-MANAGER vcl_hash
}

sub vcl_purge {
  #SUNET-CDN-MANAGER vcl_purge
}

sub vcl_miss {
  #SUNET-CDN-MANAGER vcl_miss
}

sub vcl_hit {
  #SUNET-CDN-MANAGER vcl_hit
}

sub vcl_deliver {
  #SUNET-CDN-MANAGER vcl_deliver
}

sub vcl_synth {
  #SUNET-CDN-MANAGER vcl_synth
}

sub vcl_backend_fetch {
  #SUNET-CDN-MANAGER vcl_backend_fetch
}

sub vcl_backend_response {
  #SUNET-CDN-MANAGER vcl_backend_response
}

sub vcl_backend_error {
  #SUNET-CDN-MANAGER vcl_backend_error
}
`,
			expectErr:   true,
			errContains: "missing required macro: #SUNET-CDN-MANAGER preamble",
		},
		{
			description: "missing vcl_recv macro",
			template: `#SUNET-CDN-MANAGER preamble

sub vcl_pipe {
  #SUNET-CDN-MANAGER vcl_pipe
}

sub vcl_pass {
  #SUNET-CDN-MANAGER vcl_pass
}

sub vcl_hash {
  #SUNET-CDN-MANAGER vcl_hash
}

sub vcl_purge {
  #SUNET-CDN-MANAGER vcl_purge
}

sub vcl_miss {
  #SUNET-CDN-MANAGER vcl_miss
}

sub vcl_hit {
  #SUNET-CDN-MANAGER vcl_hit
}

sub vcl_deliver {
  #SUNET-CDN-MANAGER vcl_deliver
}

sub vcl_synth {
  #SUNET-CDN-MANAGER vcl_synth
}

sub vcl_backend_fetch {
  #SUNET-CDN-MANAGER vcl_backend_fetch
}

sub vcl_backend_response {
  #SUNET-CDN-MANAGER vcl_backend_response
}

sub vcl_backend_error {
  #SUNET-CDN-MANAGER vcl_backend_error
}
`,
			expectErr:   true,
			errContains: "missing required macro: #SUNET-CDN-MANAGER vcl_recv",
		},
		{
			description: "duplicate vcl_recv macro",
			template: `#SUNET-CDN-MANAGER preamble

sub vcl_recv {
  #SUNET-CDN-MANAGER vcl_recv
  #SUNET-CDN-MANAGER vcl_recv
}

sub vcl_pipe {
  #SUNET-CDN-MANAGER vcl_pipe
}

sub vcl_pass {
  #SUNET-CDN-MANAGER vcl_pass
}

sub vcl_hash {
  #SUNET-CDN-MANAGER vcl_hash
}

sub vcl_purge {
  #SUNET-CDN-MANAGER vcl_purge
}

sub vcl_miss {
  #SUNET-CDN-MANAGER vcl_miss
}

sub vcl_hit {
  #SUNET-CDN-MANAGER vcl_hit
}

sub vcl_deliver {
  #SUNET-CDN-MANAGER vcl_deliver
}

sub vcl_synth {
  #SUNET-CDN-MANAGER vcl_synth
}

sub vcl_backend_fetch {
  #SUNET-CDN-MANAGER vcl_backend_fetch
}

sub vcl_backend_response {
  #SUNET-CDN-MANAGER vcl_backend_response
}

sub vcl_backend_error {
  #SUNET-CDN-MANAGER vcl_backend_error
}
`,
			expectErr:   true,
			errContains: "duplicate macro: #SUNET-CDN-MANAGER vcl_recv",
		},
		{
			description: "unknown macro",
			template:    cdntypes.DefaultVCLTemplate + "\n#SUNET-CDN-MANAGER vcl_unknown\n",
			expectErr:   true,
			errContains: "unknown macro: #SUNET-CDN-MANAGER vcl_unknown",
		},
		{
			description: "empty template",
			template:    "",
			expectErr:   true,
			errContains: "VCL template must not be empty",
		},
		{
			description: "valid template with user code around macros",
			template: `#SUNET-CDN-MANAGER preamble

sub vcl_recv {
  #SUNET-CDN-MANAGER vcl_recv
  if (req.url ~ "^/admin") {
    return(pass);
  }
}

sub vcl_pipe {
  #SUNET-CDN-MANAGER vcl_pipe
}

sub vcl_pass {
  #SUNET-CDN-MANAGER vcl_pass
}

sub vcl_hash {
  #SUNET-CDN-MANAGER vcl_hash
}

sub vcl_purge {
  #SUNET-CDN-MANAGER vcl_purge
}

sub vcl_miss {
  #SUNET-CDN-MANAGER vcl_miss
}

sub vcl_hit {
  #SUNET-CDN-MANAGER vcl_hit
}

sub vcl_deliver {
  #SUNET-CDN-MANAGER vcl_deliver
}

sub vcl_synth {
  #SUNET-CDN-MANAGER vcl_synth
}

sub vcl_backend_fetch {
  #SUNET-CDN-MANAGER vcl_backend_fetch
}

sub vcl_backend_response {
  #SUNET-CDN-MANAGER vcl_backend_response
}

sub vcl_backend_error {
  #SUNET-CDN-MANAGER vcl_backend_error
}
`,
			expectErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			err := validateVCLMacros(test.template)
			if test.expectErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if test.errContains != "" && !strings.Contains(err.Error(), test.errContains) {
					t.Fatalf("expected error containing %q, got: %s", test.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
			}
		})
	}
}

func TestConsoleIPNetworks(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	client, _ := consoleLogin(t, ts.URL, "admin", validAdminPassword)

	t.Run("list page renders", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/console/superuser/ip-networks", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("failed to parse HTML: %v", err)
		}

		type networkRow struct {
			network   string
			family    string
			allocated string
			disabled  bool
		}

		rows := []networkRow{}
		doc.Find("table tbody tr").Each(func(_ int, s *goquery.Selection) {
			tds := s.Find("td")
			row := networkRow{
				network:   strings.TrimSpace(tds.Eq(0).Text()),
				family:    strings.TrimSpace(tds.Eq(1).Text()),
				allocated: strings.TrimSpace(tds.Eq(2).Text()),
			}
			_, row.disabled = tds.Eq(3).Find("button").Attr("disabled")
			rows = append(rows, row)
		})

		// Verify seeded networks appear with correct data
		found := map[string]networkRow{}
		for _, r := range rows {
			found[r.network] = r
		}

		if r, ok := found["192.0.2.0/24"]; !ok {
			t.Fatal("expected 192.0.2.0/24 in list page")
		} else {
			if r.family != "IPv4" {
				t.Fatalf("expected IPv4 family, got %s", r.family)
			}
			if r.allocated != "2" {
				t.Fatalf("expected 2 allocations for 192.0.2.0/24, got %s", r.allocated)
			}
			if !r.disabled {
				t.Fatal("expected delete button to be disabled for 192.0.2.0/24 (has allocations)")
			}
		}

		if r, ok := found["198.51.100.0/24"]; !ok {
			t.Fatal("expected 198.51.100.0/24 in list page")
		} else {
			if r.allocated != "0" {
				t.Fatalf("expected 0 allocations for 198.51.100.0/24, got %s", r.allocated)
			}
			if r.disabled {
				t.Fatal("expected delete button to be enabled for 198.51.100.0/24 (no allocations)")
			}
		}
	})

	t.Run("create page renders", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/console/superuser/create/ip-network", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}
	})

	t.Run("create network via form", func(t *testing.T) {
		form := url.Values{"network": {"10.20.0.0/24"}}
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/console/superuser/create/ip-network", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(body), "10.20.0.0/24") {
			t.Fatal("expected newly created network in redirect page")
		}
	})

	t.Run("create duplicate network shows error", func(t *testing.T) {
		form := url.Values{"network": {"10.20.0.0/24"}}
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/console/superuser/create/ip-network", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(body), consoleAlreadyExists) {
			t.Fatal("expected 'already exists' error message")
		}
	})

	t.Run("create overlapping network shows error", func(t *testing.T) {
		form := url.Values{"network": {"10.20.0.0/25"}}
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/console/superuser/create/ip-network", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(body), "overlaps with an existing network") {
			t.Fatal("expected 'overlaps' error message")
		}
	})

	t.Run("create invalid prefix shows error", func(t *testing.T) {
		form := url.Values{"network": {"not-a-prefix"}}
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/console/superuser/create/ip-network", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(body), "not a valid network prefix") {
			t.Fatal("expected validation error message")
		}
	})

	t.Run("delete network with allocated IPs shows error", func(t *testing.T) {
		// 192.0.2.0/24 has allocated IPs, use its UUID
		req, err := http.NewRequest(http.MethodDelete, ts.URL+"/console/superuser/ip-networks/00000011-0000-0000-0000-000000000001", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(body), "Cannot delete IP network") {
			t.Fatal("expected FK violation error message in page")
		}
	})

	t.Run("delete unused network succeeds", func(t *testing.T) {
		// Use a seeded network with no allocated IPs: 3fff::/20 (ID 00000012-0000-0000-0000-000000000002)
		req, err := http.NewRequest(http.MethodDelete, ts.URL+"/console/superuser/ip-networks/00000012-0000-0000-0000-000000000002", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		if !strings.Contains(string(body), "deleted!") {
			t.Fatal("expected flash message confirming deletion")
		}
	})
}

func TestConsoleCookieExpiration(t *testing.T) {
	tests := []struct {
		description          string
		username             string
		password             string
		expectedStatus       int
		consoleSessionMaxAge time.Duration
		consoleSessionCapAge time.Duration
		sleepDuration        time.Duration
		expectedLocation     string
	}{
		{
			description:          "re-auth on expired activity window",
			username:             "admin",
			password:             validAdminPassword,
			expectedStatus:       http.StatusFound,
			consoleSessionMaxAge: 1 * time.Second,
			consoleSessionCapAge: 1 * time.Hour,
			sleepDuration:        2 * time.Second,
			expectedLocation:     cdntypes.AuthLoginPath,
		},
		{
			description:          "re-auth on expired cap window",
			username:             "admin",
			password:             validAdminPassword,
			expectedStatus:       http.StatusFound,
			consoleSessionMaxAge: 1 * time.Hour,
			consoleSessionCapAge: 1 * time.Second,
			sleepDuration:        2 * time.Second,
			expectedLocation:     cdntypes.AuthLoginPath,
		},
		{
			description:          "valid cookie got MaxAge renewed",
			username:             "admin",
			password:             validAdminPassword,
			expectedStatus:       http.StatusOK,
			consoleSessionMaxAge: 1 * time.Hour,
			consoleSessionCapAge: 8 * time.Hour,
			sleepDuration:        2 * time.Second,
			expectedLocation:     "",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			ts, dbPool, err := prepareServer(t, testServerInput{consoleSessionMaxAge: test.consoleSessionMaxAge, consoleSessionCapAge: test.consoleSessionCapAge})
			if dbPool != nil {
				defer dbPool.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			defer ts.Close()

			// Initial login
			_, sessionCookie := consoleLogin(t, ts.URL, test.username, test.password)

			time.Sleep(test.sleepDuration)

			// New client that does not use a cookie jar that will
			// leave out expired cookies, we add the cookie
			// manually to test server behavior
			client := &http.Client{
				// Do not automatically follow redirects so we
				// can test the different cookie state outcomes
				// based on initial server response.
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}

			req, err := http.NewRequest(http.MethodGet, ts.URL+"/console", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(&http.Cookie{
				Name:     cookieName,
				Value:    sessionCookie.Value,
				Secure:   true,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})

			resp, err := client.Do(req) // #nosec G704
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if test.expectedLocation != "" {
				if resp.Header.Get("Location") != test.expectedLocation {
					t.Fatalf("unexpected Location header: have: '%s', want: '%s'", resp.Header.Get("Location"), test.expectedLocation)
				}
			}

			if resp.StatusCode != test.expectedStatus {
				t.Fatalf("unexpected status code: %d", resp.StatusCode)
			}

			// If the response was OK we want to verify the expires
			// duration has been increased by sliding
			if resp.StatusCode == http.StatusOK {
				if sessionCookie.Expires.IsZero() {
					t.Fatal("initial session cookie expires field is zero")
				}

				var sessionCookieNext *http.Cookie
				for _, c := range resp.Cookies() {
					if c.Name == cookieName {
						sessionCookieNext = c
					}
				}

				if sessionCookieNext.Expires.IsZero() {
					t.Fatal("next session cookie expires field is zero")
				}

				if !sessionCookieNext.Expires.After(sessionCookie.Expires) {
					t.Fatal("next session cookie expires field is not after initial session cookie")
				}
			}
		})
	}
}

func TestValidateRelativeRedirect(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantAccept  bool
		wantErrText string // substring of the error message; ignored if wantAccept is true
	}{
		{name: "console root", input: "/console", wantAccept: true},
		{name: "nested console path", input: "/console/org/foo/services?x=y#z", wantAccept: true},
		{name: "auth login", input: cdntypes.AuthLoginPath, wantAccept: true},
		{name: "bare root", input: "/", wantAccept: true},

		{name: "empty", input: "", wantErrText: "empty"},
		{name: "no leading slash", input: "console", wantErrText: "must start with"},
		{name: "protocol-relative", input: "//evil.example/foo", wantErrText: "host not allowed"},
		{name: "absolute https", input: "https://evil.example/foo", wantErrText: "must start with"},
		{name: "javascript scheme", input: "javascript:alert(1)", wantErrText: "must start with"},
		{name: "scheme-only opaque", input: "http:foo", wantErrText: "must start with"},
		{name: "encoded slash decodes to leading double slash", input: "/%2fevil.example/foo", wantErrText: "decoded path starts"},

		// Backslash in the decoded path: browsers may normalize \ to /,
		// turning "/\evil/foo" into "//evil/foo" (cross-origin). Check
		// catches both raw and percent-encoded forms via u.Path inspection.
		{name: "raw backslash in path", input: "/\\evil.example/foo", wantErrText: "decoded path contains backslash"},
		{name: "encoded backslash lowercase", input: "/%5cevil.example/foo", wantErrText: "decoded path contains backslash"},
		{name: "encoded backslash uppercase", input: "/%5Cevil.example/foo", wantErrText: "decoded path contains backslash"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRelativeRedirect(tc.input)
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("validateRelativeRedirect(%q) err = %v, want nil", tc.input, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateRelativeRedirect(%q) err = nil, want error containing %q", tc.input, tc.wantErrText)
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("validateRelativeRedirect(%q) err = %q, want substring %q", tc.input, err.Error(), tc.wantErrText)
			}
		})
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantRedacted bool
	}{
		{
			name:         "callback url that should have params redacted",
			input:        "/auth" + keycloakCallbackPath + "?code=some-opaque-code&iss=https%3A%2F%2Fkeycloak.sunet-cdn.localhost%3A8443%2Frealms%2Fsunet-cdn-manager&session_state=some-opaque-session-state&state=some-opaque-state",
			wantRedacted: true,
		},
		{
			name:         "unrelated url that should not have params redacted",
			input:        "/unrelated/callback?code=some-opaque-code&iss=https%3A%2F%2Fkeycloak.sunet-cdn.localhost%3A8443%2Frealms%2Fsunet-cdn-manager&session_state=some-opaque-session-state&state=some-opaque-state",
			wantRedacted: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.input)
			if err != nil {
				t.Fatalf("unable to parse input url: %v", err)
			}

			output := sanitizeURL(u)
			if tc.wantRedacted {
				for k, vals := range output.Query() {
					if _, ok := sensitiveQueryParams[k]; ok {
						for _, v := range vals {
							if v != "REDACTED" {
								t.Fatalf("found un-redacted query param in '%s': %s", k, v)
							}
						}
					} else {
						for _, v := range vals {
							if v == "REDACTED" {
								t.Fatalf("found redacted query param in '%s' that is not part of sensitiveQueryParams: %s", k, v)
							}
						}
					}
				}
			} else {
				for k, vals := range output.Query() {
					for _, v := range vals {
						if v == "REDACTED" {
							t.Fatalf("found redacted query param in unrelated URL '%s': %s", k, v)
						}
					}
				}
			}
		})
	}
}
