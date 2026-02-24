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
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path"
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
	"github.com/coreos/go-oidc/v3/oidc"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rs/zerolog"
	"github.com/stapelberg/postgrestest"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

var pgt *postgrestest.Server

func Ptr[T any](v T) *T {
	return &v
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	var err error
	pgt, err = postgrestest.Start(ctx, postgrestest.WithSQLDriver("pgx"))
	if err != nil {
		panic(err)
	}
	defer pgt.Cleanup()

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

		// Service origin groups
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000001', id, true, 'default' FROM services WHERE name='org1-service1'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000002', id, true, 'default' FROM services WHERE name='org1-service2'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000003', id, true, 'default' FROM services WHERE name='org1-service3'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000004', id, true, 'default' FROM services WHERE name='org1-service4'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000005', id, true, 'default' FROM services WHERE name='org1-service5'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000006', id, true, 'default' FROM services WHERE name='org1-service6'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000007', id, true, 'default' FROM services WHERE name='org2-service1'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000008', id, true, 'default' FROM services WHERE name='org2-service2'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000009', id, true, 'default' FROM services WHERE name='org2-service3'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000010', id, true, 'default' FROM services WHERE name='org3-service1'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000011', id, true, 'default' FROM services WHERE name='org3-service2'",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) SELECT '00000020-0000-0000-0000-000000000012', id, true, 'default' FROM services WHERE name='org3-service3'",

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
		// org1-service1-version3
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000001', '00000004-0000-0000-0000-000000000003', '00000020-0000-0000-0000-000000000001', '198.51.100.10', 80, false)",
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000002', '00000004-0000-0000-0000-000000000003', '00000020-0000-0000-0000-000000000001', '198.51.100.11', 443, true)",
		// org1-service1-version2
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000003', '00000004-0000-0000-0000-000000000002', '00000020-0000-0000-0000-000000000001', '198.51.100.10', 80, false)",
		// org1-service1-version1
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000004', '00000004-0000-0000-0000-000000000001', '00000020-0000-0000-0000-000000000001', '198.51.100.10', 80, false)",

		// org2-service1-version2
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port, tls) VALUES ('00000009-0000-0000-0000-000000000005', '00000004-0000-0000-0000-000000000005', '00000020-0000-0000-0000-000000000008', '198.51.100.20', 80, false)",

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
				err := tx.QueryRow(ctx, "SELECT id FROM orgs WHERE name=$1", localUser.orgName).Scan(&orgID)
				if err != nil {
					return err
				}
			}

			err = tx.QueryRow(ctx, "SELECT id FROM auth_providers WHERE name=$1", localUser.authProvider).Scan(&authProviderID)
			if err != nil {
				return err
			}

			_, err = tx.Exec(ctx, "INSERT INTO users (id, org_id, name, role_id, auth_provider_id) VALUES ($1, $2, $3, (SELECT id FROM roles WHERE name=$4), (SELECT id from auth_providers WHERE name=$5))", userID, orgID, localUser.name, localUser.role, localUser.authProvider)
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

			_, err = tx.Exec(ctx, "INSERT INTO service_vcls (id, service_version_id, vcl_recv) VALUES($1, $2, $3)", vclID, serviceVersionID, vclRecvContentBytes)
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
	encryptedSessionKey bool
	vclValidator        *vclValidatorClient
	kcClientManager     *keycloakClientManager
	jwkCache            *jwk.Cache
	jwtIssuer           string
	oiConf              openidConfig
	encryptionPasswords []string
	dbPool              *pgxpool.Pool
}

func initDatabase(ctx context.Context, t *testing.T, logger zerolog.Logger, encryptedSessionKey bool) (*pgxpool.Pool, error) {
	pgurl, err := pgt.CreateDatabase(ctx)
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

	err = migrations.Up(logger, pgConfig)
	if err != nil {
		dbPool.Close()
		return nil, err
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

	cookieStore, err := getSessionStore(ctx, logger, tsi.dbPool)
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		return nil, nil, err
	}

	confTemplates := configTemplates{}

	confTemplates.vcl, err = template.ParseFS(templateFS, "templates/sunet-cdn.vcl")
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		t.Fatalf("unable to create varnish template: %v", err)
	}

	confTemplates.haproxy, err = template.ParseFS(templateFS, "templates/haproxy.cfg")
	if err != nil {
		if dbPoolCreated {
			tsi.dbPool.Close()
		}
		t.Fatalf("unable to create haproxy template: %v", err)
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

	router := newChiRouter(config.Config{}, logger, dbc, &argon2Mutex, loginCache, cookieStore, nil, tsi.vclValidator, confTemplates, false, clientCredAEADs, tsi.kcClientManager, &url.URL{}, serverURL)

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
	pgurl, err := pgt.CreateDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(pgConfig.ConnString())

	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Caller().Logger()

	initPassword := "test-server-init"

	u, err := Init(logger, pgConfig, false, initPassword)
	if err != nil {
		t.Fatal(err)
	}

	expectedUsername := "admin"
	expectedPasswordLength := len(initPassword)

	if u.Name != expectedUsername {
		t.Fatalf("expected initial user '%s', got: '%s'", expectedUsername, u.Name)
	}

	if len(u.Password) != expectedPasswordLength {
		t.Fatalf("expected initial user password length %d, got: %d", expectedPasswordLength, len(u.Password))
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
	for i := 0; i < numAdded; i++ {
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
	for i := 0; i < numAdded; i++ {
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Log(string(b))

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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
			ctx := context.Background()
			// Verify uses exists prior to deletion
			var testQuery string
			if isUUID(test.targetUserIDorName) {
				testQuery = "SELECT name, id FROM users WHERE id = $1"
			} else {
				testQuery = "SELECT name, id FROM users WHERE name = $1"
			}

			var name string
			var id pgtype.UUID
			err := dbPool.QueryRow(ctx, testQuery, test.targetUserIDorName).Scan(&name, &id)
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

			t.Logf("%s\n", jsonData)

			// Verify user is removed if a http.StatusNoContent was returned, otherwise they are expected to still exist
			err = dbPool.QueryRow(ctx, testQuery, test.targetUserIDorName).Scan(&name, &id)
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
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)

			// Verify old password no longer works
			statusCode, err := testAuth(t, ts, test.modifiedUserIDorName, test.oldPassword)
			if err == nil {
				t.Fatal(errors.New("old password still works, unexpected"))
			}
			if statusCode != http.StatusUnauthorized {
				t.Fatal(fmt.Errorf("unexected status code: %d", statusCode))
			}

			// Verify new password works
			statusCode, err = testAuth(t, ts, test.modifiedUserIDorName, test.newPassword)
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
		}()
	}
}

func testAuth(t *testing.T, ts *httptest.Server, username string, password string) (int, error) {
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
			req, err := http.NewRequest("GET", ts.URL+"/api/v1/orgs/"+test.nameOrID+"/client-credentials", nil)
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

			t.Logf("%s\n", jsonData)
		}()
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

	createResp, err := adminClient.Post(u.String(), "application/json", bodyReader)
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
		req.Header.Add("Content-Type", "application/json")
	}

	if queryParams != nil {
		req.URL.RawQuery = queryParams.Encode()
	}

	resp, err := client.Do(req)
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

	jwkCtx, jwkCancel := context.WithCancel(t.Context())

	jwkCache, err := setupJwkCache(jwkCtx, logger, client, oiConf)
	if err != nil {
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
			password:             "adminpass1",
			expectedPostStatus:   http.StatusCreated,
			expectedDeleteStatus: http.StatusNoContent,
			credName:             "post-cred-1",
			credDescription:      "a description 1",
			orgNameOrID:          "org1",
		},
	}

	for _, test := range tests {
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

		postReq, err := http.NewRequest("POST", ts.URL+"/api/v1/orgs/"+test.orgNameOrID+"/client-credentials", r)
		if err != nil {
			t.Fatal(err)
		}

		postReq.SetBasicAuth(test.username, test.password)

		postResp, err := http.DefaultClient.Do(postReq)
		if err != nil {
			t.Fatal(err)
		}
		defer postResp.Body.Close()

		if postResp.StatusCode != test.expectedPostStatus {
			r, err := io.ReadAll(postResp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s: POST org client credentials unexpected status code: %d (%s)", test.description, postResp.StatusCode, string(r))
		}

		postJSONData, err := io.ReadAll(postResp.Body)
		if err != nil {
			t.Fatalf("%s: %s", test.description, err)
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
				func() {
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

					clientCredResp, err := client.Do(clientCredGetReq)
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
						t.Fatalf("%s: client cred got unexpected status code when looking up own org, want: %d, have: %d", clientCredTest.description, clientCredTest.expectedStatus, clientCredResp.StatusCode)
					}
				}()
			}

		}

		// Attempt re-encryption prior to DELETE
		reEncryptReq, err := http.NewRequest("POST", ts.URL+"/api/v1/re-encrypt-org-client-registration-tokens", nil)
		if err != nil {
			t.Fatal(err)
		}

		reEncryptReq.SetBasicAuth(test.username, test.password)

		reEncryptResp, err := http.DefaultClient.Do(reEncryptReq)
		if err != nil {
			t.Fatal(err)
		}
		defer reEncryptResp.Body.Close()

		if reEncryptResp.StatusCode != http.StatusOK {
			r, err := io.ReadAll(reEncryptResp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s: POST org client credentials re-encryption unexpected status code: %d (%s)", test.description, reEncryptResp.StatusCode, string(r))
		}

		reEncryptBody, err := io.ReadAll(reEncryptResp.Body)
		if err != nil {
			t.Fatalf("%s: POST org client credentials re-encryption failed to parse body: %s", test.description, err)
		}

		var reEncryptResult cdntypes.OrgClientRegistrationTokenReEncryptResult

		if err := json.Unmarshal(reEncryptBody, &reEncryptResult); err != nil {
			t.Fatalf("%s: failed to decode re-encryption response JSON: %v (body: %s)", test.description, err, string(reEncryptBody))
		}

		// Since the token was created above (so using the last password in the list) we expect to skip it
		if reEncryptResult.TotalTokens != 1 || reEncryptResult.UpdatedTokens != 0 || reEncryptResult.SkippedTokens != 1 || reEncryptResult.FailedTokens != 0 {
			t.Fatalf("%s: invalid re-encryption counts: TotalTokens=%d, UpdatedTokens=%d, SkippedTokens=%d, FailedTokens=%d", test.description, reEncryptResult.TotalTokens, reEncryptResult.UpdatedTokens, reEncryptResult.SkippedTokens, reEncryptResult.FailedTokens)
		}

		deleteReq, err := http.NewRequest("DELETE", ts.URL+"/api/v1/orgs/"+test.orgNameOrID+"/client-credentials/"+test.credName, nil)
		if err != nil {
			t.Fatal(err)
		}

		deleteReq.SetBasicAuth(test.username, test.password)

		deleteResp, err := http.DefaultClient.Do(deleteReq)
		if err != nil {
			t.Fatal(err)
		}
		defer deleteResp.Body.Close()

		if deleteResp.StatusCode != test.expectedDeleteStatus {
			r, err := io.ReadAll(deleteResp.Body)
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("%s: DELETE org client credentials unexpected status code: %d (%s)", test.description, deleteResp.StatusCode, string(r))
		}

		deleteJSONData, err := io.ReadAll(deleteResp.Body)
		if err != nil {
			t.Fatalf("%s: %s", test.description, err)
		}

		t.Logf("%s\n", deleteJSONData)
	}
}

func createCred(t *testing.T, testDesc string, ts *httptest.Server, username, password, org string, name string, desc string) cdntypes.NewOrgClientCredential {
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

	postReq, err := http.NewRequest("POST", ts.URL+"/api/v1/orgs/"+org+"/client-credentials", r)
	if err != nil {
		t.Fatal(err)
	}

	postReq.SetBasicAuth(username, password)

	postResp, err := http.DefaultClient.Do(postReq)
	if err != nil {
		t.Fatal(err)
	}
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusCreated {
		r, err := io.ReadAll(postResp.Body)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("%s: POST org client credentials unexpected status code: %d (%s)", testDesc, postResp.StatusCode, string(r))
	}

	postJSONData, err := io.ReadAll(postResp.Body)
	if err != nil {
		t.Fatalf("%s: %s", testDesc, err)
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
			password:             "adminpass1",
			expectedDeleteStatus: http.StatusNoContent,
			orgNameOrID:          "org1",
			server1Passwords:     []string{"test-encryption-password-1"},
			server2Passwords:     []string{"test-encryption-password-1", "test-encryption-password-2"},
			server3Passwords:     []string{"test-encryption-password-2"},
		},
	}

	for _, test := range tests {

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
			cred1 = createCred(t, test.description, ts1, test.username, test.password, test.orgNameOrID, "re-encrypt-cred-1", "re-encrypt desc 1")
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
			cred2 = createCred(t, test.description, ts2, test.username, test.password, test.orgNameOrID, "re-encrypt-cred-2", "re-encrypt desc 2")
			createdCredNames = append(createdCredNames, cred2.Name)

			err = dbPool.QueryRow(ctx, "SELECT crypt_registration_access_token FROM org_keycloak_client_credentials WHERE id = $1", cred2.ID).Scan(&cred2CiphertextOrig)
			if err != nil {
				t.Fatal(err)
			}

			// Attempt re-encryption
			reEncryptReq, err := http.NewRequest("POST", ts2.URL+"/api/v1/re-encrypt-org-client-registration-tokens", nil)
			if err != nil {
				t.Fatal(err)
			}

			reEncryptReq.SetBasicAuth(test.username, test.password)

			reEncryptResp, err := http.DefaultClient.Do(reEncryptReq)
			if err != nil {
				t.Fatal(err)
			}
			defer reEncryptResp.Body.Close()

			if reEncryptResp.StatusCode != http.StatusOK {
				r, err := io.ReadAll(reEncryptResp.Body)
				if err != nil {
					t.Fatal(err)
				}
				t.Fatalf("%s: POST org client credentials re-encryption unexpected status code: %d (%s)", test.description, reEncryptResp.StatusCode, string(r))
			}

			reEncryptBody, err := io.ReadAll(reEncryptResp.Body)
			if err != nil {
				t.Fatalf("%s: POST org client credentials re-encryption failed to parse body: %s", test.description, err)
			}

			var reEncryptResult cdntypes.OrgClientRegistrationTokenReEncryptResult

			if err := json.Unmarshal(reEncryptBody, &reEncryptResult); err != nil {
				t.Fatalf("%s: failed to decode re-encryption response JSON: %v (body: %s)", test.description, err, string(reEncryptBody))
			}

			// Since the first token was created by ts1 and the second by ts2 we expect to update one and skip one
			if reEncryptResult.TotalTokens != 2 || reEncryptResult.UpdatedTokens != 1 || reEncryptResult.SkippedTokens != 1 || reEncryptResult.FailedTokens != 0 {
				t.Fatalf("%s: invalid re-encryption counts: TotalTokens=%d, UpdatedTokens=%d, SkippedTokens=%d, FailedTokens=%d", test.description, reEncryptResult.TotalTokens, reEncryptResult.UpdatedTokens, reEncryptResult.SkippedTokens, reEncryptResult.FailedTokens)
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
				deleteReq, err := http.NewRequest("DELETE", ts3.URL+"/api/v1/orgs/"+test.orgNameOrID+"/client-credentials/"+credName, nil)
				if err != nil {
					t.Fatal(err)
				}

				deleteReq.SetBasicAuth(test.username, test.password)

				deleteResp, err := http.DefaultClient.Do(deleteReq)
				if err != nil {
					t.Fatal(err)
				}
				defer deleteResp.Body.Close()

				if deleteResp.StatusCode != test.expectedDeleteStatus {
					r, err := io.ReadAll(deleteResp.Body)
					if err != nil {
						t.Fatal(err)
					}
					t.Fatalf("%s: DELETE org client credentials unexpected status code: %d (%s)", test.description, deleteResp.StatusCode, string(r))
				}

				deleteJSONData, err := io.ReadAll(deleteResp.Body)
				if err != nil {
					t.Fatalf("%s: %s", test.description, err)
				}

				t.Logf("%s\n", deleteJSONData)
			}()
		}
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
			password:       "adminpass1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request for specific org",
			username:       "admin",
			password:       "adminpass1",
			orgNameOrID:    "org2",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request",
			username:       "username1",
			password:       "password1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful org request for same org explicity",
			username:       "username1",
			password:       "password1",
			orgNameOrID:    "org1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "failed org request for other org",
			username:       "username1",
			password:       "password1",
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
		func() {
			req, err := http.NewRequest("GET", ts.URL+"/api/v1/services", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.SetBasicAuth(test.username, test.password)

			if test.orgNameOrID != "" {
				values := req.URL.Query()
				values.Add("org", test.orgNameOrID)
				req.URL.RawQuery = values.Encode()
			}

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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		description     string
		username        string
		password        string
		expectedStatus  int
		newService      string
		orgNameOrID     string
		serviceNameOrID string
		domains         []string
		origins         []cdntypes.InputOrigin
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "198.51.100.20",
					Port:        443,
					TLS:         true,
					VerifyTLS:   true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "198.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "198.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "198.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "198.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "192.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "192.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "192.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        strings.Repeat("a", 254),
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "192.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "192.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "192.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "192.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
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
			origins: []cdntypes.InputOrigin{
				{
					OriginGroup: "default",
					Host:        "192.51.100.20",
					Port:        443,
					TLS:         true,
				},
				{
					OriginGroup: "default",
					Host:        "192.51.100.21",
					Port:        80,
					TLS:         false,
				},
			},
			expectedStatus: http.StatusForbidden,
			active:         true,
			vclRecvFile:    "testdata/vcl/vcl_recv/content1.vcl",
		},
	}

	for _, test := range tests {
		func() {
			newServiceVersion := struct {
				Org     string                 `json:"org"`
				Active  bool                   `json:"active"`
				Domains []string               `json:"domains"`
				Origins []cdntypes.InputOrigin `json:"origins"`
				VclRecv string                 `json:"vcl_recv"`
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

			t.Log(string(b))

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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
	}
}

func TestGetOriginGroups(t *testing.T) {
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
			description:     "failed user request with id but wrong password",
			username:        "username1",
			password:        "password1-wrong",
			expectedStatus:  http.StatusUnauthorized,
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
		func() {
			req, err := http.NewRequest("GET", ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/origin-groups", nil)
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
				t.Fatalf("%s: GET origin groups unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("%s: %s", test.description, err)
			}

			t.Logf("%s\n", jsonData)
		}()
	}
}

func TestPostOriginGroups(t *testing.T) {
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
		orgNameOrID     string
		serviceNameOrID string
		name            string
	}{
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			name:            "origin-group-new1",
			expectedStatus:  http.StatusCreated,
		},
		{
			description:     "successful superuser request with ID",
			username:        "admin",
			password:        "adminpass1",
			orgNameOrID:     "00000002-0000-0000-0000-000000000001",
			serviceNameOrID: "00000003-0000-0000-0000-000000000001",
			name:            "origin-group-new2",
			expectedStatus:  http.StatusCreated,
		},
	}

	for _, test := range tests {
		func() {
			newOriginGroup := struct {
				Name string `json:"name"`
			}{
				Name: test.name,
			}

			b, err := json.Marshal(newOriginGroup)
			if err != nil {
				t.Fatal(err)
			}

			t.Log(string(b))

			r := bytes.NewReader(b)

			req, err := http.NewRequest("POST", ts.URL+"/api/v1/services/"+test.serviceNameOrID+"/origin-groups", r)
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
				t.Fatalf("%s: POST origin group unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("%s: %s", test.description, err)
			}

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
			password:          "adminpass1",
			cacheNodeNameOrID: "00000022-0000-0000-0000-000000000001",
			expectedStatus:    http.StatusOK,
		},
		{
			description:       "successful superuser request with name",
			username:          "admin",
			password:          "adminpass1",
			cacheNodeNameOrID: "cache-node1",
			expectedStatus:    http.StatusOK,
		},
		{
			description:       "successful superuser request with id and node group membership",
			username:          "admin",
			password:          "adminpass1",
			cacheNodeNameOrID: "00000022-0000-0000-0000-000000000003",
			expectedStatus:    http.StatusOK,
		},
		{
			description:       "successful superuser request with name and node group membership",
			username:          "admin",
			password:          "adminpass1",
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
			password:          "password1",
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
		func() {
			req, err := http.NewRequest("GET", ts.URL+"/api/v1/cache-node-configs/"+test.cacheNodeNameOrID, nil)
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

			t.Logf("%s\n", jsonData)
		}()
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
			password:       "adminpass1",
			l4lbNameOrID:   "00000016-0000-0000-0000-000000000001",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request, with id that is member of node group",
			username:       "admin",
			password:       "adminpass1",
			l4lbNameOrID:   "00000016-0000-0000-0000-000000000003",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request, with name",
			username:       "admin",
			password:       "adminpass1",
			l4lbNameOrID:   "l4lb-node1",
			expectedStatus: http.StatusOK,
		},
		{
			description:    "successful superuser request, with name that is member if node group",
			username:       "admin",
			password:       "adminpass1",
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
			password:       "password1",
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
		func() {
			req, err := http.NewRequest("GET", ts.URL+"/api/v1/l4lb-node-configs/"+test.l4lbNameOrID, nil)
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

			t.Logf("%s\n", jsonData)
		}()
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
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			cacheNodeDescr: "cache-node-post-1.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
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
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::2")},
			name:           "cache-node-post-3",
		},
		{
			description:    "failed superuser request with description above limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			cacheNodeDescr: strings.Repeat("a", 101),
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::2")},
			name:           "cache-node-post-4",
		},
		{
			description:    "failed superuser request with description below limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			cacheNodeDescr: "",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("::3")},
			name:           "cache-node-post-5",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
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
	}

	for _, test := range tests {
		func() {
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

			resultData := struct {
				Name string `json:"name"`
			}{}

			if test.expectedStatus == http.StatusCreated {
				err = json.Unmarshal(jsonData, &resultData)
				if err != nil {
					t.Fatalf("%s: POST cache-nodes unable to unmarshal response: (%s)", test.description, err)
				}

				if newCacheNode.Name != resultData.Name {
					t.Fatalf("%s: POST cache-nodes unexpected name in response, want: '%s', have: '%s'", test.description, newCacheNode.Name, resultData.Name)
				}
			}

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
			password:          "adminpass1",
			cacheNodeNameOrID: "00000022-0000-0000-0000-000000000001",
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
		func() {
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

			t.Logf("%s\n", jsonData)
		}()
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
			password:               "adminpass1",
			cacheNodeNameOrID:      "00000022-0000-0000-0000-000000000005",
			cacheNodeGroupNameOrID: "00000021-0000-0000-0000-000000000002",
			expectedStatus:         http.StatusNoContent,
		},
		{
			description:            "failed superuser request with nonexistent group ID",
			username:               "admin",
			password:               "adminpass1",
			cacheNodeNameOrID:      "00000022-0000-0000-0000-000000000005",
			cacheNodeGroupNameOrID: "00000021-0001-0000-0000-000000000002",
			expectedStatus:         http.StatusUnprocessableEntity,
		},
		{
			description:            "successful superuser request with name",
			username:               "admin",
			password:               "adminpass1",
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
			password:               "password1",
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
		func() {
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

			req, err := http.NewRequest("PUT", ts.URL+"/api/v1/cache-nodes/"+test.cacheNodeNameOrID+"/node-group", r)
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
				t.Fatalf("%s: PUT l4lb-nodes group-node unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		}()
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
		func() {
			req, err := http.NewRequest("GET", ts.URL+"/api/v1/l4lb-nodes", nil)
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
				t.Fatalf("%s: GET l4lb-nodes unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		}()
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
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			l4lbNodeDescr:  "l4lb-node-post-1.example.com",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")},
			name:           "l4lb-node-post-1",
		},
		{
			description:    "successful superuser request without addresses",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			l4lbNodeDescr:  "l4lb-node-post-2-no-addrs.example.com",
			name:           "l4lb-node-post-2",
		},
		{
			description:    "successful superuser request with description right at limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusCreated,
			l4lbNodeDescr:  strings.Repeat("a", 100),
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::2")},
			name:           "l4lb-node-post-3",
		},
		{
			description:    "failed superuser request with description above limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			l4lbNodeDescr:  strings.Repeat("a", 101),
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::2")},
			name:           "l4lb-node-post-4",
		},
		{
			description:    "failed superuser request with description below limit",
			username:       "admin",
			password:       "adminpass1",
			expectedStatus: http.StatusUnprocessableEntity,
			l4lbNodeDescr:  "",
			addresses:      []netip.Addr{netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("::3")},
			name:           "l4lb-node-post-5",
		},
		{
			description:    "failed non-superuser request",
			username:       "username1",
			password:       "password1",
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
	}

	for _, test := range tests {
		func() {
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

			req, err := http.NewRequest("POST", ts.URL+"/api/v1/l4lb-nodes", r)
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
				t.Fatalf("%s: POST l4lb-nodes unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
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
					t.Fatalf("%s: POST l4lb-nodes unable to unmarshal response: (%s)", test.description, err)
				}

				if newCacheNode.Name != resultData.Name {
					t.Fatalf("%s: POST l4lb-nodes unexpected name in response, want: '%s', have: '%s'", test.description, newCacheNode.Name, resultData.Name)
				}
			}

			t.Logf("%s\n", jsonData)
		}()
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
			password:         "adminpass1",
			l4lbNodeNameOrID: "00000016-0000-0000-0000-000000000001",
			maintenance:      true,
			expectedStatus:   http.StatusNoContent,
		},
		{
			description:      "successful superuser request with name",
			username:         "admin",
			password:         "adminpass1",
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
			password:         "password1",
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
		func() {
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

			req, err := http.NewRequest("PUT", ts.URL+"/api/v1/l4lb-nodes/"+test.l4lbNodeNameOrID+"/maintenance", r)
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
				t.Fatalf("%s: PUT l4lb-nodes maintenance unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		}()
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
			password:              "adminpass1",
			l4lbNodeNameOrID:      "00000016-0000-0000-0000-000000000005",
			l4lbNodeGroupNameOrID: "00000021-0000-0000-0000-000000000002",
			expectedStatus:        http.StatusNoContent,
		},
		{
			description:           "failed superuser request with nonexistent group ID",
			username:              "admin",
			password:              "adminpass1",
			l4lbNodeNameOrID:      "00000016-0000-0000-0000-000000000005",
			l4lbNodeGroupNameOrID: "00000021-0001-0000-0000-000000000002",
			expectedStatus:        http.StatusUnprocessableEntity,
		},
		{
			description:           "successful superuser request with name",
			username:              "admin",
			password:              "adminpass1",
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
			password:              "password1",
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
		func() {
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

			req, err := http.NewRequest("PUT", ts.URL+"/api/v1/l4lb-nodes/"+test.l4lbNodeNameOrID+"/node-group", r)
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
				t.Fatalf("%s: PUT l4lb-nodes group-node unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("%s\n", jsonData)
		}()
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
			password:       "adminpass1",
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
			password:       "password1",
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
		func() {
			req, err := http.NewRequest("GET", ts.URL+"/api/v1/node-groups", nil)
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
				t.Fatalf("%s: GET node groups unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("%s: %s", test.description, err)
			}

			t.Logf("%s\n", jsonData)
		}()
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
			password:         "adminpass1",
			name:             "node-group-new1",
			groupDescription: "some node group",
			expectedStatus:   http.StatusCreated,
		},
	}

	for _, test := range tests {
		func() {
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

			req, err := http.NewRequest("POST", ts.URL+"/api/v1/node-groups", r)
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
				t.Fatalf("%s: POST node group unexpected status code: %d (%s)", test.description, resp.StatusCode, string(r))
			}

			jsonData, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("%s: %s", test.description, err)
			}

			t.Logf("%s\n", jsonData)
		}()
	}
}

func TestAuthChallenge(t *testing.T) {
	expectedChallenge := `Basic realm="test realm"`
	challenge := authChallenge("Basic", "test realm")
	if challenge != expectedChallenge {
		t.Fatalf("unexpected challenge string, want '%s', have: '%s'", expectedChallenge, challenge)
	}
}

func TestRetryWithBackoff(t *testing.T) {
	errAllFailed := errors.New("all failed")

	logger := zerolog.New(zerolog.NewTestWriter(t)).With().Timestamp().Caller().Logger()

	tests := []struct {
		description string
		sleepBase   time.Duration
		sleepCap    time.Duration
		attempts    int
		operation   func(context.Context) error
		err         error
		cancel      bool
	}{
		{
			description: "successful first attempt",
			sleepBase:   time.Millisecond * 1,
			sleepCap:    time.Millisecond * 10,
			attempts:    3,
			operation: func(context.Context) error {
				return nil
			},
			err:    nil,
			cancel: false,
		},
		{
			description: "all attempts failed",
			sleepBase:   time.Millisecond * 1,
			sleepCap:    time.Millisecond * 10,
			attempts:    3,
			operation: func(context.Context) error {
				return errAllFailed
			},
			err:    errAllFailed,
			cancel: false,
		},
		{
			description: "success after retry",
			sleepBase:   time.Millisecond * 1,
			sleepCap:    time.Millisecond * 10,
			attempts:    3,
			operation: func() func(context.Context) error {
				attemptCounter := 0
				return func(context.Context) error {
					logger.Info().Int("attempt_counter", attemptCounter).Msg("trying attempt")
					if attemptCounter > 0 {
						return nil
					}
					attemptCounter++
					return errors.New("first attempt")
				}
			}(),
			err:    nil,
			cancel: false,
		},
		{
			description: "failed with cancelled context",
			sleepBase:   time.Millisecond * 1,
			sleepCap:    time.Millisecond * 10,
			attempts:    3,
			operation: func(context.Context) error {
				return errors.New("we expect to exit early due to context being cancelled")
			},
			err:    context.Canceled,
			cancel: true,
		},
	}

	for _, test := range tests {
		func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if test.cancel {
				cancel()
			}
			err := retryWithBackoff(ctx, logger, test.sleepBase, test.sleepCap, test.attempts, test.description, test.operation)
			if !errors.Is(err, test.err) {
				t.Fatalf("wanted err to be: %#v, got: %#v", test.err, err)
			}
		}()
	}
}
