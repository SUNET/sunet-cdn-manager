package migrations

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/testhelpers"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	pgContainer *postgres.PostgresContainer
	logger      zerolog.Logger
)

func TestMain(m *testing.M) {
	var err error

	ctx := context.Background()

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

	zerolog.CallerMarshalFunc = func(_ uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	logger = zerolog.New(os.Stderr).With().Timestamp().Caller().Logger()

	m.Run()
}

func prepareDatabase(ctx context.Context, t *testing.T) (*pgxpool.Config, error) {
	pgurl, err := testhelpers.CreateDatabase(ctx, t, pgContainer)
	if err != nil {
		return nil, err
	}

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		return nil, errors.New("unable to parse PostgreSQL config string")
	}

	fmt.Println(pgConfig.ConnString())

	return pgConfig, nil
}

func TestUpMigrations(t *testing.T) {
	ctx := context.Background()
	pgConfig, err := prepareDatabase(ctx, t)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		description string
	}{
		{
			description: "run migration",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			err := Up(context.Background(), logger, pgConfig)
			if err != nil {
				t.Fatalf("up call failed: %s", err)
			}
		})
	}
}

// TestVersionedOriginGroupsMigration seeds a database with pre-00010
// (service-scoped) origin groups and verifies migration 00010 copies them
// into every service version losslessly: positions assigned by name (the
// pre-00010 code emitted backends in name order, so name-based positions
// keep regenerated configs as close as possible except for the default group
// always being at the last position, origins repointed to the copy
// in their own version, unreferenced groups preserved, and the legacy
// columns dropped.
func TestVersionedOriginGroupsMigration(t *testing.T) {
	ctx := context.Background()
	pgConfig, err := prepareDatabase(ctx, t)
	if err != nil {
		t.Fatal(err)
	}

	// The migration files reference the "cdn" schema explicitly (see
	// 00009_qualify_function_references.sql), and the production/server
	// bootstrap creates that schema before migrating. Replicate that
	// here, and put it first on the search_path so migrated objects land
	// in it like they do in a real deployment.
	bootstrapPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapPool.Exec(ctx, "CREATE SCHEMA cdn"); err != nil {
		bootstrapPool.Close()
		t.Fatalf("creating cdn schema failed: %s", err)
	}
	bootstrapPool.Close()
	pgConfig.ConnConfig.RuntimeParams["search_path"] = "cdn,public"

	if err := upTo(ctx, logger, pgConfig, 9); err != nil {
		t.Fatalf("migrating up to version 9 failed: %s", err)
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer dbPool.Close()

	// Legacy-shape seed: svc-a has three service-level groups created in
	// non-alphabetical order ("zeta" before "alpha") so that creation
	// order and name order differ; svc-b has a default group plus a group
	// referenced by no origin at all.
	seed := []string{
		"INSERT INTO orgs (id, name) VALUES ('90000000-0000-0000-0000-000000000001', 'mig-org')",
		"INSERT INTO services (id, org_id, name, uid_range) VALUES ('90000000-0000-0000-0000-000000000002', '90000000-0000-0000-0000-000000000001', 'svc-a', '(1000010000, 1000019999)')",
		"INSERT INTO services (id, org_id, name, uid_range) VALUES ('90000000-0000-0000-0000-000000000003', '90000000-0000-0000-0000-000000000001', 'svc-b', '(1000020000, 1000029999)')",

		"INSERT INTO service_origin_groups (id, service_id, default_group, name) VALUES ('90000000-0000-0000-0000-00000000000a', '90000000-0000-0000-0000-000000000002', false, 'zeta')",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) VALUES ('90000000-0000-0000-0000-00000000000b', '90000000-0000-0000-0000-000000000002', true,  'default')",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) VALUES ('90000000-0000-0000-0000-00000000000c', '90000000-0000-0000-0000-000000000002', false, 'alpha')",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) VALUES ('90000000-0000-0000-0000-00000000000d', '90000000-0000-0000-0000-000000000003', true,  'default')",
		"INSERT INTO service_origin_groups (id, service_id, default_group, name) VALUES ('90000000-0000-0000-0000-00000000000e', '90000000-0000-0000-0000-000000000003', false, 'extra-b')",

		"INSERT INTO service_versions (id, service_id, version) VALUES ('90000000-0000-0000-0000-000000000101', '90000000-0000-0000-0000-000000000002', 1)",
		"INSERT INTO service_versions (id, service_id, version, active) VALUES ('90000000-0000-0000-0000-000000000102', '90000000-0000-0000-0000-000000000002', 2, true)",
		"INSERT INTO service_versions (id, service_id, version, active) VALUES ('90000000-0000-0000-0000-000000000103', '90000000-0000-0000-0000-000000000003', 1, true)",

		// svc-a v1: origins in zeta and default; v2: origins in alpha and zeta.
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port) VALUES ('90000000-0000-0000-0000-000000000201', '90000000-0000-0000-0000-000000000101', '90000000-0000-0000-0000-00000000000a', '198.51.100.10', 443)",
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port) VALUES ('90000000-0000-0000-0000-000000000202', '90000000-0000-0000-0000-000000000101', '90000000-0000-0000-0000-00000000000b', '198.51.100.11', 443)",
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port) VALUES ('90000000-0000-0000-0000-000000000203', '90000000-0000-0000-0000-000000000102', '90000000-0000-0000-0000-00000000000c', '198.51.100.12', 443)",
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port) VALUES ('90000000-0000-0000-0000-000000000204', '90000000-0000-0000-0000-000000000102', '90000000-0000-0000-0000-00000000000a', '198.51.100.13', 443)",
		// svc-b v1: origin in its default group; extra-b stays unreferenced.
		"INSERT INTO service_origins (id, service_version_id, origin_group_id, host, port) VALUES ('90000000-0000-0000-0000-000000000205', '90000000-0000-0000-0000-000000000103', '90000000-0000-0000-0000-00000000000d', '198.51.100.20', 443)",
	}
	for _, stmt := range seed {
		if _, err := dbPool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed statement failed: %s: %s", stmt, err)
		}
	}

	if err := upTo(ctx, logger, pgConfig, 10); err != nil {
		t.Fatalf("migrating to version 10 failed: %s", err)
	}

	// Every version owns a copy of all of its service's groups, positions
	// assigned by name order (note: the default group will always end up
	// last for migrated rows).
	expectedGroups := map[string][]struct {
		name         string
		position     int64
		defaultGroup bool
	}{
		"90000000-0000-0000-0000-000000000101": {{"alpha", 0, false}, {"zeta", 1, false}, {"default", 2, true}},
		"90000000-0000-0000-0000-000000000102": {{"alpha", 0, false}, {"zeta", 1, false}, {"default", 2, true}},
		"90000000-0000-0000-0000-000000000103": {{"extra-b", 0, false}, {"default", 1, true}},
	}

	totalGroups := 0
	for versionID, expected := range expectedGroups {
		rows, err := dbPool.Query(ctx, "SELECT name, position, default_group, condition FROM service_origin_groups WHERE service_version_id = $1 ORDER BY position", versionID)
		if err != nil {
			t.Fatal(err)
		}
		i := 0
		for rows.Next() {
			var name string
			var position int64
			var defaultGroup bool
			var condition *string
			if err := rows.Scan(&name, &position, &defaultGroup, &condition); err != nil {
				t.Fatal(err)
			}
			if i >= len(expected) {
				t.Fatalf("version %s: more groups than expected (extra: %s)", versionID, name)
			}
			want := expected[i]
			if name != want.name || position != want.position || defaultGroup != want.defaultGroup {
				t.Errorf("version %s group %d: got (%s, %d, %t), want (%s, %d, %t)", versionID, i, name, position, defaultGroup, want.name, want.position, want.defaultGroup)
			}
			if condition != nil {
				t.Errorf("version %s group %s: migrated group has non-NULL condition", versionID, name)
			}
			i++
			totalGroups++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if i != len(expected) {
			t.Errorf("version %s: got %d groups, want %d", versionID, i, len(expected))
		}
	}
	if totalGroups != 8 {
		t.Errorf("total migrated groups: got %d, want 8", totalGroups)
	}

	// Every origin must point at a group copy living in the origin's own
	// version, with the name of the group it originally referenced.
	expectedOriginGroups := map[string]string{
		"198.51.100.10": "zeta",
		"198.51.100.11": "default",
		"198.51.100.12": "alpha",
		"198.51.100.13": "zeta",
		"198.51.100.20": "default",
	}
	rows, err := dbPool.Query(ctx, "SELECT so.host, g.name, so.service_version_id = g.service_version_id FROM service_origins so JOIN service_origin_groups g ON so.origin_group_id = g.id")
	if err != nil {
		t.Fatal(err)
	}
	originCount := 0
	for rows.Next() {
		var host, groupName string
		var sameVersion bool
		if err := rows.Scan(&host, &groupName, &sameVersion); err != nil {
			t.Fatal(err)
		}
		if !sameVersion {
			t.Errorf("origin %s references a group outside its own service version", host)
		}
		if want := expectedOriginGroups[host]; groupName != want {
			t.Errorf("origin %s: got group %s, want %s", host, groupName, want)
		}
		originCount++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if originCount != len(expectedOriginGroups) {
		t.Errorf("origin count after migration: got %d, want %d", originCount, len(expectedOriginGroups))
	}

	// The legacy columns must be gone.
	for _, column := range []string{"service_id", "legacy_id"} {
		var count int
		err := dbPool.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'service_origin_groups' AND column_name = $1", column).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("legacy column %s still present after migration", column)
		}
	}
}
