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
	"github.com/jackc/pgx/v5/pgconn"
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

// TestStripCRMigration seeds service_vcls and service_origin_groups rows with
// the line endings that the console textareas (CRLF) and API clients may have
// stored before migration 00016, and verifies the migration normalizes them
// to LF, leaves already clean rows untouched and then rejects new CR
// characters.
func TestStripCRMigration(t *testing.T) {
	ctx := context.Background()
	pgConfig, err := prepareDatabase(ctx, t)
	if err != nil {
		t.Fatal(err)
	}

	// See TestVersionedOriginGroupsMigration for why the cdn schema is
	// created here.
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

	if err := upTo(ctx, logger, pgConfig, 15); err != nil {
		t.Fatalf("migrating up to version 15 failed: %s", err)
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer dbPool.Close()

	seed := []string{
		"INSERT INTO orgs (id, name) VALUES ('91000000-0000-0000-0000-000000000001', 'mig-org')",
		"INSERT INTO services (id, org_id, name, uid_range) VALUES ('91000000-0000-0000-0000-000000000002', '91000000-0000-0000-0000-000000000001', 'svc-a', '(1000010000, 1000019999)')",
		"INSERT INTO service_versions (id, service_id, version) VALUES ('91000000-0000-0000-0000-000000000101', '91000000-0000-0000-0000-000000000002', 1)",
		"INSERT INTO service_versions (id, service_id, version) VALUES ('91000000-0000-0000-0000-000000000102', '91000000-0000-0000-0000-000000000002', 2)",
		"INSERT INTO service_versions (id, service_id, version) VALUES ('91000000-0000-0000-0000-000000000103', '91000000-0000-0000-0000-000000000002', 3)",
		"INSERT INTO service_versions (id, service_id, version, active) VALUES ('91000000-0000-0000-0000-000000000104', '91000000-0000-0000-0000-000000000002', 4, true)",
		"INSERT INTO service_versions (id, service_id, version) VALUES ('91000000-0000-0000-0000-000000000105', '91000000-0000-0000-0000-000000000002', 5)",
		// Default groups have a NULL condition which must survive the
		// migration and pass the new constraint.
		"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, position) VALUES ('91000000-0000-0000-0000-000000000200', '91000000-0000-0000-0000-000000000101', true, 'default', 4)",
	}
	for _, stmt := range seed {
		if _, err := dbPool.Exec(ctx, stmt); err != nil {
			t.Fatalf("seed statement failed: %s: %s", stmt, err)
		}
	}

	vclTests := []struct {
		description      string
		serviceVersionID string
		template         string
		expected         string
	}{
		{
			description:      "LF only",
			serviceVersionID: "91000000-0000-0000-0000-000000000101",
			template:         "sub vcl_recv {\n#SUNET-CDN-MANAGER vcl_recv\n}\n",
			expected:         "sub vcl_recv {\n#SUNET-CDN-MANAGER vcl_recv\n}\n",
		},
		{
			description:      "CRLF from console textarea",
			serviceVersionID: "91000000-0000-0000-0000-000000000102",
			template:         "sub vcl_recv {\r\n#SUNET-CDN-MANAGER vcl_recv\r\n}\r\n",
			expected:         "sub vcl_recv {\n#SUNET-CDN-MANAGER vcl_recv\n}\n",
		},
		{
			description:      "mixed CRLF and LF",
			serviceVersionID: "91000000-0000-0000-0000-000000000103",
			template:         "sub vcl_recv {\r\n#SUNET-CDN-MANAGER vcl_recv\n}\r\n",
			expected:         "sub vcl_recv {\n#SUNET-CDN-MANAGER vcl_recv\n}\n",
		},
		{
			description:      "lone CR",
			serviceVersionID: "91000000-0000-0000-0000-000000000104",
			template:         "sub vcl_recv {\r#SUNET-CDN-MANAGER vcl_recv\r\r\n}",
			expected:         "sub vcl_recv {\n#SUNET-CDN-MANAGER vcl_recv\n\n}",
		},
	}

	for _, vt := range vclTests {
		_, err := dbPool.Exec(ctx, "INSERT INTO service_vcls (service_version_id, vcl_template) VALUES ($1, $2)", vt.serviceVersionID, vt.template)
		if err != nil {
			t.Fatalf("seeding vcl %q failed: %s", vt.description, err)
		}
	}

	conditionTests := []struct {
		description string
		groupID     string
		condition   string
		expected    string
	}{
		{
			description: "single line",
			groupID:     "91000000-0000-0000-0000-000000000201",
			condition:   `req.url ~ "^/api/"`,
			expected:    `req.url ~ "^/api/"`,
		},
		{
			description: "LF only",
			groupID:     "91000000-0000-0000-0000-000000000202",
			condition:   "req.url ~ \"^/a\" ||\nreq.url ~ \"^/b\"",
			expected:    "req.url ~ \"^/a\" ||\nreq.url ~ \"^/b\"",
		},
		{
			description: "CRLF from console textarea",
			groupID:     "91000000-0000-0000-0000-000000000203",
			condition:   "req.url ~ \"^/c\" ||\r\nreq.url ~ \"^/d\"",
			expected:    "req.url ~ \"^/c\" ||\nreq.url ~ \"^/d\"",
		},
		{
			description: "lone CR",
			groupID:     "91000000-0000-0000-0000-000000000204",
			condition:   "req.url ~ \"^/e\" ||\rreq.url ~ \"^/f\"",
			expected:    "req.url ~ \"^/e\" ||\nreq.url ~ \"^/f\"",
		},
	}

	for i, ct := range conditionTests {
		_, err := dbPool.Exec(ctx,
			"INSERT INTO service_origin_groups (id, service_version_id, default_group, name, condition, position) VALUES ($1, '91000000-0000-0000-0000-000000000101', false, $2, $3, $4)",
			ct.groupID, fmt.Sprintf("group-%d", i), ct.condition, i)
		if err != nil {
			t.Fatalf("seeding condition %q failed: %s", ct.description, err)
		}
	}

	// xmin changes whenever a row is rewritten, so it shows which rows the
	// migration touched.
	vclXmin := func(serviceVersionID string) string {
		t.Helper()
		var xmin string
		err := dbPool.QueryRow(ctx, "SELECT xmin::text FROM service_vcls WHERE service_version_id = $1", serviceVersionID).Scan(&xmin)
		if err != nil {
			t.Fatal(err)
		}
		return xmin
	}
	groupXmin := func(groupID string) string {
		t.Helper()
		var xmin string
		err := dbPool.QueryRow(ctx, "SELECT xmin::text FROM service_origin_groups WHERE id = $1", groupID).Scan(&xmin)
		if err != nil {
			t.Fatal(err)
		}
		return xmin
	}

	vclXminBefore := map[string]string{}
	for _, vt := range vclTests {
		vclXminBefore[vt.serviceVersionID] = vclXmin(vt.serviceVersionID)
	}
	groupXminBefore := map[string]string{}
	for _, ct := range conditionTests {
		groupXminBefore[ct.groupID] = groupXmin(ct.groupID)
	}
	defaultGroupXminBefore := groupXmin("91000000-0000-0000-0000-000000000200")

	if err := upTo(ctx, logger, pgConfig, 16); err != nil {
		t.Fatalf("migrating to version 16 failed: %s", err)
	}

	for _, vt := range vclTests {
		t.Run("vcl_template "+vt.description, func(t *testing.T) {
			var got string
			err := dbPool.QueryRow(ctx, "SELECT vcl_template FROM service_vcls WHERE service_version_id = $1", vt.serviceVersionID).Scan(&got)
			if err != nil {
				t.Fatal(err)
			}
			if got != vt.expected {
				t.Errorf("got %q, want %q", got, vt.expected)
			}

			// Only rows containing CR characters are rewritten.
			rewritten := vclXmin(vt.serviceVersionID) != vclXminBefore[vt.serviceVersionID]
			if wantRewritten := vt.template != vt.expected; rewritten != wantRewritten {
				t.Errorf("row rewritten by migration: got %t, want %t", rewritten, wantRewritten)
			}
		})
	}

	for _, ct := range conditionTests {
		t.Run("condition "+ct.description, func(t *testing.T) {
			var got string
			err := dbPool.QueryRow(ctx, "SELECT condition FROM service_origin_groups WHERE id = $1", ct.groupID).Scan(&got)
			if err != nil {
				t.Fatal(err)
			}
			if got != ct.expected {
				t.Errorf("got %q, want %q", got, ct.expected)
			}

			// Only rows containing CR characters are rewritten.
			rewritten := groupXmin(ct.groupID) != groupXminBefore[ct.groupID]
			if wantRewritten := ct.condition != ct.expected; rewritten != wantRewritten {
				t.Errorf("row rewritten by migration: got %t, want %t", rewritten, wantRewritten)
			}
		})
	}

	var defaultCondition *string
	err = dbPool.QueryRow(ctx, "SELECT condition FROM service_origin_groups WHERE id = '91000000-0000-0000-0000-000000000200'").Scan(&defaultCondition)
	if err != nil {
		t.Fatal(err)
	}
	if defaultCondition != nil {
		t.Errorf("default group condition: got %q, want NULL", *defaultCondition)
	}
	if groupXmin("91000000-0000-0000-0000-000000000200") != defaultGroupXminBefore {
		t.Error("default group row with NULL condition was rewritten by migration")
	}

	// The constraints added by the migration reject new CR characters.
	for _, crText := range []string{"\r\n", "\r"} {
		_, err = dbPool.Exec(ctx, "INSERT INTO service_vcls (service_version_id, vcl_template) VALUES ('91000000-0000-0000-0000-000000000105', $1)", "sub vcl_recv {"+crText+"}")
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "vcl_template_no_cr" {
			t.Errorf("inserting vcl_template with %q: expected vcl_template_no_cr check violation, got: %v", crText, err)
		}

		_, err = dbPool.Exec(ctx, "INSERT INTO service_origin_groups (service_version_id, default_group, name, condition, position) VALUES ('91000000-0000-0000-0000-000000000105', false, 'cr-group', $1, 0)", "req.url ~ \"^/a\" ||"+crText+"req.url ~ \"^/b\"")
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "condition_no_cr" {
			t.Errorf("inserting condition with %q: expected condition_no_cr check violation, got: %v", crText, err)
		}
	}
}
