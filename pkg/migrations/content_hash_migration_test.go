package migrations

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// hashSeedOrigin, hashSeedGroup and hashSeedVersion describe service version
// content in the shape the tables store it, for seeding versions directly
// with SQL before migration 00021 exists.
type hashSeedOrigin struct {
	host      string
	port      int
	tls       bool
	verifyTLS bool
}

type hashSeedGroup struct {
	name      string
	condition *string
	isDefault bool
	origins   []hashSeedOrigin
}

type hashSeedVersion struct {
	vclTemplate string
	description string
	domains     []string
	// groups is in priority order, the index is stored as position.
	groups []hashSeedGroup
}

// migrateToBeforeContentHash creates the cdn schema (see
// TestVersionedOriginGroupsMigration for why) and migrates to version 20,
// the last one before service_versions.content_hash.
func migrateToBeforeContentHash(ctx context.Context, t *testing.T) (*pgxpool.Pool, func() error) {
	t.Helper()

	pgConfig, err := prepareDatabase(ctx, t)
	if err != nil {
		t.Fatal(err)
	}

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

	if err := upTo(ctx, logger, pgConfig, 20); err != nil {
		t.Fatalf("migrating up to version 20 failed: %s", err)
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dbPool.Close)

	return dbPool, func() error { return Up(ctx, logger, pgConfig) }
}

// seedHashVersion inserts version number version of serviceID with the given
// content and returns its id. Domain FQDNs are looked up in orgID.
func seedHashVersion(ctx context.Context, t *testing.T, dbPool *pgxpool.Pool, orgID string, serviceID string, version int64, content hashSeedVersion) string {
	t.Helper()

	var versionID string
	err := dbPool.QueryRow(ctx, "INSERT INTO service_versions (service_id, version, description) VALUES ($1, $2, $3) RETURNING id", serviceID, version, content.description).Scan(&versionID)
	if err != nil {
		t.Fatalf("seeding service version failed: %s", err)
	}

	for _, fqdn := range content.domains {
		_, err := dbPool.Exec(ctx, "INSERT INTO service_domains (service_version_id, domain_id) SELECT $1, id FROM domains WHERE org_id = $2 AND fqdn = $3", versionID, orgID, fqdn)
		if err != nil {
			t.Fatalf("seeding service domain %s failed: %s", fqdn, err)
		}
	}

	for position, group := range content.groups {
		var groupID string
		err := dbPool.QueryRow(ctx, "INSERT INTO service_origin_groups (service_version_id, default_group, name, condition, position) VALUES ($1, $2, $3, $4, $5) RETURNING id", versionID, group.isDefault, group.name, group.condition, position).Scan(&groupID)
		if err != nil {
			t.Fatalf("seeding origin group %s failed: %s", group.name, err)
		}
		for _, origin := range group.origins {
			_, err := dbPool.Exec(ctx, "INSERT INTO service_origins (service_version_id, origin_group_id, host, port, tls, verify_tls) VALUES ($1, $2, $3, $4, $5, $6)", versionID, groupID, origin.host, origin.port, origin.tls, origin.verifyTLS)
			if err != nil {
				t.Fatalf("seeding origin %s:%d failed: %s", origin.host, origin.port, err)
			}
		}
	}

	_, err = dbPool.Exec(ctx, "INSERT INTO service_vcls (service_version_id, vcl_template) VALUES ($1, $2)", versionID, content.vclTemplate)
	if err != nil {
		t.Fatalf("seeding vcl failed: %s", err)
	}

	return versionID
}

func seedHashService(ctx context.Context, t *testing.T, dbPool *pgxpool.Pool, orgID string, index int) string {
	t.Helper()

	var serviceID string
	low := 1000010000 + index*10000
	err := dbPool.QueryRow(ctx, "INSERT INTO services (org_id, name, uid_range) VALUES ($1, $2, int8range($3, $4)) RETURNING id", orgID, fmt.Sprintf("svc-%d", index), low, low+10000).Scan(&serviceID)
	if err != nil {
		t.Fatalf("seeding service %d failed: %s", index, err)
	}
	return serviceID
}

func seedHashOrg(ctx context.Context, t *testing.T, dbPool *pgxpool.Pool, name string, domains ...string) string {
	t.Helper()

	var orgID string
	if err := dbPool.QueryRow(ctx, "INSERT INTO orgs (name) VALUES ($1) RETURNING id", name).Scan(&orgID); err != nil {
		t.Fatalf("seeding org failed: %s", err)
	}
	for _, fqdn := range domains {
		_, err := dbPool.Exec(ctx, "INSERT INTO domains (org_id, fqdn, verified, verification_token) VALUES ($1, $2, true, 'token')", orgID, fqdn)
		if err != nil {
			t.Fatalf("seeding domain %s failed: %s", fqdn, err)
		}
	}
	return orgID
}

func baseHashSeedVersion() hashSeedVersion {
	return hashSeedVersion{
		vclTemplate: "vcl 4.1;\n",
		description: "base",
		domains:     []string{"a.example.com", "b.example.com"},
		groups: []hashSeedGroup{
			{
				name:      "api",
				condition: new(`req.url ~ "^/api"`),
				origins: []hashSeedOrigin{
					{host: "x.example.net", port: 443, tls: true, verifyTLS: true},
					{host: "y.example.net", port: 80},
				},
			},
			{
				name:      "img",
				condition: new(`req.url ~ "^/img"`),
				origins: []hashSeedOrigin{
					{host: "i.example.net", port: 443, tls: true},
				},
			},
			{
				name:      "default",
				isDefault: true,
				origins: []hashSeedOrigin{
					{host: "z.example.net", port: 443, tls: true},
				},
			},
		},
	}
}

// TestServiceVersionContentHashMigration seeds versions whose content differs
// from a base version in one way each, migrates, and checks which of them
// hash the same as the base. Each version lives in its own service so that
// identical content does not trip the per-service UNIQUE constraint.
func TestServiceVersionContentHashMigration(t *testing.T) {
	ctx := context.Background()
	dbPool, migrateUp := migrateToBeforeContentHash(ctx, t)

	orgID := seedHashOrg(ctx, t, dbPool, "hash-org", "a.example.com", "b.example.com", "c.example.com")

	tests := []struct {
		description string
		modify      func(v *hashSeedVersion)
		sameAsBase  bool
	}{
		{
			description: "identical",
			modify:      func(*hashSeedVersion) {},
			sameAsBase:  true,
		},
		{
			description: "description differs",
			modify:      func(v *hashSeedVersion) { v.description = "something else" },
			sameAsBase:  true,
		},
		{
			description: "domains inserted in the other order",
			modify:      func(v *hashSeedVersion) { v.domains = []string{"b.example.com", "a.example.com"} },
			sameAsBase:  true,
		},
		{
			description: "origins of a group inserted in the other order",
			modify: func(v *hashSeedVersion) {
				o := v.groups[0].origins
				v.groups[0].origins = []hashSeedOrigin{o[1], o[0]}
			},
			sameAsBase: true,
		},
		{
			description: "conditional groups in the other priority order",
			modify: func(v *hashSeedVersion) {
				v.groups[0], v.groups[1] = v.groups[1], v.groups[0]
			},
		},
		{
			description: "vcl template differs",
			modify:      func(v *hashSeedVersion) { v.vclTemplate = "vcl 4.1;\n# changed\n" },
		},
		{
			description: "domain removed",
			modify:      func(v *hashSeedVersion) { v.domains = []string{"a.example.com"} },
		},
		{
			description: "domain replaced",
			modify:      func(v *hashSeedVersion) { v.domains = []string{"a.example.com", "c.example.com"} },
		},
		{
			description: "group renamed",
			modify:      func(v *hashSeedVersion) { v.groups[0].name = "api2" },
		},
		{
			description: "condition differs",
			modify:      func(v *hashSeedVersion) { v.groups[0].condition = new(`req.url ~ "^/v2"`) },
		},
		{
			description: "origin host differs",
			modify:      func(v *hashSeedVersion) { v.groups[0].origins[0].host = "w.example.net" },
		},
		{
			description: "origin port differs",
			modify:      func(v *hashSeedVersion) { v.groups[0].origins[0].port = 8443 },
		},
		{
			description: "origin tls differs",
			modify:      func(v *hashSeedVersion) { v.groups[0].origins[1].tls = true },
		},
		{
			description: "origin verify_tls differs",
			modify:      func(v *hashSeedVersion) { v.groups[0].origins[0].verifyTLS = false },
		},
		{
			description: "origin moved to another group",
			modify: func(v *hashSeedVersion) {
				moved := v.groups[0].origins[1]
				v.groups[0].origins = v.groups[0].origins[:1]
				v.groups[1].origins = append(v.groups[1].origins, moved)
			},
		},
		// The API requires at least one domain, and at least one origin
		// per group, but the schema does not, so the backfill can meet
		// empty sets. string_agg over no rows is NULL, and these cases
		// check that the function's COALESCEs turn that into a hash
		// rather than a NULL that fails SET NOT NULL.
		{
			description: "no domains",
			modify:      func(v *hashSeedVersion) { v.domains = nil },
		},
		{
			description: "group without origins",
			modify:      func(v *hashSeedVersion) { v.groups[1].origins = nil },
		},
		{
			description: "no origin groups",
			modify:      func(v *hashSeedVersion) { v.groups = nil },
		},
		{
			description: "group removed",
			modify:      func(v *hashSeedVersion) { v.groups = append(v.groups[:1], v.groups[2:]...) },
		},
	}

	baseServiceID := seedHashService(ctx, t, dbPool, orgID, 0)
	baseVersionID := seedHashVersion(ctx, t, dbPool, orgID, baseServiceID, 1, baseHashSeedVersion())

	versionIDs := make([]string, len(tests))
	for i, test := range tests {
		content := baseHashSeedVersion()
		test.modify(&content)
		serviceID := seedHashService(ctx, t, dbPool, orgID, i+1)
		versionIDs[i] = seedHashVersion(ctx, t, dbPool, orgID, serviceID, 1, content)
	}

	if err := migrateUp(); err != nil {
		t.Fatalf("migrating up failed: %s", err)
	}

	storedHash := func(t *testing.T, versionID string) []byte {
		t.Helper()
		var h []byte
		if err := dbPool.QueryRow(ctx, "SELECT content_hash FROM service_versions WHERE id = $1", versionID).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h
	}

	baseHash := storedHash(t, baseVersionID)
	if len(baseHash) != 32 {
		t.Fatalf("base content_hash is %d bytes, want 32", len(baseHash))
	}

	for i, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			same := string(storedHash(t, versionIDs[i])) == string(baseHash)
			if same != test.sameAsBase {
				t.Fatalf("hash equal to base: %t, want %t", same, test.sameAsBase)
			}
		})
	}

	// What keeps these apart is the COALESCE around the origins
	// string_agg in service_version_content_hash(). A group without
	// origins aggregates them to NULL, which the COALESCE turns into an
	// empty list, so the group is still written as (...,origins:).
	// Without it the group's whole element would be NULL, and the outer
	// string_agg over groups skips NULL elements: the group would vanish
	// from the hash and match a version where it really is gone.
	// Comparing against the base does not catch that, as a vanished group
	// still changes the hash, so compare against such a version.
	t.Run("group without origins differs from group removed", func(t *testing.T) {
		versionIDOf := func(description string) string {
			t.Helper()
			for i, test := range tests {
				if test.description == description {
					return versionIDs[i]
				}
			}
			t.Fatalf("no test case %q", description)
			return ""
		}
		withoutOrigins := storedHash(t, versionIDOf("group without origins"))
		removed := storedHash(t, versionIDOf("group removed"))
		if string(withoutOrigins) == string(removed) {
			t.Fatal("a group without origins hashes the same as the group being absent")
		}
	})

	// Every stored hash must be what the function computes from the
	// version's rows today. Up runs every migration, so a later migration
	// that changes hashed content without rehashing makes this fail.
	t.Run("stored hashes match the function", func(t *testing.T) {
		var stale int
		err := dbPool.QueryRow(ctx, "SELECT count(*) FROM service_versions WHERE content_hash IS DISTINCT FROM service_version_content_hash(id)").Scan(&stale)
		if err != nil {
			t.Fatal(err)
		}
		if stale != 0 {
			t.Fatalf("%d service versions have a content_hash that does not match service_version_content_hash(id)", stale)
		}
	})
}

// TestServiceVersionContentHashMigrationRefusesDuplicates checks that two
// versions of one service with the same content make the migration fail as a
// whole, so duplicates have to be cleaned up before upgrading.
func TestServiceVersionContentHashMigrationRefusesDuplicates(t *testing.T) {
	ctx := context.Background()
	dbPool, migrateUp := migrateToBeforeContentHash(ctx, t)

	orgID := seedHashOrg(ctx, t, dbPool, "dup-org", "a.example.com", "b.example.com")
	serviceID := seedHashService(ctx, t, dbPool, orgID, 0)

	first := baseHashSeedVersion()
	second := baseHashSeedVersion()
	second.description = "same content, other description"
	seedHashVersion(ctx, t, dbPool, orgID, serviceID, 1, first)
	seedHashVersion(ctx, t, dbPool, orgID, serviceID, 2, second)

	err := migrateUp()
	if err == nil {
		t.Fatal("migrating up succeeded with duplicate service versions, want failure")
	}
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); !ok || pgErr.Code != "23505" {
		t.Fatalf("migrating up failed with %v, want a unique violation", err)
	}

	// The migration runs in one transaction, so nothing of it is left.
	var hasColumn bool
	err = dbPool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'cdn' AND table_name = 'service_versions' AND column_name = 'content_hash')").Scan(&hasColumn)
	if err != nil {
		t.Fatal(err)
	}
	if hasColumn {
		t.Fatal("content_hash column exists after the failed migration")
	}
}

// TestServiceVersionContentHashSchema checks the constraints that keep stored
// hashes present and unique, and that the foreign keys to service_versions
// can be deferred, which inserting a version with its hash relies on.
func TestServiceVersionContentHashSchema(t *testing.T) {
	ctx := context.Background()
	dbPool, migrateUp := migrateToBeforeContentHash(ctx, t)
	if err := migrateUp(); err != nil {
		t.Fatalf("migrating up failed: %s", err)
	}

	// The manager inserts a version's rows before its service_versions
	// row, so every foreign key to service_versions has to be in the list
	// it defers, or inserting into a new child table fails.
	t.Run("ServiceVersionForeignKeys lists every foreign key to service_versions", func(t *testing.T) {
		rows, err := dbPool.Query(ctx, "SELECT conname FROM pg_constraint WHERE contype = 'f' AND confrelid = 'service_versions'::regclass ORDER BY conname")
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		if want := slices.Sorted(slices.Values(ServiceVersionForeignKeys)); !slices.Equal(got, want) {
			t.Fatalf("foreign keys to service_versions are %v, ServiceVersionForeignKeys has %v", got, want)
		}
	})

	for _, name := range ServiceVersionForeignKeys {
		t.Run(name, func(t *testing.T) {
			var deferrable, initiallyDeferred bool
			err := dbPool.QueryRow(ctx, "SELECT condeferrable, condeferred FROM pg_constraint WHERE conname = $1 AND connamespace = 'cdn'::regnamespace", name).Scan(&deferrable, &initiallyDeferred)
			if err != nil {
				t.Fatal(err)
			}
			if !deferrable || initiallyDeferred {
				t.Fatalf("deferrable=%t initially deferred=%t, want DEFERRABLE INITIALLY IMMEDIATE", deferrable, initiallyDeferred)
			}
		})
	}

	orgID := seedHashOrg(ctx, t, dbPool, "schema-org")
	serviceID := seedHashService(ctx, t, dbPool, orgID, 0)

	wantViolation := func(t *testing.T, err error, code string) {
		t.Helper()
		pgErr, ok := errors.AsType[*pgconn.PgError](err)
		if !ok || pgErr.Code != code {
			t.Fatalf("got %v, want SQLSTATE %s", err, code)
		}
	}

	t.Run("content_hash is required", func(t *testing.T) {
		_, err := dbPool.Exec(ctx, "INSERT INTO service_versions (service_id, version) VALUES ($1, 1)", serviceID)
		wantViolation(t, err, "23502")
	})

	t.Run("content_hash is a sha256", func(t *testing.T) {
		_, err := dbPool.Exec(ctx, "INSERT INTO service_versions (service_id, version, content_hash) VALUES ($1, 1, '\\x00')", serviceID)
		wantViolation(t, err, "23514")
	})

	t.Run("content_hash is unique per service", func(t *testing.T) {
		_, err := dbPool.Exec(ctx, "INSERT INTO service_versions (service_id, version, content_hash) VALUES ($1, 1, sha256('x'))", serviceID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = dbPool.Exec(ctx, "INSERT INTO service_versions (service_id, version, content_hash) VALUES ($1, 2, sha256('x'))", serviceID)
		wantViolation(t, err, "23505")
	})
}

// unhashedContentColumns lists every column of the content tables that
// service_version_content_hash() does not read, with the reason it is not
// content. The content tables are service_versions, every table that
// references it (directly or through another content table), and every
// table the function reads.
//
// TestServiceVersionContentHashCoversEveryColumn fails when a column is
// neither read by the function nor listed here. A new column that changes
// what a version does belongs in the function, followed by a rehash (see
// migration 00021). Otherwise two versions differing only in that column
// count as identical, and the second is never created. Anything else gets
// an entry here.
var unhashedContentColumns = map[string]string{
	"service_versions.id":           "the argument to service_version_content_hash(), not content",
	"service_versions.time_created": "when the version was created, not what it contains",
	"service_versions.service_id":   "the owner, the UNIQUE constraint is per service",
	"service_versions.version":      "assigned on insert, never part of what is submitted",
	"service_versions.active":       "state that activation changes, not content",
	"service_versions.description":  "describes the content, the same content under another description is still a duplicate",
	"service_versions.content_hash": "the hash itself",

	"service_vcls.id":           "row identity, new for every version",
	"service_vcls.time_created": "when the row was created, not what it contains",

	"service_domains.id":           "row identity, new for every version",
	"service_domains.time_created": "when the row was created, not what it contains",

	"domains.org_id":             "always the service's org",
	"domains.time_created":       "domain state, not version content",
	"domains.verified":           "domain state, not version content",
	"domains.verification_token": "domain state, not version content",
	"domains.time_retired":       "domain state, not version content",

	"service_origin_groups.time_created": "when the row was created, not what it contains",

	"service_origins.id":                 "row identity, new for every version",
	"service_origins.time_created":       "when the row was created, not what it contains",
	"service_origins.service_version_id": "the function finds origins through their group, origin_group_id",
}

// TestServiceVersionContentHashCoversEveryColumn makes adding a column to
// the content tables, or a new table referencing them, force a decision
// about whether it is hashed. Which columns the function reads comes from
// pg_depend: a SQL-standard function body records a dependency on every
// column it uses, join columns included.
func TestServiceVersionContentHashCoversEveryColumn(t *testing.T) {
	ctx := context.Background()
	dbPool, migrateUp := migrateToBeforeContentHash(ctx, t)
	if err := migrateUp(); err != nil {
		t.Fatalf("migrating up failed: %s", err)
	}

	queryColumns := func(t *testing.T, query string) map[string]bool {
		t.Helper()
		rows, err := dbPool.Query(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		columns, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		set := map[string]bool{}
		for _, column := range columns {
			set[column] = true
		}
		return set
	}

	// The columns the function reads, as "table.column". pg_depend is
	// PostgreSQL's record of which objects depend on which, the same
	// record that refuses to drop a column the function uses. Each row
	// says that object objid, of the kind named by classid, depends on
	// object refobjid of kind refclassid, and for a dependency on a single
	// column refobjsubid is that column's number. The catalogs identify
	// objects by oid: 'name'::regclass and 'name'::regproc look up the oid
	// of a table or function, and oid::regclass::text gives a table's name
	// back.
	read := queryColumns(t, `
		SELECT d.refobjid::regclass::text || '.' || a.attname
		FROM pg_depend d
		-- pg_attribute has one row per column, numbered by attnum.
		JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
		-- What depends: our function, a row in pg_proc.
		WHERE d.classid = 'pg_proc'::regclass
		  AND d.objid = 'service_version_content_hash'::regproc
		  -- What it depends on: tables, rows in pg_class. The join
		  -- above drops the whole-table entries (refobjsubid 0).
		  AND d.refclassid = 'pg_class'::regclass`)
	if len(read) == 0 {
		t.Fatal("found no columns that service_version_content_hash() depends on")
	}

	// Every column of every content table, as "table.column". The content
	// tables are service_versions, every table holding a foreign key to it
	// or to another content table (found by following pg_constraint
	// recursively), and every table the function reads (from pg_depend as
	// above), which adds domains.
	all := queryColumns(t, `
		WITH RECURSIVE referencing(rel) AS (
			-- Start from service_versions ...
			SELECT 'service_versions'::regclass::oid
			UNION
			-- ... and repeatedly add tables (conrelid) with a foreign
			-- key (contype 'f') to a table already found (confrelid),
			-- until no new ones turn up.
			SELECT c.conrelid
			FROM pg_constraint c
			JOIN referencing r ON c.confrelid = r.rel
			WHERE c.contype = 'f'
		), content_tables(rel) AS (
			SELECT rel FROM referencing
			UNION
			-- Tables the function depends on, as in the query above.
			SELECT refobjid
			FROM pg_depend
			WHERE classid = 'pg_proc'::regclass
			  AND objid = 'service_version_content_hash'::regproc
			  AND refclassid = 'pg_class'::regclass
		)
		SELECT a.attrelid::regclass::text || '.' || a.attname
		FROM pg_attribute a
		JOIN content_tables t ON t.rel = a.attrelid
		-- Leave out system columns (ctid, xmin, ..., numbered below 1)
		-- and dropped columns, which pg_attribute keeps.
		WHERE a.attnum > 0 AND NOT a.attisdropped`)

	for _, column := range slices.Sorted(maps.Keys(all)) {
		_, listed := unhashedContentColumns[column]
		switch {
		case read[column] && listed:
			t.Errorf("%s is read by service_version_content_hash() but listed in unhashedContentColumns", column)
		case !read[column] && !listed:
			t.Errorf("%s is not read by service_version_content_hash(): add it to the function and rehash, or list it in unhashedContentColumns with the reason it is not content", column)
		}
	}
	for _, column := range slices.Sorted(maps.Keys(unhashedContentColumns)) {
		if !all[column] {
			t.Errorf("unhashedContentColumns entry %s is not a column of any content table (stale)", column)
		}
	}
}
