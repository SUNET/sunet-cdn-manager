package migrations

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestUserOrgsMigration verifies that migration 00023 copies every set
// users.org_id into user_orgs, drops the column, keeps memberships unique,
// refuses to delete an org that still has members and removes a deleted
// user's memberships along with the user.
func TestUserOrgsMigration(t *testing.T) {
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

	if err := upTo(ctx, logger, pgConfig, 22); err != nil {
		t.Fatalf("migrating up to version 22 failed: %s", err)
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer dbPool.Close()

	const (
		roleID         = "94000000-0000-0000-0000-000000000001"
		authProviderID = "94000000-0000-0000-0000-000000000002"
		org1           = "94000000-0000-0000-0000-000000000011"
		org2           = "94000000-0000-0000-0000-000000000012"
		user1          = "94000000-0000-0000-0000-000000000021"
		user2          = "94000000-0000-0000-0000-000000000022"
		user3          = "94000000-0000-0000-0000-000000000023"
		insertUserSQL  = "INSERT INTO users (id, role_id, auth_provider_id, display_name, org_id) VALUES ($1, $2, $3, $4, $5)"
	)

	seed := []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO roles (id, name) VALUES ($1, 'mig-role')", []any{roleID}},
		{"INSERT INTO auth_providers (id, name) VALUES ($1, 'local')", []any{authProviderID}},
		{"INSERT INTO orgs (id, name) VALUES ($1, 'mig-org-1')", []any{org1}},
		{"INSERT INTO orgs (id, name) VALUES ($1, 'mig-org-2')", []any{org2}},
		{insertUserSQL, []any{user1, roleID, authProviderID, "mig-user-1", org1}},
		{insertUserSQL, []any{user2, roleID, authProviderID, "mig-user-2", nil}},
		{insertUserSQL, []any{user3, roleID, authProviderID, "mig-user-3", org2}},
	}
	for _, stmt := range seed {
		if _, err := dbPool.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("seed statement failed: %s: %s", stmt.sql, err)
		}
	}

	if err := upTo(ctx, logger, pgConfig, 23); err != nil {
		t.Fatalf("migrating up to version 23 failed: %s", err)
	}

	type membership struct {
		UserID string
		OrgID  string
	}

	readMemberships := func() []membership {
		t.Helper()
		rows, err := dbPool.Query(ctx, "SELECT user_id, org_id FROM user_orgs ORDER BY user_id")
		if err != nil {
			t.Fatalf("querying user_orgs failed: %s", err)
		}
		got, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (membership, error) {
			var userID, orgID pgtype.UUID
			if err := row.Scan(&userID, &orgID); err != nil {
				return membership{}, err
			}
			return membership{UserID: userID.String(), OrgID: orgID.String()}, nil
		})
		if err != nil {
			t.Fatalf("collecting user_orgs rows failed: %s", err)
		}
		return got
	}

	want := []membership{{user1, org1}, {user3, org2}}
	if got := readMemberships(); !slices.Equal(got, want) {
		t.Errorf("user_orgs after migration: got %v, want %v", got, want)
	}

	var orgIDColumns int
	err = dbPool.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'org_id'").Scan(&orgIDColumns)
	if err != nil {
		t.Fatalf("looking up users.org_id failed: %s", err)
	}
	if orgIDColumns != 0 {
		t.Errorf("users.org_id still exists after migration")
	}

	wantSQLState := func(description string, err error, code string) {
		t.Helper()
		pgErr, ok := errors.AsType[*pgconn.PgError](err)
		if !ok || pgErr.Code != code {
			t.Errorf("%s: expected SQLSTATE %s, got: %v", description, code, err)
		}
	}

	_, err = dbPool.Exec(ctx, "INSERT INTO user_orgs (user_id, org_id) VALUES ($1, $2)", user1, org1)
	wantSQLState("adding a membership twice", err, "23505")

	_, err = dbPool.Exec(ctx, "DELETE FROM orgs WHERE id = $1", org1)
	wantSQLState("deleting an org with members", err, "23503")

	_, err = dbPool.Exec(ctx, "DELETE FROM users WHERE id = $1", user1)
	if err != nil {
		t.Fatalf("deleting a user with memberships failed: %s", err)
	}

	want = []membership{{user3, org2}}
	if got := readMemberships(); !slices.Equal(got, want) {
		t.Errorf("user_orgs after deleting user 1: got %v, want %v", got, want)
	}
}
