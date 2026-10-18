package consolesession

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/SUNET/sunet-cdn-manager/pkg/migrations"
	"github.com/SUNET/sunet-cdn-manager/pkg/testhelpers"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
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

	m.Run()
}

const (
	userAID = "00000006-0000-0000-0000-00000000000a"
	userBID = "00000006-0000-0000-0000-00000000000b"
	orgAID  = "00000002-0000-0000-0000-00000000000a"
	orgBID  = "00000002-0000-0000-0000-00000000000b"
)

var v4TokenFormat = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}$`)

func mustUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var u pgtype.UUID
	if err := u.Scan(s); err != nil {
		t.Fatal(err)
	}
	return u
}

func execSQL(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// newTestStore migrates a new database, adds two orgs and two users, and
// returns a store with a 30 minute idle and 8 hour absolute timeout (so a
// 1 minute touch interval and the 5 minute flash lifetime).
func newTestStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	pgurl, err := testhelpers.CreateDatabase(ctx, t, pgContainer)
	if err != nil {
		t.Fatal(err)
	}

	pgConfig, err := pgxpool.ParseConfig(pgurl)
	if err != nil {
		t.Fatal(err)
	}
	pgConfig.MaxConns = 1

	// The migrations reference the "cdn" schema (see
	// 00009_qualify_function_references.sql), and the production bootstrap
	// creates that schema before migrating. Replicate that here, the same
	// way pkg/migrations/migrations_test.go does.
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

	err = migrations.Up(ctx, zerolog.Nop(), pgConfig)
	if err != nil {
		t.Fatal(err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	execSQL(t, pool, "INSERT INTO orgs (id, name) VALUES ($1, 'org-a'), ($2, 'org-b')", orgAID, orgBID)
	execSQL(t, pool, "INSERT INTO roles (id, name) VALUES ('00000005-0000-0000-0000-00000000000a', 'user')")
	execSQL(t, pool, "INSERT INTO auth_providers (id, name) VALUES ('00000010-0000-0000-0000-00000000000a', 'local')")
	execSQL(
		t,
		pool,
		"INSERT INTO users (id, role_id, auth_provider_id, display_name) VALUES ($1, '00000005-0000-0000-0000-00000000000a', '00000010-0000-0000-0000-00000000000a', 'user-a'), ($2, '00000005-0000-0000-0000-00000000000a', '00000010-0000-0000-0000-00000000000a', 'user-b')",
		userAID,
		userBID,
	)

	store, err := NewStore(pool, 30*time.Minute, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	return store, pool
}

func createSession(t *testing.T, pool *pgxpool.Pool, userID string) Token {
	t.Helper()
	ctx := context.Background()

	var tok Token
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		tok, err = CreateTx(ctx, tx, mustUUID(t, userID))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	return tok
}

// ageSession moves a session back in time: it was last used lastSeen ago
// and created created ago.
func ageSession(t *testing.T, pool *pgxpool.Pool, id pgtype.UUID, lastSeen time.Duration, created time.Duration) {
	t.Helper()
	execSQL(t, pool, "UPDATE console_sessions SET last_seen = now() - $2::interval, time_created = now() - $3::interval WHERE id = $1", id, lastSeen, created)
}

func lastSeen(t *testing.T, pool *pgxpool.Pool, id pgtype.UUID) time.Time {
	t.Helper()
	var ts time.Time
	err := pool.QueryRow(context.Background(), "SELECT last_seen FROM console_sessions WHERE id = $1", id).Scan(&ts)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func sessionExists(t *testing.T, pool *pgxpool.Pool, id pgtype.UUID) bool {
	t.Helper()
	var exists bool
	err := pool.QueryRow(context.Background(), "SELECT EXISTS (SELECT 1 FROM console_sessions WHERE id = $1)", id).Scan(&exists)
	if err != nil {
		t.Fatal(err)
	}
	return exists
}

func TestNewStore(t *testing.T) {
	_, pool := newTestStore(t)

	tests := []struct {
		name     string
		idle     time.Duration
		absolute time.Duration
	}{
		{name: "zero idle", idle: 0, absolute: time.Hour},
		{name: "absolute below idle", idle: time.Hour, absolute: time.Minute},
	}
	for _, test := range tests {
		if _, err := NewStore(pool, test.idle, test.absolute); err == nil {
			t.Errorf("%s: expected an error", test.name)
		}
	}

	if _, err := NewStore(nil, time.Hour, time.Hour); err == nil {
		t.Error("nil pool: expected an error")
	}

	// The touch interval is min(1 minute, idle / 10)
	long, err := NewStore(pool, 30*time.Minute, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if long.touchInterval != time.Minute {
		t.Errorf("touch interval for 30m idle: got %s, want 1m", long.touchInterval)
	}

	short, err := NewStore(pool, 5*time.Minute, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if short.touchInterval != 30*time.Second {
		t.Errorf("touch interval for 5m idle: got %s, want 30s", short.touchInterval)
	}
}

func TestCreateTxStoresOnlyHash(t *testing.T) {
	_, pool := newTestStore(t)
	ctx := context.Background()

	tok := createSession(t, pool, userAID)

	if !v4TokenFormat.MatchString(tok.String()) {
		t.Fatalf("token %q does not have the expected format", tok.String())
	}
	parsed, err := ParseToken(tok.String())
	if err != nil || parsed != tok {
		t.Fatalf("token does not round-trip: %v", err)
	}

	// s::text is the whole row as one string, so the secret is searched
	// for in every column, including columns added later.
	var storedHash []byte
	var rowText string
	err = pool.QueryRow(ctx, "SELECT secret_hash, s::text FROM console_sessions s WHERE id = $1", tok.ID).Scan(&storedHash, &rowText)
	if err != nil {
		t.Fatal(err)
	}

	want := sha256.Sum256(tok.secret[:])
	if !bytes.Equal(storedHash, want[:]) {
		t.Fatal("secret_hash is not the SHA-256 of the secret")
	}

	for _, form := range []string{
		hex.EncodeToString(tok.secret[:]),
		base64.RawURLEncoding.EncodeToString(tok.secret[:]),
		base64.StdEncoding.EncodeToString(tok.secret[:]),
	} {
		if strings.Contains(rowText, form) {
			t.Fatalf("the session row contains the raw secret (%s)", form)
		}
	}
}

func TestCreateTxUnique(t *testing.T) {
	_, pool := newTestStore(t)

	a := createSession(t, pool, userAID)
	b := createSession(t, pool, userAID)
	if a.ID == b.ID {
		t.Fatal("two sessions got the same id")
	}
	if a.secret == b.secret {
		t.Fatal("two sessions got the same secret")
	}
}

func TestCreateTxRollback(t *testing.T) {
	_, pool := newTestStore(t)
	ctx := context.Background()

	errAbort := errors.New("abort")
	var tok Token
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		tok, err = CreateTx(ctx, tx, mustUUID(t, userAID))
		if err != nil {
			return err
		}
		return errAbort
	})
	if !errors.Is(err, errAbort) {
		t.Fatalf("expected the abort error, got %v", err)
	}

	if sessionExists(t, pool, tok.ID) {
		t.Fatal("a session created in a rolled back transaction exists")
	}
}

func TestLookup(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	tok := createSession(t, pool, userAID)

	sess, err := store.Lookup(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID != tok.ID || sess.UserID != mustUUID(t, userAID) {
		t.Fatalf("unexpected session: %+v", sess)
	}
	if sess.OrgSelected || sess.SelectedOrgID != nil || sess.TouchDue || sess.HasFlashes {
		t.Fatalf("unexpected flags on a new session: %+v", sess)
	}

	wrongSecret := tok
	wrongSecret.secret[0] ^= 0xff
	if _, err := store.Lookup(ctx, wrongSecret); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("wrong secret: want ErrBadSecret, got %v", err)
	}
	if !sessionExists(t, pool, tok.ID) {
		t.Fatal("a wrong secret deleted the session")
	}

	idOnly := Token{ID: tok.ID}
	if _, err := store.Lookup(ctx, idOnly); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("id without its secret: want ErrBadSecret, got %v", err)
	}

	unknown := tok
	unknown.ID = pgtype.UUID{Bytes: uuid.NewV4(), Valid: true}
	if _, err := store.Lookup(ctx, unknown); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: want ErrNotFound, got %v", err)
	}
}

// The idle timeout (30m), absolute timeout (8h) and touch interval (1m)
// have different values, so a query that passes them in the wrong
// positions fails a case.
func TestLookupFlags(t *testing.T) {
	store, pool := newTestStore(t)

	tests := []struct {
		name     string
		lastSeen time.Duration
		created  time.Duration
		idle     bool
		absolute bool
		touch    bool
	}{
		{name: "fresh"},
		{name: "touch due", lastSeen: 2 * time.Minute, created: 2 * time.Minute, touch: true},
		{name: "idle expired", lastSeen: 45 * time.Minute, created: 45 * time.Minute, idle: true, touch: true},
		{name: "absolute expired", created: 9 * time.Hour, absolute: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tok := createSession(t, pool, userAID)
			ageSession(t, pool, tok.ID, test.lastSeen, test.created)

			row, err := store.lookupRow(context.Background(), tok.ID)
			if err != nil {
				t.Fatal(err)
			}
			if row.idleExpired != test.idle || row.absoluteExpired != test.absolute || row.session.TouchDue != test.touch {
				t.Fatalf("got idle=%t absolute=%t touch=%t, want idle=%t absolute=%t touch=%t",
					row.idleExpired, row.absoluteExpired, row.session.TouchDue, test.idle, test.absolute, test.touch)
			}
		})
	}
}

func TestLookupExpiry(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	tests := []struct {
		name     string
		lastSeen time.Duration
		created  time.Duration
		want     error
	}{
		{name: "idle", lastSeen: 31 * time.Minute, created: 31 * time.Minute, want: ErrIdleExpired},
		{name: "absolute", created: 8*time.Hour + time.Minute, want: ErrAbsoluteExpired},
		{name: "both, absolute wins", lastSeen: 9 * time.Hour, created: 9 * time.Hour, want: ErrAbsoluteExpired},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tok := createSession(t, pool, userAID)
			ageSession(t, pool, tok.ID, test.lastSeen, test.created)

			sess, err := store.Lookup(ctx, tok)
			if !errors.Is(err, test.want) {
				t.Fatalf("want %v, got %v", test.want, err)
			}
			if sess.UserID != mustUUID(t, userAID) {
				t.Fatal("an expired lookup must report the session's user for logging")
			}
			if sessionExists(t, pool, tok.ID) {
				t.Fatal("the expired session was not deleted")
			}
		})
	}
}

func TestLoweredTimeoutsApplyToExistingSessions(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	idle := createSession(t, pool, userAID)
	ageSession(t, pool, idle.ID, 20*time.Minute, 2*time.Hour)
	if _, err := store.Lookup(ctx, idle); err != nil {
		t.Fatalf("with a 30m idle timeout: %v", err)
	}

	lowerIdle, err := NewStore(pool, 10*time.Minute, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lowerIdle.Lookup(ctx, idle); !errors.Is(err, ErrIdleExpired) {
		t.Fatalf("with a 10m idle timeout: want ErrIdleExpired, got %v", err)
	}

	absolute := createSession(t, pool, userAID)
	ageSession(t, pool, absolute.ID, 0, 2*time.Hour)

	lowerAbsolute, err := NewStore(pool, 30*time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lowerAbsolute.Lookup(ctx, absolute); !errors.Is(err, ErrAbsoluteExpired) {
		t.Fatalf("with a 1h absolute timeout: want ErrAbsoluteExpired, got %v", err)
	}
}

func TestTouch(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	tok := createSession(t, pool, userAID)
	ageSession(t, pool, tok.ID, 2*time.Minute, 2*time.Minute)

	sess, err := store.Lookup(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if !sess.TouchDue {
		t.Fatal("expected TouchDue after 2 minutes")
	}

	if err := store.Touch(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}

	sess, err = store.Lookup(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if sess.TouchDue {
		t.Fatal("TouchDue still set after Touch")
	}

	// A second Touch within touchInterval, e.g. from a concurrent request
	// that also saw TouchDue, must not write. Every statement here gets
	// its own now(), so a write would change last_seen.
	touched := lastSeen(t, pool, tok.ID)
	if err := store.Touch(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	if got := lastSeen(t, pool, tok.ID); !got.Equal(touched) {
		t.Fatalf("second Touch changed last_seen from %s to %s", touched, got)
	}
}

func TestDestroy(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	tok := createSession(t, pool, userAID)

	wrong := tok
	wrong.secret[0] ^= 0xff
	if _, err := store.Destroy(ctx, wrong); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("wrong secret: want ErrBadSecret, got %v", err)
	}
	if !sessionExists(t, pool, tok.ID) {
		t.Fatal("a wrong secret destroyed the session")
	}

	userID, err := store.Destroy(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if userID != mustUUID(t, userAID) {
		t.Fatalf("Destroy returned user %s, want %s", userID.String(), userAID)
	}
	if sessionExists(t, pool, tok.ID) {
		t.Fatal("the session still exists after Destroy")
	}

	if _, err := store.Destroy(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Destroy: want ErrNotFound, got %v", err)
	}
}

func TestDeleteForUserTx(t *testing.T) {
	_, pool := newTestStore(t)
	ctx := context.Background()

	a1 := createSession(t, pool, userAID)
	a2 := createSession(t, pool, userAID)
	b := createSession(t, pool, userBID)

	// A rolled back transaction deletes nothing
	errAbort := errors.New("abort")
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		n, err := DeleteForUserTx(ctx, tx, mustUUID(t, userAID))
		if err != nil {
			return err
		}
		if n != 2 {
			t.Errorf("deleted %d sessions, want 2", n)
		}
		return errAbort
	})
	if !errors.Is(err, errAbort) {
		t.Fatalf("expected the abort error, got %v", err)
	}
	if !sessionExists(t, pool, a1.ID) || !sessionExists(t, pool, a2.ID) {
		t.Fatal("a rolled back DeleteForUserTx removed sessions")
	}

	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := DeleteForUserTx(ctx, tx, mustUUID(t, userAID))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if sessionExists(t, pool, a1.ID) || sessionExists(t, pool, a2.ID) {
		t.Fatal("the user's sessions still exist")
	}
	if !sessionExists(t, pool, b.ID) {
		t.Fatal("another user's session was deleted")
	}
}

func TestSelectedOrg(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()
	tok := createSession(t, pool, userAID)
	orgA := mustUUID(t, orgAID)

	lookup := func(t *testing.T) Session {
		t.Helper()
		sess, err := store.Lookup(ctx, tok)
		if err != nil {
			t.Fatal(err)
		}
		return sess
	}

	if sess := lookup(t); sess.OrgSelected || sess.SelectedOrgID != nil {
		t.Fatalf("new session: %+v", sess)
	}

	if err := store.SetSelectedOrg(ctx, tok.ID, nil); err != nil {
		t.Fatal(err)
	}
	if sess := lookup(t); !sess.OrgSelected || sess.SelectedOrgID != nil {
		t.Fatalf("explicitly no org: %+v", sess)
	}

	if err := store.SetSelectedOrg(ctx, tok.ID, &orgA); err != nil {
		t.Fatal(err)
	}
	if sess := lookup(t); !sess.OrgSelected || sess.SelectedOrgID == nil || *sess.SelectedOrgID != orgA {
		t.Fatalf("org a selected: %+v", sess)
	}

	execSQL(t, pool, "DELETE FROM orgs WHERE id = $1", orgAID)
	if sess := lookup(t); !sess.OrgSelected || sess.SelectedOrgID != nil {
		t.Fatalf("after deleting the selected org: %+v", sess)
	}

	// The database refuses a selected org without the flag
	_, err := pool.Exec(ctx, "UPDATE console_sessions SET org_selected = false, selected_org_id = $2 WHERE id = $1", tok.ID, orgBID)
	if err == nil {
		t.Fatal("a selected org without org_selected was accepted")
	}
}

func TestSweep(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	fresh := createSession(t, pool, userAID)
	idle := createSession(t, pool, userAID)
	ageSession(t, pool, idle.ID, 31*time.Minute, 31*time.Minute)
	absolute := createSession(t, pool, userBID)
	ageSession(t, pool, absolute.ID, 0, 8*time.Hour+time.Minute)
	// Used just now but created an hour ago: only the absolute timeout
	// (8h) and the idle timeout (measured from last_seen) apply, so it
	// must survive. Swapped timeouts in Sweep would delete it.
	longLived := createSession(t, pool, userBID)
	ageSession(t, pool, longLived.ID, 0, time.Hour)

	addFlash(t, store, fresh.ID, "cat", nil, "stale")
	execSQL(t, pool, "UPDATE console_session_flashes SET time_created = now() - $1::interval WHERE message = 'stale'", 6*time.Minute)
	addFlash(t, store, fresh.ID, "cat", nil, "fresh")

	sessions, flashes, err := store.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sessions != 2 || flashes != 1 {
		t.Fatalf("deleted %d sessions and %d flash messages, want 2 and 1", sessions, flashes)
	}

	if !sessionExists(t, pool, fresh.ID) || !sessionExists(t, pool, longLived.ID) || sessionExists(t, pool, idle.ID) || sessionExists(t, pool, absolute.ID) {
		t.Fatal("Sweep kept an expired session or removed a valid one")
	}
	if got := popFlashes(t, store, fresh.ID, "cat", nil); !slices.Equal(got, []string{"fresh"}) {
		t.Fatalf("after Sweep: got %q, want only the fresh message", got)
	}
}
