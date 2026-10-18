package consolesession

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func addFlash(t *testing.T, store *Store, sessionID pgtype.UUID, category FlashCategory, orgID *pgtype.UUID, message string) {
	t.Helper()
	if err := store.AddFlash(context.Background(), sessionID, category, orgID, message); err != nil {
		t.Fatal(err)
	}
}

func popFlashes(t *testing.T, store *Store, sessionID pgtype.UUID, category FlashCategory, orgID *pgtype.UUID) []string {
	t.Helper()
	messages, err := store.PopFlashes(context.Background(), sessionID, category, orgID)
	if err != nil {
		t.Fatal(err)
	}
	return messages
}

func countFlashes(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), "SELECT count(*) FROM console_session_flashes").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPopFlashesOnceOldestFirst(t *testing.T) {
	store, pool := newTestStore(t)
	tok := createSession(t, pool, userAID)

	// Added in another order than their time_created, the result must
	// follow time_created.
	addFlash(t, store, tok.ID, "cat", nil, "second")
	addFlash(t, store, tok.ID, "cat", nil, "first")
	addFlash(t, store, tok.ID, "cat", nil, "third")
	for message, age := range map[string]time.Duration{"first": 3 * time.Minute, "second": 2 * time.Minute, "third": time.Minute} {
		execSQL(t, pool, "UPDATE console_session_flashes SET time_created = now() - $1::interval WHERE message = $2", age, message)
	}

	if got := popFlashes(t, store, tok.ID, "cat", nil); !slices.Equal(got, []string{"first", "second", "third"}) {
		t.Fatalf("got %q, want first, second, third", got)
	}
	if got := popFlashes(t, store, tok.ID, "cat", nil); len(got) != 0 {
		t.Fatalf("flash messages shown twice: %q", got)
	}
}

func TestFlashScoping(t *testing.T) {
	store, pool := newTestStore(t)
	tok := createSession(t, pool, userAID)
	orgA := mustUUID(t, orgAID)
	orgB := mustUUID(t, orgBID)

	addFlash(t, store, tok.ID, "cat", &orgA, "org a")
	addFlash(t, store, tok.ID, "cat", &orgB, "org b")
	addFlash(t, store, tok.ID, "cat", nil, "global")
	addFlash(t, store, tok.ID, "other", nil, "other category")

	if got := popFlashes(t, store, tok.ID, "cat", &orgB); !slices.Equal(got, []string{"org b"}) {
		t.Fatalf("org b: got %q", got)
	}
	if got := popFlashes(t, store, tok.ID, "cat", nil); !slices.Equal(got, []string{"global"}) {
		t.Fatalf("global: got %q", got)
	}
	if got := popFlashes(t, store, tok.ID, "cat", &orgA); !slices.Equal(got, []string{"org a"}) {
		t.Fatalf("org a: got %q", got)
	}
	if got := popFlashes(t, store, tok.ID, "other", nil); !slices.Equal(got, []string{"other category"}) {
		t.Fatalf("other category: got %q", got)
	}

	// Another session of the same user does not see them
	other := createSession(t, pool, userAID)
	addFlash(t, store, tok.ID, "cat", nil, "mine")
	if got := popFlashes(t, store, other.ID, "cat", nil); len(got) != 0 {
		t.Fatalf("another session got %q", got)
	}
}

// The flash lifetime (5m) differs from the touch interval (1m) and the
// timeouts, so a query that passes them in the wrong positions fails here.
func TestStaleFlashes(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()
	tok := createSession(t, pool, userAID)

	addFlash(t, store, tok.ID, "cat", nil, "stale")
	execSQL(t, pool, "UPDATE console_session_flashes SET time_created = now() - $1::interval WHERE message = 'stale'", 6*time.Minute)

	row, err := store.lookupRow(ctx, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.session.HasFlashes {
		t.Fatal("a 6 minute old flash counts for HasFlashes")
	}

	addFlash(t, store, tok.ID, "cat", nil, "fresh")
	execSQL(t, pool, "UPDATE console_session_flashes SET time_created = now() - $1::interval WHERE message = 'fresh'", 3*time.Minute)

	row, err = store.lookupRow(ctx, tok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !row.session.HasFlashes {
		t.Fatal("a 3 minute old flash does not count for HasFlashes")
	}

	if got := popFlashes(t, store, tok.ID, "cat", nil); !slices.Equal(got, []string{"fresh"}) {
		t.Fatalf("got %q, want only the fresh message", got)
	}
	if n := countFlashes(t, pool); n != 0 {
		t.Fatalf("popping must also delete the stale message, %d left", n)
	}
}

func TestAddFlashTargetGone(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	ended := createSession(t, pool, userAID)
	if _, err := store.Destroy(ctx, ended); err != nil {
		t.Fatal(err)
	}
	if err := store.AddFlash(ctx, ended.ID, "cat", nil, "msg"); !errors.Is(err, ErrFlashTargetGone) {
		t.Fatalf("ended session: want ErrFlashTargetGone, got %v", err)
	}

	live := createSession(t, pool, userAID)
	unknownOrg := pgtype.UUID{Bytes: uuid.NewV4(), Valid: true}
	if err := store.AddFlash(ctx, live.ID, "cat", &unknownOrg, "msg"); !errors.Is(err, ErrFlashTargetGone) {
		t.Fatalf("unknown org: want ErrFlashTargetGone, got %v", err)
	}
}

func TestDeletesCascade(t *testing.T) {
	store, pool := newTestStore(t)
	ctx := context.Background()

	// Ending a session removes its flash messages
	tok := createSession(t, pool, userAID)
	addFlash(t, store, tok.ID, "cat", nil, "msg")
	if _, err := store.Destroy(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if n := countFlashes(t, pool); n != 0 {
		t.Fatalf("%d flash messages left after the session ended", n)
	}

	// Deleting a user removes their sessions and those sessions' messages
	tok = createSession(t, pool, userAID)
	addFlash(t, store, tok.ID, "cat", nil, "msg")
	execSQL(t, pool, "DELETE FROM users WHERE id = $1", userAID)
	if sessionExists(t, pool, tok.ID) {
		t.Fatal("a deleted user's session still exists")
	}
	if n := countFlashes(t, pool); n != 0 {
		t.Fatalf("%d flash messages left after the user was deleted", n)
	}
}
