package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

const dedupOrg1ID = "00000002-0000-0000-0000-000000000001"

// dedupVersionBody is the API body for creating a service version.
type dedupVersionBody struct {
	Org                     string                                 `json:"org"`
	Domains                 []string                               `json:"domains"`
	ConditionalOriginGroups []cdntypes.InputConditionalOriginGroup `json:"conditional_origin_groups,omitempty"`
	DefaultOriginGroup      cdntypes.InputDefaultOriginGroup       `json:"default_origin_group"`
	VCLTemplate             string                                 `json:"vcl_template"`
	Active                  bool                                   `json:"active,omitempty"`
	Description             string                                 `json:"description,omitempty"`
}

func dedupBaseBody() dedupVersionBody {
	return dedupVersionBody{
		Org:     dedupOrg1ID,
		Domains: []string{"example.com", "example.se"},
		ConditionalOriginGroups: []cdntypes.InputConditionalOriginGroup{
			{
				Name:      "api",
				Condition: `req.url ~ "^/api"`,
				Origins: []cdntypes.InputOrigin{
					{Host: "198.51.100.30", Port: 443, TLS: true, VerifyTLS: true},
					{Host: "198.51.100.31", Port: 80},
				},
			},
		},
		DefaultOriginGroup: cdntypes.InputDefaultOriginGroup{
			Origins: []cdntypes.InputOrigin{{Host: "198.51.100.32", Port: 443, TLS: true}},
		},
		VCLTemplate: cdntypes.DefaultVCLTemplate,
		Description: "first",
	}
}

// newDedupService adds an empty service to org1, so a test starts with no
// versions to collide with.
func newDedupService(t *testing.T, dbPool *pgxpool.Pool, name string, uidLow int) string {
	t.Helper()

	var serviceID string
	err := dbPool.QueryRow(context.Background(),
		"INSERT INTO services (org_id, name, uid_range) VALUES ($1, $2, int8range($3, $4)) RETURNING id",
		dedupOrg1ID, name, uidLow, uidLow+10000).Scan(&serviceID)
	if err != nil {
		t.Fatal(err)
	}
	return serviceID
}

func postDedupVersion(t *testing.T, serverURL string, serviceID string, body dedupVersionBody) (int, cdntypes.ServiceVersion) {
	t.Helper()

	status, respBody := apiJSON(t, http.MethodPost, serverURL+"/api/v1/services/"+serviceID+"/service-versions", "admin", validAdminPassword, body)
	var sv cdntypes.ServiceVersion
	if status == http.StatusOK || status == http.StatusCreated {
		if err := json.Unmarshal([]byte(respBody), &sv); err != nil {
			t.Fatalf("unable to decode response %q: %s", respBody, err)
		}
	} else {
		t.Logf("response body: %s", respBody)
	}
	return status, sv
}

func dedupVersionCount(t *testing.T, dbPool *pgxpool.Pool, serviceID string) int {
	t.Helper()

	var n int
	err := dbPool.QueryRow(context.Background(), "SELECT count(*) FROM service_versions WHERE service_id = $1", serviceID).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// dedupActiveVersion returns the service's active version number, or 0 when
// no version is active, so callers report that as a wrong version.
func dedupActiveVersion(t *testing.T, dbPool *pgxpool.Pool, serviceID string) int64 {
	t.Helper()

	var version int64
	err := dbPool.QueryRow(context.Background(), "SELECT version FROM service_versions WHERE service_id = $1 AND active", serviceID).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return version
}

// assertStoredHashesCurrent checks that every version created through the
// manager stored the hash the database function computes from its rows.
func assertStoredHashesCurrent(t *testing.T, dbPool *pgxpool.Pool, serviceID string) {
	t.Helper()

	var stale int
	err := dbPool.QueryRow(context.Background(),
		"SELECT count(*) FROM service_versions WHERE service_id = $1 AND content_hash IS DISTINCT FROM service_version_content_hash(id)",
		serviceID).Scan(&stale)
	if err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("%d versions have a content_hash that does not match their content", stale)
	}
}

func prepareDedupServer(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()

	validator := newBlockingValidator(t)
	// Every VCL is accepted at once: the content is not what these tests
	// are about.
	validator.release()

	ts, dbPool, err := prepareServer(t, testServerInput{vclValidator: validator.client})
	if dbPool != nil {
		t.Cleanup(dbPool.Close)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ts.Close)

	return ts.URL, dbPool
}

// TestPostServiceVersionDuplicateReturnsExisting submits content that only
// differs from an existing version in the order of its sets and in its
// description, and expects that version back instead of a new one.
func TestPostServiceVersionDuplicateReturnsExisting(t *testing.T) {
	serverURL, dbPool := prepareDedupServer(t)
	serviceID := newDedupService(t, dbPool, "dedup-existing", 1000960000)

	status, first := postDedupVersion(t, serverURL, serviceID, dedupBaseBody())
	if status != http.StatusCreated {
		t.Fatalf("first POST returned %d, want %d", status, http.StatusCreated)
	}

	again := dedupBaseBody()
	again.Domains = []string{"example.se", "example.com"}
	origins := again.ConditionalOriginGroups[0].Origins
	again.ConditionalOriginGroups[0].Origins = []cdntypes.InputOrigin{origins[1], origins[0]}
	again.Description = "second"

	status, second := postDedupVersion(t, serverURL, serviceID, again)
	if status != http.StatusOK {
		t.Fatalf("identical POST returned %d, want %d", status, http.StatusOK)
	}
	if second.ID != first.ID || second.Version != first.Version {
		t.Fatalf("identical POST returned version %d (%s), want the existing version %d (%s)", second.Version, second.ID, first.Version, first.ID)
	}
	if second.Description != "first" {
		t.Fatalf("identical POST returned description %q, want the stored %q", second.Description, "first")
	}
	if n := dedupVersionCount(t, dbPool, serviceID); n != 1 {
		t.Fatalf("service has %d versions, want 1", n)
	}

	changed := dedupBaseBody()
	changed.DefaultOriginGroup.Origins[0].Port = 8443
	status, third := postDedupVersion(t, serverURL, serviceID, changed)
	if status != http.StatusCreated {
		t.Fatalf("changed POST returned %d, want %d", status, http.StatusCreated)
	}
	// The duplicate did not use up a version number.
	if third.Version != first.Version+1 {
		t.Fatalf("changed POST created version %d, want %d", third.Version, first.Version+1)
	}

	assertStoredHashesCurrent(t, dbPool, serviceID)
}

// TestPostServiceVersionDuplicateActivation checks that asking for an
// identical version to be active activates the existing one, and that a
// duplicate never deactivates anything, whether it matches the active
// version or another one.
func TestPostServiceVersionDuplicateActivation(t *testing.T) {
	serverURL, dbPool := prepareDedupServer(t)
	serviceID := newDedupService(t, dbPool, "dedup-activation", 1000970000)

	a := dedupBaseBody()
	b := dedupBaseBody()
	b.DefaultOriginGroup.Origins[0].Port = 8443
	b.Active = true

	status, va := postDedupVersion(t, serverURL, serviceID, a)
	if status != http.StatusCreated {
		t.Fatalf("POST of A returned %d, want %d", status, http.StatusCreated)
	}
	status, vb := postDedupVersion(t, serverURL, serviceID, b)
	if status != http.StatusCreated {
		t.Fatalf("POST of B returned %d, want %d", status, http.StatusCreated)
	}
	if active := dedupActiveVersion(t, dbPool, serviceID); active != vb.Version {
		t.Fatalf("active version is %d, want B (%d)", active, vb.Version)
	}

	a.Active = true
	status, got := postDedupVersion(t, serverURL, serviceID, a)
	if status != http.StatusOK {
		t.Fatalf("active POST of A again returned %d, want %d", status, http.StatusOK)
	}
	if got.Version != va.Version || !got.Active {
		t.Fatalf("active POST of A again returned version %d active=%t, want version %d active", got.Version, got.Active, va.Version)
	}
	if active := dedupActiveVersion(t, dbPool, serviceID); active != va.Version {
		t.Fatalf("active version is %d, want A (%d)", active, va.Version)
	}

	// Already active: still answered with the version, still active.
	status, got = postDedupVersion(t, serverURL, serviceID, a)
	if status != http.StatusOK || !got.Active {
		t.Fatalf("repeated active POST of A returned %d active=%t, want %d active", status, got.Active, http.StatusOK)
	}

	// Not asking for activation leaves the active version alone, even when
	// it is the one matched.
	a.Active = false
	status, got = postDedupVersion(t, serverURL, serviceID, a)
	if status != http.StatusOK || !got.Active {
		t.Fatalf("inactive POST of the active A returned %d active=%t, want %d active", status, got.Active, http.StatusOK)
	}
	if active := dedupActiveVersion(t, dbPool, serviceID); active != va.Version {
		t.Fatalf("active version is %d, want A (%d)", active, va.Version)
	}

	// Nor does matching another version: B comes back as it is, inactive,
	// and A stays active.
	b.Active = false
	status, got = postDedupVersion(t, serverURL, serviceID, b)
	if status != http.StatusOK || got.Version != vb.Version || got.Active {
		t.Fatalf("inactive POST of B again returned %d version %d active=%t, want %d version %d inactive", status, got.Version, got.Active, http.StatusOK, vb.Version)
	}
	if active := dedupActiveVersion(t, dbPool, serviceID); active != va.Version {
		t.Fatalf("active version is %d, want A (%d)", active, va.Version)
	}

	if n := dedupVersionCount(t, dbPool, serviceID); n != 2 {
		t.Fatalf("service has %d versions, want 2", n)
	}
}

// TestPostServiceVersionConcurrentDuplicates checks that two identical
// submissions arriving together give one new version and the existing one
// back. That depends on inserts for a service being serialized on its row
// lock: the second must not look for a match until the first has committed.
//
// The shared test pool has a single connection, which would run the two
// write transactions one after the other however the manager locks. The
// server gets a pool of its own with room for both, and a transaction from
// holdPool holds the service row until both are waiting for it, so they
// contend for the lock rather than happen to run in turn.
func TestPostServiceVersionConcurrentDuplicates(t *testing.T) {
	ctx := context.Background()
	validator := newBlockingValidator(t)

	dbPool, err := initDatabase(ctx, t, zerolog.New(zerolog.NewTestWriter(t)), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dbPool.Close)

	newPool := func(maxConns int32) *pgxpool.Pool {
		cfg := dbPool.Config().Copy()
		cfg.MaxConns = maxConns
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	}
	serverPool := newPool(2)
	// One connection holds the service row, the other watches who waits
	// for it.
	holdPool := newPool(2)

	ts, _, err := prepareServer(t, testServerInput{vclValidator: validator.client, dbPool: serverPool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ts.Close)

	serviceID := newDedupService(t, dbPool, "dedup-concurrent", 1000980000)

	first := postServiceVersionAsync(ctx, ts.URL, "admin", validAdminPassword, serviceID)
	second := postServiceVersionAsync(ctx, ts.URL, "admin", validAdminPassword, serviceID)
	waitForSignal(t, validator.seen, "the first validator request")
	waitForSignal(t, validator.seen, "the second validator request while the first is still held")

	// Taken only now: the lookup before validation reads the service row
	// too, and must not be what waits.
	hold, err := holdPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Normally already committed, this covers an early t.Fatal().
		if err := hold.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Logf("rollback during cleanup: %v", err)
		}
	})
	if _, err := hold.Exec(ctx, "SELECT 1 FROM services WHERE id = $1 FOR UPDATE", serviceID); err != nil {
		t.Fatal(err)
	}

	validator.release()

	// The held transaction is idle, so the backends waiting for a lock can
	// only be the two submissions. Only the first waits for the holder
	// directly: the second queues behind it for the same row, so
	// pg_blocking_pids() would name the first submission, not the holder.
	deadline := time.Now().Add(promptLimit)
	for {
		var waiting int
		err := holdPool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'").Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting == 2 {
			break
		}
		select {
		case res := <-first:
			t.Fatalf("a submission finished without waiting for the service row: status %d, err %v", res.status, res.err)
		case res := <-second:
			t.Fatalf("a submission finished without waiting for the service row: status %d, err %v", res.status, res.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of 2 submissions are waiting for the service row", waiting)
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := hold.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	statuses := map[int]int{}
	for _, resCh := range []<-chan postResult{first, second} {
		res := waitForPost(t, resCh)
		if res.err != nil {
			t.Fatal(res.err)
		}
		statuses[res.status]++
	}

	if statuses[http.StatusCreated] != 1 || statuses[http.StatusOK] != 1 {
		t.Fatalf("got statuses %v, want one %d and one %d", statuses, http.StatusCreated, http.StatusOK)
	}
	if n := dedupVersionCount(t, dbPool, serviceID); n != 1 {
		t.Fatalf("service has %d versions, want 1", n)
	}
}

// TestConsoleCreateServiceVersionDuplicate submits the create-version form
// with content identical to an existing version and expects the form back
// with a pointer to that version instead of a new version.
func TestConsoleCreateServiceVersionDuplicate(t *testing.T) {
	serverURL, dbPool := prepareDedupServer(t)
	serviceID := newDedupService(t, dbPool, "dedup-console", 1000990000)

	client, _ := consoleLogin(t, serverURL, "username1", validUserPassword)

	submit := func(t *testing.T) (int, string) {
		t.Helper()

		req, err := http.NewRequest(http.MethodPost, serverURL+"/console/org/org1/create/service/version/"+serviceID, strings.NewReader(createVersionForm().Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}

	// The client follows the redirect to the service page, so the
	// first submission is judged by the version it created.
	status, body := submit(t)
	if status != http.StatusOK || strings.Contains(body, `id="error-message"`) {
		t.Fatalf("first submission returned %d with an error: %s", status, body)
	}

	var version int64
	err := dbPool.QueryRow(context.Background(), "SELECT version FROM service_versions WHERE service_id = $1", serviceID).Scan(&version)
	if err != nil {
		t.Fatal(err)
	}

	status, body = submit(t)
	if status != http.StatusOK {
		t.Fatalf("identical submission returned %d, want the form again (%d)", status, http.StatusOK)
	}
	if want := fmt.Sprintf("Identical to version %d", version); !strings.Contains(body, want) {
		t.Fatalf("identical submission page does not contain %q: %s", want, body)
	}
	if link := fmt.Sprintf(`href="/console/org/org1/services/%s/%d"`, serviceID, version); !strings.Contains(body, link) {
		t.Fatalf("identical submission page does not link to the version with %s: %s", link, body)
	}
	if n := dedupVersionCount(t, dbPool, serviceID); n != 1 {
		t.Fatalf("service has %d versions, want 1", n)
	}
}
