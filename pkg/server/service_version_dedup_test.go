package server

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5/pgxpool"
)

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

// TestPostServiceVersionDuplicateReturnsExisting submits content that only
// differs from an existing version in the order of its sets and in its
// description, and expects that version back instead of a new one.
func TestPostServiceVersionDuplicateReturnsExisting(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "dedup-existing", 1000960000)

	status, first := postVersion(t, serverURL, serviceID, baseVersionBody())
	if status != http.StatusCreated {
		t.Fatalf("first POST returned %d, want %d", status, http.StatusCreated)
	}

	again := baseVersionBody()
	again.Domains = []string{"example.se", "example.com"}
	origins := again.ConditionalOriginGroups[0].Origins
	again.ConditionalOriginGroups[0].Origins = []cdntypes.InputOrigin{origins[1], origins[0]}
	again.Description = "second"

	status, second := postVersion(t, serverURL, serviceID, again)
	if status != http.StatusOK {
		t.Fatalf("identical POST returned %d, want %d", status, http.StatusOK)
	}
	if second.ID != first.ID || second.Version != first.Version {
		t.Fatalf("identical POST returned version %d (%s), want the existing version %d (%s)", second.Version, second.ID, first.Version, first.ID)
	}
	if second.Description != "first" {
		t.Fatalf("identical POST returned description %q, want the stored %q", second.Description, "first")
	}
	if n := serviceVersionCount(t, dbPool, serviceID); n != 1 {
		t.Fatalf("service has %d versions, want 1", n)
	}

	changed := baseVersionBody()
	changed.DefaultOriginGroup.Origins[0].Port = 8443
	status, third := postVersion(t, serverURL, serviceID, changed)
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
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "dedup-activation", 1000970000)

	a := baseVersionBody()
	b := baseVersionBody()
	b.DefaultOriginGroup.Origins[0].Port = 8443
	b.Active = true

	status, va := postVersion(t, serverURL, serviceID, a)
	if status != http.StatusCreated {
		t.Fatalf("POST of A returned %d, want %d", status, http.StatusCreated)
	}
	status, vb := postVersion(t, serverURL, serviceID, b)
	if status != http.StatusCreated {
		t.Fatalf("POST of B returned %d, want %d", status, http.StatusCreated)
	}
	if active := activeServiceVersion(t, dbPool, serviceID); active != vb.Version {
		t.Fatalf("active version is %d, want B (%d)", active, vb.Version)
	}

	a.Active = true
	status, got := postVersion(t, serverURL, serviceID, a)
	if status != http.StatusOK {
		t.Fatalf("active POST of A again returned %d, want %d", status, http.StatusOK)
	}
	if got.Version != va.Version || !got.Active {
		t.Fatalf("active POST of A again returned version %d active=%t, want version %d active", got.Version, got.Active, va.Version)
	}
	if active := activeServiceVersion(t, dbPool, serviceID); active != va.Version {
		t.Fatalf("active version is %d, want A (%d)", active, va.Version)
	}

	// Already active: still answered with the version, still active.
	status, got = postVersion(t, serverURL, serviceID, a)
	if status != http.StatusOK || !got.Active {
		t.Fatalf("repeated active POST of A returned %d active=%t, want %d active", status, got.Active, http.StatusOK)
	}

	// Not asking for activation leaves the active version alone, even when
	// it is the one matched.
	a.Active = false
	status, got = postVersion(t, serverURL, serviceID, a)
	if status != http.StatusOK || !got.Active {
		t.Fatalf("inactive POST of the active A returned %d active=%t, want %d active", status, got.Active, http.StatusOK)
	}
	if active := activeServiceVersion(t, dbPool, serviceID); active != va.Version {
		t.Fatalf("active version is %d, want A (%d)", active, va.Version)
	}

	// Nor does matching another version: B comes back as it is, inactive,
	// and A stays active.
	b.Active = false
	status, got = postVersion(t, serverURL, serviceID, b)
	if status != http.StatusOK || got.Version != vb.Version || got.Active {
		t.Fatalf("inactive POST of B again returned %d version %d active=%t, want %d version %d inactive", status, got.Version, got.Active, http.StatusOK, vb.Version)
	}
	if active := activeServiceVersion(t, dbPool, serviceID); active != va.Version {
		t.Fatalf("active version is %d, want A (%d)", active, va.Version)
	}

	if n := serviceVersionCount(t, dbPool, serviceID); n != 2 {
		t.Fatalf("service has %d versions, want 2", n)
	}
}

// TestPostServiceVersionConcurrentDuplicates checks that two identical
// submissions arriving together give one new version and the existing one
// back. That depends on inserts for a service being serialized on its row
// lock: the second must not look for a match until the first has committed.
func TestPostServiceVersionConcurrentDuplicates(t *testing.T) {
	rs := prepareRaceServer(t)
	serviceID := newEmptyService(t, rs.dbPool, "dedup-concurrent", 1000980000)

	statuses := rs.postRacingVersions(t, serviceID, [2]string{"198.51.100.20", "198.51.100.20"})

	if statuses[http.StatusCreated] != 1 || statuses[http.StatusOK] != 1 {
		t.Fatalf("got statuses %v, want one %d and one %d", statuses, http.StatusCreated, http.StatusOK)
	}
	if n := serviceVersionCount(t, rs.dbPool, serviceID); n != 1 {
		t.Fatalf("service has %d versions, want 1", n)
	}
}

// TestConsoleCreateServiceVersionDuplicate submits the create-version form
// with content identical to an existing version and expects the form back
// with a pointer to that version instead of a new version.
func TestConsoleCreateServiceVersionDuplicate(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "dedup-console", 1000990000)

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
	if n := serviceVersionCount(t, dbPool, serviceID); n != 1 {
		t.Fatalf("service has %d versions, want 1", n)
	}
}
