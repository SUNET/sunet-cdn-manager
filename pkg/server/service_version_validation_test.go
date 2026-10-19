package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5/pgxpool"
)

// blockingValidator stands in for sunet-vcl-validator. It accepts any VCL but
// holds each request until release is called, giving a test a window in which
// insertServiceVersion is known to be waiting on the validator.
type blockingValidator struct {
	client *vclValidatorClient
	// seen receives a value for every request that reaches the validator.
	seen chan struct{}
	// cancelled receives a value for every request the manager abandons
	// before release.
	cancelled chan struct{}
	// release lets all current and future requests through. Safe to call
	// more than once.
	release func()
}

func newBlockingValidator(t *testing.T) *blockingValidator {
	t.Helper()

	releaseCh := make(chan struct{})
	var once sync.Once
	bv := &blockingValidator{
		seen:      make(chan struct{}, 8),
		cancelled: make(chan struct{}, 8),
		release:   func() { once.Do(func() { close(releaseCh) }) },
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the VCL as the real validator does. net/http only starts
		// watching for the client going away once the body has been read
		// to EOF, so without this r.Context() is never cancelled.
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		bv.seen <- struct{}{}
		select {
		case <-releaseCh:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
			bv.cancelled <- struct{}{}
		}
	}))
	// Cleanups run last-registered-first, so the handler is released
	// before Close waits for it.
	t.Cleanup(srv.Close)
	t.Cleanup(bv.release)

	u, err := url.Parse(srv.URL + "/validate-vcl")
	if err != nil {
		t.Fatal(err)
	}
	bv.client = newVclValidator(u)

	return bv
}

// newProbePool opens a second pool against the test database. The shared test
// pool is capped at one connection, so while a request holds a transaction a
// query through it would wait for that transaction rather than observe it.
func newProbePool(t *testing.T, dbPool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()

	cfg := dbPool.Config().Copy()
	cfg.MaxConns = 1
	probePool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(probePool.Close)

	return probePool
}

func waitForSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(promptLimit):
		t.Fatalf("timed out waiting for %s", what)
	}
}

type postResult struct {
	status int
	err    error
}

// postServiceVersionAsync submits a minimal valid service version for an org1
// service through the API and reports the outcome on the returned channel. It
// runs on its own goroutine, so it reports errors instead of using t.
func postServiceVersionAsync(ctx context.Context, serverURL string, username string, password string, serviceID string) <-chan postResult {
	resCh := make(chan postResult, 1)
	go func() {
		body, err := json.Marshal(struct {
			Org                string                           `json:"org"`
			Domains            []string                         `json:"domains"`
			DefaultOriginGroup cdntypes.InputDefaultOriginGroup `json:"default_origin_group"`
			VCLTemplate        string                           `json:"vcl_template"`
		}{
			Org:     "00000002-0000-0000-0000-000000000001",
			Domains: []string{"example.com"},
			DefaultOriginGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{{Host: "198.51.100.20", Port: 443, TLS: true}},
			},
			VCLTemplate: cdntypes.DefaultVCLTemplate,
		})
		if err != nil {
			resCh <- postResult{err: err}
			return
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/services/"+serviceID+"/service-versions", bytes.NewReader(body))
		if err != nil {
			resCh <- postResult{err: err}
			return
		}
		req.SetBasicAuth(username, password)

		resp, err := http.DefaultClient.Do(req) // #nosec G704 -- filled in by test, so not susceptible to SSRF
		if err != nil {
			resCh <- postResult{err: err}
			return
		}
		resp.Body.Close()
		resCh <- postResult{status: resp.StatusCode}
	}()
	return resCh
}

func waitForPost(t *testing.T, resCh <-chan postResult) postResult {
	t.Helper()
	select {
	case res := <-resCh:
		return res
	case <-time.After(promptLimit):
		t.Fatal("timed out waiting for the service version POST")
	}
	return postResult{}
}

// TestPostServiceVersionValidationHoldsNoTransaction covers the reason the
// validator call sits between two transactions. While the call is in flight,
// the manager must hold neither an open transaction (a pooled connection
// idling in it) nor the services row lock.
func TestPostServiceVersionValidationHoldsNoTransaction(t *testing.T) {
	const serviceID = "00000003-0000-0000-0000-000000000001" // org1-service1

	validator := newBlockingValidator(t)

	ts, dbPool, err := prepareServer(t, testServerInput{vclValidator: validator.client})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	// Deferred after ts.Close so it runs first: Close waits for the
	// handler, which waits for the validator.
	defer validator.release()

	ctx := context.Background()

	probePool := newProbePool(t, dbPool)

	resCh := postServiceVersionAsync(ctx, ts.URL, "admin", validAdminPassword, serviceID)
	waitForSignal(t, validator.seen, "the validator request")

	var idleInTx int64
	err = probePool.QueryRow(ctx, "SELECT COUNT(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'idle in transaction'").Scan(&idleInTx)
	if err != nil {
		t.Fatal(err)
	}
	if idleInTx != 0 {
		t.Errorf("%d connections idle in transaction while the validator runs, want 0", idleInTx)
	}

	tx, err := probePool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, lockErr := tx.Exec(ctx, "SELECT id FROM services WHERE id = $1 FOR UPDATE NOWAIT", serviceID)
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if lockErr != nil {
		t.Errorf("services row is locked while the validator runs: %v", lockErr)
	}

	validator.release()
	res := waitForPost(t, resCh)
	if res.err != nil {
		t.Fatal(res.err)
	}
	if res.status != http.StatusCreated {
		t.Fatalf("POST returned %d, want %d", res.status, http.StatusCreated)
	}
}

// TestPostServiceVersionRechecksServiceAfterValidation changes the service
// while its VCL is being validated. The write transaction re-resolves the
// service by the UUIDs pinned before validation, so the version must not be
// written to a service that is gone or now belongs to another org.
func TestPostServiceVersionRechecksServiceAfterValidation(t *testing.T) {
	tests := []struct {
		description string
		serviceID   string
		change      string
	}{
		{
			description: "service deleted",
			serviceID:   "00000003-0000-0000-0000-0000000000e1",
			change:      "DELETE FROM services WHERE id = $1",
		},
		{
			description: "service moved to another org",
			serviceID:   "00000003-0000-0000-0000-0000000000e2",
			change:      "UPDATE services SET org_id = '00000002-0000-0000-0000-000000000002' WHERE id = $1",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			validator := newBlockingValidator(t)

			ts, dbPool, err := prepareServer(t, testServerInput{vclValidator: validator.client})
			if dbPool != nil {
				defer dbPool.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			defer ts.Close()
			defer validator.release()

			ctx := context.Background()

			_, err = dbPool.Exec(ctx,
				"INSERT INTO services (id, org_id, name, uid_range) SELECT $1, id, 'recheck-service', '(1000960000, 1000969999)' FROM orgs WHERE name='org1'",
				test.serviceID)
			if err != nil {
				t.Fatal(err)
			}

			probePool := newProbePool(t, dbPool)

			resCh := postServiceVersionAsync(ctx, ts.URL, "admin", validAdminPassword, test.serviceID)
			waitForSignal(t, validator.seen, "the validator request")

			// Bounded: while validation ran inside the transaction this
			// statement queued behind the services row lock until the
			// validator answered.
			changeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, changeErr := probePool.Exec(changeCtx, test.change, test.serviceID)
			cancel()
			validator.release()
			if changeErr != nil {
				t.Fatalf("changing the service while the validator runs: %v", changeErr)
			}

			res := waitForPost(t, resCh)
			if res.err != nil {
				t.Fatal(res.err)
			}
			if res.status != http.StatusUnprocessableEntity {
				t.Fatalf("POST returned %d, want %d", res.status, http.StatusUnprocessableEntity)
			}

			var versions int64
			err = dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM service_versions WHERE service_id = $1", test.serviceID).Scan(&versions)
			if err != nil {
				t.Fatal(err)
			}
			if versions != 0 {
				t.Fatalf("service has %d versions, want 0", versions)
			}
		})
	}
}

// TestPostServiceVersionClientDisconnectCancelsValidation checks that the
// validator call follows the request context: nothing has been written yet,
// so a client that goes away should not keep a validator request running.
func TestPostServiceVersionClientDisconnectCancelsValidation(t *testing.T) {
	const serviceID = "00000003-0000-0000-0000-000000000001" // org1-service1

	validator := newBlockingValidator(t)

	ts, dbPool, err := prepareServer(t, testServerInput{vclValidator: validator.client})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	defer validator.release()

	ctx := context.Background()

	versionCount := func() int64 {
		t.Helper()
		var n int64
		if err := dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM service_versions WHERE service_id = $1", serviceID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := versionCount()

	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resCh := postServiceVersionAsync(reqCtx, ts.URL, "admin", validAdminPassword, serviceID)
	waitForSignal(t, validator.seen, "the validator request")

	cancel()
	waitForSignal(t, validator.cancelled, "the manager to abandon the validator request")

	if res := waitForPost(t, resCh); !errors.Is(res.err, context.Canceled) {
		t.Fatalf("expected the client request to end with context.Canceled, got status %d err %v", res.status, res.err)
	}

	if after := versionCount(); after != before {
		t.Fatalf("service has %d versions after an abandoned request, want %d", after, before)
	}
}

// TestPostServiceVersionConcurrentValidation documents a consequence of
// validating outside the transaction. Two submissions for the same service
// both reach the validator at once, and only their inserts serialize, on the
// services row lock and version_counter.
func TestPostServiceVersionConcurrentValidation(t *testing.T) {
	const serviceID = "00000003-0000-0000-0000-000000000001" // org1-service1

	validator := newBlockingValidator(t)

	ts, dbPool, err := prepareServer(t, testServerInput{vclValidator: validator.client})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	defer validator.release()

	ctx := context.Background()

	versionCount := func() int64 {
		t.Helper()
		var n int64
		if err := dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM service_versions WHERE service_id = $1", serviceID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := versionCount()

	first := postServiceVersionAsync(ctx, ts.URL, "admin", validAdminPassword, serviceID)
	second := postServiceVersionAsync(ctx, ts.URL, "admin", validAdminPassword, serviceID)
	waitForSignal(t, validator.seen, "the first validator request")
	waitForSignal(t, validator.seen, "the second validator request while the first is still held")

	validator.release()
	for _, resCh := range []<-chan postResult{first, second} {
		res := waitForPost(t, resCh)
		if res.err != nil {
			t.Fatal(res.err)
		}
		if res.status != http.StatusCreated {
			t.Fatalf("POST returned %d, want %d", res.status, http.StatusCreated)
		}
	}

	if after := versionCount(); after != before+2 {
		t.Fatalf("service has %d versions, want %d", after, before+2)
	}
}

// TestPostServiceVersionForbiddenSkipsValidation checks that authorization
// still comes before validation now that they run in separate steps. A
// refused caller must not be able to make the manager call the validator.
func TestPostServiceVersionForbiddenSkipsValidation(t *testing.T) {
	const serviceID = "00000003-0000-0000-0000-000000000001" // org1-service1

	validator := newBlockingValidator(t)
	// Released up front: a validator call here is the failure being
	// tested for, not something to wait on.
	validator.release()

	ts, dbPool, err := prepareServer(t, testServerInput{vclValidator: validator.client})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	// username2 belongs to org2, the service to org1.
	res := waitForPost(t, postServiceVersionAsync(context.Background(), ts.URL, "username2", "password2", serviceID))
	if res.err != nil {
		t.Fatal(res.err)
	}
	if res.status != http.StatusForbidden {
		t.Fatalf("POST returned %d, want %d", res.status, http.StatusForbidden)
	}

	select {
	case <-validator.seen:
		t.Fatal("the validator was called for a refused request")
	default:
	}
}
