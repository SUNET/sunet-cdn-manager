package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// Helpers shared by the service version tests: a server that accepts any
// VCL, empty services to add versions to, and the version API body.

const testOrg1ID = "00000002-0000-0000-0000-000000000001"

// versionBody is the API body for creating a service version.
type versionBody struct {
	Org                     string                                 `json:"org"`
	Domains                 []string                               `json:"domains"`
	ConditionalOriginGroups []cdntypes.InputConditionalOriginGroup `json:"conditional_origin_groups,omitempty"`
	DefaultOriginGroup      cdntypes.InputDefaultOriginGroup       `json:"default_origin_group"`
	VCLTemplate             string                                 `json:"vcl_template"`
	Active                  bool                                   `json:"active,omitempty"`
	Description             string                                 `json:"description,omitempty"`
}

func baseVersionBody() versionBody {
	return versionBody{
		Org:     testOrg1ID,
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

// newEmptyService adds an empty service to org1, so a test starts with no
// versions to collide with.
func newEmptyService(t *testing.T, dbPool *pgxpool.Pool, name string, uidLow int) string {
	t.Helper()

	var serviceID string
	err := dbPool.QueryRow(context.Background(),
		"INSERT INTO services (org_id, name, uid_range) VALUES ($1, $2, int8range($3, $4)) RETURNING id",
		testOrg1ID, name, uidLow, uidLow+10000).Scan(&serviceID)
	if err != nil {
		t.Fatal(err)
	}
	return serviceID
}

func postVersion(t *testing.T, serverURL string, serviceID string, body versionBody) (int, cdntypes.ServiceVersion) {
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

func serviceVersionCount(t *testing.T, dbPool *pgxpool.Pool, serviceID string) int {
	t.Helper()

	var n int
	err := dbPool.QueryRow(context.Background(), "SELECT count(*) FROM service_versions WHERE service_id = $1", serviceID).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// activeServiceVersion returns the service's active version number, or 0 when
// no version is active, so callers report that as a wrong version.
func activeServiceVersion(t *testing.T, dbPool *pgxpool.Pool, serviceID string) int64 {
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

func prepareVersionServer(t *testing.T) (string, *pgxpool.Pool) {
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

// raceServer is a test server for making two service version submissions
// contend for the services row lock. The shared test pool has a single
// connection, which would run two write transactions one after the other
// however the manager locks, so the server gets a pool of its own with room
// for both.
type raceServer struct {
	url string
	// dbPool is the shared test pool, for setup and checks.
	dbPool *pgxpool.Pool
	// holdPool has one connection to hold the service row and one to watch
	// who waits for it.
	holdPool  *pgxpool.Pool
	validator *blockingValidator
}

func prepareRaceServer(t *testing.T) raceServer {
	t.Helper()

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
	holdPool := newPool(2)

	ts, _, err := prepareServer(t, testServerInput{vclValidator: validator.client, dbPool: serverPool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ts.Close)

	return raceServer{url: ts.URL, dbPool: dbPool, holdPool: holdPool, validator: validator}
}

// postRacingVersions submits two versions for the service at the same time,
// one per origin host, so identical hosts give identical content. A
// transaction from holdPool holds the service row until both submissions are
// waiting for it, so they contend for the lock rather than happen to run in
// turn. It returns how many submissions got each status.
func (rs raceServer) postRacingVersions(t *testing.T, serviceID string, originHosts [2]string) map[int]int {
	t.Helper()

	ctx := context.Background()

	first := postServiceVersionWithOriginAsync(ctx, rs.url, "admin", validAdminPassword, serviceID, testOrg1ID, originHosts[0])
	second := postServiceVersionWithOriginAsync(ctx, rs.url, "admin", validAdminPassword, serviceID, testOrg1ID, originHosts[1])
	waitForSignal(t, rs.validator.seen, "the first validator request")
	waitForSignal(t, rs.validator.seen, "the second validator request while the first is still held")

	// Taken only now: the lookup before validation reads the service row
	// too, and must not be what waits.
	hold, err := rs.holdPool.Begin(ctx)
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

	rs.validator.release()

	// The held transaction is idle, so the backends waiting for a lock can
	// only be the two submissions. Only the first waits for the holder
	// directly: the second queues behind it for the same row, so
	// pg_blocking_pids() would name the first submission, not the holder.
	deadline := time.Now().Add(promptLimit)
	for {
		var waiting int
		err := rs.holdPool.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'").Scan(&waiting)
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
	return statuses
}
