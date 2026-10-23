package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

const (
	retireInactiveDomainID = "00000015-0000-0000-0000-000000000101"
	retireActiveDomainID   = "00000015-0000-0000-0000-000000000102"
	retireUnusedDomainID   = "00000015-0000-0000-0000-000000000103"
	retireOrg2DomainID     = "00000015-0000-0000-0000-000000000104"
)

// addRetireFixtures adds verified domains covering each case retiring has
// to tell apart:
//   - retire-inactive.se (org1) is used only by org1-service1 version 1,
//     which is not active.
//   - retire-active.se (org1) is used by org1-service1 versions 2 and 3,
//     and version 3 is the active one.
//   - retire-unused.se (org1) is used by no version.
//   - retire-org2.se (org2) is used by org2-service1 version 1, which is
//     not active.
func addRetireFixtures(t *testing.T, dbPool *pgxpool.Pool) {
	t.Helper()

	const org1ID = "00000002-0000-0000-0000-000000000001"
	const org2ID = "00000002-0000-0000-0000-000000000002"

	domains := []struct {
		id    string
		orgID string
		fqdn  string
	}{
		{retireInactiveDomainID, org1ID, "retire-inactive.se"},
		{retireActiveDomainID, org1ID, "retire-active.se"},
		{retireUnusedDomainID, org1ID, "retire-unused.se"},
		{retireOrg2DomainID, org2ID, "retire-org2.se"},
	}
	for _, d := range domains {
		execSQL(t, dbPool, "INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ($1, $2, $3, true, $4)", d.id, d.orgID, d.fqdn, "token-"+d.fqdn)
	}

	links := []struct {
		versionID string
		domainID  string
	}{
		{"00000004-0000-0000-0000-000000000001", retireInactiveDomainID},
		{"00000004-0000-0000-0000-000000000002", retireActiveDomainID},
		{"00000004-0000-0000-0000-000000000003", retireActiveDomainID},
		{"00000004-0000-0000-0000-000000000004", retireOrg2DomainID},
	}
	for _, l := range links {
		execSQL(t, dbPool, "INSERT INTO service_domains (service_version_id, domain_id) VALUES ($1, $2)", l.versionID, l.domainID)
	}
}

func TestRetireDomain(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	// The cases share one database and run in order: retiring
	// retire-inactive.se a second time relies on the first case.
	// The first case names it in a non-canonical form (upper case, trailing
	// dot) that must still find the stored domain.
	tests := []struct {
		description    string
		username       string
		password       string
		domain         string
		expectedStatus int
		bodyContains   string
		// retiredID is a domain that must be retired afterwards
		retiredID string
	}{
		{
			description:    "user retires domain used by inactive version",
			username:       "username1",
			password:       validUserPassword,
			domain:         "RETIRE-INACTIVE.SE.",
			expectedStatus: http.StatusNoContent,
			retiredID:      retireInactiveDomainID,
		},
		{
			description:    "superuser retires other org's domain by ID",
			username:       "admin",
			password:       validAdminPassword,
			domain:         retireOrg2DomainID,
			expectedStatus: http.StatusNoContent,
			retiredID:      retireOrg2DomainID,
		},
		{
			description:    "domain used by active version",
			username:       "username1",
			password:       validUserPassword,
			domain:         "retire-active.se",
			expectedStatus: http.StatusConflict,
			bodyContains:   "org1-service1",
		},
		{
			description:    "unused domain",
			username:       "username1",
			password:       validUserPassword,
			domain:         "retire-unused.se",
			expectedStatus: http.StatusConflict,
			bodyContains:   "delete it instead",
		},
		{
			description:    "domain retired a second time",
			username:       "username1",
			password:       validUserPassword,
			domain:         "retire-inactive.se",
			expectedStatus: http.StatusConflict,
			bodyContains:   "domain is retired",
		},
		{
			description:    "other org's domain by name",
			username:       "username2",
			password:       "password2",
			domain:         "retire-inactive.se",
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "other org's domain by ID",
			username:       "username2",
			password:       "password2",
			domain:         retireInactiveDomainID,
			expectedStatus: http.StatusNotFound,
		},
		{
			description:    "IP address instead of a domain name",
			username:       "username1",
			password:       validUserPassword,
			domain:         "127.0.0.1",
			expectedStatus: http.StatusBadRequest,
		},
		{
			description:    "user without org",
			username:       "username3-no-org",
			password:       "password3",
			domain:         "retire-unused.se",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/"+test.domain+"/retire", test.username, test.password, nil)
			if status != test.expectedStatus {
				t.Fatalf("unexpected status code: got %d, want %d (%s)", status, test.expectedStatus, body)
			}
			if !strings.Contains(body, test.bodyContains) {
				t.Fatalf("body %q does not contain %q", body, test.bodyContains)
			}

			if test.retiredID != "" {
				var retired bool
				err := dbPool.QueryRow(context.Background(), "SELECT time_retired IS NOT NULL AND NOT verified FROM domains WHERE id = $1", test.retiredID).Scan(&retired)
				if err != nil {
					t.Fatal(err)
				}
				if !retired {
					t.Fatalf("expected domain %s to be retired and unverified", test.retiredID)
				}
			}
		})
	}
}

// TestDomainNameLookupNeedsOrg checks that a superuser looking up a domain
// name held by several orgs is asked for the org rather than given one of
// them.
func TestDomainNameLookupNeedsOrg(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	const sharedOrg1ID = "00000015-0000-0000-0000-000000000201"
	const sharedOrg2ID = "00000015-0000-0000-0000-000000000202"
	execSQL(t, dbPool, "INSERT INTO domains (id, org_id, fqdn, verified, verification_token, time_retired) VALUES ($1, '00000002-0000-0000-0000-000000000001', 'shared.se', false, 'token-shared-1', now())", sharedOrg1ID)
	execSQL(t, dbPool, "INSERT INTO domains (id, org_id, fqdn, verified, verification_token, time_retired) VALUES ($1, '00000002-0000-0000-0000-000000000002', 'shared.se', false, 'token-shared-2', now())", sharedOrg2ID)

	status, body := apiJSON(t, http.MethodDelete, ts.URL+"/api/v1/domains/shared.se", "admin", validAdminPassword, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("DELETE without org: got status %d, want %d (%s)", status, http.StatusBadRequest, body)
	}
	if !strings.Contains(body, "include org") {
		t.Fatalf("DELETE without org: body %q does not ask for the org", body)
	}

	status, body = apiJSON(t, http.MethodDelete, ts.URL+"/api/v1/domains/shared.se?org=org2", "admin", validAdminPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("DELETE with org: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	rows, err := dbPool.Query(context.Background(), "SELECT id::text FROM domains WHERE fqdn = 'shared.se'")
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0] != sharedOrg1ID {
		t.Fatalf("expected only org1's shared.se to remain, got %v", remaining)
	}
}

func TestDeleteUsedDomainSuggestsRetire(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	status, body := apiJSON(t, http.MethodDelete, ts.URL+"/api/v1/domains/retire-inactive.se", "username1", validUserPassword, nil)
	if status != http.StatusConflict {
		t.Fatalf("unexpected status code: got %d, want %d (%s)", status, http.StatusConflict, body)
	}
	if !strings.Contains(body, "retire it instead") {
		t.Fatalf("body %q does not suggest retiring", body)
	}
}

// TestDeleteActiveUsedDomainDoesNotSuggestRetire checks that deleting a
// domain the active version uses does not suggest retiring it, since
// retiring would be refused as well.
func TestDeleteActiveUsedDomainDoesNotSuggestRetire(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	status, body := apiJSON(t, http.MethodDelete, ts.URL+"/api/v1/domains/retire-active.se", "username1", validUserPassword, nil)
	if status != http.StatusConflict {
		t.Fatalf("unexpected status code: got %d, want %d (%s)", status, http.StatusConflict, body)
	}
	if !strings.Contains(body, "org1-service1") {
		t.Fatalf("body %q does not name the service using the domain", body)
	}
	if strings.Contains(body, "retire it instead") {
		t.Fatalf("body %q suggests retiring a domain the active version uses", body)
	}
}

// TestInsertVersionWithUnknownDomainNamesIt checks that adding a service
// version with a domain that is not a verified domain of the org names the
// domain in the 422 response, both for a name never added and for a retired
// one.
func TestInsertVersionWithUnknownDomainNamesIt(t *testing.T) {
	validatorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer validatorServer.Close()

	u, err := url.Parse(validatorServer.URL + "/validate-vcl")
	if err != nil {
		t.Fatal(err)
	}

	ts, dbPool, err := prepareServer(t, testServerInput{vclValidator: newVclValidator(u)})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/retire-inactive.se/retire?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("retire: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	for _, domain := range []string{"never-added.se", "retire-inactive.se"} {
		t.Run(domain, func(t *testing.T) {
			version := map[string]any{
				"org":     "org1",
				"domains": []string{"example.se", domain},
				"default_origin_group": cdntypes.InputDefaultOriginGroup{
					Origins: []cdntypes.InputOrigin{{Host: "198.51.100.20", Port: 443, TLS: true}},
				},
				"vcl_template": cdntypes.DefaultVCLTemplate,
			}
			status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/services/org1-service1/service-versions", "username1", validUserPassword, version)
			if status != http.StatusUnprocessableEntity {
				t.Fatalf("got status %d, want %d (%s)", status, http.StatusUnprocessableEntity, body)
			}
			if !strings.Contains(body, "unknown domain name: "+domain) {
				t.Fatalf("body %q does not name the domain", body)
			}
		})
	}
}

func TestReAddRetiredDomain(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	var oldToken string
	err = dbPool.QueryRow(context.Background(), "SELECT verification_token FROM domains WHERE id = $1", retireInactiveDomainID).Scan(&oldToken)
	if err != nil {
		t.Fatal(err)
	}

	status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/retire-inactive.se/retire?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("retire: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	status, body = apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains?org=org1", "username1", validUserPassword, map[string]string{"fqdn": "retire-inactive.se"})
	if status != http.StatusCreated {
		t.Fatalf("re-add: got status %d, want %d (%s)", status, http.StatusCreated, body)
	}

	var d cdntypes.Domain
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("unable to unmarshal %q: %v", body, err)
	}
	if d.ID.String() != retireInactiveDomainID {
		t.Fatalf("expected the retired row %s to be revived, got id %s", retireInactiveDomainID, d.ID.String())
	}
	if d.Verified {
		t.Fatal("expected revived domain to be unverified")
	}
	if d.Retired {
		t.Fatal("expected revived domain to not be retired")
	}
	// Version 1 still references the revived row.
	if !d.InUse {
		t.Fatalf("expected revived domain to be in use: %s", body)
	}
	if d.VerificationToken == "" || d.VerificationToken == oldToken {
		t.Fatalf("expected a new verification token, got %q (old %q)", d.VerificationToken, oldToken)
	}

	var storedToken string
	var live, verified bool
	err = dbPool.QueryRow(context.Background(), "SELECT time_retired IS NULL, verified, verification_token FROM domains WHERE id = $1", retireInactiveDomainID).Scan(&live, &verified, &storedToken)
	if err != nil {
		t.Fatal(err)
	}
	if !live || verified || storedToken != d.VerificationToken {
		t.Fatalf("unexpected stored row: live %t, verified %t, token %q", live, verified, storedToken)
	}
}

func TestAddDomainHeldByOtherOrg(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	add := func(username string, password string, org string) (int, string) {
		return apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains?org="+org, username, password, map[string]string{"fqdn": "retire-inactive.se"})
	}

	status, body := add("username2", "password2", "org2")
	if status != http.StatusConflict {
		t.Fatalf("add while org1 holds it: got status %d, want %d (%s)", status, http.StatusConflict, body)
	}

	status, body = apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/retire-inactive.se/retire?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("retire: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	status, body = add("username2", "password2", "org2")
	if status != http.StatusCreated {
		t.Fatalf("add after retire: got status %d, want %d (%s)", status, http.StatusCreated, body)
	}
	var d cdntypes.Domain
	if err := json.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("unable to unmarshal %q: %v", body, err)
	}
	if d.ID.String() == retireInactiveDomainID {
		t.Fatalf("org2 got org1's row %s", retireInactiveDomainID)
	}

	status, body = add("username1", validUserPassword, "org1")
	if status != http.StatusConflict {
		t.Fatalf("org1 re-add while org2 holds it: got status %d, want %d (%s)", status, http.StatusConflict, body)
	}
}

func TestDomainQuotaIgnoresRetired(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)
	execSQL(t, dbPool, "UPDATE orgs SET domain_quota = 2 WHERE name = 'org2'")

	status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/retire-org2.se/retire?org=org2", "admin", validAdminPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("retire: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	add := func(fqdn string) (int, string) {
		return apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains?org=org2", "username2", "password2", map[string]string{"fqdn": fqdn})
	}

	// The retired row plus these two make three rows for a quota of two.
	for _, fqdn := range []string{"quota-a.se", "quota-b.se"} {
		status, body = add(fqdn)
		if status != http.StatusCreated {
			t.Fatalf("add %s: got status %d, want %d (%s)", fqdn, status, http.StatusCreated, body)
		}
	}
	status, body = add("quota-c.se")
	if status != http.StatusConflict {
		t.Fatalf("add past quota: got status %d, want %d (%s)", status, http.StatusConflict, body)
	}

	// Two live domains fit a quota of two even though the org has three rows.
	status, body = apiJSON(t, http.MethodPut, ts.URL+"/api/v1/orgs/org2", "admin", validAdminPassword, map[string]any{
		"name":               "org2",
		"service_quota":      100,
		"domain_quota":       2,
		"client_token_quota": 100,
	})
	if status != http.StatusOK {
		t.Fatalf("PUT org with quota equal to live domains: got status %d, want %d (%s)", status, http.StatusOK, body)
	}

	// Reviving counts as adding, so it is refused at the quota.
	status, body = add("retire-org2.se")
	if status != http.StatusConflict {
		t.Fatalf("revive past quota: got status %d, want %d (%s)", status, http.StatusConflict, body)
	}
}

// TestDeleteRetiredUsedDomain checks that deleting a retired domain a
// version still references is refused without suggesting to retire it again.
func TestDeleteRetiredUsedDomain(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/retire-inactive.se/retire?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("retire: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	status, body = apiJSON(t, http.MethodDelete, ts.URL+"/api/v1/domains/retire-inactive.se", "username1", validUserPassword, nil)
	if status != http.StatusConflict {
		t.Fatalf("unexpected status code: got %d, want %d (%s)", status, http.StatusConflict, body)
	}
	if !strings.Contains(body, "org1-service1") {
		t.Fatalf("body %q does not name the service using the domain", body)
	}
	if strings.Contains(body, "retire it instead") {
		t.Fatalf("body %q suggests retiring an already retired domain", body)
	}
}

// TestDeleteOrgWithRetiredDomain checks that a retired domain still blocks
// deleting its org, since it is org data and not covered by the quota.
func TestDeleteOrgWithRetiredDomain(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	execSQL(t, dbPool, "INSERT INTO orgs (id, name) VALUES ('00000002-0000-0000-0000-0000000000a1', 'retired-only')")
	execSQL(t, dbPool, "INSERT INTO domains (org_id, fqdn, verified, verification_token, time_retired) VALUES ('00000002-0000-0000-0000-0000000000a1', 'only-retired.se', false, 'token-only-retired', now())")

	status, body := apiJSON(t, http.MethodDelete, ts.URL+"/api/v1/orgs/retired-only", "admin", validAdminPassword, nil)
	if status != http.StatusConflict {
		t.Fatalf("delete org with retired domain: got status %d, want %d (%s)", status, http.StatusConflict, body)
	}

	status, body = apiJSON(t, http.MethodDelete, ts.URL+"/api/v1/domains/only-retired.se?org=retired-only", "admin", validAdminPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete retired domain: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	status, body = apiJSON(t, http.MethodDelete, ts.URL+"/api/v1/orgs/retired-only", "admin", validAdminPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete org after domain delete: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}
}

// TestActivateVersionWithUnverifiedDomain checks that a version using a
// domain that is not verified, whether retired or pending after being added
// again, cannot be activated, and that the active version is left alone.
func TestActivateVersionWithUnverifiedDomain(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/retire-inactive.se/retire?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("retire: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	activate := func() (int, string) {
		return apiJSON(t, http.MethodPut, ts.URL+"/api/v1/services/org1-service1/service-versions/1/active?org=org1", "username1", validUserPassword, map[string]bool{"active": true})
	}

	activeVersion := func() int64 {
		var version int64
		err := dbPool.QueryRow(context.Background(), "SELECT version FROM service_versions WHERE service_id = '00000003-0000-0000-0000-000000000001' AND active").Scan(&version)
		if err != nil {
			t.Fatal(err)
		}
		return version
	}

	status, body = activate()
	if status != http.StatusConflict {
		t.Fatalf("activate with retired domain: got status %d, want %d (%s)", status, http.StatusConflict, body)
	}
	if !strings.Contains(body, "retire-inactive.se") {
		t.Fatalf("activate with retired domain: body %q does not name the domain", body)
	}
	if v := activeVersion(); v != 3 {
		t.Fatalf("activate with retired domain: active version changed to %d", v)
	}

	status, body = apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains?org=org1", "username1", validUserPassword, map[string]string{"fqdn": "retire-inactive.se"})
	if status != http.StatusCreated {
		t.Fatalf("re-add: got status %d, want %d (%s)", status, http.StatusCreated, body)
	}

	status, body = activate()
	if status != http.StatusConflict {
		t.Fatalf("activate with pending domain: got status %d, want %d (%s)", status, http.StatusConflict, body)
	}
	if !strings.Contains(body, "retire-inactive.se") {
		t.Fatalf("activate with pending domain: body %q does not name the domain", body)
	}
	if v := activeVersion(); v != 3 {
		t.Fatalf("activate with pending domain: active version changed to %d", v)
	}

	execSQL(t, dbPool, "UPDATE domains SET verified = true WHERE id = $1", retireInactiveDomainID)

	status, body = activate()
	if status != http.StatusNoContent {
		t.Fatalf("activate with verified domain: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}
	if v := activeVersion(); v != 1 {
		t.Fatalf("activate with verified domain: active version is %d, want 1", v)
	}
}

// TestMarkDomainVerified checks that the verifier only marks the row it
// looked up, and only while it is still live with the token it checked.
func TestMarkDomainVerified(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	const org1ID = "00000002-0000-0000-0000-000000000001"
	const liveID = "00000015-0000-0000-0000-000000000301"
	const staleID = "00000015-0000-0000-0000-000000000302"
	const retiredID = "00000015-0000-0000-0000-000000000303"
	execSQL(t, dbPool, "INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ($1, $2, 'mark-live.se', false, 'token-live')", liveID, org1ID)
	execSQL(t, dbPool, "INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ($1, $2, 'mark-stale.se', false, 'token-new')", staleID, org1ID)
	execSQL(t, dbPool, "INSERT INTO domains (id, org_id, fqdn, verified, verification_token, time_retired) VALUES ($1, $2, 'mark-retired.se', false, 'token-retired', now())", retiredID, org1ID)

	tests := []struct {
		description string
		id          string
		fqdn        string
		token       string
		expected    bool
	}{
		{
			description: "live domain with matching token",
			id:          liveID,
			fqdn:        "mark-live.se",
			token:       "token-live",
			expected:    true,
		},
		{
			description: "token replaced since lookup",
			id:          staleID,
			fqdn:        "mark-stale.se",
			token:       "token-old",
			expected:    false,
		},
		{
			description: "retired domain with matching token",
			id:          retiredID,
			fqdn:        "mark-retired.se",
			token:       "token-retired",
			expected:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			var id pgtype.UUID
			if err := id.Scan(test.id); err != nil {
				t.Fatal(err)
			}

			updated, err := markDomainVerified(context.Background(), dbPool, domainVerifyData{ID: id, FQDN: test.fqdn, VerificationToken: test.token})
			if err != nil {
				t.Fatal(err)
			}
			if updated != test.expected {
				t.Fatalf("markDomainVerified returned %t, want %t", updated, test.expected)
			}

			var verified bool
			err = dbPool.QueryRow(context.Background(), "SELECT verified FROM domains WHERE id = $1", test.id).Scan(&verified)
			if err != nil {
				t.Fatal(err)
			}
			if verified != test.expected {
				t.Fatalf("domain verified is %t, want %t", verified, test.expected)
			}
		})
	}
}

// TestConsoleActivateVersionWithUnverifiedDomain checks that the console
// names the domain that keeps a version from being activated.
func TestConsoleActivateVersionWithUnverifiedDomain(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)
	execSQL(t, dbPool, "UPDATE domains SET time_retired = now(), verified = false WHERE id = $1", retireInactiveDomainID)

	jar := loginJar(t, ts.URL, "username1", validUserPassword)
	res := doConsole(t, jar, http.MethodPost, ts.URL+"/console/org/org1/services/00000003-0000-0000-0000-000000000001/1/activate", url.Values{"confirmation": {"on"}})
	if res.status != http.StatusOK {
		t.Fatalf("unexpected status code: got %d, want %d (%s)", res.status, http.StatusOK, res.body)
	}
	if !strings.Contains(res.body, "retire-inactive.se") {
		t.Fatalf("body does not name the unverified domain: %s", res.body)
	}

	var active int64
	err = dbPool.QueryRow(context.Background(), "SELECT version FROM service_versions WHERE service_id = '00000003-0000-0000-0000-000000000001' AND active").Scan(&active)
	if err != nil {
		t.Fatal(err)
	}
	if active != 3 {
		t.Fatalf("active version changed to %d", active)
	}
}

// TestCacheNodeConfigExcludesVersionsWithUnverifiedDomains checks that a
// version using a retired or pending domain is not sent to cache nodes at
// all, while the service's other versions still are.
func TestCacheNodeConfigExcludesVersionsWithUnverifiedDomains(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	const (
		org1ID         = "00000002-0000-0000-0000-000000000001"
		org1Service1ID = "00000003-0000-0000-0000-000000000001"
	)

	// Give version 1 a second, healthy domain. Without it, retiring its only
	// domain would leave the version without domains and hide it for that
	// reason alone, rather than because it has an unverified domain.
	execSQL(t, dbPool, "INSERT INTO domains (id, org_id, fqdn, verified, verification_token) VALUES ('00000015-0000-0000-0000-000000000105', $1, 'retire-extra.se', true, 'token-retire-extra')", org1ID)
	execSQL(t, dbPool, "INSERT INTO service_domains (service_version_id, domain_id) VALUES ('00000004-0000-0000-0000-000000000001', '00000015-0000-0000-0000-000000000105')")

	getVersions := func() map[int64]cdntypes.ServiceVersionWithConfig {
		t.Helper()

		status, body := apiJSON(t, http.MethodGet, ts.URL+"/api/v1/cache-node-configs/cache-node1", "admin", validAdminPassword, nil)
		if status != http.StatusOK {
			t.Fatalf("unexpected status code: %d (%s)", status, body)
		}

		var cnc cdntypes.CacheNodeConfig
		if err := json.Unmarshal([]byte(body), &cnc); err != nil {
			t.Fatalf("unable to unmarshal %q: %v", body, err)
		}

		return cnc.Orgs[org1ID].Services[org1Service1ID].ServiceVersions
	}

	checkVersions := func(step string, present map[int64]bool) {
		t.Helper()

		versions := getVersions()
		for _, v := range []int64{1, 2, 3} {
			_, ok := versions[v]
			if ok != present[v] {
				t.Fatalf("%s: version %d present is %t, want %t (versions: %+v)", step, v, ok, present[v], versions)
			}
		}
	}

	checkVersions("baseline", map[int64]bool{1: true, 2: true, 3: true})

	status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/retire-inactive.se/retire?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("retire: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}
	checkVersions("retired", map[int64]bool{2: true, 3: true})

	status, body = apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains?org=org1", "username1", validUserPassword, map[string]string{"fqdn": "retire-inactive.se"})
	if status != http.StatusCreated {
		t.Fatalf("re-add: got status %d, want %d (%s)", status, http.StatusCreated, body)
	}
	checkVersions("pending", map[int64]bool{2: true, 3: true})

	execSQL(t, dbPool, "UPDATE domains SET verified = true WHERE id = $1", retireInactiveDomainID)
	checkVersions("verified", map[int64]bool{1: true, 2: true, 3: true})
}

// TestServiceVersionsUnusableDomains retires retire-inactive.se, which only
// version 1 uses, and checks that the service version list reports it in
// unusable_domains for version 1 and leaves the field out for the other
// versions.
func TestServiceVersionsUnusableDomains(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/retire-inactive.se/retire?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("retire: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	status, body = apiJSON(t, http.MethodGet, ts.URL+"/api/v1/services/org1-service1/service-versions?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusOK {
		t.Fatalf("list: got status %d, want %d (%s)", status, http.StatusOK, body)
	}

	// Decode into raw messages to tell an omitted field from an empty one.
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("unable to unmarshal %q: %v", body, err)
	}

	unusable := map[int64][]string{}
	for _, sv := range raw {
		var version int64
		if err := json.Unmarshal(sv["version"], &version); err != nil {
			t.Fatal(err)
		}
		if field, ok := sv["unusable_domains"]; ok {
			var domains []string
			if err := json.Unmarshal(field, &domains); err != nil {
				t.Fatal(err)
			}
			unusable[version] = domains
		}
	}
	if len(unusable) != 1 || len(unusable[1]) != 1 || unusable[1][0] != "retire-inactive.se" {
		t.Fatalf("expected only version 1 to list retire-inactive.se, got %v (%s)", unusable, body)
	}
}

func TestConsoleRetireDomain(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})
	addRetireFixtures(t, dbPool)
	jar := loginJar(t, ts.URL, "username1", validUserPassword)

	const retirePath = "/console/org/org1/domains/%s/retire"

	retireButton := func(body string, fqdn string) *goquery.Selection {
		t.Helper()
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b := doc.Find(fmt.Sprintf("button[hx-post='"+retirePath+"']", fqdn))
		if b.Length() != 1 {
			t.Fatalf("expected one Retire button for %s in %s", fqdn, body)
		}
		return b
	}

	// A domain only inactive versions use can be retired.
	res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org1/domains", nil)
	if res.status != http.StatusOK {
		t.Fatalf("domains page: unexpected status %d", res.status)
	}
	if _, disabled := retireButton(res.body, "retire-inactive.se").Attr("disabled"); disabled {
		t.Fatalf("Retire should be enabled for retire-inactive.se")
	}

	res = doConsole(t, jar, http.MethodPost, ts.URL+fmt.Sprintf(retirePath, "retire-inactive.se"), url.Values{})
	if res.status != http.StatusSeeOther {
		t.Fatalf("retire: unexpected status %d (%s)", res.status, res.body)
	}
	if res.location != "/console/org/org1/domains" {
		t.Fatalf("retire: unexpected redirect %q", res.location)
	}

	res = doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org1/domains", nil)
	if res.status != http.StatusOK {
		t.Fatalf("domains page: unexpected status %d", res.status)
	}
	if !strings.Contains(res.body, "Domain &#39;retire-inactive.se&#39; retired!") {
		t.Fatalf("domains page lacks the flash message: %s", res.body)
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(res.body))
	if err != nil {
		t.Fatal(err)
	}
	row := func(fqdn string) *goquery.Selection {
		t.Helper()
		var found *goquery.Selection
		doc.Find("tbody tr").Each(func(_ int, tr *goquery.Selection) {
			if strings.TrimSpace(tr.Find("td").First().Text()) == fqdn {
				found = tr
			}
		})
		if found == nil {
			t.Fatalf("no row for %s in %s", fqdn, res.body)
		}
		return found
	}

	retired := row("retire-inactive.se")
	if !strings.Contains(retired.Text(), "Retired") {
		t.Fatalf("retired row does not say so: %s", retired.Text())
	}
	if strings.Contains(retired.Text(), "IN TXT") {
		t.Fatalf("retired row shows a TXT record: %s", retired.Text())
	}
	if n := retired.Find("button").Length(); n != 1 {
		t.Fatalf("retired row should have exactly one action, got %d", n)
	}
	addAgain := retired.Find("button[hx-post='/console/org/org1/create/domain']")
	if addAgain.Length() != 1 || !strings.Contains(addAgain.Text(), "Add again") {
		t.Fatalf("retired row lacks the Add again control: %s", res.body)
	}
	if vals, _ := addAgain.Attr("hx-vals"); !strings.Contains(vals, "retire-inactive.se") {
		t.Fatalf("Add again does not carry the fqdn: %q", vals)
	}

	// Verified and used: Retire. Unused: Delete.
	active := row("retire-active.se")
	if n := active.Find("button").Length(); n != 1 || active.Find("button[hx-post='/console/org/org1/domains/retire-active.se/retire']").Length() != 1 {
		t.Fatalf("used domain should offer only Retire: %s", active.Text())
	}
	if !strings.Contains(active.Text(), "IN TXT") {
		t.Fatalf("live row lacks the TXT record: %s", active.Text())
	}
	// The active version uses it, so Retire is disabled and the row says why.
	if _, disabled := retireButton(res.body, "retire-active.se").Attr("disabled"); !disabled {
		t.Fatalf("Retire should be disabled for retire-active.se, used by the active version")
	}
	// The reason sits under the status, not next to the button, and names
	// the service.
	if note := active.Find("td").Eq(1).Find("small").Text(); !strings.Contains(note, "org1-service1") {
		t.Fatalf("status does not say which service keeps it from being retired: %q", note)
	}
	if active.Find("td").Last().Find("small").Length() != 0 {
		t.Fatalf("the actions cell should only hold the button: %s", active.Text())
	}
	unused := row("retire-unused.se")
	if n := unused.Find("button").Length(); n != 1 || unused.Find("button[hx-delete='/console/org/org1/domains/retire-unused.se']").Length() != 1 {
		t.Fatalf("unused domain should offer only Delete: %s", unused.Text())
	}

	// A retired domain nothing uses is deleted, not added again.
	execSQL(t, dbPool, "UPDATE domains SET verified = false, time_retired = now() WHERE id = $1", retireUnusedDomainID)
	res = doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org1/domains", nil)
	doc, err = goquery.NewDocumentFromReader(strings.NewReader(res.body))
	if err != nil {
		t.Fatal(err)
	}
	unused = row("retire-unused.se")
	if n := unused.Find("button").Length(); n != 1 || unused.Find("button[hx-delete='/console/org/org1/domains/retire-unused.se']").Length() != 1 {
		t.Fatalf("retired unused domain should offer only Delete: %s", unused.Text())
	}

	// The server still refuses it if posted directly. The error is
	// rendered inline on the domains page, as for delete, so htmx swaps it
	// in.
	res = doConsole(t, jar, http.MethodPost, ts.URL+fmt.Sprintf(retirePath, "retire-active.se"), url.Values{})
	if res.status != http.StatusOK {
		t.Fatalf("retire active: unexpected status %d (%s)", res.status, res.body)
	}
	if !strings.Contains(res.body, "org1-service1") {
		t.Fatalf("retire active: error does not name the service: %s", res.body)
	}
}

func TestConsoleServiceShowsBlockedVersion(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})
	addRetireFixtures(t, dbPool)
	jar := loginJar(t, ts.URL, "username1", validUserPassword)

	versionRow := func(version string) *goquery.Selection {
		t.Helper()
		res := doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org1/services/org1-service1", nil)
		if res.status != http.StatusOK {
			t.Fatalf("service page: unexpected status %d", res.status)
		}
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(res.body))
		if err != nil {
			t.Fatal(err)
		}
		var found *goquery.Selection
		doc.Find("tbody tr").Each(func(_ int, tr *goquery.Selection) {
			if strings.TrimSpace(tr.Find("td").First().Text()) == version {
				found = tr
			}
		})
		if found == nil {
			t.Fatalf("no row for version %s in %s", version, res.body)
		}
		return found
	}
	activate := func(tr *goquery.Selection) *goquery.Selection {
		t.Helper()
		b := tr.Find("button[hx-get$='/activate']")
		if b.Length() != 1 {
			t.Fatalf("expected one Activate button in %s", tr.Text())
		}
		return b
	}
	// The note a blocked version's row carries next to its Activate button.
	blockedNote := func(tr *goquery.Selection) string {
		return tr.Find("small.error-text").Text()
	}

	// Before retiring, version 1 can be activated.
	v1 := versionRow("1")
	if _, disabled := activate(v1).Attr("disabled"); disabled || blockedNote(v1) != "" {
		t.Fatalf("version 1 should not be blocked before retiring: %s", v1.Text())
	}

	res := doConsole(t, jar, http.MethodPost, ts.URL+"/console/org/org1/domains/retire-inactive.se/retire", url.Values{})
	if res.status != http.StatusSeeOther {
		t.Fatalf("retire: unexpected status %d (%s)", res.status, res.body)
	}

	v1 = versionRow("1")
	if _, disabled := activate(v1).Attr("disabled"); !disabled {
		t.Fatalf("Activate should be disabled for version 1: %s", v1.Text())
	}
	if !strings.Contains(blockedNote(v1), "retire-inactive.se") {
		t.Fatalf("version 1 does not say which domain blocks it: %s", v1.Text())
	}

	v2 := versionRow("2")
	if _, disabled := activate(v2).Attr("disabled"); disabled {
		t.Fatalf("Activate should stay enabled for version 2: %s", v2.Text())
	}

	// The version page marks the same domain.
	res = doConsole(t, jar, http.MethodGet, ts.URL+"/console/org/org1/services/org1-service1/1", nil)
	if res.status != http.StatusOK {
		t.Fatalf("version page: unexpected status %d", res.status)
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(res.body))
	if err != nil {
		t.Fatal(err)
	}
	var item string
	doc.Find("li").Each(func(_ int, li *goquery.Selection) {
		if strings.Contains(li.Text(), "retire-inactive.se") {
			item = li.Text()
		}
	})
	if item == "" {
		t.Fatalf("version page does not list retire-inactive.se: %s", res.body)
	}
	if !strings.Contains(item, "cannot be activated") {
		t.Fatalf("version page does not mark retire-inactive.se: %q", item)
	}
}

func TestGetDomainsStateFields(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	addRetireFixtures(t, dbPool)

	status, body := apiJSON(t, http.MethodPost, ts.URL+"/api/v1/domains/retire-inactive.se/retire?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusNoContent {
		t.Fatalf("retire: got status %d, want %d (%s)", status, http.StatusNoContent, body)
	}

	status, body = apiJSON(t, http.MethodGet, ts.URL+"/api/v1/domains?org=org1", "username1", validUserPassword, nil)
	if status != http.StatusOK {
		t.Fatalf("list: got status %d, want %d (%s)", status, http.StatusOK, body)
	}
	var domains []cdntypes.Domain
	if err := json.Unmarshal([]byte(body), &domains); err != nil {
		t.Fatalf("unable to unmarshal %q: %v", body, err)
	}

	type state struct {
		retired        bool
		inUse          bool
		activeServices string
	}
	got := map[string]state{}
	for _, d := range domains {
		got[d.FQDN] = state{d.Retired, d.InUse, strings.Join(d.ActiveServices, ",")}
	}
	want := map[string]state{
		"retire-inactive.se": {retired: true, inUse: true},
		"retire-active.se":   {retired: false, inUse: true, activeServices: "org1-service1"},
		"retire-unused.se":   {retired: false, inUse: false},
	}
	for fqdn, w := range want {
		if got[fqdn] != w {
			t.Fatalf("%s: got %+v, want %+v (%s)", fqdn, got[fqdn], w, body)
		}
	}
	if !strings.Contains(body, `"retired":true`) || !strings.Contains(body, `"in_use":false`) || !strings.Contains(body, `"active_services":["org1-service1"]`) {
		t.Fatalf("response lacks the retired, in_use and active_services fields: %s", body)
	}
}

// TestConsoleCloneBlockedVersion clones a version that cannot be activated
// because one of its domains is retired: the form is prefilled from the
// version, keeps its still verified domain checked, leaves the retired one
// out and says that it was not carried over.
func TestConsoleCloneBlockedVersion(t *testing.T) {
	ts, dbPool := newSessionTestServer(t, testServerInput{})
	addRetireFixtures(t, dbPool)
	// Give version 1 a domain that stays verified next to the one that is
	// retired below.
	execSQL(t, dbPool, "INSERT INTO service_domains (service_version_id, domain_id) VALUES ($1, $2)", "00000004-0000-0000-0000-000000000001", "00000015-0000-0000-0000-000000000001")
	jar := loginJar(t, ts.URL, "username1", validUserPassword)

	cloneURL := ts.URL + "/console/org/org1/create/service/version/00000003-0000-0000-0000-000000000001?clone-version=1"
	clonePage := func() *goquery.Document {
		t.Helper()
		res := doConsole(t, jar, http.MethodGet, cloneURL, nil)
		if res.status != http.StatusOK {
			t.Fatalf("clone page: unexpected status %d (%s)", res.status, res.body)
		}
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(res.body))
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	const notCarriedOver = "#clone-dropped-domains"

	// Before retiring, both domains are carried over and there is no note.
	doc := clonePage()
	if _, checked := doc.Find("input[name='domains'][value='retire-inactive.se']").Attr("checked"); !checked {
		t.Fatalf("retire-inactive.se should be checked before retiring")
	}
	if doc.Find(notCarriedOver).Length() != 0 {
		t.Fatalf("unexpected not-carried-over note before retiring: %s", doc.Find(notCarriedOver).Text())
	}

	res := doConsole(t, jar, http.MethodPost, ts.URL+"/console/org/org1/domains/retire-inactive.se/retire", url.Values{})
	if res.status != http.StatusSeeOther {
		t.Fatalf("retire: unexpected status %d (%s)", res.status, res.body)
	}

	doc = clonePage()

	if doc.Find("input[name='domains'][value='retire-inactive.se']").Length() != 0 {
		t.Fatalf("retired domain retire-inactive.se should not be offered")
	}
	if _, checked := doc.Find("input[name='domains'][value='example.se']").Attr("checked"); !checked {
		t.Fatalf("still verified example.se should stay checked")
	}
	// Domains the cloned version did not use are offered but not checked.
	if _, checked := doc.Find("input[name='domains'][value='example.com']").Attr("checked"); checked {
		t.Fatalf("example.com is not used by version 1 and should not be checked")
	}

	note := doc.Find(notCarriedOver)
	if note.Length() != 1 || !strings.Contains(note.Text(), "retire-inactive.se") {
		t.Fatalf("expected a note naming retire-inactive.se as not carried over, got %q", note.Text())
	}

	// The rest of the version is prefilled.
	if !strings.Contains(doc.Find("textarea").Text(), "#SUNET-CDN-MANAGER vcl_recv") {
		t.Fatalf("VCL template is not prefilled from version 1")
	}
	if doc.Find("input[value='198.51.100.10']").Length() == 0 {
		t.Fatalf("origin 198.51.100.10 is not prefilled from version 1")
	}
}

// TestRetireRacesActivation overlaps retiring retire-inactive.se with
// activating version 1 of org1-service1, which uses it, and with creating a
// new active version that uses it, in both orders. Whichever commits first
// wins and the other must be refused, so a domain is never retired while an
// active version uses it.
//
// Each case starts the first operation in a transaction the test keeps
// open, so the row locks it took stay held. It then starts the second
// operation on another connection, waits until that one is blocked on a row
// lock, and only then commits the first. What the second operation sees
// once it gets the lock decides the outcome.
//
// The held operations call the same Tx functions as the API and console
// paths (retireDomainTx, activateServiceVersionTx, insertServiceVersionTx),
// preceded by the identifier lookups their wrappers do. The wrappers
// themselves open and commit their own transaction, so they can only be
// used for the operation that waits.
func TestRetireRacesActivation(t *testing.T) {
	const fqdn = "retire-inactive.se"

	// setup gives every case its own database. The operation that waits
	// runs through dbc, which uses the shared test pool and its single
	// connection. The held transaction and the pg_stat_activity polling
	// need two more connections, from holdPool.
	setup := func(t *testing.T) (*pgxpool.Pool, *dbConn, *pgxpool.Pool) {
		t.Helper()
		ts, dbPool, err := prepareServer(t, testServerInput{})
		if dbPool != nil {
			t.Cleanup(dbPool.Close)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(ts.Close)
		addRetireFixtures(t, dbPool)

		cfg := dbPool.Config().Copy()
		cfg.MaxConns = 2
		holdPool, err := pgxpool.NewWithConfig(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(holdPool.Close)

		return dbPool, &dbConn{dbPool: dbPool, queryTimeout: time.Minute}, holdPool
	}

	begin := func(t *testing.T, pool *pgxpool.Pool) pgx.Tx {
		t.Helper()
		tx, err := pool.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			// Normally already committed, this covers an early t.Fatal().
			if err := tx.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
				t.Logf("rollback during cleanup: %v", err)
			}
		})
		return tx
	}

	// Takes FOR UPDATE on the domain row and marks it retired and not
	// verified.
	retireTx := func(ctx context.Context, tx pgx.Tx, ad cdntypes.AuthData) error {
		_, err := retireDomainTx(ctx, tx, ad, fqdn, "org1")
		return err
	}

	// Takes FOR UPDATE on the services row, FOR SHARE on version 1's
	// domain rows, then makes version 1 the active one.
	activateTx := func(ctx context.Context, tx pgx.Tx, ad cdntypes.AuthData) error {
		serviceIdent, err := resolveService(ctx, tx, ad, "org1-service1", "org1", lockUpdate)
		if err != nil {
			return err
		}
		_, err = activateServiceVersionTx(ctx, tx, serviceIdent, 1)
		return err
	}

	// Takes FOR UPDATE on the services row, inserts version 4 as the
	// active one, and looks its domain up FOR SHARE before linking it,
	// which also takes the foreign key's FOR KEY SHARE on the domain row.
	createActiveTx := func(ctx context.Context, tx pgx.Tx, ad cdntypes.AuthData) error {
		orgIdent, err := resolveOrg(ctx, tx, ad, "org1", lockShare)
		if err != nil {
			return err
		}
		serviceIdent, err := resolveService(ctx, tx, ad, "org1-service1", orgIdent.id.String(), lockUpdate)
		if err != nil {
			return err
		}
		defaultGroup := cdntypes.InputDefaultOriginGroup{Origins: []cdntypes.InputOrigin{{Host: "198.51.100.10", Port: 80}}}
		_, err = insertServiceVersionTx(ctx, tx, orgIdent, serviceIdent, []cdntypes.DomainString{fqdn}, nil, defaultGroup, true, "vcl 4.1;", "race")
		return err
	}

	// waitUntilBlocked returns once a backend in the test database waits
	// for a row lock. The held transaction is idle while the test waits, so
	// that backend can only be the second operation. If the second
	// operation finishes first it never waited for the held one, which is
	// exactly the race the locks are there to prevent.
	waitUntilBlocked := func(t *testing.T, pool *pgxpool.Pool, done <-chan error) {
		t.Helper()
		deadline := time.Now().Add(promptLimit)
		for {
			var blocked bool
			err := pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock')`).Scan(&blocked)
			if err != nil {
				t.Fatal(err)
			}
			if blocked {
				return
			}
			select {
			case err := <-done:
				t.Fatalf("the second operation finished without waiting for the first: %v", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("the second operation did not block on the first")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	activeVersion := func(t *testing.T, dbPool *pgxpool.Pool) int64 {
		t.Helper()
		var version int64
		err := dbPool.QueryRow(context.Background(), "SELECT version FROM service_versions WHERE service_id = $1 AND active", "00000003-0000-0000-0000-000000000001").Scan(&version)
		if err != nil {
			t.Fatal(err)
		}
		return version
	}

	domainRetired := func(t *testing.T, dbPool *pgxpool.Pool) bool {
		t.Helper()
		var retired bool
		err := dbPool.QueryRow(context.Background(), "SELECT time_retired IS NOT NULL FROM domains WHERE id = $1", retireInactiveDomainID).Scan(&retired)
		if err != nil {
			t.Fatal(err)
		}
		return retired
	}

	t.Run("retire commits before activation", func(t *testing.T) {
		dbPool, dbc, holdPool := setup(t)
		ad := scopeTestOrg1Member(t)
		ctx := context.Background()

		// Held: the domain row is locked FOR UPDATE and changed to
		// retired, not yet committed.
		tx := begin(t, holdPool)
		if err := retireTx(ctx, tx, ad); err != nil {
			t.Fatal(err)
		}

		// The activation gets the services row lock, which the retire
		// does not hold, and then blocks in unverifiedVersionDomainsTx:
		// its FOR SHARE on the domain row conflicts with the FOR UPDATE.
		// Without that FOR SHARE it would read the last committed row,
		// still verified, and activate without waiting.
		done := make(chan error, 1)
		go func() { done <- activateServiceVersion(ctx, ad, dbc, "org1", "org1-service1", 1) }()
		waitUntilBlocked(t, holdPool, done)

		// Once the retire commits, the locked row is read again, now
		// not verified, so the activation is refused before it has
		// deactivated anything.
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, cdnerrors.ErrDomainNotVerified) {
			t.Fatalf("activation after the retire committed: got %v, want ErrDomainNotVerified", err)
		}
		if v := activeVersion(t, dbPool); v != 3 {
			t.Fatalf("active version: got %d, want 3", v)
		}
	})

	t.Run("activation commits before retire", func(t *testing.T) {
		dbPool, dbc, holdPool := setup(t)
		ad := scopeTestOrg1Member(t)
		ctx := context.Background()
		logger := zerolog.New(zerolog.NewTestWriter(t))

		// Held: version 1 is made active, not yet committed, and its
		// domain row is locked FOR SHARE by unverifiedVersionDomainsTx.
		tx := begin(t, holdPool)
		if err := activateTx(ctx, tx, ad); err != nil {
			t.Fatal(err)
		}

		// The retire blocks in resolveDomain: its FOR UPDATE on the
		// domain row conflicts with the FOR SHARE. Without that FOR
		// SHARE it would not wait, would not see the uncommitted
		// activation when looking for active versions, and would retire
		// the domain under it.
		done := make(chan error, 1)
		go func() {
			_, err := retireDomain(ctx, &logger, dbc, ad, fqdn, "org1")
			done <- err
		}()
		waitUntilBlocked(t, holdPool, done)

		// Once the activation commits, the retire's look for active
		// versions finds version 1 and it is refused.
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok := errors.AsType[*cdnerrors.DomainActiveError](<-done); !ok {
			t.Fatal("retire after the activation committed should be refused with DomainActiveError")
		}
		if domainRetired(t, dbPool) {
			t.Fatal("the domain was retired although the active version uses it")
		}
		if v := activeVersion(t, dbPool); v != 1 {
			t.Fatalf("active version: got %d, want 1", v)
		}
	})

	t.Run("retire commits before active version creation", func(t *testing.T) {
		dbPool, dbc, holdPool := setup(t)
		ad := scopeTestOrg1Member(t)
		ctx := context.Background()

		// Held: the domain row is locked FOR UPDATE and changed to
		// retired, not yet committed.
		tx := begin(t, holdPool)
		if err := retireTx(ctx, tx, ad); err != nil {
			t.Fatal(err)
		}

		// The creation gets the services row lock and inserts version 4,
		// then blocks in insertServiceVersionTx's domain lookup: its FOR
		// SHARE conflicts with the FOR UPDATE. Without that FOR SHARE the
		// lookup would find the domain still verified, and the foreign
		// key check when linking it would only wait for the retire to
		// commit, after which the row still exists, so the version would
		// be created with a retired domain.
		done := make(chan error, 1)
		go func() {
			done <- pgx.BeginFunc(ctx, dbc.dbPool, func(tx pgx.Tx) error {
				return createActiveTx(ctx, tx, ad)
			})
		}()
		waitUntilBlocked(t, holdPool, done)

		// Once the retire commits, the locked row is read again and no
		// longer matches verified = true, so the domain is unknown and
		// the whole creation rolls back.
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, cdnerrors.ErrUnknownDomain) {
			t.Fatalf("version creation after the retire committed: got %v, want ErrUnknownDomain", err)
		}
		if v := activeVersion(t, dbPool); v != 3 {
			t.Fatalf("active version: got %d, want 3", v)
		}
	})

	t.Run("active version creation commits before retire", func(t *testing.T) {
		dbPool, dbc, holdPool := setup(t)
		ad := scopeTestOrg1Member(t)
		ctx := context.Background()
		logger := zerolog.New(zerolog.NewTestWriter(t))

		// Held: version 4 is inserted as the active one and linked to the
		// domain, not yet committed. The domain row is locked FOR SHARE
		// by the lookup and FOR KEY SHARE by the foreign key check.
		tx := begin(t, holdPool)
		if err := createActiveTx(ctx, tx, ad); err != nil {
			t.Fatal(err)
		}

		// The retire blocks in resolveDomain: its FOR UPDATE conflicts
		// with both locks. The foreign key lock alone would already make
		// it wait, so this case pins the outcome rather than the FOR
		// SHARE.
		done := make(chan error, 1)
		go func() {
			_, err := retireDomain(ctx, &logger, dbc, ad, fqdn, "org1")
			done <- err
		}()
		waitUntilBlocked(t, holdPool, done)

		// Once the creation commits, the retire finds version 4 active
		// and is refused.
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if _, ok := errors.AsType[*cdnerrors.DomainActiveError](<-done); !ok {
			t.Fatal("retire after the active version was created should be refused with DomainActiveError")
		}
		if domainRetired(t, dbPool) {
			t.Fatal("the domain was retired although the active version uses it")
		}
		if v := activeVersion(t, dbPool); v != 4 {
			t.Fatalf("active version: got %d, want 4", v)
		}
	})
}
