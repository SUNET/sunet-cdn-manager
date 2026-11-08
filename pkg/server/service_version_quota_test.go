package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestServiceVersionQuotaExposed verifies that the version quota is returned
// by service create, get and list, with the default for a new service and the
// stored value after it has been changed.
func TestServiceVersionQuotaExposed(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)

	status, body := apiJSON(t, http.MethodPost, serverURL+"/api/v1/services", "admin", validAdminPassword, map[string]string{"name": "quota-exposed", "org": "org1"})
	if status != http.StatusCreated {
		t.Fatalf("POST returned %d, want %d: %s", status, http.StatusCreated, body)
	}
	var created cdntypes.Service
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("unable to decode response %q: %s", body, err)
	}
	if created.VersionQuota != 1000 {
		t.Errorf("created service has version_quota %d, want 1000", created.VersionQuota)
	}

	serviceID := created.ID.String()

	status, body = apiJSON(t, http.MethodGet, serverURL+"/api/v1/services/"+serviceID, "admin", validAdminPassword, nil)
	if status != http.StatusOK {
		t.Fatalf("GET returned %d, want %d: %s", status, http.StatusOK, body)
	}
	var got cdntypes.Service
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("unable to decode response %q: %s", body, err)
	}
	if got.VersionQuota != 1000 {
		t.Errorf("fetched service has version_quota %d, want 1000", got.VersionQuota)
	}

	setVersionQuota(t, dbPool, serviceID, 7)

	status, body = apiJSON(t, http.MethodGet, serverURL+"/api/v1/services?org=org1", "admin", validAdminPassword, nil)
	if status != http.StatusOK {
		t.Fatalf("list returned %d, want %d: %s", status, http.StatusOK, body)
	}
	var list []cdntypes.Service
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("unable to decode response %q: %s", body, err)
	}
	found := false
	for _, s := range list {
		if s.ID.String() == serviceID {
			found = true
			if s.VersionQuota != 7 {
				t.Errorf("listed service has version_quota %d, want 7", s.VersionQuota)
			}
		}
	}
	if !found {
		t.Errorf("service %s not in list: %s", serviceID, body)
	}
}

// setVersionQuota sets the version quota of a service directly in the
// database.
func setVersionQuota(t *testing.T, dbPool *pgxpool.Pool, serviceID string, quota int64) {
	t.Helper()

	_, err := dbPool.Exec(context.Background(), "UPDATE services SET version_quota = $1 WHERE id = $2", quota, serviceID)
	if err != nil {
		t.Fatal(err)
	}
}

// quotaBody returns a version body whose content differs per n.
func quotaBody(n int) versionBody {
	body := baseVersionBody()
	body.DefaultOriginGroup.Origins[0].Port = 8000 + n
	return body
}

func TestPostServiceVersionQuotaReached(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-reached", 1001100000)
	setVersionQuota(t, dbPool, serviceID, 2)

	for i := 1; i <= 2; i++ {
		status, _ := postVersion(t, serverURL, serviceID, quotaBody(i))
		if status != http.StatusCreated {
			t.Fatalf("POST %d returned %d, want %d", i, status, http.StatusCreated)
		}
	}

	status, body := apiJSON(t, http.MethodPost, serverURL+"/api/v1/services/"+serviceID+"/service-versions", "admin", validAdminPassword, quotaBody(3))
	if status != http.StatusConflict {
		t.Fatalf("POST over the quota returned %d, want %d: %s", status, http.StatusConflict, body)
	}
	if want := "service version quota reached (2 of 2), contact an operator to raise it"; !strings.Contains(body, want) {
		t.Fatalf("response %q does not contain %q", body, want)
	}
	if n := serviceVersionCount(t, dbPool, serviceID); n != 2 {
		t.Fatalf("service has %d versions, want 2", n)
	}

	var counter int64
	err := dbPool.QueryRow(context.Background(), "SELECT version_counter FROM services WHERE id = $1", serviceID).Scan(&counter)
	if err != nil {
		t.Fatal(err)
	}
	if counter != 2 {
		t.Fatalf("version_counter is %d, want 2: the refused attempt must not use up a version number", counter)
	}
}

func TestPostServiceVersionQuotaDuplicateStillAllowed(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-duplicate", 1001110000)
	setVersionQuota(t, dbPool, serviceID, 2)

	status, first := postVersion(t, serverURL, serviceID, quotaBody(1))
	if status != http.StatusCreated {
		t.Fatalf("first POST returned %d, want %d", status, http.StatusCreated)
	}
	status, _ = postVersion(t, serverURL, serviceID, quotaBody(2))
	if status != http.StatusCreated {
		t.Fatalf("second POST returned %d, want %d", status, http.StatusCreated)
	}

	again := quotaBody(1)
	again.Active = true
	status, got := postVersion(t, serverURL, serviceID, again)
	if status != http.StatusOK {
		t.Fatalf("duplicate POST at the quota returned %d, want %d", status, http.StatusOK)
	}
	if got.Version != first.Version {
		t.Fatalf("duplicate POST returned version %d, want %d", got.Version, first.Version)
	}
	if v := activeServiceVersion(t, dbPool, serviceID); v != first.Version {
		t.Fatalf("active version is %d, want %d", v, first.Version)
	}
	if n := serviceVersionCount(t, dbPool, serviceID); n != 2 {
		t.Fatalf("service has %d versions, want 2", n)
	}
}

func TestActivateServiceVersionAtQuota(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-activate", 1001120000)
	setVersionQuota(t, dbPool, serviceID, 2)

	for i := 1; i <= 2; i++ {
		status, _ := postVersion(t, serverURL, serviceID, quotaBody(i))
		if status != http.StatusCreated {
			t.Fatalf("POST %d returned %d, want %d", i, status, http.StatusCreated)
		}
	}

	status, body := apiJSON(t, http.MethodPut, serverURL+"/api/v1/services/"+serviceID+"/service-versions/1/active", "admin", validAdminPassword, map[string]bool{"active": true})
	if status != http.StatusNoContent {
		t.Fatalf("activate at the quota returned %d, want %d: %s", status, http.StatusNoContent, body)
	}
	if v := activeServiceVersion(t, dbPool, serviceID); v != 1 {
		t.Fatalf("active version is %d, want 1", v)
	}
}

func TestPostServiceVersionQuotaZero(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-zero", 1001130000)
	setVersionQuota(t, dbPool, serviceID, 0)

	status, body := apiJSON(t, http.MethodPost, serverURL+"/api/v1/services/"+serviceID+"/service-versions", "admin", validAdminPassword, quotaBody(1))
	if status != http.StatusConflict {
		t.Fatalf("POST with quota 0 returned %d, want %d: %s", status, http.StatusConflict, body)
	}
	if !strings.Contains(body, "(0 of 0)") {
		t.Fatalf("response %q does not contain %q", body, "(0 of 0)")
	}
	if n := serviceVersionCount(t, dbPool, serviceID); n != 0 {
		t.Fatalf("service has %d versions, want 0", n)
	}
}

// TestPostServiceVersionQuotaConcurrent races two different versions for the
// last free slot: exactly one may win. That depends on inserts for a service
// being serialized on its row lock: the second must not count the versions
// until the first has committed.
func TestPostServiceVersionQuotaConcurrent(t *testing.T) {
	rs := prepareRaceServer(t)
	serviceID := newEmptyService(t, rs.dbPool, "quota-concurrent", 1001140000)
	setVersionQuota(t, rs.dbPool, serviceID, 1)

	statuses := rs.postRacingVersions(t, serviceID, [2]string{"198.51.100.21", "198.51.100.22"})

	if statuses[http.StatusCreated] != 1 || statuses[http.StatusConflict] != 1 {
		t.Fatalf("got statuses %v, want one %d and one %d", statuses, http.StatusCreated, http.StatusConflict)
	}
	if n := serviceVersionCount(t, rs.dbPool, serviceID); n != 1 {
		t.Fatalf("service has %d versions, want 1", n)
	}
}

func TestConsoleCreateServiceVersionQuotaReached(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-console", 1001150000)
	setVersionQuota(t, dbPool, serviceID, 1)

	status, _ := postVersion(t, serverURL, serviceID, quotaBody(1))
	if status != http.StatusCreated {
		t.Fatalf("POST returned %d, want %d", status, http.StatusCreated)
	}

	client, _ := consoleLogin(t, serverURL, "username1", validUserPassword)

	form := createVersionForm()
	form.Set("description", "quota-kept")
	req, err := http.NewRequest(http.MethodPost, serverURL+"/console/org/org1/create/service/version/"+serviceID, strings.NewReader(form.Encode()))
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
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("submission returned %d, want the form again (%d)", resp.StatusCode, http.StatusOK)
	}
	if !strings.Contains(body, `id="error-message"`) {
		t.Fatalf("page has no error message: %s", body)
	}
	if want := "Service version quota reached (1 of 1), contact an operator to raise it"; !strings.Contains(body, want) {
		t.Fatalf("page does not contain %q: %s", want, body)
	}
	if !strings.Contains(body, "quota-kept") {
		t.Fatalf("re-rendered form lost the submitted description: %s", body)
	}
	if n := serviceVersionCount(t, dbPool, serviceID); n != 1 {
		t.Fatalf("service has %d versions, want 1", n)
	}
}

func TestPutServiceVersionQuota(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-put", 1001300000)

	for i := 1; i <= 2; i++ {
		status, _ := postVersion(t, serverURL, serviceID, quotaBody(i))
		if status != http.StatusCreated {
			t.Fatalf("POST %d returned %d, want %d", i, status, http.StatusCreated)
		}
	}

	tests := []struct {
		name      string
		path      string
		user      string
		password  string
		quota     int64
		wantCode  int
		wantBody  string
		wantQuota *int64 // nil means the stored quota is not checked
	}{
		{name: "non-superuser", path: serviceID + "/version-quota", user: "username1", password: validUserPassword, quota: 10, wantCode: http.StatusForbidden},
		{name: "below usage", path: serviceID + "/version-quota", user: "admin", password: validAdminPassword, quota: 1, wantCode: http.StatusUnprocessableEntity, wantBody: "quota 1, usage 2"},
		{name: "negative", path: serviceID + "/version-quota", user: "admin", password: validAdminPassword, quota: -1, wantCode: http.StatusUnprocessableEntity},
		{name: "equal to usage", path: serviceID + "/version-quota", user: "admin", password: validAdminPassword, quota: 2, wantCode: http.StatusNoContent, wantQuota: new(int64(2))},
		{name: "by name with org", path: "quota-put/version-quota?org=org1", user: "admin", password: validAdminPassword, quota: 5, wantCode: http.StatusNoContent, wantQuota: new(int64(5))},
		// 400, like every other endpoint taking a service by name: resolveService
		// reports the missing org as a bad identifier.
		{name: "by name without org", path: "quota-put/version-quota", user: "admin", password: validAdminPassword, quota: 7, wantCode: http.StatusBadRequest, wantBody: "looking up service by name requires org"},
		{name: "unknown service", path: "00000000-0000-4000-8000-000000000001/version-quota", user: "admin", password: validAdminPassword, quota: 7, wantCode: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := apiJSON(t, http.MethodPut, serverURL+"/api/v1/services/"+tt.path, tt.user, tt.password, map[string]int64{"version_quota": tt.quota})
			if status != tt.wantCode {
				t.Fatalf("PUT returned %d, want %d: %s", status, tt.wantCode, body)
			}
			if tt.wantBody != "" && !strings.Contains(body, tt.wantBody) {
				t.Fatalf("response %q does not contain %q", body, tt.wantBody)
			}
			if tt.wantQuota != nil {
				if got := dbVersionQuota(t, dbPool, serviceID); got != *tt.wantQuota {
					t.Fatalf("version_quota is %d, want %d", got, *tt.wantQuota)
				}
			}
		})
	}
}

// Zero is a valid quota, it stops new versions, but only a service without
// versions can be set to it, and only when given explicitly: a body without
// version_quota must not be read as 0.
func TestPutServiceVersionQuotaZeroWithoutVersions(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-put-zero", 1001520000)

	status, body := apiJSON(t, http.MethodPut, serverURL+"/api/v1/services/"+serviceID+"/version-quota", "admin", validAdminPassword, map[string]int64{})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("PUT without version_quota returned %d, want %d: %s", status, http.StatusUnprocessableEntity, body)
	}
	if got := dbVersionQuota(t, dbPool, serviceID); got != 1000 {
		t.Fatalf("version_quota is %d after PUT without it, want 1000", got)
	}

	status, body = apiJSON(t, http.MethodPut, serverURL+"/api/v1/services/"+serviceID+"/version-quota", "admin", validAdminPassword, map[string]int64{"version_quota": 0})
	if status != http.StatusNoContent {
		t.Fatalf("PUT returned %d, want %d: %s", status, http.StatusNoContent, body)
	}
	if got := dbVersionQuota(t, dbPool, serviceID); got != 0 {
		t.Fatalf("version_quota is %d, want 0", got)
	}
}

func TestServiceVersionQuotaRaiseWorkflow(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-raise", 1001310000)
	setVersionQuota(t, dbPool, serviceID, 2)

	for i := 1; i <= 2; i++ {
		status, _ := postVersion(t, serverURL, serviceID, quotaBody(i))
		if status != http.StatusCreated {
			t.Fatalf("POST %d returned %d, want %d", i, status, http.StatusCreated)
		}
	}

	status, _ := postVersion(t, serverURL, serviceID, quotaBody(3))
	if status != http.StatusConflict {
		t.Fatalf("POST over the quota returned %d, want %d", status, http.StatusConflict)
	}

	status, body := apiJSON(t, http.MethodPut, serverURL+"/api/v1/services/"+serviceID+"/version-quota", "admin", validAdminPassword, map[string]int64{"version_quota": 3})
	if status != http.StatusNoContent {
		t.Fatalf("PUT returned %d, want %d: %s", status, http.StatusNoContent, body)
	}

	status, sv := postVersion(t, serverURL, serviceID, quotaBody(3))
	if status != http.StatusCreated {
		t.Fatalf("retried POST returned %d, want %d", status, http.StatusCreated)
	}
	if sv.Version != 3 {
		t.Fatalf("retried POST created version %d, want 3: the refused attempt must not use up a version number", sv.Version)
	}
	if n := serviceVersionCount(t, dbPool, serviceID); n != 3 {
		t.Fatalf("service has %d versions, want 3", n)
	}
}

// consoleQuotaPost POSTs the version quota form as the given console user and
// returns the final status and body, after redirects.
func consoleQuotaPost(t *testing.T, serverURL string, username string, password string, serviceID string, value string) (int, string) {
	t.Helper()

	return consoleQuotaPostForm(t, serverURL, username, password, serviceID, url.Values{"version-quota": {value}})
}

// consoleQuotaPostForm is consoleQuotaPost with the whole form chosen by the
// caller, so a test can leave the field out.
func consoleQuotaPostForm(t *testing.T, serverURL string, username string, password string, serviceID string, form url.Values) (int, string) {
	t.Helper()

	client, _ := consoleLogin(t, serverURL, username, password)

	req, err := http.NewRequest(http.MethodPost, serverURL+"/console/org/org1/services/"+serviceID+"/version-quota", strings.NewReader(form.Encode()))
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
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

func dbVersionQuota(t *testing.T, dbPool *pgxpool.Pool, serviceID string) int64 {
	t.Helper()

	var quota int64
	err := dbPool.QueryRow(context.Background(), "SELECT version_quota FROM services WHERE id = $1", serviceID).Scan(&quota)
	if err != nil {
		t.Fatal(err)
	}
	return quota
}

func TestConsoleServiceVersionQuota(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-form", 1001500000)

	for i := 1; i <= 2; i++ {
		status, _ := postVersion(t, serverURL, serviceID, quotaBody(i))
		if status != http.StatusCreated {
			t.Fatalf("POST %d returned %d, want %d", i, status, http.StatusCreated)
		}
	}

	tests := []struct {
		name      string
		username  string
		password  string
		value     string
		wantCode  int
		wantBody  string
		wantQuota int64
	}{
		{"non-superuser", "username1", validUserPassword, "50", http.StatusForbidden, "", 1000},
		{"below usage", "admin", validAdminPassword, "1", http.StatusOK, "Cannot be lower than the current number of service versions", 1000},
		{"negative", "admin", validAdminPassword, "-1", http.StatusOK, validationMinZero, 1000},
		{"non-numeric", "admin", validAdminPassword, "abc", http.StatusOK, consoleQuotaNotNumber, 1000},
		{"success", "admin", validAdminPassword, "50", http.StatusOK, "2 of 50 versions used", 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := consoleQuotaPost(t, serverURL, tt.username, tt.password, serviceID, tt.value)
			if status != tt.wantCode {
				t.Fatalf("status %d, want %d: %s", status, tt.wantCode, body)
			}
			if !strings.Contains(body, tt.wantBody) {
				t.Fatalf("body does not contain %q: %s", tt.wantBody, body)
			}
			if got := dbVersionQuota(t, dbPool, serviceID); got != tt.wantQuota {
				t.Fatalf("version_quota is %d, want %d", got, tt.wantQuota)
			}
		})
	}
}

// TestConsoleServiceVersionQuotaRequiresValue checks that an empty or missing
// quota is refused rather than decoded as 0. On a service without versions 0
// passes the usage check, so only an explicit "0" may set it.
func TestConsoleServiceVersionQuotaRequiresValue(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-required", 1001510000)

	tests := []struct {
		name      string
		form      url.Values
		wantBody  string
		wantQuota int64
	}{
		{"empty", url.Values{"version-quota": {""}}, consoleQuotaNotNumber, 1000},
		{"missing", url.Values{}, consoleQuotaNotNumber, 1000},
		{"explicit zero", url.Values{"version-quota": {"0"}}, "0 of 0 versions used", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := consoleQuotaPostForm(t, serverURL, "admin", validAdminPassword, serviceID, tt.form)
			if status != http.StatusOK {
				t.Fatalf("status %d, want %d: %s", status, http.StatusOK, body)
			}
			if !strings.Contains(body, tt.wantBody) {
				t.Fatalf("body does not contain %q: %s", tt.wantBody, body)
			}
			if got := dbVersionQuota(t, dbPool, serviceID); got != tt.wantQuota {
				t.Fatalf("version_quota is %d, want %d", got, tt.wantQuota)
			}
		})
	}
}

func TestConsoleServicePageVersionQuotaLine(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)
	serviceID := newEmptyService(t, dbPool, "quota-page", 1001510000)

	status, _ := postVersion(t, serverURL, serviceID, quotaBody(1))
	if status != http.StatusCreated {
		t.Fatalf("POST returned %d, want %d", status, http.StatusCreated)
	}

	client, _ := consoleLogin(t, serverURL, "username1", validUserPassword)
	resp, err := client.Get(serverURL + "/console/org/org1/services/quota-page") // #nosec G704 -- test URL
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "1 of 1000 versions used") {
		t.Fatalf("page has no usage line: %s", body)
	}
	if strings.Contains(body, `name="version-quota"`) {
		t.Fatalf("non-superuser sees the quota form: %s", body)
	}
}

func TestConsoleOrgDashboardServiceVersions(t *testing.T) {
	serverURL, dbPool := prepareVersionServer(t)

	type orgService struct {
		ID   pgtype.UUID
		Name string
	}
	rows, err := dbPool.Query(context.Background(), `SELECT id, name FROM services WHERE org_id = (SELECT id FROM orgs WHERE name = $1) ORDER BY name`, "org1")
	if err != nil {
		t.Fatal(err)
	}
	services, err := pgx.CollectRows(rows, pgx.RowToStructByPos[orgService])
	if err != nil {
		t.Fatal(err)
	}
	if len(services) == 0 {
		t.Fatal("org1 has no services")
	}

	client, _ := consoleLogin(t, serverURL, "username1", validUserPassword)

	type dashboardRow struct {
		name  string
		quota string
	}
	// dashboardRows returns the cards of the dashboard's "Service versions" section
	// in page order.
	dashboardRows := func() []dashboardRow {
		t.Helper()
		resp, err := client.Get(serverURL + "/console/org/org1") // #nosec G704 -- test URL
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		heading := doc.Find("h2").FilterFunction(func(_ int, h *goquery.Selection) bool {
			return h.Text() == "Service versions"
		})
		if heading.Length() != 1 {
			t.Fatalf("found %d Service versions headings, want 1", heading.Length())
		}
		var rows []dashboardRow
		heading.Next().Find("article").Each(func(_ int, a *goquery.Selection) {
			rows = append(rows, dashboardRow{
				name:  a.Find("header a").Text(),
				quota: a.Find(".quota-value").Text(),
			})
		})
		return rows
	}

	before := dashboardRows()
	if len(before) != len(services) {
		t.Fatalf("dashboard shows %d services, want %d: %+v", len(before), len(services), before)
	}
	for i, svc := range services {
		if before[i].name != svc.Name {
			t.Fatalf("row %d is %q, want %q (services in name order)", i, before[i].name, svc.Name)
		}
	}

	setVersionQuota(t, dbPool, services[0].ID.String(), 5)
	// The seeded services may already have versions, so take the used
	// count from the row as it was before the update.
	used, ok := strings.CutSuffix(before[0].quota, "/1000")
	if !ok {
		t.Fatalf("row for %q showed %q before update, want default /1000", services[0].Name, before[0].quota)
	}
	if after := dashboardRows()[0].quota; after != used+"/5" {
		t.Fatalf("row for %q shows %q after update, want %q", services[0].Name, after, used+"/5")
	}
}
