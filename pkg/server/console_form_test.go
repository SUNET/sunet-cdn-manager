package server

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

func TestCreateServiceVersionFormDecode(t *testing.T) {
	form := url.Values{}
	form.Set("vcl_template", "vcl-content")
	form.Set("description", "my service version")
	form.Add("domains", "example.com")
	form.Set("conditional-origin-groups.0.name", "api")
	form.Set("conditional-origin-groups.0.condition", `req.url ~ "^/api/"`)
	form.Set("conditional-origin-groups.0.origins.0.host", "10.0.0.1")
	form.Set("conditional-origin-groups.0.origins.0.port", "443")
	form.Set("conditional-origin-groups.0.origins.0.tls", "on")
	form.Set("conditional-origin-groups.0.origins.0.verify-tls", "on")
	form.Set("conditional-origin-groups.1.name", "static")
	form.Set("conditional-origin-groups.1.condition", "req.url ~ \"^/a\" ||\nreq.url ~ \"^/b\"")
	form.Set("conditional-origin-groups.1.origins.0.host", "10.0.1.1")
	form.Set("conditional-origin-groups.1.origins.0.port", "80")
	form.Set("default-origin-group.origins.0.host", "10.0.2.1")
	form.Set("default-origin-group.origins.0.port", "443")
	form.Set("default-origin-group.origins.0.tls", "on")

	formData := cdntypes.CreateServiceVersionForm{}
	if err := schemaDecoder.Decode(&formData, form); err != nil {
		t.Fatal(err)
	}

	if formData.Description != "my service version" {
		t.Errorf("description not decoded: got %q", formData.Description)
	}
	if len(formData.ConditionalGroups) != 2 {
		t.Fatalf("expected 2 conditional groups, got %d", len(formData.ConditionalGroups))
	}
	if formData.ConditionalGroups[0].Name != "api" || formData.ConditionalGroups[1].Name != "static" {
		t.Errorf("group order not preserved: %+v", formData.ConditionalGroups)
	}
	if formData.ConditionalGroups[0].Origins[0].OriginPort != 443 {
		t.Errorf("nested origin not decoded: %+v", formData.ConditionalGroups[0].Origins)
	}
	if len(formData.DefaultGroup.Origins) != 1 || formData.DefaultGroup.Origins[0].OriginHost != "10.0.2.1" {
		t.Errorf("default group origins not decoded: %+v", formData.DefaultGroup)
	}
}

// TestMapCreateServiceVersionForm covers mapCreateServiceVersionForm, the
// function consoleCreateServiceVersionHandler's POST branch uses to convert
// decoded+validated form data into the InputConditionalOriginGroup/
// InputDefaultOriginGroup shapes insertServiceVersion expects. This is I4's
// fallback path: a full httptest-based end-to-end console POST test would
// need an authenticated session (a consoleLogin helper already exists for
// that) plus figuring out the org-selection and nested gorilla/schema
// dotted-index form encoding from scratch, since no existing test exercises
// a console form POST with nested array fields. That is a bigger, riskier
// lift than unit-testing the extracted mapping function directly, which
// covers the same order-preservation/defaulting/validation logic that
// matters here.
func TestMapCreateServiceVersionForm(t *testing.T) {
	t.Run("order and nesting preserved, default group named default", func(t *testing.T) {
		form := url.Values{}
		form.Set("vcl_template", "vcl-content")
		form.Add("domains", "example.com")
		form.Set("conditional-origin-groups.0.name", "api")
		form.Set("conditional-origin-groups.0.condition", `req.url ~ "^/api/"`)
		form.Set("conditional-origin-groups.0.origins.0.host", "10.0.0.1")
		form.Set("conditional-origin-groups.0.origins.0.port", "443")
		form.Set("conditional-origin-groups.0.origins.0.tls", "on")
		form.Set("conditional-origin-groups.0.origins.0.verify-tls", "on")
		form.Set("conditional-origin-groups.1.name", "static")
		form.Set("conditional-origin-groups.1.condition", `req.url ~ "^/static/"`)
		form.Set("conditional-origin-groups.1.origins.0.host", "10.0.1.1")
		form.Set("conditional-origin-groups.1.origins.0.port", "80")
		form.Set("default-origin-group.origins.0.host", "10.0.2.1")
		form.Set("default-origin-group.origins.0.port", "443")
		form.Set("default-origin-group.origins.0.tls", "on")

		formData := cdntypes.CreateServiceVersionForm{}
		if err := schemaDecoder.Decode(&formData, form); err != nil {
			t.Fatal(err)
		}

		conditionalGroups, defaultGroup, err := mapCreateServiceVersionForm(formData)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}

		if len(conditionalGroups) != 2 {
			t.Fatalf("expected 2 conditional groups, got %d: %+v", len(conditionalGroups), conditionalGroups)
		}
		if conditionalGroups[0].Name != "api" || conditionalGroups[1].Name != "static" {
			t.Errorf("conditional group order not preserved: %+v", conditionalGroups)
		}
		if conditionalGroups[0].Condition != `req.url ~ "^/api/"` {
			t.Errorf("conditional group condition not mapped: %+v", conditionalGroups[0])
		}
		if len(conditionalGroups[0].Origins) != 1 || conditionalGroups[0].Origins[0].Host != "10.0.0.1" || conditionalGroups[0].Origins[0].Port != 443 {
			t.Errorf("nested origins not mapped for group 0: %+v", conditionalGroups[0].Origins)
		}
		if !conditionalGroups[0].Origins[0].TLS || !conditionalGroups[0].Origins[0].VerifyTLS {
			t.Errorf("origin TLS/VerifyTLS flags not mapped for group 0: %+v", conditionalGroups[0].Origins[0])
		}
		if len(conditionalGroups[1].Origins) != 1 || conditionalGroups[1].Origins[0].Host != "10.0.1.1" || conditionalGroups[1].Origins[0].Port != 80 {
			t.Errorf("nested origins not mapped for group 1: %+v", conditionalGroups[1].Origins)
		}

		if len(defaultGroup.Origins) != 1 || defaultGroup.Origins[0].Host != "10.0.2.1" || !defaultGroup.Origins[0].TLS {
			t.Errorf("default group origins not mapped: %+v", defaultGroup.Origins)
		}
	})

	t.Run("invalid conditional group name rejected", func(t *testing.T) {
		// "My Group" has an uppercase letter and a space, so it fails the
		// DNS-label pattern the API enforces via huma but the console
		// form type does not (min=1,max=63 only). Without
		// mapCreateServiceVersionForm's originGroupNamePattern check this
		// would sail through to VCL generation.
		formData := cdntypes.CreateServiceVersionForm{
			ConditionalGroups: []cdntypes.CreateServiceVersionConditionalGroup{
				{
					Name:      "My Group",
					Condition: `req.url ~ "^/api/"`,
					Origins: []cdntypes.CreateServiceVersionOrigin{
						{OriginHost: "10.0.0.1", OriginPort: 443},
					},
				},
			},
			DefaultGroup: cdntypes.CreateServiceVersionDefaultGroup{
				Origins: []cdntypes.CreateServiceVersionOrigin{
					{OriginHost: "10.0.2.1", OriginPort: 443},
				},
			},
		}

		_, _, err := mapCreateServiceVersionForm(formData)
		if err == nil {
			t.Fatal("expected an error for an invalid conditional group name, got nil")
		}
	})

	t.Run("valid DNS-label conditional group name accepted", func(t *testing.T) {
		formData := cdntypes.CreateServiceVersionForm{
			ConditionalGroups: []cdntypes.CreateServiceVersionConditionalGroup{
				{
					Name:      "api-2",
					Condition: `req.url ~ "^/api/"`,
					Origins: []cdntypes.CreateServiceVersionOrigin{
						{OriginHost: "10.0.0.1", OriginPort: 443},
					},
				},
			},
			DefaultGroup: cdntypes.CreateServiceVersionDefaultGroup{
				Origins: []cdntypes.CreateServiceVersionOrigin{
					{OriginHost: "10.0.2.1", OriginPort: 443},
				},
			},
		}

		if _, _, err := mapCreateServiceVersionForm(formData); err != nil {
			t.Fatalf("unexpected error for valid DNS-label name: %s", err)
		}
	})
}

// TestDeleteServiceNeedsDisabledPageNamesTheService checks the stale-state
// error path on the delete confirmation page.
//
// The Delete link only renders for a disabled service, so reaching the
// "must be disabled first" page means the service was re-enabled after the
// services list was rendered. That URL carries the service UUID, so the
// handler has to supply the resolved name or the breadcrumb trail shows a
// UUID to the user.
func TestDeleteServiceNeedsDisabledPageNamesTheService(t *testing.T) {
	const enabledServiceID = "00000003-0000-0000-0000-000000000001"

	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	// Deleting a service is a superuser action.
	client, _ := consoleLogin(t, ts.URL, "admin-with-org", validAdminPassword)

	resp, err := client.Get(ts.URL + "/console/org/org1/services/" + enabledServiceID + "/delete") // #nosec G704
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	// The fixture service is enabled, so this must be the needs-disabled page.
	if !strings.Contains(doc.Text(), "must be disabled before it can be deleted") {
		t.Fatalf("expected the needs-disabled page, got:\n%s", doc.Text())
	}

	crumbs := doc.Find("nav.breadcrumb a")
	if crumbs.Length() == 0 {
		t.Fatal("no breadcrumb links rendered")
	}

	var labels []string
	crumbs.Each(func(_ int, a *goquery.Selection) {
		labels = append(labels, strings.TrimSpace(a.Text()))
	})

	for _, label := range labels {
		if label == enabledServiceID {
			t.Errorf("breadcrumb shows the service UUID instead of its name: %v", labels)
		}
	}
	if !slices.Contains(labels, "org1-service1") {
		t.Errorf("breadcrumb does not name the service, labels were: %v", labels)
	}
}

// createVersionValidator starts a VCL validator so create-version POSTs can
// actually succeed. Without one every POST fails and any assertion about a
// version NOT being created passes vacuously.
func createVersionValidator(t *testing.T) *vclValidatorClient {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "platform.sunet.se/sunet-cdn/sunet-vcl-validator:e46f64d255425ec1d87329b9a7246101b1416547",
		ExposedPorts: []string{"8888/tcp"},
		WaitingFor:   wait.ForLog("starting server"),
	}

	ctx := context.Background()
	validatorC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	// Not deferred: CleanupContainer registers t.Cleanup rather than
	// terminating, and t is the parent test, so the container lives until
	// that test ends rather than until this helper returns. Called before the
	// error check on purpose, so a partially-created container is still torn
	// down.
	testcontainers.CleanupContainer(t, validatorC)
	if err != nil {
		t.Fatal(err)
	}

	endpoint, err := validatorC.PortEndpoint(ctx, "8888/tcp", "")
	if err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse("http://" + endpoint + "/validate-vcl")
	if err != nil {
		t.Fatal(err)
	}

	return newVclValidator(u)
}

// createVersionForm is a minimally valid create-service-version submission for
// org1, whose fixtures include the verified domain example.se.
func createVersionForm() url.Values {
	return url.Values{
		"vcl_template":                        {cdntypes.DefaultVCLTemplate},
		"description":                         {"version from a captured form"},
		"domains":                             {"example.se"},
		"default-origin-group.origins.0.host": {"192.0.2.10"},
		"default-origin-group.origins.0.port": {"443"},
		"default-origin-group.origins.0.tls":  {"on"},
	}
}

// TestCreateServiceVersionFormSurvivesNameReuse covers the flow where a stale
// reference is most costly, and covers it end to end rather than stopping at
// the navigation link.
//
// The user opens the create-version form while the service exists, spends
// minutes filling it in, and submits. Meanwhile the service is deleted and a
// new one is created reusing the name. The captured form action must not
// deposit the version on the replacement.
//
// The positive control matters: the same form body is first submitted against
// a live service and asserted to create a version. Without it, a malformed
// body would make the negative assertion pass for the wrong reason.
func TestCreateServiceVersionFormSurvivesNameReuse(t *testing.T) {
	const (
		serviceName = "toctou-version-service"
		firstID     = "00000003-0000-0000-0000-0000000000f3"
		secondID    = "00000003-0000-0000-0000-0000000000f4"
		controlName = "toctou-control-service"
		controlID   = "00000003-0000-0000-0000-0000000000f5"
	)

	validator := createVersionValidator(t)

	ts, dbPool, err := prepareServer(t, testServerInput{vclValidator: validator})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	for _, svc := range []struct {
		id, name, uidRange string
	}{
		{firstID, serviceName, "'(1000920000, 1000929999)'"},
		{controlID, controlName, "'(1000940000, 1000949999)'"},
	} {
		_, err = dbPool.Exec(ctx,
			"INSERT INTO services (id, org_id, name, uid_range) SELECT $1, id, $2, "+svc.uidRange+" FROM orgs WHERE name='org1'",
			svc.id, svc.name)
		if err != nil {
			t.Fatal(err)
		}
	}

	client, _ := consoleLogin(t, ts.URL, "username1", validUserPassword)

	// formAction opens the create-version page for a service and returns the
	// action of the form rendered there.
	formAction := func(name string) string {
		t.Helper()
		resp, err := client.Get(ts.URL + "/console/org/org1/services/" + name) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		href := ""
		doc.Find("a").EachWithBreak(func(_ int, a *goquery.Selection) bool {
			if strings.Contains(strings.ToLower(a.Text()), "create your first version") {
				href, _ = a.Attr("href")
				return false
			}
			return true
		})
		if href == "" {
			t.Fatalf("no create-version link on the page for %q", name)
		}

		formResp, err := client.Get(ts.URL + href) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer formResp.Body.Close()
		if formResp.StatusCode != http.StatusOK {
			t.Fatalf("create-version page for %q returned %d", name, formResp.StatusCode)
		}

		formDoc, err := goquery.NewDocumentFromReader(formResp.Body)
		if err != nil {
			t.Fatal(err)
		}
		action, ok := formDoc.Find("form[method='post']").First().Attr("action")
		if !ok {
			t.Fatalf("no form action on the create-version page for %q", name)
		}
		return action
	}

	submit := func(action string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, ts.URL+action, strings.NewReader(createVersionForm().Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")

		resp, err := client.Do(req) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	versionCount := func(serviceID string) int64 {
		t.Helper()
		var n int64
		if err := dbPool.QueryRow(ctx, "SELECT COUNT(*) FROM service_versions WHERE service_id = $1", serviceID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Positive control: this exact form body does create a version.
	controlAction := formAction(controlName)
	submit(controlAction)
	if got := versionCount(controlID); got != 1 {
		t.Fatalf("control service has %d versions, want 1 -- the form body is not valid, so the negative case below would pass for the wrong reason", got)
	}

	// Now the real case. Open the form while the first service exists.
	staleAction := formAction(serviceName)

	if !strings.Contains(staleAction, firstID) {
		t.Errorf("form action does not carry the service UUID: %q", staleAction)
	}
	if strings.Contains(staleAction, serviceName) {
		t.Errorf("form action still addresses the service by name: %q", staleAction)
	}

	// The user is still typing. Meanwhile the service is replaced by a
	// different one reusing the name.
	if _, err := dbPool.Exec(ctx, "DELETE FROM services WHERE id = $1", firstID); err != nil {
		t.Fatal(err)
	}
	_, err = dbPool.Exec(ctx,
		"INSERT INTO services (id, org_id, name, uid_range) SELECT $1, id, $2, '(1000930000, 1000939999)' FROM orgs WHERE name='org1'",
		secondID, serviceName)
	if err != nil {
		t.Fatal(err)
	}

	// They submit the form they filled in.
	submit(staleAction)

	if got := versionCount(secondID); got != 0 {
		t.Errorf("the replacement service received %d versions from a form opened against its deleted predecessor, want 0", got)
	}
}

// TestActivateServiceVersionRequiresOrgMembership asserts that the response
// carries no information about whether the named service exists: an existing
// service and a made-up one must produce the same refusal. The service name
// itself does appear in the breadcrumb, because that is built from the request
// path. The caller supplied that string, so echoing it back reveals nothing.
func TestActivateServiceVersionRequiresOrgMembership(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	// username7 is an org2 member, present in the fixtures specifically to
	// prove org1 actions are refused for someone outside org1.
	client, _ := consoleLogin(t, ts.URL, "username7", validUserPassword)

	get := func(path string) string {
		t.Helper()
		resp, err := client.Get(ts.URL + path) // #nosec G704
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	existing := get("/console/org/org1/services/org1-service1/3/activate")
	missing := get("/console/org/org1/services/no-such-service-here/3/activate")

	for name, text := range map[string]string{"existing service": existing, "made-up service": missing} {
		if strings.Contains(text, "about to activate") {
			t.Errorf("%s: a non-member was shown the activate confirmation page", name)
		}
		if !strings.Contains(text, consoleNotAllowedActivateSV) {
			t.Errorf("%s: expected the not-allowed message, got:\n%s", name, text)
		}
	}

	// No oracle: the refusal must not distinguish the two.
	if strings.Contains(existing, "version 3") != strings.Contains(missing, "version 3") {
		t.Error("the refusal differs between an existing and a non-existent service")
	}
}
