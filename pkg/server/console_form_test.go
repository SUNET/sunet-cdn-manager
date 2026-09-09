package server

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"

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
