package components

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

// TestServiceContentDescriptionRender checks that the service version list
// table shows each version's description.
func TestServiceContentDescriptionRender(t *testing.T) {
	var serviceID pgtype.UUID
	if err := serviceID.Scan("6ba7b810-9dad-11d1-80b4-00c04fd430c8"); err != nil {
		t.Fatal(err)
	}

	serviceVersions := []cdntypes.ServiceVersionListItem{
		{OrgName: "myorg", ServiceName: "myservice", Version: 1, Active: true, Description: "first version"},
	}

	html := render(t, ServiceContent("myorg", serviceID, serviceVersions, ServiceVersionQuotaView{Used: 1, Quota: 1000, Input: "1000"}))

	if !strings.Contains(html, "first version") {
		t.Errorf("rendered HTML missing version description\n--- HTML ---\n%s", html)
	}
}

// TestServicesContentActionLinksUseTheServiceID checks that the Disable,
// Enable and Delete links address the service by UUID rather than by name.
//
// A name is not a stable identifier: the services page can sit open while the
// service is deleted and a new one created reusing the name, and a name-keyed
// link would then act on the replacement. Disable and Delete lead to a
// confirmation page rather than acting directly, but they need the UUID just
// as much as the Enable POST does -- reaching the wrong confirmation page is
// how the user is deceived into confirming the wrong thing.
func TestServicesContentActionLinksUseTheServiceID(t *testing.T) {
	var serviceID pgtype.UUID
	if err := serviceID.Scan("6ba7b810-9dad-11d1-80b4-00c04fd430c8"); err != nil {
		t.Fatal(err)
	}

	timeDisabled := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	services := []ServiceEntry{
		{ID: serviceID, Name: "trap-name", OrgName: "myorg"},
		{ID: serviceID, Name: "trap-name", OrgName: "myorg", TimeDisabled: &timeDisabled},
	}

	// superuser so the Delete link renders too.
	html := render(t, ServicesContent("myorg", services, true, 100, nil, ""))

	for _, want := range []string{
		"/console/org/myorg/services/6ba7b810-9dad-11d1-80b4-00c04fd430c8/disable",
		"/console/org/myorg/services/6ba7b810-9dad-11d1-80b4-00c04fd430c8/enable",
		"/console/org/myorg/services/6ba7b810-9dad-11d1-80b4-00c04fd430c8/delete",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing %q\n--- HTML ---\n%s", want, html)
		}
	}

	for _, unwanted := range []string{
		"/console/org/myorg/services/trap-name/disable",
		"/console/org/myorg/services/trap-name/enable",
		"/console/org/myorg/services/trap-name/delete",
	} {
		if strings.Contains(html, unwanted) {
			t.Errorf("action link still addresses the service by name: %q\n--- HTML ---\n%s", unwanted, html)
		}
	}

	// The service detail link is a browsing URL and deliberately stays
	// name-keyed, so the name must still appear somewhere on the page.
	if !strings.Contains(html, "/console/org/myorg/services/trap-name\"") {
		t.Errorf("service detail link should still be name-keyed\n--- HTML ---\n%s", html)
	}
}

// TestBreadcrumbsNameServiceAddressedByID checks that the confirmation pages
// reached from those links show the service's name in the breadcrumb trail
// rather than the UUID now carried in their path.
func TestBreadcrumbsNameServiceAddressedByID(t *testing.T) {
	const serviceUUID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

	for _, action := range []string{"disable", "delete"} {
		u, err := url.Parse("/console/org/myorg/services/" + serviceUUID + "/" + action)
		if err != nil {
			t.Fatal(err)
		}

		crumbs := buildBreadcrumbs(u, "myorg", "my-service")

		last := crumbs[len(crumbs)-1]
		if last.Label != "my-service" {
			t.Errorf("%s page: breadcrumb label is %q, want the service name", action, last.Label)
		}
		if last.URL != "/console/org/myorg/services/"+serviceUUID {
			t.Errorf("%s page: breadcrumb URL is %q, want the UUID-keyed path", action, last.URL)
		}
	}
}

// TestBreadcrumbsNameServiceOnCreateVersionRoute covers the create-version
// route, which takes a different branch of buildBreadcrumbs than the pages
// above and so needs its own itemLabel handling.
func TestBreadcrumbsNameServiceOnCreateVersionRoute(t *testing.T) {
	const serviceUUID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

	u, err := url.Parse("/console/org/myorg/create/service/version/" + serviceUUID)
	if err != nil {
		t.Fatal(err)
	}

	crumbs := buildBreadcrumbs(u, "myorg", "my-service")

	last := crumbs[len(crumbs)-1]
	if last.Label != "my-service" {
		t.Errorf("breadcrumb label is %q, want the service name", last.Label)
	}
	if last.URL != "/console/org/myorg/services/"+serviceUUID {
		t.Errorf("breadcrumb URL is %q, want the UUID-keyed service path", last.URL)
	}
	for _, c := range crumbs {
		if c.Label == serviceUUID {
			t.Errorf("a crumb displays the raw UUID as its label: %+v", c)
		}
	}
}

// TestBreadcrumbsFallBackToPathSegment checks that pages passing no itemLabel
// -- the browsing pages, which stay name-keyed -- are unaffected.
func TestBreadcrumbsFallBackToPathSegment(t *testing.T) {
	u, err := url.Parse("/console/org/myorg/services/my-service/3")
	if err != nil {
		t.Fatal(err)
	}

	crumbs := buildBreadcrumbs(u, "myorg", "")

	last := crumbs[len(crumbs)-1]
	if last.Label != "my-service" {
		t.Errorf("without an itemLabel the path segment should be shown, got %q", last.Label)
	}
}

// TestServiceContentCreateVersionLinksUseTheServiceID checks that the links
// which create a version address the service by UUID.
//
// This flow is one of the more important ones to refer to a UUID instead of a
// name. The form behind these links takes minutes to fill in, there is no
// confirmation step that could reveal a changed target, and the result is a
// version silently attached to a service the user never saw (given that the
// original one was deleted and another one put in its place with the same
// name).
func TestServiceContentCreateVersionLinksUseTheServiceID(t *testing.T) {
	const uuid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

	var serviceID pgtype.UUID
	if err := serviceID.Scan(uuid); err != nil {
		t.Fatal(err)
	}

	// Rendered twice: with a version present (Create / Clone links) and with
	// none (the "create your first version" empty state, which has no version
	// row to take an ID from).
	withVersions := render(t, ServiceContent("myorg", serviceID, []cdntypes.ServiceVersionListItem{
		{OrgName: "myorg", ServiceName: "trap-name", Version: 1, Description: "v1"},
	}, ServiceVersionQuotaView{Used: 1, Quota: 1000, Input: "1000"}))
	empty := render(t, ServiceContent("myorg", serviceID, nil, ServiceVersionQuotaView{Quota: 1000, Input: "1000"}))

	for name, html := range map[string]string{"with versions": withVersions, "empty state": empty} {
		if !strings.Contains(html, "/console/org/myorg/create/service/version/"+uuid) {
			t.Errorf("%s: create-version link does not carry the service UUID\n--- HTML ---\n%s", name, html)
		}
		if strings.Contains(html, "/console/org/myorg/create/service/version/trap-name") {
			t.Errorf("%s: create-version link still addresses the service by name\n--- HTML ---\n%s", name, html)
		}
	}

	// The Clone link carries the source version alongside the service UUID.
	if !strings.Contains(withVersions, "/console/org/myorg/create/service/version/"+uuid+"?clone-version=1") {
		t.Errorf("clone link does not carry the service UUID\n--- HTML ---\n%s", withVersions)
	}

	// Activate is mutating too: it flips which version cache nodes serve.
	if !strings.Contains(withVersions, "/console/org/myorg/services/"+uuid+"/1/activate") {
		t.Errorf("activate link does not carry the service UUID\n--- HTML ---\n%s", withVersions)
	}
	if strings.Contains(withVersions, "/console/org/myorg/services/trap-name/1/activate") {
		t.Errorf("activate link still addresses the service by name\n--- HTML ---\n%s", withVersions)
	}

	// The version detail link stays name-keyed: it is a browsing URL.
	if !strings.Contains(withVersions, "/console/org/myorg/services/trap-name/1\"") {
		t.Errorf("version detail link should still be name-keyed\n--- HTML ---\n%s", withVersions)
	}
}

const quotaTestServiceID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"

func quotaTestRender(t *testing.T, versions []cdntypes.ServiceVersionListItem, view ServiceVersionQuotaView) string {
	t.Helper()

	var serviceID pgtype.UUID
	if err := serviceID.Scan(quotaTestServiceID); err != nil {
		t.Fatal(err)
	}
	return render(t, ServiceContent("myorg", serviceID, versions, view))
}

// TestServiceContentVersionQuotaLine checks that the usage line is shown both
// with and without versions.
func TestServiceContentVersionQuotaLine(t *testing.T) {
	two := []cdntypes.ServiceVersionListItem{
		{OrgName: "myorg", ServiceName: "svc", Version: 1},
		{OrgName: "myorg", ServiceName: "svc", Version: 2},
	}
	html := quotaTestRender(t, two, ServiceVersionQuotaView{Used: 2, Quota: 1000, Input: "1000"})
	if !strings.Contains(html, "2 of 1000 versions used") {
		t.Errorf("list state missing usage line\n%s", html)
	}

	html = quotaTestRender(t, nil, ServiceVersionQuotaView{Used: 0, Quota: 1000, Input: "1000"})
	if !strings.Contains(html, "0 of 1000 versions used") {
		t.Errorf("empty state missing usage line\n%s", html)
	}
}

// TestServiceContentVersionQuotaFormOnlyForSuperuser checks that only
// operators get the form for changing the quota.
func TestServiceContentVersionQuotaFormOnlyForSuperuser(t *testing.T) {
	html := quotaTestRender(t, nil, ServiceVersionQuotaView{Quota: 1000, Input: "1000"})
	if strings.Contains(html, `name="version-quota"`) {
		t.Errorf("non-superuser sees the quota form\n%s", html)
	}

	html = quotaTestRender(t, nil, ServiceVersionQuotaView{Quota: 1000, Superuser: true, Input: "1000"})
	for _, want := range []string{
		`name="version-quota"`,
		`min="0"`,
		`value="1000"`,
		`action="/console/org/myorg/services/` + quotaTestServiceID + `/version-quota"`,
		`hx-push-url="/console/org/myorg/services/` + quotaTestServiceID + `"`,
		"Version quota",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("superuser form missing %q\n%s", want, html)
		}
	}
}

// TestServiceContentVersionQuotaError checks that a field error and the
// submitted value are re-rendered, and that the error is tied to the input and
// announced so screen reader users learn why the change was refused. Without
// an error the input carries neither attribute and no empty alert is rendered.
func TestServiceContentVersionQuotaError(t *testing.T) {
	const msg = "Cannot be lower than the current number of service versions"

	parse := func(view ServiceVersionQuotaView) (*goquery.Selection, *goquery.Selection) {
		t.Helper()
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(quotaTestRender(t, nil, view)))
		if err != nil {
			t.Fatal(err)
		}
		return doc.Find("input#version-quota"), doc.Find("#version-quota-error")
	}

	input, errSpan := parse(ServiceVersionQuotaView{Used: 2, Quota: 1000, Superuser: true, Input: "1", Error: msg})
	if input.Length() != 1 {
		t.Fatalf("found %d quota inputs, want 1", input.Length())
	}
	if v, _ := input.Attr("value"); v != "1" {
		t.Errorf("input value is %q, want the submitted %q", v, "1")
	}
	if v, _ := input.Attr("aria-invalid"); v != "true" {
		t.Errorf("input aria-invalid is %q, want %q", v, "true")
	}
	if v, _ := input.Attr("aria-describedby"); v != "version-quota-error" {
		t.Errorf("input aria-describedby is %q, want %q", v, "version-quota-error")
	}
	if got := errSpan.Text(); got != msg {
		t.Errorf("error text is %q, want %q", got, msg)
	}
	if v, _ := errSpan.Attr("role"); v != "alert" {
		t.Errorf("error role is %q, want %q", v, "alert")
	}

	input, errSpan = parse(ServiceVersionQuotaView{Used: 2, Quota: 1000, Superuser: true, Input: "1000"})
	for _, attr := range []string{"aria-invalid", "aria-describedby"} {
		if v, ok := input.Attr(attr); ok {
			t.Errorf("input without error has %s=%q", attr, v)
		}
	}
	if errSpan.Length() != 0 {
		t.Errorf("error element rendered without an error")
	}
}
