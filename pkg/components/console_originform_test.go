package components

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/a-h/templ"
	"github.com/jackc/pgx/v5/pgtype"
)

// render is a small helper to render a templ.Component into a string for
// substring assertions in the tests below.
func render(t *testing.T, c templ.Component) string {
	t.Helper()
	var buf bytes.Buffer
	if err := c.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render failed: %v", err)
	}
	return buf.String()
}

// TestCreateServiceVersionContentCloneRender renders
// CreateServiceVersionContent with clone data containing a conditional
// group and a default group and checks the resulting HTML uses the exact
// dotted/indexed name attributes the server-side form decoder depends on,
// and the condition-editor class the CodeMirror bundle attaches to.
func TestCreateServiceVersionContentCloneRender(t *testing.T) {
	apiGroupID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	defaultGroupID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	condition := `req.url ~ "^/api/"`

	cloneData := cdntypes.ServiceVersionCloneData{
		VCLTemplate: "vcl-content",
		Domains:     []cdntypes.DomainString{"example.com"},
		OriginGroups: []cdntypes.OriginGroup{
			{ID: apiGroupID, DefaultGroup: false, Name: "api", Condition: &condition, Position: 0},
			{ID: defaultGroupID, DefaultGroup: true, Name: "default", Condition: nil, Position: 1},
		},
		Origins: []cdntypes.Origin{
			{OriginGroupID: apiGroupID, Host: "10.0.0.1", Port: 443, TLS: true, VerifyTLS: true},
			{OriginGroupID: defaultGroupID, Host: "10.0.2.1", Port: 443, TLS: true},
		},
	}

	domains := []cdntypes.Domain{{FQDN: "example.com", Verified: true}}

	html := render(t, CreateServiceVersionContent("myservice", "myorg", domains, nil, "vcl-content", cloneData, nil, ""))

	wantSubstrings := []string{
		// The conditional group itself.
		`name="conditional-origin-groups.0.name"`,
		`value="api"`,
		`name="conditional-origin-groups.0.condition"`,
		`class="condition-editor"`,
		// The conditional group's origin, prefilled from clone data.
		`name="conditional-origin-groups.0.origins.0.host"`,
		`value="10.0.0.1"`,
		`name="conditional-origin-groups.0.origins.0.port"`,
		`value="443"`,
		// The pinned default group's origin, prefilled from clone data.
		`name="default-origin-group.origins.0.host"`,
		`value="10.0.2.1"`,
		// data-group-index used by the renumbering hyperscript.
		`data-group-index="0"`,
		// Keeps htmx from restoring a stale CodeMirror-mutated DOM
		// snapshot on back/forward navigation.
		`hx-history="false"`,
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing expected substring %q\n--- HTML ---\n%s", want, html)
		}
	}

	// The condition text should appear (HTML-escaped) inside the
	// condition-editor textarea.
	if !strings.Contains(html, "req.url ~") {
		t.Errorf("rendered HTML missing condition text")
	}

	// The default group must not carry a name/condition input, and must
	// not be inside #origin-group-fieldsets (so it can never be
	// renumbered as a conditional group).
	defaultFieldsetIdx := strings.Index(html, `id="default-origin-group-fieldset"`)
	groupFieldsetsIdx := strings.Index(html, `id="origin-group-fieldsets"`)
	if defaultFieldsetIdx == -1 || groupFieldsetsIdx == -1 {
		t.Fatalf("expected both #origin-group-fieldsets and #default-origin-group-fieldset in output")
	}
	if defaultFieldsetIdx < groupFieldsetsIdx {
		t.Errorf("expected default group fieldset to be rendered after #origin-group-fieldsets")
	}
	if strings.Contains(html, `name="default-origin-group.name"`) {
		t.Errorf("default group must not have a name input")
	}
}

// TestCreateServiceVersionContentSubmittedRender checks that resubmitted
// (post-validation-failure) form data takes precedence over clone data and
// that a legacy condition-less clone group renders an empty condition
// editor.
func TestCreateServiceVersionContentSubmittedRender(t *testing.T) {
	submitted := &cdntypes.CreateServiceVersionForm{
		VCLTemplate: "vcl-content",
		ConditionalGroups: []cdntypes.CreateServiceVersionConditionalGroup{
			{
				Name:      "static",
				Condition: `req.url ~ "^/static/"`,
				Origins: []cdntypes.CreateServiceVersionOrigin{
					{OriginHost: "10.9.9.9", OriginPort: 80},
				},
			},
		},
		DefaultGroup: cdntypes.CreateServiceVersionDefaultGroup{
			Origins: []cdntypes.CreateServiceVersionOrigin{
				{OriginHost: "10.9.9.1", OriginPort: 443, OriginTLS: true},
			},
		},
	}

	// cloneData should be ignored entirely since submittedData != nil.
	cloneID := pgtype.UUID{Bytes: [16]byte{9}, Valid: true}
	cloneData := cdntypes.ServiceVersionCloneData{
		OriginGroups: []cdntypes.OriginGroup{
			{ID: cloneID, DefaultGroup: false, Name: "should-not-appear", Condition: nil, Position: 0},
		},
		Origins: []cdntypes.Origin{
			{OriginGroupID: cloneID, Host: "192.0.2.1", Port: 1, TLS: false},
		},
	}

	domains := []cdntypes.Domain{{FQDN: "example.com", Verified: true}}

	html := render(t, CreateServiceVersionContent("myservice", "myorg", domains, submitted, "", cloneData, nil, ""))

	if strings.Contains(html, "should-not-appear") {
		t.Errorf("clone data leaked through despite submittedData being set")
	}
	if strings.Contains(html, "192.0.2.1") {
		t.Errorf("clone origin leaked through despite submittedData being set")
	}
	if !strings.Contains(html, `value="static"`) {
		t.Errorf("expected submitted group name to be prefilled")
	}
	if !strings.Contains(html, `value="10.9.9.9"`) {
		t.Errorf("expected submitted conditional group origin host to be prefilled")
	}
	if !strings.Contains(html, `value="10.9.9.1"`) {
		t.Errorf("expected submitted default group origin host to be prefilled")
	}
}

// TestServiceVersionContentGroupRender checks that the version detail page
// shows origin groups in position order with their conditions, marks the
// default group and nests each group's origins under it.
func TestServiceVersionContentGroupRender(t *testing.T) {
	apiGroupID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	legacyGroupID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	defaultGroupID := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}

	apiCondition := `req.url ~ "^/api/"`

	sv := cdntypes.ServiceVersionConfig{
		Version: 3,
		Active:  true,
		OriginGroups: []cdntypes.OriginGroup{
			{ID: apiGroupID, Name: "api", Condition: &apiCondition, Position: 0},
			{ID: legacyGroupID, Name: "manual", Position: 1},
			{ID: defaultGroupID, Name: "default", DefaultGroup: true, Position: 2},
		},
		Origins: []cdntypes.Origin{
			{OriginGroupID: apiGroupID, Host: "10.0.0.1", Port: 443, TLS: true, VerifyTLS: true},
			{OriginGroupID: legacyGroupID, Host: "10.0.1.1", Port: 8080},
			{OriginGroupID: defaultGroupID, Host: "10.0.2.1", Port: 443, TLS: true},
		},
	}

	html := render(t, ServiceVersionContent("myservice", sv))

	wantSubstrings := []string{
		"Origin groups",
		// Condition rendered (HTML-escaped) for the conditional group.
		"req.url ~ &#34;^/api/&#34;",
		// Default group marker.
		"default group — used when no condition matches",
		// Each group's origin appears.
		"10.0.0.1",
		"10.0.1.1",
		"10.0.2.1",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing expected substring %q\n--- HTML ---\n%s", want, html)
		}
	}

	// Groups must render in position order: api, manual, default.
	apiIdx := strings.Index(html, ">api")
	manualIdx := strings.Index(html, ">manual")
	defaultIdx := strings.Index(html, ">default")
	if apiIdx == -1 || manualIdx == -1 || defaultIdx == -1 || apiIdx >= manualIdx || manualIdx >= defaultIdx {
		t.Errorf("groups not rendered in position order (api=%d manual=%d default=%d)\n--- HTML ---\n%s", apiIdx, manualIdx, defaultIdx, html)
	}

	// Each origin must appear after its own group heading and before the
	// next group heading, i.e. nested under the right group.
	if hostIdx := strings.Index(html, "10.0.0.1"); hostIdx <= apiIdx || hostIdx >= manualIdx {
		t.Errorf("api group origin not nested under api group (host=%d api=%d manual=%d)", hostIdx, apiIdx, manualIdx)
	}
	if hostIdx := strings.Index(html, "10.0.1.1"); hostIdx <= manualIdx || hostIdx >= defaultIdx {
		t.Errorf("manual group origin not nested under manual group (host=%d manual=%d default=%d)", hostIdx, manualIdx, defaultIdx)
	}
	if hostIdx := strings.Index(html, "10.0.2.1"); hostIdx < defaultIdx {
		t.Errorf("default group origin not nested under default group (host=%d default=%d)", hostIdx, defaultIdx)
	}
}
