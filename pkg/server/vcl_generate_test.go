package server

import (
	"strings"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5/pgtype"
)

func testUUID(n byte) pgtype.UUID {
	var id pgtype.UUID
	id.Bytes[15] = n
	id.Valid = true
	return id
}

func testGroup(n byte, name string, isDefault bool, condition *string, position int64) cdntypes.OriginGroup {
	return cdntypes.OriginGroup{
		ID:           testUUID(n),
		DefaultGroup: isDefault,
		Name:         name,
		Condition:    condition,
		Position:     position,
	}
}

func testOrigin(groupID pgtype.UUID, host string, port int, tls bool) cdntypes.Origin {
	return cdntypes.Origin{OriginGroupID: groupID, Host: host, Port: port, TLS: tls, VerifyTLS: tls}
}

func TestGenerateCompleteVclSelection(t *testing.T) {
	confTemplates, err := newConfigTemplates()
	if err != nil {
		t.Fatal(err)
	}

	defaultOnlyGroups := []cdntypes.OriginGroup{testGroup(1, "default", true, nil, 0)}
	defaultOnlyOrigins := []cdntypes.Origin{
		testOrigin(testUUID(1), "198.51.100.10", 80, false),
		testOrigin(testUUID(1), "198.51.100.11", 443, true),
	}

	chainGroups := []cdntypes.OriginGroup{
		testGroup(2, "api", false, new(`req.url ~ "^/api/"`), 0),
		testGroup(3, "static", false, new(`req.http.host == "static.example.com"`), 1),
		testGroup(1, "default", true, nil, 2),
	}
	chainOrigins := []cdntypes.Origin{
		testOrigin(testUUID(2), "10.0.0.1", 443, true),
		testOrigin(testUUID(2), "10.0.0.2", 80, false),
		testOrigin(testUUID(3), "10.0.1.1", 443, true), // static: HTTPS only
		testOrigin(testUUID(1), "10.0.2.1", 443, true),
		testOrigin(testUUID(1), "10.0.2.2", 80, false),
	}

	legacyGroups := []cdntypes.OriginGroup{
		testGroup(1, "default", true, nil, 0),
		testGroup(4, "manual", false, nil, 1), // legacy: no condition
	}
	legacyOrigins := []cdntypes.Origin{
		testOrigin(testUUID(1), "198.51.100.10", 443, true),
		testOrigin(testUUID(4), "198.51.100.20", 443, true),
	}

	multilineGroups := []cdntypes.OriginGroup{
		testGroup(2, "api", false, new("req.url ~ \"^/api/\" ||\n    req.url ~ \"^/graphql\""), 0),
		testGroup(1, "default", true, nil, 1),
	}
	multilineOrigins := []cdntypes.Origin{
		testOrigin(testUUID(2), "10.0.0.1", 443, true),
		testOrigin(testUUID(1), "10.0.2.1", 443, true),
	}

	tests := []struct {
		description string
		groups      []cdntypes.OriginGroup
		origins     []cdntypes.Origin
		contains    []string
		notContains []string
	}{
		{
			description: "only default group: plain assignment, no chain",
			groups:      defaultOnlyGroups,
			origins:     defaultOnlyOrigins,
			contains: []string{
				"set req.backend_hint = default_https;",
				"set req.backend_hint = default_http;",
			},
			// NOTE: bare "elseif"/"} else {" are not safe markers here — the
			// vcl_backend_response macro already contains an unrelated
			// "} elseif (...)" for Vary-header handling, and vcl_recv's
			// outer "if (proxy.is_ssl()) {...} else {...}" scheme wrapper
			// always contains "} else {" whether or not a chain exists.
			// "# origin group"/"# default origin group" are only emitted
			// by buildBackendSelection when a chain is actually generated,
			// so they are the precise signal for "no chain".
			notContains: []string{"# origin group", "# default origin group"},
		},
		{
			description: "conditional groups: full chain in position order with owner comments",
			groups:      chainGroups,
			origins:     chainOrigins,
			contains: []string{
				`if (req.url ~ "^/api/") { # origin group "api" (1/2)`,
				`} elseif (req.http.host == "static.example.com") { # origin group "static" (2/2)`,
				`} else { # default origin group "default"`,
				"set req.backend_hint = api_https;",
				"set req.backend_hint = default_https;",
				// static group has no HTTP origin: synth in the HTTP branch
				`return(synth(400, "HTTP request but origin group static has no HTTP origin"));`,
			},
		},
		{
			description: "legacy condition-less non-default group: backends only, no chain",
			groups:      legacyGroups,
			origins:     legacyOrigins,
			contains: []string{
				"backend manual_https {",
				"set req.backend_hint = default_https;",
			},
			// See note above: bare "elseif" collides with the unrelated
			// vcl_backend_response Vary-header logic.
			notContains: []string{"# origin group", "# default origin group"},
		},
		{
			description: "multiline condition retained as multiple lines",
			groups:      multilineGroups,
			origins:     multilineOrigins,
			contains: []string{
				"if (req.url ~ \"^/api/\" ||\n    req.url ~ \"^/graphql\") { # origin group \"api\" (1/1)",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			vcl, err := generateCompleteVcl(confTemplates, test.groups, test.origins, cdntypes.DefaultVCLTemplate)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.contains {
				if !strings.Contains(vcl, want) {
					t.Errorf("generated VCL missing %q\n---\n%s", want, vcl)
				}
			}
			for _, unwanted := range test.notContains {
				if strings.Contains(vcl, unwanted) {
					t.Errorf("generated VCL unexpectedly contains %q\n---\n%s", unwanted, vcl)
				}
			}
		})
	}
}

// Chain order must follow position, both scheme branches in the same order.
func TestGenerateCompleteVclChainOrder(t *testing.T) {
	confTemplates, err := newConfigTemplates()
	if err != nil {
		t.Fatal(err)
	}
	groups := []cdntypes.OriginGroup{
		// deliberately passed out of position order
		testGroup(3, "second", false, new(`req.url ~ "^/b"`), 1),
		testGroup(2, "first", false, new(`req.url ~ "^/a"`), 0),
		testGroup(1, "default", true, nil, 2),
	}
	origins := []cdntypes.Origin{
		testOrigin(testUUID(2), "10.0.0.1", 443, true),
		testOrigin(testUUID(3), "10.0.1.1", 443, true),
		testOrigin(testUUID(1), "10.0.2.1", 443, true),
	}
	vcl, err := generateCompleteVcl(confTemplates, groups, origins, cdntypes.DefaultVCLTemplate)
	if err != nil {
		t.Fatal(err)
	}
	firstIdx := strings.Index(vcl, `"first" (1/2)`)
	secondIdx := strings.Index(vcl, `"second" (2/2)`)
	if firstIdx == -1 || secondIdx == -1 || firstIdx > secondIdx {
		t.Errorf("chain not ordered by position:\n%s", vcl)
	}
}

func TestGenerateCompleteVclLegacyStable(t *testing.T) {
	confTemplates, err := newConfigTemplates()
	if err != nil {
		t.Fatal(err)
	}
	groups := []cdntypes.OriginGroup{testGroup(1, "default", true, nil, 0)}
	origins := []cdntypes.Origin{
		testOrigin(testUUID(1), "198.51.100.10", 80, false),
		testOrigin(testUUID(1), "198.51.100.11", 443, true),
	}
	vcl, err := generateCompleteVcl(confTemplates, groups, origins, cdntypes.DefaultVCLTemplate)
	if err != nil {
		t.Fatal(err)
	}
	expectedRecvBlock := `# begin SUNET-CDN-MANAGER vcl_recv
  if (proxy.is_ssl()) {
    set req.http.X-Forwarded-Proto = "https";
    set req.backend_hint = default_https;
  } else {
    set req.http.X-Forwarded-Proto = "http";
    set req.backend_hint = default_http;
  }

# end SUNET-CDN-MANAGER vcl_recv`
	if !strings.Contains(vcl, expectedRecvBlock) {
		t.Errorf("legacy vcl_recv block changed:\n%s", vcl)
	}
}
