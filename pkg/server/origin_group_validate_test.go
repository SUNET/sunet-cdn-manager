package server

import (
	"strings"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

func TestValidateOriginGroupInput(t *testing.T) {
	group := func(name string, condition string) cdntypes.InputConditionalOriginGroup {
		return cdntypes.InputConditionalOriginGroup{Name: name, Condition: condition}
	}

	tests := []struct {
		description  string
		defaultGroup cdntypes.InputDefaultOriginGroup
		groups       []cdntypes.InputConditionalOriginGroup
		errContains  string
	}{
		{
			description:  "no conditional groups is valid",
			defaultGroup: cdntypes.InputDefaultOriginGroup{},
			groups:       nil,
		},
		{
			description: "valid IPv4 origin host",
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{
						Host: "198.51.100.1",
					},
				},
			},
			groups: nil,
		},
		{
			description: "valid IPv6 origin host",
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{
						Host: "2001:db8::1",
					},
				},
			},
			groups: nil,
		},
		{
			description: "valid origin host",
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{
						Host: "origin1.example.com",
					},
				},
			},
			groups: nil,
		},
		{
			description: "valid IDN origin host",
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{
						Host: "räksmörgås1.example.com",
					},
				},
			},
			groups: nil,
		},
		{
			description: "default group origin host config injection",
			defaultGroup: cdntypes.InputDefaultOriginGroup{
				Origins: []cdntypes.InputOrigin{
					{
						Host: "127.0.0.1:8080 resolvers mydns\nprogram scm_poc\n        command /usr/bin/touch /evidence/HAPROXY-CODE-EXECUTED\n        no option start-on-reload\n#",
					},
				},
			},
			groups:      nil,
			errContains: "origin host is neither an IPv4 address nor an IPv6 address nor a valid DNS hostname",
		},
		{
			description:  "conditional group origin host config injection",
			defaultGroup: cdntypes.InputDefaultOriginGroup{},
			groups: []cdntypes.InputConditionalOriginGroup{
				{
					Origins: []cdntypes.InputOrigin{
						{
							Host: "127.0.0.1:8080 resolvers mydns\nprogram scm_poc\n        command /usr/bin/touch /evidence/HAPROXY-CODE-EXECUTED\n        no option start-on-reload\n#",
						},
					},
				},
			},
			errContains: "origin host is neither an IPv4 address nor an IPv6 address nor a valid DNS hostname",
		},
		{
			description:  "distinct names and conditions are valid",
			defaultGroup: cdntypes.InputDefaultOriginGroup{},
			groups: []cdntypes.InputConditionalOriginGroup{
				group("api", `req.url ~ "^/api/"`),
				group("static", `req.url ~ "^/static/"`),
			},
		},
		{
			description:  "duplicate name rejected",
			defaultGroup: cdntypes.InputDefaultOriginGroup{},
			groups: []cdntypes.InputConditionalOriginGroup{
				group("api", `req.url ~ "^/api/"`),
				group("api", `req.url ~ "^/static/"`),
			},
			errContains: "duplicate origin group name: api",
		},
		{
			description:  "name colliding with default group rejected",
			defaultGroup: cdntypes.InputDefaultOriginGroup{},
			groups: []cdntypes.InputConditionalOriginGroup{
				group("default", `req.url ~ "^/api/"`),
			},
			errContains: "duplicate origin group name: default",
		},
		{
			description:  "identical condition rejected",
			defaultGroup: cdntypes.InputDefaultOriginGroup{},
			groups: []cdntypes.InputConditionalOriginGroup{
				group("api", `req.url ~ "^/api/"`),
				group("api2", `req.url ~ "^/api/"`),
			},
			errContains: "origin groups api and api2 have identical conditions",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			err := validateOriginGroupInput(&test.defaultGroup, test.groups)
			if test.errContains == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", test.errContains)
			}
			if !strings.Contains(err.Error(), test.errContains) {
				t.Errorf("expected error containing %q, got: %v", test.errContains, err)
			}
		})
	}
}

func TestCanonicalizeOriginHost(t *testing.T) {
	tests := []struct {
		description string
		host        string
		wantResult  string
		errContains string
	}{
		{
			description: "valid public IPv4",
			host:        "198.51.100.1",
			wantResult:  "198.51.100.1",
		},
		{
			description: "valid public IPv6",
			host:        "2001:db8::1",
			wantResult:  "2001:db8::1",
		},
		{
			description: "IPv4-mapped IPv6 loopback is rejected",
			host:        "::ffff:127.0.0.1",
			errContains: "loopback",
		},
		{
			description: "IPv4-mapped IPv6 private address is rejected",
			host:        "::ffff:10.0.0.1",
			errContains: "private",
		},
		{
			description: "IPv4 broadcast",
			host:        "255.255.255.255",
			errContains: "must be a global unicast address",
		},
		{
			description: "interface-local multicast is rejected with correct message",
			host:        "ff01::1",
			errContains: "interface-local multicast",
		},
		{
			description: "IPv6 addresses must not contain a zone index",
			host:        "fe80::1ff:fe23:4567:890a%eth2",
			errContains: "must not include an IPv6 zone",
		},
		{
			description: "IDN hostname is converted to punycode",
			host:        "srv1.räksmörgås.example.com",
			wantResult:  "srv1.xn--rksmrgs-5wao1o.example.com",
		},
		{
			description: "IPv4-mapped IPv6 address is converted to IPv4",
			host:        "::ffff:198.51.100.1",
			wantResult:  "198.51.100.1",
		},
		{
			description: "Special address prefix match",
			host:        "100.64.0.1",
			errContains: "belongs to a special prefix",
		},
		{
			description: "IPv4 with trailing dot should not be accepted",
			host:        "198.51.100.1.",
			errContains: "origin host is neither an IPv4 address nor an IPv6 address nor a valid DNS hostname",
		},
		{
			description: "IPv6 with trailing dot should not be accepted",
			host:        "2001:db8::1.",
			errContains: "origin host is neither an IPv4 address nor an IPv6 address nor a valid DNS hostname",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			result, err := canonicalizeOriginHost(test.host)
			if test.errContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", test.errContains)
				}
				if !strings.Contains(err.Error(), test.errContains) {
					t.Errorf("expected error containing %q, got: %v", test.errContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			if result != test.wantResult {
				t.Errorf("expected %q, got %q", test.wantResult, result)
			}
		})
	}
}
