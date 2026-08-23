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
		description string
		groups      []cdntypes.InputConditionalOriginGroup
		errContains string
	}{
		{
			description: "no conditional groups is valid",
			groups:      nil,
		},
		{
			description: "distinct names and conditions are valid",
			groups: []cdntypes.InputConditionalOriginGroup{
				group("api", `req.url ~ "^/api/"`),
				group("static", `req.url ~ "^/static/"`),
			},
		},
		{
			description: "duplicate name rejected",
			groups: []cdntypes.InputConditionalOriginGroup{
				group("api", `req.url ~ "^/api/"`),
				group("api", `req.url ~ "^/static/"`),
			},
			errContains: "duplicate origin group name: api",
		},
		{
			description: "name colliding with default group rejected",
			groups: []cdntypes.InputConditionalOriginGroup{
				group("default", `req.url ~ "^/api/"`),
			},
			errContains: "duplicate origin group name: default",
		},
		{
			description: "identical condition rejected",
			groups: []cdntypes.InputConditionalOriginGroup{
				group("api", `req.url ~ "^/api/"`),
				group("api2", `req.url ~ "^/api/"`),
			},
			errContains: "origin groups api and api2 have identical conditions",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			err := validateOriginGroupInput(test.groups)
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
