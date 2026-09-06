package components

import (
	"strings"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

// TestServiceContentDescriptionRender checks that the service version list
// table shows each version's description.
func TestServiceContentDescriptionRender(t *testing.T) {
	serviceVersions := []cdntypes.ServiceVersion{
		{OrgName: "myorg", ServiceName: "myservice", Version: 1, Active: true, Description: "first version"},
	}

	html := render(t, ServiceContent("myorg", "myservice", serviceVersions))

	if !strings.Contains(html, "first version") {
		t.Errorf("rendered HTML missing version description\n--- HTML ---\n%s", html)
	}
}
