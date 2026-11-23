package components

import (
	"strings"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

// TestEditUserContentResetPasswordPushesEditURL checks that the reset password
// form keeps the edit page in the address bar, since its own URL only answers
// POST and a reload after a refused reset would otherwise fail.
func TestEditUserContentResetPasswordPushesEditURL(t *testing.T) {
	const userID = "00000001-0000-0000-0000-000000000001"

	html := render(t, EditUserContent(UserFormData{}, nil, nil, cdntypes.LocalAuthProvider, userID, PasswordResetFormData{}))
	for _, want := range []string{
		`action="/console/superuser/users/` + userID + `/reset-password"`,
		`hx-push-url="/console/superuser/users/` + userID + `/edit"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("reset password form missing %q\n%s", want, html)
		}
	}
}

// TestEditUserContentOrgCheckboxes checks that the org choice is a group of
// checkboxes with the user's orgs checked, rather than a single select.
func TestEditUserContentOrgCheckboxes(t *testing.T) {
	orgs := []cdntypes.Org{{Name: "org1"}, {Name: "org2"}, {Name: "org3"}}
	formData := UserFormData{Orgs: []string{"org1", "org3"}}

	html := render(t, EditUserContent(formData, nil, orgs, cdntypes.LocalAuthProvider, "00000001-0000-0000-0000-000000000001", PasswordResetFormData{}))

	if strings.Contains(html, `<select id="org"`) || strings.Contains(html, `name="org"`) {
		t.Errorf("single org select still rendered\n%s", html)
	}
	if !strings.Contains(html, "<fieldset") || !strings.Contains(html, "<legend>Organizations</legend>") {
		t.Errorf("missing Organizations fieldset\n%s", html)
	}
	if n := strings.Count(html, `<input type="checkbox" name="orgs"`); n != 3 {
		t.Errorf("got %d org checkboxes, want 3\n%s", n, html)
	}
	for _, tc := range []struct {
		org     string
		checked bool
	}{{"org1", true}, {"org2", false}, {"org3", true}} {
		prefix := `<input type="checkbox" name="orgs" value="` + tc.org + `"`
		i := strings.Index(html, prefix)
		if i < 0 {
			t.Errorf("checkbox for %s missing\n%s", tc.org, html)
			continue
		}
		tag := html[i : i+strings.Index(html[i:], ">")]
		if got := strings.Contains(tag, "checked"); got != tc.checked {
			t.Errorf("%s checked = %v, want %v (%s)", tc.org, got, tc.checked, tag)
		}
	}
}
