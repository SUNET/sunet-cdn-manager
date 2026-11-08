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
