package components

import (
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/a-h/templ"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

// TestFormFieldErrorsAreAccessible renders each console form with every field
// error set and checks that each message is tied to its control and announced:
// the control is marked invalid and described by the message, which is an
// alert. Without errors no control is marked and no message is rendered.
func TestFormFieldErrorsAreAccessible(t *testing.T) {
	nodeErrs := NodeFormErrors{Name: "e-name", Description: "e-description", Addresses: "e-addresses"}
	nodeWant := map[string]string{"name": "e-name", "description": "e-description", "addresses": "e-addresses"}
	groupErrs := NodeGroupFormErrors{Name: "e-name", Description: "e-description"}
	groupWant := map[string]string{"name": "e-name", "description": "e-description"}
	orgErrs := OrgFormErrors{Name: "e-name", ServiceQuota: "e-service", DomainQuota: "e-domain", ClientTokenQuota: "e-token"}
	orgWant := map[string]string{"name": "e-name", "service-quota": "e-service", "domain-quota": "e-domain", "client-token-quota": "e-token"}

	tests := []struct {
		name       string
		withErrs   templ.Component
		withoutErr templ.Component
		// want maps each control id to the message it must be described by.
		want map[string]string
	}{
		{
			name:       "create domain",
			withErrs:   CreateDomainContent("myorg", DomainData{Errors: DomainErrors{DomainFormFields: DomainFormFields{FQDN: "e-fqdn"}}}),
			withoutErr: CreateDomainContent("myorg", DomainData{}),
			want:       map[string]string{"fqdn": "e-fqdn"},
		},
		{
			name:       "create API token",
			withErrs:   CreateAPITokenContent("myorg", APITokenData{Errors: APITokenErrors{APITokenFormFields: APITokenFormFields{Name: "e-name", Description: "e-description"}}}),
			withoutErr: CreateAPITokenContent("myorg", APITokenData{}),
			want:       map[string]string{"name": "e-name", "description": "e-description"},
		},
		{
			name:       "create cache node",
			withErrs:   CreateCacheNodeContent(CacheNodeFormData{Errors: nodeErrs}),
			withoutErr: CreateCacheNodeContent(CacheNodeFormData{}),
			want:       nodeWant,
		},
		{
			name:       "edit cache node",
			withErrs:   EditCacheNodeContent("node", CacheNodeFormData{Errors: nodeErrs}),
			withoutErr: EditCacheNodeContent("node", CacheNodeFormData{}),
			want:       nodeWant,
		},
		{
			name:       "create L4LB node",
			withErrs:   CreateL4LBNodeContent(L4LBNodeFormData{Errors: nodeErrs}),
			withoutErr: CreateL4LBNodeContent(L4LBNodeFormData{}),
			want:       nodeWant,
		},
		{
			name:       "edit L4LB node",
			withErrs:   EditL4LBNodeContent("node", L4LBNodeFormData{Errors: nodeErrs}),
			withoutErr: EditL4LBNodeContent("node", L4LBNodeFormData{}),
			want:       nodeWant,
		},
		{
			name:       "create node group",
			withErrs:   CreateNodeGroupContent(NodeGroupFormData{Errors: groupErrs}),
			withoutErr: CreateNodeGroupContent(NodeGroupFormData{}),
			want:       groupWant,
		},
		{
			name:       "edit node group",
			withErrs:   EditNodeGroupContent("group", NodeGroupFormData{Errors: groupErrs}),
			withoutErr: EditNodeGroupContent("group", NodeGroupFormData{}),
			want:       groupWant,
		},
		{
			name:       "create IP network",
			withErrs:   CreateIPNetworkContent(IPNetworkFormData{Errors: IPNetworkFormErrors{Network: "e-network"}}),
			withoutErr: CreateIPNetworkContent(IPNetworkFormData{}),
			want:       map[string]string{"network": "e-network"},
		},
		{
			name:       "create org",
			withErrs:   CreateOrgContent(OrgFormData{Errors: orgErrs}),
			withoutErr: CreateOrgContent(OrgFormData{}),
			want:       orgWant,
		},
		{
			name:       "edit org",
			withErrs:   EditOrgContent("myorg", OrgFormData{Errors: orgErrs}),
			withoutErr: EditOrgContent("myorg", OrgFormData{}),
			want:       orgWant,
		},
		{
			name: "create user",
			withErrs: CreateUserContent(UserFormData{Errors: UserFormErrors{
				DisplayName: "e-display", Role: "e-role", Org: "e-org", Password: "e-password", ConfirmPassword: "e-confirm",
			}}, nil, nil),
			withoutErr: CreateUserContent(UserFormData{}, nil, nil),
			want:       map[string]string{"display_name": "e-display", "role": "e-role", "org": "e-org", "password": "e-password", "confirm-password": "e-confirm"},
		},
		{
			name: "edit user with password reset",
			withErrs: EditUserContent(UserFormData{Errors: UserFormErrors{DisplayName: "e-display", Role: "e-role", Org: "e-org"}}, nil, nil, cdntypes.LocalAuthProvider, "user-id",
				PasswordResetFormData{Errors: PasswordResetFormErrors{Password: "e-password", ConfirmPassword: "e-confirm"}}),
			withoutErr: EditUserContent(UserFormData{}, nil, nil, cdntypes.LocalAuthProvider, "user-id", PasswordResetFormData{}),
			want:       map[string]string{"display_name": "e-display", "role": "e-role", "org": "e-org", "password": "e-password", "confirm-password": "e-confirm"},
		},
		{
			name:       "edit externally managed user",
			withErrs:   EditUserContent(UserFormData{Errors: UserFormErrors{DisplayName: "e-display"}}, nil, nil, "keycloak", "user-id", PasswordResetFormData{}),
			withoutErr: EditUserContent(UserFormData{}, nil, nil, "keycloak", "user-id", PasswordResetFormData{}),
			want:       map[string]string{"display_name": "e-display"},
		},
	}

	parse := func(t *testing.T, c templ.Component) *goquery.Document {
		t.Helper()
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(render(t, c)))
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := parse(t, tt.withErrs)
			for id, msg := range tt.want {
				control := doc.Find("#" + id)
				if control.Length() != 1 {
					t.Errorf("found %d controls with id %q, want 1", control.Length(), id)
					continue
				}
				if v, _ := control.Attr("aria-invalid"); v != "true" {
					t.Errorf("%s aria-invalid is %q, want %q", id, v, "true")
				}
				describedBy, _ := control.Attr("aria-describedby")
				if describedBy != id+"-error" {
					t.Errorf("%s aria-describedby is %q, want %q", id, describedBy, id+"-error")
				}
				errElem := doc.Find("#" + id + "-error")
				if got := errElem.Text(); got != msg {
					t.Errorf("%s error text is %q, want %q", id, got, msg)
				}
				if v, _ := errElem.Attr("role"); v != "alert" {
					t.Errorf("%s error role is %q, want %q", id, v, "alert")
				}
			}
			// Nothing beyond the expected controls is marked, so a
			// message cannot end up tied to the wrong control.
			if n := doc.Find(`[aria-invalid="true"]`).Length(); n != len(tt.want) {
				t.Errorf("%d controls marked invalid, want %d", n, len(tt.want))
			}
			if n := doc.Find(`.error-text[id$="-error"]`).Length(); n != len(tt.want) {
				t.Errorf("%d field error messages rendered, want %d", n, len(tt.want))
			}

			doc = parse(t, tt.withoutErr)
			if n := doc.Find("[aria-invalid]").Length(); n != 0 {
				t.Errorf("%d controls marked invalid without errors", n)
			}
			if n := doc.Find(`[id$="-error"]`).Length(); n != 0 {
				t.Errorf("%d field error elements rendered without errors", n)
			}
		})
	}
}
