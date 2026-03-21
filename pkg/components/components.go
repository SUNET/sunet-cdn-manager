package components

//go:generate templ fmt .
//go:generate templ generate

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
)

//go:embed css/*.css
//go:embed css/dist
var CSSFS embed.FS

// The "all:" prefix is needed here because by default files beginning with ‘.’ or
// ‘_’ are excluded and we want to include "_hyperscript.min.js"
//
//go:embed all:js/dist
var JsFS embed.FS

type DomainFormFields struct {
	FQDN string
}

type DomainData struct {
	DomainFormFields
	Errors DomainErrors
}

type DomainErrors struct {
	DomainFormFields
	ServerError string
}

type APITokenFormFields struct {
	Name        string
	Description string
}

type APITokenData struct {
	APITokenFormFields
	Errors APITokenErrors
}

type APITokenErrors struct {
	APITokenFormFields
	ServerError string
}

// ServiceEntry is a console-specific view type that combines a Service with
// its allocated IP addresses for display on the services overview page.
type ServiceEntry struct {
	cdntypes.Service
	IPAddresses []netip.Addr
}

type NodeFormFields struct {
	Name        string
	Description string
	Addresses   string
}

type NodeFormErrors struct {
	Name        string
	Description string
	Addresses   string
	ServerError string
}

type CacheNodeFormData struct {
	NodeFormFields
	Errors NodeFormErrors
}

type L4LBNodeFormData struct {
	NodeFormFields
	Errors NodeFormErrors
}

type OrgFormFields struct {
	Name             string
	ServiceQuota     string
	DomainQuota      string
	ClientTokenQuota string
}

type OrgFormErrors struct {
	Name             string
	ServiceQuota     string
	DomainQuota      string
	ClientTokenQuota string
	ServerError      string
}

type OrgFormData struct {
	OrgFormFields
	Errors OrgFormErrors
}

type NodeGroupFormFields struct {
	Name        string
	Description string
}

type NodeGroupFormErrors struct {
	Name        string
	Description string
	ServerError string
}

type NodeGroupFormData struct {
	NodeGroupFormFields
	Errors NodeGroupFormErrors
}

type UserFormFields struct {
	DisplayName     string `schema:"display_name" validate:"required,min=1,max=63"`
	Role            string `schema:"role" validate:"required"`
	Org             string `schema:"org"`
	Password        string `schema:"password"`         // #nosec G117 -- Used for form password input, never used for serialized output
	ConfirmPassword string `schema:"confirm-password"` // #nosec G117 -- Used for form password input, never used for serialized output
}

type UserFormErrors struct {
	DisplayName     string
	Role            string
	Org             string
	Password        string // #nosec G117 -- Error message for password field, not a secret
	ConfirmPassword string
	ServerError     string
}

type UserFormData struct {
	UserFormFields
	Errors UserFormErrors
}

type PasswordResetFormFields struct {
	Password        string `schema:"password" validate:"required,min=15,max=64"`            // #nosec G117 -- Used for form password input, never used for serialized output
	ConfirmPassword string `schema:"confirm-password" validate:"required,eqfield=Password"` // #nosec G117 -- Used for form password input, never used for serialized output
}

type PasswordResetFormErrors struct {
	Password        string // #nosec G117 -- Error message for password field, not a secret
	ConfirmPassword string
	ServerError     string
}

type PasswordResetFormData struct {
	PasswordResetFormFields
	Errors PasswordResetFormErrors
}

// AddressesString formats a node's addresses as newline-separated text for
// display in textarea form fields.
func AddressesString(node cdntypes.Node) string {
	parts := make([]string, 0, len(node.Addresses))
	for _, addr := range node.Addresses {
		parts = append(parts, addr.String())
	}
	return strings.Join(parts, "\n")
}

type addButtonVals struct {
	Org     string `json:"org"`
	Service string `json:"service"`
}

// https://htmx.org/attributes/hx-vals/
func jsonAddButtonVals(orgName string, serviceName string) string {
	abv := addButtonVals{
		Org:     orgName,
		Service: serviceName,
	}

	b, err := json.Marshal(abv)
	if err != nil {
		// Should never happen
		panic(err)
	}

	return string(b)
}

// Make it easier to print pre-formatted text for use in the html template
func tokenCurlCommand(tokenURL *url.URL) string {
	return fmt.Sprintf(`curl -X POST %s \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET"`, tokenURL.String())
}

func apiSampleCurlCommand(serverURL *url.URL, orgName string) string {
	apiURL := serverURL.JoinPath("api/v1/orgs", orgName, "client-credentials")
	return fmt.Sprintf(`curl -X GET %s \
  -H 'Authorization: Bearer YOUR_ACCESS_TOKEN'`, apiURL.String())
}

// Breadcrumb represents one item in the breadcrumb navigation trail.
type Breadcrumb struct {
	Label string
	URL   string
}

// section defines the metadata for a console navigation section. To add a new
// section, add an entry to the sections map below — both urlToSection and
// buildBreadcrumbs will pick it up automatically.
type section struct {
	Label      string // Display name shown in navigation list (e.g. "Domains")
	CreateSlug string // Singular form used in /create/ paths (e.g. "domain")
}

// sections maps URL path segments to their configuration. This is the single
// source of truth for section names used by both urlToSection (active nav
// highlighting) and buildBreadcrumbs (ancestor navigation).
var sections = map[string]section{
	"domains":     {Label: "Domains", CreateSlug: "domain"},
	"services":    {Label: "Services", CreateSlug: "service"},
	"api-tokens":  {Label: "API tokens", CreateSlug: "api-token"},
	"cache-nodes": {Label: "Cache nodes", CreateSlug: "cache-node"},
	"l4lb-nodes":  {Label: "L4LB nodes", CreateSlug: "l4lb-node"},
	"node-groups": {Label: "Node groups", CreateSlug: "node-group"},
	"orgs":        {Label: "Organizations", CreateSlug: "org"},
	"users":       {Label: "Users", CreateSlug: "user"},
}

// createSlugToSection provides reverse lookup from the singular create/ path
// segment to the section URL path (e.g. "domain" -> "domains").
var createSlugToSection = func() map[string]string {
	m := map[string]string{}
	for path, sec := range sections {
		m[sec.CreateSlug] = path
	}
	return m
}()

// buildBreadcrumbs returns the ancestor navigation path for the given console
// URL. Each item is a link. The current page is not included since it is
// already shown in the <h1> title.
func buildBreadcrumbs(u *url.URL, orgName string, itemLabel string) []Breadcrumb {
	urlPath := u.EscapedPath()
	parts := strings.Split(strings.Trim(urlPath, "/"), "/")

	// Handle superuser paths: /console/superuser/{section}[/{item}[/edit]]
	if strings.HasPrefix(urlPath, "/console/superuser/") {
		return buildSuperuserBreadcrumbs(parts, itemLabel)
	}

	// Handle superuser create paths: /console/superuser/create/{slug}
	// (already covered by the prefix check above since /console/superuser/create/ starts with /console/superuser/)

	// Only generate breadcrumbs for org-scoped pages with depth beyond the org dashboard
	if !strings.HasPrefix(urlPath, "/console/org/") || len(parts) <= 3 {
		return nil
	}

	orgBase := fmt.Sprintf("/console/org/%s", orgName)

	crumbs := []Breadcrumb{{Label: orgName, URL: orgBase}}

	switch {
	case parts[3] == "create" && len(parts) >= 5:
		// /console/org/{org}/create/{slug}[/version/{service}]
		if sectionPath, ok := createSlugToSection[parts[4]]; ok {
			sec := sections[sectionPath]
			crumbs = append(crumbs, Breadcrumb{Label: sec.Label, URL: orgBase + "/" + sectionPath})

			// Handle nested create paths like /create/service/version/{service}
			if len(parts) >= 7 && parts[5] == "version" {
				serviceName := parts[6]
				crumbs = append(crumbs, Breadcrumb{Label: serviceName, URL: fmt.Sprintf("%s/%s/%s", orgBase, sectionPath, serviceName)})
			}
		}

	default:
		// /console/org/{org}/{section}[/{item}[/{sub}[/...]]]
		sec, ok := sections[parts[3]]
		if !ok {
			return crumbs
		}
		sectionPath := parts[3]

		if len(parts) >= 5 {
			// Deeper than the section list, add section crumb
			crumbs = append(crumbs, Breadcrumb{Label: sec.Label, URL: orgBase + "/" + sectionPath})
			itemName := parts[4]

			if len(parts) >= 6 {
				// Deeper than the item, add item crumb
				crumbs = append(crumbs, Breadcrumb{Label: itemName, URL: fmt.Sprintf("%s/%s/%s", orgBase, sectionPath, itemName)})

				if len(parts) >= 7 {
					// Deeper than sub-item (e.g. /services/test-service/3/activate)
					subItem := parts[5]
					crumbs = append(crumbs, Breadcrumb{Label: "Version " + subItem, URL: fmt.Sprintf("%s/%s/%s/%s", orgBase, sectionPath, itemName, subItem)})
				}
			}
		}
	}

	return crumbs
}

// buildSuperuserBreadcrumbs generates breadcrumbs for /console/superuser/ paths.
// List pages (e.g. /console/superuser/cache-nodes) get no breadcrumbs since
// they are already the top-level view. Deeper pages (create, edit, and other
// actions like maintenance/node-group) get the section list page as root crumb.
func buildSuperuserBreadcrumbs(parts []string, itemLabel string) []Breadcrumb {
	// parts: ["console", "superuser", ...]
	if len(parts) <= 3 {
		// /console/superuser or /console/superuser/{section} — no breadcrumbs
		return nil
	}

	superBase := "/console/superuser"

	switch {
	case parts[2] == "create" && len(parts) >= 4:
		// /console/superuser/create/{slug}
		if sectionPath, ok := createSlugToSection[parts[3]]; ok {
			sec := sections[sectionPath]
			return []Breadcrumb{{Label: sec.Label, URL: superBase + "/" + sectionPath}}
		}
		return nil
	default:
		// /console/superuser/{section}/{item}[/edit]
		sec, ok := sections[parts[2]]
		if !ok {
			return nil
		}
		sectionPath := parts[2]

		crumbs := []Breadcrumb{{Label: sec.Label, URL: superBase + "/" + sectionPath}}

		if len(parts) >= 5 {
			// /console/superuser/{section}/{item}/{action} — link to edit
			// page since there is no standalone item detail page
			itemID := parts[3]
			label := itemID
			if itemLabel != "" {
				label = itemLabel
			}
			crumbs = append(crumbs, Breadcrumb{Label: label, URL: fmt.Sprintf("%s/%s/%s/edit", superBase, sectionPath, itemID)})
		}

		return crumbs
	}
}

// urlToSection returns the active navigation section for the given console URL,
// used by NavBar to highlight the current section link.
func urlToSection(u *url.URL) string {
	urlPath := u.EscapedPath()
	parts := strings.Split(strings.Trim(urlPath, "/"), "/")

	// Handle superuser paths: /console/superuser/{section}[/...]
	if strings.HasPrefix(urlPath, "/console/superuser/") && len(parts) >= 3 {
		// Map /console/superuser/create/{slug} back to the section path
		if parts[2] == "create" && len(parts) >= 4 {
			if sectionPath, ok := createSlugToSection[parts[3]]; ok {
				return sectionPath
			}
		}
		return parts[2]
	}

	if !strings.HasPrefix(urlPath, "/console/org/") {
		return ""
	}

	if len(parts) <= 3 {
		return "dashboard"
	}

	// Map /create/{slug} back to the section path
	if parts[3] == "create" && len(parts) >= 5 {
		if sectionPath, ok := createSlugToSection[parts[4]]; ok {
			return sectionPath
		}
	}

	return parts[3]
}
