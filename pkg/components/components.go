package components

//go:generate templ fmt .
//go:generate templ generate

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
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
	Name string
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
