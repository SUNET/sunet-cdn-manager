package components

//go:generate templ fmt .
//go:generate templ generate

import (
	"embed"
	"encoding/json"
)

//go:embed css/*.css
var CSSFS embed.FS

//go:embed js/*.js
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

// https://htmx.org/docs/#csrf-prevention
type hxHeaders struct {
	XCsrfToken string `json:"X-CSRF-TOKEN"`
}

// https://templ.guide/syntax-and-usage/attributes#json-attributes
func jsonHxHeaders(csrfToken string) string {
	hh := hxHeaders{
		XCsrfToken: csrfToken,
	}

	b, err := json.Marshal(hh)
	if err != nil {
		// Should never happen
		panic(err)
	}

	return string(b)
}
