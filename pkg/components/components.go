package components

//go:generate templ fmt .
//go:generate templ generate

import (
	"embed"
	"encoding/json"
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
