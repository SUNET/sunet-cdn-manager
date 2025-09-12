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
