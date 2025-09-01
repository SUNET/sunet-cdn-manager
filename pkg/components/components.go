package components

//go:generate templ fmt .
//go:generate templ generate

import (
	"embed"
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
