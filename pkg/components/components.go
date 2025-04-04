package components

//go:generate templ fmt .
//go:generate templ generate

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
