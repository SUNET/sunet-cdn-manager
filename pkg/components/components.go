package components

//go:generate templ fmt .
//go:generate templ generate

type Service struct {
	Name string
}

type ServiceVersion struct {
	Version int64
}
