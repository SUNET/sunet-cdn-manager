package cdnerrors

import "errors"

// Errors that can be shared across the other packages
var (
	ErrForbidden               = errors.New("access to resource is not allowed")
	ErrNotFound                = errors.New("resource not found")
	ErrUnprocessable           = errors.New("resource not processable")
	ErrAlreadyExists           = errors.New("resource already exists")
	ErrCheckViolation          = errors.New("invalid input data")
	ErrExclutionViolation      = errors.New("conflicting data in database")
	ErrBadPassword             = errors.New("bad password")
	ErrKeyCloakEmailUnverified = errors.New("keycloak user email is not verified")
	ErrBadOldPassword          = errors.New("old password is invalid")
	ErrUnableToParseNameOrID   = errors.New("unable to parse name or ID")
	ErrInvalidFormData         = errors.New("invalid form data")
	ErrServiceByNameNeedsOrg   = errors.New("looking up service by name requires org")
)
