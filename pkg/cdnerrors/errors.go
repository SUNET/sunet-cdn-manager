package cdnerrors

import (
	"errors"
	"fmt"
)

// Errors that can be shared across the other packages
var (
	ErrDatabaseInitialized           = errors.New("database is already initialized")
	ErrForbidden                     = errors.New("access to resource is not allowed")
	ErrNotFound                      = errors.New("resource not found")
	ErrUnprocessable                 = errors.New("resource not processable")
	ErrAlreadyExists                 = errors.New("resource already exists")
	ErrCheckViolation                = errors.New("invalid input data")
	ErrExclutionViolation            = errors.New("conflicting data in database")
	ErrBadPassword                   = errors.New("bad password")
	ErrKeyCloakEmailUnverified       = errors.New("keycloak user email is not verified")
	ErrKeyCloakUserExists            = errors.New("keycloak username already exists with other UUID")
	ErrBadOldPassword                = errors.New("old password is invalid")
	ErrUnableToParseNameOrID         = errors.New("unable to parse name or ID")
	ErrInvalidFormData               = errors.New("invalid form data")
	ErrServiceByNameNeedsOrg         = errors.New("looking up service by name requires org")
	ErrOriginGroupByNameNeedsService = errors.New("looking up origin group by name requires service")
	ErrServiceQuotaHit               = errors.New("not allowed to create more services")
	ErrDomainQuotaHit                = errors.New("not allowed to create more domains")
	ErrOrgClientTokenQuotaHit        = errors.New("not allowed to create more org client tokens")
	ErrInvalidVCL                    = errors.New("VCL is invalid")
	ErrUnknownDomain                 = errors.New("unknown domain name")
	ErrReEncryptionMissingPassword   = errors.New("re-encryption needs at least two configured encryption passwords")
	ErrReEncryptionFailed            = errors.New("re-encryption failed for at least one token")
)

// VCLValidationError identifies as ErrInvalidVCL error but also includes a
// detailed message from the failed validation
type VCLValidationError struct {
	Details string // Message returned from validation service
}

// Implement the error interface
func (e *VCLValidationError) Error() string {
	return fmt.Sprintf("%s: %s", ErrInvalidVCL, e.Details)
}

// Make it possible to use errors.Is(err, ErrInvalidVCL)
func (e *VCLValidationError) Unwrap() error {
	return ErrInvalidVCL
}

// Creates a new validation error containing the supplied details
func NewValidationError(details string) error {
	return &VCLValidationError{
		Details: details,
	}
}
