package cdnerrors

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Errors that can be shared across the other packages
var (
	ErrDatabaseInitialized         = errors.New("database is already initialized")
	ErrForbidden                   = errors.New("access to resource is not allowed")
	ErrNotFound                    = errors.New("resource not found")
	ErrUnprocessable               = errors.New("resource not processable")
	ErrAlreadyExists               = errors.New("resource already exists")
	ErrCheckViolation              = errors.New("invalid input data")
	ErrExclutionViolation          = errors.New("conflicting data in database")
	ErrBadPassword                 = errors.New("bad password")
	ErrKeyCloakEmailUnverified     = errors.New("keycloak user email is not verified")
	ErrKeyCloakUserExists          = errors.New("keycloak username already exists with other UUID")
	ErrBadOldPassword              = errors.New("old password is invalid")
	ErrUnableToParseNameOrID       = errors.New("unable to parse name or ID")
	ErrInvalidFormData             = errors.New("invalid form data")
	ErrServiceByNameNeedsOrg       = errors.New("looking up service by name requires org")
	ErrServiceQuotaHit             = errors.New("not allowed to create more services")
	ErrDomainQuotaHit              = errors.New("not allowed to create more domains")
	ErrOrgClientTokenQuotaHit      = errors.New("not allowed to create more org client tokens")
	ErrServiceQuotaBelowUsage      = errors.New("service quota is below current usage")
	ErrDomainQuotaBelowUsage       = errors.New("domain quota is below current usage")
	ErrClientTokenQuotaBelowUsage  = errors.New("client token quota is below current usage")
	ErrInvalidVCL                  = errors.New("VCL is invalid")
	ErrUnknownDomain               = errors.New("unknown domain name")
	ErrReEncryptionMissingPassword = errors.New("re-encryption needs at least two configured encryption passwords")
	ErrReEncryptionFailed          = errors.New("re-encryption failed for at least one token")
	ErrHasDependents               = errors.New("resource has dependent resources")
	ErrNotLocalUser                = errors.New("operation is only available for local users")
	ErrOldPasswordRequired         = errors.New("old password is required")
	ErrSelfDelete                  = errors.New("users cannot delete themselves")
	ErrNoServiceIPAddresses        = errors.New("no service IP addresses available for allocation")
	ErrServiceNotDisabled          = errors.New("service must be disabled before it can be deleted")
	ErrConfirmNameMismatch         = errors.New("confirmation name does not match resource name")
	ErrLoginRateLimited            = errors.New("too many login attempts")
	ErrLoginBusy                   = errors.New("server busy handling logins")
	ErrDomainRetired               = errors.New("domain is retired")
	ErrDomainUnused                = errors.New("domain is not used by any service version, delete it instead")
	ErrDomainNotVerified           = errors.New("domain is not verified")
	ErrDomainChallengeTooLong      = errors.New("domain is too long to fit challenge label")
	// ErrReferencedOrgNotFound is deliberately the same for an unknown org
	// and for an org the caller may not use, so the response cannot be used
	// to probe for which orgs exist.
	ErrReferencedOrgNotFound = errors.New("referenced organization not found")
)

// UserMessager is implemented by errors whose details are safe and useful to
// show to users as-is. It embeds error so it can be looked up in an error chain
// with errors.AsType.
type UserMessager interface {
	error
	UserMessage() string
}

// Quota is one of the per-org quotas.
type Quota int

const (
	ServiceQuota Quota = iota
	DomainQuota
	ClientCredentialQuota
)

// String returns the human readable name of the resource the quota limits,
// e.g. "domain".
func (q Quota) String() string {
	switch q {
	case ServiceQuota:
		return "service"
	case DomainQuota:
		return "domain"
	case ClientCredentialQuota:
		return "client credential"
	default:
		return fmt.Sprintf("Quota(%d)", int(q))
	}
}

// hitErr returns the sentinel for having hit the quota.
func (q Quota) hitErr() error {
	switch q {
	case ServiceQuota:
		return ErrServiceQuotaHit
	case DomainQuota:
		return ErrDomainQuotaHit
	case ClientCredentialQuota:
		return ErrOrgClientTokenQuotaHit
	default:
		return nil
	}
}

// QuotaError identifies as the *QuotaHit error for its Quota but also
// includes how much of the quota is used.
type QuotaError struct {
	Quota Quota
	Used  int64
	Limit int64
}

func (e *QuotaError) Error() string {
	return fmt.Sprintf("%s quota reached (%d of %d)", e.Quota, e.Used, e.Limit)
}

// Make it possible to use errors.Is(err, ErrDomainQuotaHit) and friends
func (e *QuotaError) Unwrap() error {
	return e.Quota.hitErr()
}

func (e *QuotaError) UserMessage() string {
	return e.Error()
}

// ServiceVersionRef points out a specific version of a service by name.
type ServiceVersionRef struct {
	Service string
	Version int64
}

// DomainInUseError identifies as ErrHasDependents and lists the service
// versions that still reference the domain. Error() lists each service once,
// in the order it first appears in Versions, with its versions in the order
// given. Error() ends by suggesting to retire the domain instead, unless
// Retired says it already is or Active says an active version uses it,
// which would make retiring fail as well.
type DomainInUseError struct {
	Domain   string
	Versions []ServiceVersionRef
	Retired  bool
	Active   bool
}

func (e *DomainInUseError) Error() string {
	services := []string{}
	versionsByService := map[string][]string{}
	for _, v := range e.Versions {
		if _, seen := versionsByService[v.Service]; !seen {
			services = append(services, v.Service)
		}
		versionsByService[v.Service] = append(versionsByService[v.Service], strconv.FormatInt(v.Version, 10))
	}

	parts := []string{}
	for _, service := range services {
		versions := versionsByService[service]
		if len(versions) == 1 {
			parts = append(parts, fmt.Sprintf("%s version %s", service, versions[0]))
		} else {
			parts = append(parts, fmt.Sprintf("%s versions %s", service, strings.Join(versions, ", ")))
		}
	}
	msg := fmt.Sprintf("cannot delete %q: used by %s", e.Domain, joinParts(parts))
	if !e.Retired && !e.Active {
		msg += ", retire it instead"
	}
	return msg
}

func (e *DomainInUseError) Unwrap() error {
	return ErrHasDependents
}

func (e *DomainInUseError) UserMessage() string {
	return e.Error()
}

// UnknownDomainError identifies as ErrUnknownDomain and names the domain
// that is not a verified domain of the org, so a version listing several
// domains tells which one to fix.
type UnknownDomainError struct {
	Domain string
}

func (e *UnknownDomainError) Error() string {
	return fmt.Sprintf("%s: %s", ErrUnknownDomain, e.Domain)
}

// Make it possible to use errors.Is(err, ErrUnknownDomain)
func (e *UnknownDomainError) Unwrap() error {
	return ErrUnknownDomain
}

func (e *UnknownDomainError) UserMessage() string {
	return e.Error()
}

// DomainActiveError identifies as ErrHasDependents and lists the services
// whose active version references a domain that is to be retired. Only the
// active version blocks retiring, so versions are not listed.
type DomainActiveError struct {
	Domain   string
	Services []string
}

func (e *DomainActiveError) Error() string {
	return fmt.Sprintf("cannot retire %q: used by the active version of %s", e.Domain, joinParts(e.Services))
}

func (e *DomainActiveError) Unwrap() error {
	return ErrHasDependents
}

func (e *DomainActiveError) UserMessage() string {
	return e.Error()
}

// DomainsNotVerifiedError identifies as ErrDomainNotVerified and lists the
// domains of a service version that keep it from being activated.
type DomainsNotVerifiedError struct {
	Domains []string
}

func (e *DomainsNotVerifiedError) Error() string {
	return "version uses domains that are not verified: " + strings.Join(e.Domains, ", ")
}

func (e *DomainsNotVerifiedError) Unwrap() error {
	return ErrDomainNotVerified
}

func (e *DomainsNotVerifiedError) UserMessage() string {
	return e.Error()
}

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

// The validation details are what the user needs to fix the VCL
func (e *VCLValidationError) UserMessage() string {
	return e.Details
}

// LoginRateLimitedError identifies as ErrLoginRateLimited error but also
// includes how long the client should wait before trying again
type LoginRateLimitedError struct {
	RetryAfter time.Duration
}

// Implement the error interface
func (e *LoginRateLimitedError) Error() string {
	return fmt.Sprintf("%s: retry after %s", ErrLoginRateLimited, e.RetryAfter)
}

// Make it possible to use errors.Is(err, ErrLoginRateLimited)
func (e *LoginRateLimitedError) Unwrap() error {
	return ErrLoginRateLimited
}

// Creates a new validation error containing the supplied details
func NewValidationError(details string) error {
	return &VCLValidationError{
		Details: details,
	}
}

// AddressConflictError identifies as ErrAlreadyExists but indicates that a
// specific IP address is already assigned to another node.
type AddressConflictError struct {
	Address string
}

func (e *AddressConflictError) Error() string {
	return fmt.Sprintf("address already in use: %s", e.Address)
}

func (e *AddressConflictError) Unwrap() error {
	return ErrAlreadyExists
}

func (e *AddressConflictError) UserMessage() string {
	return e.Error()
}

// DuplicateOriginError identifies as ErrAlreadyExists but indicates that a
// service version's submitted origin data contains the same host:port pair
// more than once (service_origins
// UNIQUE(service_version_id, host, port)). Unlike a genuine
// already-exists-in-the-database conflict this stems from the client's own
// submitted data, so callers generally want to treat it like a 422 rather
// than a 409.
type DuplicateOriginError struct{}

func (e *DuplicateOriginError) Error() string {
	return "duplicate origin host/port present in service version"
}

func (e *DuplicateOriginError) Unwrap() error {
	return ErrAlreadyExists
}

func (e *DuplicateOriginError) UserMessage() string {
	return e.Error()
}

// DependentsError identifies as ErrHasDependents and includes counts of
// dependent resources that prevent deletion.
type DependentsError struct {
	Name         string
	Services     int64
	Domains      int64
	ClientTokens int64
}

func (e *DependentsError) Error() string {
	parts := []string{}
	if e.Services > 0 {
		parts = append(parts, fmt.Sprintf("%d services", e.Services))
	}
	if e.Domains > 0 {
		parts = append(parts, fmt.Sprintf("%d domains", e.Domains))
	}
	if e.ClientTokens > 0 {
		parts = append(parts, fmt.Sprintf("%d client tokens", e.ClientTokens))
	}
	return fmt.Sprintf("cannot delete %q: has %s", e.Name, joinParts(parts))
}

func (e *DependentsError) Unwrap() error {
	return ErrHasDependents
}

func (e *DependentsError) UserMessage() string {
	return e.Error()
}

// IPAllocationError identifies as ErrNoServiceIPAddresses and indicates which
// address family (IPv4 or IPv6) could not be allocated and how many were requested.
type IPAllocationError struct {
	Family    string // "IPv4" or "IPv6"
	Requested int
}

func (e *IPAllocationError) Error() string {
	suffix := "addresses"
	if e.Requested == 1 {
		suffix = "address"
	}
	return fmt.Sprintf("unable to allocate %d service %s %s", e.Requested, e.Family, suffix)
}

func (e *IPAllocationError) Unwrap() error {
	return ErrNoServiceIPAddresses
}

func (e *IPAllocationError) UserMessage() string {
	return e.Error()
}

func joinParts(parts []string) string {
	switch len(parts) {
	case 0:
		return "dependents"
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		var result strings.Builder
		for i, p := range parts {
			if i == len(parts)-1 {
				result.WriteString("and " + p)
			} else {
				result.WriteString(p + ", ")
			}
		}
		return result.String()
	}
}
