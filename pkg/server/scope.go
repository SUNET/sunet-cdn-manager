package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// callerScope is the set of orgs a caller may see. A superuser sees every org
// regardless of orgIDs.
type callerScope struct {
	superuser bool
	orgIDs    []pgtype.UUID
}

// scopeOf builds the scope for an authenticated caller. It is a set rather
// than a single org so that letting a user belong to several orgs only
// changes this function, not the resolvers or the queries using the scope.
func scopeOf(ad cdntypes.AuthData) callerScope {
	s := callerScope{superuser: ad.Superuser}
	if ad.OrgID != nil {
		s.orgIDs = append(s.orgIDs, *ad.OrgID)
	}
	return s
}

// hasNoAccess reports whether the caller can see no org at all, in which case
// every lookup is forbidden whatever it names.
func (s callerScope) hasNoAccess() bool {
	return !s.superuser && len(s.orgIDs) == 0
}

// parseNameOrID splits a client supplied identifier into a UUID or a name.
// Names must be valid DNS labels, the same rule enforced when orgs and
// services are created, so input that could never match is rejected here
// without a query.
func parseNameOrID(input string) (pgtype.UUID, bool, error) {
	if input == "" {
		return pgtype.UUID{}, false, fmt.Errorf("%w: input identifier is empty", cdnerrors.ErrUnableToParseNameOrID)
	}

	var id pgtype.UUID
	if err := id.Scan(input); err == nil {
		return id, true, nil
	}

	if err := validate.Var(input, "min=1,max=63,dns_rfc1035_label"); err != nil {
		return pgtype.UUID{}, false, fmt.Errorf("%w: not a UUID or valid name", cdnerrors.ErrUnableToParseNameOrID)
	}

	return pgtype.UUID{}, false, nil
}

// notFoundErr maps an empty lookup result to cdnerrors.ErrNotFound. Any other
// query error is a server-side failure that stays a 500; it is wrapped with
// what was being looked up, since callers return resolver errors as is.
func notFoundErr(err error, what string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return cdnerrors.ErrNotFound
	}
	return fmt.Errorf("unable to look up %s: %w", what, err)
}

// resolveOrg maps an org name or UUID to an orgIdentifier, limited to the orgs
// the caller may see.
//
// For client mistakes it returns exactly one of three errors:
//   - cdnerrors.ErrForbidden: the caller can see no org at all.
//   - cdnerrors.ErrUnableToParseNameOrID: the input is empty or malformed.
//     Decided without touching the database.
//   - cdnerrors.ErrNotFound: no org the caller may see matches. An org that
//     exists outside the caller's scope gives the very same error as one that
//     does not exist, so the response does not reveal which.
//
// Any other error is a server-side failure and is returned as is.
//
// The scope is part of the single lookup query rather than checked after an
// unrestricted lookup. Unknown and out-of-scope inputs then follow the same query
// path, with no extra round trip that happens only when the resource exists
// and could otherwise be told apart by timing.
func resolveOrg(ctx context.Context, tx pgx.Tx, ad cdntypes.AuthData, input string, lock rowLock) (orgIdentifier, error) {
	scope := scopeOf(ad)
	if scope.hasNoAccess() {
		return orgIdentifier{}, cdnerrors.ErrForbidden
	}

	inputID, isID, err := parseNameOrID(input)
	if err != nil {
		return orgIdentifier{}, err
	}

	return lookupOrg(ctx, tx, scope, input, inputID, isID, lock)
}

// lookupOrg runs the scoped org query for input already accepted by
// parseNameOrID.
func lookupOrg(ctx context.Context, tx pgx.Tx, scope callerScope, input string, inputID pgtype.UUID, isID bool, lock rowLock) (orgIdentifier, error) {
	var query string
	var args []any
	switch {
	case isID && scope.superuser:
		query = "SELECT id, name FROM orgs WHERE id = $1" + lock.clause()
		args = []any{inputID}
	case isID:
		query = "SELECT id, name FROM orgs WHERE id = $1 AND id = ANY($2)" + lock.clause()
		args = []any{inputID, scope.orgIDs}
	case scope.superuser:
		query = "SELECT id, name FROM orgs WHERE name = $1" + lock.clause()
		args = []any{input}
	default:
		query = "SELECT id, name FROM orgs WHERE name = $1 AND id = ANY($2)" + lock.clause()
		args = []any{input, scope.orgIDs}
	}

	var oi orgIdentifier
	if err := tx.QueryRow(ctx, query, args...).Scan(&oi.id, &oi.name); err != nil {
		return orgIdentifier{}, notFoundErr(err, "org")
	}

	return oi, nil
}

// resolveService maps a service name or UUID to a serviceIdentifier, limited
// to the orgs the caller may see. It follows the same three-error contract and
// single scoped query as resolveOrg.
//
// orgInput may be empty only when serviceInput is a UUID, since service names
// are unique per org. When orgInput is given the org is resolved first and
// the service must belong to it: a service UUID from another org then behaves
// like an unknown one, so a caller cannot look a service up by ID in one org
// and act on a different one.
func resolveService(ctx context.Context, tx pgx.Tx, ad cdntypes.AuthData, serviceInput string, orgInput string, lock rowLock) (serviceIdentifier, error) {
	scope := scopeOf(ad)
	if scope.hasNoAccess() {
		return serviceIdentifier{}, cdnerrors.ErrForbidden
	}

	// Both inputs are parsed before any query so a malformed one never
	// reaches the database.
	serviceID, serviceIsID, err := parseNameOrID(serviceInput)
	if err != nil {
		return serviceIdentifier{}, err
	}

	if orgInput == "" {
		if !serviceIsID {
			return serviceIdentifier{}, fmt.Errorf("%w: %w", cdnerrors.ErrUnableToParseNameOrID, errServiceNameNeedsOrg)
		}

		var query string
		var args []any
		if scope.superuser {
			query = "SELECT id, name, org_id FROM services WHERE id = $1" + lock.clause()
			args = []any{serviceID}
		} else {
			query = "SELECT id, name, org_id FROM services WHERE id = $1 AND org_id = ANY($2)" + lock.clause()
			args = []any{serviceID, scope.orgIDs}
		}

		var si serviceIdentifier
		if err := tx.QueryRow(ctx, query, args...).Scan(&si.id, &si.name, &si.orgID); err != nil {
			return serviceIdentifier{}, notFoundErr(err, "service")
		}
		return si, nil
	}

	orgID, orgIsID, err := parseNameOrID(orgInput)
	if err != nil {
		return serviceIdentifier{}, err
	}

	// The org row only needs to stay put while the service is resolved, so it
	// is always share locked; lock applies to the services row.
	oi, err := lookupOrg(ctx, tx, scope, orgInput, orgID, orgIsID, lockShare)
	if err != nil {
		return serviceIdentifier{}, err
	}

	var query string
	var arg any
	if serviceIsID {
		query = "SELECT id, name, org_id FROM services WHERE id = $1 AND org_id = $2" + lock.clause()
		arg = serviceID
	} else {
		query = "SELECT id, name, org_id FROM services WHERE name = $1 AND org_id = $2" + lock.clause()
		arg = serviceInput
	}

	var si serviceIdentifier
	if err := tx.QueryRow(ctx, query, arg, oi.id).Scan(&si.id, &si.name, &si.orgID); err != nil {
		return serviceIdentifier{}, notFoundErr(err, "service")
	}

	return si, nil
}

// serviceNameNeedsOrgError is what resolveService wraps inside
// cdnerrors.ErrUnableToParseNameOrID when a service is given by name but no
// org is given. Its UserMessage makes the API response say that the org is
// missing. Without it the response would say "unable to parse name or ID",
// which sounds like the service name itself is malformed.
//
// It has the same text as cdnerrors.ErrServiceByNameNeedsOrg but is a separate
// type on purpose. resolveService only ever returns the three cdnerrors
// sentinels listed in its doc comment, and putting a fourth one in the chain
// would break that.
type serviceNameNeedsOrgError struct{}

func (serviceNameNeedsOrgError) Error() string {
	return "looking up service by name requires org"
}

func (e serviceNameNeedsOrgError) UserMessage() string {
	return e.Error()
}

var errServiceNameNeedsOrg = serviceNameNeedsOrgError{}
