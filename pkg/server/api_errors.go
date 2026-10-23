package server

import (
	"errors"
	"net/http"
	"unicode"
	"unicode/utf8"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
	"github.com/danielgtaylor/huma/v2"
)

// expectedErrorStatuses maps the cdnerrors sentinels that describe an expected
// problem (the client asked for something that is not allowed or not possible)
// to the HTTP status that should be returned for them.
//
// Handler error switches fall through to a plain error for anything they do not
// handle explicitly, which huma turns into a 500. This table lets those
// fall-through paths answer with the right 4xx and a message safe to show to
// the user instead. Handler-specific cases still take priority: they are
// checked first and apiError only replaces the fall-through return.
//
// The table is applied explicitly through apiError at each call site rather
// than through a global huma hook (overriding huma.NewError). That keeps it
// visible where errors are returned and leaves huma's own errors (validation,
// parsing and so on) untouched.
//
// The first matching entry wins, so more specific sentinels must come before
// more general ones if they ever overlap.
var expectedErrorStatuses = []struct {
	err    error
	status int
}{
	{cdnerrors.ErrBadOldPassword, http.StatusBadRequest},
	{cdnerrors.ErrOldPasswordRequired, http.StatusBadRequest},
	{cdnerrors.ErrUnableToParseNameOrID, http.StatusBadRequest},

	{cdnerrors.ErrForbidden, http.StatusForbidden},
	{cdnerrors.ErrSelfDelete, http.StatusForbidden},

	{cdnerrors.ErrNotFound, http.StatusNotFound},

	{cdnerrors.ErrAlreadyExists, http.StatusConflict},
	{cdnerrors.ErrExclutionViolation, http.StatusConflict},
	{cdnerrors.ErrServiceQuotaHit, http.StatusConflict},
	{cdnerrors.ErrDomainQuotaHit, http.StatusConflict},
	{cdnerrors.ErrOrgClientTokenQuotaHit, http.StatusConflict},
	{cdnerrors.ErrHasDependents, http.StatusConflict},
	{cdnerrors.ErrServiceNotDisabled, http.StatusConflict},
	{cdnerrors.ErrDomainRetired, http.StatusConflict},
	{cdnerrors.ErrDomainUnused, http.StatusConflict},
	{cdnerrors.ErrDomainNotVerified, http.StatusConflict},

	{cdnerrors.ErrUnprocessable, http.StatusUnprocessableEntity},
	{cdnerrors.ErrCheckViolation, http.StatusUnprocessableEntity},
	{cdnerrors.ErrInvalidFormData, http.StatusUnprocessableEntity},
	{cdnerrors.ErrServiceQuotaBelowUsage, http.StatusUnprocessableEntity},
	{cdnerrors.ErrDomainQuotaBelowUsage, http.StatusUnprocessableEntity},
	{cdnerrors.ErrClientTokenQuotaBelowUsage, http.StatusUnprocessableEntity},
	{cdnerrors.ErrInvalidVCL, http.StatusUnprocessableEntity},
	{cdnerrors.ErrUnknownDomain, http.StatusUnprocessableEntity},
	{cdnerrors.ErrNotLocalUser, http.StatusUnprocessableEntity},
	{cdnerrors.ErrServiceByNameNeedsOrg, http.StatusUnprocessableEntity},
	{cdnerrors.ErrNoServiceIPAddresses, http.StatusUnprocessableEntity},
	{cdnerrors.ErrConfirmNameMismatch, http.StatusUnprocessableEntity},
	{cdnerrors.ErrReferencedOrgNotFound, http.StatusUnprocessableEntity},
}

// lookupExpectedError returns the HTTP status and user facing message for the
// first expectedErrorStatuses entry that err matches. The message comes from
// the first error in the chain that implements cdnerrors.UserMessager, since
// those carry details that are safe and useful to show (and avoid leaking the
// wrapping context), and falls back to the sentinel's own text.
func lookupExpectedError(err error) (int, string, bool) {
	for _, e := range expectedErrorStatuses {
		if !errors.Is(err, e.err) {
			continue
		}

		if um, ok := errors.AsType[cdnerrors.UserMessager](err); ok {
			return e.status, um.UserMessage(), true
		}
		return e.status, e.err.Error(), true
	}

	return 0, "", false
}

// apiError converts expected errors to a huma error with a proper 4xx status
// and only the user message. Anything else, including errors that already carry
// a status, is returned unchanged so unexpected errors still end up as 500.
func apiError(err error) error {
	if err == nil {
		return nil
	}

	if _, ok := errors.AsType[huma.StatusError](err); ok {
		return err
	}

	if status, message, ok := lookupExpectedError(err); ok {
		return huma.NewError(status, message)
	}

	return err
}

// consoleErrorMessage returns the user message for expected errors, starting
// with an upper case letter to fit as a sentence in the console, or fallback
// for everything else. Console handlers keep answering 200 with an inline error
// message since htmx does not swap 4xx/5xx responses.
//
// An expected error with an empty user message (such as a validation error
// without details) also gets the fallback, since an empty message tells the
// user nothing and capitalising it would render a replacement character.
func consoleErrorMessage(err error, fallback string) string {
	_, message, ok := lookupExpectedError(err)
	if !ok || message == "" {
		return fallback
	}

	r, size := utf8.DecodeRuneInString(message)
	return string(unicode.ToUpper(r)) + message[size:]
}
