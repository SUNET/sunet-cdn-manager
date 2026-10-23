package server

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
	"github.com/danielgtaylor/huma/v2"
	"github.com/jackc/pgx/v5"
)

// Sentinel errors that are deliberately not in expectedErrorStatuses, with the
// reason for each.
var unmappedSentinels = map[error]string{
	// Only raised by the init command, never from a request.
	cdnerrors.ErrDatabaseInitialized: "only raised by the init command",
	// Operator/server-side failures, 500 is the correct answer.
	cdnerrors.ErrReEncryptionMissingPassword: "operator/server-side failure, 500 is correct",
	cdnerrors.ErrReEncryptionFailed:          "operator/server-side failure, 500 is correct",
	// Must answer 401 with a WWW-Authenticate header, which the table cannot
	// express, so it is handled where it is raised.
	cdnerrors.ErrBadPassword: "needs 401 with WWW-Authenticate, handled where raised",
	// Need a Retry-After header, handled where raised.
	cdnerrors.ErrLoginRateLimited: "needs Retry-After header, handled where raised",
	cdnerrors.ErrLoginBusy:        "needs Retry-After header, handled where raised",
	// Only raised in the OIDC login flow, which renders its own page.
	cdnerrors.ErrKeyCloakEmailUnverified: "only raised in the OIDC login flow, which renders its own page",
	cdnerrors.ErrKeyCloakUserExists:      "only raised in the OIDC login flow, which renders its own page",
}

func TestLookupExpectedError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantMsg    string
		wantOK     bool
	}{
		{
			name:       "wrapped sentinel uses sentinel text",
			err:        fmt.Errorf("x: %w", cdnerrors.ErrForbidden),
			wantStatus: 403,
			wantMsg:    "access to resource is not allowed",
			wantOK:     true,
		},
		{
			name:       "quota error uses user message",
			err:        &cdnerrors.QuotaError{Quota: cdnerrors.DomainQuota, Used: 5, Limit: 5},
			wantStatus: 409,
			wantMsg:    "domain quota reached (5 of 5)",
			wantOK:     true,
		},
		{
			name: "wrapped domain in use error uses user message",
			err: fmt.Errorf("x: %w", &cdnerrors.DomainInUseError{
				Domain:   "example.se",
				Versions: []cdnerrors.ServiceVersionRef{{Service: "svc", Version: 3}},
			}),
			wantStatus: 409,
			wantMsg:    `cannot delete "example.se": used by svc version 3, retire it instead`,
			wantOK:     true,
		},
		{
			name:       "wrapped unknown domain error names the domain",
			err:        fmt.Errorf("x: %w", &cdnerrors.UnknownDomainError{Domain: "example.se"}),
			wantStatus: 422,
			wantMsg:    "unknown domain name: example.se",
			wantOK:     true,
		},
		{
			name: "unexpected error is not found",
			err:  errors.New("boom"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, msg, ok := lookupExpectedError(tt.err)
			if ok != tt.wantOK {
				t.Fatalf("ok = %t, want %t", ok, tt.wantOK)
			}
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
			if msg != tt.wantMsg {
				t.Errorf("message = %q, want %q", msg, tt.wantMsg)
			}
		})
	}
}

func TestAPIError(t *testing.T) {
	if got := apiError(nil); got != nil {
		t.Errorf("apiError(nil) = %v, want nil", got)
	}

	t.Run("unknown error is returned unchanged", func(t *testing.T) {
		unknown := fmt.Errorf("tx: %w", pgx.ErrNoRows)
		if got := apiError(unknown); got != unknown {
			t.Errorf("apiError() = %v, want the input error unchanged", got)
		}
	})

	t.Run("existing huma error is returned unchanged", func(t *testing.T) {
		h := huma.Error404NotFound("domain not found")
		in := fmt.Errorf("w: %w", h)
		if got := apiError(in); got != in {
			t.Errorf("apiError() = %v, want the input error unchanged", got)
		}
	})

	t.Run("referenced org not found is unprocessable", func(t *testing.T) {
		got := apiError(fmt.Errorf("wrap: %w", cdnerrors.ErrReferencedOrgNotFound))
		se, ok := got.(huma.StatusError)
		if !ok {
			t.Fatalf("apiError() = %v, want a huma.StatusError", got)
		}
		if se.GetStatus() != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want %d", se.GetStatus(), http.StatusUnprocessableEntity)
		}
		if want := "referenced organization not found"; se.Error() != want {
			t.Errorf("message = %q, want %q", se.Error(), want)
		}
	})

	t.Run("expected error keeps only the user message", func(t *testing.T) {
		// The context added while the error is returned up the stack,
		// here "deleteDomain transaction failed: ", is internal detail
		// that must not end up in the response. Huma's default 500
		// would put the whole error text in the errors list.
		got := apiError(fmt.Errorf("deleteDomain transaction failed: %w", cdnerrors.ErrForbidden))
		model, ok := errors.AsType[*huma.ErrorModel](got)
		if !ok {
			t.Fatalf("apiError() = %v, want a *huma.ErrorModel", got)
		}
		if model.Status != http.StatusForbidden {
			t.Errorf("status = %d, want %d", model.Status, http.StatusForbidden)
		}
		if want := cdnerrors.ErrForbidden.Error(); model.Detail != want {
			t.Errorf("detail = %q, want %q", model.Detail, want)
		}
		if len(model.Errors) != 0 {
			t.Errorf("errors = %v, want none", model.Errors)
		}
	})
}

func TestConsoleErrorMessage(t *testing.T) {
	const fallback = "unable to insert domain"

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			// A typed error shows its own user message, with the first
			// letter upper-cased to read as a sentence on the page.
			name: "typed error uses its user message",
			err:  &cdnerrors.QuotaError{Quota: cdnerrors.DomainQuota},
			want: "Domain quota reached (0 of 0)",
		},
		{
			// A mapped sentinel without details shows the sentinel's
			// own text, also upper-cased, and not the wrapping context.
			name: "mapped sentinel uses the sentinel text",
			err:  fmt.Errorf("deleteDomain transaction failed: %w", cdnerrors.ErrForbidden),
			want: "Access to resource is not allowed",
		},
		{
			// An error that is not in the table may carry internal
			// details, so the handler's generic message is shown instead.
			name: "unmapped error uses the fallback",
			err:  errors.New("connection reset by peer"),
			want: fallback,
		},
		{
			// A mapped error whose user message is empty would tell
			// the user nothing (and upper-casing "" would render a
			// replacement character), so it gets the fallback too.
			name: "mapped error with empty user message uses the fallback",
			err:  cdnerrors.NewValidationError(""),
			want: fallback,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := consoleErrorMessage(tt.err, fallback); got != tt.want {
				t.Errorf("consoleErrorMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Every sentinel in cdnerrors must be either in expectedErrorStatuses or in
// unmappedSentinels, so that adding a new sentinel forces a decision about
// which HTTP status (if any) it should produce.
//
// Go has no way to list the variables of a package at runtime, so the test
// reads the cdnerrors source instead: it parses the files into a syntax tree
// (go/ast) and collects every exported variable named Err*. The syntax tree
// only has the source text, not the error values, so the sentinels are
// identified by their errors.New() message and compared with the Error() text
// of the entries in the two lists.
func TestEverySentinelHasStatusDecision(t *testing.T) {
	// Sentinel message -> variable name
	sentinels := map[string]string{}
	for _, f := range parseCdnerrorsFiles(t) {
		// f.Decls holds the top level declarations of the file:
		// functions, imports, types, consts and vars.
		for _, decl := range f.Decls {
			// A var declaration, either "var x = ..." or a
			// "var ( ... )" block, is a GenDecl with the VAR token.
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			// Each line of a var block is a ValueSpec, holding the
			// names on the left of "=" and the values on the right.
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if !strings.HasPrefix(name.Name, "Err") {
						continue
					}
					// Values[i] is the value assigned to Names[i].
					// There are fewer values than names for
					// "var ErrX error" (no value) and for
					// "var ErrA, ErrB = f()" (one call, two names).
					if i >= len(vs.Values) {
						t.Errorf("%s has no value, expected errors.New(\"...\")", name.Name)
						continue
					}
					// Get the message out of errors.New("...")
					// to identify the sentinel by.
					msg, ok := errorsNewLiteral(vs.Values[i])
					if !ok {
						t.Errorf("%s must be defined as errors.New(<string literal>) so its status decision can be checked", name.Name)
						continue
					}
					// Entries are matched to sentinels by message,
					// so two sentinels sharing one would be
					// indistinguishable here.
					if other, ok := sentinels[msg]; ok {
						t.Errorf("%s and %s share the message %q, sentinel messages must be unique", other, name.Name, msg)
						continue
					}
					sentinels[msg] = name.Name
				}
			}
		}
	}

	// Count how many times each sentinel is listed, and catch entries
	// left behind for a sentinel that has been removed or renamed.
	covered := map[string]int{}
	for _, e := range expectedErrorStatuses {
		msg := e.err.Error()
		name, ok := sentinels[msg]
		if !ok {
			t.Errorf("expectedErrorStatuses entry %q matches no sentinel in cdnerrors (stale)", msg)
			continue
		}
		covered[name]++
	}
	for err := range unmappedSentinels {
		msg := err.Error()
		name, ok := sentinels[msg]
		if !ok {
			t.Errorf("unmappedSentinels entry %q matches no sentinel in cdnerrors (stale)", msg)
			continue
		}
		covered[name]++
	}

	// Every sentinel needs exactly one decision. Sorted so failures are
	// reported in the same order on every run.
	for _, name := range slices.Sorted(maps.Values(sentinels)) {
		switch covered[name] {
		case 1:
			// Exactly one decision
		case 0:
			t.Errorf("cdnerrors.%s has no HTTP status decision: add it to expectedErrorStatuses or to unmappedSentinels (with a reason)", name)
		default:
			t.Errorf("cdnerrors.%s is listed more than once in expectedErrorStatuses/unmappedSentinels", name)
		}
	}
}

// parseCdnerrorsFiles parses every non-test file in pkg/cdnerrors, so a
// sentinel added outside errors.go is checked as well. The files are listed
// by hand since parser.ParseDir (and the ast.Package it returns) is
// deprecated.
func parseCdnerrorsFiles(t *testing.T) []*ast.File {
	t.Helper()

	const dir = "../cdnerrors"

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	files := []*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}

	if len(files) == 0 {
		t.Fatalf("no Go files found in %s", dir)
	}

	return files
}

// errorsNewLiteral returns the string literal when expr is errors.New("...").
func errorsNewLiteral(expr ast.Expr) (string, bool) {
	// A function call with a single argument
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return "", false
	}
	// The function is a selector "X.Sel", where Sel must be New ...
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "New" {
		return "", false
	}
	// ... and X must be the errors package
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "errors" {
		return "", false
	}
	// The argument is a string literal. Its Value is the source text,
	// including the quotes and any escapes, so unquote it to get the
	// same string errors.New() was given.
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	msg, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return msg, true
}
