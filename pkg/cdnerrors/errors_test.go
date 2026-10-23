package cdnerrors

import (
	"errors"
	"fmt"
	"testing"
)

func TestQuotaError(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &QuotaError{Quota: DomainQuota, Used: 5, Limit: 5})

	if !errors.Is(err, ErrDomainQuotaHit) {
		t.Errorf("expected error to match ErrDomainQuotaHit")
	}

	um, ok := errors.AsType[UserMessager](err)
	if !ok {
		t.Fatalf("expected error to implement UserMessager")
	}
	want := "domain quota reached (5 of 5)"
	if got := um.UserMessage(); got != want {
		t.Errorf("unexpected user message: got %q, want %q", got, want)
	}
}

func TestDomainInUseError(t *testing.T) {
	tests := []struct {
		name     string
		versions []ServiceVersionRef
		retired  bool
		active   bool
		want     string
	}{
		{
			name:     "retired domain is not told to retire",
			versions: []ServiceVersionRef{{Service: "svc", Version: 3}},
			retired:  true,
			want:     `cannot delete "example.se": used by svc version 3`,
		},
		{
			name:     "domain used by an active version is not told to retire",
			versions: []ServiceVersionRef{{Service: "svc", Version: 3}},
			active:   true,
			want:     `cannot delete "example.se": used by svc version 3`,
		},
		{
			name: "multiple services",
			versions: []ServiceVersionRef{
				{Service: "org1-service1", Version: 1},
				{Service: "org1-service1", Version: 3},
				{Service: "org1-service2", Version: 2},
			},
			want: `cannot delete "example.se": used by org1-service1 versions 1, 3 and org1-service2 version 2, retire it instead`,
		},
		{
			name:     "single version",
			versions: []ServiceVersionRef{{Service: "svc", Version: 3}},
			want:     `cannot delete "example.se": used by svc version 3, retire it instead`,
		},
		{
			name: "services interleaved",
			versions: []ServiceVersionRef{
				{Service: "org1-service2", Version: 2},
				{Service: "org1-service1", Version: 1},
				{Service: "org1-service2", Version: 4},
			},
			want: `cannot delete "example.se": used by org1-service2 versions 2, 4 and org1-service1 version 1, retire it instead`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fmt.Errorf("wrapped: %w", &DomainInUseError{Domain: "example.se", Versions: tt.versions, Retired: tt.retired, Active: tt.active})

			inUse, ok := errors.AsType[*DomainInUseError](err)
			if !ok {
				t.Fatalf("expected error to be a DomainInUseError")
			}
			if got := inUse.Error(); got != tt.want {
				t.Errorf("unexpected error text: got %q, want %q", got, tt.want)
			}
			if got := inUse.UserMessage(); got != tt.want {
				t.Errorf("unexpected user message: got %q, want %q", got, tt.want)
			}
			if !errors.Is(err, ErrHasDependents) {
				t.Errorf("expected error to match ErrHasDependents")
			}
		})
	}
}

func TestDomainActiveError(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &DomainActiveError{Domain: "example.se", Services: []string{"svc-a", "svc-b"}})

	if !errors.Is(err, ErrHasDependents) {
		t.Errorf("expected error to match ErrHasDependents")
	}

	um, ok := errors.AsType[UserMessager](err)
	if !ok {
		t.Fatalf("expected error to implement UserMessager")
	}
	want := `cannot retire "example.se": used by the active version of svc-a and svc-b`
	if got := um.UserMessage(); got != want {
		t.Errorf("unexpected user message: got %q, want %q", got, want)
	}
}

func TestDomainsNotVerifiedError(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &DomainsNotVerifiedError{Domains: []string{"a.example", "b.example"}})

	if !errors.Is(err, ErrDomainNotVerified) {
		t.Errorf("expected error to match ErrDomainNotVerified")
	}

	um, ok := errors.AsType[UserMessager](err)
	if !ok {
		t.Fatalf("expected error to implement UserMessager")
	}
	want := "version uses domains that are not verified: a.example, b.example"
	if got := um.UserMessage(); got != want {
		t.Errorf("unexpected user message: got %q, want %q", got, want)
	}
}

func TestUnknownDomainError(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &UnknownDomainError{Domain: "example.se"})

	if !errors.Is(err, ErrUnknownDomain) {
		t.Errorf("expected error to match ErrUnknownDomain")
	}

	um, ok := errors.AsType[UserMessager](err)
	if !ok {
		t.Fatalf("expected error to implement UserMessager")
	}
	want := "unknown domain name: example.se"
	if got := um.UserMessage(); got != want {
		t.Errorf("unexpected user message: got %q, want %q", got, want)
	}
	if got := um.Error(); got != want {
		t.Errorf("unexpected error text: got %q, want %q", got, want)
	}
}

func TestUserMessages(t *testing.T) {
	if got := NewValidationError("bad vcl").(UserMessager).UserMessage(); got != "bad vcl" {
		t.Errorf("unexpected VCL validation user message: %q", got)
	}

	for _, err := range []error{
		&AddressConflictError{Address: "192.0.2.1"},
		&DuplicateOriginError{},
		&DependentsError{Name: "org1", Services: 2},
		&IPAllocationError{Family: "IPv4", Requested: 1},
	} {
		um, ok := err.(UserMessager)
		if !ok {
			t.Errorf("%T does not implement UserMessager", err)
			continue
		}
		if um.UserMessage() != err.Error() {
			t.Errorf("%T: user message %q differs from Error() %q", err, um.UserMessage(), err.Error())
		}
	}

	if _, ok := error(&LoginRateLimitedError{}).(UserMessager); ok {
		t.Errorf("LoginRateLimitedError must not implement UserMessager")
	}
}
