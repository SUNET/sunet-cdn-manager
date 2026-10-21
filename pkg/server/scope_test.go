package server

import (
	"context"
	"errors"
	"testing"

	"github.com/SUNET/sunet-cdn-manager/pkg/cdnerrors"
	"github.com/SUNET/sunet-cdn-manager/pkg/cdntypes"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	scopeTestOrg1ID         = "00000002-0000-0000-0000-000000000001"
	scopeTestOrg2ID         = "00000002-0000-0000-0000-000000000002"
	scopeTestOrg1Service1ID = "00000003-0000-0000-0000-000000000001"
	scopeTestOrg2Service1ID = "00000003-0000-0000-0000-000000000004"
	// Valid UUID that matches no org and no service in the seed data.
	scopeTestUnknownID = "00000009-0000-0000-0000-0000000000ff"
)

func scopeTestOrg1Member(t *testing.T) cdntypes.AuthData {
	t.Helper()
	var orgID pgtype.UUID
	if err := orgID.Scan(scopeTestOrg1ID); err != nil {
		t.Fatal(err)
	}
	orgName := "org1"
	return cdntypes.AuthData{OrgID: &orgID, OrgName: &orgName}
}

func TestResolveOrg(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	member := scopeTestOrg1Member(t)
	superuser := cdntypes.AuthData{Superuser: true}

	resolve := func(t *testing.T, ad cdntypes.AuthData, input string) (orgIdentifier, error) {
		t.Helper()
		var oi orgIdentifier
		var resolveErr error
		err := pgx.BeginFunc(ctx, dbPool, func(tx pgx.Tx) error {
			oi, resolveErr = resolveOrg(ctx, tx, ad, input, lockShare)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return oi, resolveErr
	}

	okTests := []struct {
		description string
		ad          cdntypes.AuthData
		input       string
	}{
		{description: "member resolves own org by name", ad: member, input: "org1"},
		{description: "member resolves own org by UUID", ad: member, input: scopeTestOrg1ID},
		{description: "superuser resolves any org by name", ad: superuser, input: "org2"},
		{description: "superuser resolves any org by UUID", ad: superuser, input: scopeTestOrg2ID},
	}

	for _, test := range okTests {
		t.Run(test.description, func(t *testing.T) {
			oi, err := resolve(t, test.ad, test.input)
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if oi.name != test.input && oi.id.String() != test.input {
				t.Fatalf("resolved %q/%s, which does not match input %q", oi.name, oi.id.String(), test.input)
			}
		})
	}

	t.Run("member cannot tell out of scope from unknown", func(t *testing.T) {
		var msgs []string
		for _, input := range []string{"org2", scopeTestOrg2ID, "nonexistent-org", scopeTestUnknownID} {
			_, err := resolve(t, member, input)
			if !errors.Is(err, cdnerrors.ErrNotFound) {
				t.Fatalf("input %q: expected ErrNotFound, got %v", input, err)
			}
			msgs = append(msgs, err.Error())
		}
		for i, msg := range msgs[1:] {
			if msg != msgs[0] {
				t.Errorf("error %d differs from the first: %q vs %q", i+1, msg, msgs[0])
			}
		}
	})

	t.Run("superuser gets not found for unknown org", func(t *testing.T) {
		_, err := resolve(t, superuser, "nonexistent-org")
		if !errors.Is(err, cdnerrors.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	// The remaining cases are decided before any query, so a nil tx proves
	// the database is never touched: using it would panic.
	noDBTests := []struct {
		description string
		ad          cdntypes.AuthData
		input       string
		expected    error
	}{
		{description: "no access, existing org", ad: cdntypes.AuthData{}, input: "org1", expected: cdnerrors.ErrForbidden},
		{description: "no access, nonexistent org", ad: cdntypes.AuthData{}, input: "nonexistent-org", expected: cdnerrors.ErrForbidden},
		{description: "no access, malformed input", ad: cdntypes.AuthData{}, input: "Not_A_Label!", expected: cdnerrors.ErrForbidden},
		{description: "member, empty input", ad: member, input: "", expected: cdnerrors.ErrUnableToParseNameOrID},
		{description: "member, malformed name", ad: member, input: "Not_A_Label!", expected: cdnerrors.ErrUnableToParseNameOrID},
		{description: "superuser, empty input", ad: superuser, input: "", expected: cdnerrors.ErrUnableToParseNameOrID},
		{description: "superuser, malformed name", ad: superuser, input: "Not_A_Label!", expected: cdnerrors.ErrUnableToParseNameOrID},
	}

	for _, test := range noDBTests {
		t.Run(test.description, func(t *testing.T) {
			_, err := resolveOrg(ctx, nil, test.ad, test.input, lockShare)
			if !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
		})
	}
}

func TestResolveService(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	member := scopeTestOrg1Member(t)
	superuser := cdntypes.AuthData{Superuser: true}

	resolve := func(t *testing.T, ad cdntypes.AuthData, serviceInput string, orgInput string) (serviceIdentifier, error) {
		t.Helper()
		var si serviceIdentifier
		var resolveErr error
		err := pgx.BeginFunc(ctx, dbPool, func(tx pgx.Tx) error {
			si, resolveErr = resolveService(ctx, tx, ad, serviceInput, orgInput, lockShare)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return si, resolveErr
	}

	okTests := []struct {
		description  string
		ad           cdntypes.AuthData
		serviceInput string
		orgInput     string
		expectedID   string
		expectedOrg  string
	}{
		{description: "member, own service by name in own org", ad: member, serviceInput: "org1-service1", orgInput: "org1", expectedID: scopeTestOrg1Service1ID, expectedOrg: scopeTestOrg1ID},
		{description: "member, own service by UUID without org", ad: member, serviceInput: scopeTestOrg1Service1ID, expectedID: scopeTestOrg1Service1ID, expectedOrg: scopeTestOrg1ID},
		{description: "member, own service by UUID in own org", ad: member, serviceInput: scopeTestOrg1Service1ID, orgInput: scopeTestOrg1ID, expectedID: scopeTestOrg1Service1ID, expectedOrg: scopeTestOrg1ID},
		{description: "superuser, any service by UUID without org", ad: superuser, serviceInput: scopeTestOrg2Service1ID, expectedID: scopeTestOrg2Service1ID, expectedOrg: scopeTestOrg2ID},
		{description: "superuser, any service by name", ad: superuser, serviceInput: "org2-service1", orgInput: "org2", expectedID: scopeTestOrg2Service1ID, expectedOrg: scopeTestOrg2ID},
	}

	for _, test := range okTests {
		t.Run(test.description, func(t *testing.T) {
			si, err := resolve(t, test.ad, test.serviceInput, test.orgInput)
			if err != nil {
				t.Fatalf("expected success, got %v", err)
			}
			if si.id.String() != test.expectedID {
				t.Errorf("expected service %s, got %s", test.expectedID, si.id.String())
			}
			if si.orgID.String() != test.expectedOrg {
				t.Errorf("expected org %s, got %s", test.expectedOrg, si.orgID.String())
			}
		})
	}

	t.Run("member cannot tell out of scope from unknown", func(t *testing.T) {
		inputs := []struct {
			service string
			org     string
		}{
			{service: scopeTestOrg2Service1ID},
			{service: scopeTestUnknownID},
			// The UUID exists, but not in the org the caller named.
			{service: scopeTestOrg2Service1ID, org: "org1"},
			{service: "org2-service1", org: "org2"},
			{service: "org2-service1", org: scopeTestOrg2ID},
			{service: "nonexistent-service", org: "org1"},
			{service: "org1-service1", org: "nonexistent-org"},
		}
		var msgs []string
		for _, input := range inputs {
			_, err := resolve(t, member, input.service, input.org)
			if !errors.Is(err, cdnerrors.ErrNotFound) {
				t.Fatalf("input %q in org %q: expected ErrNotFound, got %v", input.service, input.org, err)
			}
			msgs = append(msgs, err.Error())
		}
		for i, msg := range msgs[1:] {
			if msg != msgs[0] {
				t.Errorf("error %d differs from the first: %q vs %q", i+1, msg, msgs[0])
			}
		}
	})

	t.Run("superuser gets not found for unknown service", func(t *testing.T) {
		_, err := resolve(t, superuser, scopeTestUnknownID, "")
		if !errors.Is(err, cdnerrors.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	// Decided before any query; a nil tx would panic if it were used.
	noDBTests := []struct {
		description  string
		ad           cdntypes.AuthData
		serviceInput string
		orgInput     string
		expected     error
	}{
		{description: "no access, by UUID", ad: cdntypes.AuthData{}, serviceInput: scopeTestOrg1Service1ID, expected: cdnerrors.ErrForbidden},
		{description: "no access, nonexistent name", ad: cdntypes.AuthData{}, serviceInput: "nonexistent-service", orgInput: "nonexistent-org", expected: cdnerrors.ErrForbidden},
		{description: "member, empty service", ad: member, serviceInput: "", orgInput: "org1", expected: cdnerrors.ErrUnableToParseNameOrID},
		{description: "member, malformed service name", ad: member, serviceInput: "Not_A_Label!", orgInput: "org1", expected: cdnerrors.ErrUnableToParseNameOrID},
		{description: "member, malformed org name", ad: member, serviceInput: "org1-service1", orgInput: "Not_A_Label!", expected: cdnerrors.ErrUnableToParseNameOrID},
		{description: "member, name without org", ad: member, serviceInput: "org1-service1", expected: cdnerrors.ErrUnableToParseNameOrID},
		{description: "superuser, name without org", ad: superuser, serviceInput: "org1-service1", expected: cdnerrors.ErrUnableToParseNameOrID},
	}

	for _, test := range noDBTests {
		t.Run(test.description, func(t *testing.T) {
			_, err := resolveService(ctx, nil, test.ad, test.serviceInput, test.orgInput, lockShare)
			if !errors.Is(err, test.expected) {
				t.Fatalf("expected %v, got %v", test.expected, err)
			}
		})
	}
}

// TestServiceVersionCloneDataRechecksService moves a service to another org
// after its ids were resolved. The clone read must not return the config to
// a caller holding the ids from before the move.
func TestServiceVersionCloneDataRechecksService(t *testing.T) {
	ts, dbPool, err := prepareServer(t, testServerInput{})
	if dbPool != nil {
		defer dbPool.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()

	ctx := context.Background()

	var orgID, serviceID pgtype.UUID
	if err := orgID.Scan(scopeTestOrg1ID); err != nil {
		t.Fatal(err)
	}
	if err := serviceID.Scan(scopeTestOrg1Service1ID); err != nil {
		t.Fatal(err)
	}

	member := scopeTestOrg1Member(t)
	superuser := cdntypes.AuthData{Superuser: true}

	cloneData := func(t *testing.T, ad cdntypes.AuthData) error {
		t.Helper()
		return pgx.BeginFunc(ctx, dbPool, func(tx pgx.Tx) error {
			_, err := getServiceVersionCloneData(ctx, tx, ad, orgID, serviceID, 1)
			return err
		})
	}

	if err := cloneData(t, member); err != nil {
		t.Fatalf("clone before the move: %v", err)
	}

	_, err = dbPool.Exec(ctx, "UPDATE services SET org_id = $1 WHERE id = $2", scopeTestOrg2ID, scopeTestOrg1Service1ID)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		description string
		ad          cdntypes.AuthData
	}{
		{description: "member of the old org", ad: member},
		{description: "superuser with the old org", ad: superuser},
	} {
		t.Run(test.description, func(t *testing.T) {
			if err := cloneData(t, test.ad); !errors.Is(err, cdnerrors.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
		})
	}
}
