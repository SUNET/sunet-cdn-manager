package cdntypes

import (
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

func mustUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	if err := id.Scan(s); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAuthDataMemberOf(t *testing.T) {
	orgA := mustUUID(t, "00000002-0000-0000-0000-00000000000a")
	orgB := mustUUID(t, "00000002-0000-0000-0000-00000000000b")
	orgC := mustUUID(t, "00000002-0000-0000-0000-00000000000c")

	member := AuthData{Orgs: []OrgRef{{ID: orgA, Name: "org-a"}, {ID: orgB, Name: "org-b"}}}
	if !member.MemberOf(orgA) {
		t.Error("member of A: got false")
	}
	if !member.MemberOf(orgB) {
		t.Error("member of B: got false")
	}
	if member.MemberOf(orgC) {
		t.Error("member of C: got true")
	}

	// Membership is not access: a superuser sees every org but is a
	// member of none here.
	superuser := AuthData{Superuser: true}
	if superuser.MemberOf(orgA) {
		t.Error("superuser without orgs, member of A: got true")
	}
}

func TestAuthDataOrgIDs(t *testing.T) {
	orgA := mustUUID(t, "00000002-0000-0000-0000-00000000000a")
	orgB := mustUUID(t, "00000002-0000-0000-0000-00000000000b")

	ad := AuthData{Orgs: []OrgRef{{ID: orgA, Name: "org-a"}, {ID: orgB, Name: "org-b"}}}
	if got, want := ad.OrgIDs(), []pgtype.UUID{orgA, orgB}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if got := (AuthData{}).OrgIDs(); len(got) != 0 {
		t.Errorf("no orgs: got %v, want empty", got)
	}
}
