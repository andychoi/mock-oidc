package entra

import (
	"reflect"
	"testing"
)

const dirJSON = `{
  "tenants": [
    {"tid": "11111111-1111-1111-1111-111111111111", "domains": ["corp.example"],
     "groups": [{"name": "AMS Engineers", "description": "Engineering",
                 "mailNickname": "ams-eng", "mail": "ams@corp.example",
                 "securityEnabled": false, "mailEnabled": true},
                {"name": "Declared Only"}]},
    {"tid": "22222222-2222-2222-2222-22222222abcd", "domains": ["customer-x.example"]}
  ],
  "users": [
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111",
     "upn": "jane@corp.example", "groups": ["AMS Engineers", "PMO"]},
    {"username": "sora", "tid": "11111111-1111-1111-1111-111111111111",
     "email": "sora@corp.example", "manager": "jane", "groups": ["PMO"]},
    {"username": "off", "tid": "11111111-1111-1111-1111-111111111111", "accountEnabled": false},
    {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd", "groups": ["PMO"]}
  ]
}`

func dirConfig(t *testing.T) *Config {
	t.Helper()
	c, err := ParseConfig([]byte(dirJSON))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func groupNames(gs []DirGroup) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Name)
	}
	return out
}

func TestGroupsInUnionOfDeclaredAndUsed(t *testing.T) {
	c := dirConfig(t)
	got := c.GroupsIn(tidA)
	if len(got) != 3 {
		t.Fatalf("groups = %v, want AMS Engineers, Declared Only and PMO", groupNames(got))
	}
	var ams, pmo, declared DirGroup
	for _, g := range got {
		switch g.Name {
		case "AMS Engineers":
			ams = g
		case "PMO":
			pmo = g
		case "Declared Only":
			declared = g
		}
	}
	// Declared metadata wins over the derived defaults.
	if ams.Description != "Engineering" || ams.MailNickname != "ams-eng" ||
		ams.Mail != "ams@corp.example" || ams.SecurityEnabled || !ams.MailEnabled {
		t.Errorf("declared group = %+v", ams)
	}
	// A name only a user uses still becomes a group, with derived defaults.
	if pmo.Description != "" || pmo.MailNickname != "pmo" || !pmo.SecurityEnabled || pmo.MailEnabled {
		t.Errorf("derived group = %+v", pmo)
	}
	// A declared group with no members still exists.
	if declared.OID != GroupObjectID(tidA, "Declared Only") {
		t.Errorf("declared-only group = %+v", declared)
	}
	// Ordered by object ID, so offset paging is stable.
	for i := 1; i < len(got); i++ {
		if got[i-1].OID >= got[i].OID {
			t.Fatalf("groups are not ordered by OID: %v", got)
		}
	}
}

// The object ID a Graph group carries must be the value an "object_id" group
// claim already puts in the token, or an RP cannot match one to the other.
func TestGroupIDMatchesGroupClaim(t *testing.T) {
	c := dirConfig(t)
	tn := *c.Tenant(tidA)
	tn.GroupClaimFormat = FormatObjectID
	jane := c.User(tidA, "jane")
	claims := IDTokenClaims(TokenInput{Origin: "http://h:1", BasePath: "entra", Tenant: &tn,
		User: jane, ClientID: "app", Expiry: 3600})
	want := claims["groups"].([]string)
	got := c.GroupIDsOf(jane)
	if len(got) != len(want) {
		t.Fatalf("group ids = %v, claim = %v", got, want)
	}
	for _, id := range want {
		found := false
		for _, g := range got {
			if g == id {
				found = true
			}
		}
		if !found {
			t.Errorf("claim group %s is not a Graph group id (%v)", id, got)
		}
	}
}

func TestGroupLookupByIDAndDisplayName(t *testing.T) {
	c := dirConfig(t)
	id := GroupObjectID(tidA, "PMO")
	byID := c.GroupByID(tidA, id)
	byName := c.GroupByID(tidA, "PMO")
	if byID == nil || byName == nil || byID.OID != byName.OID {
		t.Fatalf("byID=%v byName=%v", byID, byName)
	}
	if c.GroupByID(tidA, "nope") != nil || c.GroupByID(tidA, "") != nil {
		t.Error("unknown group must not resolve")
	}
}

// A group name shared by two tenants is two distinct groups with disjoint
// members: Graph must never leak across the tenant boundary.
func TestGroupsAreTenantScoped(t *testing.T) {
	c := dirConfig(t)
	corp := c.GroupByID(tidA, "PMO")
	cust := c.GroupByID(tidB, "PMO")
	if corp == nil || cust == nil || corp.OID == cust.OID {
		t.Fatalf("corp=%v cust=%v", corp, cust)
	}
	if c.GroupByID(tidB, corp.OID) != nil {
		t.Error("a group id must not resolve in another tenant")
	}
	members := c.MembersOf(tidA, "PMO")
	if len(members) != 2 {
		t.Fatalf("corp PMO members = %d, want jane and sora", len(members))
	}
	for _, u := range members {
		if u.TID != tidA {
			t.Errorf("member %s is from tenant %s", u.Username, u.TID)
		}
	}
	if got := len(c.MembersOf(tidB, "PMO")); got != 1 {
		t.Errorf("customer PMO members = %d, want sam", got)
	}
}

func TestMembersOfOrdering(t *testing.T) {
	c := dirConfig(t)
	members := c.MembersOf(tidA, "PMO")
	for i := 1; i < len(members); i++ {
		if members[i-1].OID >= members[i].OID {
			t.Fatalf("members are not ordered by OID")
		}
	}
	if c.MembersOf(tidA, "nope") != nil {
		t.Error("unknown group must have no members")
	}
}

func TestUserByUPNOrOIDAcceptsBoth(t *testing.T) {
	c := dirConfig(t)
	jane := c.User(tidA, "jane")
	for _, key := range []string{jane.OID, "jane@corp.example", "JANE@CORP.EXAMPLE", "jane"} {
		if got := c.UserByUPNOrOID(tidA, key); got == nil || got.Username != "jane" {
			t.Errorf("UserByUPNOrOID(%q) = %v", key, got)
		}
	}
	// A user without an explicit upn is still reachable by the derived one.
	if got := c.UserByUPNOrOID(tidA, "sora@corp.example"); got == nil || got.Username != "sora" {
		t.Errorf("derived UPN lookup = %v", got)
	}
	if c.UserByUPNOrOID(tidA, jane.OID[:8]) != nil || c.UserByUPNOrOID(tidB, jane.OID) != nil {
		t.Error("partial ids and cross-tenant ids must not resolve")
	}
}

func TestManagerAndDirectReports(t *testing.T) {
	c := dirConfig(t)
	jane, sora := c.User(tidA, "jane"), c.User(tidA, "sora")
	if m := c.ManagerOf(sora); m == nil || m.Username != "jane" {
		t.Errorf("manager of sora = %v", m)
	}
	if c.ManagerOf(jane) != nil {
		t.Error("jane has no manager")
	}
	reports := c.DirectReports(jane)
	if len(reports) != 1 || reports[0].Username != "sora" {
		t.Errorf("direct reports = %v", reports)
	}
	if got := c.DirectReports(sora); len(got) != 0 {
		t.Errorf("sora has no reports, got %v", got)
	}
}

func TestEnabledDefaultsTrue(t *testing.T) {
	c := dirConfig(t)
	if !c.User(tidA, "jane").Enabled() {
		t.Error("an unset accountEnabled means enabled")
	}
	if c.User(tidA, "off").Enabled() {
		t.Error("accountEnabled false must disable")
	}
}

func TestPrincipalNameFallsBackToPreferredUsername(t *testing.T) {
	c := dirConfig(t)
	tn := c.Tenant(tidA)
	cases := map[string]string{
		"jane": "jane@corp.example", // explicit upn
		"sora": "sora@corp.example", // email
		"off":  "off@corp.example",  // username@first domain
	}
	for username, want := range cases {
		u := c.User(tidA, username)
		if got := u.PrincipalName(tn); got != want {
			t.Errorf("%s PrincipalName = %q, want %q", username, got, want)
		}
		if username != "jane" && u.PrincipalName(tn) != preferredUsername(tn, u) {
			t.Errorf("%s must match the preferred_username rule", username)
		}
	}
}

func TestMailNickname(t *testing.T) {
	cases := map[string]string{"AMS Engineers": "amsengineers", "G-1": "g1", "": ""}
	for in, want := range cases {
		if got := mailNickname(in); got != want {
			t.Errorf("mailNickname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUsersOrderedInIsStable(t *testing.T) {
	c := dirConfig(t)
	first := c.UsersOrderedIn(tidA)
	second := c.UsersOrderedIn(tidA)
	if !reflect.DeepEqual(first, second) {
		t.Error("ordering must be stable across calls")
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].OID >= first[i].OID {
			t.Fatalf("users are not ordered by OID")
		}
	}
}
