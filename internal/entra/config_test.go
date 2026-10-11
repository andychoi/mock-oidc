package entra

import "testing"

const tidA = "11111111-1111-1111-1111-111111111111"
const tidB = "22222222-2222-2222-2222-22222222abcd"

const validJSON = `{
  "basePath": "/entra/",
  "tenants": [
    {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"]},
    {"tid": "22222222-2222-2222-2222-22222222ABCD", "groupClaimFormat": "object_id", "groupLimit": 3}
  ],
  "consents": [{"clientId": "app", "tid": "11111111-1111-1111-1111-111111111111"}],
  "users": [
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "groups": ["G1"]},
    {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd", "oid": "AAAAAAAA-0000-0000-0000-000000000001"}
  ]
}`

func TestParseConfigDefaultsAndNormalization(t *testing.T) {
	c, err := ParseConfig([]byte(validJSON))
	if err != nil {
		t.Fatal(err)
	}
	if c.BasePath != "entra" || c.DefaultGroupLimit != 200 || c.TokenExpiry != 3600 {
		t.Fatalf("defaults: basePath=%q limit=%d expiry=%d", c.BasePath, c.DefaultGroupLimit, c.TokenExpiry)
	}
	corp := c.Tenant(tidA)
	if corp == nil || corp.GroupClaimFormat != FormatName || corp.GroupLimit != 200 || corp.Name != "Corp" {
		t.Fatalf("corp = %+v", corp)
	}
	cust := c.Tenant("22222222-2222-2222-2222-22222222ABCD") // lookup is case-insensitive
	if cust == nil || cust.TID != tidB || cust.GroupLimit != 3 || cust.Name != tidB {
		t.Fatalf("cust = %+v", cust)
	}
	jane := c.User(tidA, "jane")
	if jane == nil || jane.Name != "jane" || jane.OID != UUIDv5(oidNamespace, tidA+":jane") {
		t.Fatalf("jane = %+v", jane)
	}
	sam := c.User(tidB, "sam")
	if sam == nil || sam.OID != "aaaaaaaa-0000-0000-0000-000000000001" {
		t.Fatalf("sam = %+v", sam)
	}
	if c.User(tidA, "sam") != nil {
		t.Error("users are scoped to their tenant")
	}
	if got := len(c.UsersIn("")); got != 2 {
		t.Errorf("UsersIn(\"\") = %d, want 2", got)
	}
	if got := len(c.UsersIn(tidA)); got != 1 {
		t.Errorf("UsersIn(tidA) = %d, want 1", got)
	}
}

func TestParseConfigRejects(t *testing.T) {
	const one = `{"tid": "11111111-1111-1111-1111-111111111111"}`
	cases := map[string]string{
		"no tenants":          `{"tenants": []}`,
		"bad tid":             `{"tenants": [{"tid": "corp"}]}`,
		"duplicate tid":       `{"tenants": [` + one + `,` + one + `]}`,
		"bad basePath":        `{"basePath": "a/b", "tenants": [` + one + `]}`,
		"bad basePath chars":  `{"basePath": "en tra", "tenants": [` + one + `]}`,
		"bad group format":    `{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "groupClaimFormat": "guid"}]}`,
		"unknown field":       `{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "groupFormat": "name"}]}`,
		"consent unknown tid": `{"tenants": [` + one + `], "consents": [{"clientId": "a", "tid": "22222222-2222-2222-2222-222222222222"}]}`,
		"consent no client":   `{"tenants": [` + one + `], "consents": [{"tid": "11111111-1111-1111-1111-111111111111"}]}`,
		"missing username":    `{"tenants": [` + one + `], "users": [{"tid": "11111111-1111-1111-1111-111111111111"}]}`,
		"unknown user tid":    `{"tenants": [` + one + `], "users": [{"username": "x", "tid": "22222222-2222-2222-2222-222222222222"}]}`,
		"duplicate user":      `{"tenants": [` + one + `], "users": [{"username": "x", "tid": "11111111-1111-1111-1111-111111111111"}, {"username": "x", "tid": "11111111-1111-1111-1111-111111111111"}]}`,
		"bad error":           `{"tenants": [` + one + `], "users": [{"username": "x", "tid": "11111111-1111-1111-1111-111111111111", "error": "boom"}]}`,
		"bad user oid":        `{"tenants": [` + one + `], "users": [{"username": "x", "tid": "11111111-1111-1111-1111-111111111111", "oid": "not-a-guid"}]}`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(js)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

const profileJSON = `{
  "tenants": [
    {"tid": "11111111-1111-1111-1111-111111111111", "domains": ["corp.example"],
     "groups": [{"name": "AMS Engineers", "description": "Engineering", "securityEnabled": true}]}
  ],
  "apps": [{"clientId": "sync", "tid": "11111111-1111-1111-1111-111111111111", "roles": ["User.Read.All"]}],
  "users": [
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111",
     "givenName": "Jane", "surname": "Kim", "upn": "Jane@Corp.Example",
     "accountEnabled": false, "jobTitle": "Staff Engineer", "officeLocation": "Seoul",
     "businessPhones": ["+82-2-555-0100"], "mobilePhone": "+82-10-555-0101",
     "preferredLanguage": "en-US", "roles": ["Portal.Admin"],
     "wids": ["62E90394-69F5-4237-9190-012177145E10"], "groups": ["AMS Engineers"]},
    {"username": "sora", "tid": "11111111-1111-1111-1111-111111111111", "manager": "jane"}
  ]
}`

func TestUserProfileFieldsNormalize(t *testing.T) {
	c, err := ParseConfig([]byte(profileJSON))
	if err != nil {
		t.Fatal(err)
	}
	jane := c.User(tidA, "jane")
	if jane.UPN != "jane@corp.example" {
		t.Errorf("upn = %q, want lowercased", jane.UPN)
	}
	if jane.WIDs[0] != "62e90394-69f5-4237-9190-012177145e10" {
		t.Errorf("wids = %v, want lowercased", jane.WIDs)
	}
	if jane.GivenName != "Jane" || jane.Surname != "Kim" || jane.JobTitle != "Staff Engineer" ||
		jane.OfficeLocation != "Seoul" || jane.MobilePhone != "+82-10-555-0101" ||
		jane.PreferredLanguage != "en-US" || len(jane.BusinessPhones) != 1 || len(jane.Roles) != 1 {
		t.Errorf("profile = %+v", jane)
	}
	if jane.AccountEnabled == nil || *jane.AccountEnabled {
		t.Errorf("accountEnabled must round-trip false, got %v", jane.AccountEnabled)
	}
	if sora := c.User(tidA, "sora"); sora.AccountEnabled != nil {
		t.Errorf("an unset accountEnabled must stay nil, got %v", *sora.AccountEnabled)
	}
	if len(c.Apps) != 1 || c.Apps[0].ClientID != "sync" || c.Apps[0].Roles[0] != "User.Read.All" {
		t.Errorf("apps = %+v", c.Apps)
	}
}

func TestProfileAndGroupRejects(t *testing.T) {
	const one = `{"tid": "11111111-1111-1111-1111-111111111111"}`
	user := func(extra string) string {
		return `{"tenants": [` + one + `], "users": [{"username": "x",
			"tid": "11111111-1111-1111-1111-111111111111"` + extra + `}]}`
	}
	cases := map[string]string{
		"bad wid":         user(`, "wids": ["not-a-guid"]`),
		"unknown manager": user(`, "manager": "nobody"`),
		"self manager":    user(`, "manager": "x"`),
		"group no name":   `{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "groups": [{"description": "d"}]}]}`,
		"duplicate group": `{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "groups": [{"name": "G"}, {"name": "G"}]}]}`,
		"bad group oid":   `{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "groups": [{"name": "G", "oid": "nope"}]}]}`,
		"app no client":   `{"tenants": [` + one + `], "apps": [{"roles": ["a"]}]}`,
		"app unknown tid": `{"tenants": [` + one + `], "apps": [{"clientId": "a", "tid": "22222222-2222-2222-2222-222222222222"}]}`,
		"unknown profile": user(`, "given_name": "x"`),
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(js)); err == nil {
				t.Fatalf("expected an error for %s", js)
			}
		})
	}
}

// A manager reference must not survive its target's deletion as a dangling
// pointer, nor make the delete fail validation.
func TestManagerClearedWhenManagerDeleted(t *testing.T) {
	c, err := ParseConfig([]byte(profileJSON))
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore(c)
	if err := s.DeleteUser(tidA, "jane"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if got := s.Snapshot().User(tidA, "sora").Manager; got != "" {
		t.Errorf("manager = %q, want cleared", got)
	}
}

func TestStoreClonesProfileFields(t *testing.T) {
	c, err := ParseConfig([]byte(profileJSON))
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore(c)
	before := s.Snapshot()
	jane := *before.User(tidA, "jane")
	updated := jane
	updated.JobTitle = "Principal Engineer"
	updated.BusinessPhones = []string{"+82-2-555-0999"}
	updated.AccountEnabled = nil
	if err := s.UpdateUser(tidA, "jane", updated); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	after := s.Snapshot()
	if after.User(tidA, "jane").JobTitle != "Principal Engineer" {
		t.Error("the update did not publish")
	}
	// The previously published snapshot must be untouched.
	old := before.User(tidA, "jane")
	if old.JobTitle != "Staff Engineer" || old.BusinessPhones[0] != "+82-2-555-0100" ||
		old.AccountEnabled == nil || *old.AccountEnabled {
		t.Errorf("the earlier snapshot was mutated: %+v", old)
	}
	// Tenant group metadata and the graph block are copied, not shared.
	if before.Tenants[0].Groups[0].SecurityEnabled == after.Tenants[0].Groups[0].SecurityEnabled {
		t.Error("group flags share a pointer across snapshots")
	}
	if before.Graph == after.Graph {
		t.Error("the graph block is shared across snapshots")
	}
}
