package entra

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// orgJSONConfig models the org-chart scenario: an org code in
// extensionAttribute1, dynamic department groups, and a manager chain.
const orgJSONConfig = `{
  "tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "domains": ["corp.example"],
    "groups": [
      {"name": "GRP_DEPT_DEPT001_HRTeam", "membershipRule": "(user.extensionAttribute1 -eq \"DEPT001\")"},
      {"name": "GRP_DEPT_DEPT002_Finance", "membershipRule": "user.extensionAttribute1 -eq \"DEPT002\""},
      {"name": "GRP_REPORTS_boss", "membershipRule": "Direct Reports for \"00000000-0000-0000-0000-0000000000b0\""},
      {"name": "Static Team"}
    ]}],
  "apps": [{"clientId": "iam", "claims": [
    {"name": "org_code", "source": "user.extensionAttribute1"},
    {"name": "department", "source": "user.department"}]}],
  "users": [
    {"username": "boss", "tid": "11111111-1111-1111-1111-111111111111", "oid": "00000000-0000-0000-0000-0000000000b0",
     "upn": "boss@corp.example"},
    {"username": "hana", "tid": "11111111-1111-1111-1111-111111111111", "department": "HR",
     "manager": "BOSS@corp.example", "groups": ["Static Team"],
     "onPremisesExtensionAttributes": {"extensionAttribute1": "DEPT001"}},
    {"username": "finn", "tid": "11111111-1111-1111-1111-111111111111", "department": "Finance",
     "manager": "00000000-0000-0000-0000-0000000000B0",
     "onPremisesExtensionAttributes": {"extensionAttribute1": "DEPT002"}}
  ]
}`

func orgConfig(t *testing.T) *Config {
	t.Helper()
	c, err := ParseConfig([]byte(orgJSONConfig))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestManagerResolvesByOIDOrUPN(t *testing.T) {
	c := orgConfig(t)
	for _, name := range []string{"hana", "finn"} {
		if got := c.User(tidA, name).Manager; got != "boss" {
			t.Errorf("%s manager = %q, want boss (canonical username)", name, got)
		}
	}
}

func TestDynamicGroupMembership(t *testing.T) {
	c := orgConfig(t)
	hana, finn := c.User(tidA, "hana"), c.User(tidA, "finn")
	if got, want := hana.MemberGroups(), []string{"Static Team", "GRP_DEPT_DEPT001_HRTeam", "GRP_REPORTS_boss"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hana groups = %v, want %v", got, want)
	}
	if got, want := finn.DynamicGroups(), []string{"GRP_DEPT_DEPT002_Finance", "GRP_REPORTS_boss"}; !reflect.DeepEqual(got, want) {
		t.Errorf("finn dynamic groups = %v, want %v", got, want)
	}
	if got := c.User(tidA, "boss").MemberGroups(); len(got) != 0 {
		t.Errorf("boss groups = %v, want none", got)
	}
	g := c.GroupByID(tidA, "GRP_DEPT_DEPT001_HRTeam")
	if g == nil {
		t.Fatal("dynamic group not in the directory")
	}
	members := c.MembersOf(tidA, g.OID)
	if len(members) != 1 || members[0].Username != "hana" {
		t.Errorf("HR members = %v", members)
	}
}

func TestOrgConfigRejects(t *testing.T) {
	const ten = `{"tid": "11111111-1111-1111-1111-111111111111", "groups": [{"name": "Dyn", "membershipRule": "user.department -eq \"HR\""}]}`
	cases := map[string]string{
		"extension attribute 4": `{"tenants": [` + ten + `], "users": [{"username": "u", "tid": "11111111-1111-1111-1111-111111111111",
			"onPremisesExtensionAttributes": {"extensionAttribute4": "x"}}]}`,
		"static member of a dynamic group": `{"tenants": [` + ten + `], "users": [{"username": "u", "tid": "11111111-1111-1111-1111-111111111111",
			"groups": ["Dyn"]}]}`,
		"bad rule":         `{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "groups": [{"name": "D", "membershipRule": "user.nope -eq \"x\""}]}]}`,
		"reserved claim":   `{"tenants": [` + ten + `], "apps": [{"clientId": "a", "claims": [{"name": "groups", "source": "user.department"}]}]}`,
		"bad claim source": `{"tenants": [` + ten + `], "apps": [{"clientId": "a", "claims": [{"name": "x", "source": "user.manager"}]}]}`,
		"duplicate claim": `{"tenants": [` + ten + `], "apps": [{"clientId": "a", "claims": [{"name": "x", "source": "user.department"},
			{"name": "x", "source": "user.jobTitle"}]}]}`,
		"unknown manager oid": `{"tenants": [` + ten + `], "users": [{"username": "u", "tid": "11111111-1111-1111-1111-111111111111",
			"manager": "00000000-0000-0000-0000-000000000999"}]}`,
	}
	for name, cfg := range cases {
		if _, err := ParseConfig([]byte(cfg)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err := ParseConfig([]byte(cases["static member of a dynamic group"]))
	if err == nil || !strings.Contains(err.Error(), "is dynamic") {
		t.Errorf("static member error = %v", err)
	}
}

// Changing an org code through the Store moves the user between dynamic
// groups on the next snapshot: the HR-transfer case.
func TestStoreUpdateMovesDynamicMembership(t *testing.T) {
	s := NewStore(orgConfig(t))
	hana := *s.Snapshot().User(tidA, "hana")
	hana.ExtensionAttributes.ExtensionAttribute1 = "DEPT002"
	if err := s.UpdateUser(tidA, "hana", hana); err != nil {
		t.Fatal(err)
	}
	got := s.Snapshot().User(tidA, "hana").DynamicGroups()
	if want := []string{"GRP_DEPT_DEPT002_Finance", "GRP_REPORTS_boss"}; !reflect.DeepEqual(got, want) {
		t.Errorf("after transfer = %v, want %v", got, want)
	}
	s.Reset()
	if got := s.Snapshot().User(tidA, "hana").DynamicGroups(); got[0] != "GRP_DEPT_DEPT001_HRTeam" {
		t.Errorf("after reset = %v", got)
	}
	// Deleting the manager empties the Direct Reports group.
	if err := s.DeleteUser(tidA, "boss"); err != nil {
		t.Fatal(err)
	}
	if got := s.Snapshot().User(tidA, "finn").DynamicGroups(); !reflect.DeepEqual(got, []string{"GRP_DEPT_DEPT002_Finance"}) {
		t.Errorf("after manager delete = %v", got)
	}
}

// The shipped demo config showcases the org-chart scenario in its own tenant.
func TestEntraDemoOrgChartTenant(t *testing.T) {
	data, err := os.ReadFile("../../entra-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	const org = "44444444-4444-4444-4444-444444444444"
	want := map[string][]string{
		"ceo":     nil,
		"hrlead":  {"GRP_DEPT_DEPT001_HRTeam", "GRP_REPORTS_CEO"},
		"hrstaff": {"GRP_DEPT_DEPT001_HRTeam"},
		"finlead": {"GRP_DEPT_DEPT002_Finance", "GRP_REPORTS_CEO"},
	}
	for name, groups := range want {
		u := c.User(org, name)
		if u == nil {
			t.Fatalf("demo user %s missing", name)
		}
		if got := u.DynamicGroups(); !reflect.DeepEqual(got, groups) {
			t.Errorf("%s dynamic groups = %v, want %v", name, got, groups)
		}
	}
	if got := c.MappedClaims("iam", c.User(org, "hrstaff")); got["org_code"] != "DEPT001" || got["department"] != "HR" {
		t.Errorf("mapped claims = %v", got)
	}
}
