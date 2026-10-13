package entra

import (
	"strings"
	"testing"
)

const ruleJSONConfig = `{
  "tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "domains": ["corp.example"]}],
  "users": [
    {"username": "boss", "tid": "11111111-1111-1111-1111-111111111111", "oid": "00000000-0000-0000-0000-0000000000b0",
     "department": "Executive"},
    {"username": "hana", "tid": "11111111-1111-1111-1111-111111111111", "name": "Hana Yoon",
     "email": "hana@corp.example", "department": "HR", "companyName": "Corp", "employeeId": "E100",
     "jobTitle": "HR Partner", "officeLocation": "Seoul", "manager": "boss",
     "onPremisesExtensionAttributes": {"extensionAttribute1": "DEPT001", "extensionAttribute2": "L3"}},
    {"username": "off", "tid": "11111111-1111-1111-1111-111111111111", "accountEnabled": false}
  ]
}`

func ruleFixture(t *testing.T) (*Config, *Tenant) {
	t.Helper()
	c, err := ParseConfig([]byte(ruleJSONConfig))
	if err != nil {
		t.Fatal(err)
	}
	return c, c.Tenant(tidA)
}

func TestRuleMatches(t *testing.T) {
	c, ten := ruleFixture(t)
	hana, boss, off := c.User(tidA, "hana"), c.User(tidA, "boss"), c.User(tidA, "off")
	cases := []struct {
		rule string
		want map[*User]bool
	}{
		{`user.extensionAttribute1 -eq "DEPT001"`, map[*User]bool{hana: true}},
		{`(user.extensionAttribute1 -eq "dept001")`, map[*User]bool{hana: true}}, // values are case-insensitive
		{`user.Department -eq "hr"`, map[*User]bool{hana: true}},                 // so are property names
		{`user.department -ne "HR"`, map[*User]bool{boss: true, off: true}},
		{`user.department -eq null`, map[*User]bool{off: true}},
		{`user.department -ne null`, map[*User]bool{hana: true, boss: true}},
		{`user.employeeId -startsWith "e1"`, map[*User]bool{hana: true}},
		{`user.employeeId -notStartsWith "E1"`, map[*User]bool{boss: true, off: true}},
		{`user.jobTitle -contains "partner"`, map[*User]bool{hana: true}},
		{`user.jobTitle -notContains "partner"`, map[*User]bool{boss: true, off: true}},
		{`user.department -in ["HR", "Finance"]`, map[*User]bool{hana: true}},
		{`user.department -notIn ["HR", "Executive"]`, map[*User]bool{off: true}},
		{`user.accountEnabled -eq false`, map[*User]bool{off: true}},
		{`(user.department -eq "HR") -and (user.extensionAttribute2 -eq "L3")`, map[*User]bool{hana: true}},
		{`user.department -eq "HR" -or user.department -eq "Executive"`, map[*User]bool{hana: true, boss: true}},
		{`-not (user.accountEnabled -eq true)`, map[*User]bool{off: true}},
		{`user.companyName -eq "Corp" -and user.officeLocation -eq "Seoul" -and user.mail -eq "HANA@corp.example"`, map[*User]bool{hana: true}},
		{`user.userPrincipalName -startsWith "hana@"`, map[*User]bool{hana: true}},
		{`user.displayName -eq "Hana Yoon"`, map[*User]bool{hana: true}},
		{`user.extensionAttribute3 -eq null`, map[*User]bool{hana: true, boss: true, off: true}},
		{`Direct Reports for "00000000-0000-0000-0000-0000000000B0"`, map[*User]bool{hana: true}},
		{`user.department -eq "Say \"hi\""`, map[*User]bool{}},
	}
	for _, tc := range cases {
		r, err := parseRule(tc.rule)
		if err != nil {
			t.Errorf("%s: %v", tc.rule, err)
			continue
		}
		for _, u := range []*User{hana, boss, off} {
			if got := r.match(c, ten, u); got != tc.want[u] {
				t.Errorf("%s on %s = %v, want %v", tc.rule, u.Username, got, tc.want[u])
			}
		}
	}
}

func TestRuleParseErrors(t *testing.T) {
	cases := map[string]string{
		`user.extensionAttribute4 -eq "x"`:  "unsupported property",
		`device.displayName -eq "x"`:        "unsupported property",
		`user.department -match "^H"`:       "unsupported operator",
		`user.department -eq`:               "expected a value",
		`user.department "HR"`:              "expected an operator",
		`(user.department -eq "HR"`:         "expected )",
		`user.department -eq "HR" trailing`: "unexpected",
		`user.department -in "HR"`:          "-in needs an array",
		`user.department -startsWith null`:  "needs a string",
		`user.accountEnabled -eq "yes"`:     "true or false",
		`user.accountEnabled -contains "x"`: "only supports -eq and -ne",
		`user.department -eq "unterminated`: "unterminated string",
		`Direct Reports for "not-a-guid"`:   "GUID",
		`user.department -in ["HR", null]`:  "strings",
		``:                                  "empty",
	}
	for rule, want := range cases {
		_, err := parseRule(rule)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("parseRule(%q) = %v, want error containing %q", rule, err, want)
		}
	}
}
