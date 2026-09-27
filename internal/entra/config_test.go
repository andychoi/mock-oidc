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
