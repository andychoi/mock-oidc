package e2e

import (
	"net/http"
	"net/url"
	"testing"
)

// entraOrgConfig is the org-chart scenario: an org code in extensionAttribute1,
// dynamic department groups named by rule, a manager chain, and the org code
// mapped into the iam app's ID token.
const entraOrgConfig = `{
  "interactiveLogin": true,
  "entra": {
    "tenants": [
      {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"],
       "groups": [
         {"name": "GRP_DEPT_DEPT001_HRTeam", "membershipRule": "(user.extensionAttribute1 -eq \"DEPT001\")"},
         {"name": "GRP_DEPT_DEPT002_Finance", "membershipRule": "(user.extensionAttribute1 -eq \"DEPT002\")"}
       ]}
    ],
    "apps": [{"clientId": "iam", "claims": [{"name": "org_code", "source": "user.extensionAttribute1"}]}],
    "users": [
      {"username": "boss", "tid": "11111111-1111-1111-1111-111111111111", "name": "Boss Kang",
       "email": "boss@corp.example"},
      {"username": "hana", "tid": "11111111-1111-1111-1111-111111111111", "name": "Hana Yoon",
       "email": "hana@corp.example", "manager": "boss@corp.example", "department": "HR",
       "onPremisesExtensionAttributes": {"extensionAttribute1": "DEPT001"}}
    ]
  }
}`

func claimGroups(t *testing.T, claims map[string]any) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	raw, _ := claims["groups"].([]any)
	for _, g := range raw {
		out[g.(string)] = true
	}
	return out
}

func TestGraphEndToEndOrgChart(t *testing.T) {
	_, base := startServer(t, entraOrgConfig)
	graph := base + "/entra/graph/v1.0"
	at, id := entraAccessToken(t, base, tidCorp, tidCorp, "hana")

	// The token: dynamic membership in groups, the org code as a mapped claim.
	if !claimGroups(t, id)["GRP_DEPT_DEPT001_HRTeam"] || id["org_code"] != "DEPT001" {
		t.Fatalf("ID token groups=%v org_code=%v", id["groups"], id["org_code"])
	}

	// Graph agrees with the token: the department groups by naming rule...
	status, _, groups := graphCall(t, http.MethodGet,
		graph+"/groups?$filter="+url.QueryEscape("startsWith(displayName,'GRP_DEPT_')"), at, "")
	if status != http.StatusOK || len(groups["value"].([]any)) != 2 {
		t.Fatalf("groups: %d %v", status, groups)
	}
	var hrID string
	for _, g := range groups["value"].([]any) {
		if g := g.(map[string]any); g["displayName"] == "GRP_DEPT_DEPT001_HRTeam" {
			hrID = g["id"].(string)
		}
	}
	// ...whose members are computed from the rule...
	_, _, members := graphCall(t, http.MethodGet, graph+"/groups/"+hrID+"/members", at, "")
	if v := members["value"].([]any); len(v) != 1 || v[0].(map[string]any)["id"] != id["oid"] {
		t.Errorf("HR members = %v", members)
	}
	// ...the users by org code, and the manager in one call.
	_, _, users := graphCall(t, http.MethodGet, graph+"/users?$filter="+
		url.QueryEscape("onPremisesExtensionAttributes/extensionAttribute1 eq 'DEPT001'")+"&$expand=manager", at, "")
	v := users["value"].([]any)
	if len(v) != 1 || v[0].(map[string]any)["manager"].(map[string]any)["displayName"] != "Boss Kang" {
		t.Errorf("users by org code = %v", users)
	}

	// HR transfer through the admin API: the next sign-in and Graph call follow.
	status, _, raw := do(t, http.MethodPut, base+"/admin/api/entra/users/"+tidCorp+"/hana",
		`{"name":"Hana Yoon","email":"hana@corp.example","manager":"boss","department":"Finance",
		  "onPremisesExtensionAttributes":{"extensionAttribute1":"DEPT002"}}`,
		map[string]string{"Content-Type": "application/json"})
	if status != http.StatusOK {
		t.Fatalf("admin update: %d %s", status, raw)
	}
	at, id = entraAccessToken(t, base, tidCorp, tidCorp, "hana")
	if g := claimGroups(t, id); g["GRP_DEPT_DEPT001_HRTeam"] || !g["GRP_DEPT_DEPT002_Finance"] || id["org_code"] != "DEPT002" {
		t.Errorf("after transfer: groups=%v org_code=%v", id["groups"], id["org_code"])
	}
	_, _, memberOf := graphCall(t, http.MethodGet, graph+"/me/memberOf", at, "")
	if v := memberOf["value"].([]any); len(v) != 1 || v[0].(map[string]any)["displayName"] != "GRP_DEPT_DEPT002_Finance" {
		t.Errorf("memberOf after transfer = %v", memberOf)
	}
}
