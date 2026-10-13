package entra

import (
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func orgHandler(t *testing.T) *Handler {
	t.Helper()
	return New(orgConfig(t), WithClock(func() time.Time { return verifyNow }))
}

// orgGet issues a Graph GET whose query values are percent-encoded.
func orgGet(t *testing.T, h *Handler, path string, query map[string]string) (int, map[string]any) {
	t.Helper()
	if len(query) > 0 {
		q := url.Values{}
		for k, v := range query {
			q.Set(k, v)
		}
		path += "?" + q.Encode()
	}
	return graphGet(t, h, path, graphToken(t, h, tidA, "hana"))
}

func displayNames(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, ok := body["value"].([]any)
	if !ok {
		t.Fatalf("no value array: %v", body)
	}
	var out []string
	for _, item := range raw {
		out = append(out, item.(map[string]any)["displayName"].(string))
	}
	sort.Strings(out)
	return out
}

func TestGraphOrgAttributesAreSelectOnly(t *testing.T) {
	h := orgHandler(t)
	_, me := orgGet(t, h, "/v1.0/me", nil)
	for _, k := range []string{"department", "companyName", "employeeId", "onPremisesExtensionAttributes"} {
		if _, present := me[k]; present {
			t.Errorf("%s must not be in the default property set", k)
		}
	}
	_, me = orgGet(t, h, "/v1.0/me", map[string]string{"$select": "department,onPremisesExtensionAttributes"})
	if me["department"] != "HR" {
		t.Errorf("department = %v", me["department"])
	}
	ext, _ := me["onPremisesExtensionAttributes"].(map[string]any)
	if ext["extensionAttribute1"] != "DEPT001" || ext["extensionAttribute2"] != nil || len(ext) != 3 {
		t.Errorf("onPremisesExtensionAttributes = %v", ext)
	}
}

func TestGraphDynamicGroupShape(t *testing.T) {
	h := orgHandler(t)
	status, g := orgGet(t, h, "/v1.0/groups/GRP_DEPT_DEPT001_HRTeam", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, g)
	}
	if !reflect.DeepEqual(g["groupTypes"], []any{"DynamicMembership"}) || g["membershipRuleProcessingState"] != "On" ||
		g["membershipRule"] != `(user.extensionAttribute1 -eq "DEPT001")` {
		t.Errorf("dynamic group = %v", g)
	}
	_, s := orgGet(t, h, "/v1.0/groups/"+GroupObjectID(tidA, "Static Team"), nil)
	if !reflect.DeepEqual(s["groupTypes"], []any{}) || s["membershipRule"] != nil || s["membershipRuleProcessingState"] != nil {
		t.Errorf("static group = %v", s)
	}
	_, members := orgGet(t, h, "/v1.0/groups/GRP_DEPT_DEPT001_HRTeam/members", nil)
	if ids := collectionIDs(t, members); len(ids) != 1 || ids[0] != h.conf().User(tidA, "hana").OID {
		t.Errorf("members = %v", ids)
	}
}

func TestGraphFilter(t *testing.T) {
	h := orgHandler(t)
	cases := []struct {
		path, filter string
		want         []string
	}{
		{"/v1.0/groups", "startsWith(displayName,'grp_dept_')", []string{"GRP_DEPT_DEPT001_HRTeam", "GRP_DEPT_DEPT002_Finance"}},
		{"/v1.0/groups", "groupTypes/any(c:c eq 'DynamicMembership') and not startsWith(displayName,'GRP_DEPT')", []string{"GRP_REPORTS_boss"}},
		{"/v1.0/groups", "membershipRule eq null", []string{"Static Team"}},
		{"/v1.0/users", "onPremisesExtensionAttributes/extensionAttribute1 eq 'dept001'", []string{"hana"}},
		{"/v1.0/users", "department in ('HR', 'Finance')", []string{"finn", "hana"}},
		{"/v1.0/users", "department eq 'HR' or (department ne null and accountEnabled eq true and employeeId eq null)", []string{"finn", "hana"}},
		{"/v1.0/users", "department eq 'O''Brien'", nil},
		{"/v1.0/me/memberOf", "startsWith(displayName, 'GRP_')", []string{"GRP_DEPT_DEPT001_HRTeam", "GRP_REPORTS_boss"}},
	}
	for _, tc := range cases {
		status, body := orgGet(t, h, tc.path, map[string]string{"$filter": tc.filter})
		if status != http.StatusOK {
			t.Errorf("%s ?$filter=%s: status %d %v", tc.path, tc.filter, status, body)
			continue
		}
		if got := displayNames(t, body); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s ?$filter=%s = %v, want %v", tc.path, tc.filter, got, tc.want)
		}
	}
}

func TestGraphFilterPagesTheFilteredSet(t *testing.T) {
	h := orgHandler(t)
	_, body := orgGet(t, h, "/v1.0/groups", map[string]string{"$filter": "startsWith(displayName,'GRP_')", "$top": "2"})
	next, _ := body["@odata.nextLink"].(string)
	if len(body["value"].([]any)) != 2 || !strings.Contains(next, "$filter=") {
		t.Fatalf("page 1 = %v", body)
	}
	u, _ := url.Parse(next)
	_, page2 := graphGet(t, h, "/v1.0/groups?"+u.RawQuery, graphToken(t, h, tidA, "hana"))
	if got := len(page2["value"].([]any)); got != 1 || page2["@odata.nextLink"] != nil {
		t.Errorf("page 2 = %v", page2)
	}
}

func TestGraphFilterRejects(t *testing.T) {
	h := orgHandler(t)
	static := "/v1.0/groups/" + GroupObjectID(tidA, "Static Team")
	cases := []struct{ path, filter string }{
		{"/v1.0/users", "nope eq 'x'"},
		{"/v1.0/users", "onPremisesExtensionAttributes/extensionAttribute4 eq 'x'"},
		{"/v1.0/users", "onPremisesExtensionAttributes eq null"},
		{"/v1.0/users", "department gt 'a'"},
		{"/v1.0/users", "department eq"},
		{"/v1.0/users", "endsWith(mail,'.com')"},
		{"/v1.0/groups", "displayName eq 'unterminated"},
		{"/v1.0/groups", "displayName/any(c:c eq 'x')"},
		{"/v1.0/me", "department eq 'HR'"}, // single entities do not filter
		{static, "displayName eq 'x'"},
	}
	for _, tc := range cases {
		status, body := orgGet(t, h, tc.path, map[string]string{"$filter": tc.filter})
		if status != http.StatusBadRequest || graphErrCode(t, body) != CodeUnsupportedQuery {
			t.Errorf("%s ?$filter=%s: status %d %v", tc.path, tc.filter, status, body)
		}
	}
}

func TestGraphExpandManager(t *testing.T) {
	h := orgHandler(t)
	boss := h.conf().User(tidA, "boss")
	_, me := orgGet(t, h, "/v1.0/me", map[string]string{"$expand": "manager"})
	m, ok := me["manager"].(map[string]any)
	if !ok || m["id"] != boss.OID || m["@odata.type"] != "#microsoft.graph.user" || m["userPrincipalName"] != "boss@corp.example" {
		t.Fatalf("expanded manager = %v", me["manager"])
	}
	if _, leaked := m["department"]; leaked {
		t.Error("expanded manager must use the default property set")
	}
	// $select narrows the user but keeps the expansion; the inner $select
	// narrows the manager.
	_, me = orgGet(t, h, "/v1.0/me", map[string]string{"$select": "displayName", "$expand": "manager($select=id,displayName)"})
	m, _ = me["manager"].(map[string]any)
	if me["mail"] != nil || m == nil || len(m) != 3 || m["displayName"] != "boss" {
		t.Errorf("selected = %v", me)
	}
	// On the collection, users without a manager have no manager property.
	_, users := orgGet(t, h, "/v1.0/users", map[string]string{"$expand": "manager"})
	for _, raw := range users["value"].([]any) {
		u := raw.(map[string]any)
		_, has := u["manager"]
		if has != (u["id"] != boss.OID) {
			t.Errorf("%v: manager present = %v", u["displayName"], has)
		}
	}
	cases := []struct{ path, expand string }{
		{"/v1.0/me", "directReports"},
		{"/v1.0/users", "manager($top=1)"},
		{"/v1.0/me/directReports", "manager"}, // only /me, /users and /users/{id} expand
		{"/v1.0/groups/" + GroupObjectID(tidA, "Static Team"), "members"},
	}
	for _, tc := range cases {
		status, body := orgGet(t, h, tc.path, map[string]string{"$expand": tc.expand})
		if status != http.StatusBadRequest || graphErrCode(t, body) != CodeUnsupportedQuery {
			t.Errorf("%s ?$expand=%s: status %d %v", tc.path, tc.expand, status, body)
		}
	}
}
