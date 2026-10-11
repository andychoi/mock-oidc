package entra

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

const graphJSONConfig = `{
  "tenants": [
    {"tid": "11111111-1111-1111-1111-111111111111", "domains": ["corp.example"],
     "groups": [{"name": "AMS Engineers", "description": "Engineering"}]},
    {"tid": "22222222-2222-2222-2222-22222222abcd", "domains": ["customer-x.example"]}
  ],
  "users": [
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Kim",
     "email": "jane@corp.example", "givenName": "Jane", "surname": "Kim",
     "jobTitle": "Staff Engineer", "officeLocation": "Seoul",
     "businessPhones": ["+82-2-555-0100"], "preferredLanguage": "en-US",
     "groups": ["AMS Engineers", "PMO"]},
    {"username": "sora", "tid": "11111111-1111-1111-1111-111111111111", "name": "Sora Han",
     "manager": "jane", "groups": ["PMO"]},
    {"username": "minimal", "tid": "11111111-1111-1111-1111-111111111111"},
    {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd", "name": "Sam Lee",
     "groups": ["PMO"]}
  ]
}`

// graphHandler builds a handler on the frozen clock over graphJSONConfig.
func graphHandler(t *testing.T) *Handler {
	t.Helper()
	cfg, err := ParseConfig([]byte(graphJSONConfig))
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, WithClock(func() time.Time { return verifyNow }))
}

// graphToken mints a delegated access token for a user in a tenant.
func graphToken(t *testing.T, h *Handler, tid, username string) string {
	t.Helper()
	cfg := h.conf()
	u := cfg.User(tid, username)
	if u == nil {
		t.Fatalf("no user %s in %s", username, tid)
	}
	in := TokenInput{Origin: "http://mock.test", BasePath: cfg.BasePath, Tenant: cfg.Tenant(tid),
		User: u, ClientID: "app", Scopes: []string{"openid"}, Now: h.now(), Expiry: cfg.TokenExpiry}
	return h.keys.Sign(AccessTokenClaims(in))
}

// graphAppToken mints an app-only token (no oid) for a tenant.
func graphAppToken(t *testing.T, h *Handler, tid string) string {
	t.Helper()
	cfg := h.conf()
	in := TokenInput{Origin: "http://mock.test", BasePath: cfg.BasePath, Tenant: cfg.Tenant(tid),
		User: cfg.UsersIn(tid)[0], ClientID: "app", Scopes: []string{"openid"}, Now: h.now(),
		Expiry: cfg.TokenExpiry}
	claims := AccessTokenClaims(in)
	delete(claims, "oid")
	return h.keys.Sign(claims)
}

// callGraph runs one Graph request through the full handler with a token.
func callGraph(t *testing.T, h *Handler, method, path, bearer, body string) routing.Response {
	t.Helper()
	r := httptest.NewRequest(method, "http://mock.test/entra/graph"+path, strings.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	req, err := oauth2.FromHTTPRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	return h.Handle(req)
}

func graphGet(t *testing.T, h *Handler, path, bearer string) (int, map[string]any) {
	t.Helper()
	resp := callGraph(t, h, http.MethodGet, path, bearer, "")
	var m map[string]any
	if resp.Body != "" {
		if err := json.Unmarshal([]byte(resp.Body), &m); err != nil {
			t.Fatalf("GET %s: decode %q: %v", path, resp.Body, err)
		}
	}
	return resp.Status, m
}

// graphErrCode reads the Graph error code out of a response body.
func graphErrCode(t *testing.T, body map[string]any) string {
	t.Helper()
	e, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("not a Graph error body: %v", body)
	}
	code, _ := e["code"].(string)
	return code
}

func collectionIDs(t *testing.T, body map[string]any) []string {
	t.Helper()
	raw, ok := body["value"].([]any)
	if !ok {
		t.Fatalf("no value array: %v", body)
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		id, _ := item.(map[string]any)["id"].(string)
		out = append(out, id)
	}
	return out
}

func TestGraphMeShape(t *testing.T) {
	h := graphHandler(t)
	status, body := graphGet(t, h, "/v1.0/me", graphToken(t, h, tidA, "jane"))
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, body)
	}
	jane := h.conf().User(tidA, "jane")
	want := map[string]any{
		"id": jane.OID, "displayName": "Jane Kim", "userPrincipalName": "jane@corp.example",
		"mail": "jane@corp.example", "givenName": "Jane", "surname": "Kim",
		"jobTitle": "Staff Engineer", "officeLocation": "Seoul",
		"preferredLanguage": "en-US", "accountEnabled": true,
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v", k, body[k], v)
		}
	}
	if phones, ok := body["businessPhones"].([]any); !ok || len(phones) != 1 || phones[0] != "+82-2-555-0100" {
		t.Errorf("businessPhones = %v", body["businessPhones"])
	}
	if ctx, _ := body["@odata.context"].(string); !strings.HasSuffix(ctx, "$metadata#users/$entity") {
		t.Errorf("@odata.context = %v", ctx)
	}
}

// Graph emits the key with a null rather than omitting it, and SDK
// deserializers depend on that.
func TestGraphMeRendersGapsAsNullNotMissing(t *testing.T) {
	h := graphHandler(t)
	_, body := graphGet(t, h, "/v1.0/me", graphToken(t, h, tidA, "minimal"))
	for _, k := range []string{"mail", "givenName", "surname", "jobTitle", "officeLocation", "mobilePhone", "preferredLanguage"} {
		v, present := body[k]
		if !present {
			t.Errorf("%s must be present as null, not omitted", k)
		}
		if v != nil {
			t.Errorf("%s = %v, want null", k, v)
		}
	}
	if phones, ok := body["businessPhones"].([]any); !ok || len(phones) != 0 {
		t.Errorf("businessPhones = %v, want []", body["businessPhones"])
	}
}

func TestGraphMeRequiresDelegatedToken(t *testing.T) {
	h := graphHandler(t)
	status, body := graphGet(t, h, "/v1.0/me", graphAppToken(t, h, tidA))
	if status != http.StatusForbidden || graphErrCode(t, body) != CodeAuthorizationRequestDenied {
		t.Fatalf("status %d body %v", status, body)
	}
}

func TestGraphRequiresBearer(t *testing.T) {
	h := graphHandler(t)
	resp := callGraph(t, h, http.MethodGet, "/v1.0/me", "", "")
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.Status)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
		t.Fatalf("an unauthenticated Graph call must still answer JSON, got %q", resp.Body)
	}
	if graphErrCode(t, body) != CodeInvalidAuthenticationToken {
		t.Errorf("code = %v", body)
	}
}

func TestGraphUserByOIDAndUPN(t *testing.T) {
	h := graphHandler(t)
	tok := graphToken(t, h, tidA, "jane")
	jane := h.conf().User(tidA, "jane")
	for _, key := range []string{jane.OID, "jane@corp.example"} {
		status, body := graphGet(t, h, "/v1.0/users/"+key, tok)
		if status != http.StatusOK || body["id"] != jane.OID {
			t.Errorf("GET /users/%s = %d %v", key, status, body)
		}
	}
}

func TestGraphUnknownUserIs404(t *testing.T) {
	h := graphHandler(t)
	status, body := graphGet(t, h, "/v1.0/users/nobody@corp.example", graphToken(t, h, tidA, "jane"))
	if status != http.StatusNotFound || graphErrCode(t, body) != CodeResourceNotFound {
		t.Fatalf("status %d body %v", status, body)
	}
}

func TestGraphUsersPaging(t *testing.T) {
	h := graphHandler(t)
	tok := graphToken(t, h, tidA, "jane")
	_, all := graphGet(t, h, "/v1.0/users", tok)
	total := collectionIDs(t, all)
	if len(total) != 3 {
		t.Fatalf("tenant users = %v, want 3", total)
	}
	var paged []string
	skip, pages := 0, 0
	for {
		pages++
		if pages > 5 {
			t.Fatal("paging did not terminate")
		}
		_, body := graphGet(t, h, "/v1.0/users?$top=1&$skiptoken="+strconv.Itoa(skip), tok)
		ids := collectionIDs(t, body)
		if len(ids) != 1 {
			t.Fatalf("page %d returned %d rows", pages, len(ids))
		}
		paged = append(paged, ids...)
		next, more := body["@odata.nextLink"].(string)
		if !more {
			break
		}
		if !strings.Contains(next, "$top=1") {
			t.Fatalf("nextLink dropped $top: %s", next)
		}
		skip++
	}
	if pages != 3 || strings.Join(paged, ",") != strings.Join(total, ",") {
		t.Errorf("paged %d pages %v, unpaged %v", pages, paged, total)
	}
}

func TestGraphMemberOfAndTransitiveMatch(t *testing.T) {
	h := graphHandler(t)
	tok := graphToken(t, h, tidA, "jane")
	status, direct := graphGet(t, h, "/v1.0/me/memberOf", tok)
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, direct)
	}
	if ctx, _ := direct["@odata.context"].(string); !strings.HasSuffix(ctx, "$metadata#directoryObjects") {
		t.Errorf("memberOf context = %v", ctx)
	}
	ids := collectionIDs(t, direct)
	if len(ids) != 2 {
		t.Fatalf("jane's groups = %v, want 2", ids)
	}
	// Groups are flat in this emulator, so the transitive closure is the
	// direct one; an RP must get the same answer from either path.
	_, transitive := graphGet(t, h, "/v1.0/me/transitiveMemberOf", tok)
	if strings.Join(collectionIDs(t, transitive), ",") != strings.Join(ids, ",") {
		t.Errorf("transitiveMemberOf = %v, memberOf = %v", collectionIDs(t, transitive), ids)
	}
	// And the same via /users/{id}/memberOf.
	_, byID := graphGet(t, h, "/v1.0/users/"+h.conf().User(tidA, "jane").OID+"/memberOf", tok)
	if strings.Join(collectionIDs(t, byID), ",") != strings.Join(ids, ",") {
		t.Errorf("/users/{id}/memberOf = %v", collectionIDs(t, byID))
	}
}

func TestGraphGroupsAndMembers(t *testing.T) {
	h := graphHandler(t)
	tok := graphToken(t, h, tidA, "jane")
	status, list := graphGet(t, h, "/v1.0/groups", tok)
	if status != http.StatusOK || len(collectionIDs(t, list)) != 2 {
		t.Fatalf("groups = %d %v", status, list)
	}
	pmo := h.conf().GroupByID(tidA, "PMO")
	_, one := graphGet(t, h, "/v1.0/groups/"+pmo.OID, tok)
	if one["displayName"] != "PMO" || one["securityEnabled"] != true || one["mailEnabled"] != false {
		t.Errorf("group = %v", one)
	}
	if one["description"] != nil {
		t.Errorf("an undeclared description must be null, got %v", one["description"])
	}
	_, members := graphGet(t, h, "/v1.0/groups/"+pmo.OID+"/members", tok)
	if got := len(collectionIDs(t, members)); got != 2 {
		t.Errorf("PMO members = %d, want jane and sora", got)
	}
	// Declared metadata surfaces on the group entity.
	ams := h.conf().GroupByID(tidA, "AMS Engineers")
	_, amsBody := graphGet(t, h, "/v1.0/groups/"+ams.OID, tok)
	if amsBody["description"] != "Engineering" || amsBody["mailNickname"] != "amsengineers" {
		t.Errorf("declared group = %v", amsBody)
	}
}

func TestGraphUnknownGroupIs404(t *testing.T) {
	h := graphHandler(t)
	status, body := graphGet(t, h, "/v1.0/groups/99999999-9999-9999-9999-999999999999", graphToken(t, h, tidA, "jane"))
	if status != http.StatusNotFound || graphErrCode(t, body) != CodeResourceNotFound {
		t.Fatalf("status %d body %v", status, body)
	}
}

func TestGraphGetMemberObjects(t *testing.T) {
	h := graphHandler(t)
	tok := graphToken(t, h, tidA, "jane")
	want := h.conf().GroupIDsOf(h.conf().User(tidA, "jane"))
	for _, body := range []string{"", `{"securityEnabledOnly": true}`, `{"securityEnabledOnly": false}`} {
		for _, path := range []string{"/v1.0/me/getMemberObjects", "/v1.0/users/" + h.conf().User(tidA, "jane").OID + "/getMemberObjects", "/v1.0/me/getMemberGroups"} {
			resp := callGraph(t, h, http.MethodPost, path, tok, body)
			if resp.Status != http.StatusOK {
				t.Fatalf("POST %s body %q: status %d (%s)", path, body, resp.Status, resp.Body)
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(resp.Body), &m); err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, v := range m["value"].([]any) {
				got = append(got, v.(string))
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("POST %s = %v, want %v", path, got, want)
			}
		}
	}
}

func TestGraphGetMemberObjectsRejectsBadBody(t *testing.T) {
	h := graphHandler(t)
	resp := callGraph(t, h, http.MethodPost, "/v1.0/me/getMemberObjects", graphToken(t, h, tidA, "jane"), "{not json")
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("status %d", resp.Status)
	}
}

func TestGraphManagerAndDirectReports(t *testing.T) {
	h := graphHandler(t)
	janeTok := graphToken(t, h, tidA, "jane")
	soraTok := graphToken(t, h, tidA, "sora")
	status, mgr := graphGet(t, h, "/v1.0/me/manager", soraTok)
	if status != http.StatusOK || mgr["displayName"] != "Jane Kim" {
		t.Fatalf("manager = %d %v", status, mgr)
	}
	status, _ = graphGet(t, h, "/v1.0/me/manager", janeTok)
	if status != http.StatusNotFound {
		t.Errorf("a user without a manager must 404, got %d", status)
	}
	_, reports := graphGet(t, h, "/v1.0/me/directReports", janeTok)
	if ids := collectionIDs(t, reports); len(ids) != 1 || ids[0] != h.conf().User(tidA, "sora").OID {
		t.Errorf("direct reports = %v", ids)
	}
}

func TestGraphPhotoIs404(t *testing.T) {
	h := graphHandler(t)
	tok := graphToken(t, h, tidA, "jane")
	for _, path := range []string{"/v1.0/me/photo", "/v1.0/me/photo/$value"} {
		status, body := graphGet(t, h, path, tok)
		if status != http.StatusNotFound || graphErrCode(t, body) != CodeImageNotFound {
			t.Errorf("GET %s = %d %v", path, status, body)
		}
	}
}

// An unknown Graph path must answer a Graph error body, not the plain-text
// 404 the rest of the router uses, or a Graph SDK cannot parse it.
func TestGraphUnknownPathIsGraph404(t *testing.T) {
	h := graphHandler(t)
	tok := graphToken(t, h, tidA, "jane")
	for _, path := range []string{"/v1.0/applications", "/v1.0/me/nope", "/v2.0/me", "/v1.0"} {
		resp := callGraph(t, h, http.MethodGet, path, tok, "")
		if resp.Status != http.StatusNotFound {
			t.Errorf("GET %s = %d", path, resp.Status)
			continue
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
			t.Errorf("GET %s answered %q, not a Graph error", path, resp.Body)
			continue
		}
		if graphErrCode(t, body) != CodeResourceNotFound {
			t.Errorf("GET %s code = %v", path, body)
		}
	}
}

func TestGraphOptionsIs204(t *testing.T) {
	h := graphHandler(t)
	if resp := callGraph(t, h, http.MethodOptions, "/v1.0/me", "", ""); resp.Status != http.StatusNoContent {
		t.Fatalf("OPTIONS = %d", resp.Status)
	}
}

// The review focus of this task: a token from one tenant must not reach any
// part of another tenant's directory.
func TestGraphTenantIsolation(t *testing.T) {
	h := graphHandler(t)
	corp := graphToken(t, h, tidA, "jane")
	cfg := h.conf()
	sam := cfg.User(tidB, "sam")
	custPMO := cfg.GroupByID(tidB, "PMO")

	_, users := graphGet(t, h, "/v1.0/users", corp)
	for _, id := range collectionIDs(t, users) {
		if cfg.UserByOID(tidA, id) == nil {
			t.Errorf("/users leaked %s from another tenant", id)
		}
	}
	_, groups := graphGet(t, h, "/v1.0/groups", corp)
	for _, id := range collectionIDs(t, groups) {
		if cfg.GroupByID(tidA, id) == nil {
			t.Errorf("/groups leaked %s from another tenant", id)
		}
	}
	// Cross-tenant ids must be invisible, not merely filtered out of lists.
	crossTenant := []string{
		"/v1.0/users/" + sam.OID,
		"/v1.0/users/sam@customer-x.example",
		"/v1.0/users/" + sam.OID + "/memberOf",
		"/v1.0/groups/" + custPMO.OID,
		"/v1.0/groups/" + custPMO.OID + "/members",
	}
	for _, path := range crossTenant {
		status, body := graphGet(t, h, path, corp)
		if status != http.StatusNotFound {
			t.Errorf("GET %s with a Corp token = %d %v, want 404", path, status, body)
		}
	}
	// The customer's own token sees its own directory, so the 404s above are
	// isolation rather than the fixtures being empty.
	status, body := graphGet(t, h, "/v1.0/users/"+sam.OID, graphToken(t, h, tidB, "sam"))
	if status != http.StatusOK || body["displayName"] != "Sam Lee" {
		t.Errorf("customer token on its own user = %d %v", status, body)
	}
	// The same group name in both tenants has disjoint membership.
	_, corpMembers := graphGet(t, h, "/v1.0/groups/"+cfg.GroupByID(tidA, "PMO").OID+"/members", corp)
	if len(collectionIDs(t, corpMembers)) != 2 {
		t.Errorf("corp PMO members = %v", collectionIDs(t, corpMembers))
	}
}

// $select narrows the account fields a caller receives, on an entity and
// inside a collection.
func TestGraphSelect(t *testing.T) {
	h := graphHandler(t)
	tok := graphToken(t, h, tidA, "jane")
	_, body := graphGet(t, h, "/v1.0/me?$select=displayName", tok)
	if _, has := body["jobTitle"]; has {
		t.Errorf("$select must drop jobTitle: %v", body)
	}
	if body["displayName"] != "Jane Kim" || body["id"] == nil {
		t.Errorf("$select must keep the selection and id: %v", body)
	}
	_, coll := graphGet(t, h, "/v1.0/users?$select=displayName", tok)
	first := coll["value"].([]any)[0].(map[string]any)
	if _, has := first["mail"]; has {
		t.Errorf("$select must apply inside a collection: %v", first)
	}
	status, bad := graphGet(t, h, "/v1.0/me?$select=nope", tok)
	if status != http.StatusBadRequest || graphErrCode(t, bad) != CodeUnsupportedQuery {
		t.Errorf("unknown $select = %d %v", status, bad)
	}
}

// With Graph disabled the segment is not reserved, so the path falls through
// to tenant resolution and answers exactly as a server without the feature.
func TestGraphDisabledFallsThroughToTenantResolution(t *testing.T) {
	cfg, err := ParseConfig([]byte(strings.Replace(graphJSONConfig, `{
  "tenants"`, `{
  "graph": {"enabled": false},
  "tenants"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	h := New(cfg, WithClock(func() time.Time { return verifyNow }))
	resp := callGraph(t, h, http.MethodGet, "/v1.0/me", "", "")
	if resp.Status != http.StatusBadRequest || !strings.Contains(resp.Body, "aadsts90002") {
		t.Fatalf("status %d body %s", resp.Status, resp.Body)
	}
}
