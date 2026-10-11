package entra

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"
)

const appOnlyJSON = `{
  "graph": {"appOnly": true},
  "tenants": [
    {"tid": "11111111-1111-1111-1111-111111111111", "domains": ["corp.example"]},
    {"tid": "22222222-2222-2222-2222-22222222abcd"}
  ],
  "apps": [
    {"clientId": "sync", "tid": "11111111-1111-1111-1111-111111111111",
     "roles": ["User.Read.All", "Group.Read.All"]},
    {"clientId": "anywhere", "roles": ["User.Read.All"]}
  ],
  "users": [
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Kim",
     "groups": ["PMO"]},
    {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd"}
  ]
}`

func appOnlyHandler(t *testing.T) *Handler {
	t.Helper()
	return New(mustConfig(t, appOnlyJSON), WithClock(func() time.Time { return verifyNow }))
}

// clientCreds posts a client_credentials request and returns the response and
// the decoded body.
func clientCreds(t *testing.T, h *Handler, seg, form string) (int, map[string]any) {
	t.Helper()
	resp := serve(h, http.MethodPost, "http://mock.test/entra/"+seg+"/oauth2/v2.0/token", form)
	var m map[string]any
	if resp.Body != "" {
		_ = json.Unmarshal([]byte(resp.Body), &m)
	}
	return resp.Status, m
}

const defaultScope = "client_credentials&scope=" +
	"https%3A%2F%2Fgraph.microsoft.com%2F.default"

func TestClientCredentialsRejectedUnlessEnabled(t *testing.T) {
	// The same config without the graph block: the grant stays unsupported.
	h := New(mustConfig(t, `{"tenants": [{"tid": "`+tidA+`"}],
		"users": [{"username": "jane", "tid": "`+tidA+`"}]}`))
	status, body := clientCreds(t, h, tidA, "grant_type="+defaultScope+"&client_id=sync&client_secret=s")
	if status != http.StatusBadRequest {
		t.Fatalf("status %d: %v", status, body)
	}
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestAppOnlyTokenClaims(t *testing.T) {
	h := appOnlyHandler(t)
	status, body := clientCreds(t, h, tidA, "grant_type="+defaultScope+"&client_id=sync&client_secret=s")
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, body)
	}
	if body["token_type"] != "Bearer" || body["expires_in"] == nil {
		t.Errorf("response = %v", body)
	}
	// An app-only grant has no user, so there is no id_token and no refresh.
	for _, absent := range []string{"id_token", "refresh_token"} {
		if _, has := body[absent]; has {
			t.Errorf("%s must not be issued to an app-only grant", absent)
		}
	}
	_, claims, ok := h.keys.Verify(body["access_token"].(string))
	if !ok {
		t.Fatal("the minted token must verify")
	}
	want := map[string]any{
		"aud": graphAppID, "sub": "sync", "azp": "sync", "appid": "sync",
		"tid": tidA, "ver": "2.0", "iss": "http://mock.test/entra/" + tidA + "/v2.0",
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("%s = %v, want %v", k, claims[k], v)
		}
	}
	roles, _ := claims["roles"].([]any)
	if len(roles) != 2 || roles[0] != "User.Read.All" {
		t.Errorf("roles = %v", claims["roles"])
	}
	// No user: no oid, and scp is for delegated permissions only.
	for _, absent := range []string{"oid", "scp", "name", "preferred_username", "groups"} {
		if _, has := claims[absent]; has {
			t.Errorf("%s must be absent from an app-only token, got %v", absent, claims[absent])
		}
	}
}

// An unregistered client still gets a token, as everywhere else in mock-oidc;
// it simply carries no roles.
func TestAppOnlyUnregisteredClientHasNoRoles(t *testing.T) {
	h := appOnlyHandler(t)
	_, body := clientCreds(t, h, tidA, "grant_type="+defaultScope+"&client_id=stranger&client_secret=s")
	_, claims, ok := h.keys.Verify(body["access_token"].(string))
	if !ok {
		t.Fatal("token must verify")
	}
	if _, has := claims["roles"]; has {
		t.Errorf("roles = %v, want absent", claims["roles"])
	}
	if claims["appid"] != "stranger" {
		t.Errorf("appid = %v", claims["appid"])
	}
}

// A registration without a tid applies in every tenant.
func TestAppOnlyTenantlessRegistrationAppliesEverywhere(t *testing.T) {
	h := appOnlyHandler(t)
	for _, tid := range []string{tidA, tidB} {
		_, body := clientCreds(t, h, tid, "grant_type="+defaultScope+"&client_id=anywhere&client_secret=s")
		_, claims, ok := h.keys.Verify(body["access_token"].(string))
		if !ok {
			t.Fatalf("tenant %s: token must verify", tid)
		}
		if roles, _ := claims["roles"].([]any); len(roles) != 1 {
			t.Errorf("tenant %s roles = %v", tid, claims["roles"])
		}
		if claims["tid"] != tid {
			t.Errorf("tid = %v, want %s", claims["tid"], tid)
		}
	}
	// The tenant-scoped registration does not leak into the other tenant.
	_, body := clientCreds(t, h, tidB, "grant_type="+defaultScope+"&client_id=sync&client_secret=s")
	_, claims, _ := h.keys.Verify(body["access_token"].(string))
	if _, has := claims["roles"]; has {
		t.Errorf("roles leaked across tenants: %v", claims["roles"])
	}
}

func TestAppOnlyTokenOnMultiTenantPathIsRejected(t *testing.T) {
	h := appOnlyHandler(t)
	for _, seg := range []string{ScopeOrganizations, ScopeCommon} {
		status, body := clientCreds(t, h, seg, "grant_type="+defaultScope+"&client_id=sync&client_secret=s")
		if status != http.StatusBadRequest || body["error"] != "invalid_request" {
			t.Errorf("%s = %d %v", seg, status, body)
		}
	}
}

func TestAppOnlyRequiresDefaultScope(t *testing.T) {
	h := appOnlyHandler(t)
	status, body := clientCreds(t, h, tidA,
		"grant_type=client_credentials&client_id=sync&client_secret=s&scope="+url.QueryEscape("User.Read"))
	if status != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("status %d body %v", status, body)
	}
	// A bare .default and an absent scope are both accepted.
	for _, scope := range []string{"", "&scope=.default"} {
		if st, b := clientCreds(t, h, tidA, "grant_type=client_credentials&client_id=sync&client_secret=s"+scope); st != http.StatusOK {
			t.Errorf("scope %q = %d %v", scope, st, b)
		}
	}
}

func TestAppOnlyAcceptsBasicAuthClient(t *testing.T) {
	h := appOnlyHandler(t)
	r := httptestNewForm(t, "http://mock.test/entra/"+tidA+"/oauth2/v2.0/token",
		"grant_type="+defaultScope)
	r.SetBasicAuth("sync", "secret")
	resp := h.Handle(mustRequest(t, r))
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Status, resp.Body)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
		t.Fatal(err)
	}
	_, claims, _ := h.keys.Verify(body["access_token"].(string))
	if claims["appid"] != "sync" {
		t.Errorf("appid = %v, want the Basic-auth client", claims["appid"])
	}
}

// The authorization model this emulator borrows: an app-only token reads the
// directory but has no /me to describe.
func TestAppOnlyReadsUsersAndGroupsButNotMe(t *testing.T) {
	h := appOnlyHandler(t)
	_, body := clientCreds(t, h, tidA, "grant_type="+defaultScope+"&client_id=sync&client_secret=s")
	at := body["access_token"].(string)

	for _, path := range []string{"/v1.0/users", "/v1.0/groups"} {
		status, got := graphGet(t, h, path, at)
		if status != http.StatusOK {
			t.Errorf("GET %s = %d %v", path, status, got)
		}
	}
	// It reads only its own tenant.
	_, users := graphGet(t, h, "/v1.0/users", at)
	ids := collectionIDs(t, users)
	if len(ids) != 1 || ids[0] != h.conf().User(tidA, "jane").OID {
		t.Errorf("app-only /users = %v, want only the token's tenant", ids)
	}
	// But /me and its sub-resources have no user behind them.
	for _, path := range []string{"/v1.0/me", "/v1.0/me/memberOf", "/v1.0/me/manager"} {
		status, got := graphGet(t, h, path, at)
		if status != http.StatusForbidden || graphErrCode(t, got) != CodeAuthorizationRequestDenied {
			t.Errorf("GET %s = %d %v", path, status, got)
		}
	}
	// A specific user is still readable by id, which is how a sync job works.
	status, one := graphGet(t, h, "/v1.0/users/"+h.conf().User(tidA, "jane").OID, at)
	if status != http.StatusOK || one["displayName"] != "Jane Kim" {
		t.Errorf("app-only user read = %d %v", status, one)
	}
}

func TestAppOnlyCannotCallUserInfo(t *testing.T) {
	h := appOnlyHandler(t)
	_, body := clientCreds(t, h, tidA, "grant_type="+defaultScope+"&client_id=sync&client_secret=s")
	resp, info := callUserInfo(t, h, http.MethodGet, body["access_token"].(string))
	if resp.Status != http.StatusForbidden || info["error"] != "insufficient_scope" {
		t.Fatalf("status %d body %v", resp.Status, info)
	}
}

func TestAppRegistrationLookup(t *testing.T) {
	cfg := mustConfig(t, appOnlyJSON)
	if app := cfg.App("sync", tidA); app == nil || len(app.Roles) != 2 {
		t.Errorf("App(sync, corp) = %v", app)
	}
	if app := cfg.App("sync", tidB); app != nil {
		t.Errorf("App(sync, customer) = %v, want nil", app)
	}
	if app := cfg.App("anywhere", tidB); app == nil {
		t.Error("a tenantless registration must match any tenant")
	}
	if app := cfg.App("missing", tidA); app != nil {
		t.Errorf("App(missing) = %v", app)
	}
}
