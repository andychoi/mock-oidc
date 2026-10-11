package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// entraGraphConfig is entraConfig plus the account profile data the Graph
// surface serves. Graph itself needs no config: it is on with Entra mode.
const entraGraphConfig = `{
  "interactiveLogin": true,
  "entra": {
    "tenants": [
      {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"],
       "groups": [{"name": "AMS Engineers", "description": "Engineering", "mailNickname": "ams-eng"}]},
      {"tid": "22222222-2222-2222-2222-22222222abcd", "name": "Customer X", "domains": ["customer-x.example"],
       "groupClaimFormat": "object_id", "groupLimit": 3}
    ],
    "users": [
      {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Kim",
       "email": "jane@corp.example", "givenName": "Jane", "surname": "Kim",
       "jobTitle": "Staff Engineer", "officeLocation": "Seoul",
       "businessPhones": ["+82-2-555-0100"], "mobilePhone": "+82-10-555-0101",
       "preferredLanguage": "en-US", "groups": ["AMS Engineers", "PMO"], "admin": true},
      {"username": "sora", "tid": "11111111-1111-1111-1111-111111111111", "name": "Sora Han",
       "manager": "jane", "groups": ["PMO"]},
      {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd", "name": "Sam Lee",
       "email": "sam@customer-x.example", "groups": ["G1", "G2"]},
      {"username": "many", "tid": "22222222-2222-2222-2222-22222222abcd",
       "groups": ["G1", "G2", "G3", "G4"]}
    ]
  }
}`

// entraAccessToken signs in a user and returns the access token and the
// decoded ID token claims.
func entraAccessToken(t *testing.T, base, seg, tid, username string) (string, map[string]any) {
	t.Helper()
	loc := entraSignIn(t, entraAuthorizeURL(base, seg, "iam", ""), tid, username)
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", loc)
	}
	status, tok, body := entraRedeem(t, base, seg, "iam", code, "", nil)
	if status != http.StatusOK {
		t.Fatalf("token status %d: %s", status, body)
	}
	at, ok := tok["access_token"].(string)
	if !ok {
		t.Fatalf("no access_token: %s", body)
	}
	return at, decodeClaims(t, tok["id_token"].(string))
}

// graphCall issues a Graph request with a Bearer token.
func graphCall(t *testing.T, method, rawURL, bearer, body string) (int, http.Header, map[string]any) {
	t.Helper()
	headers := map[string]string{"Authorization": "Bearer " + bearer}
	if body != "" {
		headers["Content-Type"] = "application/json"
	}
	status, hdr, raw := do(t, method, rawURL, body, headers)
	var m map[string]any
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("%s %s: body is not JSON: %q", method, rawURL, raw)
		}
	}
	return status, hdr, m
}

func TestGraphEndToEndMe(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	at, idClaims := entraAccessToken(t, base, tidCorp, tidCorp, "jane")

	status, _, me := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/me", at, "")
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, me)
	}
	if me["id"] != idClaims["oid"] {
		t.Errorf("/me id = %v, token oid = %v", me["id"], idClaims["oid"])
	}
	want := map[string]any{
		"displayName": "Jane Kim", "userPrincipalName": "jane@corp.example",
		"mail": "jane@corp.example", "givenName": "Jane", "surname": "Kim",
		"jobTitle": "Staff Engineer", "officeLocation": "Seoul",
		"mobilePhone": "+82-10-555-0101", "preferredLanguage": "en-US", "accountEnabled": true,
	}
	for k, v := range want {
		if me[k] != v {
			t.Errorf("%s = %v, want %v", k, me[k], v)
		}
	}
	if ctx, _ := me["@odata.context"].(string); ctx != base+"/entra/graph/v1.0/$metadata#users/$entity" {
		t.Errorf("@odata.context = %v", ctx)
	}

	// The whole point: the groups in the token are the groups Graph reports.
	status, _, groups := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/me/memberOf", at, "")
	if status != http.StatusOK {
		t.Fatalf("memberOf status %d: %v", status, groups)
	}
	names := map[string]bool{}
	for _, g := range groups["value"].([]any) {
		names[g.(map[string]any)["displayName"].(string)] = true
	}
	for _, claimed := range idClaims["groups"].([]any) {
		if !names[claimed.(string)] {
			t.Errorf("token group %v is not in /me/memberOf (%v)", claimed, names)
		}
	}
}

// An ID token is not a Graph credential: its audience is the client.
func TestGraphRejectsIDToken(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "jane")
	_, tok, body := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", nil)
	idToken, ok := tok["id_token"].(string)
	if !ok {
		t.Fatalf("no id_token: %s", body)
	}
	status, hdr, resp := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/me", idToken, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("status %d: %v", status, resp)
	}
	if hdr.Get("WWW-Authenticate") == "" {
		t.Error("a 401 must carry the Bearer challenge")
	}
}

func TestGraphEndToEndUsersAndGroups(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	at, _ := entraAccessToken(t, base, tidCorp, tidCorp, "jane")

	_, _, users := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/users", at, "")
	if got := len(users["value"].([]any)); got != 2 {
		t.Errorf("corp users = %d, want jane and sora", got)
	}
	// Reachable by UPN, as real Graph allows.
	status, _, byUPN := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/users/sora@corp.example", at, "")
	if status != http.StatusOK || byUPN["displayName"] != "Sora Han" {
		t.Errorf("by UPN = %d %v", status, byUPN)
	}
	// Declared group metadata surfaces.
	_, _, groups := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/groups", at, "")
	var ams map[string]any
	for _, g := range groups["value"].([]any) {
		if m := g.(map[string]any); m["displayName"] == "AMS Engineers" {
			ams = m
		}
	}
	if ams == nil || ams["description"] != "Engineering" || ams["mailNickname"] != "ams-eng" {
		t.Errorf("AMS Engineers = %v", ams)
	}
	// A Corp token must not see the customer tenant.
	custAT, custClaims := entraAccessToken(t, base, tidCust, tidCust, "sam")
	status, _, cross := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/users/"+custClaims["oid"].(string), at, "")
	if status != http.StatusNotFound {
		t.Errorf("cross-tenant user = %d %v", status, cross)
	}
	status, _, own := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/me", custAT, "")
	if status != http.StatusOK || own["displayName"] != "Sam Lee" {
		t.Errorf("the customer's own token = %d %v", status, own)
	}
}

func TestGraphEndToEndManagerChain(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	at, _ := entraAccessToken(t, base, tidCorp, tidCorp, "sora")
	status, _, mgr := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/me/manager", at, "")
	if status != http.StatusOK || mgr["displayName"] != "Jane Kim" {
		t.Fatalf("manager = %d %v", status, mgr)
	}
	janeAT, _ := entraAccessToken(t, base, tidCorp, tidCorp, "jane")
	_, _, reports := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/me/directReports", janeAT, "")
	if got := reports["value"].([]any); len(got) != 1 || got[0].(map[string]any)["displayName"] != "Sora Han" {
		t.Errorf("direct reports = %v", got)
	}
}

// Behind a proxy the context and nextLink URLs must use the forwarded origin,
// and a token is only valid on the origin it was minted for.
func TestGraphHonorsForwardedHeaders(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	fwd := map[string]string{"x-forwarded-proto": "https", "x-forwarded-port": "443"}

	// Mint behind the proxy.
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "jane")
	status, tok, body := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", fwd)
	if status != http.StatusOK {
		t.Fatalf("token status %d: %s", status, body)
	}
	fwdAT := tok["access_token"].(string)

	headers := map[string]string{"Authorization": "Bearer " + fwdAT}
	for k, v := range fwd {
		headers[k] = v
	}
	st, _, raw := do(t, http.MethodGet, base+"/entra/graph/v1.0/users?$top=1", "", headers)
	if st != http.StatusOK {
		t.Fatalf("status %d: %s", st, raw)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	// Port 443 is implied by the scheme, so the forwarded origin drops it --
	// the same origin the issuer claim uses behind this proxy.
	const fwdOrigin = "https://127.0.0.1"
	if ctx, _ := doc["@odata.context"].(string); ctx != fwdOrigin+"/entra/graph/v1.0/$metadata#users" {
		t.Errorf("@odata.context = %v, want the forwarded origin", ctx)
	}
	next, ok := doc["@odata.nextLink"].(string)
	if !ok || !strings.HasPrefix(next, fwdOrigin+"/entra/graph/v1.0/users?") {
		t.Errorf("@odata.nextLink = %v, want the forwarded origin", doc["@odata.nextLink"])
	}
	if !strings.Contains(next, "$top=1") {
		t.Errorf("@odata.nextLink dropped $top: %s", next)
	}

	// That token belongs to the forwarded origin, so the direct one rejects it.
	if st, _, _ := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/me", fwdAT, ""); st != http.StatusUnauthorized {
		t.Errorf("a token minted behind the proxy must not pass on the direct origin, got %d", st)
	}
	// And a directly minted token does not pass behind the proxy.
	directAT, _ := entraAccessToken(t, base, tidCorp, tidCorp, "jane")
	direct := map[string]string{"Authorization": "Bearer " + directAT}
	for k, v := range fwd {
		direct[k] = v
	}
	if st, _, _ := do(t, http.MethodGet, base+"/entra/graph/v1.0/me", "", direct); st != http.StatusUnauthorized {
		t.Errorf("a directly minted token must not pass behind the proxy, got %d", st)
	}
}

// Graph must not shadow the sign-in endpoints, and the built-in navikt routes
// must stay reachable with Graph mounted.
func TestGraphDoesNotShadowOtherRoutes(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	if status, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil); status != http.StatusOK ||
		doc["token_endpoint"] != base+"/entra/"+tidCorp+"/oauth2/v2.0/token" {
		t.Errorf("entra discovery = %d %v", status, doc)
	}
	if status, doc := entraGetJSON(t, base+"/default/.well-known/openid-configuration", nil); status != http.StatusOK ||
		doc["issuer"] != base+"/default" {
		t.Errorf("built-in discovery = %d %v", status, doc)
	}
	// "graph" is not a tenant, so the Graph segment answers Graph's 401 rather
	// than the tenant error.
	status, _, body := do(t, http.MethodGet, base+"/entra/graph/v1.0/me", "", nil)
	if status != http.StatusUnauthorized || !strings.Contains(body, "InvalidAuthenticationToken") {
		t.Errorf("status %d body %s", status, body)
	}
}

// Discovery advertises UserInfo and the advertised URL works with the access
// token from the same sign-in.
func TestGraphEndToEndUserInfo(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	_, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil)
	endpoint, ok := doc["userinfo_endpoint"].(string)
	if !ok || endpoint != base+"/entra/graph/oidc/userinfo" {
		t.Fatalf("userinfo_endpoint = %v", doc["userinfo_endpoint"])
	}
	at, idClaims := entraAccessToken(t, base, tidCorp, tidCorp, "jane")
	status, hdr, body := graphCall(t, http.MethodGet, endpoint, at, "")
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, body)
	}
	// sub must be the same pairwise subject the ID token carries.
	if body["sub"] != idClaims["sub"] || body["oid"] != idClaims["oid"] || body["tid"] != idClaims["tid"] {
		t.Errorf("userinfo = %v, id token = %v", body, idClaims)
	}
	if body["given_name"] != "Jane" || body["family_name"] != "Kim" || body["email"] != "jane@corp.example" {
		t.Errorf("profile claims = %v", body)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", hdr.Get("Cache-Control"))
	}
	// POST is equivalent, as OIDC requires.
	if st, _, post := graphCall(t, http.MethodPost, endpoint, at, ""); st != http.StatusOK || post["sub"] != body["sub"] {
		t.Errorf("POST userinfo = %d %v", st, post)
	}
}

// The loop that motivated this feature: a user over the group limit gets no
// groups claim but an overage pointer, and that pointer -- fetched with the
// access token from the same sign-in -- returns the group ids.
func TestGraphResolvesGroupOverage(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	at, claims := entraAccessToken(t, base, tidCust, tidCust, "many")

	if _, has := claims["groups"]; has {
		t.Fatalf("a user over the limit must have no groups claim: %v", claims["groups"])
	}
	names, ok := claims["_claim_names"].(map[string]any)
	if !ok || names["groups"] != "src1" {
		t.Fatalf("_claim_names = %v", claims["_claim_names"])
	}
	sources, ok := claims["_claim_sources"].(map[string]any)
	if !ok {
		t.Fatalf("_claim_sources = %v", claims["_claim_sources"])
	}
	endpoint, _ := sources["src1"].(map[string]any)["endpoint"].(string)
	// It must point at this server, not at the real Graph.
	if !strings.HasPrefix(endpoint, base+"/entra/graph/v1.0/users/") ||
		!strings.HasSuffix(endpoint, "/getMemberObjects") {
		t.Fatalf("overage endpoint = %q, want one on this server", endpoint)
	}

	// Follow it exactly as an RP would.
	status, _, body := graphCall(t, http.MethodPost, endpoint, at, `{"securityEnabledOnly": true}`)
	if status != http.StatusOK {
		t.Fatalf("getMemberObjects status %d: %v", status, body)
	}
	got := []string{}
	for _, v := range body["value"].([]any) {
		got = append(got, v.(string))
	}
	if len(got) != 4 {
		t.Fatalf("group ids = %v, want the four groups that overflowed", got)
	}
	// Those ids are the ones /me/memberOf reports, so the overage answer and
	// the directory agree.
	_, _, groups := graphCall(t, http.MethodGet, base+"/entra/graph/v1.0/me/memberOf", at, "")
	fromGraph := map[string]bool{}
	for _, g := range groups["value"].([]any) {
		fromGraph[g.(map[string]any)["id"].(string)] = true
	}
	for _, id := range got {
		if !fromGraph[id] {
			t.Errorf("overage id %s is not a group in /me/memberOf (%v)", id, fromGraph)
		}
	}
}

// scp carries API permission short names; the response's scope field keeps
// everything the client asked for.
func TestGraphAccessTokenScp(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	authorize := base + "/entra/" + tidCorp + "/oauth2/v2.0/authorize?response_type=code&client_id=iam" +
		"&redirect_uri=" + url.QueryEscape(entraRedirect) + "&state=st1&scope=" +
		url.QueryEscape("openid offline_access https://graph.microsoft.com/User.Read")
	loc := entraSignIn(t, authorize, tidCorp, "jane")
	status, tok, body := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", nil)
	if status != http.StatusOK {
		t.Fatalf("token status %d: %s", status, body)
	}
	if got := tok["scope"]; got != "openid offline_access https://graph.microsoft.com/User.Read" {
		t.Errorf("response scope = %v, want every requested scope", got)
	}
	claims := decodeClaims(t, tok["access_token"].(string))
	if claims["scp"] != "openid User.Read" {
		t.Errorf("scp = %v, want short names without offline_access", claims["scp"])
	}
	if claims["azp"] != "iam" || claims["appid"] != "iam" {
		t.Errorf("azp=%v appid=%v", claims["azp"], claims["appid"])
	}
	// offline_access was requested, so a refresh token comes back regardless.
	if tok["refresh_token"] == nil {
		t.Error("offline_access must still yield a refresh token")
	}
}

// entraGraphOffConfig disables Graph, which must restore the pre-feature
// behavior exactly.
const entraGraphOffConfig = `{
  "interactiveLogin": true,
  "entra": {
    "graph": {"enabled": false},
    "tenants": [
      {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"]},
      {"tid": "22222222-2222-2222-2222-22222222abcd", "name": "Customer X", "groupLimit": 1}
    ],
    "users": [
      {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "email": "jane@corp.example"},
      {"username": "many", "tid": "22222222-2222-2222-2222-22222222abcd", "groups": ["G1", "G2"]}
    ]
  }
}`

func TestGraphDisabledByConfig(t *testing.T) {
	_, base := startServer(t, entraGraphOffConfig)

	// The Graph segment is not reserved, so it resolves as a tenant.
	status, _, body := do(t, http.MethodGet, base+"/entra/graph/v1.0/me", "", nil)
	if status != http.StatusBadRequest || !strings.Contains(body, "aadsts90002") {
		t.Errorf("graph path = %d %s", status, body)
	}

	// Discovery advertises no UserInfo, and the path does not serve.
	_, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil)
	if _, has := doc["userinfo_endpoint"]; has {
		t.Errorf("userinfo_endpoint = %v, want absent", doc["userinfo_endpoint"])
	}
	if status, _, _ := do(t, http.MethodGet, base+"/entra/graph/oidc/userinfo", "", nil); status != http.StatusBadRequest {
		t.Errorf("userinfo path = %d, want the tenant error", status)
	}

	// client_credentials stays unsupported.
	status, _, body = do(t, http.MethodPost, base+"/entra/"+tidCorp+"/oauth2/v2.0/token",
		"grant_type=client_credentials&client_id=iam&client_secret=s&scope="+
			url.QueryEscape("https://graph.microsoft.com/.default"), formHeaders)
	if status != http.StatusBadRequest || !strings.Contains(body, "unsupported_grant_type") {
		t.Errorf("client_credentials = %d %s", status, body)
	}

	// And the overage claim points back at the real Graph.
	_, claims := entraAccessToken(t, base, tidCust, tidCust, "many")
	src := claims["_claim_sources"].(map[string]any)["src1"].(map[string]any)
	if endpoint, _ := src["endpoint"].(string); !strings.HasPrefix(endpoint, "https://graph.microsoft.com/v1.0/users/") {
		t.Errorf("overage endpoint = %q, want the real Graph", endpoint)
	}
}

// login_hint works over HTTP end to end: one GET, no picker, straight to the
// redirect with a code.
func TestGraphEndToEndLoginHint(t *testing.T) {
	_, base := startServer(t, entraGraphConfig)
	target := base + "/entra/" + tidCorp + "/oauth2/v2.0/authorize?response_type=code&client_id=iam" +
		"&redirect_uri=" + url.QueryEscape(entraRedirect) + "&state=st1&scope=openid" +
		"&login_hint=" + url.QueryEscape("jane@corp.example")
	status, hdr, body := do(t, http.MethodGet, target, "", nil)
	if status != http.StatusFound {
		t.Fatalf("status %d body %s", status, body)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", loc)
	}
	// The code redeems for the hinted account.
	st, tok, raw := entraRedeem(t, base, tidCorp, "iam", code, "", nil)
	if st != http.StatusOK {
		t.Fatalf("token status %d: %s", st, raw)
	}
	if claims := decodeClaims(t, tok["id_token"].(string)); claims["preferred_username"] != "jane@corp.example" {
		t.Errorf("signed in as %v", claims["preferred_username"])
	}
}
