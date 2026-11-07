package entra

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	tidOne = "11111111-1111-1111-1111-111111111111"
	tidTwo = "22222222-2222-2222-2222-222222222222"
)

// A code issued on organizations can be redeemed there even after its tenant
// is gone, so every way of removing the account is reachable.
func TestRedeemAfterAccountRemovedIsInvalidGrant(t *testing.T) {
	const cfg = `{
	  "tenants": [{"tid": "` + tidOne + `"}, {"tid": "` + tidTwo + `"}],
	  "users": [{"username": "jane", "tid": "` + tidOne + `"}]
	}`
	cases := map[string]struct {
		username string
		remove   func(h *Handler) error
	}{
		"user deleted":             {"jane", func(h *Handler) error { return h.AdminDeleteUser(tidOne, "jane") }},
		"tenant deleted":           {"jane", func(h *Handler) error { return h.AdminDeleteTenant(tidOne) }},
		"reset drops runtime user": {"temp", func(h *Handler) error { h.AdminResetToSeed(); return nil }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := New(mustConfig(t, cfg))
			if err := h.AdminCreateUser(User{Username: "temp", TID: tidOne}); err != nil {
				t.Fatal(err)
			}
			base := "http://mock.test/entra/organizations/oauth2/v2.0/"
			signin := serve(h, http.MethodPost, base+"authorize?response_type=code&client_id=app"+
				"&redirect_uri=http%3A%2F%2Fapp.test%2Fcb&scope=openid&state=s",
				"tid="+tidOne+"&username="+tc.username)
			loc, err := url.Parse(signin.Header.Get("Location"))
			code := ""
			if err == nil {
				code = loc.Query().Get("code")
			}
			if signin.Status != http.StatusFound || code == "" {
				t.Fatalf("sign-in: %d %s", signin.Status, signin.Body)
			}
			if err := tc.remove(h); err != nil {
				t.Fatal(err)
			}
			resp := serve(h, http.MethodPost, base+"token", "grant_type=authorization_code&client_id=app&code="+
				url.QueryEscape(code)+"&redirect_uri="+url.QueryEscape("http://app.test/cb"))
			if resp.Status != http.StatusBadRequest || !strings.Contains(resp.Body, `"invalid_grant"`) {
				t.Fatalf("redeem = %d %s, want 400 invalid_grant", resp.Status, resp.Body)
			}
		})
	}
}

// jwtClaims decodes a JWS payload without verifying it.
func jwtClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", jwt)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// A configured group oid is the group's identity everywhere: the groups
// claim, Graph overage resolution and the test API.
func TestConfiguredGroupOIDAgreesAcrossClaimAndGraph(t *testing.T) {
	const adminsOID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	h := New(mustConfig(t, `{
	  "tenants": [{"tid": "`+tidOne+`", "groupClaimFormat": "object_id",
	               "groups": [{"name": "Admins", "oid": "`+adminsOID+`"}]}],
	  "users": [{"username": "jane", "tid": "`+tidOne+`", "groups": ["Admins"]}]
	}`))
	tok, err := h.AdminMintToken("http://mock.test", MintInput{TID: tidOne, Username: "jane"})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(jwtClaims(t, tok.IDToken)["groups"]); got != "["+adminsOID+"]" {
		t.Errorf("id_token groups = %s, want [%s]", got, adminsOID)
	}
	resp := callGraph(t, h, http.MethodPost, "/v1.0/me/getMemberObjects", tok.AccessToken, `{"securityEnabledOnly": false}`)
	if got := fmt.Sprint(decodeBody(t, resp)["value"]); got != "["+adminsOID+"]" {
		t.Errorf("getMemberObjects = %d %s", resp.Status, resp.Body)
	}
	resp = serve(h, http.MethodGet, "http://mock.test/entra/_entra/groups?tid="+tidOne, "")
	if got := decodeBody(t, resp)["Admins"]; got != adminsOID {
		t.Errorf("_entra/groups Admins = %v, want %s", got, adminsOID)
	}
}

// Nesting is capped, so a request cannot grow a goroutine stack without bound.
func TestGraphFilterNestingIsCapped(t *testing.T) {
	h := graphHandler(t)
	tok := graphToken(t, h, tidA, "jane")
	const n = 10000
	for name, filter := range map[string]string{
		"balanced": strings.Repeat("(", n) + "displayName eq 'Jane Kim'" + strings.Repeat(")", n),
		"unclosed": strings.Repeat("(", n),
		"not":      strings.Repeat("not ", n) + "displayName eq 'Jane Kim'",
	} {
		t.Run(name, func(t *testing.T) {
			status, body := graphGet(t, h, "/v1.0/users?$filter="+url.QueryEscape(filter), tok)
			if status != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", status)
			}
			msg, _ := body["error"].(map[string]any)["message"].(string)
			if graphErrCode(t, body) != CodeUnsupportedQuery || !strings.HasPrefix(msg, "Invalid filter clause:") {
				t.Fatalf("body %.200v, want an invalid filter error", body)
			}
		})
	}
	shallow := strings.Repeat("(", 32) + "displayName eq 'Jane Kim'" + strings.Repeat(")", 32)
	if status, body := graphGet(t, h, "/v1.0/users?$filter="+url.QueryEscape(shallow), tok); status != http.StatusOK {
		t.Fatalf("32 levels: status %d body %v", status, body)
	}
}

func TestMembershipRuleNestingIsCapped(t *testing.T) {
	const leaf = `user.department -eq \"HR\"`
	config := func(rule string) string {
		return `{"tenants": [{"tid": "` + tidOne + `", "groups": [{"name": "HR", "membershipRule": "` + rule + `"}]}]}`
	}
	for name, rule := range map[string]string{
		"parens": strings.Repeat("(", 10000) + leaf + strings.Repeat(")", 10000),
		"not":    strings.Repeat("-not ", 10000) + leaf,
	} {
		_, err := ParseConfig([]byte(config(rule)))
		if err == nil || !strings.Contains(err.Error(), "nested too deeply") {
			t.Errorf("%s: err = %.200v, want a nesting error", name, err)
		}
	}
	shallow := strings.Repeat("(", 32) + leaf + strings.Repeat(")", 32)
	if _, err := ParseConfig([]byte(config(shallow))); err != nil {
		t.Errorf("32 levels: %v", err)
	}
}

// An object ID names one user or one group per tenant, whether configured or
// derived.
func TestDuplicateObjectIDsAreRejected(t *testing.T) {
	const oid = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	tenants := `"tenants": [{"tid": "` + tidOne + `"}, {"tid": "` + tidTwo + `"}]`
	rejected := map[string]string{
		"user oids": `{` + tenants + `, "users": [
		  {"username": "a", "tid": "` + tidOne + `", "oid": "` + oid + `"},
		  {"username": "b", "tid": "` + tidOne + `", "oid": "` + strings.ToUpper(oid) + `"}]}`,
		"group oids": `{"tenants": [{"tid": "` + tidOne + `", "groups": [
		  {"name": "A", "oid": "` + oid + `"}, {"name": "B", "oid": "` + oid + `"}]}]}`,
		"group oid equals a derived one": `{"tenants": [{"tid": "` + tidOne + `", "groups": [
		  {"name": "A"}, {"name": "B", "oid": "` + GroupObjectID(tidOne, "A") + `"}]}]}`,
	}
	for name, js := range rejected {
		if _, err := ParseConfig([]byte(js)); err == nil || !strings.Contains(err.Error(), "already used") {
			t.Errorf("%s: err = %v, want a duplicate oid error", name, err)
		}
	}

	s := NewStore(mustConfig(t, `{`+tenants+`, "users": [{"username": "a", "tid": "`+tidOne+`"}]}`))
	derived := s.Snapshot().User(tidOne, "a").OID
	if err := s.CreateUser(User{Username: "b", TID: tidOne, OID: derived}); err == nil {
		t.Error("a user taking another user's derived oid must be rejected")
	}
	if err := s.CreateUser(User{Username: "b", TID: tidTwo, OID: derived}); err != nil {
		t.Errorf("object IDs are per tenant: %v", err)
	}
}

// error: invalid_grant and accountEnabled: false are the same account state,
// so minting refuses both, like the token endpoint.
func TestMintTokenRefusesInvalidGrantAccount(t *testing.T) {
	h := New(mustConfig(t, `{"tenants": [{"tid": "`+tidOne+`"}],
	  "users": [{"username": "broken", "tid": "`+tidOne+`", "error": "invalid_grant"}]}`))
	resp := serve(h, http.MethodPost, "http://mock.test/entra/_entra/mint-token", "tid="+tidOne+"&username=broken")
	if resp.Status != http.StatusBadRequest || !strings.Contains(resp.Body, "aadsts50057") {
		t.Fatalf("mint-token = %d %.300s, want 400 AADSTS50057", resp.Status, resp.Body)
	}
}

// An ID token issued to a client whose id is Graph's app id carries the Graph
// audience, but it is still not an access token.
func TestGraphRejectsIDTokens(t *testing.T) {
	h := graphHandler(t)
	base := "http://mock.test/entra/" + tidA + "/oauth2/v2.0/"
	signin := serve(h, http.MethodPost, base+"authorize?response_type=code&client_id="+graphAppID+
		"&redirect_uri=http%3A%2F%2Fapp.test%2Fcb&scope=openid", "tid="+tidA+"&username=jane")
	loc, err := url.Parse(signin.Header.Get("Location"))
	if signin.Status != http.StatusFound || err != nil {
		t.Fatalf("sign-in: %d %s", signin.Status, signin.Body)
	}
	resp := serve(h, http.MethodPost, base+"token", "grant_type=authorization_code&client_id="+graphAppID+
		"&code="+url.QueryEscape(loc.Query().Get("code"))+"&redirect_uri="+url.QueryEscape("http://app.test/cb"))
	tokens := decodeBody(t, resp)
	idToken, _ := tokens["id_token"].(string)
	accessToken, _ := tokens["access_token"].(string)
	if aud := jwtClaims(t, idToken)["aud"]; aud != graphAppID {
		t.Fatalf("id_token aud = %v, want the Graph app id", aud)
	}
	if status, _ := graphGet(t, h, "/v1.0/me", accessToken); status != http.StatusOK {
		t.Errorf("access token: /me status %d, want 200", status)
	}
	if status, _ := graphGet(t, h, "/v1.0/me", idToken); status != http.StatusUnauthorized {
		t.Errorf("id token: /me status %d, want 401", status)
	}
	if status, _ := graphGet(t, h, "/oidc/userinfo", idToken); status != http.StatusUnauthorized {
		t.Errorf("id token: userinfo status %d, want 401", status)
	}
}

// A group listed twice is one membership: it must not push the user over the
// group limit or repeat in the claim.
func TestDuplicateGroupIsOneMembership(t *testing.T) {
	h := New(mustConfig(t, `{"tenants": [{"tid": "`+tidOne+`", "groupLimit": 1}],
	  "users": [{"username": "jane", "tid": "`+tidOne+`", "groups": ["PMO", "PMO"]}]}`))
	tok, err := h.AdminMintToken("http://mock.test", MintInput{TID: tidOne, Username: "jane"})
	if err != nil {
		t.Fatal(err)
	}
	claims := jwtClaims(t, tok.IDToken)
	if got := fmt.Sprint(claims["groups"]); got != "[PMO]" || claims["_claim_names"] != nil {
		t.Errorf("groups = %s, _claim_names = %v; want [PMO] and no overage", got, claims["_claim_names"])
	}
}

// An unknown $select property is refused whether or not any row (or manager)
// is rendered.
func TestGraphSelectValidatedWithoutRows(t *testing.T) {
	h := graphHandler(t)
	jane := graphToken(t, h, tidA, "jane")
	for path, want := range map[string]int{
		"/v1.0/users?$select=bogus&$skiptoken=100":                                                                        http.StatusBadRequest,
		"/v1.0/me?$expand=manager($select=bogus)":                                                                         http.StatusBadRequest, // jane has no manager
		"/v1.0/users?$expand=manager($select=bogus)&$skiptoken=100":                                                       http.StatusBadRequest,
		"/v1.0/users?$select=displayName&$skiptoken=100":                                                                  http.StatusOK,
		"/v1.0/users?$expand=manager($select=displayName)&$skiptoken=100":                                                 http.StatusOK,
		"/v1.0/users?$select=displayName,manager&$expand=manager&$skiptoken=100":                                          http.StatusOK,
		"/v1.0/users?$select=displayName,manager&$expand=manager&$filter=" + url.QueryEscape("displayName eq 'Sora Han'"): http.StatusOK,
	} {
		if status, body := graphGet(t, h, path, jane); status != want {
			t.Errorf("GET %s = %d %.200v, want %d", path, status, body, want)
		}
	}
}

// A disabled administrator cannot sign in, so it cannot grant admin consent
// either.
func TestAdminConsentRefusesDisabledAdmin(t *testing.T) {
	h := New(mustConfig(t, `{"tenants": [{"tid": "`+tidOne+`"}],
	  "users": [{"username": "off", "tid": "`+tidOne+`", "admin": true, "accountEnabled": false},
	            {"username": "broken", "tid": "`+tidOne+`", "admin": true, "error": "invalid_grant"}]}`))
	for _, username := range []string{"off", "broken"} {
		resp := serve(h, http.MethodPost, "http://mock.test/entra/"+tidOne+"/v2.0/adminconsent?client_id=newapp"+
			"&redirect_uri=http%3A%2F%2Fapp.test%2Fcb&state=cs1", "action=accept&tid="+tidOne+"&username="+username)
		loc, err := url.Parse(resp.Header.Get("Location"))
		if resp.Status != http.StatusFound || err != nil {
			t.Fatalf("%s: consent = %d %s", username, resp.Status, resp.Body)
		}
		q := loc.Query()
		if q.Get("error") != "access_denied" || q.Get("error_description") != "AADSTS50057: The user account is disabled." ||
			q.Get("state") != "cs1" || q.Get("admin_consent") != "" {
			t.Errorf("%s: consent redirect = %v, want access_denied AADSTS50057", username, q)
		}
	}
	if consents := serve(h, http.MethodGet, "http://mock.test/entra/_entra/consents", ""); strings.Contains(consents.Body, "newapp") {
		t.Errorf("consents = %s, want no grant for newapp", consents.Body)
	}
}

// A configured upn is the user's sign-in name everywhere, tokens included.
func TestTokensCarryConfiguredUPN(t *testing.T) {
	h := New(mustConfig(t, `{"tenants": [{"tid": "`+tidOne+`", "domains": ["corp.test"]}],
	  "users": [{"username": "jane", "tid": "`+tidOne+`", "email": "jane@mail.test", "upn": "jane.doe@corp.test"}]}`))
	tok, err := h.AdminMintToken("http://mock.test", MintInput{TID: tidOne, Username: "jane"})
	if err != nil {
		t.Fatal(err)
	}
	for name, jwt := range map[string]string{"id_token": tok.IDToken, "access_token": tok.AccessToken} {
		if got := jwtClaims(t, jwt)["preferred_username"]; got != "jane.doe@corp.test" {
			t.Errorf("%s preferred_username = %v, want the upn", name, got)
		}
	}
}

// $select=manager is valid whenever $expand=manager is present, including on
// a user who has no manager to expand. Unknown properties stay refused.
func TestGraphSelectManagerAcceptsManagerlessUsers(t *testing.T) {
	h := graphHandler(t)
	jane := graphToken(t, h, tidA, "jane") // jane has no manager; sora's manager is jane
	const opts = "?$select=displayName,manager&$expand=manager"

	status, body := graphGet(t, h, "/v1.0/users"+opts, jane)
	rows, _ := body["value"].([]any)
	managers := map[any]any{}
	for _, row := range rows {
		u, _ := row.(map[string]any)
		if m, ok := u["manager"].(map[string]any); ok {
			managers[u["displayName"]] = m["displayName"]
		}
	}
	if status != http.StatusOK || len(rows) != 3 || len(managers) != 1 || managers["Sora Han"] != "Jane Kim" {
		t.Errorf("GET /users%s = %d %.300v, want 200 with only Sora Han managed by Jane Kim", opts, status, body)
	}

	for _, path := range []string{"/v1.0/me" + opts, "/v1.0/users/jane@corp.example" + opts} {
		status, body := graphGet(t, h, path, jane)
		if status != http.StatusOK || body["displayName"] != "Jane Kim" || body["manager"] != nil {
			t.Errorf("GET %s = %d %.300v, want 200 with displayName and no manager", path, status, body)
		}
	}

	for _, path := range []string{
		"/v1.0/users?$select=bogus",
		"/v1.0/users?$select=bogus&$skiptoken=100",
		"/v1.0/users?$select=displayName,bogus&$expand=manager",
		"/v1.0/users?$select=manager",
		"/v1.0/me?$select=bogus",
		"/v1.0/me?$select=displayName,bogus&$expand=manager",
		"/v1.0/me?$select=manager",
	} {
		if status, body := graphGet(t, h, path, jane); status != http.StatusBadRequest {
			t.Errorf("GET %s = %d %.200v, want 400", path, status, body)
		}
	}
}
