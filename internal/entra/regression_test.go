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
