package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// adminJSON round-trips one admin-API JSON call.
func adminJSON(t *testing.T, method, rawURL, payload string) (int, map[string]any) {
	t.Helper()
	status, _, raw := do(t, method, rawURL, payload, map[string]string{"Content-Type": "application/json"})
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("%s %s: decode: %v\n%s", method, rawURL, err, raw)
	}
	return status, m
}

// loginHintCode resolves login_hint to a single account and returns the code
// issued at the redirect URI (no picker round-trip).
func loginHintCode(t *testing.T, base, seg, clientID, redirectURI, hint string) string {
	t.Helper()
	u := base + "/entra/" + seg + "/oauth2/v2.0/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirectURI) + "&scope=" + url.QueryEscape("openid profile email") +
		"&state=e2e&login_hint=" + url.QueryEscape(hint)
	status, hdr, raw := do(t, http.MethodGet, u, "", nil)
	if status != http.StatusFound {
		t.Fatalf("login_hint sign-in status %d: %s", status, raw)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query().Get("code")
}

func redeemWithSecret(t *testing.T, base, seg, clientID, redirectURI, code, secret string) (int, map[string]any, string) {
	t.Helper()
	form := "grant_type=authorization_code&client_id=" + url.QueryEscape(clientID) +
		"&code=" + url.QueryEscape(code) + "&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&client_secret=" + url.QueryEscape(secret)
	status, _, raw := do(t, http.MethodPost, base+"/entra/"+seg+"/oauth2/v2.0/token", form, formHeaders)
	var m map[string]any
	_ = json.Unmarshal([]byte(raw), &m)
	return status, m, raw
}

// One app registration driven through the whole surface: the admin API creates
// it, the authorize endpoint enforces its redirect list and client secret, and
// an unregistered client keeps the permissive default.
func TestEntraAppRegistrationEndToEnd(t *testing.T) {
	_, base := startServer(t, entraConfig)
	redirect := "http://localhost:8123/cb"

	status, app := adminJSON(t, http.MethodPost, base+"/admin/api/entra/apps",
		`{"name":"E2E Portal","tid":"`+tidCorp+`","redirectUris":[{"platform":"web","uri":"`+redirect+`"}]}`)
	if status != http.StatusOK {
		t.Fatalf("create app: %d %v", status, app)
	}
	clientID, _ := app["clientId"].(string)
	if clientID == "" || app["objectId"] == "" || app["signInAudience"] != "AzureADMyOrg" {
		t.Fatalf("created app = %v", app)
	}

	code := loginHintCode(t, base, tidCorp, clientID, redirect, "jane")
	if code == "" {
		t.Fatal("no code issued at the registered redirect URI")
	}
	status, tok, raw := redeemWithSecret(t, base, tidCorp, clientID, redirect, code, "")
	if status != http.StatusOK {
		t.Fatalf("token exchange: %d %s", status, raw)
	}
	if claims := verifyEntraJWT(t, base, tok["id_token"].(string)); claims["aud"] != clientID {
		t.Errorf("id_token aud = %v, want the registered client", claims["aud"])
	}

	mismatch := base + "/entra/" + tidCorp + "/oauth2/v2.0/authorize?response_type=code&client_id=" +
		url.QueryEscape(clientID) + "&redirect_uri=" + url.QueryEscape("https://evil.test/cb") + "&scope=openid"
	if status, _, raw = do(t, http.MethodGet, mismatch, "", nil); status != http.StatusBadRequest || !strings.Contains(raw, "aadsts50011") {
		t.Errorf("mismatched redirect_uri: %d %s", status, raw)
	}

	status, sec := adminJSON(t, http.MethodPost, base+"/admin/api/entra/apps/"+clientID+"/secrets",
		`{"description":"ci","expires":"12m"}`)
	if status != http.StatusOK || sec["value"] == "" {
		t.Fatalf("add secret: %d %v", status, sec)
	}

	code = loginHintCode(t, base, tidCorp, clientID, redirect, "jane")
	status, errTok, raw := redeemWithSecret(t, base, tidCorp, clientID, redirect, code, "wrong-secret")
	if status != http.StatusUnauthorized || errTok["error"] != "invalid_client" || !strings.Contains(raw, "aadsts7000215") {
		t.Errorf("wrong secret: %d %s", status, raw)
	}
	code = loginHintCode(t, base, tidCorp, clientID, redirect, "jane")
	if status, _, raw = redeemWithSecret(t, base, tidCorp, clientID, redirect, code, sec["value"].(string)); status != http.StatusOK {
		t.Errorf("right secret: %d %s", status, raw)
	}

	// A client with no registration signs in and redeems exactly as before.
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "stranger", ""), tidCorp, "jane")
	if status, _, raw = entraRedeem(t, base, tidCorp, "stranger", loc.Query().Get("code"), "", nil); status != http.StatusOK {
		t.Errorf("unregistered client: %d %s", status, raw)
	}
}
