// Package e2e runs full-flow tests against a real server instance on a random
// port — the Go equivalent of the upstream e2e suite, plus byte-level parity
// checks for the JSON shapes captured from the 6.0.2 server.
package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	mockoidc "github.com/andychoi/mock-oidc"
	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/token"
)

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// repoLikeConfig mirrors this repo's mock-oidc.json (minus the login page path).
const repoLikeConfig = `{
  "interactiveLogin": true,
  "tokenCallbacks": [
    { "issuerId": "oidc", "tokenExpiry": 3600,
      "requestMappings": [
        { "requestParam": "grant_type", "match": "authorization_code",
          "claims": { "tid": "mock-tenant-id" } }
      ]
    }
  ]
}`

func startServer(t *testing.T, cfgJSON string) (*mockoidc.Server, string) {
	t.Helper()
	var cfg *config.OAuth2Config
	if cfgJSON != "" {
		var err error
		cfg, err = config.ParseJSON([]byte(cfgJSON))
		if err != nil {
			t.Fatal(err)
		}
	}
	s, err := mockoidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s, s.URL()
}

func do(t *testing.T, method, rawURL, body string, headers map[string]string) (int, http.Header, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, rdr)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func decodeClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	claims, err := oauth2.ParseJWTClaims(jwt)
	if err != nil {
		t.Fatalf("parse jwt: %v", err)
	}
	return claims
}

// --- discovery & jwks ---

func TestDiscoveryGoldenFormat(t *testing.T) {
	_, base := startServer(t, "")
	status, hdr, body := do(t, "GET", base+"/oidc/.well-known/openid-configuration", "", nil)
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if ct := hdr.Get("Content-Type"); ct != "application/json;charset=UTF-8" {
		t.Errorf("content-type %q", ct)
	}
	expected := fmt.Sprintf(`{
  "issuer" : "%[1]s/oidc",
  "authorization_endpoint" : "%[1]s/oidc/authorize",
  "end_session_endpoint" : "%[1]s/oidc/endsession",
  "revocation_endpoint" : "%[1]s/oidc/revoke",
  "token_endpoint" : "%[1]s/oidc/token",
  "userinfo_endpoint" : "%[1]s/oidc/userinfo",
  "jwks_uri" : "%[1]s/oidc/jwks",
  "introspection_endpoint" : "%[1]s/oidc/introspect",
  "response_types_supported" : [ "code", "none", "id_token", "token" ],
  "response_modes_supported" : [ "query", "fragment", "form_post" ],
  "subject_types_supported" : [ "public" ],
  "id_token_signing_alg_values_supported" : [ "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512" ],
  "code_challenge_methods_supported" : [ "plain", "S256" ]
}`, base)
	if body != expected {
		t.Errorf("discovery body mismatch:\ngot:  %s\nwant: %s", body, expected)
	}
	// oauth-authorization-server variant identical
	_, _, body2 := do(t, "GET", base+"/oidc/.well-known/oauth-authorization-server", "", nil)
	if body2 != expected {
		t.Errorf("oauth well-known should match oidc well-known")
	}
}

func TestJWKSKidAndFormat(t *testing.T) {
	_, base := startServer(t, "")
	_, _, body := do(t, "GET", base+"/oidc/jwks", "", nil)
	expectedPrefix := `{
  "keys" : [ {
    "kty" : "RSA",
    "e" : "AQAB",
    "use" : "sig",
    "kid" : "oidc",
    "alg" : "RS256",
    "n" : "`
	if !strings.HasPrefix(body, expectedPrefix) {
		t.Errorf("jwks format:\n%s", body)
	}
	if !strings.HasSuffix(body, "\n  } ]\n}") {
		t.Errorf("jwks suffix: %q", body[len(body)-24:])
	}
}

// --- grants ---

func TestClientCredentials(t *testing.T) {
	_, base := startServer(t, "")
	status, _, body := do(t, "POST", base+"/oidc/token",
		"grant_type=client_credentials&scope=read", basicAuth("gold-client", "gold-secret"))
	if status != 200 {
		t.Fatalf("status %d body %s", status, body)
	}
	var resp struct {
		TokenType   string `json:"token_type"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.TokenType != "Bearer" || resp.ExpiresIn < 3590 || resp.Scope != "read" {
		t.Errorf("token response: %+v", resp)
	}
	// field order parity
	order := []string{`"token_type"`, `"access_token"`, `"expires_in"`, `"scope"`}
	last := -1
	for _, f := range order {
		i := strings.Index(body, f)
		if i == -1 || i < last {
			t.Fatalf("token response field order: %s", body)
		}
		last = i
	}
	claims := decodeClaims(t, resp.AccessToken)
	if claims["sub"] != "gold-client" || claims["aud"] != "read" || claims["tid"] != "oidc" {
		t.Errorf("claims: %v", claims)
	}
	// public client (form client_id only) is rejected for client_credentials
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=client_credentials&client_id=x", nil)
	if status != 401 || !strings.Contains(body, `"invalid_client"`) ||
		!strings.Contains(body, "client authentication failed: missing client authentication") {
		t.Errorf("public client_credentials: %d %s", status, body)
	}
}

func authCodeURL(base, issuer string, extra string) string {
	return base + "/" + issuer + "/authorize?response_type=code&client_id=cid&redirect_uri=" +
		url.QueryEscape("http://localhost/cb") + "&scope=openid" + extra
}

func exchangeCode(t *testing.T, base, issuer, code string) (int, string) {
	t.Helper()
	status, _, body := do(t, "POST", base+"/"+issuer+"/token",
		"grant_type=authorization_code&code="+url.QueryEscape(code)+"&redirect_uri="+url.QueryEscape("http://localhost/cb"),
		basicAuth("cid", "secret"))
	return status, body
}

func TestAuthCodeImmediateAndExchange(t *testing.T) {
	_, base := startServer(t, "") // interactiveLogin defaults to false in library mode
	status, hdr, _ := do(t, "GET", authCodeURL(base, "oidc", "&state=abc&nonce=n1"), "", nil)
	if status != 302 {
		t.Fatalf("expected 302, got %d", status)
	}
	loc, _ := url.Parse(hdr.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" || loc.Query().Get("state") != "abc" {
		t.Fatalf("redirect location: %v", loc)
	}

	status, body := exchangeCode(t, base, "oidc", code)
	if status != 200 {
		t.Fatalf("exchange: %d %s", status, body)
	}
	var resp struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatal(err)
	}
	id := decodeClaims(t, resp.IDToken)
	if id["sub"] == "" || id["aud"] != "cid" || id["nonce"] != "n1" || id["tid"] != "oidc" || id["azp"] != "cid" {
		t.Errorf("id_token claims: %v", id)
	}
	at := decodeClaims(t, resp.AccessToken)
	if at["aud"] != "default" { // scope=openid is an OIDC scope
		t.Errorf("access_token aud: %v", at["aud"])
	}
	if at["nonce"] != "n1" {
		t.Errorf("access_token nonce: %v", at["nonce"])
	}
	// nonce present => refresh token is an unsigned JWT with jti+nonce
	if !strings.HasSuffix(resp.RefreshToken, ".") {
		t.Errorf("plain refresh token should end with '.': %s", resp.RefreshToken)
	}
	rf := decodeClaims(t, resp.RefreshToken)
	if rf["nonce"] != "n1" || rf["jti"] == "" {
		t.Errorf("refresh claims: %v", rf)
	}

	// code reuse fails
	status, body = exchangeCode(t, base, "oidc", code)
	if status != 400 || !strings.Contains(body, "unknown or already-used authorization code") {
		t.Errorf("code reuse: %d %s", status, body)
	}
}

func TestInteractiveLoginWithMappingAndClaimsMerge(t *testing.T) {
	_, base := startServer(t, repoLikeConfig)
	// GET shows the login page
	status, hdr, body := do(t, "GET", authCodeURL(base, "oidc", "&state=s&nonce=n"), "", nil)
	if status != 200 || !strings.Contains(hdr.Get("Content-Type"), "text/html") {
		t.Fatalf("login page: %d", status)
	}
	if !strings.Contains(body, `name="username"`) || !strings.Contains(body, `name="claims"`) {
		t.Errorf("login page form fields: %s", body[:200])
	}
	// POST login with claims JSON
	form := url.Values{}
	form.Set("username", "alice")
	form.Set("claims", `{"email":"a@b.c","groups":["g1","g2"],"tid":"login-tid-should-lose"}`)
	status, hdr, _ = do(t, "POST", authCodeURL(base, "oidc", "&state=s&nonce=n"), form.Encode(), formHeader())
	if status != 302 {
		t.Fatalf("login submit: %d", status)
	}
	loc, _ := url.Parse(hdr.Get("Location"))
	code := loc.Query().Get("code")

	status, body = exchangeCode(t, base, "oidc", code)
	if status != 200 {
		t.Fatalf("exchange: %d %s", status, body)
	}
	var resp struct {
		IDToken string `json:"id_token"`
	}
	_ = json.Unmarshal([]byte(body), &resp)
	id := decodeClaims(t, resp.IDToken)
	if id["sub"] != "alice" {
		t.Errorf("sub = %v, want login username", id["sub"])
	}
	// mapping claims (tid=mock-tenant-id) win over login claims
	if id["tid"] != "mock-tenant-id" {
		t.Errorf("tid = %v, want mock-tenant-id (mapping wins)", id["tid"])
	}
	if id["email"] != "a@b.c" || fmt.Sprint(id["groups"]) != "[g1 g2]" {
		t.Errorf("login claims merged: %v", id)
	}

	// POST without username
	status, _, body = do(t, "POST", authCodeURL(base, "oidc", ""), "claims=x", formHeader())
	if status != 400 || !strings.Contains(body, "missing required parameter username") {
		t.Errorf("missing username: %d %s", status, body)
	}
}

func TestPKCE(t *testing.T) {
	_, base := startServer(t, "")
	// S256 success
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := s256Challenge(verifier)
	status, hdr, _ := do(t, "GET", authCodeURL(base, "oidc", "&code_challenge="+challenge+"&code_challenge_method=S256"), "", nil)
	if status != 302 {
		t.Fatalf("authorize: %d", status)
	}
	loc, _ := url.Parse(hdr.Get("Location"))
	code := loc.Query().Get("code")
	status, _, body := do(t, "POST", base+"/oidc/token",
		"grant_type=authorization_code&code="+url.QueryEscape(code)+
			"&redirect_uri="+url.QueryEscape("http://localhost/cb")+"&code_verifier="+verifier, basicAuth("cid", "s"))
	if status != 200 {
		t.Fatalf("pkce exchange: %d %s", status, body)
	}

	// wrong verifier fails and burns the code
	status, hdr, _ = do(t, "GET", authCodeURL(base, "oidc", "&code_challenge="+challenge+"&code_challenge_method=S256"), "", nil)
	loc, _ = url.Parse(hdr.Get("Location"))
	code = loc.Query().Get("code")
	status, _, body = do(t, "POST", base+"/oidc/token",
		"grant_type=authorization_code&code="+url.QueryEscape(code)+
			"&redirect_uri="+url.QueryEscape("http://localhost/cb")+"&code_verifier=wrong", basicAuth("cid", "s"))
	if status != 400 || !strings.Contains(body, "invalid_pkce") {
		t.Fatalf("wrong verifier: %d %s", status, body)
	}
	// code is unusable after PKCE failure
	status, _, body = do(t, "POST", base+"/oidc/token",
		"grant_type=authorization_code&code="+url.QueryEscape(code)+
			"&redirect_uri="+url.QueryEscape("http://localhost/cb")+"&code_verifier="+verifier, basicAuth("cid", "s"))
	if status != 400 {
		t.Fatalf("code should be burned after PKCE failure: %d %s", status, body)
	}
}

func TestRefreshRotationAndErrors(t *testing.T) {
	cfgJSON := `{"interactiveLogin":false,"rotateRefreshToken":true}`
	s, base := startServer(t, cfgJSON)
	_ = s
	// mint tokens via auth code without nonce => opaque refresh token
	status, hdr, _ := do(t, "GET", authCodeURL(base, "oidc", ""), "", nil)
	loc, _ := url.Parse(hdr.Get("Location"))
	code := loc.Query().Get("code")
	_, body := exchangeCode(t, base, "oidc", code)
	var resp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal([]byte(body), &resp)

	// refresh (rotation on)
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=refresh_token&refresh_token="+url.QueryEscape(resp.RefreshToken), basicAuth("cid", "s"))
	if status != 200 {
		t.Fatalf("refresh: %d %s", status, body)
	}
	var resp2 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal([]byte(body), &resp2)
	if resp2.RefreshToken == "" || resp2.RefreshToken == resp.RefreshToken {
		t.Errorf("rotation should mint a new refresh token")
	}
	// old token now invalid
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=refresh_token&refresh_token="+url.QueryEscape(resp.RefreshToken), basicAuth("cid", "s"))
	if status != 400 || !strings.Contains(body, "unknown refresh_token") {
		t.Errorf("rotated-away token: %d %s", status, body)
	}
	// unknown token
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=refresh_token&refresh_token=bogus", basicAuth("cid", "s"))
	if status != 400 || !strings.Contains(body, "unknown refresh_token") {
		t.Errorf("unknown refresh: %d %s", status, body)
	}
	// cross-issuer: mint on /other, refresh on /oidc
	status, hdr, _ = do(t, "GET", authCodeURL(base, "other", ""), "", nil)
	loc, _ = url.Parse(hdr.Get("Location"))
	_, body = exchangeCode(t, base, "other", loc.Query().Get("code"))
	var other struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal([]byte(body), &other)
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=refresh_token&refresh_token="+url.QueryEscape(other.RefreshToken), basicAuth("cid", "s"))
	if status != 400 || !strings.Contains(body, "refresh_token was issued by a different issuer") {
		t.Errorf("cross-issuer refresh: %d %s", status, body)
	}
}

func TestPasswordGrant(t *testing.T) {
	_, base := startServer(t, "")
	status, _, body := do(t, "POST", base+"/oidc/token",
		"grant_type=password&username=bob&password=x&scope=read", basicAuth("app", "s"))
	if status != 200 {
		t.Fatalf("password: %d %s", status, body)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	_ = json.Unmarshal([]byte(body), &resp)
	if decodeClaims(t, resp.AccessToken)["sub"] != "bob" {
		t.Errorf("sub should be username")
	}
	if decodeClaims(t, resp.AccessToken)["aud"] != "read" {
		t.Errorf("aud should be non-OIDC scope")
	}
	// missing username
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=password&password=x", basicAuth("app", "s"))
	if status != 400 || !strings.Contains(body, "missing or empty username parameter") {
		t.Errorf("missing username: %d %s", status, body)
	}
}

func TestJWTBearerGrant(t *testing.T) {
	s, base := startServer(t, "")
	assertion := s.IssueToken("oidc", map[string]any{"sub": "subject", "scope": "read", "acr": "ref"}, 3600)
	status, _, body := do(t, "POST", base+"/oidc/token",
		"grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion="+url.QueryEscape(assertion), basicAuth("app", "s"))
	if status != 200 {
		t.Fatalf("jwt-bearer: %d %s", status, body)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	_ = json.Unmarshal([]byte(body), &resp)
	claims := decodeClaims(t, resp.AccessToken)
	if claims["sub"] != "subject" || claims["acr"] != "ref" || claims["iss"] != s.IssuerURL("oidc") {
		t.Errorf("carried claims: %v", claims)
	}
	if resp.Scope != "read" {
		t.Errorf("scope from assertion claim: %q", resp.Scope)
	}
	// missing assertion
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer", basicAuth("app", "s"))
	if status != 400 || !strings.Contains(body, "missing or empty assertion parameter") {
		t.Errorf("missing assertion: %d %s", status, body)
	}
}

func plainAssertion(iss, sub, aud string, expSkew int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	claims := fmt.Sprintf(`{"iss":%q,"sub":%q,"aud":%q,"exp":%d}`, iss, sub, aud, nowUnix()+expSkew)
	payload := base64.RawURLEncoding.EncodeToString([]byte(claims))
	return header + "." + payload + "."
}

func TestTokenExchangeGrant(t *testing.T) {
	s, base := startServer(t, "")
	issuerURL := s.IssuerURL("oidc")
	subjectToken := s.IssueToken("oidc", map[string]any{"sub": "acting-user", "aud": "other-api"}, 3600)
	form := url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":         {subjectToken},
		"subject_token_type":    {"urn:ietf:params:oauth:token-type:access_token"},
		"client_id":             {"ex-client"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {plainAssertion("ex-client", "ex-client", issuerURL, 60)},
	}
	status, _, body := do(t, "POST", base+"/oidc/token", form.Encode(), nil)
	if status != 200 {
		t.Fatalf("token exchange: %d %s", status, body)
	}
	var resp struct {
		AccessToken     string `json:"access_token"`
		IssuedTokenType string `json:"issued_token_type"`
	}
	_ = json.Unmarshal([]byte(body), &resp)
	if resp.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("issued_token_type: %q", resp.IssuedTokenType)
	}
	claims := decodeClaims(t, resp.AccessToken)
	if claims["sub"] != "acting-user" || claims["iss"] != issuerURL {
		t.Errorf("exchanged claims: %v", claims)
	}

	// no client auth at all
	form.Del("client_assertion")
	form.Del("client_assertion_type")
	form.Del("client_id")
	status, _, body = do(t, "POST", base+"/oidc/token", form.Encode(), nil)
	if status != 400 || !strings.Contains(body, `"invalid_request"`) {
		t.Errorf("token exchange without client auth: %d %s", status, body)
	}

	// assertion audience mismatch
	form.Set("client_id", "ex-client")
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", plainAssertion("ex-client", "ex-client", "https://evil", 60))
	status, _, body = do(t, "POST", base+"/oidc/token", form.Encode(), nil)
	if status != 400 || !strings.Contains(body, "audience should be "+issuerURL) {
		t.Errorf("bad audience: %d %s", status, body)
	}

	// expiry too far ahead
	form.Set("client_assertion", plainAssertion("ex-client", "ex-client", issuerURL, 500))
	status, _, body = do(t, "POST", base+"/oidc/token", form.Encode(), nil)
	if status != 400 || !strings.Contains(body, "expiry must be less than 120 seconds") {
		t.Errorf("long expiry: %d %s", status, body)
	}

	// iss != client_id
	form.Set("client_assertion", plainAssertion("someone-else", "ex-client", issuerURL, 60))
	status, _, body = do(t, "POST", base+"/oidc/token", form.Encode(), nil)
	if status != 400 || !strings.Contains(body, "issuer must match client_id 'ex-client'") {
		t.Errorf("iss mismatch: %d %s", status, body)
	}
}

// --- token-consuming endpoints ---

func mintAndVerifySetup(t *testing.T) (base, issuerURL, accessToken string) {
	s, base := startServer(t, "")
	return base, s.IssuerURL("oidc"), s.IssueToken("oidc", map[string]any{
		"sub": "alice", "email": "a@b.c", "scope": "openid read", "client_id": "cid", "username": "alice",
	}, 3600)
}

func TestUserinfo(t *testing.T) {
	base, _, accessToken := mintAndVerifySetup(t)
	status, hdr, body := do(t, "GET", base+"/oidc/userinfo", "", map[string]string{"Authorization": "Bearer " + accessToken})
	if status != 200 || !strings.Contains(hdr.Get("Content-Type"), "application/json") {
		t.Fatalf("userinfo: %d %s", status, body)
	}
	var claims map[string]any
	_ = json.Unmarshal([]byte(body), &claims)
	if claims["sub"] != "alice" || claims["email"] != "a@b.c" {
		t.Errorf("userinfo claims: %v", claims)
	}
	// missing/invalid token
	status, _, body = do(t, "GET", base+"/oidc/userinfo", "", nil)
	if status != 401 || !strings.Contains(body, "missing bearer token") {
		t.Errorf("no bearer: %d %s", status, body)
	}
	status, _, body = do(t, "GET", base+"/oidc/userinfo", "", map[string]string{"Authorization": "Bearer not-a-jwt"})
	if status != 401 || !strings.Contains(body, `"invalid_token"`) {
		t.Errorf("bad bearer: %d %s", status, body)
	}
}

func TestIntrospect(t *testing.T) {
	base, _, accessToken := mintAndVerifySetup(t)
	status, _, body := do(t, "POST", base+"/oidc/introspect",
		"token="+url.QueryEscape(accessToken), basicAuth("cid", "s"))
	if status != 200 {
		t.Fatalf("introspect: %d %s", status, body)
	}
	var resp map[string]any
	_ = json.Unmarshal([]byte(body), &resp)
	if resp["active"] != true || resp["sub"] != "alice" || resp["token_type"] != "Bearer" {
		t.Errorf("introspect response: %v", resp)
	}
	// inactive for garbage
	_, _, body = do(t, "POST", base+"/oidc/introspect", "token=garbage", basicAuth("cid", "s"))
	if !strings.Contains(body, `"active" : false`) {
		t.Errorf("inactive: %s", body)
	}
	// missing auth header
	status, _, body = do(t, "POST", base+"/oidc/introspect", "token=x", nil)
	if status != 401 || !strings.Contains(body, "the client authentication was invalid") {
		t.Errorf("no auth: %d %s", status, body)
	}
}

func TestRevoke(t *testing.T) {
	_, base := startServer(t, "")
	// get a refresh token
	_, hdr, _ := do(t, "GET", authCodeURL(base, "oidc", ""), "", nil)
	loc, _ := url.Parse(hdr.Get("Location"))
	_, body := exchangeCode(t, base, "oidc", loc.Query().Get("code"))
	var resp struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal([]byte(body), &resp)

	// wrong hint
	status, _, body := do(t, "POST", base+"/oidc/revoke", "token=x&token_type_hint=access_token", basicAuth("cid", "s"))
	if status != 400 || !strings.Contains(body, `"unsupported_token_type"`) {
		t.Errorf("wrong hint: %d %s", status, body)
	}
	// revoke refresh token
	status, _, _ = do(t, "POST", base+"/oidc/revoke",
		"token="+url.QueryEscape(resp.RefreshToken)+"&token_type_hint=refresh_token", basicAuth("cid", "s"))
	if status != 200 {
		t.Fatalf("revoke: %d", status)
	}
	// refresh now fails
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=refresh_token&refresh_token="+url.QueryEscape(resp.RefreshToken), basicAuth("cid", "s"))
	if status != 400 || !strings.Contains(body, "unknown refresh_token") {
		t.Errorf("revoked refresh: %d %s", status, body)
	}
}

func TestEndSession(t *testing.T) {
	_, base := startServer(t, "")
	status, hdr, _ := do(t, "GET", base+"/oidc/endsession?post_logout_redirect_uri="+url.QueryEscape("http://localhost/bye")+"&state=xyz", "", nil)
	if status != 302 || hdr.Get("Location") != "http://localhost/bye?state=xyz" {
		t.Errorf("endsession redirect: %d %q", status, hdr.Get("Location"))
	}
	status, _, body := do(t, "GET", base+"/oidc/endsession", "", nil)
	if status != 200 || body != "logged out" {
		t.Errorf("endsession plain: %d %q", status, body)
	}
}

// --- router behaviors ---

func TestRouterEdges(t *testing.T) {
	_, base := startServer(t, "")
	// GET /token -> 405
	status, _, body := do(t, "GET", base+"/oidc/token", "", nil)
	if status != 405 || body != "unsupported method" {
		t.Errorf("GET token: %d %q", status, body)
	}
	// unknown path -> 405 (upstream quirk: OPTIONS catch-all makes all paths known)
	status, _, body = do(t, "GET", base+"/oidc/nope", "", nil)
	if status != 405 || body != "method not allowed" {
		t.Errorf("unknown path: %d %q", status, body)
	}
	// unsupported grant
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=bogus&client_id=x", nil)
	if status != 400 || !strings.Contains(body, "grant_type bogus not supported.") {
		t.Errorf("bogus grant: %d %s", status, body)
	}
	// missing grant_type
	status, _, body = do(t, "POST", base+"/oidc/token", "client_id=x", nil)
	if status != 400 || !strings.Contains(body, "missing required parameter grant_type") {
		t.Errorf("missing grant: %d %s", status, body)
	}
	// authorize parse errors
	status, _, body = do(t, "GET", base+"/oidc/authorize?client_id=c", "", nil)
	if status != 400 || !strings.Contains(body, "invalid request: missing response_type parameter") {
		t.Errorf("missing response_type: %d %s", status, body)
	}
	status, _, body = do(t, "GET", base+"/oidc/authorize?response_type=code&scope=openid", "", nil)
	if status != 400 || !strings.Contains(body, "invalid request: missing client_id parameter") {
		t.Errorf("missing client_id: %d %s", status, body)
	}
	// implicit flow rejected
	status, _, body = do(t, "GET", base+"/oidc/authorize?response_type=id_token&scope=openid&client_id=c&redirect_uri="+url.QueryEscape("http://l/cb")+"&nonce=n", "", nil)
	if status != 400 || !strings.Contains(body, "hybrid og implicit flow not supported (yet).") {
		t.Errorf("implicit: %d %s", status, body)
	}
	// favicon
	status, _, _ = do(t, "GET", base+"/favicon.ico", "", nil)
	if status != 200 {
		t.Errorf("favicon: %d", status)
	}
}

func TestAuthorizeParseErrorMessages(t *testing.T) {
	_, base := startServer(t, "")
	cases := []struct {
		query string
		want  string
	}{
		{"scope=openid&client_id=c&redirect_uri=http%3A%2F%2Fl%2Fcb", "missing response_type parameter"},
		{"response_type=code&client_id=c&redirect_uri=http%3A%2F%2Fl%2Fcb", "missing scope parameter"},
		{"response_type=code&scope=openid&redirect_uri=http%3A%2F%2Fl%2Fcb", "missing client_id parameter"},
		{"response_type=code&scope=openid&client_id=c", "missing redirect_uri parameter"},
		{"response_type=bogus&scope=openid&client_id=c&redirect_uri=http%3A%2F%2Fl%2Fcb", `"unsupported_response_type"`},
	}
	for _, c := range cases {
		status, _, body := do(t, "GET", base+"/oidc/authorize?"+c.query, "", nil)
		if status != 400 || !strings.Contains(body, c.want) {
			t.Errorf("query %s: %d %s (want %s)", c.query, status, body, c.want)
		}
	}
}

func TestCORS(t *testing.T) {
	_, base := startServer(t, "")
	// preflight
	status, hdr, _ := do(t, "OPTIONS", base+"/oidc/token", "", map[string]string{
		"Origin":                         "http://x.test",
		"Access-Control-Request-Headers": "content-type,authorization",
	})
	if status != 204 {
		t.Fatalf("preflight status %d", status)
	}
	for k, want := range map[string]string{
		"Access-Control-Allow-Origin":      "http://x.test",
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Allow-Methods":     "POST, GET, OPTIONS",
		"Access-Control-Allow-Headers":     "content-type,authorization",
	} {
		if got := hdr.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// simple GET with Origin reflects origin
	_, hdr, _ = do(t, "GET", base+"/oidc/jwks", "", map[string]string{"Origin": "http://y.test"})
	if hdr.Get("Access-Control-Allow-Origin") != "http://y.test" {
		t.Errorf("origin not reflected on GET")
	}
	// no Origin header => no CORS headers
	_, hdr, _ = do(t, "GET", base+"/oidc/jwks", "", nil)
	if hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("CORS headers without Origin")
	}
}

func TestMultiIssuerDistinctKeys(t *testing.T) {
	_, base := startServer(t, "")
	_, _, jwks1 := do(t, "GET", base+"/iss-a/jwks", "", nil)
	_, _, jwks2 := do(t, "GET", base+"/iss-b/jwks", "", nil)
	if !strings.Contains(jwks1, `"kid" : "iss-a"`) || !strings.Contains(jwks2, `"kid" : "iss-b"`) {
		t.Errorf("kids should derive from issuer path")
	}
	if jwks1 == jwks2 {
		t.Errorf("issuers must use distinct keys")
	}
}

func TestRootLevelTokenIssuerQuirk(t *testing.T) {
	_, base := startServer(t, "")
	status, _, body := do(t, "POST", base+"/token", "grant_type=client_credentials", basicAuth("c", "s"))
	if status != 200 {
		t.Fatalf("root token: %d %s", status, body)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal([]byte(body), &resp)
	claims := decodeClaims(t, resp.AccessToken)
	// upstream quirk: a bare /token at the root derives issuerId "token"
	if claims["iss"] != base+"/token" || claims["tid"] != "token" {
		t.Errorf("root /token claims: iss=%v tid=%v", claims["iss"], claims["tid"])
	}
}

func TestBodyCap(t *testing.T) {
	_, base := startServer(t, "")
	big := strings.Repeat("a", (1<<20)+10)
	status, _, _ := do(t, "POST", base+"/oidc/token", "grant_type=client_credentials&x="+big, basicAuth("c", "s"))
	if status != 413 {
		t.Errorf("oversized body: %d, want 413", status)
	}
}

// --- library API ---

func TestFacadeIssueTokenAndEnqueue(t *testing.T) {
	s, base := startServer(t, "")
	tok := s.IssueToken("oidc", map[string]any{"sub": "library-user", "groups": []string{"g"}}, 1200)
	claims := decodeClaims(t, tok)
	if claims["sub"] != "library-user" || claims["tid"] != "oidc" {
		t.Errorf("issued claims: %v", claims)
	}
	// token verifies through userinfo
	status, _, body := do(t, "GET", base+"/oidc/userinfo", "", map[string]string{"Authorization": "Bearer " + tok})
	if status != 200 {
		t.Fatalf("userinfo with issued token: %d %s", status, body)
	}

	// enqueued callback overrides config defaults for the next matching request
	cb := token.NewDefaultCallback("oidc")
	cb.SubjectValue = "enqueued-subject"
	cb.Claims = map[string]any{"tid": "enqueued-tenant"}
	cb.Expiry = 600
	s.EnqueueTokenCallback(cb)
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=client_credentials", basicAuth("c", "s"))
	if status != 200 {
		t.Fatalf("client_credentials with enqueued: %d %s", status, body)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal([]byte(body), &resp)
	c2 := decodeClaims(t, resp.AccessToken)
	if c2["sub"] != "c" { // client_credentials subject is client id regardless
		t.Errorf("sub: %v", c2["sub"])
	}
	if c2["tid"] != "enqueued-tenant" {
		t.Errorf("enqueued claims should apply: tid=%v", c2["tid"])
	}
	// queue consumed: next request falls back
	status, _, body = do(t, "POST", base+"/oidc/token", "grant_type=client_credentials", basicAuth("c", "s"))
	_ = json.Unmarshal([]byte(body), &resp)
	if decodeClaims(t, resp.AccessToken)["tid"] != "oidc" {
		t.Errorf("queue should be consumed once")
	}
}

// --- helpers ---

func basicAuth(user, pass string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))}
}

func formHeader() map[string]string {
	return map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
}

func nowUnix() int64 { return time.Now().Unix() }

func s256Challenge(verifier string) string {
	d := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(d[:])
}
