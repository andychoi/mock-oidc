package e2e

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/entra"
)

const (
	tidCorp = "11111111-1111-1111-1111-111111111111"
	tidCust = "22222222-2222-2222-2222-22222222abcd"
)

const entraConfig = `{
  "interactiveLogin": true,
  "entra": {
    "tenants": [
      {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"]},
      {"tid": "22222222-2222-2222-2222-22222222abcd", "name": "Customer X", "domains": ["customer-x.example"],
       "groupClaimFormat": "object_id", "consentRequired": true, "groupLimit": 3}
    ],
    "consents": [
      {"clientId": "iam", "tid": "11111111-1111-1111-1111-111111111111"},
      {"clientId": "iam", "tid": "22222222-2222-2222-2222-22222222abcd"}
    ],
    "users": [
      {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Kim",
       "email": "jane@corp.example", "emailVerified": true, "groups": ["AMS Engineers", "PMO"],
       "amr": ["pwd", "mfa"], "admin": true},
      {"username": "unassigned", "tid": "11111111-1111-1111-1111-111111111111", "error": "access_denied"},
      {"username": "disabled", "tid": "11111111-1111-1111-1111-111111111111", "error": "invalid_grant"},
      {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd", "name": "Sam Lee",
       "email": "sam@customer-x.example", "groups": ["G1", "G2"]},
      {"username": "many", "tid": "22222222-2222-2222-2222-22222222abcd", "groups": ["G1", "G2", "G3", "G4"]},
      {"username": "custadmin", "tid": "22222222-2222-2222-2222-22222222abcd", "admin": true},
      {"username": "mfa", "tid": "22222222-2222-2222-2222-22222222abcd", "error": "interaction_required"}
    ]
  }
}`

func entraGetJSON(t *testing.T, rawURL string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	status, _, body := do(t, http.MethodGet, rawURL, "", headers)
	var m map[string]any
	if status == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("decode %s: %v\n%s", rawURL, err, body)
		}
	}
	return status, m
}

func TestEntraDiscoveryPerTenant(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	want := map[string]string{
		"issuer":                 base + "/entra/" + tidCorp + "/v2.0",
		"authorization_endpoint": base + "/entra/" + tidCorp + "/oauth2/v2.0/authorize",
		"token_endpoint":         base + "/entra/" + tidCorp + "/oauth2/v2.0/token",
		"jwks_uri":               base + "/entra/" + tidCorp + "/discovery/v2.0/keys",
		"end_session_endpoint":   base + "/entra/" + tidCorp + "/oauth2/v2.0/logout",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %v, want %v", k, doc[k], v)
		}
	}
	if _, ok := doc["userinfo_endpoint"]; ok {
		t.Error("userinfo_endpoint must be absent")
	}
}

func TestEntraDiscoveryOrganizationsTemplate(t *testing.T) {
	_, base := startServer(t, entraConfig)
	for _, seg := range []string{"organizations", "common"} {
		_, doc := entraGetJSON(t, base+"/entra/"+seg+"/v2.0/.well-known/openid-configuration", nil)
		if doc["issuer"] != base+"/entra/{tenantid}/v2.0" {
			t.Errorf("%s issuer = %v", seg, doc["issuer"])
		}
		if doc["authorization_endpoint"] != base+"/entra/"+seg+"/oauth2/v2.0/authorize" {
			t.Errorf("%s authorization_endpoint = %v", seg, doc["authorization_endpoint"])
		}
	}
}

func TestEntraTenantPathCaseInsensitive(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, doc := entraGetJSON(t, base+"/entra/"+strings.ToUpper(tidCust)+"/v2.0/.well-known/openid-configuration", nil)
	if status != http.StatusOK || doc["issuer"] != base+"/entra/"+tidCust+"/v2.0" {
		t.Fatalf("status %d issuer %v", status, doc["issuer"])
	}
}

func TestEntraUnknownTenant(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, _, body := do(t, http.MethodGet, base+"/entra/99999999-9999-9999-9999-999999999999/v2.0/.well-known/openid-configuration", "", nil)
	if status != http.StatusBadRequest || !strings.Contains(body, "aadsts90002") {
		t.Fatalf("status %d body %s", status, body)
	}
}

func TestEntraKeysSharedAcrossTenants(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, _, corp := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/discovery/v2.0/keys", "", nil)
	_, _, cust := do(t, http.MethodGet, base+"/entra/"+tidCust+"/discovery/v2.0/keys", "", nil)
	_, _, common := do(t, http.MethodGet, base+"/entra/common/discovery/v2.0/keys", "", nil)
	if corp != cust || corp != common || !strings.Contains(corp, `"entra-1"`) {
		t.Fatalf("key sets differ or missing kid:\n%s\n%s\n%s", corp, cust, common)
	}
}

func TestEntraDiscoveryHonorsForwardedHeaders(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration",
		map[string]string{"x-forwarded-proto": "https", "x-forwarded-port": "443"})
	if doc["issuer"] != "https://127.0.0.1/entra/"+tidCorp+"/v2.0" {
		t.Fatalf("issuer = %v", doc["issuer"])
	}
}

func TestEntraLogoutAndOptions(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, hdr, _ := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/oauth2/v2.0/logout?post_logout_redirect_uri=http%3A%2F%2Fapp.test%2Fbye&state=s1", "", nil)
	if status != http.StatusFound || hdr.Get("Location") != "http://app.test/bye?state=s1" {
		t.Fatalf("logout status %d location %q", status, hdr.Get("Location"))
	}
	status, _, _ = do(t, http.MethodOptions, base+"/entra/"+tidCorp+"/oauth2/v2.0/token", "", map[string]string{"Origin": "http://app.test"})
	if status != http.StatusNoContent {
		t.Fatalf("OPTIONS status %d", status)
	}
}

func TestEntraBuiltinsNotShadowed(t *testing.T) {
	_, base := startServer(t, entraConfig)
	// the built-in issuer keeps working next to Entra mode
	_, doc := entraGetJSON(t, base+"/oidc/.well-known/openid-configuration", nil)
	if doc["issuer"] != base+"/oidc" {
		t.Fatalf("built-in issuer = %v", doc["issuer"])
	}
	// a path under /entra that ends in a built-in suffix is Entra's (404), not the built-in GET /token (405)
	status, _, _ := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/token", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("GET /entra/{tid}/token status %d, want 404", status)
	}
}

func TestEntraRoutesAbsentWhenDisabled(t *testing.T) {
	_, base := startServer(t, repoLikeConfig)
	_, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil)
	if _, entra := doc["tenant_region_scope"]; entra {
		t.Fatal("Entra discovery served although Entra mode is off")
	}
}

const entraRedirect = "http://app.test/cb"

func entraAuthorizeURL(base, seg, clientID, extra string) string {
	return base + "/entra/" + seg + "/oauth2/v2.0/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape(entraRedirect) + "&scope=" + url.QueryEscape("openid profile email") +
		"&state=st1&nonce=n1" + extra
}

var formHeaders = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

// entraSignIn posts an account choice and returns the redirect Location.
func entraSignIn(t *testing.T, authorizeURL, tid, username string) *url.URL {
	t.Helper()
	form := url.Values{"tid": {tid}, "username": {username}}.Encode()
	status, hdr, body := do(t, http.MethodPost, authorizeURL, form, formHeaders)
	if status != http.StatusFound {
		t.Fatalf("sign-in status %d: %s", status, body)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// entraRedeem exchanges a code at the {seg} token endpoint.
func entraRedeem(t *testing.T, base, seg, clientID, code, extraForm string, headers map[string]string) (int, map[string]any, string) {
	t.Helper()
	form := "grant_type=authorization_code&client_id=" + clientID + "&client_secret=s&code=" + url.QueryEscape(code) +
		"&redirect_uri=" + url.QueryEscape(entraRedirect) + extraForm
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for k, v := range headers {
		h[k] = v
	}
	status, _, body := do(t, http.MethodPost, base+"/entra/"+seg+"/oauth2/v2.0/token", form, h)
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	return status, m, body
}

// verifyEntraJWT checks the RS256 signature against the shared JWKS and returns the claims.
func verifyEntraJWT(t *testing.T, base, jwt string) map[string]any {
	t.Helper()
	_, _, jwks := do(t, http.MethodGet, base+"/entra/common/discovery/v2.0/keys", "", nil)
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", jwt)
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr struct{ Kid, Alg string }
	_ = json.Unmarshal(hb, &hdr)
	var doc struct {
		Keys []struct{ Kid, N, E string } `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range doc.Keys {
		if k.Kid != hdr.Kid {
			continue
		}
		n, _ := base64.RawURLEncoding.DecodeString(k.N)
		e, _ := base64.RawURLEncoding.DecodeString(k.E)
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("signature: %v", err)
		}
		return decodeClaims(t, jwt)
	}
	t.Fatalf("kid %q not in JWKS %s", hdr.Kid, jwks)
	return nil
}

func strList(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}

func TestEntraPickerScopes(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, _, page := do(t, http.MethodGet, entraAuthorizeURL(base, tidCorp, "iam", ""), "", nil)
	if !strings.Contains(page, `value="jane"`) || strings.Contains(page, `value="sam"`) {
		t.Errorf("tenant picker must list only corp users:\n%s", page)
	}
	_, _, page = do(t, http.MethodGet, entraAuthorizeURL(base, "organizations", "iam", ""), "", nil)
	if !strings.Contains(page, `value="jane"`) || !strings.Contains(page, `value="sam"`) || !strings.Contains(page, "Customer X") {
		t.Errorf("organizations picker must list all tenants:\n%s", page)
	}
}

func TestEntraTenantSignInAndTokens(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "jane")
	if loc.Query().Get("state") != "st1" || loc.Query().Get("code") == "" {
		t.Fatalf("redirect = %s", loc)
	}
	status, tok, body := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", nil)
	if status != http.StatusOK || tok["token_type"] != "Bearer" || tok["access_token"] == nil {
		t.Fatalf("token status %d: %s", status, body)
	}
	if _, ok := tok["refresh_token"]; ok {
		t.Error("refresh_token only with offline_access")
	}
	c := verifyEntraJWT(t, base, tok["id_token"].(string))
	if c["iss"] != base+"/entra/"+tidCorp+"/v2.0" || c["tid"] != tidCorp || c["aud"] != "iam" || c["nonce"] != "n1" || c["ver"] != "2.0" {
		t.Errorf("claims = %v", c)
	}
	if c["email"] != "jane@corp.example" || c["xms_edov"] != true || !reflect.DeepEqual(strList(c["amr"]), []string{"pwd", "mfa"}) {
		t.Errorf("email/edov/amr = %v %v %v", c["email"], c["xms_edov"], c["amr"])
	}
	if !reflect.DeepEqual(strList(c["groups"]), []string{"AMS Engineers", "PMO"}) {
		t.Errorf("groups = %v", c["groups"])
	}
	if c["sub"] != entra.PairwiseSub("iam", c["oid"].(string)) {
		t.Errorf("sub %v is not pairwise for oid %v", c["sub"], c["oid"])
	}
}

func TestEntraOrganizationsSignIn(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, "organizations", "iam", ""), tidCust, "sam")
	status, tok, body := entraRedeem(t, base, "organizations", "iam", loc.Query().Get("code"), "", nil)
	if status != http.StatusOK {
		t.Fatalf("token status %d: %s", status, body)
	}
	c := verifyEntraJWT(t, base, tok["id_token"].(string))
	if c["iss"] != base+"/entra/"+tidCust+"/v2.0" || c["tid"] != tidCust {
		t.Errorf("iss/tid must come from the user's tenant: %v %v", c["iss"], c["tid"])
	}
	want := []string{entra.GroupObjectID(tidCust, "G1"), entra.GroupObjectID(tidCust, "G2")}
	if !reflect.DeepEqual(strList(c["groups"]), want) {
		t.Errorf("object-ID groups = %v, want %v", c["groups"], want)
	}
}

func TestEntraGroupOverage(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCust, "iam", ""), tidCust, "many")
	_, tok, _ := entraRedeem(t, base, tidCust, "iam", loc.Query().Get("code"), "", nil)
	c := verifyEntraJWT(t, base, tok["id_token"].(string))
	if _, ok := c["groups"]; ok {
		t.Error("groups must be omitted on overage")
	}
	names, _ := c["_claim_names"].(map[string]any)
	if names["groups"] != "src1" {
		t.Errorf("_claim_names = %v", c["_claim_names"])
	}
}

func TestEntraConsentRequired(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCust, "newapp", ""), tidCust, "sam")
	q := loc.Query()
	if q.Get("error") != "consent_required" || q.Get("state") != "st1" || !strings.Contains(q.Get("error_description"), "AADSTS65001") {
		t.Fatalf("redirect = %s", loc)
	}
	// corp does not require consent: any client may sign in there
	loc = entraSignIn(t, entraAuthorizeURL(base, tidCorp, "newapp", ""), tidCorp, "jane")
	if loc.Query().Get("code") == "" {
		t.Fatalf("corp sign-in for newapp = %s", loc)
	}
}

func TestEntraErrorInjection(t *testing.T) {
	_, base := startServer(t, entraConfig)
	if q := entraSignIn(t, entraAuthorizeURL(base, tidCust, "iam", ""), tidCust, "mfa").Query(); q.Get("error") != "interaction_required" || !strings.Contains(q.Get("error_description"), "AADSTS50076") {
		t.Errorf("mfa user = %v", q)
	}
	if q := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "unassigned").Query(); q.Get("error") != "access_denied" || !strings.Contains(q.Get("error_description"), "AADSTS50105") {
		t.Errorf("unassigned user = %v", q)
	}
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "disabled")
	status, _, body := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", nil)
	if status != http.StatusBadRequest || !strings.Contains(body, "aadsts50057") {
		t.Errorf("disabled user token: %d %s", status, body)
	}
}

func TestEntraCodeRules(t *testing.T) {
	_, base := startServer(t, entraConfig)
	code := func(seg, tid, user, extra string) string {
		return entraSignIn(t, entraAuthorizeURL(base, seg, "iam", extra), tid, user).Query().Get("code")
	}
	// single use
	c1 := code(tidCorp, tidCorp, "jane", "")
	if s, _, _ := entraRedeem(t, base, tidCorp, "iam", c1, "", nil); s != http.StatusOK {
		t.Fatalf("first redemption %d", s)
	}
	if s, _, body := entraRedeem(t, base, tidCorp, "iam", c1, "", nil); s != http.StatusBadRequest || !strings.Contains(body, "aadsts70008") {
		t.Errorf("replay: %d %s", s, body)
	}
	// cross-tenant redemption
	c2 := code("organizations", tidCorp, "jane", "")
	if s, _, _ := entraRedeem(t, base, tidCust, "iam", c2, "", nil); s != http.StatusBadRequest {
		t.Errorf("code from organizations(corp user) redeemed at customer tenant: %d", s)
	}
	// user's own tenant path is allowed for an organizations code
	c3 := code("organizations", tidCorp, "jane", "")
	if s, _, body := entraRedeem(t, base, tidCorp, "iam", c3, "", nil); s != http.StatusOK {
		t.Errorf("organizations code at user's tenant path: %d %s", s, body)
	}
	// client and redirect must match
	if s, _, _ := entraRedeem(t, base, tidCorp, "other", code(tidCorp, tidCorp, "jane", ""), "", nil); s != http.StatusBadRequest {
		t.Errorf("client mismatch: %d", s)
	}
	c4 := code(tidCorp, tidCorp, "jane", "")
	form := "grant_type=authorization_code&client_id=iam&code=" + url.QueryEscape(c4) + "&redirect_uri=" + url.QueryEscape("http://evil.test/cb")
	if s, _, _ := do(t, http.MethodPost, base+"/entra/"+tidCorp+"/oauth2/v2.0/token", form, formHeaders); s != http.StatusBadRequest {
		t.Errorf("redirect mismatch: %d", s)
	}
	// PKCE S256
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	pkce := "&code_challenge=" + base64.RawURLEncoding.EncodeToString(sum[:]) + "&code_challenge_method=S256"
	if s, _, body := entraRedeem(t, base, tidCorp, "iam", code(tidCorp, tidCorp, "jane", pkce), "", nil); s != http.StatusBadRequest || !strings.Contains(body, "aadsts501481") {
		t.Errorf("missing verifier: %d %s", s, body)
	}
	if s, _, body := entraRedeem(t, base, tidCorp, "iam", code(tidCorp, tidCorp, "jane", pkce), "&code_verifier="+verifier, nil); s != http.StatusOK {
		t.Errorf("correct verifier: %d %s", s, body)
	}
}

func TestEntraPostedUserOutsideRouteTenant(t *testing.T) {
	_, base := startServer(t, entraConfig)
	form := url.Values{"tid": {tidCust}, "username": {"sam"}}.Encode()
	status, _, body := do(t, http.MethodPost, entraAuthorizeURL(base, tidCorp, "iam", ""), form, formHeaders)
	if status != http.StatusBadRequest || !strings.Contains(body, "aadsts50020") {
		t.Fatalf("status %d body %s", status, body)
	}
}

func TestEntraUnsupportedResponseType(t *testing.T) {
	_, base := startServer(t, entraConfig)
	u := strings.Replace(entraAuthorizeURL(base, tidCorp, "iam", ""), "response_type=code", "response_type=id_token", 1)
	status, hdr, _ := do(t, http.MethodGet, u, "", nil)
	loc, _ := url.Parse(hdr.Get("Location"))
	if status != http.StatusFound || loc.Query().Get("error") != "unsupported_response_type" {
		t.Fatalf("status %d location %s", status, hdr.Get("Location"))
	}
}

func TestEntraUnsupportedGrantIsEntraError(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, _, body := do(t, http.MethodPost, base+"/entra/"+tidCorp+"/oauth2/v2.0/token",
		"grant_type=client_credentials&client_id=iam&client_secret=s&scope=x", formHeaders)
	if status != http.StatusBadRequest || !strings.Contains(body, "unsupported_grant_type") {
		t.Fatalf("status %d body %s (a 200 here means the built-in token handler answered)", status, body)
	}
}

func TestEntraTokenIssuerHonorsForwardedHeaders(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "jane")
	fwd := map[string]string{"x-forwarded-proto": "https", "x-forwarded-port": "443"}
	_, tok, body := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", fwd)
	idt, ok := tok["id_token"].(string)
	if !ok {
		t.Fatalf("no id_token: %s", body)
	}
	if c := decodeClaims(t, idt); c["iss"] != "https://127.0.0.1/entra/"+tidCorp+"/v2.0" {
		t.Fatalf("iss = %v", c["iss"])
	}
}
