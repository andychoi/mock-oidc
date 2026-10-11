package entra

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
)

const verifyJSON = `{
  "tenants": [
    {"tid": "11111111-1111-1111-1111-111111111111", "domains": ["corp.example"]},
    {"tid": "22222222-2222-2222-2222-22222222abcd"}
  ],
  "users": [
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111"},
    {"username": "off", "tid": "11111111-1111-1111-1111-111111111111", "accountEnabled": false}
  ]
}`

var verifyNow = time.Unix(1790000000, 0)

// verifyHandler builds a handler on a frozen clock, plus a request whose
// origin the minted tokens are issued for.
func verifyHandler(t *testing.T, cfgJSON string) (*Handler, *oauth2.Request) {
	t.Helper()
	cfg, err := ParseConfig([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	h := New(cfg, WithClock(func() time.Time { return verifyNow }))
	return h, graphRequest(t, "http://mock.test/entra/graph/v1.0/me", "")
}

// graphRequest builds a GET request the way the router delivers one, so the
// scheme and host behind ProxyAwareURL are real.
func graphRequest(t *testing.T, raw, bearer string) *oauth2.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, raw, nil)
	if bearer != "" {
		r.Header.Set("Authorization", bearer)
	}
	req, err := oauth2.FromHTTPRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// mintAccess signs an access token for a user, the way the token endpoint does.
func mintAccess(h *Handler, req *oauth2.Request, username string, mutate func(map[string]any)) string {
	cfg := h.conf()
	u := cfg.User(tidA, username)
	in := TokenInput{Origin: origin(req), BasePath: cfg.BasePath, Tenant: cfg.Tenant(u.TID), User: u,
		ClientID: "app", Scopes: []string{"openid"}, Now: h.now(), Expiry: cfg.TokenExpiry}
	claims := AccessTokenClaims(in)
	if mutate != nil {
		mutate(claims)
	}
	return h.keys.Sign(claims)
}

func TestKeySetVerifyRoundTrip(t *testing.T) {
	ks := NewKeySet()
	jwt := ks.Sign(map[string]any{"sub": "u1", "n": float64(7)})
	header, claims, ok := ks.Verify(jwt)
	if !ok {
		t.Fatal("a freshly signed token must verify")
	}
	if header["kid"] != "entra-1" || header["alg"] != "RS256" || claims["sub"] != "u1" {
		t.Errorf("header=%v claims=%v", header, claims)
	}
}

func TestKeySetVerifyRejectsMalformedAndTampered(t *testing.T) {
	ks := NewKeySet()
	jwt := ks.Sign(map[string]any{"sub": "u1"})
	other := NewKeySet().Sign(map[string]any{"sub": "u1"})
	cases := map[string]string{
		"empty":            "",
		"two parts":        "a.b",
		"garbage":          "a.b.c",
		"tampered payload": jwt[:len(jwt)-6] + "AAAAAA",
		"foreign key":      other, // same kid, different key material
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := ks.Verify(tok); ok {
				t.Fatal("must not verify")
			}
		})
	}
}

// A token minted before a rotation keeps working while its key is published,
// and stops the moment the key drops out of the set.
func TestKeySetVerifyAcceptsPreviousKeyUntilDropped(t *testing.T) {
	ks := NewKeySet()
	jwt := ks.Sign(map[string]any{"sub": "u1"})
	ks.Rotate()
	if _, _, ok := ks.Verify(jwt); !ok {
		t.Fatal("one rotation must not invalidate an outstanding token")
	}
	ks.Rotate()
	if _, _, ok := ks.Verify(jwt); ok {
		t.Fatal("a dropped key must stop verifying")
	}
}

func TestValidateAccessTokenHappyPath(t *testing.T) {
	h, req := verifyHandler(t, verifyJSON)
	bearer := mintAccess(h, req, "jane", nil)
	caller, gerr := h.ValidateAccessToken(req, h.conf(), bearer)
	if gerr != nil {
		t.Fatalf("validate: %+v", gerr)
	}
	if !caller.Delegated() || caller.User.Username != "jane" || caller.TID != tidA {
		t.Fatalf("caller = %+v", caller)
	}
	if caller.OID != h.conf().User(tidA, "jane").OID {
		t.Errorf("oid = %s", caller.OID)
	}
	// Caller.ClientID reads azp/appid, which the access token starts carrying
	// in task 7; it is asserted there.
}

func TestValidateAccessTokenAppOnly(t *testing.T) {
	h, req := verifyHandler(t, verifyJSON)
	bearer := mintAccess(h, req, "jane", func(c map[string]any) { delete(c, "oid") })
	caller, gerr := h.ValidateAccessToken(req, h.conf(), bearer)
	if gerr != nil {
		t.Fatalf("validate: %+v", gerr)
	}
	if caller.Delegated() || caller.User != nil || caller.OID != "" {
		t.Fatalf("a token without oid is app-only, got %+v", caller)
	}
}

func TestValidateAccessTokenRejects(t *testing.T) {
	h, req := verifyHandler(t, verifyJSON)
	idToken := func() string {
		cfg := h.conf()
		u := cfg.User(tidA, "jane")
		return h.keys.Sign(IDTokenClaims(TokenInput{Origin: origin(req), BasePath: cfg.BasePath,
			Tenant: cfg.Tenant(u.TID), User: u, ClientID: "app", Now: h.now(), Expiry: 3600}))
	}()
	otherOrigin := graphRequest(t, "http://elsewhere.test/entra/graph/v1.0/me", "")

	cases := map[string]string{
		"empty":            "",
		"not a jws":        "abc",
		"id token":         idToken, // aud is the client, not Graph
		"unknown kid":      NewKeySet().Sign(map[string]any{"sub": "x"}),
		"wrong audience":   mintAccess(h, req, "jane", func(c map[string]any) { c["aud"] = "api://other" }),
		"wrong version":    mintAccess(h, req, "jane", func(c map[string]any) { c["ver"] = "1.0" }),
		"no tid":           mintAccess(h, req, "jane", func(c map[string]any) { delete(c, "tid") }),
		"unknown tenant":   mintAccess(h, req, "jane", func(c map[string]any) { c["tid"] = "99999999-9999-9999-9999-999999999999" }),
		"mismatched tid":   mintAccess(h, req, "jane", func(c map[string]any) { c["tid"] = tidB }),
		"foreign issuer":   mintAccess(h, otherOrigin, "jane", nil),
		"no exp":           mintAccess(h, req, "jane", func(c map[string]any) { delete(c, "exp") }),
		"expired":          mintAccess(h, req, "jane", func(c map[string]any) { c["exp"] = verifyNow.Unix() - 3600 }),
		"not yet valid":    mintAccess(h, req, "jane", func(c map[string]any) { c["nbf"] = verifyNow.Unix() + 3600 }),
		"unknown oid":      mintAccess(h, req, "jane", func(c map[string]any) { c["oid"] = "99999999-9999-9999-9999-999999999999" }),
		"disabled account": mintAccess(h, req, "off", nil),
	}
	for name, bearer := range cases {
		t.Run(name, func(t *testing.T) {
			caller, gerr := h.ValidateAccessToken(req, h.conf(), bearer)
			if gerr == nil {
				t.Fatalf("must be rejected, got %+v", caller)
			}
			// Always the same opaque answer: the error must not say which
			// check failed, or it becomes a directory probe.
			if gerr.Status != http.StatusUnauthorized || gerr.Code != CodeInvalidAuthenticationToken ||
				gerr.Message != "Access token is empty or invalid." {
				t.Errorf("error = %+v", gerr)
			}
		})
	}
}

// A token minted for one origin must not be accepted on another, or a mock
// behind a proxy would accept tokens addressed elsewhere.
func TestValidateAccessTokenIsOriginBound(t *testing.T) {
	h, req := verifyHandler(t, verifyJSON)
	fwd := graphRequest(t, "http://mock.test/entra/graph/v1.0/me", "")
	fwd.Header.Set("x-forwarded-proto", "https")
	fwd.Header.Set("x-forwarded-port", "443")

	plain := mintAccess(h, req, "jane", nil)
	forwarded := mintAccess(h, fwd, "jane", nil)
	if _, gerr := h.ValidateAccessToken(fwd, h.conf(), plain); gerr == nil {
		t.Error("a token minted without the forwarded headers must not pass behind the proxy")
	}
	if _, gerr := h.ValidateAccessToken(fwd, h.conf(), forwarded); gerr != nil {
		t.Errorf("a token minted behind the proxy must pass there: %+v", gerr)
	}
	if _, gerr := h.ValidateAccessToken(req, h.conf(), forwarded); gerr == nil {
		t.Error("and must not pass on the direct origin")
	}
}

func TestValidateAccessTokenClockSkew(t *testing.T) {
	// 30 seconds past exp: inside the default 60s leeway, outside a zero one.
	stale := func(c map[string]any) { c["exp"] = verifyNow.Unix() - 30 }

	h, req := verifyHandler(t, verifyJSON)
	if _, gerr := h.ValidateAccessToken(req, h.conf(), mintAccess(h, req, "jane", stale)); gerr != nil {
		t.Errorf("default skew must tolerate 30s: %+v", gerr)
	}

	strict, sreq := verifyHandler(t, `{"graph": {"clockSkew": 0},
		"tenants": [{"tid": "`+tidA+`"}], "users": [{"username": "jane", "tid": "`+tidA+`"}]}`)
	if _, gerr := strict.ValidateAccessToken(sreq, strict.conf(), mintAccess(strict, sreq, "jane", stale)); gerr == nil {
		t.Error("clockSkew 0 must reject an expired token")
	}
}

func TestBearerToken(t *testing.T) {
	cases := map[string]string{
		"Bearer abc":     "abc",
		"bearer abc":     "abc",
		"Bearer   abc  ": "abc",
		"Basic abc":      "",
		"abc":            "",
		"":               "",
	}
	for header, want := range cases {
		if got := BearerToken(graphRequest(t, "http://h/x", header)); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}
