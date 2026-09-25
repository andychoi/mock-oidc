package token

import (
	"strings"
	"testing"
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
)

func newTestProvider(t *testing.T) *TokenProvider {
	t.Helper()
	kp, err := DefaultKeyProvider("RS256")
	if err != nil {
		t.Fatal(err)
	}
	return NewTokenProvider(kp, nil)
}

// initialkey-1's public modulus, captured from the live 6.0.2 server (first
// issuer draws initialkey-1 rebuilt with kid = issuerId).
const goldenInitialN = "onZcB1ryWS1keTIcbgsLKJ1UBwL1Wbzse5P2HjkrNwbG3Jy2lefUEcTVJxN8bpLeW460Luz3ScZd3d9p8IoHjmhZ2cyO49E41aBRIlBRzWNpebK5xeC95rSKenYHpOPlLzPgybg2qxallzQUOcKCheiF0fsErlapaA9YmKwzP3DwvzYW4JqSrHhDGWPwUCcsR4dpetwKXP_9tRFso06ryr4um3qiq7giyZEyZVG3fHMplD-5e-2-RrzBiGFW_zvs-XVRGPIf9Y5YNjeQJRuS4vF82V8mNZxEZddtUY5plSz-vgX3GSvANLDH-LZJ76Zmx3a8dEZbI7VxgsBQAqcUlQ"

func TestKeyProviderDeterministicInitialKeys(t *testing.T) {
	p1 := newTestProvider(t)
	p2 := newTestProvider(t)
	j1 := p1.PublicJWKS("oidc")
	j2 := p2.PublicJWKS("oidc")
	if j1 != j2 {
		t.Errorf("two providers produced different JWKS for the same issuer")
	}
	if !strings.Contains(j1, `"kid" : "oidc"`) {
		t.Errorf("kid not derived from issuerId:\n%s", j1)
	}
	if !strings.Contains(j1, goldenInitialN) {
		t.Errorf("first issuer did not draw initialkey-1 (modulus mismatch)")
	}
	// JWKS field order parity (RSA: kty,e,use,kid,alg,n)
	wantOrder := []string{`"kty" : "RSA"`, `"e" : "AQAB"`, `"use" : "sig"`, `"kid" : "oidc"`, `"alg" : "RS256"`, `"n" :`}
	pos := -1
	for _, w := range wantOrder {
		i := strings.Index(j1, w)
		if i == -1 || i < pos {
			t.Fatalf("JWKS field order mismatch around %q:\n%s", w, j1)
		}
		pos = i
	}
}

func TestKeyProviderDistinctKidsAndDepletion(t *testing.T) {
	p := newTestProvider(t)
	first := p.PublicJWKS("a")
	second := p.PublicJWKS("b")
	if first == second || strings.Contains(second, goldenInitialN) && strings.Contains(first, goldenInitialN) {
		// different kids guarantee different output regardless
		if !strings.Contains(second, `"kid" : "b"`) {
			t.Errorf("second issuer kid mismatch:\n%s", second)
		}
	}
	// same issuer is stable
	if p.PublicJWKS("a") != first {
		t.Errorf("signing key not stable per issuer")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	p := newTestProvider(t)
	req := &oauth2.TokenRequest{GrantType: oauth2.GrantClientCredentials, ClientID: "c1", Scope: "read", ScopeList: []string{"read"}}
	cb := NewDefaultCallback("oidc")
	tok := p.AccessToken(req, "http://h/oidc", "oidc", cb, "")
	claims, err := p.Verify("http://h/oidc", tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims["iss"] != "http://h/oidc" {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["sub"] != "c1" {
		t.Errorf("client_credentials sub should be client id, got %v", claims["sub"])
	}
	if claims["aud"] != "read" {
		t.Errorf("aud = %v (want scope echo)", claims["aud"])
	}
	if claims["tid"] != "oidc" {
		t.Errorf("tid = %v", claims["tid"])
	}
	// wrong issuer fails
	if _, err := p.Verify("http://h/other", tok); err == nil {
		t.Errorf("verify with wrong issuer should fail")
	}
}

func TestSystemTimeFreezesDates(t *testing.T) {
	frozen := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	kp, _ := DefaultKeyProvider("RS256")
	p := NewTokenProvider(kp, &frozen)
	req := &oauth2.TokenRequest{GrantType: oauth2.GrantClientCredentials, ClientID: "c", ClientAuthMethod: oauth2.AuthMethodBasic}
	tok := p.AccessToken(req, "http://h/oidc", "oidc", NewDefaultCallback("oidc"), "")
	claims, _ := oauth2.ParseJWTClaims(tok)
	if got := int64(claims["iat"].(float64)); got != frozen.Unix() {
		t.Errorf("iat = %d, want %d", got, frozen.Unix())
	}
	// verify against frozen clock still works
	if _, err := p.Verify("http://h/oidc", tok); err != nil {
		t.Errorf("verify with systemTime: %v", err)
	}
}

func TestES256Signing(t *testing.T) {
	kp, err := DefaultKeyProvider("ES256")
	if err != nil {
		t.Fatal(err)
	}
	p := NewTokenProvider(kp, nil)
	req := &oauth2.TokenRequest{GrantType: oauth2.GrantClientCredentials, ClientID: "c", ClientAuthMethod: oauth2.AuthMethodBasic}
	tok := p.AccessToken(req, "http://h/default", "default", NewDefaultCallback("default"), "")
	if _, err := p.Verify("http://h/default", tok); err != nil {
		t.Fatalf("ES256 verify: %v", err)
	}
	if !strings.Contains(p.PublicJWKS("default"), `"kty" : "EC"`) {
		t.Errorf("EC JWKS expected")
	}
}

func TestUnsupportedAlgorithm(t *testing.T) {
	if _, err := DefaultKeyProvider("HS256"); err == nil {
		t.Errorf("HS256 should be rejected")
	}
	if _, err := DefaultKeyProvider("ES512"); err == nil {
		t.Errorf("ES512 should be rejected (upstream parity)")
	}
}
