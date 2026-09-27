package entra

import (
	"reflect"
	"testing"
)

func TestKeySetStartsWithOneKey(t *testing.T) {
	ks := NewKeySet()
	if ks.ActiveKid() != "entra-1" {
		t.Fatalf("active kid = %s", ks.ActiveKid())
	}
	if got := jwksKids(t, ks.JWKS()); !reflect.DeepEqual(got, []string{"entra-1"}) {
		t.Fatalf("kids = %v", got)
	}
}

func TestKeySetRotateKeepsOnePreviousKey(t *testing.T) {
	ks := NewKeySet()
	if kid := ks.Rotate(); kid != "entra-2" {
		t.Fatalf("rotate = %s", kid)
	}
	if got := jwksKids(t, ks.JWKS()); !reflect.DeepEqual(got, []string{"entra-1", "entra-2"}) {
		t.Fatalf("after 1 rotation kids = %v", got)
	}
	ks.Rotate()
	if got := jwksKids(t, ks.JWKS()); !reflect.DeepEqual(got, []string{"entra-2", "entra-3"}) {
		t.Fatalf("after 2 rotations kids = %v", got)
	}
}

func TestKeySetSignsWithActiveKey(t *testing.T) {
	ks := NewKeySet()
	old := ks.Sign(map[string]any{"sub": "a"})
	ks.Rotate()
	fresh := ks.Sign(map[string]any{"sub": "b"})
	jwks := ks.JWKS()
	if h, _ := verifyWithJWKS(t, jwks, old); h["kid"] != "entra-1" {
		t.Errorf("old token kid = %v", h["kid"])
	}
	h, c := verifyWithJWKS(t, jwks, fresh)
	if h["kid"] != "entra-2" || h["alg"] != "RS256" || h["typ"] != "JWT" || c["sub"] != "b" {
		t.Errorf("fresh token header=%v claims=%v", h, c)
	}
}
