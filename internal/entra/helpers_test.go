package entra

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// verifyWithJWKS verifies an RS256 JWS against a JWKS document and returns the
// decoded header and claims.
func verifyWithJWKS(t *testing.T, jwks, jwt string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", jwt)
	}
	var header, claims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(hb, &header); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(pb, &claims); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []struct{ Kid, N, E string } `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range doc.Keys {
		if k.Kid != header["kid"] {
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
		return header, claims
	}
	t.Fatalf("kid %v not in JWKS %s", header["kid"], jwks)
	return nil, nil
}

func jwksKids(t *testing.T, jwks string) []string {
	t.Helper()
	var doc struct {
		Keys []struct{ Kid string } `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks), &doc); err != nil {
		t.Fatal(err)
	}
	var kids []string
	for _, k := range doc.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}
