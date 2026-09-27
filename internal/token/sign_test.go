package token

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicJWKSOfKeepsOrderAndOnlyPublicParts(t *testing.T) {
	k1, err := GenerateSigningKey("k1", "RS256")
	if err != nil {
		t.Fatal(err)
	}
	k2, err := GenerateSigningKey("k2", "RS256")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(PublicJWKSOf(k1, k2)), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 2 || doc.Keys[0]["kid"] != "k1" || doc.Keys[1]["kid"] != "k2" {
		t.Fatalf("keys = %v", doc.Keys)
	}
	for _, k := range doc.Keys {
		if _, leaked := k["d"]; leaked {
			t.Errorf("private exponent leaked: %v", k)
		}
		if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" || k["e"] != "AQAB" {
			t.Errorf("unexpected JWK %v", k)
		}
	}
}

func TestGenerateSigningKeyRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := GenerateSigningKey("k", "HS256"); err == nil {
		t.Fatal("expected error for HS256")
	}
}

func TestSignJWTHeaderAndSignature(t *testing.T) {
	key, err := GenerateSigningKey("kid-x", "RS256")
	if err != nil {
		t.Fatal(err)
	}
	jwt := SignJWT(key, map[string]any{"sub": "u1"}, "JWT")
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %s", jwt)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if string(hdr) != `{"kid":"kid-x","typ":"JWT","alg":"RS256"}` {
		t.Errorf("header = %s", hdr)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.RSA.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
}
