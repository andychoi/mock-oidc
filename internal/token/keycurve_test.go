package token_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/token"
)

func publicJWK(t *testing.T, jwks string) map[string]string {
	t.Helper()
	var doc struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks), &doc); err != nil || len(doc.Keys) != 1 {
		t.Fatalf("JWKS %q: %v", jwks, err)
	}
	return doc.Keys[0]
}

func b64int(t *testing.T, s string) *big.Int {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return new(big.Int).SetBytes(b)
}

// An ES384 token must verify, as any JOSE library would, against the JWKS key
// on P-384 with a 96-byte r||s signature (RFC 7518 3.4).
func TestDefaultES384TokenVerifiesOnP384(t *testing.T) {
	kp, err := token.DefaultKeyProvider("ES384")
	if err != nil {
		t.Fatal(err)
	}
	p := token.NewTokenProvider(kp, nil)
	for _, issuer := range []string{"issuer0", "issuer1", "issuer2"} {
		jwk := publicJWK(t, p.PublicJWKS(issuer))
		if jwk["crv"] != "P-384" {
			t.Fatalf("%s: JWKS crv %q, want P-384", issuer, jwk["crv"])
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P384(), X: b64int(t, jwk["x"]), Y: b64int(t, jwk["y"])}

		tok := p.IssueToken("http://h/"+issuer, issuer, token.NewDefaultCallback(issuer))
		parts := strings.Split(tok, ".")
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		if len(sig) != 96 {
			t.Fatalf("%s: signature is %d bytes, want 96", issuer, len(sig))
		}
		h := crypto.SHA384.New()
		h.Write([]byte(parts[0] + "." + parts[1]))
		if !ecdsa.Verify(pub, h.Sum(nil), new(big.Int).SetBytes(sig[:48]), new(big.Int).SetBytes(sig[48:])) {
			t.Fatalf("%s: ES384 signature does not verify against the JWKS key", issuer)
		}
	}
}

// RS* and ES256 keep drawing the embedded deterministic keys, in file order.
func TestDefaultProviderKeepsDeterministicKeys(t *testing.T) {
	cases := []struct {
		alg, file, coord string
	}{
		{"RS256", "initial-keys.json", "n"},
		{"RS384", "initial-keys.json", "n"},
		{"RS512", "initial-keys.json", "n"},
		{"ES256", "initial-keys-ec.json", "x"},
	}
	for _, c := range cases {
		raw, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		var set struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(raw, &set); err != nil {
			t.Fatal(err)
		}
		kp, err := token.DefaultKeyProvider(c.alg)
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range set.Keys {
			issuer := "issuer" + string(rune('a'+i))
			got := publicJWK(t, kp.PublicJWKS(issuer))
			if got[c.coord] != want[c.coord] || got["alg"] != c.alg || got["kid"] != issuer {
				t.Fatalf("%s %s: JWKS %v does not carry pool key %d", c.alg, issuer, got, i)
			}
		}
	}
}
