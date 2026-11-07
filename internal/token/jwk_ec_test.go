package token_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/andychoi/mock-oidc/internal/token"
)

// RFC 7518 6.2.1.2: EC x and y are the full coordinate size, left-padded with
// zero bytes.
func TestPublicJWKPadsECCoordinates(t *testing.T) {
	for alg, size := range map[string]int{"ES256": 32, "ES384": 48} {
		var key *token.SigningKey
		for i := 0; i < 5000 && key == nil; i++ {
			k, err := token.GenerateSigningKey("k", alg)
			if err != nil {
				t.Fatal(err)
			}
			if len(k.EC.X.Bytes()) < size || len(k.EC.Y.Bytes()) < size {
				key = k
			}
		}
		if key == nil {
			t.Fatalf("%s: no key with a short coordinate found", alg)
		}
		var doc struct {
			Keys []map[string]string `json:"keys"`
		}
		if err := json.Unmarshal([]byte(token.PublicJWKSOf(key)), &doc); err != nil {
			t.Fatal(err)
		}
		for _, coord := range []string{"x", "y"} {
			raw, err := base64.RawURLEncoding.DecodeString(doc.Keys[0][coord])
			if err != nil || len(raw) != size {
				t.Errorf("%s %s: %d bytes (err %v), want %d", alg, coord, len(raw), err, size)
			}
		}
	}
}
