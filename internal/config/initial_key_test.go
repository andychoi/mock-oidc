package config_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/config"
)

func ecInitialKeyConfig(t *testing.T, curve elliptic.Curve, crv, alg string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	size := (curve.Params().BitSize + 7) / 8
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	jwk, _ := json.Marshal(map[string]string{
		"kty": "EC", "crv": crv, "kid": "k",
		"x": b64(priv.X.FillBytes(make([]byte, size))),
		"y": b64(priv.Y.FillBytes(make([]byte, size))),
		"d": b64(priv.D.FillBytes(make([]byte, size))),
	})
	cfg, _ := json.Marshal(map[string]any{
		"tokenProvider": map[string]any{
			"keyProvider": map[string]string{"algorithm": alg, "initialKeys": string(jwk)},
		},
	})
	return cfg
}

func TestInitialECKeyCurveMustMatchAlgorithm(t *testing.T) {
	for _, tc := range []struct {
		curve    elliptic.Curve
		crv, alg string
	}{
		{elliptic.P384(), "P-384", "ES256"},
		{elliptic.P256(), "P-256", "ES384"},
		{elliptic.P521(), "P-521", "ES256"},
	} {
		_, err := config.ParseJSON(ecInitialKeyConfig(t, tc.curve, tc.crv, tc.alg))
		if err == nil || !strings.Contains(err.Error(), tc.crv) {
			t.Errorf("%s key with %s: err = %v, want a curve mismatch error", tc.crv, tc.alg, err)
		}
	}
}

func TestInitialECKeyMatchingCurveIsAccepted(t *testing.T) {
	for alg, c := range map[string]struct {
		curve elliptic.Curve
		crv   string
	}{"ES256": {elliptic.P256(), "P-256"}, "ES384": {elliptic.P384(), "P-384"}} {
		if _, err := config.ParseJSON(ecInitialKeyConfig(t, c.curve, c.crv, alg)); err != nil {
			t.Errorf("%s key with %s: %v", c.crv, alg, err)
		}
	}
}
