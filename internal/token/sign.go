package token

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/andychoi/mock-oidc/internal/jsonx"
)

// GenerateSigningKey creates a fresh signing key with the given kid for the
// algorithm (RSA-2048 for RS*, the matching curve for ES*).
func GenerateSigningKey(kid, alg string) (*SigningKey, error) {
	family, err := AlgorithmFamily(alg)
	if err != nil {
		return nil, err
	}
	return generateKey(kid, alg, family), nil
}

// SignJWT produces a compact JWS with header {kid, typ, alg} over the claims.
func SignJWT(key *SigningKey, claims map[string]any, typ string) string {
	header := fmt.Sprintf(`{"kid":%s,"typ":%s,"alg":%s}`, jsonQuote(key.Kid), jsonQuote(typ), jsonQuote(key.Alg))
	payload, _ := json.Marshal(claims) // map keys sorted — semantically identical JWT
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(header)) +
		"." + base64.RawURLEncoding.EncodeToString(payload)

	var sig []byte
	if key.RSA != nil {
		h := hashFor(key.Alg)
		digest := hashDigest(signingInput, h)
		sig, _ = rsa.SignPKCS1v15(rand.Reader, key.RSA, h, digest)
	} else {
		h := hashFor(key.Alg)
		digest := hashDigest(signingInput, h)
		r, s, _ := ecdsa.Sign(rand.Reader, key.EC, digest)
		size := (key.EC.Curve.Params().N.BitLen() + 7) / 8
		sig = make([]byte, 2*size)
		r.FillBytes(sig[:size])
		s.FillBytes(sig[size:])
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// PublicJWKSOf renders a JWKS document with the public part of each key, in
// the given order.
func PublicJWKSOf(keys ...*SigningKey) string {
	arr := make(jsonx.Arr, 0, len(keys))
	for _, k := range keys {
		arr = append(arr, publicJWK(k))
	}
	return jsonx.Render(jsonx.Obj{{Name: "keys", V: arr}})
}

// publicJWK renders one public JWK with the field order the nimbus-based
// server emits (RSA: kty,e,use,kid,alg,n — EC: kty,use,crv,kid,x,y,alg).
func publicJWK(k *SigningKey) jsonx.Obj {
	if k.RSA != nil {
		return jsonx.Obj{
			{Name: "kty", V: "RSA"},
			{Name: "e", V: "AQAB"},
			{Name: "use", V: k.Use},
			{Name: "kid", V: k.Kid},
			{Name: "alg", V: k.Alg},
			{Name: "n", V: base64.RawURLEncoding.EncodeToString(k.RSA.N.Bytes())},
		}
	}
	return jsonx.Obj{
		{Name: "kty", V: "EC"},
		{Name: "use", V: k.Use},
		{Name: "crv", V: curveName(k.EC.Curve)},
		{Name: "kid", V: k.Kid},
		{Name: "x", V: base64.RawURLEncoding.EncodeToString(k.EC.X.Bytes())},
		{Name: "y", V: base64.RawURLEncoding.EncodeToString(k.EC.Y.Bytes())},
		{Name: "alg", V: k.Alg},
	}
}
