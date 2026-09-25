// Package token implements the per-issuer signing key model and JWT
// minting/verification, mirroring no.nav.security.mock.oauth2.token.
package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/andychoi/mock-oidc/internal/jsonx"
)

//go:embed initial-keys.json
var initialKeysJSON []byte

//go:embed initial-keys-ec.json
var initialKeysECJSON []byte

// Supported signing algorithms. PS* are listed in upstream discovery metadata
// but signing with them fails upstream; here they are rejected at config time.
var supportedAlgorithms = map[string]string{
	"RS256": "RSA",
	"RS384": "RSA",
	"RS512": "RSA",
	"ES256": "EC",
	"ES384": "EC",
}

// AlgorithmFamily returns "RSA" or "EC" for a supported algorithm.
func AlgorithmFamily(alg string) (string, error) {
	fam, ok := supportedAlgorithms[alg]
	if !ok {
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}
	return fam, nil
}

// SigningKey is one issuer's private signing key with JWK metadata.
type SigningKey struct {
	Kty string // RSA | EC
	Kid string
	Alg string
	Use string
	RSA *rsa.PrivateKey
	EC  *ecdsa.PrivateKey
}

// KeyProvider mirrors token/KeyProvider.kt: one signing key per issuerId,
// deterministic initial keys consumed from an ordered pool and rebuilt with
// kid = issuerId, fresh generated keys once the pool is empty.
type KeyProvider struct {
	mu      sync.Mutex
	initial []*SigningKey
	keys    sync.Map // issuerID -> *SigningKey
	alg     string
	family  string
}

// NewKeyProvider builds a provider with the given initial key set JSON
// ({"keys":[...]}) and algorithm ("RS256" default family check applies).
func NewKeyProvider(initialKeySet []byte, algorithm string) (*KeyProvider, error) {
	family, err := AlgorithmFamily(algorithm)
	if err != nil {
		return nil, err
	}
	p := &KeyProvider{alg: algorithm, family: family}
	if len(initialKeySet) > 0 {
		keys, err := parsePrivateKeySet(initialKeySet)
		if err != nil {
			return nil, err
		}
		p.initial = keys
	}
	return p, nil
}

// DefaultKeyProvider selects the embedded deterministic key set matching the
// algorithm family (RSA keys for RS*, EC keys for ES*).
func DefaultKeyProvider(algorithm string) (*KeyProvider, error) {
	family, err := AlgorithmFamily(algorithm)
	if err != nil {
		return nil, err
	}
	set := initialKeysJSON
	if family == "EC" {
		set = initialKeysECJSON
	}
	return NewKeyProvider(set, algorithm)
}

// NewKeyProviderFromInitial builds a provider seeded with a single initial key
// (the tokenProvider.keyProvider.initialKeys config: one JWK JSON string).
func NewKeyProviderFromInitial(key *SigningKey, algorithm string) (*KeyProvider, error) {
	family, err := AlgorithmFamily(algorithm)
	if err != nil {
		return nil, err
	}
	if key.Kty != family {
		return nil, fmt.Errorf("initial key type %s does not match algorithm %s (family %s)", key.Kty, algorithm, family)
	}
	return &KeyProvider{initial: []*SigningKey{key}, alg: algorithm, family: family}, nil
}

// Algorithm returns the configured signing algorithm.
func (p *KeyProvider) Algorithm() string { return p.alg }

// SigningKey returns the (lazily created) signing key for an issuer.
func (p *KeyProvider) SigningKey(issuerID string) *SigningKey {
	if v, ok := p.keys.Load(issuerID); ok {
		return v.(*SigningKey)
	}
	key := p.keyFromPoolOrNew(issuerID)
	actual, _ := p.keys.LoadOrStore(issuerID, key)
	return actual.(*SigningKey)
}

func (p *KeyProvider) keyFromPoolOrNew(issuerID string) *SigningKey {
	p.mu.Lock()
	var pooled *SigningKey
	if len(p.initial) > 0 {
		pooled = p.initial[0]
		p.initial = p.initial[1:]
	}
	p.mu.Unlock()

	if pooled != nil {
		return &SigningKey{Kty: pooled.Kty, Kid: issuerID, Alg: p.alg, Use: "sig", RSA: pooled.RSA, EC: pooled.EC}
	}
	return generateKey(issuerID, p.alg, p.family)
}

func generateKey(issuerID, alg, family string) *SigningKey {
	if family == "EC" {
		var curve elliptic.Curve
		switch alg {
		case "ES256":
			curve = elliptic.P256()
		case "ES384":
			curve = elliptic.P384()
		}
		key, _ := ecdsa.GenerateKey(curve, rand.Reader)
		return &SigningKey{Kty: "EC", Kid: issuerID, Alg: alg, Use: "sig", EC: key}
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	return &SigningKey{Kty: "RSA", Kid: issuerID, Alg: alg, Use: "sig", RSA: key}
}

// PublicJWKS renders the public JWKS for an issuer: exactly one key, with the
// field order the nimbus-based server emits
// (RSA: kty,e,use,kid,alg,n — EC: kty,use,crv,kid,x,y,alg).
func (p *KeyProvider) PublicJWKS(issuerID string) string {
	k := p.SigningKey(issuerID)
	var obj jsonx.Obj
	if k.RSA != nil {
		obj = jsonx.Obj{
			{Name: "kty", V: "RSA"},
			{Name: "e", V: "AQAB"},
			{Name: "use", V: k.Use},
			{Name: "kid", V: k.Kid},
			{Name: "alg", V: k.Alg},
			{Name: "n", V: base64.RawURLEncoding.EncodeToString(k.RSA.N.Bytes())},
		}
	} else {
		obj = jsonx.Obj{
			{Name: "kty", V: "EC"},
			{Name: "use", V: k.Use},
			{Name: "crv", V: curveName(k.EC.Curve)},
			{Name: "kid", V: k.Kid},
			{Name: "x", V: base64.RawURLEncoding.EncodeToString(k.EC.X.Bytes())},
			{Name: "y", V: base64.RawURLEncoding.EncodeToString(k.EC.Y.Bytes())},
			{Name: "alg", V: k.Alg},
		}
	}
	return jsonx.Render(jsonx.Obj{{Name: "keys", V: jsonx.Arr{obj}}})
}

func curveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	}
	return ""
}

// --- private JWK parsing ---

func parsePrivateKeySet(data []byte) ([]*SigningKey, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("invalid initial key set: %w", err)
	}
	out := make([]*SigningKey, 0, len(set.Keys))
	for _, raw := range set.Keys {
		k, err := parsePrivateJWK(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// ParsePrivateJWK parses a single private JWK JSON document (RSA with n,e,d,p,q
// or EC with crv,x,y,d).
func ParsePrivateJWK(data []byte) (*SigningKey, error) {
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return parsePrivateJWK(raw)
}

func parsePrivateJWK(raw json.RawMessage) (*SigningKey, error) {
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("invalid JWK: %w", err)
	}
	kty, _ := jwk["kty"].(string)
	kid, _ := jwk["kid"].(string)
	alg, _ := jwk["alg"].(string)

	switch kty {
	case "RSA":
		n, err := bigint(jwk["n"])
		if err != nil {
			return nil, fmt.Errorf("JWK n: %w", err)
		}
		e, err := bigint(jwk["e"])
		if err != nil {
			return nil, fmt.Errorf("JWK e: %w", err)
		}
		d, err := bigint(jwk["d"])
		if err != nil {
			return nil, fmt.Errorf("JWK d: %w", err)
		}
		p, err := bigint(jwk["p"])
		if err != nil {
			return nil, fmt.Errorf("JWK p: %w", err)
		}
		q, err := bigint(jwk["q"])
		if err != nil {
			return nil, fmt.Errorf("JWK q: %w", err)
		}
		priv := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
			D:         d,
			Primes:    []*big.Int{p, q},
		}
		if err := priv.Validate(); err != nil {
			return nil, fmt.Errorf("invalid RSA key: %w", err)
		}
		priv.Precompute()
		return &SigningKey{Kty: "RSA", Kid: kid, Alg: alg, Use: "sig", RSA: priv}, nil

	case "EC":
		crv, _ := jwk["crv"].(string)
		var curve elliptic.Curve
		switch crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", crv)
		}
		x, err := bigint(jwk["x"])
		if err != nil {
			return nil, fmt.Errorf("JWK x: %w", err)
		}
		y, err := bigint(jwk["y"])
		if err != nil {
			return nil, fmt.Errorf("JWK y: %w", err)
		}
		d, err := bigint(jwk["d"])
		if err != nil {
			return nil, fmt.Errorf("JWK d: %w", err)
		}
		return &SigningKey{Kty: "EC", Kid: kid, Alg: alg, Use: "sig",
			EC: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}}, nil
	}
	return nil, fmt.Errorf("unsupported key type: %s (want RSA or EC)", kty)
}

func bigint(v any) (*big.Int, error) {
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("expected base64url string, got %T", v)
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
