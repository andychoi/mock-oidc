package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
)

// clockSkewSeconds mirrors nimbus DefaultJWTClaimsVerifier's maxClockSkew.
const clockSkewSeconds = 60

// TokenProvider mirrors OAuth2TokenProvider.kt: builds claim sets, signs JWTs
// with the issuer's key and verifies incoming JWTs.
type TokenProvider struct {
	keys       *KeyProvider
	systemTime *time.Time
}

// NewTokenProvider creates a provider; systemTime may be nil (wall clock).
func NewTokenProvider(keys *KeyProvider, systemTime *time.Time) *TokenProvider {
	return &TokenProvider{keys: keys, systemTime: systemTime}
}

// KeyProvider exposes the underlying key provider.
func (t *TokenProvider) KeyProvider() *KeyProvider { return t.keys }

func (t *TokenProvider) now() time.Time {
	if t.systemTime != nil {
		return *t.systemTime
	}
	return time.Now()
}

// PublicJWKS renders the issuer's public JWKS document.
func (t *TokenProvider) PublicJWKS(issuerID string) string {
	return t.keys.PublicJWKS(issuerID)
}

// IssueToken mints an access token for a synthetic client-credentials request
// (library API, mirroring MockOAuth2Server.issueToken).
func (t *TokenProvider) IssueToken(issuerURL, issuerID string, cb Callback) string {
	req := &oauth2.TokenRequest{
		GrantType: oauth2.GrantClientCredentials,
		ClientID:  "mock-oidc",
		Scope:     "default",
		ScopeList: []string{"default"},
	}
	return t.AccessToken(req, issuerURL, issuerID, cb, "")
}

// IDToken mints an id_token: audience is forced to the client id.
func (t *TokenProvider) IDToken(req *oauth2.TokenRequest, issuerURL, issuerID string, cb Callback, nonce string) string {
	claims := t.defaultClaims(issuerURL, cb.Subject(req), []string{req.ClientID}, nonce, cb.AddClaims(req), cb.TokenExpiry())
	return t.sign(claims, issuerID, cb.TypeHeader(req))
}

// AccessToken mints an access token with the callback's audience resolution.
func (t *TokenProvider) AccessToken(req *oauth2.TokenRequest, issuerURL, issuerID string, cb Callback, nonce string) string {
	claims := t.defaultClaims(issuerURL, cb.Subject(req), cb.Audience(req), nonce, cb.AddClaims(req), cb.TokenExpiry())
	return t.sign(claims, issuerID, cb.TypeHeader(req))
}

// ExchangeAccessToken re-signs an incoming claim set, overriding iss/exp/nbf/
// iat/jti/aud and applying callback claims last (they win).
func (t *TokenProvider) ExchangeAccessToken(req *oauth2.TokenRequest, issuerURL, issuerID string, incoming map[string]any, cb Callback) string {
	now := t.now()
	claims := make(map[string]any, len(incoming)+8)
	for k, v := range incoming {
		claims[k] = v
	}
	claims["iss"] = issuerURL
	claims["exp"] = now.Add(time.Duration(cb.TokenExpiry()) * time.Second).Unix()
	claims["nbf"] = now.Unix()
	claims["iat"] = now.Unix()
	claims["jti"] = randomUUID()
	claims["aud"] = audienceClaim(cb.Audience(req))
	for k, v := range cb.AddClaims(req) {
		claims[k] = v
	}
	return t.sign(claims, issuerID, cb.TypeHeader(req))
}

// defaultClaims mirrors OAuth2TokenProvider.defaultClaims: base claims first,
// callback addClaims applied last (so callbacks may override any base claim).
func (t *TokenProvider) defaultClaims(issuerURL, subject string, audience []string, nonce string, addClaims map[string]any, expiry int64) map[string]any {
	now := t.now()
	claims := map[string]any{
		"sub": subject,
		"aud": audienceClaim(audience),
		"iss": issuerURL,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(time.Duration(expiry) * time.Second).Unix(),
		"jti": randomUUID(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range addClaims {
		claims[k] = v
	}
	return claims
}

// audienceClaim serializes single audiences as a scalar and empty ones as []
// (not null), like nimbus.
func audienceClaim(audience []string) any {
	if len(audience) == 1 {
		return audience[0]
	}
	if audience == nil {
		return []string{}
	}
	return audience
}

// sign produces a compact JWS with header {kid, typ, alg}.
func (t *TokenProvider) sign(claims map[string]any, issuerID, typ string) string {
	key := t.keys.SigningKey(issuerID)
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

// Verify parses and verifies a JWT against the issuer's key, requiring
// typ=JWT, the configured algorithm, exact issuer match and iat/exp claims
// (nimbus DefaultJWTClaimsVerifier semantics incl. clock skew).
func (t *TokenProvider) Verify(issuerURL, token string) (map[string]any, *oauth2.Error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return nil, oauth2.InvalidToken("signed JWT expected")
	}
	var header struct {
		Kid string `json:"kid"`
		Typ string `json:"typ"`
		Alg string `json:"alg"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil {
		return nil, oauth2.InvalidToken("invalid JWT header")
	}
	if header.Typ != "JWT" {
		return nil, oauth2.InvalidToken("invalid typ header")
	}
	key := t.keys.SigningKey(issuerIDFromURL(issuerURL))
	if header.Alg != key.Alg || header.Kid != key.Kid {
		return nil, oauth2.InvalidToken("invalid alg/kid header")
	}

	claims := map[string]any{}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &claims) != nil {
		return nil, oauth2.InvalidToken("invalid JWT payload")
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, oauth2.InvalidToken("invalid JWT signature")
	}
	h := hashFor(key.Alg)
	digest := hashDigest(parts[0]+"."+parts[1], h)
	if key.RSA != nil {
		if err := rsa.VerifyPKCS1v15(&key.RSA.PublicKey, h, digest, sig); err != nil {
			return nil, oauth2.InvalidToken("invalid signature")
		}
	} else {
		size := (key.EC.Curve.Params().N.BitLen() + 7) / 8
		if len(sig) != 2*size {
			return nil, oauth2.InvalidToken("invalid signature")
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(&key.EC.PublicKey, digest, r, s) {
			return nil, oauth2.InvalidToken("invalid signature")
		}
	}

	if iss, _ := claims["iss"].(string); iss != issuerURL {
		return nil, oauth2.InvalidToken("invalid issuer")
	}
	_, hasIAT := claims["iat"]
	_, hasEXP := claims["exp"]
	if !hasIAT || !hasEXP {
		return nil, oauth2.InvalidToken("missing iat/exp claims")
	}
	now := t.now().Unix()
	if exp, ok := numeric(claims["exp"]); !ok || exp <= now-clockSkewSeconds {
		return nil, oauth2.InvalidToken("expired token")
	}
	if nbf, ok := numeric(claims["nbf"]); ok && nbf > now+clockSkewSeconds {
		return nil, oauth2.InvalidToken("token not yet valid")
	}
	return claims, nil
}

func hashFor(alg string) crypto.Hash {
	switch alg {
	case "RS256", "ES256":
		return crypto.SHA256
	case "RS384", "ES384":
		return crypto.SHA384
	default:
		return crypto.SHA512
	}
}

// issuerIDFromURL derives the issuerId (== kid) from an issuer URL: the last
// path segment, empty for a root issuer.
func issuerIDFromURL(issuerURL string) string {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return ""
	}
	seg := strings.Trim(u.Path, "/")
	if i := strings.LastIndex(seg, "/"); i != -1 {
		return seg[i+1:]
	}
	return seg
}

func hashDigest(s string, h crypto.Hash) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256([]byte(s))
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384([]byte(s))
		return d[:]
	default:
		d := sha512.Sum512([]byte(s))
		return d[:]
	}
}

func numeric(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case int:
		return int64(t), true
	}
	return 0, false
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
