# Entra Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in "Entra mode" to mock-oidc that emulates Microsoft Entra ID v2.0 (multiple tenants, the multi-tenant `organizations` endpoint, a shared key set, v2.0 claims, group claims with overage, admin consent, error injection), so the IAM's Entra connector can be tested without a real Entra tenant.

**Architecture:** A new package `internal/entra` is mounted as a single front route `/{basePath}/*` (default `/entra/*`) that parses its own path segments, because the built-in router matches by path suffix. It keeps its own RS256 key set shared by all tenants and reuses `oauth2`, `routing`, `jsonx`, and three new exported helpers in `internal/token`. Configuration comes from an `"entra"` block in the main JSON config or `ENTRA_CONFIG_PATH`; without it, nothing changes.

**Tech Stack:** Go 1.27, stdlib only (`net/http`, `html/template`, `crypto/*`, `encoding/json`), existing internal packages.

**Spec:** [`docs/entra/00-design.md`](00-design.md). Read it first; this plan implements it section by section.

## Global Constraints

- Go version stays `go 1.27` in `go.mod`; **no new module dependencies** (`go.mod`/`go.sum` unchanged).
- **Opt-in and additive:** with no `entra` config and no `ENTRA_CONFIG_PATH`, every response is byte-for-byte unchanged. All existing tests in `internal/...` must pass **without modification**.
- `internal/entra` may import only stdlib, `internal/oauth2`, `internal/routing`, `internal/jsonx`, `internal/token`. It must never import `internal/config` or `internal/server` (that would be an import cycle).
- CI gates (`.github/workflows/test.yml`): `gofmt -l .` empty, `go vet ./...`, `go build ./...`, `go test ./...`. Also run `go test -race ./...` locally before finishing.
- JSON error bodies go through `routing.ErrorResponse`, which **lowercases the whole body** (existing navikt contract). Tests therefore match lowercase text such as `aadsts90002`. Error parameters in **redirects** are not lowercased.
- Default `basePath` is `entra`; tenant IDs are lowercase GUIDs; signing is RS256 with `kid` `entra-N`.
- US English in code comments and docs.
- Every commit message ends with a blank line and `Co-authored by AI`.

## Review Focus

1. **Route shadowing**: Entra paths ending in `/token` or `/authorize` must be answered by Entra mode, never by the built-in handlers, and with Entra mode off the built-ins must behave exactly as before. *(Tests: Task 5 `TestEntraBuiltinsNotShadowed` and `TestEntraRoutesAbsentWhenDisabled`; Task 6 `TestEntraUnsupportedGrantIsEntraError`.)*
2. **Proxy-aware issuer**: behind `mock-oidc.dev.test:8088` or `x-forwarded-*` headers, the discovery `issuer` and the token `iss` must use the same origin, or every RP rejects the token. *(Tests: Task 5 `TestEntraDiscoveryHonorsForwardedHeaders`; Task 6 `TestEntraTokenIssuerHonorsForwardedHeaders`.)*
3. **Tenant GUID case**: an uppercase tenant GUID in the path must work, and `iss`/`tid` must be the lowercase configured value. *(Test: Task 5 `TestEntraTenantPathCaseInsensitive`.)*
4. **Code replay and cross-tenant redemption**: a code is single-use, and a code issued on one tenant path can't be redeemed on another tenant's token endpoint. *(Test: Task 6 `TestEntraCodeRules`.)*
5. **Concurrency**: parallel sign-ins, key rotation, and consent writes share maps and slices, so they must be race-free. *(Test: Task 7 `TestConcurrentSignInsRotationAndConsent`, run with `-race`.)*

## File Map

| File | Responsibility | Task |
|---|---|---|
| `internal/token/sign.go` (+`sign_test.go`) | Exported `GenerateSigningKey`, `SignJWT`, `PublicJWKSOf` | 1 |
| `internal/token/tokenprovider.go`, `keyprovider.go` | Delegate to the new helpers (behavior unchanged) | 1 |
| `internal/entra/uuid.go` (+test) | UUIDv5, `GroupObjectID` | 2 |
| `internal/entra/config.go` (+test) | Config types, `ParseConfig`, lookups | 2 |
| `internal/entra/keys.go` (+test) | `KeySet` | 3 |
| `internal/entra/claims.go` (+test) | `Issuer`, `PairwiseSub`, `IDTokenClaims`, `AccessTokenClaims` | 4 |
| `internal/entra/consent.go` | `ConsentStore` | 5 |
| `internal/entra/handler.go` | `Handler`, `New`, `Handle`, scope resolution, discovery, keys, logout | 5 (extended in 6, 7) |
| `internal/config/config.go` (+test) | `"entra"` block, `ENTRA_CONFIG_PATH` | 5 |
| `internal/server/server.go` | Mount the front route | 5 |
| `internal/e2e/entra_test.go` | End-to-end suite | 5 (extended in 6, 7) |
| `internal/entra/authorize.go`, `templates/picker.html.tmpl` | Picker, sign-in, code store, redirects | 6 |
| `internal/entra/token.go` (+`handler_test.go`) | Token endpoint | 6 |
| `internal/entra/adminconsent.go`, `testapi.go` | Admin consent, `/_entra/*` | 7 |
| `entra-demo.json`, `docker-compose.yml`, `README.md` | Local wiring and docs | 8 |

---

### Task 1: Export signing helpers from `internal/token`

**Files:**
- Create: `internal/token/sign.go`, `internal/token/sign_test.go`
- Modify: `internal/token/tokenprovider.go` (`sign`, ~lines 129-155), `internal/token/keyprovider.go` (`PublicJWKS`, ~lines 156-183)

**Interfaces:**
- Consumes: existing unexported `generateKey`, `hashFor`, `hashDigest`, `jsonQuote`, `AlgorithmFamily`, `SigningKey`.
- Produces:
  - `func GenerateSigningKey(kid, alg string) (*SigningKey, error)`
  - `func SignJWT(key *SigningKey, claims map[string]any, typ string) string`
  - `func PublicJWKSOf(keys ...*SigningKey) string`

- [x] **Step 1: Write the failing tests** in `internal/token/sign_test.go`

```go
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
```

- [x] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/token/ -run 'PublicJWKSOf|GenerateSigningKey|SignJWT' -v`
Expected: build failure `undefined: GenerateSigningKey` (and `PublicJWKSOf`, `SignJWT`).

- [x] **Step 3: Create `internal/token/sign.go`** by moving the existing code (the signing body of `TokenProvider.sign` and the JWK rendering of `KeyProvider.PublicJWKS`, unchanged):

```go
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
```

- [x] **Step 4: Make the existing methods delegate.** In `internal/token/tokenprovider.go`, replace the whole body of `sign` with:

```go
// sign produces a compact JWS with header {kid, typ, alg}.
func (t *TokenProvider) sign(claims map[string]any, issuerID, typ string) string {
	return SignJWT(t.keys.SigningKey(issuerID), claims, typ)
}
```

In `internal/token/keyprovider.go`, replace the whole body of `PublicJWKS` with:

```go
// PublicJWKS renders the public JWKS for an issuer: exactly one key, with the
// field order the nimbus-based server emits.
func (p *KeyProvider) PublicJWKS(issuerID string) string {
	return PublicJWKSOf(p.SigningKey(issuerID))
}
```

Then run `go build ./...` and delete any import the compiler reports as `imported and not used` in those two files (likely `crypto/rand`, `crypto/rsa`, `crypto/ecdsa` in `tokenprovider.go`, `encoding/base64` in `keyprovider.go`; keep any still used by `Verify` or the JWK parsing).

- [x] **Step 5: Run the full suite.** The existing golden tests (`TestJWKSKidAndFormat`, `TestDiscoveryGoldenFormat`, `TestMultiIssuerDistinctKeys`) prove the refactor is byte-identical.

Run: `gofmt -l internal/token && go vet ./... && go test ./...`
Expected: no gofmt output; all tests PASS.

- [x] **Step 6: Commit**

```bash
git add internal/token/sign.go internal/token/sign_test.go internal/token/tokenprovider.go internal/token/keyprovider.go
git commit -m "refactor(token): export GenerateSigningKey, SignJWT, PublicJWKSOf" -m "Co-authored by AI"
```

---

### Task 2: Entra config and deterministic IDs

**Files:**
- Create: `internal/entra/uuid.go`, `internal/entra/uuid_test.go`, `internal/entra/config.go`, `internal/entra/config_test.go`

**Interfaces:**
- Produces:
  - `func UUIDv5(ns [16]byte, name string) string`, `func GroupObjectID(tid, name string) string`, unexported `oidNamespace`, `groupNamespace`, `mustUUID(string) [16]byte`
  - Types `Config`, `Tenant`, `Consent`, `User` (fields exactly as in the code below)
  - Constants `FormatName = "name"`, `FormatObjectID = "object_id"`, `ErrInteractionRequired`, `ErrAccessDenied`, `ErrInvalidGrant`, `ScopeOrganizations = "organizations"`, `ScopeCommon = "common"`
  - `func ParseConfig(data []byte) (*Config, error)`
  - `func (c *Config) Tenant(tid string) *Tenant`, `func (c *Config) User(tid, username string) *User`, `func (c *Config) UsersIn(tid string) []*User`

- [x] **Step 1: Write the failing tests.** `internal/entra/uuid_test.go`:

```go
package entra

import "testing"

func TestUUIDv5KnownVector(t *testing.T) {
	// Python docs: uuid.uuid5(uuid.NAMESPACE_DNS, 'python.org')
	dns := mustUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if got := UUIDv5(dns, "python.org"); got != "886313e1-3b8a-5372-9b90-0c9aee199e5d" {
		t.Fatalf("UUIDv5 = %s", got)
	}
}

func TestGroupObjectIDStableAndTenantScoped(t *testing.T) {
	a := GroupObjectID("11111111-1111-1111-1111-111111111111", "Admins")
	if a != GroupObjectID("11111111-1111-1111-1111-111111111111", "Admins") {
		t.Error("object ID must be stable")
	}
	if a == GroupObjectID("22222222-2222-2222-2222-222222222222", "Admins") {
		t.Error("object IDs must differ across tenants")
	}
}
```

`internal/entra/config_test.go`:

```go
package entra

import "testing"

const tidA = "11111111-1111-1111-1111-111111111111"
const tidB = "22222222-2222-2222-2222-22222222abcd"

const validJSON = `{
  "basePath": "/entra/",
  "tenants": [
    {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"]},
    {"tid": "22222222-2222-2222-2222-22222222ABCD", "groupClaimFormat": "object_id", "groupLimit": 3}
  ],
  "consents": [{"clientId": "app", "tid": "11111111-1111-1111-1111-111111111111"}],
  "users": [
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "groups": ["G1"]},
    {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd", "oid": "AAAAAAAA-0000-0000-0000-000000000001"}
  ]
}`

func TestParseConfigDefaultsAndNormalization(t *testing.T) {
	c, err := ParseConfig([]byte(validJSON))
	if err != nil {
		t.Fatal(err)
	}
	if c.BasePath != "entra" || c.DefaultGroupLimit != 200 || c.TokenExpiry != 3600 {
		t.Fatalf("defaults: basePath=%q limit=%d expiry=%d", c.BasePath, c.DefaultGroupLimit, c.TokenExpiry)
	}
	corp := c.Tenant(tidA)
	if corp == nil || corp.GroupClaimFormat != FormatName || corp.GroupLimit != 200 || corp.Name != "Corp" {
		t.Fatalf("corp = %+v", corp)
	}
	cust := c.Tenant("22222222-2222-2222-2222-22222222ABCD") // lookup is case-insensitive
	if cust == nil || cust.TID != tidB || cust.GroupLimit != 3 || cust.Name != tidB {
		t.Fatalf("cust = %+v", cust)
	}
	jane := c.User(tidA, "jane")
	if jane == nil || jane.Name != "jane" || jane.OID != UUIDv5(oidNamespace, tidA+":jane") {
		t.Fatalf("jane = %+v", jane)
	}
	sam := c.User(tidB, "sam")
	if sam == nil || sam.OID != "aaaaaaaa-0000-0000-0000-000000000001" {
		t.Fatalf("sam = %+v", sam)
	}
	if c.User(tidA, "sam") != nil {
		t.Error("users are scoped to their tenant")
	}
	if got := len(c.UsersIn("")); got != 2 {
		t.Errorf("UsersIn(\"\") = %d, want 2", got)
	}
	if got := len(c.UsersIn(tidA)); got != 1 {
		t.Errorf("UsersIn(tidA) = %d, want 1", got)
	}
}

func TestParseConfigRejects(t *testing.T) {
	const one = `{"tid": "11111111-1111-1111-1111-111111111111"}`
	cases := map[string]string{
		"no tenants":          `{"tenants": []}`,
		"bad tid":             `{"tenants": [{"tid": "corp"}]}`,
		"duplicate tid":       `{"tenants": [` + one + `,` + one + `]}`,
		"bad basePath":        `{"basePath": "a/b", "tenants": [` + one + `]}`,
		"bad basePath chars":  `{"basePath": "en tra", "tenants": [` + one + `]}`,
		"bad group format":    `{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "groupClaimFormat": "guid"}]}`,
		"unknown field":       `{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "groupFormat": "name"}]}`,
		"consent unknown tid": `{"tenants": [` + one + `], "consents": [{"clientId": "a", "tid": "22222222-2222-2222-2222-222222222222"}]}`,
		"consent no client":   `{"tenants": [` + one + `], "consents": [{"tid": "11111111-1111-1111-1111-111111111111"}]}`,
		"missing username":    `{"tenants": [` + one + `], "users": [{"tid": "11111111-1111-1111-1111-111111111111"}]}`,
		"unknown user tid":    `{"tenants": [` + one + `], "users": [{"username": "x", "tid": "22222222-2222-2222-2222-222222222222"}]}`,
		"duplicate user":      `{"tenants": [` + one + `], "users": [{"username": "x", "tid": "11111111-1111-1111-1111-111111111111"}, {"username": "x", "tid": "11111111-1111-1111-1111-111111111111"}]}`,
		"bad error":           `{"tenants": [` + one + `], "users": [{"username": "x", "tid": "11111111-1111-1111-1111-111111111111", "error": "boom"}]}`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(js)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
```

- [x] **Step 2: Run to verify failure**

Run: `go test ./internal/entra/ -v`
Expected: build failure (`undefined: mustUUID`, `ParseConfig`, …).

- [x] **Step 3: Implement `internal/entra/uuid.go`**

```go
package entra

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fixed namespaces so derived IDs are stable across machines and restarts.
var (
	oidNamespace   = mustUUID("5d1c3b36-6f0e-4d4e-9a39-2d2f1f5e0c01")
	groupNamespace = mustUUID("8f6a3c52-1b7e-4a55-9d0e-6c1a9b0e2f11")
)

// UUIDv5 returns the name-based (SHA-1) UUID of name in namespace ns, lowercase.
func UUIDv5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// GroupObjectID is the stable object ID emitted for a group name in a tenant
// whose groupClaimFormat is "object_id".
func GroupObjectID(tid, name string) string {
	return UUIDv5(groupNamespace, strings.ToLower(tid)+":"+name)
}

func mustUUID(s string) [16]byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		panic("entra: bad UUID literal " + s)
	}
	var u [16]byte
	copy(u[:], b)
	return u
}
```

- [x] **Step 4: Implement `internal/entra/config.go`**

```go
// Package entra implements the opt-in Microsoft Entra ID emulation ("Entra
// mode"): per-tenant and multi-tenant (organizations/common) v2.0 endpoints, a
// key set shared by all tenants, v2.0 ID token claims, group claims with
// overage, admin consent and error injection. It is mounted under
// /{basePath}/ and never changes the navikt-compatible routes.
// Design: docs/entra/00-design.md.
package entra

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Group claim formats.
const (
	FormatName     = "name"
	FormatObjectID = "object_id"
)

// Injectable user errors.
const (
	ErrInteractionRequired = "interaction_required"
	ErrAccessDenied        = "access_denied"
	ErrInvalidGrant        = "invalid_grant"
)

// Multi-tenant path segments.
const (
	ScopeOrganizations = "organizations"
	ScopeCommon        = "common"
)

// Config is the Entra mode configuration (the "entra" JSON block or the file
// at ENTRA_CONFIG_PATH).
type Config struct {
	BasePath          string    `json:"basePath"`
	DefaultGroupLimit int       `json:"defaultGroupLimit"`
	TokenExpiry       int64     `json:"tokenExpiry"`
	Tenants           []Tenant  `json:"tenants"`
	Consents          []Consent `json:"consents"`
	Users             []User    `json:"users"`
}

// Tenant is one emulated Entra tenant.
type Tenant struct {
	TID              string   `json:"tid"`
	Name             string   `json:"name"`
	Domains          []string `json:"domains"`
	GroupClaimFormat string   `json:"groupClaimFormat"`
	GroupLimit       int      `json:"groupLimit"`
	ConsentRequired  bool     `json:"consentRequired"`
}

// Consent is a pre-granted admin consent of a client in a tenant.
type Consent struct {
	ClientID string `json:"clientId"`
	TID      string `json:"tid"`
}

// User is one account in a tenant.
type User struct {
	Username      string   `json:"username"`
	TID           string   `json:"tid"`
	OID           string   `json:"oid"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	EmailVerified *bool    `json:"emailVerified"`
	Groups        []string `json:"groups"`
	AMR           []string `json:"amr"`
	Admin         bool     `json:"admin"`
	Error         string   `json:"error"`
}

var (
	guidRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	basePathRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// ParseConfig decodes (rejecting unknown fields), normalizes and validates an
// Entra config.
func ParseConfig(data []byte) (*Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("entra config: %w", err)
	}
	if err := c.normalize(); err != nil {
		return nil, fmt.Errorf("entra config: %w", err)
	}
	return &c, nil
}

func (c *Config) normalize() error {
	c.BasePath = strings.Trim(c.BasePath, "/")
	if c.BasePath == "" {
		c.BasePath = "entra"
	}
	if !basePathRE.MatchString(c.BasePath) {
		return fmt.Errorf("basePath %q must be one path segment of [A-Za-z0-9_-]", c.BasePath)
	}
	if c.DefaultGroupLimit <= 0 {
		c.DefaultGroupLimit = 200
	}
	if c.TokenExpiry <= 0 {
		c.TokenExpiry = 3600
	}
	if len(c.Tenants) == 0 {
		return errors.New("at least one tenant is required")
	}
	tenants := map[string]bool{}
	for i := range c.Tenants {
		t := &c.Tenants[i]
		t.TID = strings.ToLower(strings.TrimSpace(t.TID))
		if !guidRE.MatchString(t.TID) {
			return fmt.Errorf("tenant %q: tid must be a GUID", t.TID)
		}
		if tenants[t.TID] {
			return fmt.Errorf("tenant %s: duplicate tid", t.TID)
		}
		tenants[t.TID] = true
		switch t.GroupClaimFormat {
		case "":
			t.GroupClaimFormat = FormatName
		case FormatName, FormatObjectID:
		default:
			return fmt.Errorf("tenant %s: groupClaimFormat must be %q or %q", t.TID, FormatName, FormatObjectID)
		}
		if t.GroupLimit <= 0 {
			t.GroupLimit = c.DefaultGroupLimit
		}
		if t.Name == "" {
			t.Name = t.TID
		}
	}
	for i := range c.Consents {
		cs := &c.Consents[i]
		cs.TID = strings.ToLower(strings.TrimSpace(cs.TID))
		if cs.ClientID == "" || !tenants[cs.TID] {
			return fmt.Errorf("consent %d: clientId and a configured tid are required", i)
		}
	}
	users := map[string]bool{}
	for i := range c.Users {
		u := &c.Users[i]
		u.TID = strings.ToLower(strings.TrimSpace(u.TID))
		if u.Username == "" {
			return fmt.Errorf("user %d: username is required", i)
		}
		if !tenants[u.TID] {
			return fmt.Errorf("user %s: unknown tid %q", u.Username, u.TID)
		}
		key := u.TID + "/" + u.Username
		if users[key] {
			return fmt.Errorf("user %s: duplicate username in tenant %s", u.Username, u.TID)
		}
		users[key] = true
		switch u.Error {
		case "", ErrInteractionRequired, ErrAccessDenied, ErrInvalidGrant:
		default:
			return fmt.Errorf("user %s: error must be %s, %s or %s", u.Username, ErrInteractionRequired, ErrAccessDenied, ErrInvalidGrant)
		}
		u.OID = strings.ToLower(u.OID)
		if u.OID == "" {
			u.OID = UUIDv5(oidNamespace, u.TID+":"+u.Username)
		}
		if u.Name == "" {
			u.Name = u.Username
		}
	}
	return nil
}

// Tenant returns the configured tenant for tid (case-insensitive), or nil.
func (c *Config) Tenant(tid string) *Tenant {
	tid = strings.ToLower(tid)
	for i := range c.Tenants {
		if c.Tenants[i].TID == tid {
			return &c.Tenants[i]
		}
	}
	return nil
}

// User returns the user with username in tenant tid, or nil.
func (c *Config) User(tid, username string) *User {
	tid = strings.ToLower(tid)
	for i := range c.Users {
		if c.Users[i].TID == tid && c.Users[i].Username == username {
			return &c.Users[i]
		}
	}
	return nil
}

// UsersIn returns the users of tenant tid, or of all tenants when tid is "".
func (c *Config) UsersIn(tid string) []*User {
	tid = strings.ToLower(tid)
	var out []*User
	for i := range c.Users {
		if tid == "" || c.Users[i].TID == tid {
			out = append(out, &c.Users[i])
		}
	}
	return out
}
```

- [x] **Step 5: Run to verify pass**

Run: `go test ./internal/entra/ -v && gofmt -l internal/entra && go vet ./internal/entra/`
Expected: PASS, no gofmt output.

- [x] **Step 6: Commit**

```bash
git add internal/entra/uuid.go internal/entra/uuid_test.go internal/entra/config.go internal/entra/config_test.go
git commit -m "feat(entra): config parsing, validation and deterministic IDs" -m "Co-authored by AI"
```

---

### Task 3: Shared key set

**Files:**
- Create: `internal/entra/keys.go`, `internal/entra/keys_test.go`, `internal/entra/helpers_test.go`

**Interfaces:**
- Consumes: `token.GenerateSigningKey`, `token.SignJWT`, `token.PublicJWKSOf` (Task 1).
- Produces: `type KeySet`; `func NewKeySet() *KeySet`; `func (k *KeySet) Rotate() string` (returns new kid); `func (k *KeySet) Sign(claims map[string]any) string`; `func (k *KeySet) JWKS() string`; `func (k *KeySet) ActiveKid() string`. Test helper `verifyWithJWKS(t, jwks, jwt string) (header map[string]any, claims map[string]any)`.

- [x] **Step 1: Write the test helper** `internal/entra/helpers_test.go` (shared by later unit tests):

```go
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
```

- [x] **Step 2: Write the failing tests** `internal/entra/keys_test.go`

```go
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
```

- [x] **Step 3: Run to verify failure**

Run: `go test ./internal/entra/ -run KeySet -v`
Expected: build failure `undefined: NewKeySet`.

- [x] **Step 4: Implement `internal/entra/keys.go`**

```go
package entra

import (
	"fmt"
	"sync"

	"github.com/andychoi/mock-oidc/internal/token"
)

// KeySet is the RS256 key set shared by every emulated tenant, like Entra's
// common signing keys. The newest key signs; one previous key stays published
// so tokens signed before a rotation still verify.
type KeySet struct {
	mu   sync.RWMutex
	keys []*token.SigningKey // oldest first
	seq  int
}

// NewKeySet returns a key set with one active key (kid "entra-1").
func NewKeySet() *KeySet {
	ks := &KeySet{}
	ks.Rotate()
	return ks
}

// Rotate adds a new active key and returns its kid.
func (k *KeySet) Rotate() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.seq++
	key, err := token.GenerateSigningKey(fmt.Sprintf("entra-%d", k.seq), "RS256")
	if err != nil {
		panic(err) // RS256 is always a supported algorithm
	}
	k.keys = append(k.keys, key)
	if len(k.keys) > 2 {
		k.keys = k.keys[len(k.keys)-2:]
	}
	return key.Kid
}

// ActiveKid returns the kid of the signing key.
func (k *KeySet) ActiveKid() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keys[len(k.keys)-1].Kid
}

// Sign signs claims with the active key (typ JWT).
func (k *KeySet) Sign(claims map[string]any) string {
	k.mu.RLock()
	key := k.keys[len(k.keys)-1]
	k.mu.RUnlock()
	return token.SignJWT(key, claims, "JWT")
}

// JWKS renders all published keys, oldest first.
func (k *KeySet) JWKS() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return token.PublicJWKSOf(k.keys...)
}
```

- [x] **Step 5: Run to verify pass**

Run: `go test ./internal/entra/ -v && gofmt -l internal/entra`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add internal/entra/keys.go internal/entra/keys_test.go internal/entra/helpers_test.go
git commit -m "feat(entra): shared RS256 key set with rotation" -m "Co-authored by AI"
```

---

### Task 4: Claims

**Files:**
- Create: `internal/entra/claims.go`, `internal/entra/claims_test.go`

**Interfaces:**
- Consumes: `Tenant`, `User`, `GroupObjectID`, `FormatObjectID` (Task 2); `token.RandomAuthorizationCode` (existing).
- Produces:
  - `type TokenInput struct { Origin, BasePath string; Tenant *Tenant; User *User; ClientID, Nonce string; Scopes []string; Now time.Time; Expiry int64 }`
  - `func Issuer(origin, basePath, tid string) string`
  - `func PairwiseSub(clientID, oid string) string`
  - `func IDTokenClaims(in TokenInput) map[string]any`, `func AccessTokenClaims(in TokenInput) map[string]any`
  - `func hasScope(scopes []string, s string) bool`
  - const `graphAppID = "00000003-0000-0000-c000-000000000000"`

- [x] **Step 1: Write the failing tests** `internal/entra/claims_test.go`

```go
package entra

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

var claimsNow = time.Unix(1790000000, 0)

func claimsInput(tn *Tenant, u *User, scopes ...string) TokenInput {
	return TokenInput{Origin: "http://h:1", BasePath: "entra", Tenant: tn, User: u, ClientID: "app",
		Nonce: "n1", Scopes: scopes, Now: claimsNow, Expiry: 3600}
}

func corpTenant() *Tenant {
	return &Tenant{TID: tidA, Name: "Corp", Domains: []string{"corp.example"}, GroupClaimFormat: FormatName, GroupLimit: 200}
}

func TestIDTokenClaimsCoreShape(t *testing.T) {
	u := &User{Username: "jane", TID: tidA, OID: "oid-1", Name: "Jane"}
	c := IDTokenClaims(claimsInput(corpTenant(), u, "openid", "profile"))
	want := map[string]any{
		"iss": "http://h:1/entra/" + tidA + "/v2.0", "aud": "app", "tid": tidA, "oid": "oid-1",
		"ver": "2.0", "name": "Jane", "preferred_username": "jane@corp.example", "nonce": "n1",
		"iat": int64(1790000000), "nbf": int64(1790000000), "exp": int64(1790003600),
		"sub": PairwiseSub("app", "oid-1"),
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("%s = %v, want %v", k, c[k], v)
		}
	}
	if c["uti"] == "" || c["uti"] == nil {
		t.Error("uti missing")
	}
	for _, absent := range []string{"email", "xms_edov", "amr", "groups", "_claim_names", "_claim_sources"} {
		if _, ok := c[absent]; ok {
			t.Errorf("%s must be absent", absent)
		}
	}
}

func TestPairwiseSubStablePerClientDifferentAcrossClients(t *testing.T) {
	a := PairwiseSub("app-a", "oid-1")
	if a != PairwiseSub("app-a", "oid-1") || a == PairwiseSub("app-b", "oid-1") || len(a) != 43 {
		t.Fatalf("pairwise sub %q", a)
	}
}

func TestEmailNeedsScopeAndEdovAmrWhenConfigured(t *testing.T) {
	no := false
	u := &User{Username: "jane", TID: tidA, OID: "o", Email: "jane@corp.example", EmailVerified: &no, AMR: []string{"pwd", "mfa"}}
	without := IDTokenClaims(claimsInput(corpTenant(), u, "openid"))
	if _, ok := without["email"]; ok {
		t.Error("email must require the email scope")
	}
	with := IDTokenClaims(claimsInput(corpTenant(), u, "openid", "email"))
	if with["email"] != "jane@corp.example" || with["xms_edov"] != false || !reflect.DeepEqual(with["amr"], []string{"pwd", "mfa"}) {
		t.Errorf("claims = %v", with)
	}
	if with["preferred_username"] != "jane@corp.example" {
		t.Errorf("preferred_username = %v", with["preferred_username"])
	}
}

func TestGroupsByFormat(t *testing.T) {
	u := &User{Username: "sam", TID: tidA, OID: "o", Groups: []string{"G1", "G2"}}
	names := IDTokenClaims(claimsInput(corpTenant(), u, "openid"))
	if !reflect.DeepEqual(names["groups"], []string{"G1", "G2"}) {
		t.Errorf("name groups = %v", names["groups"])
	}
	tn := corpTenant()
	tn.GroupClaimFormat = FormatObjectID
	ids := IDTokenClaims(claimsInput(tn, u, "openid"))
	want := []string{GroupObjectID(tidA, "G1"), GroupObjectID(tidA, "G2")}
	if !reflect.DeepEqual(ids["groups"], want) {
		t.Errorf("object_id groups = %v, want %v", ids["groups"], want)
	}
}

func TestGroupOverageBoundary(t *testing.T) {
	tn := corpTenant()
	tn.GroupLimit = 3
	atLimit := &User{Username: "a", TID: tidA, OID: "oid-a", Groups: []string{"G1", "G2", "G3"}}
	if c := IDTokenClaims(claimsInput(tn, atLimit, "openid")); c["groups"] == nil || c["_claim_names"] != nil {
		t.Errorf("at the limit, groups must be emitted: %v", c)
	}
	over := &User{Username: "b", TID: tidA, OID: "oid-b", Groups: []string{"G1", "G2", "G3", "G4"}}
	c := IDTokenClaims(claimsInput(tn, over, "openid"))
	if _, ok := c["groups"]; ok {
		t.Error("over the limit, groups must be omitted")
	}
	if !reflect.DeepEqual(c["_claim_names"], map[string]any{"groups": "src1"}) {
		t.Errorf("_claim_names = %v", c["_claim_names"])
	}
	src := c["_claim_sources"].(map[string]any)["src1"].(map[string]any)
	if ep, _ := src["endpoint"].(string); !strings.Contains(ep, "/users/oid-b/getMemberObjects") {
		t.Errorf("overage endpoint = %v", src["endpoint"])
	}
}

func TestAccessTokenClaims(t *testing.T) {
	u := &User{Username: "jane", TID: tidA, OID: "o"}
	c := AccessTokenClaims(claimsInput(corpTenant(), u, "openid", "profile", "email"))
	if c["aud"] != graphAppID || c["scp"] != "openid profile email" || c["tid"] != tidA {
		t.Errorf("access claims = %v", c)
	}
	if _, ok := c["nonce"]; ok {
		t.Error("access token must not carry nonce")
	}
}
```

- [x] **Step 2: Run to verify failure**

Run: `go test ./internal/entra/ -run 'Claims|Pairwise|Email|Groups|Overage' -v`
Expected: build failure `undefined: TokenInput`.

- [x] **Step 3: Implement `internal/entra/claims.go`**

```go
package entra

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/andychoi/mock-oidc/internal/token"
)

// graphAppID is Microsoft Graph's application ID, the audience of the access
// token Entra returns when only OIDC scopes are requested.
const graphAppID = "00000003-0000-0000-c000-000000000000"

// TokenInput carries everything needed to build one sign-in's tokens.
type TokenInput struct {
	Origin   string // proxy-aware scheme://host[:port]
	BasePath string
	Tenant   *Tenant // the signing-in user's tenant (also for organizations/common)
	User     *User
	ClientID string
	Nonce    string
	Scopes   []string
	Now      time.Time
	Expiry   int64
}

// Issuer is the v2.0 issuer of a tenant: {origin}/{basePath}/{tid}/v2.0.
func Issuer(origin, basePath, tid string) string {
	return origin + "/" + basePath + "/" + tid + "/v2.0"
}

// PairwiseSub is the per-application subject: base64url(SHA-256(clientID:oid)),
// 43 characters, like Entra's pairwise sub.
func PairwiseSub(clientID, oid string) string {
	sum := sha256.Sum256([]byte(clientID + ":" + oid))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// IDTokenClaims builds the v2.0 ID token claims (design §4.1–4.2).
func IDTokenClaims(in TokenInput) map[string]any {
	now := in.Now.Unix()
	c := map[string]any{
		"iss":                Issuer(in.Origin, in.BasePath, in.Tenant.TID),
		"aud":                in.ClientID,
		"iat":                now,
		"nbf":                now,
		"exp":                in.Now.Add(time.Duration(in.Expiry) * time.Second).Unix(),
		"tid":                in.Tenant.TID,
		"oid":                in.User.OID,
		"sub":                PairwiseSub(in.ClientID, in.User.OID),
		"ver":                "2.0",
		"name":               in.User.Name,
		"preferred_username": preferredUsername(in.Tenant, in.User),
		"uti":                token.RandomAuthorizationCode()[:22],
	}
	if in.Nonce != "" {
		c["nonce"] = in.Nonce
	}
	if in.User.Email != "" && hasScope(in.Scopes, "email") {
		c["email"] = in.User.Email
	}
	if in.User.EmailVerified != nil {
		c["xms_edov"] = *in.User.EmailVerified
	}
	if len(in.User.AMR) > 0 {
		c["amr"] = in.User.AMR
	}
	addGroups(c, in.Tenant, in.User)
	return c
}

// AccessTokenClaims builds a Graph-audience access token (RPs must not
// validate it; design §4.3).
func AccessTokenClaims(in TokenInput) map[string]any {
	c := IDTokenClaims(in)
	delete(c, "nonce")
	c["aud"] = graphAppID
	c["scp"] = strings.Join(in.Scopes, " ")
	return c
}

func preferredUsername(t *Tenant, u *User) string {
	if u.Email != "" {
		return u.Email
	}
	if len(t.Domains) > 0 {
		return u.Username + "@" + t.Domains[0]
	}
	return u.Username
}

// addGroups emits groups (names or object IDs), or the overage markers when
// the user has more groups than the tenant limit.
func addGroups(c map[string]any, t *Tenant, u *User) {
	if len(u.Groups) == 0 {
		return
	}
	if len(u.Groups) > t.GroupLimit {
		c["_claim_names"] = map[string]any{"groups": "src1"}
		c["_claim_sources"] = map[string]any{"src1": map[string]any{
			"endpoint": "https://graph.microsoft.com/v1.0/users/" + u.OID + "/getMemberObjects",
		}}
		return
	}
	vals := make([]string, 0, len(u.Groups))
	for _, g := range u.Groups {
		if t.GroupClaimFormat == FormatObjectID {
			vals = append(vals, GroupObjectID(t.TID, g))
		} else {
			vals = append(vals, g)
		}
	}
	c["groups"] = vals
}

func hasScope(scopes []string, s string) bool {
	for _, v := range scopes {
		if v == s {
			return true
		}
	}
	return false
}
```

- [x] **Step 4: Run to verify pass**

Run: `go test ./internal/entra/ -v && gofmt -l internal/entra`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/entra/claims.go internal/entra/claims_test.go
git commit -m "feat(entra): v2.0 ID/access token claims with groups and overage" -m "Co-authored by AI"
```

---

### Task 5: Handler, discovery, keys, logout, and wiring (Entra mode reachable)

**Files:**
- Create: `internal/entra/consent.go`, `internal/entra/handler.go`, `internal/e2e/entra_test.go`
- Modify: `internal/config/config.go` (`OAuth2Config`, `rawConfig`, `ParseJSON`, `LoadStandalone`), `internal/config/config_test.go`, `internal/server/server.go` (`buildRouter`)

**Interfaces:**
- Consumes: Tasks 2–4.
- Produces:
  - `type ConsentStore`; `func NewConsentStore(seed []Consent) *ConsentStore`; methods `Grant(clientID, tid string)`, `Has(clientID, tid string) bool`, `Reset()`, `List() []Consent`
  - `type Handler`; `type Option func(*Handler)`; `func WithClock(now func() time.Time) Option`; `func New(cfg *Config, opts ...Option) *Handler`; `func (h *Handler) RoutePattern() string`; `func (h *Handler) Handle(req *oauth2.Request) routing.Response`
  - unexported `type scope struct{ Segment string; Tenant *Tenant }` with `Multi() bool`; `func (h *Handler) resolveScope(seg string) (scope, *oauth2.Error)`; `func (h *Handler) route(req *oauth2.Request, sc scope, rest string) routing.Response`; `func origin(req *oauth2.Request) string`
  - `config.OAuth2Config.Entra *entra.Config`
  - e2e helpers `entraConfig`, `tidCorp`, `tidCust`, `entraGetJSON`

- [x] **Step 1: Write the failing config tests.** Append to `internal/config/config_test.go` (add imports `os`, `path/filepath` if not already present):

```go
func TestParseJSONEntraBlock(t *testing.T) {
	cfg, err := ParseJSON([]byte(`{"entra": {"tenants": [{"tid": "11111111-1111-1111-1111-111111111111"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Entra == nil || cfg.Entra.BasePath != "entra" {
		t.Fatalf("Entra = %+v", cfg.Entra)
	}
}

func TestParseJSONWithoutEntraLeavesItNil(t *testing.T) {
	cfg, err := ParseJSON([]byte(`{"interactiveLogin": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Entra != nil {
		t.Fatal("Entra must be nil when not configured")
	}
}

func TestParseJSONInvalidEntraFails(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"entra": {"tenants": []}}`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadStandaloneEntraConfigPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "entra.json")
	if err := os.WriteFile(p, []byte(`{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"JSON_CONFIG": `{"interactiveLogin": true}`, "ENTRA_CONFIG_PATH": p}
	cfg, err := LoadStandalone(func(k string) string { return env[k] })
	if err != nil || cfg.Entra == nil || !cfg.InteractiveLogin {
		t.Fatalf("inline JSON + entra file: cfg=%+v err=%v", cfg, err)
	}
	fallback := map[string]string{"JSON_CONFIG_PATH": filepath.Join(dir, "missing.json"), "ENTRA_CONFIG_PATH": p}
	cfg, err = LoadStandalone(func(k string) string { return fallback[k] })
	if err != nil || cfg.Entra == nil || !cfg.InteractiveLogin {
		t.Fatalf("fallback config + entra file: cfg=%+v err=%v", cfg, err)
	}
	missing := map[string]string{"JSON_CONFIG": `{}`, "ENTRA_CONFIG_PATH": filepath.Join(dir, "nope.json")}
	if _, err := LoadStandalone(func(k string) string { return missing[k] }); err == nil {
		t.Fatal("a missing ENTRA_CONFIG_PATH file must be an error")
	}
}
```

- [x] **Step 2: Write the failing e2e tests.** Create `internal/e2e/entra_test.go`:

```go
package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const (
	tidCorp = "11111111-1111-1111-1111-111111111111"
	tidCust = "22222222-2222-2222-2222-22222222abcd"
)

const entraConfig = `{
  "interactiveLogin": true,
  "entra": {
    "tenants": [
      {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"]},
      {"tid": "22222222-2222-2222-2222-22222222abcd", "name": "Customer X", "domains": ["customer-x.example"],
       "groupClaimFormat": "object_id", "consentRequired": true, "groupLimit": 3}
    ],
    "consents": [
      {"clientId": "iam", "tid": "11111111-1111-1111-1111-111111111111"},
      {"clientId": "iam", "tid": "22222222-2222-2222-2222-22222222abcd"}
    ],
    "users": [
      {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Kim",
       "email": "jane@corp.example", "emailVerified": true, "groups": ["AMS Engineers", "PMO"],
       "amr": ["pwd", "mfa"], "admin": true},
      {"username": "unassigned", "tid": "11111111-1111-1111-1111-111111111111", "error": "access_denied"},
      {"username": "disabled", "tid": "11111111-1111-1111-1111-111111111111", "error": "invalid_grant"},
      {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd", "name": "Sam Lee",
       "email": "sam@customer-x.example", "groups": ["G1", "G2"]},
      {"username": "many", "tid": "22222222-2222-2222-2222-22222222abcd", "groups": ["G1", "G2", "G3", "G4"]},
      {"username": "custadmin", "tid": "22222222-2222-2222-2222-22222222abcd", "admin": true},
      {"username": "mfa", "tid": "22222222-2222-2222-2222-22222222abcd", "error": "interaction_required"}
    ]
  }
}`

func entraGetJSON(t *testing.T, rawURL string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	status, _, body := do(t, http.MethodGet, rawURL, "", headers)
	var m map[string]any
	if status == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("decode %s: %v\n%s", rawURL, err, body)
		}
	}
	return status, m
}

func TestEntraDiscoveryPerTenant(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	want := map[string]string{
		"issuer":                 base + "/entra/" + tidCorp + "/v2.0",
		"authorization_endpoint": base + "/entra/" + tidCorp + "/oauth2/v2.0/authorize",
		"token_endpoint":         base + "/entra/" + tidCorp + "/oauth2/v2.0/token",
		"jwks_uri":               base + "/entra/" + tidCorp + "/discovery/v2.0/keys",
		"end_session_endpoint":   base + "/entra/" + tidCorp + "/oauth2/v2.0/logout",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %v, want %v", k, doc[k], v)
		}
	}
	if _, ok := doc["userinfo_endpoint"]; ok {
		t.Error("userinfo_endpoint must be absent")
	}
}

func TestEntraDiscoveryOrganizationsTemplate(t *testing.T) {
	_, base := startServer(t, entraConfig)
	for _, seg := range []string{"organizations", "common"} {
		_, doc := entraGetJSON(t, base+"/entra/"+seg+"/v2.0/.well-known/openid-configuration", nil)
		if doc["issuer"] != base+"/entra/{tenantid}/v2.0" {
			t.Errorf("%s issuer = %v", seg, doc["issuer"])
		}
		if doc["authorization_endpoint"] != base+"/entra/"+seg+"/oauth2/v2.0/authorize" {
			t.Errorf("%s authorization_endpoint = %v", seg, doc["authorization_endpoint"])
		}
	}
}

func TestEntraTenantPathCaseInsensitive(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, doc := entraGetJSON(t, base+"/entra/"+strings.ToUpper(tidCust)+"/v2.0/.well-known/openid-configuration", nil)
	if status != http.StatusOK || doc["issuer"] != base+"/entra/"+tidCust+"/v2.0" {
		t.Fatalf("status %d issuer %v", status, doc["issuer"])
	}
}

func TestEntraUnknownTenant(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, _, body := do(t, http.MethodGet, base+"/entra/99999999-9999-9999-9999-999999999999/v2.0/.well-known/openid-configuration", "", nil)
	if status != http.StatusBadRequest || !strings.Contains(body, "aadsts90002") {
		t.Fatalf("status %d body %s", status, body)
	}
}

func TestEntraKeysSharedAcrossTenants(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, _, corp := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/discovery/v2.0/keys", "", nil)
	_, _, cust := do(t, http.MethodGet, base+"/entra/"+tidCust+"/discovery/v2.0/keys", "", nil)
	_, _, common := do(t, http.MethodGet, base+"/entra/common/discovery/v2.0/keys", "", nil)
	if corp != cust || corp != common || !strings.Contains(corp, `"entra-1"`) {
		t.Fatalf("key sets differ or missing kid:\n%s\n%s\n%s", corp, cust, common)
	}
}

func TestEntraDiscoveryHonorsForwardedHeaders(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration",
		map[string]string{"x-forwarded-proto": "https", "x-forwarded-port": "443"})
	if doc["issuer"] != "https://127.0.0.1/entra/"+tidCorp+"/v2.0" {
		t.Fatalf("issuer = %v", doc["issuer"])
	}
}

func TestEntraLogoutAndOptions(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, hdr, _ := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/oauth2/v2.0/logout?post_logout_redirect_uri=http%3A%2F%2Fapp.test%2Fbye&state=s1", "", nil)
	if status != http.StatusFound || hdr.Get("Location") != "http://app.test/bye?state=s1" {
		t.Fatalf("logout status %d location %q", status, hdr.Get("Location"))
	}
	status, _, _ = do(t, http.MethodOptions, base+"/entra/"+tidCorp+"/oauth2/v2.0/token", "", map[string]string{"Origin": "http://app.test"})
	if status != http.StatusNoContent {
		t.Fatalf("OPTIONS status %d", status)
	}
}

func TestEntraBuiltinsNotShadowed(t *testing.T) {
	_, base := startServer(t, entraConfig)
	// the built-in issuer keeps working next to Entra mode
	_, doc := entraGetJSON(t, base+"/oidc/.well-known/openid-configuration", nil)
	if doc["issuer"] != base+"/oidc" {
		t.Fatalf("built-in issuer = %v", doc["issuer"])
	}
	// a path under /entra that ends in a built-in suffix is Entra's (404), not the built-in GET /token (405)
	status, _, _ := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/token", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("GET /entra/{tid}/token status %d, want 404", status)
	}
}

func TestEntraRoutesAbsentWhenDisabled(t *testing.T) {
	_, base := startServer(t, repoLikeConfig)
	_, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil)
	if _, entra := doc["tenant_region_scope"]; entra {
		t.Fatal("Entra discovery served although Entra mode is off")
	}
}
```

- [x] **Step 3: Run to verify failure**

Run: `go test ./internal/config/ ./internal/e2e/ -run 'Entra' -v`
Expected: build failure `cfg.Entra undefined`.

- [x] **Step 4: Implement `internal/entra/consent.go`**

```go
package entra

import (
	"sort"
	"strings"
	"sync"
)

// ConsentStore holds admin consents (client ID × tenant) in memory, seeded
// from the config.
type ConsentStore struct {
	mu      sync.RWMutex
	seed    []Consent
	granted map[string]Consent
}

// NewConsentStore returns a store holding the seed consents.
func NewConsentStore(seed []Consent) *ConsentStore {
	s := &ConsentStore{seed: append([]Consent(nil), seed...)}
	s.Reset()
	return s
}

func consentKey(clientID, tid string) string { return clientID + "|" + strings.ToLower(tid) }

// Grant records consent of clientID in tenant tid.
func (s *ConsentStore) Grant(clientID, tid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.granted[consentKey(clientID, tid)] = Consent{ClientID: clientID, TID: strings.ToLower(tid)}
}

// Has reports whether clientID has consent in tenant tid.
func (s *ConsentStore) Has(clientID, tid string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.granted[consentKey(clientID, tid)]
	return ok
}

// Reset restores the seed consents.
func (s *ConsentStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.granted = map[string]Consent{}
	for _, c := range s.seed {
		s.granted[consentKey(c.ClientID, c.TID)] = Consent{ClientID: c.ClientID, TID: strings.ToLower(c.TID)}
	}
}

// List returns the consents sorted by tenant, then client ID.
func (s *ConsentStore) List() []Consent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Consent, 0, len(s.granted))
	for _, c := range s.granted {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TID != out[j].TID {
			return out[i].TID < out[j].TID
		}
		return out[i].ClientID < out[j].ClientID
	})
	return out
}
```

- [x] **Step 5: Implement `internal/entra/handler.go`**

```go
package entra

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// Handler serves every Entra mode endpoint under /{basePath}/.
type Handler struct {
	cfg      *Config
	keys     *KeySet
	consents *ConsentStore
	now      func() time.Time
}

// Option configures a Handler.
type Option func(*Handler)

// WithClock replaces the wall clock (tests).
func WithClock(now func() time.Time) Option { return func(h *Handler) { h.now = now } }

// New builds a handler for a parsed config.
func New(cfg *Config, opts ...Option) *Handler {
	h := &Handler{cfg: cfg, keys: NewKeySet(), consents: NewConsentStore(cfg.Consents), now: time.Now}
	for _, o := range opts {
		o(h)
	}
	return h
}

// RoutePattern is the router path for AddFront: every path under /{basePath}/.
func (h *Handler) RoutePattern() string { return "/" + h.cfg.BasePath + "/*" }

// scope is the tenant segment of a request: one configured tenant, or the
// multi-tenant organizations/common endpoints (Tenant == nil).
type scope struct {
	Segment string // "organizations", "common", or the lowercase tid
	Tenant  *Tenant
}

// Multi reports whether the request came in on organizations/common.
func (s scope) Multi() bool { return s.Tenant == nil }

// Handle dispatches /{basePath}/{tenant}/... requests.
func (h *Handler) Handle(req *oauth2.Request) routing.Response {
	if req.Method == http.MethodOptions {
		return routing.Response{Status: http.StatusNoContent, Header: http.Header{}}
	}
	segs := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(segs) < 3 {
		return routing.NotFound("not found")
	}
	sc, oerr := h.resolveScope(segs[1])
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	return h.route(req, sc, strings.Join(segs[2:], "/"))
}

func (h *Handler) route(req *oauth2.Request, sc scope, rest string) routing.Response {
	get := req.Method == http.MethodGet
	switch {
	case get && rest == "v2.0/.well-known/openid-configuration":
		return h.discovery(req, sc)
	case get && rest == "discovery/v2.0/keys":
		return routing.JSONString(h.keys.JWKS())
	case rest == "oauth2/v2.0/logout":
		return logout(req)
	}
	return routing.NotFound("not found")
}

func (h *Handler) resolveScope(seg string) (scope, *oauth2.Error) {
	seg = strings.ToLower(seg)
	if seg == ScopeOrganizations || seg == ScopeCommon {
		return scope{Segment: seg}, nil
	}
	if t := h.cfg.Tenant(seg); t != nil {
		return scope{Segment: t.TID, Tenant: t}, nil
	}
	return scope{}, oauth2.InvalidRequest("AADSTS90002: Tenant '" + seg + "' not found.")
}

// origin is the proxy-aware scheme://host[:port], the same derivation the
// built-in issuer uses.
func origin(req *oauth2.Request) string {
	u := req.ProxyAwareURL()
	return u.Scheme + "://" + u.Host
}

func (h *Handler) discovery(req *oauth2.Request, sc scope) routing.Response {
	base := origin(req) + "/" + h.cfg.BasePath
	issuerTID := "{tenantid}"
	if !sc.Multi() {
		issuerTID = sc.Tenant.TID
	}
	ep := base + "/" + sc.Segment
	return routing.JSON(jsonx.Obj{
		{Name: "token_endpoint", V: ep + "/oauth2/v2.0/token"},
		{Name: "token_endpoint_auth_methods_supported", V: []string{"client_secret_post", "private_key_jwt", "client_secret_basic"}},
		{Name: "jwks_uri", V: ep + "/discovery/v2.0/keys"},
		{Name: "response_modes_supported", V: []string{"query", "fragment", "form_post"}},
		{Name: "subject_types_supported", V: []string{"pairwise"}},
		{Name: "id_token_signing_alg_values_supported", V: []string{"RS256"}},
		{Name: "response_types_supported", V: []string{"code", "id_token", "code id_token", "id_token token"}},
		{Name: "scopes_supported", V: []string{"openid", "profile", "email", "offline_access"}},
		{Name: "issuer", V: base + "/" + issuerTID + "/v2.0"},
		{Name: "request_uri_parameter_supported", V: false},
		{Name: "authorization_endpoint", V: ep + "/oauth2/v2.0/authorize"},
		{Name: "end_session_endpoint", V: ep + "/oauth2/v2.0/logout"},
		{Name: "claims_supported", V: []string{"sub", "iss", "aud", "exp", "iat", "nbf", "name", "nonce", "oid",
			"preferred_username", "tid", "ver", "email", "groups", "amr", "xms_edov"}},
		{Name: "tenant_region_scope", V: "NA"},
		{Name: "cloud_instance_name", V: "microsoftonline.com"},
	})
}

func logout(req *oauth2.Request) routing.Response {
	uri := req.QueryParam("post_logout_redirect_uri")
	if uri == "" {
		return routing.HTML("<!DOCTYPE html><html><body><p>You signed out of your account.</p></body></html>")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return routing.ErrorResponse(oauth2.InvalidRequest("invalid post_logout_redirect_uri"))
	}
	if st := req.QueryParam("state"); st != "" {
		q := u.Query()
		q.Set("state", st)
		u.RawQuery = q.Encode()
	}
	return routing.Redirect(u.String())
}
```

- [x] **Step 6: Wire the config.** In `internal/config/config.go`:

1. Add the import `"github.com/andychoi/mock-oidc/internal/entra"`.
2. Add to `OAuth2Config` (after `SSL`):

```go
	// Entra enables Entra mode when set (the "entra" JSON block or
	// ENTRA_CONFIG_PATH); nil keeps the server navikt-only.
	Entra *entra.Config `json:"-"`
```

3. Add to `rawConfig`:

```go
	Entra json.RawMessage `json:"entra"`
```

4. In `ParseJSON`, immediately before its final `return cfg, nil`:

```go
	if len(raw.Entra) > 0 && string(raw.Entra) != "null" {
		ec, err := entra.ParseConfig(raw.Entra)
		if err != nil {
			return nil, err
		}
		cfg.Entra = ec
	}
```

5. Rename the existing `LoadStandalone` to `loadBaseStandalone` (body unchanged, doc comment stays on the new wrapper) and add:

```go
// LoadStandalone mirrors StandaloneConfig: JSON_CONFIG env (inline JSON) wins,
// then JSON_CONFIG_PATH (default config.json, missing file tolerated), then
// the fallback config {interactiveLogin: true}. ENTRA_CONFIG_PATH, when set,
// enables Entra mode from a separate file (it overrides an "entra" block).
func LoadStandalone(getenv func(string) string) (*OAuth2Config, error) {
	cfg, err := loadBaseStandalone(getenv)
	if err != nil {
		return nil, err
	}
	if p := getenv("ENTRA_CONFIG_PATH"); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("ENTRA_CONFIG_PATH: %w", err)
		}
		ec, err := entra.ParseConfig(data)
		if err != nil {
			return nil, err
		}
		cfg.Entra = ec
	}
	return cfg, nil
}
```

- [x] **Step 7: Mount the route.** In `internal/server/server.go`, add the import `"github.com/andychoi/mock-oidc/internal/entra"` and, in `buildRouter` immediately before `return rt`:

```go
	if s.config.Entra != nil {
		eh := entra.New(s.config.Entra)
		rt.AddFront("", eh.RoutePattern(), eh.Handle)
	}
```

- [x] **Step 8: Run to verify pass**

Run: `gofmt -l . | grep -v '^docs/'; go vet ./... && go test ./...`
Expected: no gofmt output; all tests PASS, including every pre-existing test.

- [x] **Step 9: Commit**

```bash
git add internal/entra/consent.go internal/entra/handler.go internal/config/config.go internal/config/config_test.go internal/server/server.go internal/e2e/entra_test.go
git commit -m "feat(entra): mount Entra mode with discovery, shared JWKS and logout" -m "Co-authored by AI"
```

---

### Task 6: Account picker, sign-in, and token endpoint

**Files:**
- Create: `internal/entra/authorize.go`, `internal/entra/templates/picker.html.tmpl`, `internal/entra/token.go`, `internal/entra/handler_test.go`
- Modify: `internal/entra/handler.go` (`Handler` struct, `New`, `route`), `internal/e2e/entra_test.go` (append)

**Interfaces:**
- Consumes: Tasks 2–5; `oauth2.ParseAuthRequest`, `(*oauth2.AuthRequest).ImpliesCodeFlow`, `.SuccessRedirectURL`, `oauth2.ParseTokenRequest`, `token.RandomAuthorizationCode`.
- Produces (used by Task 7): `type pickerPage struct{ Heading, Action, Submit string; ShowCancel bool; Tenants []pickerTenant }`; `func (h *Handler) pickerTenants(sc scope) []pickerTenant`; `func renderPicker(p pickerPage) routing.Response`; `func (h *Handler) postedUser(req *oauth2.Request, sc scope) (*Tenant, *User, *oauth2.Error)`; `func errorRedirect(redirectURI, state, code, description string) routing.Response`; `func redirectWith(redirectURI string, params map[string]string) routing.Response`; `Handler.codes *codeStore`.

- [x] **Step 1: Write the failing unit test** for code expiry (needs the clock option) in `internal/entra/handler_test.go`:

```go
package entra

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

const unitConfig = `{
  "tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp"}],
  "users": [{"username": "jane", "tid": "11111111-1111-1111-1111-111111111111"}]
}`

func mustConfig(t *testing.T, js string) *Config {
	t.Helper()
	c, err := ParseConfig([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// serve runs one request through the handler, like the router would.
func serve(h *Handler, method, target, form string) routing.Response {
	r := httptest.NewRequest(method, target, strings.NewReader(form))
	if form != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req, err := oauth2.FromHTTPRequest(r)
	if err != nil {
		panic(err)
	}
	return h.Handle(req)
}

const unitAuthorize = "http://mock.test/entra/11111111-1111-1111-1111-111111111111/oauth2/v2.0/authorize" +
	"?response_type=code&client_id=app&redirect_uri=http%3A%2F%2Fapp.test%2Fcb&scope=openid&state=s"

// signIn posts the picker form and returns the issued code (or "" on failure).
func signIn(h *Handler, username string) string {
	resp := serve(h, http.MethodPost, unitAuthorize, "tid=11111111-1111-1111-1111-111111111111&username="+username)
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.Status != http.StatusFound || err != nil {
		return ""
	}
	return loc.Query().Get("code")
}

func redeem(h *Handler, code string) routing.Response {
	form := "grant_type=authorization_code&client_id=app&code=" + url.QueryEscape(code) +
		"&redirect_uri=" + url.QueryEscape("http://app.test/cb")
	return serve(h, http.MethodPost, "http://mock.test/entra/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token", form)
}

func TestCodeExpiresAfterTenMinutes(t *testing.T) {
	now := time.Unix(1790000000, 0)
	h := New(mustConfig(t, unitConfig), WithClock(func() time.Time { return now }))
	code := signIn(h, "jane")
	if code == "" {
		t.Fatal("sign-in failed")
	}
	now = now.Add(11 * time.Minute)
	resp := redeem(h, code)
	if resp.Status != http.StatusBadRequest || !strings.Contains(resp.Body, "aadsts70008") {
		t.Fatalf("status %d body %s", resp.Status, resp.Body)
	}
}
```

- [x] **Step 2: Append the failing e2e tests** to `internal/e2e/entra_test.go`. Add these imports to the file's import block: `"crypto"`, `"crypto/rsa"`, `"crypto/sha256"`, `"encoding/base64"`, `"math/big"`, `"net/url"`, `"reflect"`, `"github.com/andychoi/mock-oidc/internal/entra"`.

```go
const entraRedirect = "http://app.test/cb"

func entraAuthorizeURL(base, seg, clientID, extra string) string {
	return base + "/entra/" + seg + "/oauth2/v2.0/authorize?response_type=code&client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape(entraRedirect) + "&scope=" + url.QueryEscape("openid profile email") +
		"&state=st1&nonce=n1" + extra
}

var formHeaders = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

// entraSignIn posts an account choice and returns the redirect Location.
func entraSignIn(t *testing.T, authorizeURL, tid, username string) *url.URL {
	t.Helper()
	form := url.Values{"tid": {tid}, "username": {username}}.Encode()
	status, hdr, body := do(t, http.MethodPost, authorizeURL, form, formHeaders)
	if status != http.StatusFound {
		t.Fatalf("sign-in status %d: %s", status, body)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// entraRedeem exchanges a code at the {seg} token endpoint.
func entraRedeem(t *testing.T, base, seg, clientID, code, extraForm string, headers map[string]string) (int, map[string]any, string) {
	t.Helper()
	form := "grant_type=authorization_code&client_id=" + clientID + "&client_secret=s&code=" + url.QueryEscape(code) +
		"&redirect_uri=" + url.QueryEscape(entraRedirect) + extraForm
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for k, v := range headers {
		h[k] = v
	}
	status, _, body := do(t, http.MethodPost, base+"/entra/"+seg+"/oauth2/v2.0/token", form, h)
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	return status, m, body
}

// verifyEntraJWT checks the RS256 signature against the shared JWKS and returns the claims.
func verifyEntraJWT(t *testing.T, base, jwt string) map[string]any {
	t.Helper()
	_, _, jwks := do(t, http.MethodGet, base+"/entra/common/discovery/v2.0/keys", "", nil)
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", jwt)
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr struct{ Kid, Alg string }
	_ = json.Unmarshal(hb, &hdr)
	var doc struct {
		Keys []struct{ Kid, N, E string } `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwks), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range doc.Keys {
		if k.Kid != hdr.Kid {
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
		return decodeClaims(t, jwt)
	}
	t.Fatalf("kid %q not in JWKS %s", hdr.Kid, jwks)
	return nil
}

func strList(v any) []string {
	var out []string
	for _, e := range v.([]any) {
		out = append(out, e.(string))
	}
	return out
}

func TestEntraPickerScopes(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, _, page := do(t, http.MethodGet, entraAuthorizeURL(base, tidCorp, "iam", ""), "", nil)
	if !strings.Contains(page, `value="jane"`) || strings.Contains(page, `value="sam"`) {
		t.Errorf("tenant picker must list only corp users:\n%s", page)
	}
	_, _, page = do(t, http.MethodGet, entraAuthorizeURL(base, "organizations", "iam", ""), "", nil)
	if !strings.Contains(page, `value="jane"`) || !strings.Contains(page, `value="sam"`) || !strings.Contains(page, "Customer X") {
		t.Errorf("organizations picker must list all tenants:\n%s", page)
	}
}

func TestEntraTenantSignInAndTokens(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "jane")
	if loc.Query().Get("state") != "st1" || loc.Query().Get("code") == "" {
		t.Fatalf("redirect = %s", loc)
	}
	status, tok, body := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", nil)
	if status != http.StatusOK || tok["token_type"] != "Bearer" || tok["access_token"] == nil {
		t.Fatalf("token status %d: %s", status, body)
	}
	if _, ok := tok["refresh_token"]; ok {
		t.Error("refresh_token only with offline_access")
	}
	c := verifyEntraJWT(t, base, tok["id_token"].(string))
	if c["iss"] != base+"/entra/"+tidCorp+"/v2.0" || c["tid"] != tidCorp || c["aud"] != "iam" || c["nonce"] != "n1" || c["ver"] != "2.0" {
		t.Errorf("claims = %v", c)
	}
	if c["email"] != "jane@corp.example" || c["xms_edov"] != true || !reflect.DeepEqual(strList(c["amr"]), []string{"pwd", "mfa"}) {
		t.Errorf("email/edov/amr = %v %v %v", c["email"], c["xms_edov"], c["amr"])
	}
	if !reflect.DeepEqual(strList(c["groups"]), []string{"AMS Engineers", "PMO"}) {
		t.Errorf("groups = %v", c["groups"])
	}
	if c["sub"] != entra.PairwiseSub("iam", c["oid"].(string)) {
		t.Errorf("sub %v is not pairwise for oid %v", c["sub"], c["oid"])
	}
}

func TestEntraOrganizationsSignIn(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, "organizations", "iam", ""), tidCust, "sam")
	status, tok, body := entraRedeem(t, base, "organizations", "iam", loc.Query().Get("code"), "", nil)
	if status != http.StatusOK {
		t.Fatalf("token status %d: %s", status, body)
	}
	c := verifyEntraJWT(t, base, tok["id_token"].(string))
	if c["iss"] != base+"/entra/"+tidCust+"/v2.0" || c["tid"] != tidCust {
		t.Errorf("iss/tid must come from the user's tenant: %v %v", c["iss"], c["tid"])
	}
	want := []string{entra.GroupObjectID(tidCust, "G1"), entra.GroupObjectID(tidCust, "G2")}
	if !reflect.DeepEqual(strList(c["groups"]), want) {
		t.Errorf("object-ID groups = %v, want %v", c["groups"], want)
	}
}

func TestEntraGroupOverage(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCust, "iam", ""), tidCust, "many")
	_, tok, _ := entraRedeem(t, base, tidCust, "iam", loc.Query().Get("code"), "", nil)
	c := verifyEntraJWT(t, base, tok["id_token"].(string))
	if _, ok := c["groups"]; ok {
		t.Error("groups must be omitted on overage")
	}
	names, _ := c["_claim_names"].(map[string]any)
	if names["groups"] != "src1" {
		t.Errorf("_claim_names = %v", c["_claim_names"])
	}
}

func TestEntraConsentRequired(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCust, "newapp", ""), tidCust, "sam")
	q := loc.Query()
	if q.Get("error") != "consent_required" || q.Get("state") != "st1" || !strings.Contains(q.Get("error_description"), "AADSTS65001") {
		t.Fatalf("redirect = %s", loc)
	}
	// corp does not require consent: any client may sign in there
	loc = entraSignIn(t, entraAuthorizeURL(base, tidCorp, "newapp", ""), tidCorp, "jane")
	if loc.Query().Get("code") == "" {
		t.Fatalf("corp sign-in for newapp = %s", loc)
	}
}

func TestEntraErrorInjection(t *testing.T) {
	_, base := startServer(t, entraConfig)
	if q := entraSignIn(t, entraAuthorizeURL(base, tidCust, "iam", ""), tidCust, "mfa").Query(); q.Get("error") != "interaction_required" || !strings.Contains(q.Get("error_description"), "AADSTS50076") {
		t.Errorf("mfa user = %v", q)
	}
	if q := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "unassigned").Query(); q.Get("error") != "access_denied" || !strings.Contains(q.Get("error_description"), "AADSTS50105") {
		t.Errorf("unassigned user = %v", q)
	}
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "disabled")
	status, _, body := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", nil)
	if status != http.StatusBadRequest || !strings.Contains(body, "aadsts50057") {
		t.Errorf("disabled user token: %d %s", status, body)
	}
}

func TestEntraCodeRules(t *testing.T) {
	_, base := startServer(t, entraConfig)
	code := func(seg, tid, user, extra string) string {
		return entraSignIn(t, entraAuthorizeURL(base, seg, "iam", extra), tid, user).Query().Get("code")
	}
	// single use
	c1 := code(tidCorp, tidCorp, "jane", "")
	if s, _, _ := entraRedeem(t, base, tidCorp, "iam", c1, "", nil); s != http.StatusOK {
		t.Fatalf("first redemption %d", s)
	}
	if s, _, body := entraRedeem(t, base, tidCorp, "iam", c1, "", nil); s != http.StatusBadRequest || !strings.Contains(body, "aadsts70008") {
		t.Errorf("replay: %d %s", s, body)
	}
	// cross-tenant redemption
	c2 := code("organizations", tidCorp, "jane", "")
	if s, _, _ := entraRedeem(t, base, tidCust, "iam", c2, "", nil); s != http.StatusBadRequest {
		t.Errorf("code from organizations(corp user) redeemed at customer tenant: %d", s)
	}
	// user's own tenant path is allowed for an organizations code
	c3 := code("organizations", tidCorp, "jane", "")
	if s, _, body := entraRedeem(t, base, tidCorp, "iam", c3, "", nil); s != http.StatusOK {
		t.Errorf("organizations code at user's tenant path: %d %s", s, body)
	}
	// client and redirect must match
	if s, _, _ := entraRedeem(t, base, tidCorp, "other", code(tidCorp, tidCorp, "jane", ""), "", nil); s != http.StatusBadRequest {
		t.Errorf("client mismatch: %d", s)
	}
	c4 := code(tidCorp, tidCorp, "jane", "")
	form := "grant_type=authorization_code&client_id=iam&code=" + url.QueryEscape(c4) + "&redirect_uri=" + url.QueryEscape("http://evil.test/cb")
	if s, _, _ := do(t, http.MethodPost, base+"/entra/"+tidCorp+"/oauth2/v2.0/token", form, formHeaders); s != http.StatusBadRequest {
		t.Errorf("redirect mismatch: %d", s)
	}
	// PKCE S256
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	pkce := "&code_challenge=" + base64.RawURLEncoding.EncodeToString(sum[:]) + "&code_challenge_method=S256"
	if s, _, body := entraRedeem(t, base, tidCorp, "iam", code(tidCorp, tidCorp, "jane", pkce), "", nil); s != http.StatusBadRequest || !strings.Contains(body, "aadsts501481") {
		t.Errorf("missing verifier: %d %s", s, body)
	}
	if s, _, body := entraRedeem(t, base, tidCorp, "iam", code(tidCorp, tidCorp, "jane", pkce), "&code_verifier="+verifier, nil); s != http.StatusOK {
		t.Errorf("correct verifier: %d %s", s, body)
	}
}

func TestEntraPostedUserOutsideRouteTenant(t *testing.T) {
	_, base := startServer(t, entraConfig)
	form := url.Values{"tid": {tidCust}, "username": {"sam"}}.Encode()
	status, _, body := do(t, http.MethodPost, entraAuthorizeURL(base, tidCorp, "iam", ""), form, formHeaders)
	if status != http.StatusBadRequest || !strings.Contains(body, "aadsts50020") {
		t.Fatalf("status %d body %s", status, body)
	}
}

func TestEntraUnsupportedResponseType(t *testing.T) {
	_, base := startServer(t, entraConfig)
	u := strings.Replace(entraAuthorizeURL(base, tidCorp, "iam", ""), "response_type=code", "response_type=id_token", 1)
	status, hdr, _ := do(t, http.MethodGet, u, "", nil)
	loc, _ := url.Parse(hdr.Get("Location"))
	if status != http.StatusFound || loc.Query().Get("error") != "unsupported_response_type" {
		t.Fatalf("status %d location %s", status, hdr.Get("Location"))
	}
}

func TestEntraUnsupportedGrantIsEntraError(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, _, body := do(t, http.MethodPost, base+"/entra/"+tidCorp+"/oauth2/v2.0/token",
		"grant_type=client_credentials&client_id=iam&client_secret=s&scope=x", formHeaders)
	if status != http.StatusBadRequest || !strings.Contains(body, "unsupported_grant_type") {
		t.Fatalf("status %d body %s (a 200 here means the built-in token handler answered)", status, body)
	}
}

func TestEntraTokenIssuerHonorsForwardedHeaders(t *testing.T) {
	_, base := startServer(t, entraConfig)
	loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "jane")
	fwd := map[string]string{"x-forwarded-proto": "https", "x-forwarded-port": "443"}
	_, tok, body := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", fwd)
	idt, ok := tok["id_token"].(string)
	if !ok {
		t.Fatalf("no id_token: %s", body)
	}
	if c := decodeClaims(t, idt); c["iss"] != "https://127.0.0.1/entra/"+tidCorp+"/v2.0" {
		t.Fatalf("iss = %v", c["iss"])
	}
}
```

- [x] **Step 3: Run to verify failure**

Run: `go test ./internal/entra/ ./internal/e2e/ -run 'Entra|Code' -v`
Expected: `TestCodeExpiresAfterTenMinutes` fails (sign-in returns 404, so `sign-in failed`); new e2e tests fail with 404s.

- [x] **Step 4: Create the template** `internal/entra/templates/picker.html.tmpl`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in to your account (mock Entra ID)</title>
<style>
body{font-family:"Segoe UI",system-ui,sans-serif;background:#f2f2f2;margin:0}
main{max-width:440px;margin:48px auto;background:#fff;padding:32px 40px;box-shadow:0 2px 6px rgba(0,0,0,.2)}
h1{font-size:22px;font-weight:600;margin:0 0 16px}
h2{font-size:12px;color:#555;margin:20px 0 6px;text-transform:uppercase;letter-spacing:.04em}
form{margin:0}
button{display:block;width:100%;text-align:left;padding:10px 12px;margin:4px 0;border:1px solid #ddd;background:#fff;cursor:pointer;font-size:15px}
button:hover{background:#f5f5f5}
.email{color:#666;font-size:13px}
.note{color:#888;font-size:12px;margin-top:24px}
</style>
</head>
<body>
<main>
<h1>{{.Heading}}</h1>
{{range $t := .Tenants}}
<h2>{{$t.Name}}</h2>
{{range $t.Users}}
<form method="post" action="{{$.Action}}">
<input type="hidden" name="action" value="{{$.Submit}}">
<input type="hidden" name="tid" value="{{$t.TID}}">
<input type="hidden" name="username" value="{{.Username}}">
<button type="submit">{{.Name}}{{if .Email}}<br><span class="email">{{.Email}}</span>{{end}}</button>
</form>
{{end}}
{{end}}
{{if .ShowCancel}}
<form method="post" action="{{.Action}}"><input type="hidden" name="action" value="cancel"><button type="submit">Cancel</button></form>
{{end}}
<p class="note">mock-oidc Entra mode: no password required.</p>
</main>
</body>
</html>
```

- [x] **Step 5: Implement `internal/entra/authorize.go`**

```go
package entra

import (
	"embed"
	"html/template"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
)

//go:embed templates/picker.html.tmpl
var templatesFS embed.FS

var pickerTmpl = template.Must(template.ParseFS(templatesFS, "templates/picker.html.tmpl"))

// codeTTL mirrors Entra's roughly 10-minute authorization code lifetime.
const codeTTL = 10 * time.Minute

type authCode struct {
	req      *oauth2.AuthRequest
	tid      string // the user's tenant
	username string
	segment  string // tenant path segment the code was issued on
	expires  time.Time
}

type codeStore struct {
	mu    sync.Mutex
	codes map[string]authCode
}

func newCodeStore() *codeStore { return &codeStore{codes: map[string]authCode{}} }

func (s *codeStore) put(code string, c authCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code] = c
}

// take removes and returns a code: codes are single-use even when redemption fails.
func (s *codeStore) take(code string) (authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	delete(s.codes, code)
	return c, ok
}

type pickerUser struct{ Username, Name, Email string }

type pickerTenant struct {
	TID, Name string
	Users     []pickerUser
}

type pickerPage struct {
	Heading    string
	Action     string // form target: the current request URI (query preserved)
	Submit     string // value of the hidden "action" field on account buttons
	ShowCancel bool
	Tenants    []pickerTenant
}

// pickerTenants lists the accounts selectable in a scope: one tenant, or all
// tenants for organizations/common.
func (h *Handler) pickerTenants(sc scope) []pickerTenant {
	var out []pickerTenant
	for i := range h.cfg.Tenants {
		t := &h.cfg.Tenants[i]
		if !sc.Multi() && t.TID != sc.Tenant.TID {
			continue
		}
		pt := pickerTenant{TID: t.TID, Name: t.Name}
		for _, u := range h.cfg.UsersIn(t.TID) {
			pt.Users = append(pt.Users, pickerUser{Username: u.Username, Name: u.Name, Email: u.Email})
		}
		out = append(out, pt)
	}
	return out
}

func renderPicker(p pickerPage) routing.Response {
	var b strings.Builder
	if err := pickerTmpl.Execute(&b, p); err != nil {
		return routing.ErrorResponse(oauth2.ServerError("picker template: " + err.Error()))
	}
	return routing.HTML(b.String())
}

func (h *Handler) authorizeGet(req *oauth2.Request, sc scope) routing.Response {
	ar, oerr := oauth2.ParseAuthRequest(req.URL.Query())
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	if !ar.ImpliesCodeFlow() {
		return unsupportedResponseType(ar)
	}
	return renderPicker(pickerPage{Heading: "Pick an account", Action: req.URL.RequestURI(), Submit: "signin", Tenants: h.pickerTenants(sc)})
}

func (h *Handler) authorizePost(req *oauth2.Request, sc scope) routing.Response {
	ar, oerr := oauth2.ParseAuthRequest(req.URL.Query())
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	if !ar.ImpliesCodeFlow() {
		return unsupportedResponseType(ar)
	}
	t, u, oerr := h.postedUser(req, sc)
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	switch u.Error {
	case ErrInteractionRequired:
		return errorRedirect(ar.RedirectURI, ar.State, "interaction_required",
			"AADSTS50076: Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access the resource.")
	case ErrAccessDenied:
		return errorRedirect(ar.RedirectURI, ar.State, "access_denied",
			"AADSTS50105: The signed in user is not assigned to a role for the application.")
	}
	if t.ConsentRequired && !h.consents.Has(ar.ClientID, t.TID) {
		return errorRedirect(ar.RedirectURI, ar.State, "consent_required",
			"AADSTS65001: The user or administrator has not consented to use the application with ID '"+ar.ClientID+"'.")
	}
	code := token.RandomAuthorizationCode()
	h.codes.put(code, authCode{req: ar, tid: t.TID, username: u.Username, segment: sc.Segment, expires: h.now().Add(codeTTL)})
	loc, oerr := ar.SuccessRedirectURL(code)
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	return routing.Redirect(loc)
}

// postedUser resolves the account chosen on the picker (form fields tid and
// username) within the request scope. Shared with admin consent.
func (h *Handler) postedUser(req *oauth2.Request, sc scope) (*Tenant, *User, *oauth2.Error) {
	u := h.cfg.User(req.FormParam("tid"), req.FormParam("username"))
	if u == nil {
		return nil, nil, oauth2.InvalidRequest("AADSTS50034: The user account does not exist in this directory.")
	}
	if !sc.Multi() && u.TID != sc.Tenant.TID {
		return nil, nil, oauth2.InvalidRequest("AADSTS50020: User account from tenant '" + u.TID + "' does not exist in tenant '" + sc.Tenant.TID + "'.")
	}
	return h.cfg.Tenant(u.TID), u, nil
}

func unsupportedResponseType(ar *oauth2.AuthRequest) routing.Response {
	return errorRedirect(ar.RedirectURI, ar.State, "unsupported_response_type",
		"AADSTS70005: response_type '"+strings.Join(ar.ResponseType, " ")+"' is not supported by the mock; use 'code'.")
}

// errorRedirect sends the browser back to the client with an OAuth error.
func errorRedirect(redirectURI, state, code, description string) routing.Response {
	return redirectWith(redirectURI, map[string]string{"error": code, "error_description": description, "state": state})
}

// redirectWith appends the non-empty params to redirectURI's query.
func redirectWith(redirectURI string, params map[string]string) routing.Response {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return routing.ErrorResponse(oauth2.InvalidRequest("invalid redirect_uri: " + err.Error()))
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return routing.Redirect(u.String())
}
```

- [x] **Step 6: Implement `internal/entra/token.go`**

```go
package entra

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
)

func (h *Handler) token(req *oauth2.Request, sc scope) routing.Response {
	if gt := strings.TrimSpace(req.FormParam("grant_type")); gt != oauth2.GrantAuthorizationCode {
		return routing.ErrorResponse(&oauth2.Error{Code: "unsupported_grant_type",
			Description: "AADSTS70003: The app requested an unsupported grant type '" + gt + "'.", Status: http.StatusBadRequest})
	}
	tr, oerr := oauth2.ParseTokenRequest(req)
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	c, ok := h.codes.take(tr.Code)
	if !ok || h.now().After(c.expires) {
		return invalidGrant("AADSTS70008: The provided authorization code or refresh token has expired or was already used.")
	}
	if sc.Segment != c.segment && sc.Segment != c.tid {
		return invalidGrant("authorization code was issued for tenant path '" + c.segment + "'")
	}
	if tr.ClientID != c.req.ClientID {
		return invalidGrant("client_id does not match the authorization request")
	}
	if tr.RedirectURI != c.req.RedirectURI {
		return invalidGrant("redirect_uri does not match the authorization request")
	}
	if !pkceOK(c.req, tr.CodeVerifier) {
		return invalidGrant("AADSTS501481: The Code_Verifier does not match the code_challenge supplied in the authorization request.")
	}
	t := h.cfg.Tenant(c.tid)
	u := h.cfg.User(c.tid, c.username)
	if u.Error == ErrInvalidGrant {
		return invalidGrant("AADSTS50057: The user account is disabled.")
	}
	in := TokenInput{Origin: origin(req), BasePath: h.cfg.BasePath, Tenant: t, User: u, ClientID: c.req.ClientID,
		Nonce: c.req.Nonce, Scopes: c.req.Scope, Now: h.now(), Expiry: h.cfg.TokenExpiry}
	resp := jsonx.Obj{
		{Name: "token_type", V: "Bearer"},
		{Name: "scope", V: strings.Join(c.req.Scope, " ")},
		{Name: "expires_in", V: h.cfg.TokenExpiry},
		{Name: "ext_expires_in", V: h.cfg.TokenExpiry},
		{Name: "access_token", V: h.keys.Sign(AccessTokenClaims(in))},
	}
	if hasScope(c.req.Scope, "offline_access") {
		resp = append(resp, jsonx.Field{Name: "refresh_token", V: token.RandomAuthorizationCode()})
	}
	resp = append(resp, jsonx.Field{Name: "id_token", V: h.keys.Sign(IDTokenClaims(in))})
	return routing.JSON(resp)
}

func invalidGrant(description string) routing.Response {
	return routing.ErrorResponse(oauth2.InvalidGrant(description))
}

// pkceOK enforces PKCE when the authorize request carried a code_challenge:
// a missing or wrong code_verifier fails (S256 or plain).
func pkceOK(ar *oauth2.AuthRequest, verifier string) bool {
	if ar.CodeChallenge == "" {
		return true
	}
	if verifier == "" {
		return false
	}
	computed := verifier
	if ar.CodeChallengeMethod == "S256" {
		d := sha256.Sum256([]byte(verifier))
		computed = base64.RawURLEncoding.EncodeToString(d[:])
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(ar.CodeChallenge)) == 1
}
```

- [x] **Step 7: Extend the handler.** In `internal/entra/handler.go`:

1. Add the field `codes *codeStore` to `Handler`, and in `New` initialize it:

```go
	h := &Handler{cfg: cfg, keys: NewKeySet(), consents: NewConsentStore(cfg.Consents), codes: newCodeStore(), now: time.Now}
```

2. Replace `route` with:

```go
func (h *Handler) route(req *oauth2.Request, sc scope, rest string) routing.Response {
	get, post := req.Method == http.MethodGet, req.Method == http.MethodPost
	switch {
	case get && rest == "v2.0/.well-known/openid-configuration":
		return h.discovery(req, sc)
	case get && rest == "discovery/v2.0/keys":
		return routing.JSONString(h.keys.JWKS())
	case get && rest == "oauth2/v2.0/authorize":
		return h.authorizeGet(req, sc)
	case post && rest == "oauth2/v2.0/authorize":
		return h.authorizePost(req, sc)
	case post && rest == "oauth2/v2.0/token":
		return h.token(req, sc)
	case rest == "oauth2/v2.0/logout":
		return logout(req)
	}
	return routing.NotFound("not found")
}
```

- [x] **Step 8: Run to verify pass**

Run: `gofmt -l . | grep -v '^docs/'; go vet ./... && go test ./...`
Expected: all PASS.

- [x] **Step 9: Commit**

```bash
git add internal/entra/authorize.go internal/entra/templates/picker.html.tmpl internal/entra/token.go internal/entra/handler.go internal/entra/handler_test.go internal/e2e/entra_test.go
git commit -m "feat(entra): account picker, sign-in with error injection, token endpoint" -m "Co-authored by AI"
```

---

### Task 7: Admin consent and test-helper API

**Files:**
- Create: `internal/entra/adminconsent.go`, `internal/entra/testapi.go`
- Modify: `internal/entra/handler.go` (`Handle`, `route`), `internal/entra/handler_test.go` (append), `internal/e2e/entra_test.go` (append)

**Interfaces:**
- Consumes: `pickerPage`, `pickerTenants`, `renderPicker`, `postedUser`, `errorRedirect`, `redirectWith` (Task 6); `ConsentStore` (Task 5); `KeySet.Rotate` (Task 3); `GroupObjectID` (Task 2).
- Produces: `func (h *Handler) adminConsentGet/adminConsentPost(req *oauth2.Request, sc scope) routing.Response`; `func (h *Handler) testAPI(req *oauth2.Request, action string) routing.Response`.

- [x] **Step 1: Append the failing race test** to `internal/entra/handler_test.go` (add `"sync"` to its imports):

```go
func TestConcurrentSignInsRotationAndConsent(t *testing.T) {
	h := New(mustConfig(t, unitConfig))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			code := signIn(h, "jane")
			if resp := redeem(h, code); code == "" || resp.Status != http.StatusOK {
				t.Errorf("sign-in/redeem failed: code=%q status=%d", code, resp.Status)
			}
		}()
		go func() {
			defer wg.Done()
			serve(h, http.MethodPost, "http://mock.test/entra/_entra/rotate-keys", "")
		}()
		go func() {
			defer wg.Done()
			h.consents.Grant("app", "11111111-1111-1111-1111-111111111111")
			serve(h, http.MethodGet, "http://mock.test/entra/_entra/consents", "")
		}()
	}
	wg.Wait()
}
```

- [x] **Step 2: Append the failing e2e tests** to `internal/e2e/entra_test.go`:

```go
func entraConsentURL(base, seg, clientID string) string {
	return base + "/entra/" + seg + "/v2.0/adminconsent?client_id=" + clientID +
		"&redirect_uri=" + url.QueryEscape(entraRedirect) + "&state=cs1&scope=" + url.QueryEscape("https://graph.microsoft.com/.default")
}

func consentSubmit(t *testing.T, consentURL string, form url.Values) url.Values {
	t.Helper()
	status, hdr, body := do(t, http.MethodPost, consentURL, form.Encode(), formHeaders)
	if status != http.StatusFound {
		t.Fatalf("consent status %d: %s", status, body)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc.Query()
}

func TestEntraAdminConsentFlow(t *testing.T) {
	_, base := startServer(t, entraConfig)
	cu := entraConsentURL(base, tidCust, "newapp")
	_, _, page := do(t, http.MethodGet, cu, "", nil)
	if !strings.Contains(page, `value="custadmin"`) || !strings.Contains(page, `value="cancel"`) {
		t.Fatalf("consent page:\n%s", page)
	}
	// a non-admin can't grant consent
	q := consentSubmit(t, cu, url.Values{"action": {"accept"}, "tid": {tidCust}, "username": {"sam"}})
	if q.Get("error") != "access_denied" || !strings.Contains(q.Get("error_description"), "AADSTS90094") || q.Get("state") != "cs1" {
		t.Fatalf("non-admin consent = %v", q)
	}
	// an admin can
	q = consentSubmit(t, cu, url.Values{"action": {"accept"}, "tid": {tidCust}, "username": {"custadmin"}})
	if q.Get("admin_consent") != "True" || q.Get("tenant") != tidCust || q.Get("state") != "cs1" || q.Get("scope") == "" {
		t.Fatalf("admin consent = %v", q)
	}
	_, _, list := do(t, http.MethodGet, base+"/entra/_entra/consents", "", nil)
	if !strings.Contains(list, `"newapp"`) {
		t.Fatalf("consents = %s", list)
	}
	if code := entraSignIn(t, entraAuthorizeURL(base, tidCust, "newapp", ""), tidCust, "sam").Query().Get("code"); code == "" {
		t.Fatal("sign-in after consent must succeed")
	}
	// reset restores the seed: newapp needs consent again
	if s, _, _ := do(t, http.MethodPost, base+"/entra/_entra/reset", "", nil); s != http.StatusOK {
		t.Fatalf("reset status %d", s)
	}
	if e := entraSignIn(t, entraAuthorizeURL(base, tidCust, "newapp", ""), tidCust, "sam").Query().Get("error"); e != "consent_required" {
		t.Fatalf("after reset error = %q", e)
	}
}

func TestEntraAdminConsentViaOrganizationsAndCancel(t *testing.T) {
	_, base := startServer(t, entraConfig)
	cu := entraConsentURL(base, "organizations", "newapp")
	if q := consentSubmit(t, cu, url.Values{"action": {"accept"}, "tid": {tidCust}, "username": {"custadmin"}}); q.Get("tenant") != tidCust {
		t.Fatalf("organizations consent = %v", q)
	}
	if q := consentSubmit(t, cu, url.Values{"action": {"cancel"}}); q.Get("error") != "access_denied" || !strings.Contains(q.Get("error_description"), "AADSTS65004") {
		t.Fatalf("cancel = %v", q)
	}
}

func TestEntraAdminConsentRequiresParams(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, _, body := do(t, http.MethodGet, base+"/entra/"+tidCust+"/v2.0/adminconsent?client_id=newapp", "", nil)
	if status != http.StatusBadRequest || !strings.Contains(body, "redirect_uri") {
		t.Fatalf("status %d body %s", status, body)
	}
}

func TestEntraKeyRotation(t *testing.T) {
	_, base := startServer(t, entraConfig)
	signInToken := func() string {
		loc := entraSignIn(t, entraAuthorizeURL(base, tidCorp, "iam", ""), tidCorp, "jane")
		_, tok, _ := entraRedeem(t, base, tidCorp, "iam", loc.Query().Get("code"), "", nil)
		return tok["id_token"].(string)
	}
	before := signInToken()
	_, _, body := do(t, http.MethodPost, base+"/entra/_entra/rotate-keys", "", nil)
	if !strings.Contains(body, `"entra-2"`) {
		t.Fatalf("rotate = %s", body)
	}
	after := signInToken()
	verifyEntraJWT(t, base, before) // previous key is still published
	verifyEntraJWT(t, base, after)
	do(t, http.MethodPost, base+"/entra/_entra/rotate-keys", "", nil)
	_, _, jwks := do(t, http.MethodGet, base+"/entra/common/discovery/v2.0/keys", "", nil)
	if strings.Contains(jwks, `"entra-1"`) || !strings.Contains(jwks, `"entra-3"`) {
		t.Fatalf("after two rotations JWKS = %s", jwks)
	}
}

func TestEntraGroupsHelper(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, doc := entraGetJSON(t, base+"/entra/_entra/groups?tid="+tidCust, nil)
	for _, g := range []string{"G1", "G2", "G3", "G4"} {
		if doc[g] != entra.GroupObjectID(tidCust, g) {
			t.Errorf("%s = %v", g, doc[g])
		}
	}
}
```

- [x] **Step 3: Run to verify failure**

Run: `go test ./internal/entra/ ./internal/e2e/ -run 'Entra|Concurrent' -v`
Expected: consent and test-API tests fail with 400/404 (`_entra` isn't a configured tenant yet).

- [x] **Step 4: Implement `internal/entra/adminconsent.go`**

```go
package entra

import (
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

func (h *Handler) adminConsentGet(req *oauth2.Request, sc scope) routing.Response {
	if oerr := requireConsentParams(req); oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	return renderPicker(pickerPage{
		Heading:    "Permissions requested by " + req.QueryParam("client_id") + ": sign in as a tenant administrator to accept",
		Action:     req.URL.RequestURI(),
		Submit:     "accept",
		ShowCancel: true,
		Tenants:    h.pickerTenants(sc),
	})
}

func (h *Handler) adminConsentPost(req *oauth2.Request, sc scope) routing.Response {
	if oerr := requireConsentParams(req); oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	redirectURI, state := req.QueryParam("redirect_uri"), req.QueryParam("state")
	if req.FormParam("action") == "cancel" {
		return errorRedirect(redirectURI, state, "access_denied", "AADSTS65004: User declined to consent to access the app.")
	}
	t, u, oerr := h.postedUser(req, sc)
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	if !u.Admin {
		return errorRedirect(redirectURI, state, "access_denied",
			"AADSTS90094: Admin consent is required for the permissions requested by this application. An administrator of the tenant must grant consent.")
	}
	h.consents.Grant(req.QueryParam("client_id"), t.TID)
	return redirectWith(redirectURI, map[string]string{
		"admin_consent": "True",
		"tenant":        t.TID,
		"state":         state,
		"scope":         req.QueryParam("scope"),
	})
}

func requireConsentParams(req *oauth2.Request) *oauth2.Error {
	for _, p := range []string{"client_id", "redirect_uri"} {
		if req.QueryParam(p) == "" {
			return oauth2.MissingParameter(p)
		}
	}
	return nil
}
```

- [x] **Step 5: Implement `internal/entra/testapi.go`**

```go
package entra

import (
	"net/http"
	"sort"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// testAPI serves /{basePath}/_entra/{action}: helpers for automated tests.
func (h *Handler) testAPI(req *oauth2.Request, action string) routing.Response {
	get, post := req.Method == http.MethodGet, req.Method == http.MethodPost
	switch {
	case get && action == "consents":
		arr := jsonx.Arr{}
		for _, c := range h.consents.List() {
			arr = append(arr, jsonx.Obj{{Name: "clientId", V: c.ClientID}, {Name: "tid", V: c.TID}})
		}
		return routing.JSON(arr)
	case post && action == "reset":
		h.consents.Reset()
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
	case post && action == "rotate-keys":
		return routing.JSON(jsonx.Obj{{Name: "kid", V: h.keys.Rotate()}})
	case get && action == "groups":
		t := h.cfg.Tenant(req.QueryParam("tid"))
		if t == nil {
			return routing.ErrorResponse(oauth2.InvalidRequest("AADSTS90002: Tenant '" + req.QueryParam("tid") + "' not found."))
		}
		seen := map[string]bool{}
		var names []string
		for _, u := range h.cfg.UsersIn(t.TID) {
			for _, g := range u.Groups {
				if !seen[g] {
					seen[g] = true
					names = append(names, g)
				}
			}
		}
		sort.Strings(names)
		obj := jsonx.Obj{}
		for _, n := range names {
			obj = append(obj, jsonx.Field{Name: n, V: GroupObjectID(t.TID, n)})
		}
		return routing.JSON(obj)
	}
	return routing.NotFound("not found")
}
```

- [x] **Step 6: Extend the handler.** In `internal/entra/handler.go`:

1. In `Handle`, insert right after the `len(segs) < 3` check:

```go
	if segs[1] == "_entra" {
		return h.testAPI(req, strings.Join(segs[2:], "/"))
	}
```

2. In `route`, add these two cases before the `logout` case:

```go
	case get && rest == "v2.0/adminconsent":
		return h.adminConsentGet(req, sc)
	case post && rest == "v2.0/adminconsent":
		return h.adminConsentPost(req, sc)
```

- [x] **Step 7: Run to verify pass, including the race detector**

Run: `gofmt -l . | grep -v '^docs/'; go vet ./... && go test ./... && go test -race ./internal/entra/ ./internal/e2e/`
Expected: all PASS; no `DATA RACE` reports.

- [x] **Step 8: Commit**

```bash
git add internal/entra/adminconsent.go internal/entra/testapi.go internal/entra/handler.go internal/entra/handler_test.go internal/e2e/entra_test.go
git commit -m "feat(entra): admin consent flow and test-helper API" -m "Co-authored by AI"
```

---

### Task 8: Demo config, compose wiring, README

**Files:**
- Create: `entra-demo.json`
- Modify: `docker-compose.yml`, `README.md`, `docs/entra/00-design.md` (status line)

**Interfaces:**
- Consumes: everything above. Produces the documented local setup used by the IAM project.

- [x] **Step 1: Write a failing test that the demo file parses.** Append to `internal/config/config_test.go`:

```go
func TestEntraDemoFileParses(t *testing.T) {
	data, err := os.ReadFile("../../entra-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entra.ParseConfig(data); err != nil {
		t.Fatalf("entra-demo.json: %v", err)
	}
}
```

(add the import `"github.com/andychoi/mock-oidc/internal/entra"` to the test file.)

Run: `go test ./internal/config/ -run EntraDemo -v`
Expected: FAIL (file not found).

- [x] **Step 2: Create `entra-demo.json`** (corp, a customer with object-ID groups and required consent, a partner; users for every behavior):

```json
{
  "basePath": "entra",
  "defaultGroupLimit": 200,
  "tokenExpiry": 3600,
  "tenants": [
    { "tid": "11111111-1111-1111-1111-111111111111", "name": "Corp (demo)",
      "domains": ["corp.demo.local"], "groupClaimFormat": "name" },
    { "tid": "22222222-2222-2222-2222-222222222222", "name": "Customer X (demo)",
      "domains": ["customer-x.demo.local"], "groupClaimFormat": "object_id",
      "consentRequired": true, "groupLimit": 5 },
    { "tid": "33333333-3333-3333-3333-333333333333", "name": "Partner P (demo)",
      "domains": ["partner-p.demo.local"], "groupClaimFormat": "name", "consentRequired": true }
  ],
  "consents": [
    { "clientId": "iam", "tid": "11111111-1111-1111-1111-111111111111" }
  ],
  "users": [
    { "username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Kim",
      "email": "jane@corp.demo.local", "emailVerified": true, "amr": ["pwd", "mfa"], "admin": true,
      "groups": ["AMS Engineers", "PMO"] },
    { "username": "leo", "tid": "11111111-1111-1111-1111-111111111111", "name": "Leo Park",
      "email": "leo@corp.demo.local", "groups": ["PMO"] },
    { "username": "sam", "tid": "22222222-2222-2222-2222-222222222222", "name": "Sam Lee",
      "email": "sam@customer-x.demo.local", "groups": ["AMS Service Managers"] },
    { "username": "custadmin", "tid": "22222222-2222-2222-2222-222222222222", "name": "Customer Admin",
      "email": "admin@customer-x.demo.local", "admin": true },
    { "username": "many", "tid": "22222222-2222-2222-2222-222222222222", "name": "Many Groups",
      "groups": ["G1", "G2", "G3", "G4", "G5", "G6"] },
    { "username": "mfa", "tid": "22222222-2222-2222-2222-222222222222", "name": "MFA Required",
      "error": "interaction_required" },
    { "username": "pat", "tid": "33333333-3333-3333-3333-333333333333", "name": "Pat Doe",
      "email": "pat@partner-p.demo.local", "groups": ["Partner Staff"] },
    { "username": "partneradmin", "tid": "33333333-3333-3333-3333-333333333333", "name": "Partner Admin",
      "admin": true },
    { "username": "disabled", "tid": "33333333-3333-3333-3333-333333333333", "name": "Disabled User",
      "error": "invalid_grant" }
  ]
}
```

Run: `go test ./internal/config/ -run EntraDemo -v`
Expected: PASS.

- [x] **Step 3: Wire compose.** In `docker-compose.yml`, add under `volumes:` of `mock-oidc`:

```yaml
      - ./entra-demo.json:/config/entra.json:ro
```

and under `environment:`:

```yaml
      - ENTRA_CONFIG_PATH=/config/entra.json
```

and append to the header comment block:

```yaml
# Entra mode (Microsoft Entra ID emulation, see docs/entra/00-design.md):
#   per tenant:        http://mock-oidc.dev.test:8088/entra/{tid}/v2.0
#   multi-tenant:      http://mock-oidc.dev.test:8088/entra/organizations/v2.0
```

- [x] **Step 4: Document it in `README.md`.** Add a section after "Consumer configuration":

````markdown
## Entra mode (Microsoft Entra ID emulation)

Opt-in emulation of Entra ID v2.0 for testing multi-tenant Entra relying parties
(design: [docs/entra/00-design.md](docs/entra/00-design.md)). Enabled by
`ENTRA_CONFIG_PATH` (compose mounts `entra-demo.json`) or an `"entra"` block in
the JSON config. With neither, the server behaves exactly as before.

| Value | Per tenant | "Sign in with Microsoft" (multi-tenant) |
|---|---|---|
| Authority (issuer base) | `http://mock-oidc.dev.test:8088/entra/{tid}/v2.0` | `http://mock-oidc.dev.test:8088/entra/organizations/v2.0` |
| Discovery | `…/entra/{tid}/v2.0/.well-known/openid-configuration` | `issuer` is the template `…/entra/{tenantid}/v2.0` |
| Token `iss` | `…/entra/{tid}/v2.0` | `…/entra/{user's tid}/v2.0` |
| Client ID / secret | any | any |

Demo tenants (`entra-demo.json`): Corp `11111111-…` (group names), Customer X
`22222222-…` (group object IDs, consent required, overage above 5 groups),
Partner P `33333333-…` (consent required). The account picker needs no password.
Users cover MFA-required (`mfa`), disabled (`disabled`), overage (`many`), and
tenant admins for admin consent (`jane`, `custadmin`, `partneradmin`).

Admin consent: `…/entra/{tid|organizations}/v2.0/adminconsent?client_id=…&redirect_uri=…&state=…`.

Test helpers: `GET /entra/_entra/consents`, `POST /entra/_entra/reset`,
`POST /entra/_entra/rotate-keys`, `GET /entra/_entra/groups?tid=…` (group name → object ID).

Not emulated: real Conditional Access, Microsoft's UI and exact error wording,
refresh-token redemption, implicit/hybrid flows, Microsoft Graph.
````

Also add `entra-demo.json` to the table in the README's "Files" section with the description "Entra mode demo tenants and users".

- [x] **Step 5: Update the design status.** In `docs/entra/00-design.md`, change the Status row to `Implemented (<today's date>). Plan: [01-plan.md](01-plan.md)`.

- [x] **Step 6: Full verification**

Run:
```bash
gofmt -l . | grep -v '^docs/'
go vet ./...
go build ./...
go test ./...
go test -race ./...
docker compose up -d --build
curl -s http://localhost:8088/entra/organizations/v2.0/.well-known/openid-configuration | grep '"issuer"'
curl -s http://localhost:8088/oidc/.well-known/openid-configuration | grep '"issuer"'
```
Expected: no gofmt output; vet/build clean; all tests PASS with no races; the first curl prints `"issuer" : "http://localhost:8088/entra/{tenantid}/v2.0"` and the second `"issuer" : "http://localhost:8088/oidc"` (built-in unchanged).

- [x] **Step 7: Commit**

```bash
git add entra-demo.json docker-compose.yml README.md docs/entra/00-design.md internal/config/config_test.go
git commit -m "docs(entra): demo tenants, compose wiring and README for Entra mode" -m "Co-authored by AI"
```

---

## Spec coverage (self-review)

| Design section | Task |
|---|---|
| §2 single front route, own key set, token exports | 1, 3, 5 |
| §3 endpoints: discovery, keys, logout, OPTIONS | 5 |
| §3 authorize (picker, checks 1–6), token (all checks) | 6 |
| §3.4 admin consent, test API | 7 |
| §4.1 ID token claims, §4.2 groups/overage, §4.3 access token | 4 (unit), 6 (e2e) |
| §5 configuration, validation, `ENTRA_CONFIG_PATH`, unknown-field rejection | 2, 5, 8 |
| Opt-in / no behavior change | 1 (golden tests), 5 (`TestEntraRoutesAbsentWhenDisabled`, full suite) |
| README, compose, demo data | 8 |
