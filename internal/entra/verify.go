package entra

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/token"
)

// Graph error codes (PascalCase, as real Graph emits them).
const (
	CodeInvalidAuthenticationToken = "InvalidAuthenticationToken"
	CodeAuthorizationRequestDenied = "Authorization_RequestDenied"
	CodeResourceNotFound           = "Request_ResourceNotFound"
	CodeUnsupportedQuery           = "Request_UnsupportedQuery"
	CodeImageNotFound              = "ImageNotFound"
)

// graphError is a Graph-surface failure. It is rendered by graphErrorResponse
// (odata.go) and never by routing.ErrorResponse, which lowercases bodies for
// navikt compatibility and would destroy these codes.
type graphError struct {
	Status  int
	Code    string
	Message string
}

// invalidToken is the single opaque answer to every authentication failure:
// which check failed is never disclosed.
func invalidToken() *graphError {
	return &graphError{Status: http.StatusUnauthorized, Code: CodeInvalidAuthenticationToken,
		Message: "Access token is empty or invalid."}
}

func notFound(message string) *graphError {
	return &graphError{Status: http.StatusNotFound, Code: CodeResourceNotFound, Message: message}
}

func forbidden(message string) *graphError {
	return &graphError{Status: http.StatusForbidden, Code: CodeAuthorizationRequestDenied, Message: message}
}

func unsupportedQuery(message string) *graphError {
	return &graphError{Status: http.StatusBadRequest, Code: CodeUnsupportedQuery, Message: message}
}

// TokenKind distinguishes a user (delegated) token from an app-only one.
type TokenKind int

// Token kinds.
const (
	TokenDelegated TokenKind = iota // carries oid: a signed-in user
	TokenAppOnly                    // client credentials: no user
)

// Caller is an authenticated Graph caller.
type Caller struct {
	Claims   map[string]any
	Tenant   *Tenant
	User     *User // nil for an app-only token
	TID      string
	OID      string // "" for an app-only token
	Sub      string
	ClientID string
	Kind     TokenKind
}

// Delegated reports whether a signed-in user is behind the token.
func (c *Caller) Delegated() bool { return c.Kind == TokenDelegated }

// byKid returns the published key with that kid, or nil.
func (k *KeySet) byKid(kid string) *token.SigningKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, key := range k.keys {
		if key.Kid == kid {
			return key
		}
	}
	return nil
}

// Verify checks an RS256 compact JWS against the published keys and returns
// its header and claims. A token signed by a key that has since been dropped
// from the set no longer verifies.
func (k *KeySet) Verify(jwt string) (header, claims map[string]any, ok bool) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, nil, false
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil {
		return nil, nil, false
	}
	if alg, _ := header["alg"].(string); alg != "RS256" {
		return nil, nil, false
	}
	kid, _ := header["kid"].(string)
	key := k.byKid(kid)
	if key == nil || key.RSA == nil {
		return nil, nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&key.RSA.PublicKey, crypto.SHA256, digest[:], sig) != nil {
		return nil, nil, false
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(pb, &claims) != nil {
		return nil, nil, false
	}
	return header, claims, true
}

// BearerToken extracts the credential from an Authorization: Bearer header.
func BearerToken(req *oauth2.Request) string {
	h := req.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// claimString reads a string claim.
func claimString(claims map[string]any, name string) string {
	s, _ := claims[name].(string)
	return s
}

// claimTime reads a numeric date claim. JSON numbers decode as float64.
func claimTime(claims map[string]any, name string) (int64, bool) {
	switch v := claims[name].(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	}
	return 0, false
}

// ValidateAccessToken authenticates a Graph request. It accepts only an access
// token this handler minted: signed by a published key, carrying the Graph
// audience and ver 2.0, issued for this very origin, inside its validity
// window (with the configured skew), and naming a tenant — and, for a
// delegated token, an enabled user — that still exists.
//
// Every failure returns the same opaque 401, so a caller cannot probe the
// directory through the error message.
func (h *Handler) ValidateAccessToken(req *oauth2.Request, cfg *Config, bearer string) (*Caller, *graphError) {
	if bearer == "" {
		return nil, invalidToken()
	}
	_, claims, ok := h.keys.Verify(bearer)
	if !ok {
		return nil, invalidToken()
	}
	if claimString(claims, "aud") != graphAppID || claimString(claims, "ver") != "2.0" {
		return nil, invalidToken()
	}
	tid := strings.ToLower(claimString(claims, "tid"))
	if tid == "" || claimString(claims, "iss") != Issuer(origin(req), cfg.BasePath, tid) {
		return nil, invalidToken()
	}
	now, skew := h.now().Unix(), cfg.ClockSkew()
	exp, hasExp := claimTime(claims, "exp")
	if !hasExp || now-skew >= exp {
		return nil, invalidToken()
	}
	if nbf, hasNbf := claimTime(claims, "nbf"); hasNbf && nbf > now+skew {
		return nil, invalidToken()
	}
	tenant := cfg.Tenant(tid)
	if tenant == nil {
		return nil, invalidToken()
	}
	c := &Caller{
		Claims:   claims,
		Tenant:   tenant,
		TID:      tenant.TID,
		OID:      strings.ToLower(claimString(claims, "oid")),
		Sub:      claimString(claims, "sub"),
		ClientID: claimString(claims, "appid"),
		Kind:     TokenAppOnly,
	}
	if c.ClientID == "" {
		c.ClientID = claimString(claims, "azp")
	}
	if c.OID == "" {
		return c, nil // app-only: no user to resolve
	}
	// A user deleted or disabled between mint and call loses the token with it.
	u := cfg.UserByOID(tid, c.OID)
	if u == nil || !u.Enabled() {
		return nil, invalidToken()
	}
	c.User = u
	c.Kind = TokenDelegated
	return c, nil
}
