package grant

import (
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
)

// Handler produces the token endpoint response for one grant type.
type Handler func(req *oauth2.Request, tr *oauth2.TokenRequest, issuerURL, issuerID string, cb token.Callback) routing.Response

// expiresIn computes expires_in against the WALL CLOCK (not systemTime),
// mirroring NimbusExtensions.expiresIn.
func expiresIn(jwt string) int {
	claims, err := oauth2.ParseJWTClaims(jwt)
	if err != nil {
		return 0
	}
	exp, _ := claims["exp"].(float64)
	return int(exp - float64(time.Now().Unix()))
}

// --- client_credentials ---

// ClientCredentials issues an access token only; subject is the client id.
func ClientCredentials(tp *token.TokenProvider) Handler {
	return func(req *oauth2.Request, tr *oauth2.TokenRequest, issuerURL, issuerID string, cb token.Callback) routing.Response {
		access := tp.AccessToken(tr, issuerURL, issuerID, cb, "")
		return routing.TokenResponse("Bearer", "", "", access, "", expiresIn(access), tr.Scope)
	}
}

// --- password ---

// Password issues access + id tokens with the username as subject.
func Password(tp *token.TokenProvider) Handler {
	return func(req *oauth2.Request, tr *oauth2.TokenRequest, issuerURL, issuerID string, cb token.Callback) routing.Response {
		wrapped := &passwordCallback{delegate: cb, username: tr.Username}
		access := tp.AccessToken(tr, issuerURL, issuerID, wrapped, "")
		idToken := tp.IDToken(tr, issuerURL, issuerID, wrapped, "")
		return routing.TokenResponse("Bearer", "", idToken, access, "", expiresIn(access), tr.Scope)
	}
}

type passwordCallback struct {
	delegate token.Callback
	username string
}

func (p *passwordCallback) resolved() token.Callback {
	if m, ok := p.delegate.(*token.MappingCallback); ok && p.username != "" {
		return m.WithExtraMatchParams(map[string]string{subjectParam: p.username})
	}
	return p.delegate
}

func (p *passwordCallback) IssuerID() string { return p.delegate.IssuerID() }

func (p *passwordCallback) Subject(req *oauth2.TokenRequest) string {
	if p.username != "" {
		return p.username
	}
	return p.delegate.Subject(req)
}

func (p *passwordCallback) TypeHeader(req *oauth2.TokenRequest) string {
	return p.resolved().TypeHeader(req)
}

func (p *passwordCallback) Audience(req *oauth2.TokenRequest) []string {
	return p.resolved().Audience(req)
}

func (p *passwordCallback) AddClaims(req *oauth2.TokenRequest) map[string]any {
	return p.resolved().AddClaims(req)
}

func (p *passwordCallback) TokenExpiry() int64 { return p.delegate.TokenExpiry() }

const subjectParam = "subject"

// --- jwt-bearer (RFC 7523) ---

// JWTBearer re-signs the assertion's claims; scope comes from the request or
// the assertion's scope claim.
func JWTBearer(tp *token.TokenProvider) Handler {
	return func(req *oauth2.Request, tr *oauth2.TokenRequest, issuerURL, issuerID string, cb token.Callback) routing.Response {
		claims, err := oauth2.ParseJWTClaims(tr.Assertion)
		if err != nil {
			panic(oauth2.InvalidRequest("failed to parse request: " + err.Error()))
		}
		scope := tr.Scope
		if scope == "" {
			if s, ok := claims["scope"].(string); ok {
				scope = s
			}
		}
		if scope == "" {
			panic(oauth2.InvalidRequest("scope must be specified in request or as a claim in assertion parameter"))
		}
		access := tp.ExchangeAccessToken(tr, issuerURL, issuerID, claims, cb)
		return routing.TokenResponse("Bearer", "", "", access, "", expiresIn(access), scope)
	}
}

// --- token exchange (RFC 8693) ---

const issuedTokenTypeAccess = "urn:ietf:params:oauth:token-type:access_token"

// TokenExchange re-issues the subject_token's claims as a new access token.
// Client-assertion validation happens before parsing (see server dispatch).
func TokenExchange(tp *token.TokenProvider) Handler {
	return func(req *oauth2.Request, tr *oauth2.TokenRequest, issuerURL, issuerID string, cb token.Callback) routing.Response {
		claims, err := oauth2.ParseJWTClaims(tr.SubjectToken)
		if err != nil {
			panic(oauth2.InvalidRequest("failed to parse request: invalid subject_token JWT"))
		}
		access := tp.ExchangeAccessToken(tr, issuerURL, issuerID, claims, cb)
		return routing.TokenResponse("Bearer", issuedTokenTypeAccess, "", access, "", expiresIn(access), "")
	}
}

// --- refresh_token ---

// Refresh validates the refresh token against the store (enqueued library
// callbacks take priority), optionally rotates it, and issues new tokens.
// nonce is not propagated on refresh, mirroring upstream.
func Refresh(tp *token.TokenProvider, manager *RefreshTokenManager, rotate bool, enqueued func(issuerID string) token.Callback) Handler {
	return func(req *oauth2.Request, tr *oauth2.TokenRequest, issuerURL, issuerID string, _ token.Callback) routing.Response {
		refreshToken := tr.RefreshToken

		stored := manager.Get(refreshToken)
		if stored != nil && stored.IssuerID() != issuerID {
			panic(oauth2.InvalidGrant("refresh_token was issued by a different issuer"))
		}
		var resolved token.Callback
		if enqueued != nil {
			resolved = enqueued(issuerID)
		}
		if resolved == nil {
			resolved = stored
		}
		if resolved == nil {
			panic(oauth2.InvalidGrant("unknown refresh_token"))
		}

		if rotate {
			refreshToken = manager.Rotate(refreshToken, resolved)
		}

		idToken := tp.IDToken(tr, issuerURL, issuerID, resolved, "")
		access := tp.AccessToken(tr, issuerURL, issuerID, resolved, "")
		return routing.TokenResponse("Bearer", "", idToken, access, refreshToken, expiresIn(idToken), tr.Scope)
	}
}
