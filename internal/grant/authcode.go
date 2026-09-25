package grant

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"sync"

	"github.com/andychoi/mock-oidc/internal/login"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
)

// AuthorizationCode implements the /authorize code issuance and the
// authorization_code token grant (AuthorizationCodeHandler.kt). Codes are
// single-use; a PKCE failure also invalidates the login entry.
type AuthorizationCode struct {
	tp          *token.TokenProvider
	refresh     *RefreshTokenManager
	codeToAuth  sync.Map // code -> *oauth2.AuthRequest
	codeToLogin sync.Map // code -> login.Login
}

// NewAuthorizationCode returns the handler.
func NewAuthorizationCode(tp *token.TokenProvider, refresh *RefreshTokenManager) *AuthorizationCode {
	return &AuthorizationCode{tp: tp, refresh: refresh}
}

// AuthorizationCodeResponse mints and caches a single-use code for the auth
// request, or rejects non-code flows.
func (h *AuthorizationCode) AuthorizationCodeResponse(ar *oauth2.AuthRequest, lg *login.Login) (string, *oauth2.Error) {
	if !ar.ImpliesCodeFlow() {
		return "", oauth2.InvalidGrant("hybrid og implicit flow not supported (yet).")
	}
	code := token.RandomAuthorizationCode()
	h.codeToAuth.Store(code, ar)
	if lg != nil {
		h.codeToLogin.Store(code, *lg)
	}
	return code, nil
}

// TokenResponse exchanges the code for tokens.
func (h *AuthorizationCode) TokenResponse(req *oauth2.Request, tr *oauth2.TokenRequest, issuerURL, issuerID string, cb token.Callback) routing.Response {
	v, ok := h.codeToAuth.LoadAndDelete(tr.Code)
	if !ok {
		panic(oauth2.InvalidGrant("unknown or already-used authorization code"))
	}
	ar := v.(*oauth2.AuthRequest)

	if err := verifyPKCE(ar, tr); err != nil {
		h.codeToLogin.Delete(tr.Code)
		panic(err)
	}

	lg := h.takeLogin(tr.Code)
	effective := cb
	if lg != nil {
		effective = newLoginCallback(*lg, cb)
	}

	nonce := ar.Nonce
	idToken := h.tp.IDToken(tr, issuerURL, issuerID, effective, nonce)
	access := h.tp.AccessToken(tr, issuerURL, issuerID, effective, nonce)
	refreshToken := h.refresh.RefreshToken(effective, nonce)

	return routing.TokenResponse("Bearer", "", idToken, access, refreshToken, expiresIn(idToken), tr.Scope)
}

func (h *AuthorizationCode) takeLogin(code string) *login.Login {
	if v, ok := h.codeToLogin.LoadAndDelete(code); ok {
		lg := v.(login.Login)
		return &lg
	}
	return nil
}

// verifyPKCE mirrors NimbusExtensions.verifyPkce: only enforced when a
// code_verifier is present; the challenge is computed with the auth request's
// method (plain by default) and must equal its code_challenge.
func verifyPKCE(ar *oauth2.AuthRequest, tr *oauth2.TokenRequest) *oauth2.Error {
	if tr.CodeVerifier == "" {
		return nil
	}
	var computed string
	if ar.CodeChallengeMethod == "S256" {
		digest := sha256.Sum256([]byte(tr.CodeVerifier))
		computed = base64.RawURLEncoding.EncodeToString(digest[:])
	} else {
		computed = tr.CodeVerifier
	}
	if subtle.ConstantTimeCompare([]byte(computed), []byte(ar.CodeChallenge)) != 1 {
		msg := "invalid_pkce: code_verifier does not compute to code_challenge from request"
		return oauth2.InvalidGrant(msg)
	}
	return nil
}

// loginCallback wraps the resolved callback with interactive-login semantics
// (LoginOAuth2TokenCallback): the login username participates in mapping
// matching (as "subject"), provides the subject fallback, and its claims JSON
// is merged with putIfAbsent — mapping/callback claims win.
func newLoginCallback(lg login.Login, cb token.Callback) token.Callback {
	return &loginCallback{login: lg, delegate: cb}
}

type loginCallback struct {
	login    login.Login
	delegate token.Callback
}

func (l *loginCallback) resolved() token.Callback {
	if m, ok := l.delegate.(*token.MappingCallback); ok {
		return m.WithExtraMatchParams(map[string]string{subjectParam: l.login.Username})
	}
	return l.delegate
}

func (l *loginCallback) IssuerID() string { return l.delegate.IssuerID() }

func (l *loginCallback) Subject(req *oauth2.TokenRequest) string {
	if _, isMapping := l.delegate.(*token.MappingCallback); isMapping {
		if s := l.resolved().Subject(req); s != "" {
			return s
		}
	}
	return l.login.Username
}

func (l *loginCallback) TypeHeader(req *oauth2.TokenRequest) string {
	return l.resolved().TypeHeader(req)
}

func (l *loginCallback) Audience(req *oauth2.TokenRequest) []string {
	return l.resolved().Audience(req)
}

func (l *loginCallback) TokenExpiry() int64 { return l.delegate.TokenExpiry() }

func (l *loginCallback) AddClaims(req *oauth2.TokenRequest) map[string]any {
	claims := l.resolved().AddClaims(req)
	if l.login.Claims == "" {
		return claims
	}
	var loginClaims map[string]any
	if err := json.Unmarshal([]byte(l.login.Claims), &loginClaims); err != nil {
		return claims // warn-and-continue upstream behavior
	}
	for k, v := range loginClaims {
		if _, exists := claims[k]; !exists {
			claims[k] = v
		}
	}
	return claims
}
