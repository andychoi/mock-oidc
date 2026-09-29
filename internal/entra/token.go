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
	cfg := h.conf()
	t := cfg.Tenant(c.tid)
	u := cfg.User(c.tid, c.username)
	if u.Error == ErrInvalidGrant {
		return invalidGrant("AADSTS50057: The user account is disabled.")
	}
	in := TokenInput{Origin: origin(req), BasePath: cfg.BasePath, Tenant: t, User: u, ClientID: c.req.ClientID,
		Nonce: c.req.Nonce, Scopes: c.req.Scope, Now: h.now(), Expiry: cfg.TokenExpiry}
	resp := jsonx.Obj{
		{Name: "token_type", V: "Bearer"},
		{Name: "scope", V: strings.Join(c.req.Scope, " ")},
		{Name: "expires_in", V: cfg.TokenExpiry},
		{Name: "ext_expires_in", V: cfg.TokenExpiry},
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
