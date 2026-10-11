package entra

import (
	"net/http"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// userInfoPath is the OIDC UserInfo path under the Graph base, mirroring real
// Entra, whose userinfo_endpoint is graph.microsoft.com/oidc/userinfo.
const userInfoPath = "oidc/userinfo"

// userInfo serves the OIDC UserInfo endpoint. It returns OIDC claims, not the
// Graph user shape: real Entra has both and they differ, and an RP that learns
// the wrong contract here breaks against the real thing. The Graph-shaped user
// is at /v1.0/me.
func (h *Handler) userInfo(req *oauth2.Request, cfg *Config) routing.Response {
	if req.Method != http.MethodGet && req.Method != http.MethodPost {
		return routing.MethodNotAllowed()
	}
	caller, gerr := h.ValidateAccessToken(req, cfg, BearerToken(req))
	if gerr != nil {
		return bearerError(http.StatusUnauthorized, "invalid_token", "The access token is invalid or expired.")
	}
	// UserInfo is about a user, so an app-only token has nothing to describe.
	if !caller.Delegated() {
		return bearerError(http.StatusForbidden, "insufficient_scope", "UserInfo requires a delegated user token.")
	}
	u, t := caller.User, caller.Tenant
	claims := jsonx.Obj{
		{Name: "sub", V: caller.Sub},
		{Name: "oid", V: u.OID},
		{Name: "tid", V: t.TID},
		{Name: "name", V: u.Name},
		{Name: "preferred_username", V: u.PrincipalName(t)},
	}
	if u.GivenName != "" {
		claims = append(claims, jsonx.Field{Name: "given_name", V: u.GivenName})
	}
	if u.Surname != "" {
		claims = append(claims, jsonx.Field{Name: "family_name", V: u.Surname})
	}
	if u.Email != "" {
		claims = append(claims, jsonx.Field{Name: "email", V: u.Email})
	}
	resp := graphJSON(http.StatusOK, claims)
	resp.Header.Set("Cache-Control", "no-store")
	return resp
}

// bearerError renders an RFC 6750 Bearer failure: the challenge header plus a
// matching JSON body. UserInfo is an OIDC endpoint, so it uses the OAuth error
// shape rather than the Graph one.
func bearerError(status int, code, description string) routing.Response {
	resp := graphJSON(status, jsonx.Obj{
		{Name: "error", V: code},
		{Name: "error_description", V: description},
	})
	resp.Header.Set("WWW-Authenticate", `Bearer error="`+code+`", error_description="`+description+`"`)
	resp.Header.Set("Cache-Control", "no-store")
	return resp
}
