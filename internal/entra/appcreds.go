package entra

import (
	"net/http"
	"strings"
	"time"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// AppOnlyClaims builds an app-only (client credentials) access token: no user,
// so no oid and no scp. Entra puts the application in sub, azp and appid, and
// the granted application permissions in roles.
func AppOnlyClaims(origin, basePath, tid, clientID string, roles []string, now time.Time, expiry int64) map[string]any {
	ts := now.Unix()
	c := map[string]any{
		"iss":   Issuer(origin, basePath, tid),
		"aud":   graphAppID,
		"sub":   clientID,
		"azp":   clientID,
		"appid": clientID,
		"tid":   tid,
		"iat":   ts,
		"nbf":   ts,
		"exp":   now.Add(time.Duration(expiry) * time.Second).Unix(),
		"ver":   "2.0",
	}
	if len(roles) > 0 {
		c["roles"] = roles
	}
	return c
}

// App returns the registration for a client in a tenant, or nil. An entry
// without a tid applies to every tenant.
func (c *Config) App(clientID, tid string) *App {
	tid = strings.ToLower(tid)
	for i := range c.Apps {
		if c.Apps[i].ClientID == clientID && (c.Apps[i].TID == "" || c.Apps[i].TID == tid) {
			return &c.Apps[i]
		}
	}
	return nil
}

// clientCredentials mints an app-only token. Any client id and secret are
// accepted, as everywhere else in mock-oidc; the registration only supplies
// the app roles.
func (h *Handler) clientCredentials(req *oauth2.Request, sc scope, cfg *Config) routing.Response {
	// An app-only token names one tenant, and organizations/common name none,
	// so Entra has nothing to put in tid there either.
	if sc.Multi() {
		return routing.ErrorResponse(oauth2.InvalidRequest(
			"client credentials require a tenant-specific endpoint; '" + sc.Segment + "' does not identify a tenant."))
	}
	clientID := strings.TrimSpace(req.FormParam("client_id"))
	if clientID == "" {
		if id, _, ok := req.BasicAuth(); ok {
			clientID = id
		}
	}
	if clientID == "" {
		return routing.ErrorResponse(&oauth2.Error{Code: "invalid_client",
			Description: "AADSTS900023: client_id is required.", Status: http.StatusBadRequest})
	}
	// Entra requires a .default resource scope here; a named delegated scope
	// is a client error worth surfacing rather than silently accepting.
	requested := strings.Fields(req.FormParam("scope"))
	for _, s := range requested {
		if !strings.HasSuffix(s, "/.default") && s != ".default" {
			return routing.ErrorResponse(oauth2.InvalidRequest(
				"AADSTS1002012: The provided value for the input parameter 'scope' is not valid. " +
					"Client credentials require a resource scope ending in '/.default'."))
		}
	}
	var roles []string
	if app := cfg.App(clientID, sc.Tenant.TID); app != nil {
		roles = app.Roles
	}
	claims := AppOnlyClaims(origin(req), cfg.BasePath, sc.Tenant.TID, clientID, roles, h.now(), cfg.TokenExpiry)
	return routing.JSON(jsonx.Obj{
		{Name: "token_type", V: "Bearer"},
		{Name: "expires_in", V: cfg.TokenExpiry},
		{Name: "ext_expires_in", V: cfg.TokenExpiry},
		{Name: "access_token", V: h.keys.Sign(claims)},
	})
}
