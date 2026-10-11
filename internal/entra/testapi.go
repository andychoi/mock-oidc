package entra

import (
	"net/http"
	"sort"
	"strings"

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
	// The directory as Graph sees it, without needing a token.
	case get && action == "users":
		cfg := h.conf()
		tid := req.QueryParam("tid")
		if tid != "" && cfg.Tenant(tid) == nil {
			return routing.ErrorResponse(oauth2.InvalidRequest("AADSTS90002: Tenant '" + tid + "' not found."))
		}
		arr := jsonx.Arr{}
		for _, u := range sortUsers(cfg.UsersIn(tid)) {
			t := cfg.Tenant(u.TID)
			groups := jsonx.Arr{}
			for _, g := range cfg.GroupsOf(u) {
				groups = append(groups, jsonx.Obj{{Name: "name", V: g.Name}, {Name: "oid", V: g.OID}})
			}
			arr = append(arr, jsonx.Obj{
				{Name: "username", V: u.Username},
				{Name: "tid", V: u.TID},
				{Name: "oid", V: u.OID},
				{Name: "displayName", V: u.Name},
				{Name: "userPrincipalName", V: u.PrincipalName(t)},
				{Name: "accountEnabled", V: u.Enabled()},
				{Name: "groups", V: groups},
			})
		}
		return routing.JSON(arr)
	// Mint an access token without driving the picker, so a relying-party
	// test suite can exercise Graph directly. Test-only, like the rest of
	// /_entra/.
	case post && action == "mint-token":
		return h.mintToken(req)
	case get && action == "groups":
		cfg := h.conf()
		t := cfg.Tenant(req.QueryParam("tid"))
		if t == nil {
			return routing.ErrorResponse(oauth2.InvalidRequest("AADSTS90002: Tenant '" + req.QueryParam("tid") + "' not found."))
		}
		seen := map[string]bool{}
		var names []string
		for _, u := range cfg.UsersIn(t.TID) {
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

// mintToken issues an access token for a configured account. The form or
// query carries tid, username, optional clientId (default "mock") and
// optional scope (default "openid profile email").
func (h *Handler) mintToken(req *oauth2.Request) routing.Response {
	param := func(name string) string {
		if v := req.FormParam(name); v != "" {
			return v
		}
		return req.QueryParam(name)
	}
	cfg := h.conf()
	tid, username := param("tid"), param("username")
	u := cfg.User(tid, username)
	if u == nil {
		return routing.ErrorResponse(oauth2.InvalidRequest(
			"AADSTS50034: The user account does not exist in this directory."))
	}
	if !u.Enabled() {
		return routing.ErrorResponse(oauth2.InvalidGrant("AADSTS50057: The user account is disabled."))
	}
	clientID := param("clientId")
	if clientID == "" {
		clientID = "mock"
	}
	scopes := strings.Fields(param("scope"))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	in := TokenInput{Origin: origin(req), BasePath: cfg.BasePath, GraphBase: cfg.GraphBase(),
		OverageSelfHosted: cfg.OverageSelfHosted(), Tenant: cfg.Tenant(u.TID), User: u,
		ClientID: clientID, Scopes: scopes, Now: h.now(), Expiry: cfg.TokenExpiry}
	return routing.JSON(jsonx.Obj{
		{Name: "token_type", V: "Bearer"},
		{Name: "expires_in", V: cfg.TokenExpiry},
		{Name: "scope", V: strings.Join(scopes, " ")},
		{Name: "access_token", V: h.keys.Sign(AccessTokenClaims(in))},
		{Name: "id_token", V: h.keys.Sign(IDTokenClaims(in))},
	})
}
