package entra

import (
	"errors"
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
			for _, g := range u.MemberGroups() {
				if !seen[g] {
					seen[g] = true
					names = append(names, g)
				}
			}
		}
		sort.Strings(names)
		obj := jsonx.Obj{}
		for _, n := range names {
			obj = append(obj, jsonx.Field{Name: n, V: t.GroupOID(n)})
		}
		return routing.JSON(obj)
	}
	return routing.NotFound("not found")
}

// mintToken parses the form or query (tid, username, optional clientId and
// scope) and issues tokens through AdminMintToken.
func (h *Handler) mintToken(req *oauth2.Request) routing.Response {
	param := func(name string) string {
		if v := req.FormParam(name); v != "" {
			return v
		}
		return req.QueryParam(name)
	}
	tok, err := h.AdminMintToken(IssuerOrigin(req), MintInput{
		TID: param("tid"), Username: param("username"), ClientID: param("clientId"), Scope: param("scope"),
	})
	switch {
	case errors.Is(err, ErrNotFound):
		return routing.ErrorResponse(oauth2.InvalidRequest(
			"AADSTS50034: The user account does not exist in this directory."))
	case errors.Is(err, errAccountDisabled):
		return routing.ErrorResponse(oauth2.InvalidGrant("AADSTS50057: The user account is disabled."))
	}
	return routing.JSON(tok.Obj())
}
