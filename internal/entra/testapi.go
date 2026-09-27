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
