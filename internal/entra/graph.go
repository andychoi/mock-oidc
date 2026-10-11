package entra

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// OData context suffixes. memberOf answers a directoryObjects collection, as
// real Graph does, because a membership can be a group or a directory role.
const (
	ctxUsers      = "users"
	ctxUserEntity = "users/$entity"
	ctxGroups     = "groups"
	ctxGroupEnt   = "groups/$entity"
	ctxDirObjects = "directoryObjects"
)

// graphUser renders the microsoft.graph.user subset this emulator serves.
// Graph emits a key with a null rather than omitting it, and SDK
// deserializers rely on that, so gaps are explicit nulls and businessPhones
// is an empty array.
func graphUser(c *Config, u *User) jsonx.Obj {
	t := c.Tenant(u.TID)
	phones := make(jsonx.Arr, 0, len(u.BusinessPhones))
	for _, p := range u.BusinessPhones {
		phones = append(phones, p)
	}
	return jsonx.Obj{
		{Name: "id", V: u.OID},
		{Name: "displayName", V: u.Name},
		{Name: "userPrincipalName", V: u.PrincipalName(t)},
		{Name: "mail", V: nullable(u.Email)},
		{Name: "givenName", V: nullable(u.GivenName)},
		{Name: "surname", V: nullable(u.Surname)},
		{Name: "jobTitle", V: nullable(u.JobTitle)},
		{Name: "officeLocation", V: nullable(u.OfficeLocation)},
		{Name: "mobilePhone", V: nullable(u.MobilePhone)},
		{Name: "businessPhones", V: phones},
		{Name: "preferredLanguage", V: nullable(u.PreferredLanguage)},
		{Name: "accountEnabled", V: u.Enabled()},
	}
}

// graphGroup renders the microsoft.graph.group subset.
func graphGroup(g DirGroup) jsonx.Obj {
	return jsonx.Obj{
		{Name: "id", V: g.OID},
		{Name: "displayName", V: g.Name},
		{Name: "description", V: nullable(g.Description)},
		{Name: "mail", V: nullable(g.Mail)},
		{Name: "mailNickname", V: nullable(g.MailNickname)},
		{Name: "mailEnabled", V: g.MailEnabled},
		{Name: "securityEnabled", V: g.SecurityEnabled},
	}
}

// nullable renders an unset string as JSON null, the way Graph does.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func graphUsers(c *Config, us []*User) []jsonx.Obj {
	out := make([]jsonx.Obj, 0, len(us))
	for _, u := range us {
		out = append(out, graphUser(c, u))
	}
	return out
}

func graphGroups(gs []DirGroup) []jsonx.Obj {
	out := make([]jsonx.Obj, 0, len(gs))
	for _, g := range gs {
		out = append(out, graphGroup(g))
	}
	return out
}

// graph dispatches everything under /{basePath}/{graphBase}/. The tenant is
// never in the path: it comes from the caller's token, exactly as real Graph
// scopes a response by the token's tenant.
func (h *Handler) graph(req *oauth2.Request, cfg *Config, segs []string) routing.Response {
	if strings.Join(segs, "/") == userInfoPath {
		if !cfg.UserInfoOn() {
			return h.graphErrorResponse(req, notFound("The requested resource does not exist."))
		}
		return h.userInfo(req, cfg)
	}
	if len(segs) < 2 || segs[0] != "v1.0" {
		return h.graphErrorResponse(req, notFound("The requested resource does not exist."))
	}
	caller, gerr := h.ValidateAccessToken(req, cfg, BearerToken(req))
	if gerr != nil {
		return h.graphErrorResponse(req, gerr)
	}
	path := segs[1:]
	switch path[0] {
	case "me":
		if !caller.Delegated() {
			return h.graphErrorResponse(req, forbidden("/me requires a delegated user token."))
		}
		return h.graphUserRoute(req, cfg, caller, caller.User, path[1:])
	case "users":
		return h.graphUsersRoute(req, cfg, caller, path[1:])
	case "groups":
		return h.graphGroupsRoute(req, cfg, caller, path[1:])
	}
	return h.graphErrorResponse(req, notFound("The requested resource does not exist."))
}

// graphUsersRoute serves /users and /users/{id|upn}/...
func (h *Handler) graphUsersRoute(req *oauth2.Request, cfg *Config, caller *Caller, path []string) routing.Response {
	if len(path) == 0 {
		if req.Method != http.MethodGet {
			return h.graphErrorResponse(req, notFound("The requested resource does not exist."))
		}
		return h.graphCollection(req, cfg, ctxUsers, graphUsers(cfg, cfg.UsersOrderedIn(caller.TID)), typeUser)
	}
	u := cfg.UserByUPNOrOID(caller.TID, path[0])
	if u == nil {
		return h.graphErrorResponse(req, notFound("Resource '"+path[0]+"' does not exist or one of its queried reference-property objects are not present."))
	}
	return h.graphUserRoute(req, cfg, caller, u, path[1:])
}

// graphUserRoute serves one user and its account sub-resources, shared by
// /me/... and /users/{id}/...
func (h *Handler) graphUserRoute(req *oauth2.Request, cfg *Config, caller *Caller, u *User, path []string) routing.Response {
	get, post := req.Method == http.MethodGet, req.Method == http.MethodPost
	sub := strings.Join(path, "/")
	switch {
	case get && sub == "":
		return h.graphEntity(req, cfg, ctxUserEntity, graphUser(cfg, u), typeUser)
	// Groups are flat here, so the transitive closure is the direct one.
	case get && (sub == "memberOf" || sub == "transitiveMemberOf"):
		return h.graphCollection(req, cfg, ctxDirObjects, graphGroups(cfg.GroupsOf(u)), typeGroup)
	case get && sub == "manager":
		m := cfg.ManagerOf(u)
		if m == nil {
			return h.graphErrorResponse(req, notFound("Resource 'manager' does not exist or one of its queried reference-property objects are not present."))
		}
		return h.graphEntity(req, cfg, ctxUserEntity, graphUser(cfg, m), typeUser)
	case get && sub == "directReports":
		return h.graphCollection(req, cfg, ctxDirObjects, graphUsers(cfg, cfg.DirectReports(u)), typeUser)
	// This is the endpoint a group-overage claim points at.
	case post && (sub == "getMemberObjects" || sub == "getMemberGroups"):
		return h.getMemberObjects(req, cfg, u)
	// Graph clients probe for a photo; answering 404 is the honest reply.
	case get && (sub == "photo" || sub == "photo/$value"):
		return h.graphErrorResponse(req, &graphError{Status: http.StatusNotFound,
			Code: CodeImageNotFound, Message: "The photo wasn't found."})
	}
	return h.graphErrorResponse(req, notFound("The requested resource does not exist."))
}

// getMemberObjects answers the overage endpoint: the ids of the user's groups.
// The securityEnabledOnly flag in the body is accepted and, with flat
// security groups, changes nothing; an absent or unparsable body is fine.
func (h *Handler) getMemberObjects(req *oauth2.Request, cfg *Config, u *User) routing.Response {
	if body := strings.TrimSpace(req.Body); body != "" {
		var payload struct {
			SecurityEnabledOnly *bool `json:"securityEnabledOnly"`
		}
		if json.Unmarshal([]byte(body), &payload) != nil {
			return h.graphErrorResponse(req, &graphError{Status: http.StatusBadRequest,
				Code: "Request_BadRequest", Message: "The request body is not valid JSON."})
		}
	}
	ids := make(jsonx.Arr, 0)
	for _, id := range cfg.GroupIDsOf(u) {
		ids = append(ids, id)
	}
	return graphJSON(http.StatusOK, jsonx.Obj{
		{Name: "@odata.context", V: cfg.graphContext(req, "Collection(Edm.String)")},
		{Name: "value", V: ids},
	})
}

// graphGroupsRoute serves /groups, /groups/{id} and /groups/{id}/members.
func (h *Handler) graphGroupsRoute(req *oauth2.Request, cfg *Config, caller *Caller, path []string) routing.Response {
	if req.Method != http.MethodGet {
		return h.graphErrorResponse(req, notFound("The requested resource does not exist."))
	}
	if len(path) == 0 {
		return h.graphCollection(req, cfg, ctxGroups, graphGroups(cfg.GroupsIn(caller.TID)), typeGroup)
	}
	g := cfg.GroupByID(caller.TID, path[0])
	if g == nil {
		return h.graphErrorResponse(req, notFound("Resource '"+path[0]+"' does not exist or one of its queried reference-property objects are not present."))
	}
	switch strings.Join(path[1:], "/") {
	case "":
		return h.graphEntity(req, cfg, ctxGroupEnt, graphGroup(*g), typeGroup)
	case "members", "transitiveMembers":
		return h.graphCollection(req, cfg, ctxDirObjects, graphUsers(cfg, cfg.MembersOf(caller.TID, g.OID)), typeUser)
	}
	return h.graphErrorResponse(req, notFound("The requested resource does not exist."))
}
