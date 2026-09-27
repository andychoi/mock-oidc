package entra

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// Handler serves every Entra mode endpoint under /{basePath}/.
type Handler struct {
	cfg      *Config
	keys     *KeySet
	consents *ConsentStore
	codes    *codeStore
	now      func() time.Time
}

// Option configures a Handler.
type Option func(*Handler)

// WithClock replaces the wall clock (tests).
func WithClock(now func() time.Time) Option { return func(h *Handler) { h.now = now } }

// New builds a handler for a parsed config.
func New(cfg *Config, opts ...Option) *Handler {
	h := &Handler{cfg: cfg, keys: NewKeySet(), consents: NewConsentStore(cfg.Consents), codes: newCodeStore(), now: time.Now}
	for _, o := range opts {
		o(h)
	}
	return h
}

// RoutePattern is the router path for AddFront: every path under /{basePath}/.
func (h *Handler) RoutePattern() string { return "/" + h.cfg.BasePath + "/*" }

// scope is the tenant segment of a request: one configured tenant, or the
// multi-tenant organizations/common endpoints (Tenant == nil).
type scope struct {
	Segment string // "organizations", "common", or the lowercase tid
	Tenant  *Tenant
}

// Multi reports whether the request came in on organizations/common.
func (s scope) Multi() bool { return s.Tenant == nil }

// Handle dispatches /{basePath}/{tenant}/... requests.
func (h *Handler) Handle(req *oauth2.Request) routing.Response {
	if req.Method == http.MethodOptions {
		return routing.Response{Status: http.StatusNoContent, Header: http.Header{}}
	}
	segs := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(segs) < 3 {
		return routing.NotFound("not found")
	}
	sc, oerr := h.resolveScope(segs[1])
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	return h.route(req, sc, strings.Join(segs[2:], "/"))
}

func (h *Handler) route(req *oauth2.Request, sc scope, rest string) routing.Response {
	get, post := req.Method == http.MethodGet, req.Method == http.MethodPost
	switch {
	case get && rest == "v2.0/.well-known/openid-configuration":
		return h.discovery(req, sc)
	case get && rest == "discovery/v2.0/keys":
		return routing.JSONString(h.keys.JWKS())
	case get && rest == "oauth2/v2.0/authorize":
		return h.authorizeGet(req, sc)
	case post && rest == "oauth2/v2.0/authorize":
		return h.authorizePost(req, sc)
	case post && rest == "oauth2/v2.0/token":
		return h.token(req, sc)
	case rest == "oauth2/v2.0/logout":
		return logout(req)
	}
	return routing.NotFound("not found")
}

func (h *Handler) resolveScope(seg string) (scope, *oauth2.Error) {
	seg = strings.ToLower(seg)
	if seg == ScopeOrganizations || seg == ScopeCommon {
		return scope{Segment: seg}, nil
	}
	if t := h.cfg.Tenant(seg); t != nil {
		return scope{Segment: t.TID, Tenant: t}, nil
	}
	return scope{}, oauth2.InvalidRequest("AADSTS90002: Tenant '" + seg + "' not found.")
}

// origin is the proxy-aware scheme://host[:port], the same derivation the
// built-in issuer uses.
func origin(req *oauth2.Request) string {
	u := req.ProxyAwareURL()
	return u.Scheme + "://" + u.Host
}

func (h *Handler) discovery(req *oauth2.Request, sc scope) routing.Response {
	base := origin(req) + "/" + h.cfg.BasePath
	issuerTID := "{tenantid}"
	if !sc.Multi() {
		issuerTID = sc.Tenant.TID
	}
	ep := base + "/" + sc.Segment
	return routing.JSON(jsonx.Obj{
		{Name: "token_endpoint", V: ep + "/oauth2/v2.0/token"},
		{Name: "token_endpoint_auth_methods_supported", V: []string{"client_secret_post", "private_key_jwt", "client_secret_basic"}},
		{Name: "jwks_uri", V: ep + "/discovery/v2.0/keys"},
		{Name: "response_modes_supported", V: []string{"query", "fragment", "form_post"}},
		{Name: "subject_types_supported", V: []string{"pairwise"}},
		{Name: "id_token_signing_alg_values_supported", V: []string{"RS256"}},
		{Name: "response_types_supported", V: []string{"code", "id_token", "code id_token", "id_token token"}},
		{Name: "scopes_supported", V: []string{"openid", "profile", "email", "offline_access"}},
		{Name: "issuer", V: base + "/" + issuerTID + "/v2.0"},
		{Name: "request_uri_parameter_supported", V: false},
		{Name: "authorization_endpoint", V: ep + "/oauth2/v2.0/authorize"},
		{Name: "end_session_endpoint", V: ep + "/oauth2/v2.0/logout"},
		{Name: "claims_supported", V: []string{"sub", "iss", "aud", "exp", "iat", "nbf", "name", "nonce", "oid",
			"preferred_username", "tid", "ver", "email", "groups", "amr", "xms_edov"}},
		{Name: "tenant_region_scope", V: "NA"},
		{Name: "cloud_instance_name", V: "microsoftonline.com"},
	})
}

func logout(req *oauth2.Request) routing.Response {
	uri := req.QueryParam("post_logout_redirect_uri")
	if uri == "" {
		return routing.HTML("<!DOCTYPE html><html><body><p>You signed out of your account.</p></body></html>")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return routing.ErrorResponse(oauth2.InvalidRequest("invalid post_logout_redirect_uri"))
	}
	if st := req.QueryParam("state"); st != "" {
		q := u.Query()
		q.Set("state", st)
		u.RawQuery = q.Encode()
	}
	return routing.Redirect(u.String())
}
