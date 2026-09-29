// Package adminui serves the admin dashboard at /admin/: an embedded,
// dependency-free single-page app over a small read-mostly JSON API. The UI is
// public by design — the server itself is an unauthenticated dev/test mock,
// and everything the UI renders is already visible in the config files and
// the /_entra test API.
//
// Assets are served from an explicit map, not a file server: deterministic
// content types, no directory listings, and the "exactly these files"
// property is testable. The design language is the GitHub Primer port used by
// ai-gateway's admin UI.
package adminui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"

	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

//go:embed all:static
var staticFS embed.FS

type webFile struct {
	body        []byte
	contentType string
}

// assets maps the URL path under /admin/ to the embedded file.
var assets = map[string]webFile{}

// indexHTML is kept separately for the /admin and /admin/ shell paths.
var indexHTML []byte

func init() {
	types := map[string]string{
		".html":  "text/html; charset=utf-8",
		".css":   "text/css; charset=utf-8",
		".js":    "text/javascript; charset=utf-8",
		".woff2": "font/woff2",
		".txt":   "text/plain; charset=utf-8",
	}
	entries, err := fs.ReadDir(staticFS, "static")
	if err != nil {
		panic("adminui: cannot read embedded static dir: " + err.Error())
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		body, err := staticFS.ReadFile("static/" + name)
		if err != nil {
			panic("adminui: cannot read embedded asset " + name + ": " + err.Error())
		}
		ct := "application/octet-stream"
		for ext, t := range types {
			if len(name) >= len(ext) && name[len(name)-len(ext):] == ext {
				ct = t
				break
			}
		}
		assets["/"+name] = webFile{body: body, contentType: ct}
		if name == "index.html" {
			indexHTML = body
		}
	}
	if indexHTML == nil {
		panic("adminui: static/index.html missing")
	}
}

// csp bans inline scripts outright (XSS hardening); inline styles stay allowed.
const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'"

// EntraState exposes the Entra-mode state and actions shown in the admin UI.
// Implemented by *entra.Handler; an interface keeps this package free of an
// entra import (and entra free of adminui).
type EntraState interface {
	AdminSnapshot() any
	AdminResetConsents()
	AdminRotateKeys() string
}

// Handler serves the admin UI shell, its static assets and the JSON API.
type Handler struct {
	cfg   *config.OAuth2Config
	entra EntraState
}

// New builds the admin handler. entra may be nil (Entra mode off): the UI
// then hides the Entra sections and the entra API endpoints answer 404.
func New(cfg *config.OAuth2Config, entra EntraState) *Handler {
	return &Handler{cfg: cfg, entra: entra}
}

// Handle is the routing.Handler for the /admin front routes. Mounted via
// rt.AddFront("", "/admin", ...) and rt.AddFront("", "/admin/*", ...) so it
// takes precedence over the suffix routes regardless of issuer paths.
func (a *Handler) Handle(req *oauth2.Request) routing.Response {
	if req.Method == http.MethodOptions {
		return routing.Response{Status: http.StatusNoContent, Header: http.Header{}}
	}
	trimmed := strings.Trim(req.URL.Path, "/")
	rest := strings.TrimPrefix(trimmed, "admin")
	rest = strings.TrimPrefix(rest, "/")
	if strings.HasPrefix(rest, "api/") {
		if req.Method != http.MethodGet && req.Method != http.MethodPost {
			return routing.MethodNotAllowed()
		}
		return a.api(req, strings.TrimPrefix(rest, "api/"))
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return routing.MethodNotAllowed()
	}
	if rest == "" {
		return a.serve("index.html")
	}
	return a.serve(rest)
}

func (a *Handler) serve(name string) routing.Response {
	f, ok := assets["/"+name]
	if !ok {
		return routing.NotFound("not found")
	}
	resp := routing.Response{Status: 200, Header: http.Header{}}
	resp.Header.Set("Content-Type", f.contentType)
	resp.Header.Set("Cache-Control", "no-cache")
	resp.Header.Set("Content-Security-Policy", csp)
	resp.Header.Set("X-Frame-Options", "DENY")
	resp.BodyBytes = f.body
	return resp
}

func (a *Handler) api(req *oauth2.Request, action string) routing.Response {
	get, post := req.Method == http.MethodGet, req.Method == http.MethodPost
	switch {
	case get && action == "overview":
		return routing.JSON(a.overview())
	case a.entra == nil:
		return routing.NotFound("not found")
	case get && action == "entra":
		return routing.JSON(a.entra.AdminSnapshot())
	case post && action == "entra/reset":
		a.entra.AdminResetConsents()
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
	case post && action == "entra/rotate-keys":
		return routing.JSON(jsonx.Obj{{Name: "kid", V: a.entra.AdminRotateKeys()}})
	}
	return routing.NotFound("not found")
}

// overview renders the non-Entra server facts: behavior flags and the issuer
// scopes declared by token callbacks. Endpoint URLs are derived client-side
// from window.location, matching the proxy-aware issuer derivation.
func (a *Handler) overview() jsonx.Obj {
	callbacks := jsonx.Arr{}
	for _, cb := range a.cfg.TokenCallbacks {
		callbacks = append(callbacks, jsonx.Obj{
			{Name: "issuerId", V: cb.IssuerID()},
			{Name: "tokenExpiry", V: cb.Expiry},
		})
	}
	obj := jsonx.Obj{
		{Name: "interactiveLogin", V: a.cfg.InteractiveLogin},
		{Name: "rotateRefreshToken", V: a.cfg.RotateRefreshToken},
		{Name: "entra", V: a.entra != nil},
		{Name: "tokenCallbacks", V: callbacks},
	}
	if a.cfg.LoginPagePath != "" {
		obj = append(obj, jsonx.Field{Name: "loginPagePath", V: a.cfg.LoginPagePath})
	}
	if a.cfg.StaticAssetsPath != "" {
		obj = append(obj, jsonx.Field{Name: "staticAssetsPath", V: a.cfg.StaticAssetsPath})
	}
	return obj
}
