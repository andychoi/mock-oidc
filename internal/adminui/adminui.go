// Package adminui serves the admin dashboard at /admin/: an embedded,
// dependency-free single-page app over a small JSON API. The UI is public by
// design — the server itself is an unauthenticated dev/test mock, and the
// mutations it exposes (entra tenants/users, consents, keys, runtime
// settings, login directory) are exactly what the config files and the
// /_entra test API already control.
//
// Assets are served from an explicit map, not a file server: deterministic
// content types, no directory listings, and the "exactly these files"
// property is testable. The design language is the GitHub Primer port used by
// ai-gateway's admin UI.
package adminui

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"

	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/directory"
	"github.com/andychoi/mock-oidc/internal/entra"
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

// AdminSettings is the live runtime-toggle state rendered by the settings API.
type AdminSettings struct {
	InteractiveLogin   bool
	RotateRefreshToken bool
	EntraConfigured    bool
	EntraEnabled       bool
}

// Settings exposes the server's runtime toggles; implemented by *server.Server.
type Settings interface {
	AdminSettings() AdminSettings
	AdminSetSetting(name string, value bool) error
}

// Handler serves the admin UI shell, its static assets and the JSON API.
type Handler struct {
	cfg      *config.OAuth2Config
	entra    *entra.Handler
	dir      *directory.Directory
	settings Settings
}

// New builds the admin handler. entra is nil when Entra mode is off (the
// entra API endpoints answer 404); dir may be nil (empty directory); settings
// may be nil (settings API answers 404, used by tests).
func New(cfg *config.OAuth2Config, entra *entra.Handler, dir *directory.Directory, settings Settings) *Handler {
	return &Handler{cfg: cfg, entra: entra, dir: dir, settings: settings}
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
		if req.Method != http.MethodGet && req.Method != http.MethodPost && req.Method != http.MethodPut && req.Method != http.MethodDelete {
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

// apiError renders the admin API's error envelope (lowercase, like the rest
// of the server's JSON).
func apiError(status int, msg string) routing.Response {
	resp := routing.Response{Status: status, Header: http.Header{}}
	resp.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp.Body = strings.ToLower(jsonx.Render(jsonx.Obj{{Name: "error", V: msg}}))
	return resp
}

func badRequest(err error) routing.Response {
	return apiError(400, err.Error())
}

func notFound() routing.Response { return routing.NotFound("not found") }

// decode parses a JSON request body into out with unknown-field rejection.
func decode(req *oauth2.Request, out any) error {
	dec := json.NewDecoder(strings.NewReader(req.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid json body: %w", err)
	}
	return nil
}

func (a *Handler) api(req *oauth2.Request, action string) routing.Response {
	get, post := req.Method == http.MethodGet, req.Method == http.MethodPost
	put, del := req.Method == http.MethodPut, req.Method == http.MethodDelete
	segs := strings.Split(action, "/")

	switch {
	// --- settings ---
	case get && action == "settings":
		if a.settings == nil {
			return notFound()
		}
		st := a.settings.AdminSettings()
		return routing.JSON(jsonx.Obj{
			{Name: "interactiveLogin", V: st.InteractiveLogin},
			{Name: "rotateRefreshToken", V: st.RotateRefreshToken},
			{Name: "entraConfigured", V: st.EntraConfigured},
			{Name: "entraEnabled", V: st.EntraEnabled},
		})
	case post && action == "settings":
		if a.settings == nil {
			return notFound()
		}
		var body struct {
			Name  string `json:"name"`
			Value bool   `json:"value"`
		}
		if err := decode(req, &body); err != nil {
			return badRequest(err)
		}
		if err := a.settings.AdminSetSetting(body.Name, body.Value); err != nil {
			return badRequest(err)
		}
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})

	// --- entra: read + actions ---
	case get && action == "entra":
		if a.entra == nil {
			return notFound()
		}
		return routing.JSON(a.entra.AdminSnapshot())
	case post && action == "entra/reset":
		if a.entra == nil {
			return notFound()
		}
		a.entra.AdminResetToSeed()
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
	case post && action == "entra/rotate-keys":
		if a.entra == nil {
			return notFound()
		}
		return routing.JSON(jsonx.Obj{{Name: "kid", V: a.entra.AdminRotateKeys()}})
	case del && len(segs) == 4 && segs[0] == "entra" && segs[1] == "consents":
		if a.entra == nil {
			return notFound()
		}
		a.entra.AdminRevokeConsent(segs[2], segs[3])
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})

	// --- entra: tenants ---
	case post && action == "entra/tenants":
		return a.upsertTenant(req, "")
	case len(segs) == 3 && segs[0] == "entra" && segs[1] == "tenants":
		tid := segs[2]
		switch {
		case put:
			return a.upsertTenant(req, tid)
		case del:
			if a.entra == nil {
				return notFound()
			}
			if err := a.entra.AdminDeleteTenant(tid); err != nil {
				return deleteError(err)
			}
			return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
		}

	// --- entra: users ---
	case post && action == "entra/users":
		return a.upsertUser(req, "", "")
	case len(segs) == 4 && segs[0] == "entra" && segs[1] == "users":
		tid, username := segs[2], segs[3]
		switch {
		case put:
			return a.upsertUser(req, tid, username)
		case del:
			if a.entra == nil {
				return notFound()
			}
			if err := a.entra.AdminDeleteUser(tid, username); err != nil {
				return deleteError(err)
			}
			return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
		}

	// --- directory ---
	case get && action == "directory":
		if a.dir == nil {
			return notFound()
		}
		arr := jsonx.Arr{}
		for _, u := range a.dir.List() {
			arr = append(arr, jsonx.Obj{
				{Name: "username", V: u.Username},
				{Name: "name", V: u.Name},
				{Name: "email", V: u.Email},
				{Name: "groups", V: u.Groups},
			})
		}
		return routing.JSON(arr)
	case post && action == "directory/users":
		return a.upsertDirectoryUser(req)
	case len(segs) == 3 && segs[0] == "directory" && segs[1] == "users" && del:
		if a.dir == nil {
			return notFound()
		}
		if err := a.dir.Delete(segs[2]); err != nil {
			return deleteError(err)
		}
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
	case post && action == "directory/reset":
		if a.dir == nil {
			return notFound()
		}
		a.dir.Reset()
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})

	case get && action == "overview":
		return routing.JSON(a.overview())
	}
	return notFound()
}

// deleteError maps store errors: unknown entity → 404, the rest → 400.
func deleteError(err error) routing.Response {
	if errors.Is(err, entra.ErrNotFound) || strings.HasSuffix(err.Error(), ": not found") {
		return apiError(404, err.Error())
	}
	return badRequest(err)
}

func (a *Handler) upsertTenant(req *oauth2.Request, tid string) routing.Response {
	if a.entra == nil {
		return notFound()
	}
	var t entra.Tenant
	if err := decode(req, &t); err != nil {
		return badRequest(err)
	}
	var err error
	if tid == "" {
		err = a.entra.AdminCreateTenant(t)
	} else {
		err = a.entra.AdminUpdateTenant(tid, t)
	}
	if err != nil {
		return badRequest(err)
	}
	return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
}

func (a *Handler) upsertUser(req *oauth2.Request, tid, username string) routing.Response {
	if a.entra == nil {
		return notFound()
	}
	var u entra.User
	if err := decode(req, &u); err != nil {
		return badRequest(err)
	}
	var err error
	if tid == "" {
		err = a.entra.AdminCreateUser(u)
	} else {
		err = a.entra.AdminUpdateUser(tid, username, u)
	}
	if err != nil {
		return badRequest(err)
	}
	return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
}

func (a *Handler) upsertDirectoryUser(req *oauth2.Request) routing.Response {
	if a.dir == nil {
		return notFound()
	}
	var u directory.User
	if err := decode(req, &u); err != nil {
		return badRequest(err)
	}
	if err := a.dir.Upsert(u); err != nil {
		return badRequest(err)
	}
	return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
}

// overview renders the config-derived server facts plus live toggle state
// when a settings source is wired. Endpoint URLs are derived client-side
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
		{Name: "entraConfigured", V: a.entra != nil},
		{Name: "tokenCallbacks", V: callbacks},
	}
	if a.dir != nil {
		obj = append(obj, jsonx.Field{Name: "directoryUsers", V: len(a.dir.List())})
	}
	if a.cfg.LoginPagePath != "" {
		obj = append(obj, jsonx.Field{Name: "loginPagePath", V: a.cfg.LoginPagePath})
	}
	if a.cfg.StaticAssetsPath != "" {
		obj = append(obj, jsonx.Field{Name: "staticAssetsPath", V: a.cfg.StaticAssetsPath})
	}
	if a.settings != nil {
		st := a.settings.AdminSettings()
		obj = append(obj,
			jsonx.Field{Name: "entra", V: st.EntraEnabled},
			jsonx.Field{Name: "interactiveLoginLive", V: st.InteractiveLogin},
			jsonx.Field{Name: "rotateRefreshTokenLive", V: st.RotateRefreshToken},
		)
	} else {
		obj = append(obj, jsonx.Field{Name: "entra", V: a.entra != nil})
	}
	return obj
}
