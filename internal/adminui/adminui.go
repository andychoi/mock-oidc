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
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
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

// portalHTML is the /admin/portal shell (its own SPA with hash routing).
var portalHTML []byte

func init() {
	types := map[string]string{
		".html":  "text/html; charset=utf-8",
		".css":   "text/css; charset=utf-8",
		".js":    "text/javascript; charset=utf-8",
		".woff2": "font/woff2",
		".txt":   "text/plain; charset=utf-8",
	}
	contentType := func(name string) string {
		for ext, t := range types {
			if len(name) >= len(ext) && name[len(name)-len(ext):] == ext {
				return t
			}
		}
		return "application/octet-stream"
	}
	// The static dir is walked recursively (the portal lives in static/portal/)
	// so "exactly these files" stays a property of the directory itself.
	err := fs.WalkDir(staticFS, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		body, err := staticFS.ReadFile(path)
		if err != nil {
			return err
		}
		name := "/" + strings.TrimPrefix(path, "static/")
		assets[name] = webFile{body: body, contentType: contentType(d.Name())}
		switch name {
		case "/index.html":
			indexHTML = body
		case "/portal/index.html":
			portalHTML = body
		}
		return nil
	})
	if err != nil {
		panic("adminui: cannot read embedded static dir: " + err.Error())
	}
	if indexHTML == nil {
		panic("adminui: static/index.html missing")
	}
	if portalHTML == nil {
		panic("adminui: static/portal/index.html missing")
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
	GraphEnabled       bool
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
	// The escaped path keeps an encoded "/" inside a name's segment; api
	// unescapes each segment after splitting.
	trimmed := strings.Trim(req.URL.EscapedPath(), "/")
	rest := strings.TrimPrefix(trimmed, "admin")
	rest = strings.TrimPrefix(rest, "/")
	if rest == "mcp" {
		return a.serveMCP(req)
	}
	if strings.HasPrefix(rest, "api/") {
		switch req.Method {
		case http.MethodGet, http.MethodDelete:
		case http.MethodPost, http.MethodPut:
			if !jsonContent(req) {
				return apiError(http.StatusUnsupportedMediaType, "content-type must be application/json")
			}
		default:
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
	// The portal (the Entra admin center page) is its own hash-routed SPA: its
	// real files (portal.css, portal.js) resolve directly and every other path
	// under it serves the shell.
	if rest == "portal" || rest == "portal/" || strings.HasPrefix(rest, "portal/") {
		if _, ok := assets["/"+rest]; ok {
			return a.serve(rest)
		}
		return a.serve("portal/index.html")
	}
	return a.serve(rest)
}

// jsonContent reports whether a write may reach the API. A JSON media type
// forces a CORS preflight on any cross-origin browser request, and the admin
// surface answers preflights without CORS headers. Browsers attach Origin to
// every POST, so a write with neither Content-Type nor Origin comes from a
// non-browser client.
func jsonContent(req *oauth2.Request) bool {
	ct := req.Header.Get("Content-Type")
	if ct == "" && req.Header.Get("Origin") == "" {
		return true
	}
	mt, _, _ := mime.ParseMediaType(ct)
	return mt == "application/json"
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

// decode parses a JSON request body holding exactly one value into out,
// rejecting unknown fields.
func decode(req *oauth2.Request, out any) error {
	dec := json.NewDecoder(strings.NewReader(req.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid json body: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("invalid json body: trailing data after the object")
	}
	return nil
}

func (a *Handler) api(req *oauth2.Request, action string) routing.Response {
	get, post := req.Method == http.MethodGet, req.Method == http.MethodPost
	put, del := req.Method == http.MethodPut, req.Method == http.MethodDelete
	segs := strings.Split(action, "/")
	for i, seg := range segs {
		if v, err := url.PathUnescape(seg); err == nil {
			segs[i] = v
		}
	}
	if segs[0] == "settings" && a.settings == nil ||
		segs[0] == "entra" && a.entra == nil ||
		segs[0] == "directory" && a.dir == nil {
		return notFound()
	}

	switch {
	// --- settings ---
	case get && action == "settings":
		return routing.JSON(settingsObj(a.settings.AdminSettings()))
	case post && action == "settings":
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
		return routing.JSON(a.entra.AdminSnapshot())
	case post && action == "entra/reset":
		a.entra.AdminResetToSeed()
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
	case post && action == "entra/rotate-keys":
		return routing.JSON(jsonx.Obj{{Name: "kid", V: a.entra.AdminRotateKeys()}})
	case del && len(segs) == 4 && segs[0] == "entra" && segs[1] == "consents":
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
			if err := a.entra.AdminDeleteUser(tid, username); err != nil {
				return deleteError(err)
			}
			return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
		}

	// --- entra: app registrations (the Entra admin center page) ---
	case post && action == "entra/apps":
		return a.createApp(req)
	case len(segs) >= 3 && segs[0] == "entra" && segs[1] == "apps":
		clientID := segs[2]
		switch {
		case put && len(segs) == 3:
			return a.updateApp(req, clientID)
		case del && len(segs) == 3:
			if err := a.entra.AdminDeleteApp(clientID); err != nil {
				return deleteError(err)
			}
			return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
		case post && len(segs) == 4 && segs[3] == "secrets":
			return a.addAppSecret(req, clientID)
		case del && len(segs) == 5 && segs[3] == "secrets":
			if err := a.entra.AdminDeleteAppSecret(clientID, segs[4]); err != nil {
				return deleteError(err)
			}
			return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
		}

	// --- directory ---
	case get && action == "directory":
		return routing.JSON(directoryArr(a.dir))
	case post && action == "directory/users":
		return a.upsertDirectoryUser(req)
	case len(segs) == 3 && segs[0] == "directory" && segs[1] == "users" && del:
		if err := a.dir.Delete(segs[2]); err != nil {
			return deleteError(err)
		}
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
	case post && action == "directory/reset":
		a.dir.Reset()
		return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})

	case get && action == "overview":
		return routing.JSON(a.overview())
	}
	return notFound()
}

func settingsObj(st AdminSettings) jsonx.Obj {
	return jsonx.Obj{
		{Name: "interactiveLogin", V: st.InteractiveLogin},
		{Name: "rotateRefreshToken", V: st.RotateRefreshToken},
		{Name: "entraConfigured", V: st.EntraConfigured},
		{Name: "entraEnabled", V: st.EntraEnabled},
		{Name: "graphEnabled", V: st.GraphEnabled},
	}
}

func directoryArr(dir *directory.Directory) jsonx.Arr {
	arr := jsonx.Arr{}
	for _, u := range dir.List() {
		arr = append(arr, jsonx.Obj{
			{Name: "username", V: u.Username},
			{Name: "name", V: u.Name},
			{Name: "email", V: u.Email},
			{Name: "groups", V: u.Groups},
		})
	}
	return arr
}

// deleteError maps store errors: unknown entity → 404, the rest → 400.
func deleteError(err error) routing.Response {
	if errors.Is(err, entra.ErrNotFound) || strings.HasSuffix(err.Error(), ": not found") {
		return apiError(404, err.Error())
	}
	return badRequest(err)
}

func (a *Handler) upsertTenant(req *oauth2.Request, tid string) routing.Response {
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

// createApp registers an app. Unlike the tenant/user upserts it returns the
// created registration, not {status: ok}: the New registration form needs the
// generated client ID and object ID before it can route to the app page.
func (a *Handler) createApp(req *oauth2.Request) routing.Response {
	var app entra.App
	if err := decode(req, &app); err != nil {
		return badRequest(err)
	}
	created, err := a.entra.AdminCreateApp(app)
	if err != nil {
		return badRequest(err)
	}
	return routing.JSON(entra.AppObj(created))
}

// updateApp replaces the registration fields of app clientID. Secrets in the
// body are ignored and preserved (they are managed by their own endpoints).
func (a *Handler) updateApp(req *oauth2.Request, clientID string) routing.Response {
	var app entra.App
	if err := decode(req, &app); err != nil {
		return badRequest(err)
	}
	if err := a.entra.AdminUpdateApp(clientID, app); err != nil {
		if errors.Is(err, entra.ErrNotFound) || strings.HasSuffix(err.Error(), ": not found") {
			return apiError(404, err.Error())
		}
		return badRequest(err)
	}
	return routing.JSON(jsonx.Obj{{Name: "status", V: "ok"}})
}

// addAppSecret adds a client secret and returns it with its one-time value.
func (a *Handler) addAppSecret(req *oauth2.Request, clientID string) routing.Response {
	var body struct {
		Description string `json:"description"`
		Expires     string `json:"expires"`
	}
	if err := decode(req, &body); err != nil {
		return badRequest(err)
	}
	sec, err := a.entra.AdminAddAppSecret(clientID, body.Description, body.Expires)
	if err != nil {
		return deleteError(err)
	}
	return routing.JSON(entra.AppSecretObj(sec))
}

func (a *Handler) upsertDirectoryUser(req *oauth2.Request) routing.Response {
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
			jsonx.Field{Name: "graph", V: st.GraphEnabled},
			jsonx.Field{Name: "interactiveLoginLive", V: st.InteractiveLogin},
			jsonx.Field{Name: "rotateRefreshTokenLive", V: st.RotateRefreshToken},
		)
	} else {
		obj = append(obj, jsonx.Field{Name: "entra", V: a.entra != nil})
	}
	return obj
}
