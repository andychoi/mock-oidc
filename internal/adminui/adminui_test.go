package adminui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/directory"
	"github.com/andychoi/mock-oidc/internal/entra"
	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
)

const testEntraJSON = `{
  "basePath": "entra",
  "tenants": [
    {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.test"]},
    {"tid": "22222222-2222-2222-2222-222222222222", "name": "Customer", "consentRequired": true}
  ],
  "consents": [{"clientId": "seed-client", "tid": "22222222-2222-2222-2222-222222222222"}],
  "users": [
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Doe", "admin": true},
    {"username": "cust", "tid": "22222222-2222-2222-2222-222222222222"}
  ]
}`

const corpTID = "11111111-1111-1111-1111-111111111111"

func testEntra(t *testing.T) *entra.Handler {
	t.Helper()
	cfg, err := entra.ParseConfig([]byte(testEntraJSON))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	return entra.New(cfg)
}

var errSetting = http.ErrBodyNotAllowed // sentinel with a stable Error()

// fakeSettings mirrors the server toggle semantics for API tests.
type fakeSettings struct {
	st AdminSettings
}

func (f *fakeSettings) AdminSettings() AdminSettings { return f.st }

func (f *fakeSettings) AdminSetSetting(name string, value bool) error {
	switch name {
	case "interactiveLogin":
		f.st.InteractiveLogin = value
	case "rotateRefreshToken":
		f.st.RotateRefreshToken = value
	case "entra":
		if !f.st.EntraConfigured {
			return errSetting
		}
		f.st.EntraEnabled = value
	default:
		return errSetting
	}
	return nil
}

func testConfig() *config.OAuth2Config {
	return &config.OAuth2Config{
		InteractiveLogin: true,
		TokenCallbacks:   []*token.MappingCallback{{IssuerIDValue: "oidc", Expiry: 3600}},
	}
}

// newRouter mirrors the buildRouter registration order: suffix routes, then
// the admin front routes.
func newRouter(entra *entra.Handler, dir *directory.Directory, settings Settings) *routing.Router {
	rt := routing.New()
	rt.Post("/token", func(*oauth2.Request) routing.Response {
		return routing.JSON(jsonx.Obj{{Name: "served", V: "token"}})
	})
	admin := New(testConfig(), entra, dir, settings)
	rt.AddFront("", "/admin", admin.Handle)
	rt.AddFront("", "/admin/*", admin.Handle)
	return rt
}

func do(t *testing.T, rt *routing.Router, method, target, body string) *http.Response {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	return rec.Result()
}

func body(t *testing.T, resp *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(data)
}

// postBody returns the JSON body for methods that carry one.
func postBody(method, body string) string {
	if method == http.MethodPost || method == http.MethodPut {
		return body
	}
	return ""
}

func TestShellAndAssets(t *testing.T) {
	rt := newRouter(nil, nil, nil)
	for _, path := range []string{"/admin", "/admin/"} {
		resp := do(t, rt, http.MethodGet, path, "")
		if resp.StatusCode != 200 {
			t.Errorf("GET %s: status %d, want 200", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("GET %s: content type %q", path, ct)
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s: missing CSP", path)
		}
		if resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("GET %s: missing X-Frame-Options", path)
		}
		if b := body(t, resp); !strings.Contains(b, "<title>mock-oidc admin</title>") {
			t.Errorf("GET %s: unexpected shell body", path)
		}
	}
	wantTypes := map[string]string{
		"/admin/style.css":          "text/css; charset=utf-8",
		"/admin/app.js":             "text/javascript; charset=utf-8",
		"/admin/mona-sans-vf.woff2": "font/woff2",
	}
	for path, ct := range wantTypes {
		resp := do(t, rt, http.MethodGet, path, "")
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != ct {
			t.Errorf("GET %s: status %d content type %q, want 200 %s", path, resp.StatusCode, resp.Header.Get("Content-Type"), ct)
		}
	}
	if resp := do(t, rt, http.MethodGet, "/admin/nope.txt", ""); resp.StatusCode != 404 {
		t.Errorf("GET unknown asset: status %d, want 404", resp.StatusCode)
	}
	if resp := do(t, rt, http.MethodGet, "/admin/../../etc/passwd", ""); resp.StatusCode != 404 {
		t.Errorf("GET traversal asset: status %d, want 404", resp.StatusCode)
	}
}

func TestAPIOverview(t *testing.T) {
	rt := newRouter(testEntra(t), directory.New([]directory.User{{Username: "a"}}), nil)
	resp := do(t, rt, http.MethodGet, "/admin/api/overview", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	b := body(t, resp)
	for _, want := range []string{
		`"interactiveLogin" : true`,
		`"rotateRefreshToken" : false`,
		`"entraConfigured" : true`,
		`"issuerId" : "oidc"`,
		`"directoryUsers" : 1`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("overview body missing %s:\n%s", want, b)
		}
	}
}

func TestAPISettings(t *testing.T) {
	fs := &fakeSettings{st: AdminSettings{InteractiveLogin: true, EntraConfigured: true, EntraEnabled: true}}
	rt := newRouter(testEntra(t), nil, fs)

	resp := do(t, rt, http.MethodGet, "/admin/api/settings", "")
	if resp.StatusCode != 200 {
		t.Fatalf("GET settings: status %d", resp.StatusCode)
	}
	if b := body(t, resp); !strings.Contains(b, `"entraEnabled" : true`) {
		t.Errorf("GET settings body:\n%s", b)
	}

	resp = do(t, rt, http.MethodPost, "/admin/api/settings", `{"name":"interactiveLogin","value":false}`)
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), `"status" : "ok"`) {
		t.Errorf("POST settings: status %d body %q", resp.StatusCode, body(t, resp))
	}
	if fs.st.InteractiveLogin {
		t.Errorf("toggle not applied")
	}

	if resp = do(t, rt, http.MethodPost, "/admin/api/settings", `{"name":"nope","value":true}`); resp.StatusCode != 400 {
		t.Errorf("unknown setting: status %d, want 400", resp.StatusCode)
	}
	if resp = do(t, rt, http.MethodPost, "/admin/api/settings", `{bad json`); resp.StatusCode != 400 {
		t.Errorf("bad json: status %d, want 400", resp.StatusCode)
	}

	// settings source absent → 404
	rtNil := newRouter(nil, nil, nil)
	if resp := do(t, rtNil, http.MethodGet, "/admin/api/settings", ""); resp.StatusCode != 404 {
		t.Errorf("settings without source: status %d, want 404", resp.StatusCode)
	}
}

func TestAPIEntraNotConfigured(t *testing.T) {
	rt := newRouter(nil, nil, nil)
	actions := []struct{ method, path string }{
		{http.MethodGet, "/admin/api/entra"},
		{http.MethodPost, "/admin/api/entra/reset"},
		{http.MethodPost, "/admin/api/entra/rotate-keys"},
		{http.MethodPost, "/admin/api/entra/tenants"},
		{http.MethodDelete, "/admin/api/entra/tenants/x"},
		{http.MethodPost, "/admin/api/entra/users"},
		{http.MethodDelete, "/admin/api/entra/users/x/y"},
		{http.MethodDelete, "/admin/api/entra/consents/a/b"},
	}
	for _, tc := range actions {
		resp := do(t, rt, tc.method, tc.path, postBody(tc.method, `{}`))
		if resp.StatusCode != 404 {
			t.Errorf("%s %s without entra: status %d, want 404", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestAPIEntraTenantAndUserCRUD(t *testing.T) {
	eh := testEntra(t)
	rt := newRouter(eh, nil, nil)

	// create tenant
	resp := do(t, rt, http.MethodPost, "/admin/api/entra/tenants",
		`{"tid":"33333333-3333-3333-3333-333333333333","name":"New","domains":["n.test"],"groupLimit":10}`)
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), `"status" : "ok"`) {
		t.Fatalf("create tenant: status %d body %q", resp.StatusCode, body(t, resp))
	}
	// duplicate tid rejected by normalize
	if resp = do(t, rt, http.MethodPost, "/admin/api/entra/tenants", `{"tid":"33333333-3333-3333-3333-333333333333"}`); resp.StatusCode != 400 {
		t.Errorf("duplicate tenant: status %d, want 400", resp.StatusCode)
	}
	// bad GUID rejected
	if resp = do(t, rt, http.MethodPost, "/admin/api/entra/tenants", `{"tid":"nope"}`); resp.StatusCode != 400 {
		t.Errorf("bad guid: status %d, want 400", resp.StatusCode)
	}
	// rename rejected
	if resp = do(t, rt, http.MethodPut, "/admin/api/entra/tenants/"+corpTID, `{"tid":"44444444-4444-4444-4444-444444444444"}`); resp.StatusCode != 400 {
		t.Errorf("rename tenant: status %d, want 400", resp.StatusCode)
	}
	// update name
	if resp = do(t, rt, http.MethodPut, "/admin/api/entra/tenants/"+corpTID, `{"name":"Renamed"}`); resp.StatusCode != 200 {
		t.Errorf("update tenant: status %d body %q", resp.StatusCode, body(t, resp))
	}
	// unknown tenant delete → 404
	if resp = do(t, rt, http.MethodDelete, "/admin/api/entra/tenants/99999999-9999-9999-9999-999999999999", ""); resp.StatusCode != 404 {
		t.Errorf("delete unknown tenant: status %d, want 404", resp.StatusCode)
	}

	// user in the new tenant
	newTID := "33333333-3333-3333-3333-333333333333"
	resp = do(t, rt, http.MethodPost, "/admin/api/entra/users",
		`{"username":"nina","tid":"`+newTID+`","name":"Nina","groups":["g1","g2"],"amr":["pwd","mfa"],"admin":true}`)
	if resp.StatusCode != 200 {
		t.Fatalf("create user: status %d body %q", resp.StatusCode, body(t, resp))
	}
	// unknown tid
	if resp = do(t, rt, http.MethodPost, "/admin/api/entra/users", `{"username":"x","tid":"99999999-9999-9999-9999-999999999999"}`); resp.StatusCode != 400 {
		t.Errorf("user unknown tid: status %d, want 400", resp.StatusCode)
	}
	// duplicate username in tenant
	if resp = do(t, rt, http.MethodPost, "/admin/api/entra/users", `{"username":"nina","tid":"`+newTID+`"}`); resp.StatusCode != 400 {
		t.Errorf("duplicate user: status %d, want 400", resp.StatusCode)
	}
	// update (full replace; identity immutable)
	if resp = do(t, rt, http.MethodPut, "/admin/api/entra/users/"+newTID+"/nina", `{"name":"Nina N.","groups":["g1"],"amr":["pwd"],"admin":true}`); resp.StatusCode != 200 {
		t.Errorf("update user: status %d body %q", resp.StatusCode, body(t, resp))
	}
	// delete unknown → 404
	if resp = do(t, rt, http.MethodDelete, "/admin/api/entra/users/"+newTID+"/ghost", ""); resp.StatusCode != 404 {
		t.Errorf("delete unknown user: status %d, want 404", resp.StatusCode)
	}

	// snapshot reflects everything
	resp = do(t, rt, http.MethodGet, "/admin/api/entra", "")
	b := body(t, resp)
	for _, want := range []string{`"name" : "Renamed"`, `"username" : "nina"`, `"g1"`} {
		if !strings.Contains(b, want) {
			t.Errorf("snapshot missing %s:\n%s", want, b)
		}
	}

	// reset-to-seed removes runtime entities
	if resp = do(t, rt, http.MethodPost, "/admin/api/entra/reset", ""); resp.StatusCode != 200 {
		t.Errorf("reset: status %d", resp.StatusCode)
	}
	b = body(t, do(t, rt, http.MethodGet, "/admin/api/entra", ""))
	if strings.Contains(b, `"nina"`) || strings.Contains(b, "Renamed") {
		t.Errorf("reset did not restore seed:\n%s", b)
	}
}

func TestAPIEntraConsentRevokeAndRotate(t *testing.T) {
	eh := testEntra(t)
	rt := newRouter(eh, nil, nil)

	seed := body(t, do(t, rt, http.MethodGet, "/admin/api/entra", ""))
	if !strings.Contains(seed, `"seed-client"`) {
		t.Fatalf("seed consent missing:\n%s", seed)
	}
	resp := do(t, rt, http.MethodDelete, "/admin/api/entra/consents/seed-client/22222222-2222-2222-2222-222222222222", "")
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: status %d", resp.StatusCode)
	}
	if b := body(t, do(t, rt, http.MethodGet, "/admin/api/entra", "")); strings.Contains(b, `"seed-client"`) {
		t.Errorf("consent not revoked:\n%s", b)
	}
	// seeded consent returns on reset (documented semantics)
	do(t, rt, http.MethodPost, "/admin/api/entra/reset", "")
	if b := body(t, do(t, rt, http.MethodGet, "/admin/api/entra", "")); !strings.Contains(b, `"seed-client"`) {
		t.Errorf("reset should restore seed consent:\n%s", b)
	}

	resp = do(t, rt, http.MethodPost, "/admin/api/entra/rotate-keys", "")
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), `"kid" : "entra-2"`) {
		t.Errorf("rotate-keys: status %d body %q", resp.StatusCode, body(t, resp))
	}
}

func TestAPIDirectory(t *testing.T) {
	dir := directory.New([]directory.User{{Username: "a", Name: "A", Email: "a@x.test", Groups: []string{"g"}}})
	rt := newRouter(nil, dir, nil)

	resp := do(t, rt, http.MethodGet, "/admin/api/directory", "")
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), `"username" : "a"`) {
		t.Fatalf("list: status %d body %q", resp.StatusCode, body(t, resp))
	}
	if resp = do(t, rt, http.MethodPost, "/admin/api/directory/users", `{"username":"b","name":"B","email":"b@x.test","groups":["y"]}`); resp.StatusCode != 200 {
		t.Fatalf("upsert: status %d body %q", resp.StatusCode, body(t, resp))
	}
	if resp = do(t, rt, http.MethodPost, "/admin/api/directory/users", `{"username":""}`); resp.StatusCode != 400 {
		t.Errorf("empty username: status %d, want 400", resp.StatusCode)
	}
	if resp = do(t, rt, http.MethodDelete, "/admin/api/directory/users/b", ""); resp.StatusCode != 200 {
		t.Errorf("delete: status %d", resp.StatusCode)
	}
	if resp = do(t, rt, http.MethodDelete, "/admin/api/directory/users/b", ""); resp.StatusCode != 404 {
		t.Errorf("delete again: status %d, want 404", resp.StatusCode)
	}
	// reset restores the seed user
	if resp = do(t, rt, http.MethodPost, "/admin/api/directory/reset", ""); resp.StatusCode != 200 {
		t.Errorf("reset: status %d", resp.StatusCode)
	}
	if b := body(t, do(t, rt, http.MethodGet, "/admin/api/directory", "")); !strings.Contains(b, `"username" : "a"`) {
		t.Errorf("reset lost seed:\n%s", b)
	}

	// nil directory → 404
	rtNil := newRouter(nil, nil, nil)
	if resp := do(t, rtNil, http.MethodGet, "/admin/api/directory", ""); resp.StatusCode != 404 {
		t.Errorf("directory without store: status %d, want 404", resp.StatusCode)
	}
}

func TestMethodGuard(t *testing.T) {
	rt := newRouter(nil, nil, nil)
	if resp := do(t, rt, http.MethodPatch, "/admin/api/overview", ""); resp.StatusCode != 405 {
		t.Errorf("PATCH overview: status %d, want 405", resp.StatusCode)
	}
	if resp := do(t, rt, http.MethodPost, "/admin", ""); resp.StatusCode != 405 {
		t.Errorf("POST /admin: status %d, want 405", resp.StatusCode)
	}
	if resp := do(t, rt, http.MethodPost, "/admin/style.css", ""); resp.StatusCode != 405 {
		t.Errorf("POST asset: status %d, want 405", resp.StatusCode)
	}
}

// TestFrontRoutePrecedence pins the repo rule: /admin is served by the front
// route even though suffix routes are registered, and the existing suffix
// routes keep working.
func TestFrontRoutePrecedence(t *testing.T) {
	rt := newRouter(nil, nil, nil)
	resp := do(t, rt, http.MethodGet, "/admin/api/overview", "")
	if resp.StatusCode != 200 {
		t.Errorf("GET /admin/api/overview: status %d, want 200 (front route must win)", resp.StatusCode)
	}
	for _, path := range []string{"/token", "/oidc/token"} {
		resp := do(t, rt, http.MethodPost, path, "")
		if resp.StatusCode != 200 || !strings.Contains(body(t, resp), `"served" : "token"`) {
			t.Errorf("POST %s: status %d body %q, want token route", path, resp.StatusCode, body(t, resp))
		}
	}
}
