package adminui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
)

// fakeEntra records admin actions and returns a fixed snapshot.
type fakeEntra struct {
	snapshot any
	resets   int
	rotates  int
	kid      string
}

func (f *fakeEntra) AdminSnapshot() any      { return f.snapshot }
func (f *fakeEntra) AdminResetConsents()     { f.resets++ }
func (f *fakeEntra) AdminRotateKeys() string { f.rotates++; return f.kid }

func testConfig() *config.OAuth2Config {
	return &config.OAuth2Config{
		InteractiveLogin: true,
		TokenCallbacks:   []*token.MappingCallback{{IssuerIDValue: "oidc", Expiry: 3600}},
	}
}

// newRouter mirrors the buildRouter registration order: normal routes, then
// the admin front routes.
func newRouter(entra EntraState) *routing.Router {
	rt := routing.New()
	rt.Post("/token", func(*oauth2.Request) routing.Response {
		return routing.JSON(jsonx.Obj{{Name: "served", V: "token"}})
	})
	admin := New(testConfig(), entra)
	rt.AddFront("", "/admin", admin.Handle)
	rt.AddFront("", "/admin/*", admin.Handle)
	return rt
}

func do(t *testing.T, rt *routing.Router, method, target string) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
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

func TestShellAndAssets(t *testing.T) {
	rt := newRouter(nil)
	for _, path := range []string{"/admin", "/admin/"} {
		resp := do(t, rt, http.MethodGet, path)
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
		resp := do(t, rt, http.MethodGet, path)
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != ct {
			t.Errorf("GET %s: status %d content type %q, want 200 %s", path, resp.StatusCode, resp.Header.Get("Content-Type"), ct)
		}
	}
	if resp := do(t, rt, http.MethodGet, "/admin/nope.txt"); resp.StatusCode != 404 {
		t.Errorf("GET unknown asset: status %d, want 404", resp.StatusCode)
	}
	if resp := do(t, rt, http.MethodGet, "/admin/../../etc/passwd"); resp.StatusCode != 404 {
		t.Errorf("GET traversal asset: status %d, want 404", resp.StatusCode)
	}
}

func TestAPIOverview(t *testing.T) {
	rt := newRouter(nil)
	resp := do(t, rt, http.MethodGet, "/admin/api/overview")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	b := body(t, resp)
	for _, want := range []string{
		`"interactiveLogin" : true`,
		`"rotateRefreshToken" : false`,
		`"entra" : false`,
		`"issuerId" : "oidc"`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("overview body missing %s:\n%s", want, b)
		}
	}
}

func TestAPIEntraNotConfigured(t *testing.T) {
	rt := newRouter(nil)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/admin/api/entra"},
		{http.MethodPost, "/admin/api/entra/reset"},
		{http.MethodPost, "/admin/api/entra/rotate-keys"},
	} {
		resp := do(t, rt, tc.method, tc.path)
		if resp.StatusCode != 404 {
			t.Errorf("%s %s without entra: status %d, want 404", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestAPIEntraActions(t *testing.T) {
	fe := &fakeEntra{
		snapshot: jsonx.Obj{{Name: "basePath", V: "entra"}},
		kid:      "entra-2",
	}
	rt := newRouter(fe)

	resp := do(t, rt, http.MethodGet, "/admin/api/entra")
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), `"basePath" : "entra"`) {
		t.Errorf("GET entra: status %d body %q", resp.StatusCode, body(t, resp))
	}

	resp = do(t, rt, http.MethodPost, "/admin/api/entra/reset")
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), `"status" : "ok"`) {
		t.Errorf("POST reset: status %d body %q", resp.StatusCode, body(t, resp))
	}
	if fe.resets != 1 {
		t.Errorf("resets = %d, want 1", fe.resets)
	}

	resp = do(t, rt, http.MethodPost, "/admin/api/entra/rotate-keys")
	if resp.StatusCode != 200 || !strings.Contains(body(t, resp), `"kid" : "entra-2"`) {
		t.Errorf("POST rotate-keys: status %d body %q", resp.StatusCode, body(t, resp))
	}
	if fe.rotates != 1 {
		t.Errorf("rotates = %d, want 1", fe.rotates)
	}

	if resp = do(t, rt, http.MethodGet, "/admin/api/unknown"); resp.StatusCode != 404 {
		t.Errorf("GET unknown api action: status %d, want 404", resp.StatusCode)
	}
}

func TestMethodGuard(t *testing.T) {
	rt := newRouter(nil)
	if resp := do(t, rt, http.MethodDelete, "/admin/api/overview"); resp.StatusCode != 405 {
		t.Errorf("DELETE overview: status %d, want 405", resp.StatusCode)
	}
	if resp := do(t, rt, http.MethodPost, "/admin"); resp.StatusCode != 405 {
		t.Errorf("POST /admin: status %d, want 405", resp.StatusCode)
	}
	if resp := do(t, rt, http.MethodPost, "/admin/style.css"); resp.StatusCode != 405 {
		t.Errorf("POST asset: status %d, want 405", resp.StatusCode)
	}
}

// TestFrontRoutePrecedence pins the repo rule: /admin is served by the front
// route even though suffix routes are registered, and the existing suffix
// routes keep working.
func TestFrontRoutePrecedence(t *testing.T) {
	rt := newRouter(nil)
	resp := do(t, rt, http.MethodGet, "/admin/api/overview")
	if resp.StatusCode != 200 {
		t.Errorf("GET /admin/api/overview: status %d, want 200 (front route must win)", resp.StatusCode)
	}
	// POST /token still reaches the suffix route, both at the root and under
	// an issuer path.
	for _, path := range []string{"/token", "/oidc/token"} {
		resp := do(t, rt, http.MethodPost, path)
		if resp.StatusCode != 200 || !strings.Contains(body(t, resp), `"served" : "token"`) {
			t.Errorf("POST %s: status %d body %q, want token route", path, resp.StatusCode, body(t, resp))
		}
	}
}
