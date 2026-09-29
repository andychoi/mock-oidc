package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/server"
)

const adminEntraConfig = `{
  "interactiveLogin": true,
  "entra": {
    "basePath": "entra",
    "tenants": [
      { "tid": "11111111-1111-1111-1111-111111111111", "name": "Test Tenant", "domains": ["t.test"] }
    ],
    "users": [
      { "username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Doe", "admin": true }
    ]
  }
}`

func newAdminServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg, err := config.ParseJSON([]byte(adminEntraConfig))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	s := server.New(cfg)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func adminDo(t *testing.T, ts *httptest.Server, method, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func adminBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(data)
}

func TestAdminShell(t *testing.T) {
	ts := newAdminServer(t)
	for _, path := range []string{"/admin", "/admin/"} {
		resp := adminDo(t, ts, http.MethodGet, path)
		if resp.StatusCode != 200 {
			t.Errorf("GET %s: status %d, want 200", path, resp.StatusCode)
		}
		if resp.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s: missing CSP", path)
		}
		if b := adminBody(t, resp); !strings.Contains(b, "mock-oidc") {
			t.Errorf("GET %s: unexpected shell", path)
		}
	}
}

func TestAdminOverviewAndEntra(t *testing.T) {
	ts := newAdminServer(t)

	resp := adminDo(t, ts, http.MethodGet, "/admin/api/overview")
	if resp.StatusCode != 200 {
		t.Fatalf("overview: status %d", resp.StatusCode)
	}
	if b := adminBody(t, resp); !strings.Contains(b, `"entra" : true`) {
		t.Errorf("overview: want entra true, got:\n%s", b)
	}

	resp = adminDo(t, ts, http.MethodGet, "/admin/api/entra")
	if resp.StatusCode != 200 {
		t.Fatalf("entra: status %d", resp.StatusCode)
	}
	b := adminBody(t, resp)
	for _, want := range []string{`"basePath" : "entra"`, `"username" : "jane"`, `"activeKid" : "entra-1"`} {
		if !strings.Contains(b, want) {
			t.Errorf("entra snapshot missing %s:\n%s", want, b)
		}
	}

	// rotate-keys mints a new active kid and keeps the previous one published.
	resp = adminDo(t, ts, http.MethodPost, "/admin/api/entra/rotate-keys")
	if resp.StatusCode != 200 {
		t.Fatalf("rotate-keys: status %d", resp.StatusCode)
	}
	b = adminBody(t, resp)
	if !strings.Contains(b, `"kid" : "entra-2"`) {
		t.Errorf("rotate-keys response:\n%s", b)
	}
	resp = adminDo(t, ts, http.MethodGet, "/admin/api/entra")
	b = adminBody(t, resp)
	if !strings.Contains(b, `"activeKid" : "entra-2"`) || !strings.Contains(b, `"entra-1"`) {
		t.Errorf("entra snapshot after rotate:\n%s", b)
	}

	// reset restores the seed (empty) consent set.
	resp = adminDo(t, ts, http.MethodPost, "/admin/api/entra/reset")
	if resp.StatusCode != 200 || !strings.Contains(adminBody(t, resp), `"status" : "ok"`) {
		t.Errorf("reset: status %d", resp.StatusCode)
	}
}

// TestAdminDoesNotDisturbIssuerRoutes pins navikt parity on a path family the
// front route now shadows-adjacent: the canonical issuer still serves
// discovery, and unknown admin asset paths 404 instead of leaking HTML.
func TestAdminDoesNotDisturbIssuerRoutes(t *testing.T) {
	ts := newAdminServer(t)

	resp := adminDo(t, ts, http.MethodGet, "/oidc/.well-known/openid-configuration")
	if resp.StatusCode != 200 {
		t.Errorf("discovery: status %d, want 200", resp.StatusCode)
	}
	if b := adminBody(t, resp); !strings.Contains(b, `"issuer"`) {
		t.Errorf("discovery body missing issuer:\n%s", b)
	}

	if resp = adminDo(t, ts, http.MethodGet, "/admin/missing.js"); resp.StatusCode != 404 {
		t.Errorf("GET /admin/missing.js: status %d, want 404", resp.StatusCode)
	}
}
