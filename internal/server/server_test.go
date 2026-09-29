package server_test

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/server"
)

// base64Decode decodes a raw (unpadded) base64url JWT segment.
func base64Decode(s string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

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

func newAdminServer(t *testing.T, cfgJSON string) *httptest.Server {
	t.Helper()
	cfg, err := config.ParseJSON([]byte(cfgJSON))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}
	s := server.New(cfg)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func adminDo(t *testing.T, ts *httptest.Server, method, path, body string) (int, http.Header, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	// noRedirect: authorize flows answer with 302s whose Location is the
	// client callback; following them would leave the test server.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(data)
}

func TestAdminShell(t *testing.T) {
	ts := newAdminServer(t, adminEntraConfig)
	for _, path := range []string{"/admin", "/admin/"} {
		status, hdr, b := adminDo(t, ts, http.MethodGet, path, "")
		if status != 200 {
			t.Errorf("GET %s: status %d, want 200", path, status)
		}
		if hdr.Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s: missing CSP", path)
		}
		if !strings.Contains(b, "mock-oidc") {
			t.Errorf("GET %s: unexpected shell", path)
		}
	}
}

func TestAdminOverviewAndEntraSnapshot(t *testing.T) {
	ts := newAdminServer(t, adminEntraConfig)

	status, _, b := adminDo(t, ts, http.MethodGet, "/admin/api/overview", "")
	if status != 200 || !strings.Contains(b, `"entraConfigured" : true`) {
		t.Fatalf("overview: status %d body %s", status, b)
	}

	status, _, b = adminDo(t, ts, http.MethodGet, "/admin/api/entra", "")
	if status != 200 {
		t.Fatalf("entra: status %d", status)
	}
	for _, want := range []string{`"basePath" : "entra"`, `"username" : "jane"`, `"activeKid" : "entra-1"`} {
		if !strings.Contains(b, want) {
			t.Errorf("entra snapshot missing %s:\n%s", want, b)
		}
	}
}

// TestAdminRuntimeToggleInteractiveLogin flips the flag through the admin API
// and watches authorize change behavior without a restart.
func TestAdminRuntimeToggleInteractiveLogin(t *testing.T) {
	ts := newAdminServer(t, adminEntraConfig)
	authURL := "/oidc/authorize?client_id=cid&redirect_uri=http://localhost/cb&response_type=code&scope=openid"

	status, _, b := adminDo(t, ts, http.MethodGet, authURL, "")
	if status != 200 || !strings.Contains(b, "<html") {
		t.Fatalf("interactive login on: status %d, want login page", status)
	}

	if status, _, _ = adminDo(t, ts, http.MethodPost, "/admin/api/settings", `{"name":"interactiveLogin","value":false}`); status != 200 {
		t.Fatalf("toggle: status %d", status)
	}
	status, hdr, _ := adminDo(t, ts, http.MethodGet, authURL, "")
	if status != 302 || !strings.Contains(hdr.Get("Location"), "code=") {
		t.Fatalf("interactive login off: status %d loc %q, want direct code redirect", status, hdr.Get("Location"))
	}

	// prompt=login still forces the login page
	status, _, b = adminDo(t, ts, http.MethodGet, authURL+"&prompt=login", "")
	if status != 200 || !strings.Contains(b, "<html") {
		t.Fatalf("prompt=login: status %d, want login page", status)
	}
}

// TestAdminRuntimeToggleEntra checks the entra gate: off behaves like an
// unrouted path (405 / OPTIONS 204), on serves normally.
func TestAdminRuntimeToggleEntra(t *testing.T) {
	ts := newAdminServer(t, adminEntraConfig)
	disc := "/entra/11111111-1111-1111-1111-111111111111/v2.0/.well-known/openid-configuration"

	if status, _, b := adminDo(t, ts, http.MethodGet, disc, ""); status != 200 || !strings.Contains(b, `"issuer"`) {
		t.Fatalf("enabled discovery: status %d", status)
	}

	if status, _, _ := adminDo(t, ts, http.MethodPost, "/admin/api/settings", `{"name":"entra","value":false}`); status != 200 {
		t.Fatalf("toggle off: status %d", status)
	}
	if status, _, b := adminDo(t, ts, http.MethodGet, disc, ""); status != 405 || strings.Contains(b, `"issuer"`) {
		t.Errorf("disabled discovery: status %d, want 405", status)
	}
	if status, _, _ := adminDo(t, ts, http.MethodOptions, disc, ""); status != 204 {
		t.Errorf("disabled OPTIONS: status %d, want 204", status)
	}
	if status, _, _ := adminDo(t, ts, http.MethodGet, "/entra/_entra/consents", ""); status != 405 {
		t.Errorf("disabled test api: status %d, want 405", status)
	}

	if status, _, _ := adminDo(t, ts, http.MethodPost, "/admin/api/settings", `{"name":"entra","value":true}`); status != 200 {
		t.Fatalf("toggle on: status %d", status)
	}
	if status, _, _ := adminDo(t, ts, http.MethodGet, disc, ""); status != 200 {
		t.Errorf("re-enabled discovery: status %d, want 200", status)
	}
}

// TestAdminToggleEntraWithoutConfig: the toggle is rejected when Entra mode
// was not configured at startup.
func TestAdminToggleEntraWithoutConfig(t *testing.T) {
	ts := newAdminServer(t, `{"interactiveLogin":true}`)
	status, _, b := adminDo(t, ts, http.MethodPost, "/admin/api/settings", `{"name":"entra","value":true}`)
	if status != 400 {
		t.Errorf("entra toggle without config: status %d body %s, want 400", status, b)
	}
}

// TestAdminRotateRefreshTokenToggle drives the full code flow twice, toggling
// rotation between refreshes (first coverage of rotateRefreshToken semantics).
func TestAdminRotateRefreshTokenToggle(t *testing.T) {
	ts := newAdminServer(t, `{"interactiveLogin":false}`)

	mint := func() string {
		status, hdr, _ := adminDo(t, ts, http.MethodGet,
			"/oidc/authorize?client_id=cid&redirect_uri=http://localhost/cb&response_type=code&scope=openid", "")
		if status != 302 {
			t.Fatalf("authorize: status %d", status)
		}
		loc, _ := url.Parse(hdr.Get("Location"))
		code := loc.Query().Get("code")
		status, _, b := adminDo(t, ts, http.MethodPost, "/oidc/token",
			"client_id=cid&client_secret=s&grant_type=authorization_code&code="+url.QueryEscape(code)+"&redirect_uri="+url.QueryEscape("http://localhost/cb"))
		if status != 200 {
			t.Fatalf("token: status %d %s", status, b)
		}
		var resp struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.Unmarshal([]byte(b), &resp)
		return resp.RefreshToken
	}
	refresh := func(rt string) string {
		status, _, b := adminDo(t, ts, http.MethodPost, "/oidc/token",
			"client_id=cid&client_secret=s&grant_type=refresh_token&refresh_token="+url.QueryEscape(rt))
		if status != 200 {
			t.Fatalf("refresh: status %d %s", status, b)
		}
		var resp struct {
			RefreshToken string `json:"refresh_token"`
		}
		_ = json.Unmarshal([]byte(b), &resp)
		return resp.RefreshToken
	}

	rt := mint()
	// rotation off (config default): the same refresh token is returned
	if again := refresh(rt); again != rt {
		t.Errorf("rotation off: refresh token changed (%q -> %q)", rt, again)
	}
	// rotation on: a new refresh token is minted
	adminDo(t, ts, http.MethodPost, "/admin/api/settings", `{"name":"rotateRefreshToken","value":true}`)
	if again := refresh(rt); again == rt || again == "" {
		t.Errorf("rotation on: refresh token not rotated (%q)", again)
	}
}

// TestAdminRuntimeUserSignsIn adds a user through the admin API and completes
// the full Entra authorize -> token flow with it.
func TestAdminRuntimeUserSignsIn(t *testing.T) {
	ts := newAdminServer(t, adminEntraConfig)
	tid := "11111111-1111-1111-1111-111111111111"

	status, _, b := adminDo(t, ts, http.MethodPost, "/admin/api/entra/users",
		`{"username":"runtimeuser","tid":"`+tid+`","name":"Runtime User","email":"r@t.test"}`)
	if status != 200 {
		t.Fatalf("create user: status %d %s", status, b)
	}

	auth := "/entra/" + tid + "/oauth2/v2.0/authorize?client_id=cid&redirect_uri=http://localhost/cb&response_type=code&scope=openid"
	// the picker offers the runtime user
	status, _, b = adminDo(t, ts, http.MethodGet, auth, "")
	if status != 200 || !strings.Contains(b, "runtimeuser") {
		t.Fatalf("picker missing runtime user: status %d", status)
	}
	// sign in as the runtime user
	status, hdr, _ := adminDo(t, ts, http.MethodPost, auth,
		"action=signin&tid="+tid+"&username=runtimeuser")
	if status != 302 {
		t.Fatalf("signin: status %d %s", status, b)
	}
	loc, _ := url.Parse(hdr.Get("Location"))
	code := loc.Query().Get("code")

	status, _, b = adminDo(t, ts, http.MethodPost, "/entra/"+tid+"/oauth2/v2.0/token",
		"client_id=cid&client_secret=s&grant_type=authorization_code&code="+url.QueryEscape(code)+
			"&redirect_uri="+url.QueryEscape("http://localhost/cb")+"&client_id=cid")
	if status != 200 {
		t.Fatalf("token: status %d %s", status, b)
	}
	var resp struct {
		IDToken string `json:"id_token"`
	}
	_ = json.Unmarshal([]byte(b), &resp)
	if resp.IDToken == "" {
		t.Fatalf("no id_token: %s", b)
	}
	// the id_token carries the runtime user's name claim
	payload := strings.Split(resp.IDToken, ".")[1]
	decoded, err := base64Decode(payload)
	if err != nil {
		t.Fatalf("decode id_token: %v", err)
	}
	if !strings.Contains(decoded, "Runtime User") {
		t.Errorf("id_token missing runtime user name:\n%s", decoded)
	}
}

// TestAdminDoesNotDisturbIssuerRoutes pins navikt parity on a path family the
// front route now shadows-adjacent: the canonical issuer still serves
// discovery, and unknown admin asset paths 404 instead of leaking HTML.
func TestAdminDoesNotDisturbIssuerRoutes(t *testing.T) {
	ts := newAdminServer(t, adminEntraConfig)

	status, _, b := adminDo(t, ts, http.MethodGet, "/oidc/.well-known/openid-configuration", "")
	if status != 200 || !strings.Contains(b, `"issuer"`) {
		t.Errorf("discovery: status %d, want 200", status)
	}
	if status, _, _ := adminDo(t, ts, http.MethodGet, "/admin/missing.js", ""); status != 404 {
		t.Errorf("GET /admin/missing.js: status %d, want 404", status)
	}
}
