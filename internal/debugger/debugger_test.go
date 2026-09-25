package debugger_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	mockoidc "github.com/andychoi/mock-oidc"
	"github.com/andychoi/mock-oidc/internal/config"
)

// skipVerify because the TLS test uses a self-signed certificate.
var noRedirect = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

func startServer(t *testing.T) (*mockoidc.Server, string) {
	t.Helper()
	cfg, err := config.ParseJSON([]byte(`{"interactiveLogin": false}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := mockoidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	return s, s.URL()
}

func do(t *testing.T, method, rawURL, body, cookie string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func TestDebuggerForm(t *testing.T) {
	_, base := startServer(t)
	status, _, body := do(t, "GET", base+"/oidc/debugger", "", "")
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	for _, want := range []string{
		`name="authorize_url"`, `name="token_url"`, `name="client_auth_method"`,
		`name="client_id"`, `name="client_secret"`, `name="scope"`,
		`name="response_type"`, `name="response_mode"`, `name="state"`,
		`name="nonce"`, `name="redirect_uri"`,
		`value="CLIENT_SECRET_BASIC"`, `value="someSecret"`, "openid somescope",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("form missing %q", want)
		}
	}
	if !strings.Contains(body, base+"/oidc/authorize") || !strings.Contains(body, base+"/oidc/token") {
		t.Errorf("endpoints not derived from request issuer")
	}
}

func TestDebuggerFullFlow(t *testing.T) {
	_, base := startServer(t)

	// 1. submit the form
	form := url.Values{
		"authorize_url":      {"ignored"},
		"token_url":          {"ignored"},
		"client_id":          {"debugger"},
		"client_secret":      {"someSecret"},
		"client_auth_method": {"CLIENT_SECRET_BASIC"},
		"scope":              {"openid somescope"},
		"response_type":      {"code"},
		"response_mode":      {"query"},
		"state":              {"1234"},
		"nonce":              {"5678"},
		"redirect_uri":       {"https://attacker.example/should-be-ignored"},
	}
	status, hdr, _ := do(t, "POST", base+"/oidc/debugger", form.Encode(), "")
	if status != 302 {
		t.Fatalf("submit: %d", status)
	}
	loc := hdr.Get("Location")
	// the redirect target derives from the request URL, not the form (SSRF fix)
	if !strings.HasPrefix(loc, base+"/oidc/authorize?") {
		t.Fatalf("redirect target: %s", loc)
	}
	for _, forbidden := range []string{"client_secret", "client_auth_method", "authorize_url", "token_url", "attacker.example"} {
		if strings.Contains(loc, forbidden) {
			t.Errorf("redirect leaks %q: %s", forbidden, loc)
		}
	}
	if !strings.Contains(loc, url.QueryEscape(base+"/oidc/debugger/callback")) {
		t.Errorf("redirect missing own callback uri: %s", loc)
	}
	setCookie := hdr.Get("Set-Cookie")
	if !strings.HasPrefix(setCookie, "debugger-session=") {
		t.Fatalf("no session cookie: %q", setCookie)
	}
	cookie := strings.SplitN(setCookie, ";", 2)[0]

	// 2. drive the authorize endpoint (non-interactive: immediate code)
	status, hdr, _ = do(t, "GET", loc, "", "")
	if status != 302 {
		t.Fatalf("authorize: %d", status)
	}
	cbURL := hdr.Get("Location")
	if !strings.HasPrefix(cbURL, base+"/oidc/debugger/callback?code=") {
		t.Fatalf("authorize redirect: %s", cbURL)
	}

	// 3. callback exchanges the code server-side and renders both artifacts
	status, _, body := do(t, "GET", cbURL, "", cookie)
	if status != 200 {
		t.Fatalf("callback: %d %s", status, body)
	}
	if !strings.Contains(body, "POST /oidc/token HTTP/1.1") {
		t.Errorf("token request dump missing:\n%s", body)
	}
	if !strings.Contains(body, "grant_type=authorization_code") {
		t.Errorf("token request body missing")
	}
	// html/template escapes quotes, so match the bare field names
	if !strings.Contains(body, "access_token") || !strings.Contains(body, "id_token") {
		t.Errorf("token response not rendered:\n%.500s", body)
	}
}

func TestDebuggerClientSecretPost(t *testing.T) {
	_, base := startServer(t)
	form := url.Values{
		"client_id":          {"post-client"},
		"client_secret":      {"post-secret"},
		"client_auth_method": {"CLIENT_SECRET_POST"},
		"scope":              {"openid"},
		"response_type":      {"code"},
		"response_mode":      {"query"},
		"state":              {"1"},
		"nonce":              {"2"},
	}
	_, hdr, _ := do(t, "POST", base+"/default/debugger", form.Encode(), "")
	cookie := strings.SplitN(hdr.Get("Set-Cookie"), ";", 2)[0]
	_, hdr, _ = do(t, "GET", hdr.Get("Location"), "", "")
	status, _, body := do(t, "GET", hdr.Get("Location"), "", cookie)
	if status != 200 {
		t.Fatalf("callback: %d %s", status, body)
	}
	if !strings.Contains(body, "client_id=post-client") || !strings.Contains(body, "client_secret=post-secret") {
		t.Errorf("client_secret_post credentials not in body:\n%s", body)
	}
	if strings.Contains(body, "Authorization: Basic") {
		t.Errorf("basic auth header should be absent for CLIENT_SECRET_POST")
	}
}

func TestDebuggerCallbackErrors(t *testing.T) {
	_, base := startServer(t)

	// no session cookie -> missing client_id -> error page
	status, _, body := do(t, "GET", base+"/oidc/debugger/callback?code=x", "", "")
	if status != 500 || !strings.Contains(body, "Something went wrong") {
		t.Errorf("no session: %d %.200s", status, body)
	}

	// session but no code
	form := url.Values{
		"client_id": {"c"}, "client_secret": {"s"}, "client_auth_method": {"CLIENT_SECRET_BASIC"},
		"scope": {"openid"}, "response_type": {"code"}, "response_mode": {"query"},
		"state": {"1"}, "nonce": {"2"},
	}
	_, hdr, _ := do(t, "POST", base+"/oidc/debugger", form.Encode(), "")
	cookie := strings.SplitN(hdr.Get("Set-Cookie"), ";", 2)[0]
	status, _, body = do(t, "GET", base+"/oidc/debugger/callback", "", cookie)
	if status != 500 || !strings.Contains(body, "no code parameter present") {
		t.Errorf("no code: %d %.200s", status, body)
	}
}

// TestDebuggerOverTLS: the debugger's internal token exchange must trust the
// server's own self-signed certificate when httpServer.ssl is configured.
func TestDebuggerOverTLS(t *testing.T) {
	cfg, err := config.ParseJSON([]byte(`{
		"interactiveLogin": false,
		"httpServer": {"type": "NettyWrapper", "ssl": {}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := mockoidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	base := s.URL()
	if !strings.HasPrefix(base, "https://") {
		t.Fatalf("expected https base, got %s", base)
	}

	form := url.Values{
		"client_id": {"tls-client"}, "client_secret": {"s"}, "client_auth_method": {"CLIENT_SECRET_BASIC"},
		"scope": {"openid"}, "response_type": {"code"}, "response_mode": {"query"},
		"state": {"1"}, "nonce": {"2"},
	}
	status, hdr, _ := do(t, "POST", base+"/oidc/debugger", form.Encode(), "")
	if status != 302 {
		t.Fatalf("submit over TLS: %d", status)
	}
	cookie := strings.SplitN(hdr.Get("Set-Cookie"), ";", 2)[0]
	status, hdr, _ = do(t, "GET", hdr.Get("Location"), "", "")
	if status != 302 {
		t.Fatalf("authorize over TLS: %d", status)
	}
	status, _, body := do(t, "GET", hdr.Get("Location"), "", cookie)
	if status != 200 || !strings.Contains(body, "access_token") {
		t.Errorf("debugger callback over TLS: %d %.300s", status, body)
	}
}
