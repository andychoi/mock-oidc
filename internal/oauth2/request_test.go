package oauth2

import (
	"net/http"
	"net/url"
	"testing"
)

func testRequest(method, rawURL string, header http.Header) *Request {
	u, _ := url.Parse(rawURL)
	scheme := "http"
	if header == nil {
		header = http.Header{}
	}
	return &Request{Method: method, Header: header, URL: u, scheme: scheme}
}

func TestIssuerID(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/oidc/token", "oidc"},
		{"/oidc/authorize", "oidc"},
		{"/oidc/.well-known/openid-configuration", "oidc"},
		{"/a/b/.well-known/oauth-authorization-server", "a/b"},
		{"/oidc/jwks/", "oidc"}, // trailing slash trimmed
		{"/oidc", "oidc"},       // bare issuer path
		{"/", ""},               // root
		{"/token", "token"},     // upstream quirk: bare endpoint at root
		{"/oidc/userinfo", "oidc"},
		{"/oidc/debugger/callback", "oidc"},
	}
	for _, c := range cases {
		r := testRequest("GET", "http://localhost:8080"+c.path, nil)
		if got := r.IssuerID(); got != c.want {
			t.Errorf("IssuerID(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestProxyAwareURL(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		header http.Header
		want   string
	}{
		{"host header port", "/oidc/token", hdr("Host", "mock-oidc.dev.test:8088"), "http://mock-oidc.dev.test:8088/oidc/token"},
		{"default http port elided", "/x", hdr("Host", "example.com:80"), "http://example.com/x"},
		{"x-forwarded-proto https", "/x", hdr("Host", "example.com", "X-Forwarded-Proto", "https"), "https://example.com/x"},
		{"x-forwarded-proto https with host port", "/x", hdr("Host", "example.com:8088", "X-Forwarded-Proto", "https"), "https://example.com:8088/x"},
		{"x-forwarded-port wins", "/x", hdr("Host", "internal:8080", "X-Forwarded-Port", "443", "X-Forwarded-Proto", "https"), "https://internal/x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := testRequest("GET", "http://127.0.0.1:1"+c.path, c.header)
			if got := r.ProxyAwareURL().String(); got != c.want {
				t.Errorf("ProxyAwareURL = %q, want %q", got, c.want)
			}
		})
	}
}

func TestIssuerAndEndpointURLs(t *testing.T) {
	r := testRequest("GET", "http://127.0.0.1:1/oidc/token", hdr("Host", "h.test:8088"))
	if got := r.IssuerURL(); got != "http://h.test:8088/oidc" {
		t.Errorf("IssuerURL = %q", got)
	}
	if got := r.EndpointURL(Token); got != "http://h.test:8088/oidc/token" {
		t.Errorf("EndpointURL(Token) = %q", got)
	}
	root := testRequest("GET", "http://127.0.0.1:1/.well-known/openid-configuration", hdr("Host", "h.test"))
	// Upstream quirk: a bare well-known at the root does not strip the endpoint
	// suffix, so the whole path becomes the issuerId.
	if got := root.IssuerURL(); got != "http://h.test/.well-known/openid-configuration" {
		t.Errorf("root well-known IssuerURL = %q", got)
	}
}

func TestFormParsing(t *testing.T) {
	r := testRequest("POST", "http://h/token", nil)
	r.Body = "grant_type=authorization_code&code=abc&claims=" + url.QueryEscape(`{"email":"a@b.c","note":"x=y"}`)
	form := r.Form()
	if form.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("claims") != `{"email":"a@b.c","note":"x=y"}` {
		t.Errorf("claims = %q", form.Get("claims"))
	}
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}
