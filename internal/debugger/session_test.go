package debugger

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/oauth2"
)

func testReq(cookie string) *oauth2.Request {
	return &oauth2.Request{Header: headerWithCookie(cookie)}
}

func headerWithCookie(cookie string) http.Header {
	h := http.Header{}
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	return h
}

func TestSessionCookieRoundTrip(t *testing.T) {
	m := newSessionManager()
	s := m.session(testReq(""))
	s.putAll(map[string]string{"client_id": "debugger", "client_secret": "someSecret", "client_auth_method": "CLIENT_SECRET_BASIC"})
	cookie := s.asCookie(m)

	if !strings.HasPrefix(cookie, "debugger-session=") || !strings.HasSuffix(cookie, "; HttpOnly; Path=/") {
		t.Fatalf("cookie format: %q", cookie)
	}
	jwe := strings.TrimPrefix(strings.TrimSuffix(cookie, "; HttpOnly; Path=/"), "debugger-session=")
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 || parts[1] != "" {
		t.Fatalf("expected 5-part JWE with empty encrypted key (alg=dir): %d parts", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || !strings.Contains(string(headerJSON), `"dir"`) || !strings.Contains(string(headerJSON), "A128GCM") {
		t.Fatalf("JWE header: %s %v", headerJSON, err)
	}

	// a fresh manager (different key) cannot decrypt — sessions are per-server
	other := newSessionManager().session(&oauth2.Request{Header: headerWithCookie(cookie)})
	if len(other.params) != 0 {
		t.Errorf("wrong-key decryption should yield an empty session, got %v", other.params)
	}

	// same manager round-trips
	loaded := m.session(&oauth2.Request{Header: headerWithCookie(cookie)})
	if loaded.params["client_id"] != "debugger" || loaded.params["client_secret"] != "someSecret" {
		t.Errorf("round trip: %v", loaded.params)
	}
	v, err := loaded.get("client_id")
	if err != nil || v != "debugger" {
		t.Errorf("get: %v %v", v, err)
	}
	if _, err := loaded.get("missing"); err == nil {
		t.Errorf("missing key should error")
	}
}

func TestSessionJSONShape(t *testing.T) {
	m := newSessionManager()
	s := m.session(testReq(""))
	s.putAll(map[string]string{"a": "b"})
	jwe := strings.TrimSuffix(strings.TrimPrefix(s.asCookie(m), "debugger-session="), "; HttpOnly; Path=/")
	plain, err := m.decrypt(jwe)
	if err != nil {
		t.Fatal(err)
	}
	var m2 map[string]string
	if err := json.Unmarshal([]byte(plain), &m2); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if m2["a"] != "b" {
		t.Errorf("payload: %v", m2)
	}
}
