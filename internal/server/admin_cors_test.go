package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func send(t *testing.T, ts *httptest.Server, method, path, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

// TestAdminRefusesCrossOrigin drives the admin surface the way a foreign web
// page in the developer's browser could, and checks the navikt paths keep
// their CORS behavior.
func TestAdminRefusesCrossOrigin(t *testing.T) {
	ts := newAdminServer(t, adminEntraConfig)
	const evil = "https://evil.test"

	resp, _ := send(t, ts, http.MethodOptions, "/default/token", "", map[string]string{
		"Origin": evil, "Access-Control-Request-Method": "POST",
	})
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != evil {
		t.Errorf("navikt preflight: Access-Control-Allow-Origin %q, want %q", got, evil)
	}

	crossOrigin := []struct {
		method, path string
		hdr          map[string]string
	}{
		{http.MethodOptions, "/admin/mcp", map[string]string{
			"Origin": evil, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type",
		}},
		{http.MethodGet, "/admin/api/settings", map[string]string{"Origin": evil}},
	}
	for _, c := range crossOrigin {
		resp, _ := send(t, ts, c.method, c.path, "", c.hdr)
		for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
			if got := resp.Header.Get(h); got != "" {
				t.Errorf("%s %s: %s %q, want none", c.method, c.path, h, got)
			}
		}
	}

	resp, b := send(t, ts, http.MethodPost, "/admin/api/settings", `{"name":"interactiveLogin","value":false}`,
		map[string]string{"Origin": evil, "Content-Type": "text/plain"})
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain settings POST: status %d %s, want 415", resp.StatusCode, b)
	}
	resp, b = send(t, ts, http.MethodPost, "/admin/api/entra/rotate-keys", "", map[string]string{"Origin": evil})
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("browser POST without Content-Type: status %d %s, want 415", resp.StatusCode, b)
	}

	if _, b := send(t, ts, http.MethodGet, "/admin/api/settings", "", nil); !strings.Contains(b, `"interactiveLogin" : true`) {
		t.Errorf("refused POST changed settings: %s", b)
	}
	if _, b := send(t, ts, http.MethodGet, "/admin/api/entra", "", nil); !strings.Contains(b, `"activeKid" : "entra-1"`) {
		t.Errorf("refused POST rotated keys: %s", b)
	}

	resp, b = send(t, ts, http.MethodPost, "/admin/api/settings", `{"name":"rotateRefreshToken","value":true}`,
		map[string]string{"Origin": ts.URL, "Content-Type": "application/json; charset=utf-8"})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("admin UI JSON POST: status %d %s, want 200", resp.StatusCode, b)
	}
}
