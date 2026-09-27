package entra

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// The unit tenant requires consent and seeds it for client "app", so every
// sign-in exercises the consents.Has read path.
const unitConfig = `{
  "tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "consentRequired": true}],
  "consents": [{"clientId": "app", "tid": "11111111-1111-1111-1111-111111111111"}],
  "users": [{"username": "jane", "tid": "11111111-1111-1111-1111-111111111111"}]
}`

func mustConfig(t *testing.T, js string) *Config {
	t.Helper()
	c, err := ParseConfig([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// serve runs one request through the handler, like the router would.
func serve(h *Handler, method, target, form string) routing.Response {
	r := httptest.NewRequest(method, target, strings.NewReader(form))
	if form != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req, err := oauth2.FromHTTPRequest(r)
	if err != nil {
		panic(err)
	}
	return h.Handle(req)
}

const unitAuthorize = "http://mock.test/entra/11111111-1111-1111-1111-111111111111/oauth2/v2.0/authorize" +
	"?response_type=code&client_id=app&redirect_uri=http%3A%2F%2Fapp.test%2Fcb&scope=openid&state=s"

// signIn posts the picker form and returns the issued code (or "" on failure).
func signIn(h *Handler, username string) string {
	resp := serve(h, http.MethodPost, unitAuthorize, "tid=11111111-1111-1111-1111-111111111111&username="+username)
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.Status != http.StatusFound || err != nil {
		return ""
	}
	return loc.Query().Get("code")
}

func redeem(h *Handler, code string) routing.Response {
	form := "grant_type=authorization_code&client_id=app&code=" + url.QueryEscape(code) +
		"&redirect_uri=" + url.QueryEscape("http://app.test/cb")
	return serve(h, http.MethodPost, "http://mock.test/entra/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token", form)
}

func TestCodeExpiresAfterTenMinutes(t *testing.T) {
	now := time.Unix(1790000000, 0)
	h := New(mustConfig(t, unitConfig), WithClock(func() time.Time { return now }))
	code := signIn(h, "jane")
	if code == "" {
		t.Fatal("sign-in failed")
	}
	now = now.Add(11 * time.Minute)
	resp := redeem(h, code)
	if resp.Status != http.StatusBadRequest || !strings.Contains(resp.Body, "aadsts70008") {
		t.Fatalf("status %d body %s", resp.Status, resp.Body)
	}
}

func TestPutPurgesExpiredCodes(t *testing.T) {
	now := time.Unix(1790000000, 0)
	h := New(mustConfig(t, unitConfig), WithClock(func() time.Time { return now }))
	stale := signIn(h, "jane")
	if stale == "" {
		t.Fatal("sign-in failed")
	}
	now = now.Add(11 * time.Minute)
	if signIn(h, "jane") == "" { // put must sweep the expired entry
		t.Fatal("second sign-in failed")
	}
	h.codes.mu.Lock()
	_, ok := h.codes.codes[stale]
	n := len(h.codes.codes)
	h.codes.mu.Unlock()
	if ok || n != 1 {
		t.Fatalf("expired code still stored (entries=%d, found=%v); put must purge expired entries", n, ok)
	}
}

func TestConcurrentSignInsRotationAndConsent(t *testing.T) {
	h := New(mustConfig(t, unitConfig))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(4)
		go func() {
			defer wg.Done()
			code := signIn(h, "jane")
			if resp := redeem(h, code); code == "" || resp.Status != http.StatusOK {
				t.Errorf("sign-in/redeem failed: code=%q status=%d", code, resp.Status)
			}
		}()
		go func() {
			defer wg.Done()
			serve(h, http.MethodPost, "http://mock.test/entra/_entra/rotate-keys", "")
		}()
		go func() {
			defer wg.Done()
			h.consents.Grant("app", "11111111-1111-1111-1111-111111111111")
			serve(h, http.MethodGet, "http://mock.test/entra/_entra/consents", "")
		}()
		go func() {
			defer wg.Done()
			// Reset replaces the consents map while sign-ins read it.
			serve(h, http.MethodPost, "http://mock.test/entra/_entra/reset", "")
		}()
	}
	wg.Wait()
}
