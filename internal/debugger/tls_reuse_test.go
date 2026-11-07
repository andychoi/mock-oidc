package debugger_test

import (
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	mockoidc "github.com/andychoi/mock-oidc"
	"github.com/andychoi/mock-oidc/internal/config"
)

// Each TLS token exchange must reuse the debugger's connection pool rather
// than leave a fresh keep-alive connection open on the server.
func TestDebuggerOverTLSDoesNotAccumulateConnections(t *testing.T) {
	cfg, err := config.ParseJSON([]byte(`{"interactiveLogin": false, "httpServer": {"type": "NettyWrapper", "ssl": {}}}`))
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

	exchange := func() {
		t.Helper()
		form := url.Values{
			"client_id": {"tls-client"}, "client_secret": {"s"}, "client_auth_method": {"CLIENT_SECRET_BASIC"},
			"scope": {"openid"}, "response_type": {"code"}, "response_mode": {"query"},
			"state": {"1"}, "nonce": {"2"},
		}
		_, hdr, _ := do(t, "POST", base+"/oidc/debugger", form.Encode(), "")
		cookie := strings.SplitN(hdr.Get("Set-Cookie"), ";", 2)[0]
		_, hdr, _ = do(t, "GET", hdr.Get("Location"), "", "")
		status, _, body := do(t, "GET", hdr.Get("Location"), "", cookie)
		if status != 200 || !strings.Contains(body, "access_token") {
			t.Fatalf("debugger callback: %d %.300s", status, body)
		}
	}

	exchange()
	before := settledGoroutines()
	const rounds = 10
	for i := 0; i < rounds; i++ {
		exchange()
	}
	if after := settledGoroutines(); after-before >= rounds {
		t.Errorf("goroutines grew from %d to %d over %d exchanges: connections are not reused", before, after, rounds)
	}
}

func settledGoroutines() int {
	n := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		time.Sleep(10 * time.Millisecond)
		m := runtime.NumGoroutine()
		if m == n {
			return n
		}
		n = m
	}
	return n
}
