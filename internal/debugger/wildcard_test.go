package debugger_test

import (
	"net/url"
	"strings"
	"testing"

	mockoidc "github.com/andychoi/mock-oidc"
	"github.com/andychoi/mock-oidc/internal/config"
)

// A wildcard bind must still give the debugger a connectable address for its
// server-to-server token exchange.
func TestDebuggerExchangeOnWildcardBind(t *testing.T) {
	cfg, err := config.ParseJSON([]byte(`{"interactiveLogin": false}`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := mockoidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(":0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	base := s.URL()

	form := url.Values{
		"client_id": {"c"}, "client_secret": {"s"}, "client_auth_method": {"CLIENT_SECRET_BASIC"},
		"scope": {"openid"}, "response_type": {"code"}, "response_mode": {"query"},
		"state": {"1"}, "nonce": {"2"},
	}
	_, hdr, _ := do(t, "POST", base+"/oidc/debugger", form.Encode(), "")
	cookie := strings.SplitN(hdr.Get("Set-Cookie"), ";", 2)[0]
	_, hdr, _ = do(t, "GET", hdr.Get("Location"), "", "")
	status, _, body := do(t, "GET", hdr.Get("Location"), "", cookie)
	if status != 200 || !strings.Contains(body, "access_token") {
		t.Errorf("debugger callback on %s: %d %.300s", base, status, body)
	}
}
