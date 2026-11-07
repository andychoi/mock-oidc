package debugger_test

import (
	"net/url"
	"testing"
)

// A session cookie that fails to decrypt is treated as no session, whatever
// part of the JWE is malformed.
func TestDebuggerIgnoresUndecryptableSessionCookie(t *testing.T) {
	_, base := startServer(t)
	form := url.Values{
		"client_id": {"c"}, "client_secret": {"s"}, "client_auth_method": {"CLIENT_SECRET_BASIC"},
		"scope": {"openid"}, "response_type": {"code"}, "response_mode": {"query"},
		"state": {"1"}, "nonce": {"2"},
	}
	header := "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0"
	for name, jwe := range map[string]string{
		"short iv":  header + "..AAAA.AAAA.AAAAAAAAAAAAAAAAAAAAAA",
		"empty iv":  header + "...AAAA.AAAAAAAAAAAAAAAAAAAAAA",
		"bad tag":   header + "..AAAAAAAAAAAAAAAA.AAAA.AAAA",
		"not a jwe": "garbage",
	} {
		status, hdr, body := do(t, "POST", base+"/oidc/debugger", form.Encode(), "debugger-session="+jwe)
		if status != 302 || hdr.Get("Location") == "" {
			t.Errorf("%s: status %d, want 302 redirect to authorize; body %.200s", name, status, body)
		}
	}
}
