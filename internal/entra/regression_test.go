package entra

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	tidOne = "11111111-1111-1111-1111-111111111111"
	tidTwo = "22222222-2222-2222-2222-222222222222"
)

// A code issued on organizations can be redeemed there even after its tenant
// is gone, so every way of removing the account is reachable.
func TestRedeemAfterAccountRemovedIsInvalidGrant(t *testing.T) {
	const cfg = `{
	  "tenants": [{"tid": "` + tidOne + `"}, {"tid": "` + tidTwo + `"}],
	  "users": [{"username": "jane", "tid": "` + tidOne + `"}]
	}`
	cases := map[string]struct {
		username string
		remove   func(h *Handler) error
	}{
		"user deleted":             {"jane", func(h *Handler) error { return h.AdminDeleteUser(tidOne, "jane") }},
		"tenant deleted":           {"jane", func(h *Handler) error { return h.AdminDeleteTenant(tidOne) }},
		"reset drops runtime user": {"temp", func(h *Handler) error { h.AdminResetToSeed(); return nil }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := New(mustConfig(t, cfg))
			if err := h.AdminCreateUser(User{Username: "temp", TID: tidOne}); err != nil {
				t.Fatal(err)
			}
			base := "http://mock.test/entra/organizations/oauth2/v2.0/"
			signin := serve(h, http.MethodPost, base+"authorize?response_type=code&client_id=app"+
				"&redirect_uri=http%3A%2F%2Fapp.test%2Fcb&scope=openid&state=s",
				"tid="+tidOne+"&username="+tc.username)
			loc, err := url.Parse(signin.Header.Get("Location"))
			code := ""
			if err == nil {
				code = loc.Query().Get("code")
			}
			if signin.Status != http.StatusFound || code == "" {
				t.Fatalf("sign-in: %d %s", signin.Status, signin.Body)
			}
			if err := tc.remove(h); err != nil {
				t.Fatal(err)
			}
			resp := serve(h, http.MethodPost, base+"token", "grant_type=authorization_code&client_id=app&code="+
				url.QueryEscape(code)+"&redirect_uri="+url.QueryEscape("http://app.test/cb"))
			if resp.Status != http.StatusBadRequest || !strings.Contains(resp.Body, `"invalid_grant"`) {
				t.Fatalf("redeem = %d %s, want 400 invalid_grant", resp.Status, resp.Body)
			}
		})
	}
}
