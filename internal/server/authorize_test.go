package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func formPostAuthorizePath(redirectURI string) string {
	q := "response_type=code&client_id=x&scope=openid&response_mode=form_post&state=s&redirect_uri=" + url.QueryEscape(redirectURI)
	return "/default/authorize?" + q
}

func TestFormPostRefusesNonHTTPRedirectURI(t *testing.T) {
	ts := newAdminServer(t, `{"interactiveLogin": false}`)
	for _, uri := range []string{
		"javascript:alert(1)",
		" javascript:alert(1)",
		"JaVaScRiPt:alert(1)",
		"data:text/html,<script>alert(1)</script>",
	} {
		status, _, body := adminDo(t, ts, http.MethodPost, formPostAuthorizePath(uri), "username=u&claims=")
		if status != http.StatusBadRequest || !strings.Contains(body, "invalid_request") {
			t.Errorf("redirect_uri %q: status %d, want 400 invalid_request; body %.200s", uri, status, body)
		}
		if strings.Contains(strings.ToLower(body), "<form") {
			t.Errorf("redirect_uri %q: rendered a form: %.200s", uri, body)
		}
	}
}

func TestFormPostRendersHTTPRedirectURI(t *testing.T) {
	ts := newAdminServer(t, `{"interactiveLogin": false}`)
	for _, uri := range []string{"http://localhost/cb", "https://app.test/cb?x=1"} {
		status, _, body := adminDo(t, ts, http.MethodPost, formPostAuthorizePath(uri), "username=u&claims=")
		want := `action="` + strings.ReplaceAll(uri, "&", "&amp;") + `"`
		if status != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("redirect_uri %q: status %d, want 200 with %s; body %.300s", uri, status, want, body)
		}
	}
}
