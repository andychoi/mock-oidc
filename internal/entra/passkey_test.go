package entra

import (
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/routing"
)

const passkeyJSON = `{
  "tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"]}],
  "users": [
    {"username": "passkey", "tid": "11111111-1111-1111-1111-111111111111", "name": "Passkey MFA",
     "email": "passkey@corp.example", "mfa": "passkey", "amr": ["fido", "mfa"]},
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111"},
    {"username": "blockedpk", "tid": "11111111-1111-1111-1111-111111111111", "mfa": "passkey", "error": "access_denied"}
  ]
}`

func passkeyPost(h *Handler, action, username string) routing.Response {
	form := url.Values{"tid": {tidA}, "username": {username}}
	if action != "" {
		form.Set("action", action)
	}
	return serve(h, http.MethodPost, unitAuthorize, form.Encode())
}

func TestPasskeyUserGetsPasskeyPage(t *testing.T) {
	h := New(mustConfig(t, passkeyJSON))
	for _, action := range []string{"signin", ""} {
		resp := passkeyPost(h, action, "passkey")
		if resp.Status != http.StatusOK || resp.Header.Get("Location") != "" {
			t.Fatalf("action %q: status %d location %q", action, resp.Status, resp.Header.Get("Location"))
		}
		for _, want := range []string{"Verify your identity with a passkey", "Passkey MFA",
			`value="passkey-approve"`, `value="passkey-deny"`, "Use passkey", "Cancel"} {
			if !strings.Contains(resp.Body, want) {
				t.Errorf("action %q: passkey page lacks %q:\n%s", action, want, resp.Body)
			}
		}
	}
}

func TestPasskeyApproveIssuesCodeWithConfiguredAMR(t *testing.T) {
	h := New(mustConfig(t, passkeyJSON))
	resp := passkeyPost(h, actionPasskeyApprove, "passkey")
	if resp.Status != http.StatusFound {
		t.Fatalf("approve status %d body %s", resp.Status, resp.Body)
	}
	q := redirectQuery(t, resp.Header.Get("Location"))
	if q.Get("code") == "" || q.Get("state") != "s" {
		t.Fatalf("approve redirect = %v", q)
	}
	tok := redeem(h, q.Get("code"))
	if tok.Status != http.StatusOK {
		t.Fatalf("redeem %d %s", tok.Status, tok.Body)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(tok.Body), &body); err != nil {
		t.Fatal(err)
	}
	idToken, _ := body["id_token"].(string)
	_, claims := verifyWithJWKS(t, h.keys.JWKS(), idToken)
	if !reflect.DeepEqual(claims["amr"], []any{"fido", "mfa"}) {
		t.Errorf("amr = %v, want [fido mfa]", claims["amr"])
	}
}

func TestPasskeyDenyRedirectsAccessDenied(t *testing.T) {
	h := New(mustConfig(t, passkeyJSON))
	resp := passkeyPost(h, actionPasskeyDeny, "passkey")
	if resp.Status != http.StatusFound {
		t.Fatalf("deny status %d", resp.Status)
	}
	q := redirectQuery(t, resp.Header.Get("Location"))
	if q.Get("error") != "access_denied" || q.Get("state") != "s" || q.Get("code") != "" ||
		!strings.Contains(q.Get("error_description"), "AADSTS500121") {
		t.Errorf("deny redirect = %v", q)
	}
}

// Approve is the code path itself, so posting it for an account without MFA
// just signs that account in.
func TestPasskeyApproveForUserWithoutMFAIssuesCode(t *testing.T) {
	h := New(mustConfig(t, passkeyJSON))
	resp := passkeyPost(h, actionPasskeyApprove, "jane")
	if q := redirectQuery(t, resp.Header.Get("Location")); resp.Status != http.StatusFound || q.Get("code") == "" {
		t.Errorf("approve for jane: %d %v", resp.Status, q)
	}
	if resp := passkeyPost(h, "signin", "jane"); resp.Status != http.StatusFound {
		t.Errorf("jane signin status %d, want a code redirect without a passkey page", resp.Status)
	}
}

func TestPasskeyInjectedErrorWins(t *testing.T) {
	h := New(mustConfig(t, passkeyJSON))
	resp := passkeyPost(h, "signin", "blockedpk")
	if q := redirectQuery(t, resp.Header.Get("Location")); resp.Status != http.StatusFound || q.Get("error") != "access_denied" ||
		!strings.Contains(q.Get("error_description"), "AADSTS50105") {
		t.Errorf("blockedpk signin: %d %v", resp.Status, q)
	}
}

// A resolved login_hint stands in for a session that already passed MFA.
func TestPasskeyLoginHintIssuesCodeDirectly(t *testing.T) {
	h := New(mustConfig(t, passkeyJSON))
	for _, extra := range []string{"&login_hint=passkey", "&login_hint=passkey&prompt=none"} {
		status, loc, body := hintAuthorize(h, tidA, extra)
		if status != http.StatusFound || redirectQuery(t, loc).Get("code") == "" {
			t.Errorf("%s: status %d location %q body %s", extra, status, loc, body)
		}
	}
}

func TestPasskeyPromptLoginShowsPicker(t *testing.T) {
	h := New(mustConfig(t, passkeyJSON))
	status, loc, body := hintAuthorize(h, tidA, "&login_hint=passkey&prompt=login")
	if status != http.StatusOK || loc != "" || !strings.Contains(body, `value="signin"`) {
		t.Errorf("prompt=login: status %d location %q body %s", status, loc, body)
	}
}

func TestParseConfigRejectsUnknownMFA(t *testing.T) {
	_, err := ParseConfig([]byte(strings.Replace(passkeyJSON, `"mfa": "passkey", "amr"`, `"mfa": "sms", "amr"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "mfa must be") {
		t.Errorf("mfa sms: err = %v", err)
	}
}
