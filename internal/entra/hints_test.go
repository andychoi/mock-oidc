package entra

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const hintsJSON = `{
  "tenants": [
    {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"]},
    {"tid": "22222222-2222-2222-2222-22222222abcd", "name": "Customer X", "domains": ["customer-x.example"]}
  ],
  "users": [
    {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "email": "jane@corp.example"},
    {"username": "shared", "tid": "11111111-1111-1111-1111-111111111111"},
    {"username": "mfa", "tid": "11111111-1111-1111-1111-111111111111", "error": "interaction_required"},
    {"username": "shared", "tid": "22222222-2222-2222-2222-22222222abcd"},
    {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd", "email": "sam@customer-x.example"}
  ]
}`

// hintAuthorize issues a GET /authorize with extra query parameters.
func hintAuthorize(h *Handler, seg, extra string) (int, string, string) {
	target := "http://mock.test/entra/" + seg + "/oauth2/v2.0/authorize?response_type=code&client_id=app" +
		"&redirect_uri=" + url.QueryEscape("http://app.test/cb") + "&state=st1&scope=openid" + extra
	resp := serve(h, http.MethodGet, target, "")
	return resp.Status, resp.Header.Get("Location"), resp.Body
}

// redirectQuery parses the query of a redirect Location.
func redirectQuery(t *testing.T, loc string) url.Values {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// A hint naming exactly one account skips the picker: this is what lets an RP
// test run headless.
func TestLoginHintAutoIssuesCode(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	for _, hint := range []string{"jane@corp.example", "JANE@CORP.EXAMPLE", "jane"} {
		status, loc, body := hintAuthorize(h, tidA, "&login_hint="+url.QueryEscape(hint))
		if status != http.StatusFound {
			t.Fatalf("login_hint %q: status %d body %s", hint, status, body)
		}
		q := redirectQuery(t, loc)
		if q.Get("code") == "" || q.Get("state") != "st1" {
			t.Errorf("login_hint %q redirect = %v", hint, q)
		}
	}
}

// Two accounts share the username across tenants, so on common the hint is
// ambiguous and a person must choose.
func TestLoginHintAmbiguousShowsPicker(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	status, loc, body := hintAuthorize(h, ScopeCommon, "&login_hint=shared")
	if status != http.StatusOK || loc != "" {
		t.Fatalf("status %d location %q", status, loc)
	}
	if !strings.Contains(body, `value="shared"`) {
		t.Errorf("picker missing the candidates:\n%s", body)
	}
	// On one tenant the same hint is unambiguous again.
	if status, _, _ := hintAuthorize(h, tidA, "&login_hint=shared"); status != http.StatusFound {
		t.Errorf("tenant-scoped hint status %d, want a redirect", status)
	}
}

func TestLoginHintUnknownShowsPickerPrefilled(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	status, _, body := hintAuthorize(h, tidA, "&login_hint="+url.QueryEscape("nobody@corp.example"))
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	// The client's intent is echoed even though nothing matched.
	if !strings.Contains(body, "nobody@corp.example") {
		t.Errorf("picker does not echo the hint:\n%s", body)
	}
	if strings.Contains(body, `class="match"`) {
		t.Error("nothing matched, so no account may be marked")
	}
}

func TestLoginHintMarksTheMatchingAccount(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	// prompt=select_account forces the picker, so the mark is visible.
	status, _, body := hintAuthorize(h, tidA, "&login_hint=jane&prompt=select_account")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if !strings.Contains(body, `class="match" autofocus`) {
		t.Errorf("the hinted account is not marked:\n%s", body)
	}
}

func TestLoginHintRespectsPromptSelectAccountAndLogin(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	for _, prompt := range []string{"select_account", "login", "login consent"} {
		status, loc, _ := hintAuthorize(h, tidA, "&login_hint=jane&prompt="+url.QueryEscape(prompt))
		if status != http.StatusOK || loc != "" {
			t.Errorf("prompt=%q must force the picker, got %d %q", prompt, status, loc)
		}
	}
	// A prompt that does not demand interaction leaves the shortcut alone.
	if status, _, _ := hintAuthorize(h, tidA, "&login_hint=jane&prompt=consent"); status != http.StatusFound {
		t.Errorf("prompt=consent status %d, want the shortcut", status)
	}
}

func TestIgnoreLoginHintForcesPicker(t *testing.T) {
	h := New(mustConfig(t, strings.Replace(hintsJSON, `{
  "tenants"`, `{
  "ignoreLoginHint": true,
  "tenants"`, 1)))
	status, loc, _ := hintAuthorize(h, tidA, "&login_hint=jane")
	if status != http.StatusOK || loc != "" {
		t.Fatalf("status %d location %q, want the picker", status, loc)
	}
}

// A hinted sign-in goes through the same per-account checks as a clicked one.
func TestLoginHintStillAppliesErrorInjection(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	status, loc, _ := hintAuthorize(h, tidA, "&login_hint=mfa")
	if status != http.StatusFound {
		t.Fatalf("status %d", status)
	}
	q := redirectQuery(t, loc)
	if q.Get("error") != "interaction_required" || !strings.Contains(q.Get("error_description"), "AADSTS50076") {
		t.Errorf("redirect = %v, want the injected error", q)
	}
	if q.Get("code") != "" {
		t.Error("an injected error must not also issue a code")
	}
}

func TestLoginHintStillAppliesConsentRequirement(t *testing.T) {
	h := New(mustConfig(t, `{
	  "tenants": [{"tid": "`+tidA+`", "consentRequired": true}],
	  "users": [{"username": "jane", "tid": "`+tidA+`"}]}`))
	_, loc, _ := hintAuthorize(h, tidA, "&login_hint=jane")
	if q := redirectQuery(t, loc); q.Get("error") != "consent_required" {
		t.Errorf("redirect = %v, want consent_required", q)
	}
}

func TestDomainHintNarrowsMultiTenantPicker(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	status, _, body := hintAuthorize(h, ScopeCommon, "&domain_hint=customer-x.example")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if strings.Contains(body, "Corp") || !strings.Contains(body, "Customer X") {
		t.Errorf("domain_hint did not narrow the picker:\n%s", body)
	}
	// Narrowing can make an otherwise ambiguous hint unique.
	if status, loc, _ := hintAuthorize(h, ScopeCommon, "&login_hint=shared&domain_hint=corp.example"); status != http.StatusFound {
		t.Errorf("narrowed hint status %d location %q", status, loc)
	}
}

// A domain_hint no tenant carries is ignored rather than emptying the picker.
func TestDomainHintUnknownIsIgnored(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	status, _, body := hintAuthorize(h, ScopeCommon, "&domain_hint=nowhere.example")
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	if !strings.Contains(body, "Corp") || !strings.Contains(body, "Customer X") {
		t.Errorf("an unusable domain_hint must not hide tenants:\n%s", body)
	}
}

func TestPromptNoneWithoutHintIsInteractionRequired(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	for _, extra := range []string{"", "&login_hint=nobody@corp.example", "&login_hint=shared"} {
		status, loc, body := hintAuthorize(h, ScopeCommon, "&prompt=none"+extra)
		if status != http.StatusFound {
			t.Fatalf("prompt=none%s: status %d body %s", extra, status, body)
		}
		q := redirectQuery(t, loc)
		if q.Get("error") != "interaction_required" || !strings.Contains(q.Get("error_description"), "AADSTS50058") {
			t.Errorf("prompt=none%s redirect = %v", extra, q)
		}
	}
}

func TestPromptNoneWithHintIssuesCode(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	status, loc, body := hintAuthorize(h, tidA, "&prompt=none&login_hint=jane@corp.example")
	if status != http.StatusFound {
		t.Fatalf("status %d body %s", status, body)
	}
	if q := redirectQuery(t, loc); q.Get("code") == "" {
		t.Errorf("redirect = %v, want a code", q)
	}
}

// prompt=none may never render UI, even when the shortcut is switched off.
func TestPromptNoneWithIgnoreLoginHintStillErrors(t *testing.T) {
	h := New(mustConfig(t, strings.Replace(hintsJSON, `{
  "tenants"`, `{
  "ignoreLoginHint": true,
  "tenants"`, 1)))
	status, loc, _ := hintAuthorize(h, tidA, "&prompt=none&login_hint=jane")
	if status != http.StatusFound {
		t.Fatalf("status %d", status)
	}
	if q := redirectQuery(t, loc); q.Get("error") != "interaction_required" {
		t.Errorf("redirect = %v", q)
	}
}

// Hints must not change the picker-submit path, which stays the contract the
// existing suite asserts.
func TestHintsDoNotAffectPickerSubmit(t *testing.T) {
	h := New(mustConfig(t, hintsJSON))
	target := "http://mock.test/entra/" + tidA + "/oauth2/v2.0/authorize?response_type=code&client_id=app" +
		"&redirect_uri=" + url.QueryEscape("http://app.test/cb") + "&state=st1&scope=openid&login_hint=jane"
	resp := serve(h, http.MethodPost, target, "tid="+tidA+"&username=shared")
	if resp.Status != http.StatusFound {
		t.Fatalf("status %d: %s", resp.Status, resp.Body)
	}
	// The posted account wins over the hint.
	code := redirectQuery(t, resp.Header.Get("Location")).Get("code")
	if code == "" {
		t.Fatal("no code")
	}
	stored, ok := h.codes.take(code)
	if !ok || stored.username != "shared" {
		t.Errorf("code was issued for %q, want the posted account", stored.username)
	}
}
