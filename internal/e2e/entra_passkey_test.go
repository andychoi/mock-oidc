package e2e

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const entraPasskeyConfig = `{
  "interactiveLogin": true,
  "entra": {
    "tenants": [{"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"]}],
    "users": [
      {"username": "passkey", "tid": "11111111-1111-1111-1111-111111111111", "name": "Passkey MFA",
       "mfa": "passkey", "amr": ["fido", "mfa"]}
    ]
  }
}`

// The browser path: picker submit, passkey page, approve, then a token whose
// amr is the account's configured one.
func TestEntraPasskeyStep(t *testing.T) {
	_, base := startServer(t, entraPasskeyConfig)
	authorize := entraAuthorizeURL(base, tidCorp, "iam", "")
	post := func(action string) (int, http.Header, string) {
		form := url.Values{"action": {action}, "tid": {tidCorp}, "username": {"passkey"}}.Encode()
		return do(t, http.MethodPost, authorize, form, formHeaders)
	}

	status, _, body := post("signin")
	if status != http.StatusOK || !strings.Contains(body, "Verify your identity with a passkey") {
		t.Fatalf("signin: status %d body %s", status, body)
	}

	status, hdr, _ := post("passkey-deny")
	if q := redirectValues(t, hdr); status != http.StatusFound || q.Get("error") != "access_denied" || q.Get("state") != "st1" {
		t.Errorf("deny: status %d redirect %v", status, q)
	}

	status, hdr, body = post("passkey-approve")
	q := redirectValues(t, hdr)
	if status != http.StatusFound || q.Get("code") == "" {
		t.Fatalf("approve: status %d redirect %v body %s", status, q, body)
	}
	status, tok, body := entraRedeem(t, base, tidCorp, "iam", q.Get("code"), "", nil)
	if status != http.StatusOK {
		t.Fatalf("token status %d: %s", status, body)
	}
	c := verifyEntraJWT(t, base, tok["id_token"].(string))
	if !reflect.DeepEqual(strList(c["amr"]), []string{"fido", "mfa"}) {
		t.Errorf("amr = %v", c["amr"])
	}
}

func redirectValues(t *testing.T, hdr http.Header) url.Values {
	t.Helper()
	u, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}
