package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const (
	tidCorp = "11111111-1111-1111-1111-111111111111"
	tidCust = "22222222-2222-2222-2222-22222222abcd"
)

const entraConfig = `{
  "interactiveLogin": true,
  "entra": {
    "tenants": [
      {"tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"]},
      {"tid": "22222222-2222-2222-2222-22222222abcd", "name": "Customer X", "domains": ["customer-x.example"],
       "groupClaimFormat": "object_id", "consentRequired": true, "groupLimit": 3}
    ],
    "consents": [
      {"clientId": "iam", "tid": "11111111-1111-1111-1111-111111111111"},
      {"clientId": "iam", "tid": "22222222-2222-2222-2222-22222222abcd"}
    ],
    "users": [
      {"username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Kim",
       "email": "jane@corp.example", "emailVerified": true, "groups": ["AMS Engineers", "PMO"],
       "amr": ["pwd", "mfa"], "admin": true},
      {"username": "unassigned", "tid": "11111111-1111-1111-1111-111111111111", "error": "access_denied"},
      {"username": "disabled", "tid": "11111111-1111-1111-1111-111111111111", "error": "invalid_grant"},
      {"username": "sam", "tid": "22222222-2222-2222-2222-22222222abcd", "name": "Sam Lee",
       "email": "sam@customer-x.example", "groups": ["G1", "G2"]},
      {"username": "many", "tid": "22222222-2222-2222-2222-22222222abcd", "groups": ["G1", "G2", "G3", "G4"]},
      {"username": "custadmin", "tid": "22222222-2222-2222-2222-22222222abcd", "admin": true},
      {"username": "mfa", "tid": "22222222-2222-2222-2222-22222222abcd", "error": "interaction_required"}
    ]
  }
}`

func entraGetJSON(t *testing.T, rawURL string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	status, _, body := do(t, http.MethodGet, rawURL, "", headers)
	var m map[string]any
	if status == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("decode %s: %v\n%s", rawURL, err, body)
		}
	}
	return status, m
}

func TestEntraDiscoveryPerTenant(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil)
	if status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	want := map[string]string{
		"issuer":                 base + "/entra/" + tidCorp + "/v2.0",
		"authorization_endpoint": base + "/entra/" + tidCorp + "/oauth2/v2.0/authorize",
		"token_endpoint":         base + "/entra/" + tidCorp + "/oauth2/v2.0/token",
		"jwks_uri":               base + "/entra/" + tidCorp + "/discovery/v2.0/keys",
		"end_session_endpoint":   base + "/entra/" + tidCorp + "/oauth2/v2.0/logout",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %v, want %v", k, doc[k], v)
		}
	}
	if _, ok := doc["userinfo_endpoint"]; ok {
		t.Error("userinfo_endpoint must be absent")
	}
}

func TestEntraDiscoveryOrganizationsTemplate(t *testing.T) {
	_, base := startServer(t, entraConfig)
	for _, seg := range []string{"organizations", "common"} {
		_, doc := entraGetJSON(t, base+"/entra/"+seg+"/v2.0/.well-known/openid-configuration", nil)
		if doc["issuer"] != base+"/entra/{tenantid}/v2.0" {
			t.Errorf("%s issuer = %v", seg, doc["issuer"])
		}
		if doc["authorization_endpoint"] != base+"/entra/"+seg+"/oauth2/v2.0/authorize" {
			t.Errorf("%s authorization_endpoint = %v", seg, doc["authorization_endpoint"])
		}
	}
}

func TestEntraTenantPathCaseInsensitive(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, doc := entraGetJSON(t, base+"/entra/"+strings.ToUpper(tidCust)+"/v2.0/.well-known/openid-configuration", nil)
	if status != http.StatusOK || doc["issuer"] != base+"/entra/"+tidCust+"/v2.0" {
		t.Fatalf("status %d issuer %v", status, doc["issuer"])
	}
}

func TestEntraUnknownTenant(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, _, body := do(t, http.MethodGet, base+"/entra/99999999-9999-9999-9999-999999999999/v2.0/.well-known/openid-configuration", "", nil)
	if status != http.StatusBadRequest || !strings.Contains(body, "aadsts90002") {
		t.Fatalf("status %d body %s", status, body)
	}
}

func TestEntraKeysSharedAcrossTenants(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, _, corp := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/discovery/v2.0/keys", "", nil)
	_, _, cust := do(t, http.MethodGet, base+"/entra/"+tidCust+"/discovery/v2.0/keys", "", nil)
	_, _, common := do(t, http.MethodGet, base+"/entra/common/discovery/v2.0/keys", "", nil)
	if corp != cust || corp != common || !strings.Contains(corp, `"entra-1"`) {
		t.Fatalf("key sets differ or missing kid:\n%s\n%s\n%s", corp, cust, common)
	}
}

func TestEntraDiscoveryHonorsForwardedHeaders(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration",
		map[string]string{"x-forwarded-proto": "https", "x-forwarded-port": "443"})
	if doc["issuer"] != "https://127.0.0.1/entra/"+tidCorp+"/v2.0" {
		t.Fatalf("issuer = %v", doc["issuer"])
	}
}

func TestEntraLogoutAndOptions(t *testing.T) {
	_, base := startServer(t, entraConfig)
	status, hdr, _ := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/oauth2/v2.0/logout?post_logout_redirect_uri=http%3A%2F%2Fapp.test%2Fbye&state=s1", "", nil)
	if status != http.StatusFound || hdr.Get("Location") != "http://app.test/bye?state=s1" {
		t.Fatalf("logout status %d location %q", status, hdr.Get("Location"))
	}
	status, _, _ = do(t, http.MethodOptions, base+"/entra/"+tidCorp+"/oauth2/v2.0/token", "", map[string]string{"Origin": "http://app.test"})
	if status != http.StatusNoContent {
		t.Fatalf("OPTIONS status %d", status)
	}
}

func TestEntraBuiltinsNotShadowed(t *testing.T) {
	_, base := startServer(t, entraConfig)
	// the built-in issuer keeps working next to Entra mode
	_, doc := entraGetJSON(t, base+"/oidc/.well-known/openid-configuration", nil)
	if doc["issuer"] != base+"/oidc" {
		t.Fatalf("built-in issuer = %v", doc["issuer"])
	}
	// a path under /entra that ends in a built-in suffix is Entra's (404), not the built-in GET /token (405)
	status, _, _ := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/token", "", nil)
	if status != http.StatusNotFound {
		t.Fatalf("GET /entra/{tid}/token status %d, want 404", status)
	}
}

func TestEntraRoutesAbsentWhenDisabled(t *testing.T) {
	_, base := startServer(t, repoLikeConfig)
	_, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil)
	if _, entra := doc["tenant_region_scope"]; entra {
		t.Fatal("Entra discovery served although Entra mode is off")
	}
}
