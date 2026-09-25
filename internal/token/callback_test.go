package token

import (
	"net/url"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/oauth2"
)

func mappingReq(form map[string]string, grant, clientID string) *oauth2.TokenRequest {
	f := url.Values{}
	for k, v := range form {
		f.Set(k, v)
	}
	tr := &oauth2.TokenRequest{GrantType: grant, ClientID: clientID, Form: f}
	if s, ok := form["scope"]; ok {
		tr.Scope = s
		tr.ScopeList = strings.Fields(s)
	}
	return tr
}

func TestMappingExactAndStarMatch(t *testing.T) {
	cb := &MappingCallback{IssuerIDValue: "oidc", Expiry: 3600, Mappings: []*Mapping{
		{RequestParam: "grant_type", Match: "authorization_code", Claims: map[string]any{"tid": "custom-tenant"}},
		{RequestParam: "grant_type", Match: "*", Claims: map[string]any{"tid": "fallback"}},
	}}
	// exact match wins over later star
	claims := cb.AddClaims(mappingReq(map[string]string{"grant_type": "authorization_code"}, "authorization_code", "cid"))
	if claims["tid"] != "custom-tenant" {
		t.Errorf("tid = %v, want custom-tenant (first match wins)", claims["tid"])
	}
	// star matches other grants
	claims = cb.AddClaims(mappingReq(map[string]string{"grant_type": "password"}, "password", "cid"))
	if claims["tid"] != "fallback" {
		t.Errorf("tid = %v, want fallback (star)", claims["tid"])
	}
}

func TestMappingRegexMatch(t *testing.T) {
	cb := &MappingCallback{IssuerIDValue: "oidc", Mappings: []*Mapping{
		{RequestParam: "username", Match: `^admin.*$`, Claims: map[string]any{"role": "admin"}},
	}}
	if cb.AddClaims(mappingReq(map[string]string{"username": "admin-bob"}, "password", "c"))["role"] != "admin" {
		t.Errorf("regex should match entire value")
	}
	if _, ok := cb.AddClaims(mappingReq(map[string]string{"username": "notadmin"}, "password", "c"))["role"]; ok {
		t.Errorf("regex must match the entire value, not a substring")
	}
	// invalid regex falls back to exact matching only
	bad := &MappingCallback{IssuerIDValue: "oidc", Mappings: []*Mapping{
		{RequestParam: "username", Match: "[invalid", Claims: map[string]any{"role": "x"}},
	}}
	if _, ok := bad.AddClaims(mappingReq(map[string]string{"username": "[invalid"}, "password", "c"))["role"]; !ok {
		t.Errorf("exact fallback should match the literal string")
	}
}

func TestMappingTemplating(t *testing.T) {
	cb := &MappingCallback{IssuerIDValue: "oidc", Mappings: []*Mapping{
		{RequestParam: "grant_type", Match: "*", Claims: map[string]any{
			"cid":  "${clientId}",
			"who":  "${username}",
			"keep": "${unknown}",
		}},
	}}
	claims := cb.AddClaims(mappingReq(map[string]string{"grant_type": "password", "username": "alice"}, "password", "my-app"))
	if claims["cid"] != "my-app" {
		t.Errorf("clientId templating: %v", claims["cid"])
	}
	if claims["who"] != "alice" {
		t.Errorf("form param templating: %v", claims["who"])
	}
	if claims["keep"] != "${unknown}" {
		t.Errorf("unresolved placeholders should stay: %v", claims["keep"])
	}
}

func TestMappingSubjectMatchWithExtraParams(t *testing.T) {
	cb := &MappingCallback{IssuerIDValue: "oidc", Mappings: []*Mapping{
		{RequestParam: "subject", Match: "alice", Claims: map[string]any{"acr": "loa3"}},
	}}
	wrapped := cb.WithExtraMatchParams(map[string]string{"subject": "alice"})
	claims := wrapped.AddClaims(mappingReq(map[string]string{"grant_type": "authorization_code"}, "authorization_code", "c"))
	if claims["acr"] != "loa3" {
		t.Errorf("subject extra-match-param should drive mapping: %v", claims)
	}
	// form params take precedence over extra match params on the same key
	wrapped2 := cb.WithExtraMatchParams(map[string]string{"subject": "bob"})
	if _, ok := wrapped2.AddClaims(mappingReq(map[string]string{"subject": "carol"}, "password", "c"))["acr"]; ok {
		t.Errorf("form param must override extra match param")
	}
}

func TestDefaultCallbackAudiencePrecedence(t *testing.T) {
	withAud := &DefaultCallback{Issuer: "oidc", AudienceValue: []string{"explicit"}}
	req := &oauth2.TokenRequest{GrantType: oauth2.GrantPassword, ClientID: "c", Scope: "openid read", ScopeList: []string{"openid", "read"}, Audience: []string{"from-exchange"}}
	if got := withAud.Audience(req); len(got) != 1 || got[0] != "explicit" {
		t.Errorf("explicit audience should win: %v", got)
	}
	cb := NewDefaultCallback("oidc")
	if got := cb.Audience(req); len(got) != 1 || got[0] != "from-exchange" {
		t.Errorf("token exchange aud param should win: %v", got)
	}
	noExchange := &oauth2.TokenRequest{GrantType: oauth2.GrantPassword, ClientID: "c", Scope: "openid read", ScopeList: []string{"openid", "read"}}
	if got := cb.Audience(noExchange); len(got) != 1 || got[0] != "read" {
		t.Errorf("non-OIDC scopes should be audience: %v", got)
	}
	onlyOIDC := &oauth2.TokenRequest{GrantType: oauth2.GrantPassword, ClientID: "c", Scope: "openid", ScopeList: []string{"openid"}}
	if got := cb.Audience(onlyOIDC); len(got) != 0 {
		t.Errorf("all-OIDC scope yields empty audience (scope param present): %v", got)
	}
	noScope := &oauth2.TokenRequest{GrantType: oauth2.GrantPassword, ClientID: "c"}
	if got := cb.Audience(noScope); len(got) != 1 || got[0] != "default" {
		t.Errorf("no scope => default audience: %v", got)
	}
}

func TestDefaultCallbackAutoClaims(t *testing.T) {
	cb := NewDefaultCallback("oidc")
	authCode := &oauth2.TokenRequest{GrantType: oauth2.GrantAuthorizationCode, ClientID: "my-app"}
	claims := cb.AddClaims(authCode)
	if claims["tid"] != "oidc" || claims["azp"] != "my-app" {
		t.Errorf("tid/azp auto-claims: %v", claims)
	}
	password := &oauth2.TokenRequest{GrantType: oauth2.GrantPassword, ClientID: "my-app"}
	if _, ok := cb.AddClaims(password)["azp"]; ok {
		t.Errorf("azp only for authorization_code grant")
	}
	// user claims can override tid via DefaultCallback.Claims? No: claims map is
	// applied over tid, so explicit claims win.
	withClaims := &DefaultCallback{Issuer: "oidc", Claims: map[string]any{"tid": "custom"}, Expiry: 100}
	if got := withClaims.AddClaims(password)["tid"]; got != "custom" {
		t.Errorf("explicit claims should override default tid: %v", got)
	}
}
