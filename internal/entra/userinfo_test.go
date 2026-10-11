package entra

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// callUserInfo runs a UserInfo request through the full handler.
func callUserInfo(t *testing.T, h *Handler, method, bearer string) (routing.Response, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, "http://mock.test/entra/graph/oidc/userinfo", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	req, err := oauth2.FromHTTPRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	resp := h.Handle(req)
	var m map[string]any
	if resp.Body != "" {
		if err := json.Unmarshal([]byte(resp.Body), &m); err != nil {
			t.Fatalf("userinfo body is not JSON: %q", resp.Body)
		}
	}
	return resp, m
}

func TestUserInfoClaims(t *testing.T) {
	h := graphHandler(t)
	at := graphToken(t, h, tidA, "jane")
	resp, body := callUserInfo(t, h, http.MethodGet, at)
	if resp.Status != http.StatusOK {
		t.Fatalf("status %d: %v", resp.Status, body)
	}
	jane := h.conf().User(tidA, "jane")
	want := map[string]any{
		"sub": PairwiseSub("app", jane.OID), "oid": jane.OID, "tid": tidA,
		"name": "Jane Kim", "preferred_username": "jane@corp.example",
		"given_name": "Jane", "family_name": "Kim", "email": "jane@corp.example",
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v", k, body[k], v)
		}
	}
	// This is the OIDC shape, not the Graph one: /v1.0/me owns displayName.
	for _, absent := range []string{"displayName", "userPrincipalName", "mail", "@odata.context"} {
		if _, has := body[absent]; has {
			t.Errorf("%s belongs to the Graph user shape, not UserInfo", absent)
		}
	}
}

func TestUserInfoOmitsUnsetClaims(t *testing.T) {
	h := graphHandler(t)
	_, body := callUserInfo(t, h, http.MethodGet, graphToken(t, h, tidA, "minimal"))
	for _, absent := range []string{"given_name", "family_name", "email"} {
		if _, has := body[absent]; has {
			t.Errorf("%s must be omitted when unset, got %v", absent, body[absent])
		}
	}
	if body["sub"] == nil || body["oid"] == nil || body["tid"] != tidA {
		t.Errorf("the core claims must always be present: %v", body)
	}
}

func TestUserInfoPostMatchesGet(t *testing.T) {
	h := graphHandler(t)
	at := graphToken(t, h, tidA, "jane")
	getResp, get := callUserInfo(t, h, http.MethodGet, at)
	postResp, post := callUserInfo(t, h, http.MethodPost, at)
	if getResp.Status != postResp.Status || getResp.Body != postResp.Body {
		t.Errorf("POST differs from GET:\n%v\n%v", get, post)
	}
}

func TestUserInfoNoStore(t *testing.T) {
	h := graphHandler(t)
	resp, _ := callUserInfo(t, h, http.MethodGet, graphToken(t, h, tidA, "jane"))
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

func TestUserInfoAppOnlyIs403(t *testing.T) {
	h := graphHandler(t)
	resp, body := callUserInfo(t, h, http.MethodGet, graphAppToken(t, h, tidA))
	if resp.Status != http.StatusForbidden || body["error"] != "insufficient_scope" {
		t.Fatalf("status %d body %v", resp.Status, body)
	}
	if ch := resp.Header.Get("WWW-Authenticate"); !strings.Contains(ch, `error="insufficient_scope"`) {
		t.Errorf("WWW-Authenticate = %q", ch)
	}
	if body["error_description"] == nil {
		t.Error("an RFC 6750 body carries error_description")
	}
}

func TestUserInfoInvalidTokenIs401(t *testing.T) {
	h := graphHandler(t)
	for name, bearer := range map[string]string{
		"missing":   "",
		"garbage":   "abc",
		"other key": NewKeySet().Sign(map[string]any{"sub": "x"}),
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := callUserInfo(t, h, http.MethodGet, bearer)
			if resp.Status != http.StatusUnauthorized || body["error"] != "invalid_token" {
				t.Fatalf("status %d body %v", resp.Status, body)
			}
			if ch := resp.Header.Get("WWW-Authenticate"); !strings.Contains(ch, `error="invalid_token"`) {
				t.Errorf("WWW-Authenticate = %q", ch)
			}
		})
	}
}

// A user disabled after the token was minted can no longer be described.
func TestUserInfoDisabledUserIs401(t *testing.T) {
	h := graphHandler(t)
	at := graphToken(t, h, tidA, "jane")
	jane := *h.conf().User(tidA, "jane")
	jane.AccountEnabled = boolPtr(false)
	if err := h.store.UpdateUser(tidA, "jane", jane); err != nil {
		t.Fatal(err)
	}
	resp, body := callUserInfo(t, h, http.MethodGet, at)
	if resp.Status != http.StatusUnauthorized {
		t.Fatalf("status %d body %v", resp.Status, body)
	}
}

func TestDiscoveryAdvertisesUserInfoByDefault(t *testing.T) {
	// No graph block at all: Graph, and so UserInfo, is still on.
	h := New(mustConfig(t, `{"tenants": [{"tid": "`+tidA+`"}],
		"users": [{"username": "jane", "tid": "`+tidA+`"}]}`))
	resp := serve(h, http.MethodGet, "http://mock.test/entra/"+tidA+"/v2.0/.well-known/openid-configuration", "")
	var doc map[string]any
	if err := json.Unmarshal([]byte(resp.Body), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["userinfo_endpoint"] != "http://mock.test/entra/graph/oidc/userinfo" {
		t.Fatalf("userinfo_endpoint = %v", doc["userinfo_endpoint"])
	}
	// And the advertised URL is reachable.
	if got := serve(h, http.MethodGet, doc["userinfo_endpoint"].(string), ""); got.Status != http.StatusUnauthorized {
		t.Errorf("the advertised endpoint answered %d, want an authentication challenge", got.Status)
	}
}

func TestDiscoveryOmitsUserInfoWhenDisabled(t *testing.T) {
	for name, graph := range map[string]string{
		"userinfo off": `{"userinfo": false}`,
		"graph off":    `{"enabled": false}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := New(mustConfig(t, `{"graph": `+graph+`, "tenants": [{"tid": "`+tidA+`"}],
				"users": [{"username": "jane", "tid": "`+tidA+`"}]}`))
			resp := serve(h, http.MethodGet, "http://mock.test/entra/"+tidA+"/v2.0/.well-known/openid-configuration", "")
			var doc map[string]any
			if err := json.Unmarshal([]byte(resp.Body), &doc); err != nil {
				t.Fatal(err)
			}
			if _, has := doc["userinfo_endpoint"]; has {
				t.Errorf("userinfo_endpoint = %v, want absent", doc["userinfo_endpoint"])
			}
		})
	}
}

// With Graph on but userinfo off, the path must not serve either.
func TestUserInfoPathOffWhenDisabled(t *testing.T) {
	cfg := mustConfig(t, `{"graph": {"userinfo": false}, "tenants": [{"tid": "`+tidA+`"}],
		"users": [{"username": "jane", "tid": "`+tidA+`"}]}`)
	h := New(cfg, WithClock(func() time.Time { return verifyNow }))
	resp, body := callUserInfo(t, h, http.MethodGet, graphToken(t, h, tidA, "jane"))
	if resp.Status != http.StatusNotFound || graphErrCode(t, body) != CodeResourceNotFound {
		t.Fatalf("status %d body %v", resp.Status, body)
	}
}
