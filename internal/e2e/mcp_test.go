package e2e

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

var mcpHeaders = map[string]string{"Content-Type": "application/json"}

func mcp(t *testing.T, base, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	status, _, raw := do(t, http.MethodPost, base+"/admin/mcp", string(body), mcpHeaders)
	var msg struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal([]byte(raw), &msg); status != http.StatusOK || err != nil || msg.Result == nil {
		t.Fatalf("%s: status %d %s", method, status, raw)
	}
	return msg.Result
}

func mcpTool(t *testing.T, base, name string, args any) map[string]any {
	t.Helper()
	res := mcp(t, base, "tools/call", map[string]any{"name": name, "arguments": args})
	if res["isError"] != false {
		t.Fatalf("%s: %v", name, res)
	}
	return res["structuredContent"].(map[string]any)
}

func mcpToolNames(t *testing.T, base string) []string {
	t.Helper()
	var names []string
	for _, tl := range mcp(t, base, "tools/list", nil)["tools"].([]any) {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	return names
}

func jwtKid(t *testing.T, jwt string) string {
	t.Helper()
	hb, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr struct{ Kid string }
	_ = json.Unmarshal(hb, &hdr)
	return hdr.Kid
}

func TestMCPCreateUserMintsVerifiableToken(t *testing.T) {
	_, base := startServer(t, entraConfig)

	mcp(t, base, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "e2e", "version": "1"}})
	mcpTool(t, base, "entra_create_user", map[string]any{"user": map[string]any{
		"username": "agent", "tid": tidCorp, "name": "Agent Smith", "groups": []string{"PMO"}}})
	tok := mcpTool(t, base, "entra_mint_token", map[string]any{"tid": tidCorp, "username": "agent", "clientId": "iam"})

	_, doc := entraGetJSON(t, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", nil)
	for _, field := range []string{"access_token", "id_token"} {
		claims := verifyEntraJWT(t, base, tok[field].(string))
		if claims["iss"] != doc["issuer"] {
			t.Errorf("%s iss = %v, discovery issuer = %v", field, claims["iss"], doc["issuer"])
		}
	}
	if id := decodeClaims(t, tok["id_token"].(string)); id["name"] != "Agent Smith" || id["aud"] != "iam" {
		t.Errorf("id_token claims = %v", id)
	}

	before := jwtKid(t, tok["access_token"].(string))
	kid := mcpTool(t, base, "entra_rotate_keys", nil)["kid"]
	rotated := mcpTool(t, base, "entra_mint_token", map[string]any{"tid": tidCorp, "username": "agent"})["access_token"].(string)
	if after := jwtKid(t, rotated); after == before || after != kid {
		t.Errorf("kid before %s, after %s, rotate returned %v", before, after, kid)
	}
	verifyEntraJWT(t, base, rotated)
}

func TestMCPSettingsEnumMatchesServer(t *testing.T) {
	_, base := startServer(t, entraConfig)
	var enum []any
	for _, tl := range mcp(t, base, "tools/list", nil)["tools"].([]any) {
		tool := tl.(map[string]any)
		if tool["name"] == "settings_set" {
			props := tool["inputSchema"].(map[string]any)["properties"].(map[string]any)
			enum = props["name"].(map[string]any)["enum"].([]any)
		}
	}
	if len(enum) == 0 {
		t.Fatal("settings_set enum not advertised")
	}
	for _, name := range enum {
		mcpTool(t, base, "settings_set", map[string]any{"name": name, "value": false})
		mcpTool(t, base, "settings_set", map[string]any{"name": name, "value": true})
	}

	mcpTool(t, base, "settings_set", map[string]any{"name": "entra", "value": false})
	if status, _, _ := do(t, http.MethodGet, base+"/entra/"+tidCorp+"/v2.0/.well-known/openid-configuration", "", nil); status != http.StatusMethodNotAllowed {
		t.Errorf("entra toggled off but discovery answered %d", status)
	}
	if users := mcpTool(t, base, "entra_get_state", nil)["users"].([]any); len(users) == 0 {
		t.Error("entra tools stopped working while the entra toggle is off")
	}
}

func TestMCPWithoutEntraConfig(t *testing.T) {
	_, base := startServer(t, repoLikeConfig)
	names := mcpToolNames(t, base)
	for _, n := range names {
		if strings.HasPrefix(n, "entra_") {
			t.Errorf("%s listed without Entra config", n)
		}
	}
	if len(names) == 0 {
		t.Fatal("no tools listed")
	}
	if st := mcpTool(t, base, "settings_get", nil); st["entraConfigured"] != false {
		t.Errorf("settings_get = %v", st)
	}
	res := mcp(t, base, "tools/call", map[string]any{"name": "settings_set", "arguments": map[string]any{"name": "entra", "value": true}})
	if res["isError"] != true {
		t.Errorf("enabling entra without config = %v", res)
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "entra_get_state"}})
	if status, _, raw := do(t, http.MethodPost, base+"/admin/mcp", string(body), mcpHeaders); status != http.StatusOK ||
		!strings.Contains(raw, "-32602") {
		t.Errorf("entra_get_state without Entra: %d %s", status, raw)
	}
}

func TestMCPDoesNotShadowIssuers(t *testing.T) {
	_, base := startServer(t, entraConfig)
	_, doc := entraGetJSON(t, base+"/mcp/.well-known/openid-configuration", nil)
	if doc["issuer"] != base+"/mcp" {
		t.Errorf("issuer mcp discovery = %v", doc["issuer"])
	}
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		want, _, _ := do(t, m, base+"/oidc/nosuchpath", "", mcpHeaders)
		if got, _, raw := do(t, m, base+"/oidc/mcp", "", mcpHeaders); got != want {
			t.Errorf("%s /oidc/mcp = %d (%s), unknown path = %d", m, got, raw, want)
		}
	}
}
