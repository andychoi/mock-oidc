package adminui

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/directory"
	"github.com/andychoi/mock-oidc/internal/routing"
)

const newTID = "33333333-3333-3333-3333-333333333333"

type rpcReply struct {
	status int
	header http.Header
	raw    string
	msg    map[string]any
}

func (r rpcReply) result(t *testing.T) map[string]any {
	t.Helper()
	res, ok := r.msg["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result (status %d): %s", r.status, r.raw)
	}
	return res
}

func (r rpcReply) errCode() float64 {
	e, _ := r.msg["error"].(map[string]any)
	code, _ := e["code"].(float64)
	return code
}

func postMCP(t *testing.T, rt *routing.Router, body string, headers map[string]string) rpcReply {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	r := rpcReply{status: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &r.msg)
	return r
}

func rpcBody(method string, params any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	return string(b)
}

func callLegacy(t *testing.T, rt *routing.Router, name string, args any) map[string]any {
	t.Helper()
	r := postMCP(t, rt, rpcBody("tools/call", map[string]any{"name": name, "arguments": args}), nil)
	if r.status != http.StatusOK {
		t.Fatalf("%s: status %d %s", name, r.status, r.raw)
	}
	return r.result(t)
}

func toolText(res map[string]any) string {
	return res["content"].([]any)[0].(map[string]any)["text"].(string)
}

func modernParams(extra map[string]any) map[string]any {
	p := map[string]any{"_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "test", "version": "1"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func modernHeaders(method, name string) map[string]string {
	h := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
	if name != "" {
		h["Mcp-Name"] = name
	}
	return h
}

func TestMCPLegacyInitialize(t *testing.T) {
	rt := newRouter(testEntra(t), nil, &fakeSettings{})
	for requested, want := range map[string]string{"2025-06-18": "2025-06-18", "2025-03-26": "2025-03-26", "2099-01-01": "2025-11-25"} {
		r := postMCP(t, rt, rpcBody("initialize", map[string]any{
			"protocolVersion": requested, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "c", "version": "1"},
		}), nil)
		res := r.result(t)
		if res["protocolVersion"] != want {
			t.Errorf("initialize %s answered %v, want %s", requested, res["protocolVersion"], want)
		}
		if res["serverInfo"].(map[string]any)["name"] != "mock-oidc" || res["capabilities"].(map[string]any)["tools"] == nil {
			t.Errorf("initialize result = %v", res)
		}
		if r.header.Get("Mcp-Session-Id") != "" {
			t.Error("stateless server issued a session id")
		}
		if strings.Contains(res["instructions"].(string), "Entra mode is not configured") {
			t.Error("instructions claim Entra is absent although it is configured")
		}
	}
	noEntra := newRouter(nil, nil, &fakeSettings{})
	res := postMCP(t, noEntra, rpcBody("initialize", map[string]any{"protocolVersion": "2025-11-25"}), nil).result(t)
	if !strings.Contains(res["instructions"].(string), "entra_* tools are absent") {
		t.Errorf("instructions without Entra = %q", res["instructions"])
	}
}

func TestMCPLegacyToolRoundTrip(t *testing.T) {
	rt := newRouter(testEntra(t), directory.New(nil), &fakeSettings{st: AdminSettings{EntraConfigured: true}})

	tools := postMCP(t, rt, rpcBody("tools/list", nil), nil).result(t)["tools"].([]any)
	var names []string
	for _, tl := range tools {
		names = append(names, tl.(map[string]any)["name"].(string))
	}
	if len(names) != len(registry) || !slices.Contains(names, "entra_mint_token") {
		t.Fatalf("tools/list = %v", names)
	}

	res := callLegacy(t, rt, "entra_create_tenant", map[string]any{"tenant": map[string]any{"tid": newTID, "name": "New"}})
	if res["isError"] != false || res["structuredContent"].(map[string]any)["status"] != "ok" {
		t.Fatalf("create tenant = %v", res)
	}
	state := callLegacy(t, rt, "entra_get_state", nil)["structuredContent"].(map[string]any)
	if findByKey(t, state["tenants"], "tid", newTID)["name"] != "New" {
		t.Fatalf("created tenant missing from state")
	}
	if res := callLegacy(t, rt, "entra_delete_tenant", map[string]any{"tid": newTID}); res["isError"] != false {
		t.Fatalf("delete tenant = %v", res)
	}

	callLegacy(t, rt, "directory_upsert_user", map[string]any{"user": map[string]any{"username": "ann", "groups": []string{"g"}}})
	users := callLegacy(t, rt, "directory_list", map[string]any{})["structuredContent"].(map[string]any)["users"].([]any)
	if len(users) != 1 || users[0].(map[string]any)["username"] != "ann" {
		t.Fatalf("directory after upsert = %v", users)
	}
	if res := callLegacy(t, rt, "directory_delete_user", map[string]any{"username": "nobody"}); res["isError"] != true {
		t.Errorf("deleting an unknown directory user = %v", res)
	}
	callLegacy(t, rt, "directory_reset", nil)
	if users := callLegacy(t, rt, "directory_list", nil)["structuredContent"].(map[string]any)["users"].([]any); len(users) != 0 {
		t.Errorf("directory after reset = %v", users)
	}

	if res := callLegacy(t, rt, "settings_set", map[string]any{"name": "entra", "value": true}); res["isError"] != false {
		t.Fatalf("settings_set = %v", res)
	}
	if st := callLegacy(t, rt, "settings_get", nil)["structuredContent"].(map[string]any); st["entraEnabled"] != true {
		t.Errorf("settings after set = %v", st)
	}
}

func TestMCPToolErrorsKeepCase(t *testing.T) {
	rt := newRouter(testEntra(t), nil, nil)
	res := callLegacy(t, rt, "entra_update_user", map[string]any{"tid": corpTID, "username": "Ghost", "user": map[string]any{}})
	if res["isError"] != true || !strings.Contains(toolText(res), "Ghost") {
		t.Errorf("owner error = %v", res)
	}
	res = callLegacy(t, rt, "entra_mint_token", map[string]any{"tid": corpTID, "username": "Ghost"})
	if res["isError"] != true || !strings.Contains(toolText(res), "user Ghost in tenant") {
		t.Errorf("mint for unknown user = %v", res)
	}
}

func TestMCPUnknownAndUnavailableTools(t *testing.T) {
	rt := newRouter(nil, directory.New(nil), &fakeSettings{})
	for _, name := range []string{"no_such_tool", "entra_get_state"} {
		r := postMCP(t, rt, rpcBody("tools/call", map[string]any{"name": name}), nil)
		if r.status != http.StatusOK || r.errCode() != codeInvalidParams {
			t.Errorf("%s: status %d %s", name, r.status, r.raw)
		}
	}
}

func TestMCPTransportGuards(t *testing.T) {
	rt := newRouter(testEntra(t), nil, &fakeSettings{})
	ping := rpcBody("ping", nil)

	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		resp := do(t, rt, m, "/admin/mcp", "")
		if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
			t.Errorf("%s: status %d Allow %q", m, resp.StatusCode, resp.Header.Get("Allow"))
		}
	}
	if resp := do(t, rt, http.MethodOptions, "/admin/mcp", ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("OPTIONS: status %d", resp.StatusCode)
	}

	for origin, want := range map[string]int{
		"https://evil.test":       http.StatusForbidden,
		"http://example.com":      http.StatusOK, // httptest's request host
		"http://localhost:5173":   http.StatusOK,
		"http://127.0.0.1:8080":   http.StatusOK,
		"http://example.com.evil": http.StatusForbidden,
	} {
		r := postMCP(t, rt, ping, map[string]string{"Origin": origin})
		if r.status != want {
			t.Errorf("Origin %s: status %d, want %d", origin, r.status, want)
		}
		if want == http.StatusForbidden {
			if _, hasID := r.msg["id"]; hasID || r.msg["error"] == nil {
				t.Errorf("403 body = %s", r.raw)
			}
		}
	}

	if r := postMCP(t, rt, ping, map[string]string{"Content-Type": "text/plain"}); r.status != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: status %d", r.status)
	}
	if r := postMCP(t, rt, ping, map[string]string{"Content-Type": "application/json; charset=utf-8"}); r.status != http.StatusOK {
		t.Errorf("json with charset: status %d %s", r.status, r.raw)
	}

	cases := []struct {
		name, body string
		headers    map[string]string
		status     int
		code       float64
	}{
		{"parse error", `{"jsonrpc":`, nil, 400, codeParseError},
		{"batch", "[" + ping + "]", nil, 400, codeInvalidRequest},
		{"wrong jsonrpc", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, nil, 400, codeInvalidRequest},
		{"legacy unknown method", rpcBody("resources/list", nil), nil, 200, codeMethodNotFound},
		{"legacy unsupported header", ping, map[string]string{"MCP-Protocol-Version": "2024-01-01"}, 400, codeInvalidRequest},
	}
	for _, c := range cases {
		r := postMCP(t, rt, c.body, c.headers)
		if r.status != c.status || r.errCode() != c.code {
			t.Errorf("%s: status %d body %s, want %d/%v", c.name, r.status, r.raw, c.status, c.code)
		}
	}

	for _, h := range []map[string]string{nil, modernHeaders("notifications/initialized", "")} {
		r := postMCP(t, rt, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, h)
		if r.status != http.StatusAccepted || r.raw != "" {
			t.Errorf("notification: status %d body %q", r.status, r.raw)
		}
	}
	if r := postMCP(t, rt, ping, map[string]string{"MCP-Protocol-Version": "2025-06-18"}); r.status != 200 || r.result(t)["resultType"] != "complete" {
		t.Errorf("legacy ping = %d %s", r.status, r.raw)
	}
}

func TestMCPModernEra(t *testing.T) {
	rt := newRouter(testEntra(t), nil, &fakeSettings{})

	r := postMCP(t, rt, rpcBody("server/discover", modernParams(nil)), modernHeaders("server/discover", ""))
	res := r.result(t)
	if res["resultType"] != "complete" || !reflect.DeepEqual(res["supportedVersions"], []any{"2026-07-28"}) ||
		res["_meta"].(map[string]any)["io.modelcontextprotocol/serverInfo"] == nil || res["cacheScope"] != "private" {
		t.Errorf("discover = %s", r.raw)
	}

	call := rpcBody("tools/call", modernParams(map[string]any{"name": "entra_rotate_keys", "arguments": map[string]any{}}))
	r = postMCP(t, rt, call, modernHeaders("tools/call", "entra_rotate_keys"))
	if r.status != 200 || r.result(t)["structuredContent"].(map[string]any)["kid"] == "" {
		t.Errorf("modern tools/call = %d %s", r.status, r.raw)
	}
	encoded := "=?base64?" + base64.StdEncoding.EncodeToString([]byte("entra_rotate_keys")) + "?="
	if r = postMCP(t, rt, call, modernHeaders("tools/call", encoded)); r.status != 200 {
		t.Errorf("Base64 Mcp-Name = %d %s", r.status, r.raw)
	}

	list := rpcBody("tools/list", modernParams(nil))
	cases := []struct {
		name, body string
		headers    map[string]string
		status     int
		code       float64
	}{
		{"Mcp-Name mismatch", call, modernHeaders("tools/call", "entra_reset"), 400, codeHeaderMismatch},
		{"Mcp-Name missing", call, modernHeaders("tools/call", ""), 400, codeHeaderMismatch},
		{"Mcp-Method mismatch", list, modernHeaders("tools/call", ""), 400, codeHeaderMismatch},
		{"version header missing", list, map[string]string{"Mcp-Method": "tools/list"}, 400, codeHeaderMismatch},
		{"version header mismatch", list, map[string]string{"MCP-Protocol-Version": "2025-11-25", "Mcp-Method": "tools/list"}, 400, codeHeaderMismatch},
		{"unknown method", rpcBody("resources/list", modernParams(nil)), modernHeaders("resources/list", ""), 404, codeMethodNotFound},
		{"initialize is legacy only", rpcBody("initialize", modernParams(nil)), modernHeaders("initialize", ""), 404, codeMethodNotFound},
	}
	for _, c := range cases {
		r := postMCP(t, rt, c.body, c.headers)
		if r.status != c.status || r.errCode() != c.code {
			t.Errorf("%s: status %d body %s, want %d/%v", c.name, r.status, r.raw, c.status, c.code)
		}
	}

	old := modernParams(nil)
	old["_meta"].(map[string]any)["io.modelcontextprotocol/protocolVersion"] = "1900-01-01"
	r = postMCP(t, rt, rpcBody("tools/list", old), map[string]string{"MCP-Protocol-Version": "1900-01-01", "Mcp-Method": "tools/list"})
	data, _ := r.msg["error"].(map[string]any)["data"].(map[string]any)
	if r.status != 400 || r.errCode() != codeUnsupportedVersion || data["requested"] != "1900-01-01" ||
		!reflect.DeepEqual(data["supported"], []any{"2026-07-28"}) {
		t.Errorf("unsupported version = %d %s", r.status, r.raw)
	}
}

func TestMCPParityWithAdminAPI(t *testing.T) {
	restDir, mcpDir := directory.New(nil), directory.New(nil)
	rest := newRouter(testEntra(t), restDir, nil)
	mcp := newRouter(testEntra(t), mcpDir, nil)

	user := map[string]any{"username": "kim", "tid": corpTID, "name": "Kim", "groups": []string{"Ops"},
		"accountEnabled": false, "onPremisesExtensionAttributes": map[string]any{"extensionAttribute1": "D1"}}
	tenant := map[string]any{"name": "Corp Renamed", "domains": []string{"corp.test"}, "groups": []map[string]any{{"name": "Ops"}}}
	dirUser := map[string]any{"username": "ann", "email": "ann@x.test"}

	for _, step := range []struct {
		method, path, tool string
		body, args         any
	}{
		{http.MethodPost, "/admin/api/entra/users", "entra_create_user", user, map[string]any{"user": user}},
		{http.MethodPut, "/admin/api/entra/tenants/" + corpTID, "entra_update_tenant", tenant, map[string]any{"tid": corpTID, "tenant": tenant}},
		{http.MethodDelete, "/admin/api/entra/consents/seed-client/22222222-2222-2222-2222-222222222222", "entra_revoke_consent", nil,
			map[string]any{"clientId": "seed-client", "tid": "22222222-2222-2222-2222-222222222222"}},
		{http.MethodPost, "/admin/api/directory/users", "directory_upsert_user", dirUser, map[string]any{"user": dirUser}},
	} {
		b, _ := json.Marshal(step.body)
		if step.body == nil {
			b = nil
		}
		if resp := do(t, rest, step.method, step.path, string(b)); resp.StatusCode != 200 {
			t.Fatalf("REST %s %s: %d %s", step.method, step.path, resp.StatusCode, body(t, resp))
		}
		if res := callLegacy(t, mcp, step.tool, step.args); res["isError"] != false {
			t.Fatalf("MCP %s: %v", step.tool, res)
		}
	}

	snapshot := func(rt *routing.Router) map[string]any {
		m := adminSnapshot(t, func(method, target, b string) *http.Response { return do(t, rt, method, target, b) })
		delete(m, "keys")
		return m
	}
	if a, b := snapshot(rest), snapshot(mcp); !reflect.DeepEqual(a, b) {
		t.Errorf("entra state differs\nREST %v\nMCP  %v", a, b)
	}
	if !reflect.DeepEqual(restDir.List(), mcpDir.List()) {
		t.Errorf("directory differs: %v vs %v", restDir.List(), mcpDir.List())
	}
}
