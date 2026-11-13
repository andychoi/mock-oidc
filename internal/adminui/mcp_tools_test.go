package adminui

import (
	"bytes"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/directory"
	"github.com/andychoi/mock-oidc/internal/entra"
	"github.com/andychoi/mock-oidc/internal/jsonx"
)

func fullHandler(t *testing.T) *Handler {
	t.Helper()
	return New(testConfig(), testEntra(t), directory.New([]directory.User{{Username: "seed"}}),
		&fakeSettings{st: AdminSettings{EntraConfigured: true, EntraEnabled: true}})
}

func decoded(t *testing.T, v any) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(jsonx.Render(v)), &m); err != nil {
		t.Fatalf("render is not JSON: %v", err)
	}
	return m
}

func toolNames(defs jsonx.Arr) []string {
	var out []string
	for _, d := range defs {
		out = append(out, d.(jsonx.Obj)[0].V.(string))
	}
	return out
}

func TestToolRegistryShape(t *testing.T) {
	namePattern := regexp.MustCompile(`^[a-z]+(_[a-z]+)+$`)
	seen := map[string]bool{}
	for _, tl := range registry {
		if !namePattern.MatchString(tl.name) {
			t.Errorf("tool name %q is not snake_case", tl.name)
		}
		if seen[tl.name] {
			t.Errorf("duplicate tool %q", tl.name)
		}
		seen[tl.name] = true
		s := decoded(t, tl.schema)
		if s["type"] != "object" || s["additionalProperties"] != false {
			t.Errorf("%s schema = %v", tl.name, s)
		}
	}
}

func TestToolSchemaGolden(t *testing.T) {
	want := map[string]string{
		"settings_set": `{"type":"object","properties":{` +
			`"name":{"type":"string","enum":["interactiveLogin","rotateRefreshToken","entra","graph"],"description":"toggle name"},` +
			`"value":{"type":"boolean"}},"required":["name","value"],"additionalProperties":false}`,
		"entra_mint_token": `{"type":"object","properties":{` +
			`"tid":{"type":"string","description":"tenant ID"},"username":{"type":"string"},` +
			`"clientId":{"type":"string","description":"audience app; default mock"},` +
			`"scope":{"type":"string","description":"space-separated scopes; default openid profile email"}},` +
			`"required":["tid","username"],"additionalProperties":false}`,
		"directory_reset": `{"type":"object","properties":{},"additionalProperties":false}`,
	}
	for _, tl := range registry {
		w, ok := want[tl.name]
		if !ok {
			continue
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, []byte(jsonx.Render(tl.schema))); err != nil {
			t.Fatal(err)
		}
		if compact.String() != w {
			t.Errorf("%s schema\n got %s\nwant %s", tl.name, compact.String(), w)
		}
		delete(want, tl.name)
	}
	if len(want) > 0 {
		t.Errorf("tools not registered: %v", want)
	}
}

func TestToolSchemaReflectsDomainUser(t *testing.T) {
	for _, tl := range registry {
		if tl.name != "entra_create_user" {
			continue
		}
		user := decoded(t, tl.schema)["properties"].(map[string]any)["user"].(map[string]any)
		props := user["properties"].(map[string]any)
		for _, f := range reflect.VisibleFields(reflect.TypeFor[entra.User]()) {
			if !f.IsExported() {
				continue
			}
			if _, ok := props[jsonName(f)]; !ok {
				t.Errorf("entra.User.%s missing from the user schema", f.Name)
			}
		}
		if props["emailVerified"].(map[string]any)["type"] != "boolean" ||
			props["onPremisesExtensionAttributes"].(map[string]any)["additionalProperties"] != false {
			t.Errorf("user schema = %v", props)
		}
		return
	}
	t.Fatal("entra_create_user not registered")
}

func TestToolArgumentsStrict(t *testing.T) {
	a := fullHandler(t)
	for _, tl := range registry {
		required := decoded(t, tl.schema)["required"]
		res := decoded(t, a.runTool(tl, "http://x", json.RawMessage(`{}`)))
		if required != nil && res["isError"] != true {
			t.Errorf("%s accepted {} although it requires %v", tl.name, required)
		}
	}

	cases := []struct{ tool, args, want string }{
		{"entra_create_user", `{"user":{"username":"x","tid":"` + corpTID + `","bogus":1}}`, `unknown field "bogus"`},
		{"settings_set", `{"name":"nope","value":true}`, `"name" must be one of`},
		{"settings_set", `{"name":"entra","value":null}`, `missing required argument "value"`},
		{"directory_list", `{"extra":1}`, `unknown field "extra"`},
		{"directory_list", `[1]`, `arguments must be a JSON object`},
	}
	for _, c := range cases {
		tl, ok := a.lookupTool(c.tool)
		if !ok {
			t.Fatalf("%s unavailable", c.tool)
		}
		res := decoded(t, a.runTool(tl, "http://x", json.RawMessage(c.args)))
		text := res["content"].([]any)[0].(map[string]any)["text"].(string)
		if res["isError"] != true || !strings.Contains(text, c.want) {
			t.Errorf("%s %s = %v, want error containing %q", c.tool, c.args, res, c.want)
		}
	}
}

func TestToolAvailabilityFollowsOwners(t *testing.T) {
	all := toolNames(fullHandler(t).toolDefs())
	if len(all) != len(registry) {
		t.Fatalf("fully wired handler lists %d of %d tools", len(all), len(registry))
	}

	noEntra := New(testConfig(), nil, directory.New(nil), &fakeSettings{})
	var want []string
	for _, n := range all {
		if !strings.HasPrefix(n, "entra_") {
			want = append(want, n)
		}
	}
	if got := toolNames(noEntra.toolDefs()); !slices.Equal(got, want) {
		t.Errorf("without entra: %v, want %v", got, want)
	}
	if _, ok := noEntra.lookupTool("entra_get_state"); ok {
		t.Error("entra_get_state callable without entra")
	}

	onlyEntra := New(testConfig(), testEntra(t), nil, nil)
	for _, n := range toolNames(onlyEntra.toolDefs()) {
		if !strings.HasPrefix(n, "entra_") {
			t.Errorf("%s listed without its owner", n)
		}
	}
}

// The five app-registration tools round-trip the same lifecycle the admin API
// serves: create returns the generated identity, add-secret returns the
// one-time value, update keeps secrets, and both deletes converge.
func TestMCPAppRegistrationTools(t *testing.T) {
	rt := newRouter(testEntra(t), nil, nil)

	res := callLegacy(t, rt, "entra_create_app", map[string]any{
		"app": map[string]any{"name": "Portal", "tid": corpTID, "redirectUris": []any{
			map[string]any{"platform": "web", "uri": "http://localhost:8123/cb"}}}})
	if res["isError"] != false {
		t.Fatalf("create app = %v", res)
	}
	app := res["structuredContent"].(map[string]any)
	clientID, _ := app["clientId"].(string)
	if clientID == "" || app["objectId"] == "" || app["signInAudience"] != "AzureADMyOrg" {
		t.Fatalf("created app = %v", app)
	}

	state := callLegacy(t, rt, "entra_get_state", nil)["structuredContent"].(map[string]any)
	if findByKey(t, state["apps"], "clientId", clientID)["name"] != "Portal" {
		t.Fatalf("created app missing from state")
	}

	sec := callLegacy(t, rt, "entra_add_app_secret", map[string]any{
		"clientId": clientID, "description": "ci", "expires": "6m"})["structuredContent"].(map[string]any)
	secretID, value, _ := sec["id"].(string), sec["value"].(string), sec["description"]
	if secretID == "" || value == "" {
		t.Fatalf("added secret = %v", sec)
	}

	res = callLegacy(t, rt, "entra_update_app", map[string]any{"clientId": clientID,
		"app": map[string]any{"tid": corpTID, "name": "Renamed"}})
	if res["isError"] != false {
		t.Fatalf("update app = %v", res)
	}
	state = callLegacy(t, rt, "entra_get_state", nil)["structuredContent"].(map[string]any)
	entry := findByKey(t, state["apps"], "clientId", clientID)
	if entry["name"] != "Renamed" {
		t.Fatalf("update not applied: %v", entry)
	}
	if secrets, _ := entry["secrets"].([]any); len(secrets) != 1 || secrets[0].(map[string]any)["value"] != value {
		t.Fatalf("update must keep secrets: %v", entry["secrets"])
	}

	if res = callLegacy(t, rt, "entra_delete_app_secret", map[string]any{"clientId": clientID, "secretId": secretID}); res["isError"] != false {
		t.Fatalf("delete secret = %v", res)
	}
	state = callLegacy(t, rt, "entra_get_state", nil)["structuredContent"].(map[string]any)
	if secrets, _ := findByKey(t, state["apps"], "clientId", clientID)["secrets"].([]any); len(secrets) != 0 {
		t.Fatalf("secret not deleted: %v", secrets)
	}

	if res = callLegacy(t, rt, "entra_delete_app", map[string]any{"clientId": clientID}); res["isError"] != false {
		t.Fatalf("delete app = %v", res)
	}
	state = callLegacy(t, rt, "entra_get_state", nil)["structuredContent"].(map[string]any)
	for _, a := range state["apps"].([]any) {
		if a.(map[string]any)["clientId"] == clientID {
			t.Fatalf("app still in state after delete")
		}
	}

	if res = callLegacy(t, rt, "entra_update_app", map[string]any{"clientId": "ghost", "app": map[string]any{}}); res["isError"] != true {
		t.Errorf("update unknown app = %v, want an error", res)
	}
	if res = callLegacy(t, rt, "entra_add_app_secret", map[string]any{"clientId": "ghost", "expires": "6m"}); res["isError"] != true {
		t.Errorf("secret on unknown app = %v, want an error", res)
	}
}

func TestToolsCoverOwnerOperations(t *testing.T) {
	bound := map[string]string{
		"entra.AdminSnapshot":        "entra_get_state",
		"entra.AdminCreateTenant":    "entra_create_tenant",
		"entra.AdminUpdateTenant":    "entra_update_tenant",
		"entra.AdminDeleteTenant":    "entra_delete_tenant",
		"entra.AdminCreateUser":      "entra_create_user",
		"entra.AdminUpdateUser":      "entra_update_user",
		"entra.AdminDeleteUser":      "entra_delete_user",
		"entra.AdminCreateApp":       "entra_create_app",
		"entra.AdminUpdateApp":       "entra_update_app",
		"entra.AdminDeleteApp":       "entra_delete_app",
		"entra.AdminAddAppSecret":    "entra_add_app_secret",
		"entra.AdminDeleteAppSecret": "entra_delete_app_secret",
		"entra.AdminRevokeConsent":   "entra_revoke_consent",
		"entra.AdminResetToSeed":     "entra_reset",
		"entra.AdminRotateKeys":      "entra_rotate_keys",
		"entra.AdminMintToken":       "entra_mint_token",
		"entra.AdminGraphEnabled":    "settings_get",
		"entra.AdminSetGraphEnabled": "settings_set",
		"directory.List":             "directory_list",
		"directory.Upsert":           "directory_upsert_user",
		"directory.Delete":           "directory_delete_user",
		"directory.Reset":            "directory_reset",
		"settings.AdminSettings":     "settings_get",
		"settings.AdminSetSetting":   "settings_set",
	}
	excluded := map[string]string{
		"directory.Get": "single-user read; directory_list returns every user",
	}
	var methods []string
	for m := range reflect.TypeFor[*entra.Handler]().Methods() {
		if strings.HasPrefix(m.Name, "Admin") {
			methods = append(methods, "entra."+m.Name)
		}
	}
	for m := range reflect.TypeFor[*directory.Directory]().Methods() {
		methods = append(methods, "directory."+m.Name)
	}
	for m := range reflect.TypeFor[Settings]().Methods() {
		methods = append(methods, "settings."+m.Name)
	}
	registered := map[string]bool{}
	for _, tl := range registry {
		registered[tl.name] = true
	}
	for _, m := range methods {
		name, isBound := bound[m]
		if _, isExcluded := excluded[m]; !isBound && !isExcluded {
			t.Errorf("%s is neither bound to an MCP tool nor excluded", m)
		}
		if isBound && !registered[name] {
			t.Errorf("%s is bound to unregistered tool %s", m, name)
		}
	}
}
