package adminui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

var guidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body(t, resp)), &m); err != nil {
		t.Fatalf("decode: %v\n%s", err, body(t, resp))
	}
	return m
}

func isRFC3339(s any) bool {
	v, ok := s.(string)
	if !ok {
		return false
	}
	_, err := time.Parse(time.RFC3339, v)
	return err == nil
}

func TestAPIEntraAppCRUD(t *testing.T) {
	rt := newRouter(testEntra(t), nil, nil)
	appsPath := "/admin/api/entra/apps"

	resp := do(t, rt, http.MethodPost, appsPath,
		`{"name":"Portal","tid":"`+corpTID+`","redirectUris":[{"platform":"web","uri":"http://localhost:8123/cb"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create app: status %d body %q", resp.StatusCode, body(t, resp))
	}
	app := decodeBody(t, resp)
	clientID, _ := app["clientId"].(string)
	if !guidPattern.MatchString(clientID) {
		t.Fatalf("clientId %q is not a generated GUID", clientID)
	}
	if !guidPattern.MatchString(app["objectId"].(string)) {
		t.Errorf("objectId = %v, want a derived GUID", app["objectId"])
	}
	if app["name"] != "Portal" || app["signInAudience"] != "AzureADMyOrg" {
		t.Errorf("created app = %v", app)
	}
	uri := app["redirectUris"].([]any)[0].(map[string]any)
	if uri["platform"] != "web" || uri["uri"] != "http://localhost:8123/cb" {
		t.Errorf("redirectUris = %v", app["redirectUris"])
	}

	// A write without a JSON content type is the admin surface's standing rule.
	req := httptest.NewRequest(http.MethodPost, "http://h"+appsPath, strings.NewReader(`{"name":"X"}`))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("non-JSON create: status %d, want 415", rec.Code)
	}

	if resp = do(t, rt, http.MethodPut, appsPath+"/"+clientID,
		`{"tid":"`+corpTID+`","name":"Renamed"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("update app: status %d body %q", resp.StatusCode, body(t, resp))
	}
	if resp = do(t, rt, http.MethodPut, appsPath+"/"+clientID,
		`{"clientId":"other","tid":"`+corpTID+`"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("clientId change: status %d, want 400", resp.StatusCode)
	}
	if resp = do(t, rt, http.MethodPut, appsPath+"/no-such-app", `{}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("update unknown app: status %d, want 404", resp.StatusCode)
	}

	secretPath := func(id string) string { return appsPath + "/" + id + "/secrets" }
	resp = do(t, rt, http.MethodPost, secretPath(clientID), `{"description":"ci","expires":"12m"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("add secret: status %d body %q", resp.StatusCode, body(t, resp))
	}
	sec := decodeBody(t, resp)
	secretID, _ := sec["id"].(string)
	if !guidPattern.MatchString(secretID) || sec["value"] == "" || sec["description"] != "ci" {
		t.Errorf("secret = %v", sec)
	}
	if !isRFC3339(sec["expires"]) || !isRFC3339(sec["createdOn"]) {
		t.Errorf("secret timestamps = %v %v", sec["expires"], sec["createdOn"])
	}
	if resp = do(t, rt, http.MethodPost, secretPath("no-such-app"), `{"expires":"6m"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("secret on unknown app: status %d, want 404", resp.StatusCode)
	}

	// The snapshot lists the registration with its (mock-divergent) secret value.
	snap := body(t, do(t, rt, http.MethodGet, "/admin/api/entra", ""))
	for _, want := range []string{
		clientID, `"Renamed"`, `"signInAudience" : "AzureADMyOrg"`, `"objectId"`, sec["value"].(string),
	} {
		if !strings.Contains(snap, want) {
			t.Errorf("snapshot missing %s:\n%s", want, snap)
		}
	}

	if resp = do(t, rt, http.MethodDelete, secretPath(clientID)+"/"+secretID, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete secret: status %d body %q", resp.StatusCode, body(t, resp))
	}
	if resp = do(t, rt, http.MethodDelete, secretPath(clientID)+"/"+secretID, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete secret again: status %d, want 404", resp.StatusCode)
	}
	if snap = body(t, do(t, rt, http.MethodGet, "/admin/api/entra", "")); strings.Contains(snap, sec["value"].(string)) {
		t.Errorf("secret value still in snapshot after delete:\n%s", snap)
	}

	if resp = do(t, rt, http.MethodDelete, appsPath+"/"+clientID, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete app: status %d body %q", resp.StatusCode, body(t, resp))
	}
	if snap = body(t, do(t, rt, http.MethodGet, "/admin/api/entra", "")); strings.Contains(snap, clientID) {
		t.Errorf("app still in snapshot after delete:\n%s", snap)
	}
	if resp = do(t, rt, http.MethodDelete, appsPath+"/"+clientID, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("delete unknown app: status %d, want 404", resp.StatusCode)
	}
}

func TestAdminPortalShellAndAssets(t *testing.T) {
	rt := newRouter(nil, nil, nil)
	for _, path := range []string{"/admin/portal", "/admin/portal/", "/admin/portal/deep/path"} {
		resp := do(t, rt, http.MethodGet, path, "")
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status %d, want 200 (the hash-routed SPA serves its shell)", path, resp.StatusCode)
			continue
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("GET %s: content type %q", path, ct)
		}
		if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("GET %s: missing CSP or X-Frame-Options", path)
		}
		if b := body(t, resp); !strings.Contains(b, "<title>App registrations") {
			t.Errorf("GET %s: unexpected shell body", path)
		}
	}
	wantTypes := map[string]string{
		"/admin/portal/portal.css": "text/css; charset=utf-8",
		"/admin/portal/portal.js":  "text/javascript; charset=utf-8",
	}
	for path, ct := range wantTypes {
		resp := do(t, rt, http.MethodGet, path, "")
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != ct {
			t.Errorf("GET %s: status %d content type %q, want 200 %s", path, resp.StatusCode, resp.Header.Get("Content-Type"), ct)
		}
	}
}
