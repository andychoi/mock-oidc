package adminui

import (
	"net/http"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/directory"
)

func TestAPIRejectsTrailingJSON(t *testing.T) {
	dir := directory.New(nil)
	rt := newRouter(nil, dir, nil)

	resp := do(t, rt, http.MethodPost, "/admin/api/directory/users", `{"username":"b"} {"username":"c"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("trailing value: status %d, want 400", resp.StatusCode)
	}
	if dir.Get("b") != nil {
		t.Error("trailing value: first object was applied")
	}

	if resp := do(t, rt, http.MethodPost, "/admin/api/directory/users", "{\"username\":\"b\"}\n"); resp.StatusCode != http.StatusOK {
		t.Errorf("trailing newline: status %d, want 200", resp.StatusCode)
	}
}

func TestAPINamesWithSlash(t *testing.T) {
	dir := directory.New([]directory.User{{Username: "ops/bot"}})
	rt := newRouter(testEntra(t), dir, nil)

	if resp := do(t, rt, http.MethodDelete, "/admin/api/directory/users/ops%2Fbot", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("directory delete: status %d, want 200", resp.StatusCode)
	}
	if dir.Get("ops/bot") != nil {
		t.Error("directory delete: user still present")
	}

	user := `{"username":"svc/ci","tid":"` + corpTID + `"}`
	if resp := do(t, rt, http.MethodPost, "/admin/api/entra/users", user); resp.StatusCode != http.StatusOK {
		t.Fatalf("entra create: status %d %s", resp.StatusCode, body(t, resp))
	}
	renamed := `{"username":"svc/ci","tid":"` + corpTID + `","name":"CI Bot"}`
	if resp := do(t, rt, http.MethodPut, "/admin/api/entra/users/"+corpTID+"/svc%2Fci", renamed); resp.StatusCode != http.StatusOK {
		t.Errorf("entra update: status %d %s", resp.StatusCode, body(t, resp))
	}
	if b := body(t, do(t, rt, http.MethodGet, "/admin/api/entra", "")); !strings.Contains(b, `"CI Bot"`) {
		t.Errorf("entra update not applied:\n%s", b)
	}
	if resp := do(t, rt, http.MethodDelete, "/admin/api/entra/users/"+corpTID+"/svc%2Fci", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("entra delete: status %d %s", resp.StatusCode, body(t, resp))
	}
	if b := body(t, do(t, rt, http.MethodGet, "/admin/api/entra", "")); strings.Contains(b, "svc/ci") {
		t.Errorf("entra delete not applied:\n%s", b)
	}
}
