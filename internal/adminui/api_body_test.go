package adminui

import (
	"net/http"
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
