package jsonx_test

import (
	"encoding/json"
	"testing"

	"github.com/andychoi/mock-oidc/internal/jsonx"
)

func TestRenderMapInsideArrayIsAnObject(t *testing.T) {
	claims := map[string]any{
		"orgs": []any{
			map[string]any{"id": "1"},
			map[string]any{"id": "2", "name": "Two"},
		},
	}
	got := jsonx.RenderMap(claims)
	want := `{
  "orgs" : [ {
    "id" : "1"
  }, {
    "id" : "2",
    "name" : "Two"
  } ]
}`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	var decoded struct {
		Orgs []map[string]string `json:"orgs"`
	}
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("orgs elements must decode as objects: %v", err)
	}
}

func TestRenderObjInsideArrayMatchesMap(t *testing.T) {
	fromObj := jsonx.Render(jsonx.Arr{jsonx.Obj{{Name: "id", V: "1"}}})
	fromMap := jsonx.Render(jsonx.Arr{map[string]any{"id": "1"}})
	if fromObj != fromMap {
		t.Errorf("Obj element %q and map element %q render differently", fromObj, fromMap)
	}
}
