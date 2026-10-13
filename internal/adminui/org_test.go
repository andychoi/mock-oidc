package adminui

import (
	"encoding/json"
	"net/http"
	"testing"
)

// adminSnapshot decodes GET /admin/api/entra.
func adminSnapshot(t *testing.T, do func(method, target, body string) *http.Response) map[string]any {
	t.Helper()
	var snap map[string]any
	if err := json.Unmarshal([]byte(body(t, do(http.MethodGet, "http://h/admin/api/entra", ""))), &snap); err != nil {
		t.Fatal(err)
	}
	return snap
}

func findByKey(t *testing.T, list any, key, value string) map[string]any {
	t.Helper()
	for _, item := range list.([]any) {
		if m := item.(map[string]any); m[key] == value {
			return m
		}
	}
	t.Fatalf("no %s=%s in %v", key, value, list)
	return nil
}

// A tenant save round-trips its declared groups (including a dynamic rule),
// and an org-code change on a user moves them between dynamic groups.
func TestAPIEntraDynamicGroupsAndOrgAttributes(t *testing.T) {
	rt := newRouter(testEntra(t), nil, nil)
	call := func(method, target, b string) *http.Response { return do(t, rt, method, target, b) }

	resp := call(http.MethodPut, "http://h/admin/api/entra/tenants/"+corpTID,
		`{"name":"Corp","groups":[{"name":"HR","membershipRule":"user.extensionAttribute1 -eq \"DEPT001\""},
		  {"name":"Plain","description":"static"}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tenant save: %d %s", resp.StatusCode, body(t, resp))
	}
	snap := adminSnapshot(t, call)
	corp := findByKey(t, snap["tenants"], "tid", corpTID)
	hr := findByKey(t, corp["groups"], "name", "HR")
	if hr["membershipRule"] != `user.extensionAttribute1 -eq "DEPT001"` || hr["configuredOid"] != "" || hr["oid"] == "" {
		t.Errorf("HR group = %v", hr)
	}

	// A bad rule is a 400 with the parser's reason, and changes nothing.
	resp = call(http.MethodPut, "http://h/admin/api/entra/tenants/"+corpTID,
		`{"groups":[{"name":"Bad","membershipRule":"user.extensionAttribute9 -eq \"x\""}]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad rule: %d", resp.StatusCode)
	}

	resp = call(http.MethodPost, "http://h/admin/api/entra/users",
		`{"username":"hana","tid":"`+corpTID+`","department":"HR","employeeId":"E1","emailVerified":true,
		  "onPremisesExtensionAttributes":{"extensionAttribute1":"DEPT001"}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create: %d %s", resp.StatusCode, body(t, resp))
	}
	hana := findByKey(t, adminSnapshot(t, call)["users"], "username", "hana")
	if dyn, _ := hana["dynamicGroups"].([]any); len(dyn) != 1 || dyn[0] != "HR" {
		t.Errorf("dynamicGroups = %v", hana["dynamicGroups"])
	}
	ext, _ := hana["onPremisesExtensionAttributes"].(map[string]any)
	if hana["department"] != "HR" || hana["employeeId"] != "E1" || hana["emailVerified"] != true || ext["extensionAttribute1"] != "DEPT001" {
		t.Errorf("hana = %v", hana)
	}

	// Static assignment to a dynamic group is refused.
	resp = call(http.MethodPut, "http://h/admin/api/entra/users/"+corpTID+"/hana", `{"groups":["HR"]}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("static member of dynamic group: %d", resp.StatusCode)
	}
	// Transfer: clearing the org code leaves the group.
	resp = call(http.MethodPut, "http://h/admin/api/entra/users/"+corpTID+"/hana",
		`{"department":"Finance","onPremisesExtensionAttributes":{"extensionAttribute1":"DEPT002"}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update: %d %s", resp.StatusCode, body(t, resp))
	}
	hana = findByKey(t, adminSnapshot(t, call)["users"], "username", "hana")
	if dyn, _ := hana["dynamicGroups"].([]any); len(dyn) != 0 {
		t.Errorf("after transfer dynamicGroups = %v", dyn)
	}
	if hana["emailVerified"] != nil {
		t.Errorf("a full-replace update without emailVerified unsets it: %v", hana["emailVerified"])
	}
}
