package entra

import (
	"os"
	"testing"
)

// The shipped demo config must parse and validate.
func TestEntraDemoConfigParses(t *testing.T) {
	data, err := os.ReadFile("../../entra-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseConfig(data)
	if err != nil {
		t.Fatalf("entra-demo.json: %v", err)
	}
	if !c.GraphOn() || !c.AppOnlyOn() {
		t.Errorf("demo config should showcase Graph: graph=%v appOnly=%v", c.GraphOn(), c.AppOnlyOn())
	}
	if u := c.User("11111111-1111-1111-1111-111111111111", "leo"); u == nil || u.Manager != "jane" {
		t.Errorf("manager chain missing: %+v", u)
	}
	if u := c.User("33333333-3333-3333-3333-333333333333", "disabled"); u == nil || u.Enabled() {
		t.Errorf("disabled demo user: %+v", u)
	}
	if got := len(c.GroupsIn("11111111-1111-1111-1111-111111111111")); got != 3 {
		t.Errorf("corp groups = %d, want 3 including the memberless one", got)
	}
}
