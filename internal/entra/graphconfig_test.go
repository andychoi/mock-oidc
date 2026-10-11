package entra

import "testing"

// withGraph wraps a graph block in an otherwise minimal valid config.
func withGraph(graph string) string {
	g := ""
	if graph != "" {
		g = `"graph": ` + graph + `,`
	}
	return `{` + g + `"tenants": [{"tid": "` + tidA + `"}]}`
}

func mustParse(t *testing.T, js string) *Config {
	t.Helper()
	c, err := ParseConfig([]byte(js))
	if err != nil {
		t.Fatalf("ParseConfig: %v\n%s", err, js)
	}
	return c
}

func TestGraphConfigDefaults(t *testing.T) {
	c := mustParse(t, withGraph(`{}`))
	if !c.GraphOn() || !c.UserInfoOn() || c.AppOnlyOn() {
		t.Fatalf("on=%v userinfo=%v appOnly=%v", c.GraphOn(), c.UserInfoOn(), c.AppOnlyOn())
	}
	if c.GraphBase() != "graph" {
		t.Errorf("GraphBase = %q", c.GraphBase())
	}
	if !c.OverageSelfHosted() {
		t.Error("overage must default to self-hosted")
	}
	if c.ClockSkew() != 60 {
		t.Errorf("ClockSkew = %d", c.ClockSkew())
	}
	if got := c.PageSize(0); got != 100 {
		t.Errorf("default page size = %d", got)
	}
	if got := c.PageSize(5000); got != 999 {
		t.Errorf("clamped page size = %d", got)
	}
}

// Graph is a property of Entra mode, not of the graph block: a config that
// never mentions Graph must behave exactly like "graph": {}.
func TestGraphOnWhenBlockAbsent(t *testing.T) {
	absent := mustParse(t, withGraph(""))
	empty := mustParse(t, withGraph(`{}`))
	if !absent.GraphOn() || !absent.UserInfoOn() {
		t.Fatalf("on=%v userinfo=%v", absent.GraphOn(), absent.UserInfoOn())
	}
	if absent.GraphBase() != empty.GraphBase() ||
		absent.ClockSkew() != empty.ClockSkew() ||
		absent.PageSize(0) != empty.PageSize(0) ||
		absent.OverageSelfHosted() != empty.OverageSelfHosted() ||
		absent.AppOnlyOn() != empty.AppOnlyOn() {
		t.Errorf("absent block differs from an empty one: %+v vs %+v", absent.Graph, empty.Graph)
	}
}

func TestGraphConfigDisabled(t *testing.T) {
	c := mustParse(t, withGraph(`{"enabled": false}`))
	if c.GraphOn() || c.UserInfoOn() || c.AppOnlyOn() {
		t.Fatalf("on=%v userinfo=%v appOnly=%v", c.GraphOn(), c.UserInfoOn(), c.AppOnlyOn())
	}
	if c.OverageSelfHosted() {
		t.Error("a disabled Graph must not host the overage endpoint")
	}
}

func TestGraphConfigUserInfoOffKeepsGraphOn(t *testing.T) {
	c := mustParse(t, withGraph(`{"userinfo": false}`))
	if !c.GraphOn() || c.UserInfoOn() {
		t.Fatalf("on=%v userinfo=%v", c.GraphOn(), c.UserInfoOn())
	}
}

func TestGraphConfigExplicitValues(t *testing.T) {
	c := mustParse(t, withGraph(`{"basePath": "/msgraph/", "overageEndpoint": "microsoft",
		"appOnly": true, "defaultPageSize": 2, "maxPageSize": 10, "clockSkew": 0}`))
	if c.GraphBase() != "msgraph" || !c.AppOnlyOn() || c.OverageSelfHosted() {
		t.Fatalf("graph = %+v", c.Graph)
	}
	if c.ClockSkew() != 0 {
		t.Errorf("an explicit zero skew must survive, got %d", c.ClockSkew())
	}
	if got := c.PageSize(0); got != 2 {
		t.Errorf("default page size = %d", got)
	}
	if got := c.PageSize(50); got != 10 {
		t.Errorf("clamped page size = %d", got)
	}
}

func TestGraphConfigDefaultPageSizeClampedToMax(t *testing.T) {
	c := mustParse(t, withGraph(`{"defaultPageSize": 500, "maxPageSize": 10}`))
	if got := c.PageSize(0); got != 10 {
		t.Errorf("default page size = %d, want the max 10", got)
	}
}

func TestGraphConfigRejects(t *testing.T) {
	cases := map[string]string{
		"basePath is _entra":        withGraph(`{"basePath": "_entra"}`),
		"basePath is organizations": withGraph(`{"basePath": "organizations"}`),
		"basePath is common":        withGraph(`{"basePath": "COMMON"}`),
		"basePath is the entra base": `{"basePath": "entra", "graph": {"basePath": "entra"},
			"tenants": [{"tid": "` + tidA + `"}]}`,
		"basePath charset":      withGraph(`{"basePath": "ms graph"}`),
		"basePath two segments": withGraph(`{"basePath": "a/b"}`),
		"basePath is a GUID":    withGraph(`{"basePath": "` + tidA + `"}`),
		"bad overageEndpoint":   withGraph(`{"overageEndpoint": "azure"}`),
		"negative clockSkew":    withGraph(`{"clockSkew": -1}`),
		"unknown field":         withGraph(`{"enabledd": true}`),
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(js)); err == nil {
				t.Fatalf("expected an error for %s", js)
			}
		})
	}
}
