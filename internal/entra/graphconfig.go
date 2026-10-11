package entra

import (
	"fmt"
	"strings"
)

// Graph defaults. Page sizes mirror real Microsoft Graph; the clock skew is the
// leeway ordinary JWT validators allow on exp/nbf.
const (
	defaultGraphBasePath    = "graph"
	defaultGraphPageSize    = 100
	defaultGraphMaxPageSize = 999
	defaultGraphClockSkew   = int64(60)
)

// Where the group-overage claim sends a relying party.
const (
	OverageSelf      = "self"      // our own getMemberObjects, resolvable in tests
	OverageMicrosoft = "microsoft" // the real graph.microsoft.com URL
)

// Segments that may not be used as the Graph base path, because the dispatcher
// already gives them a meaning at that position.
var reservedGraphBase = map[string]bool{
	testAPISegment:     true,
	ScopeOrganizations: true,
	ScopeCommon:        true,
}

// GraphConfig tunes the Graph account API (design: docs/entra/02-graph-design.md).
// Graph is on whenever Entra mode is, so a nil GraphConfig means "on with every
// default"; {"enabled": false} is the off switch.
type GraphConfig struct {
	Enabled         *bool  `json:"enabled"`
	BasePath        string `json:"basePath"`
	OverageEndpoint string `json:"overageEndpoint"`
	UserInfo        *bool  `json:"userinfo"`
	AppOnly         bool   `json:"appOnly"`
	DefaultPageSize int    `json:"defaultPageSize"`
	MaxPageSize     int    `json:"maxPageSize"`
	ClockSkew       *int64 `json:"clockSkew"`
}

// GraphOn reports whether the Graph surface serves requests. It is nil-safe, so
// it answers the same before and after normalize.
func (c *Config) GraphOn() bool {
	return c.Graph == nil || c.Graph.Enabled == nil || *c.Graph.Enabled
}

// UserInfoOn reports whether /oidc/userinfo is served and advertised.
func (c *Config) UserInfoOn() bool {
	if !c.GraphOn() {
		return false
	}
	return c.Graph == nil || c.Graph.UserInfo == nil || *c.Graph.UserInfo
}

// AppOnlyOn reports whether the client_credentials grant mints app-only tokens.
func (c *Config) AppOnlyOn() bool {
	return c.GraphOn() && c.Graph != nil && c.Graph.AppOnly
}

// GraphBase is the reserved path segment the Graph surface answers on.
func (c *Config) GraphBase() string {
	if c.Graph == nil || c.Graph.BasePath == "" {
		return defaultGraphBasePath
	}
	return c.Graph.BasePath
}

// OverageSelfHosted reports whether the group-overage claim points at our own
// getMemberObjects rather than at the real Graph.
func (c *Config) OverageSelfHosted() bool {
	return c.GraphOn() && (c.Graph == nil || c.Graph.OverageEndpoint != OverageMicrosoft)
}

// PageSize resolves a $top value against the configured default and cap.
func (c *Config) PageSize(requested int) int {
	def, max := defaultGraphPageSize, defaultGraphMaxPageSize
	if c.Graph != nil {
		if c.Graph.DefaultPageSize > 0 {
			def = c.Graph.DefaultPageSize
		}
		if c.Graph.MaxPageSize > 0 {
			max = c.Graph.MaxPageSize
		}
	}
	if requested <= 0 {
		requested = def
	}
	if requested > max {
		requested = max
	}
	return requested
}

// ClockSkew is the leeway in seconds allowed on a Bearer token's exp and nbf.
func (c *Config) ClockSkew() int64 {
	if c.Graph == nil || c.Graph.ClockSkew == nil {
		return defaultGraphClockSkew
	}
	return *c.Graph.ClockSkew
}

// normalizeGraph fills the Graph defaults and validates the block. It runs as
// part of Config.normalize, so a runtime admin edit is held to the same rules.
func (c *Config) normalizeGraph() error {
	if c.Graph == nil {
		c.Graph = &GraphConfig{}
	}
	g := c.Graph
	if g.Enabled == nil {
		g.Enabled = boolPtr(true)
	}
	if g.UserInfo == nil {
		g.UserInfo = boolPtr(true)
	}
	g.BasePath = strings.Trim(strings.TrimSpace(g.BasePath), "/")
	if g.BasePath == "" {
		g.BasePath = defaultGraphBasePath
	}
	if !basePathRE.MatchString(g.BasePath) {
		return fmt.Errorf("graph.basePath %q must be one path segment of [A-Za-z0-9_-]", g.BasePath)
	}
	lower := strings.ToLower(g.BasePath)
	if reservedGraphBase[lower] || lower == c.BasePath {
		return fmt.Errorf("graph.basePath %q is reserved", g.BasePath)
	}
	if guidRE.MatchString(lower) {
		return fmt.Errorf("graph.basePath %q must not be a GUID: it would shadow a tenant path", g.BasePath)
	}
	g.BasePath = lower
	switch g.OverageEndpoint {
	case "":
		g.OverageEndpoint = OverageSelf
	case OverageSelf, OverageMicrosoft:
	default:
		return fmt.Errorf("graph.overageEndpoint must be %q or %q", OverageSelf, OverageMicrosoft)
	}
	if g.MaxPageSize <= 0 {
		g.MaxPageSize = defaultGraphMaxPageSize
	}
	if g.DefaultPageSize <= 0 {
		g.DefaultPageSize = defaultGraphPageSize
	}
	if g.DefaultPageSize > g.MaxPageSize {
		g.DefaultPageSize = g.MaxPageSize
	}
	if g.ClockSkew == nil {
		g.ClockSkew = int64Ptr(defaultGraphClockSkew)
	} else if *g.ClockSkew < 0 {
		return fmt.Errorf("graph.clockSkew must not be negative")
	}
	return nil
}

func boolPtr(v bool) *bool { return &v }

func int64Ptr(v int64) *int64 { return &v }

// copyBool duplicates an optional flag so two config snapshots never share the
// pointed-to value.
func copyBool(v *bool) *bool {
	if v == nil {
		return nil
	}
	return boolPtr(*v)
}

func copyInt64(v *int64) *int64 {
	if v == nil {
		return nil
	}
	return int64Ptr(*v)
}

// clone deep-copies the Graph block.
func (g *GraphConfig) clone() *GraphConfig {
	if g == nil {
		return nil
	}
	out := *g
	out.Enabled = copyBool(g.Enabled)
	out.UserInfo = copyBool(g.UserInfo)
	out.ClockSkew = copyInt64(g.ClockSkew)
	return &out
}
