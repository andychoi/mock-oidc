package oauth2

// Endpoint path suffixes, mirroring OAuth2Endpoints.kt. Routing is suffix-based:
// any first path segment(s) before the suffix is the issuerId.
const (
	OAuth2WellKnown  = "/.well-known/oauth-authorization-server"
	OIDCWellKnown    = "/.well-known/openid-configuration"
	Authorization    = "/authorize"
	Token            = "/token"
	EndSession       = "/endsession"
	Revoke           = "/revoke"
	JWKS             = "/jwks"
	UserInfo         = "/userinfo"
	Introspect       = "/introspect"
	Debugger         = "/debugger"
	DebuggerCallback = "/debugger/callback"
)

// Endpoints is the ordered list used for issuerId extraction
// (order mirrors OAuth2Endpoints.all).
var Endpoints = []string{
	OAuth2WellKnown,
	OIDCWellKnown,
	Authorization,
	Token,
	EndSession,
	Revoke,
	JWKS,
	UserInfo,
	Introspect,
	Debugger,
	DebuggerCallback,
}
