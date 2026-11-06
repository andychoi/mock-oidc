package adminui

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"mime"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/andychoi/mock-oidc/internal/entra"
	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// The MCP endpoint (/admin/mcp) speaks Streamable HTTP statelessly: POST
// only, one JSON response per request, no SSE, no Mcp-Session-Id. It serves
// both protocol eras on the one endpoint, chosen per request by detectEra.

const modernVersion = "2026-07-28"

var legacyVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

const metaProtocolVersion = "io.modelcontextprotocol/protocolVersion"

const (
	codeParseError         = -32700
	codeInvalidRequest     = -32600
	codeMethodNotFound     = -32601
	codeInvalidParams      = -32602
	codeHeaderMismatch     = -32020
	codeUnsupportedVersion = -32022
)

type rpcError struct {
	code    int
	message string
	data    jsonx.Obj
}

type era uint8

const (
	legacyEra era = iota + 1 // initialize handshake, 2025-03-26 .. 2025-11-25
	modernEra                // per-request _meta, 2026-07-28
)

// detectEra classifies a request by its params: a modern request carries its
// protocol version in params._meta; anything else is legacy. The returned
// version is the modern request's declared version ("" when not a string).
func detectEra(params json.RawMessage) (era, string) {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if json.Unmarshal(params, &p) != nil {
		return legacyEra, ""
	}
	raw, ok := p.Meta[metaProtocolVersion]
	if !ok {
		return legacyEra, ""
	}
	var v string
	_ = json.Unmarshal(raw, &v)
	return modernEra, v
}

// httpStatus maps a JSON-RPC error code to the response status. Malformed
// envelopes are 400 in both eras; the modern era also signals header,
// version and unknown-method failures in the status, legacy answers 200.
func (e era) httpStatus(code int) int {
	switch code {
	case codeParseError, codeInvalidRequest, codeHeaderMismatch, codeUnsupportedVersion:
		return http.StatusBadRequest
	case codeMethodNotFound:
		if e == modernEra {
			return http.StatusNotFound
		}
	}
	return http.StatusOK
}

type rpcMethod func(a *Handler, req *oauth2.Request, params json.RawMessage) (jsonx.Obj, *rpcError)

var methodTables = map[era]map[string]rpcMethod{
	legacyEra: {
		"initialize": (*Handler).mcpInitialize,
		"ping":       mcpPing,
		"tools/list": (*Handler).mcpToolsList,
		"tools/call": (*Handler).mcpToolsCall,
	},
	modernEra: {
		"server/discover": (*Handler).mcpDiscover,
		"ping":            mcpPing,
		"tools/list":      (*Handler).mcpToolsList,
		"tools/call":      (*Handler).mcpToolsCall,
	},
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (a *Handler) serveMCP(req *oauth2.Request) routing.Response {
	if req.Method != http.MethodPost {
		resp := routing.Response{Status: http.StatusMethodNotAllowed, Header: http.Header{}}
		resp.Header.Set("Allow", http.MethodPost)
		return resp
	}
	if !allowedOrigin(req) {
		return rpcResponse(http.StatusForbidden, nil, nil, &rpcError{code: codeInvalidRequest, message: "Origin not allowed"})
	}
	if mt, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type")); mt != "application/json" {
		return rpcResponse(http.StatusUnsupportedMediaType, nil, nil,
			&rpcError{code: codeInvalidRequest, message: "Content-Type must be application/json"})
	}
	body := bytes.TrimSpace([]byte(req.Body))
	if len(body) > 0 && body[0] == '[' {
		return rpcResponse(http.StatusBadRequest, nil, nil, &rpcError{code: codeInvalidRequest, message: "JSON-RPC batches are not supported"})
	}
	var m rpcRequest
	if err := json.Unmarshal(body, &m); err != nil {
		return rpcResponse(http.StatusBadRequest, nil, nil, &rpcError{code: codeParseError, message: "Parse error: " + err.Error()})
	}
	if m.JSONRPC != "2.0" || m.Method == "" {
		return rpcResponse(http.StatusBadRequest, m.ID, nil, &rpcError{code: codeInvalidRequest, message: "Invalid Request"})
	}
	if m.ID == nil {
		return routing.Response{Status: http.StatusAccepted, Header: http.Header{}}
	}

	e, version := detectEra(m.Params)
	var rerr *rpcError
	if e == modernEra {
		rerr = checkModern(req, m, version)
	} else {
		rerr = checkLegacy(req)
	}
	if rerr != nil {
		return rpcResponse(e.httpStatus(rerr.code), m.ID, nil, rerr)
	}
	method, ok := methodTables[e][m.Method]
	if !ok {
		rerr = &rpcError{code: codeMethodNotFound, message: "Method not found: " + m.Method}
		return rpcResponse(e.httpStatus(rerr.code), m.ID, nil, rerr)
	}
	result, rerr := method(a, req, m.Params)
	if rerr != nil {
		return rpcResponse(e.httpStatus(rerr.code), m.ID, nil, rerr)
	}
	return rpcResponse(http.StatusOK, m.ID, result, nil)
}

// checkModern enforces the 2026-07-28 request rules: a supported _meta
// version, and MCP-Protocol-Version, Mcp-Method and (for tools/call)
// Mcp-Name headers that mirror the body.
func checkModern(req *oauth2.Request, m rpcRequest, version string) *rpcError {
	if version != modernVersion {
		return &rpcError{code: codeUnsupportedVersion, message: "Unsupported protocol version", data: jsonx.Obj{
			{Name: "supported", V: []string{modernVersion}},
			{Name: "requested", V: version},
		}}
	}
	mismatch := func(header, got, want string) *rpcError {
		if got == "" {
			return &rpcError{code: codeHeaderMismatch, message: "Header mismatch: missing " + header + " header"}
		}
		return &rpcError{code: codeHeaderMismatch,
			message: "Header mismatch: " + header + " header value '" + got + "' does not match body value '" + want + "'"}
	}
	if got := req.Header.Get("MCP-Protocol-Version"); got != version {
		return mismatch("MCP-Protocol-Version", got, version)
	}
	if got := req.Header.Get("Mcp-Method"); got != m.Method {
		return mismatch("Mcp-Method", got, m.Method)
	}
	if m.Method == "tools/call" {
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(m.Params, &p)
		raw := req.Header.Get("Mcp-Name")
		got, ok := decodeHeaderValue(raw)
		if !ok {
			return &rpcError{code: codeHeaderMismatch, message: "Header mismatch: malformed Mcp-Name header"}
		}
		if got != p.Name {
			return mismatch("Mcp-Name", raw, p.Name)
		}
	}
	return nil
}

// decodeHeaderValue undoes the MCP header value encoding: a value wrapped as
// =?base64?...?= is the Base64 of the UTF-8 original, anything else is plain.
func decodeHeaderValue(v string) (string, bool) {
	inner, ok := strings.CutPrefix(v, "=?base64?")
	if !ok || !strings.HasSuffix(inner, "?=") {
		return v, true
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(inner, "?="))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// checkLegacy rejects an MCP-Protocol-Version header naming a version this
// server does not speak. A missing header is accepted (2025-03-26 clients
// send none).
func checkLegacy(req *oauth2.Request) *rpcError {
	v := req.Header.Get("MCP-Protocol-Version")
	if v == "" || v == modernVersion || slices.Contains(legacyVersions, v) {
		return nil
	}
	return &rpcError{code: codeInvalidRequest, message: "Unsupported MCP-Protocol-Version header: " + v}
}

// allowedOrigin accepts requests without an Origin (CLI agents send none),
// from the server's own host[:port] (proxy-aware, so the admin page itself
// qualifies), and from loopback hosts. Other browser origins are refused.
func allowedOrigin(req *oauth2.Request) bool {
	o := req.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	if err != nil || u.Host == "" {
		return false
	}
	if host := u.Hostname(); host == "localhost" {
		return true
	} else if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return strings.EqualFold(u.Host, req.ProxyAwareURL().Host)
}

func rpcResponse(status int, id json.RawMessage, result jsonx.Obj, rerr *rpcError) routing.Response {
	obj := jsonx.Obj{{Name: "jsonrpc", V: "2.0"}}
	if id != nil {
		obj = append(obj, jsonx.Field{Name: "id", V: id})
	}
	if rerr != nil {
		e := jsonx.Obj{{Name: "code", V: rerr.code}, {Name: "message", V: rerr.message}}
		if rerr.data != nil {
			e = append(e, jsonx.Field{Name: "data", V: rerr.data})
		}
		obj = append(obj, jsonx.Field{Name: "error", V: e})
	} else {
		obj = append(obj, jsonx.Field{Name: "result", V: result})
	}
	resp := routing.Response{Status: status, Header: http.Header{}}
	resp.Header.Set("Content-Type", "application/json")
	resp.Body = jsonx.Render(obj)
	return resp
}

func serverInfo() jsonx.Obj {
	version := "devel"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		version = bi.Main.Version
	}
	return jsonx.Obj{{Name: "name", V: "mock-oidc"}, {Name: "version", V: version}}
}

func (a *Handler) instructions() string {
	s := "Manages the running mock-oidc server's in-memory state: runtime settings, the login-page directory " +
		"and Entra mode (tenants, users, consents, signing keys, token minting). Edits are lost on restart; " +
		"the reset tools restore the config seed."
	if a.entra == nil {
		s += " Entra mode is not configured on this server; entra_* tools are absent."
	}
	if a.dir == nil {
		s += " No login directory is loaded; directory_* tools are absent."
	}
	return s
}

func (a *Handler) mcpInitialize(_ *oauth2.Request, params json.RawMessage) (jsonx.Obj, *rpcError) {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	version := legacyVersions[0]
	if slices.Contains(legacyVersions, p.ProtocolVersion) {
		version = p.ProtocolVersion
	}
	return jsonx.Obj{
		{Name: "protocolVersion", V: version},
		{Name: "capabilities", V: jsonx.Obj{{Name: "tools", V: jsonx.Obj{{Name: "listChanged", V: false}}}}},
		{Name: "serverInfo", V: serverInfo()},
		{Name: "instructions", V: a.instructions()},
	}, nil
}

func (a *Handler) mcpDiscover(_ *oauth2.Request, _ json.RawMessage) (jsonx.Obj, *rpcError) {
	return jsonx.Obj{
		{Name: "resultType", V: "complete"},
		{Name: "supportedVersions", V: []string{modernVersion}},
		{Name: "capabilities", V: jsonx.Obj{{Name: "tools", V: jsonx.Obj{}}}},
		{Name: "_meta", V: jsonx.Obj{{Name: "io.modelcontextprotocol/serverInfo", V: serverInfo()}}},
		{Name: "instructions", V: a.instructions()},
		{Name: "ttlMs", V: 0},
		{Name: "cacheScope", V: "private"},
	}, nil
}

func mcpPing(*Handler, *oauth2.Request, json.RawMessage) (jsonx.Obj, *rpcError) {
	return jsonx.Obj{{Name: "resultType", V: "complete"}}, nil
}

func (a *Handler) mcpToolsList(_ *oauth2.Request, _ json.RawMessage) (jsonx.Obj, *rpcError) {
	return jsonx.Obj{
		{Name: "resultType", V: "complete"},
		{Name: "tools", V: a.toolDefs()},
		{Name: "ttlMs", V: 0},
		{Name: "cacheScope", V: "private"},
	}, nil
}

func (a *Handler) mcpToolsCall(req *oauth2.Request, params json.RawMessage) (jsonx.Obj, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
		return nil, &rpcError{code: codeInvalidParams, message: "tools/call needs params.name"}
	}
	t, ok := a.lookupTool(p.Name)
	if !ok {
		return nil, &rpcError{code: codeInvalidParams, message: "Unknown tool: " + p.Name}
	}
	return a.runTool(t, entra.IssuerOrigin(req), p.Arguments), nil
}
