package entra

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// OData entity type names, used in $select diagnostics.
const (
	typeUser  = "microsoft.graph.user"
	typeGroup = "microsoft.graph.group"
)

// Query options real Graph supports and this emulator does not. Refusing them
// is safer than ignoring them: a caller that filters server-side would
// otherwise silently receive the unfiltered set.
var unsupportedOptions = []string{"$filter", "$orderby", "$expand", "$search", "$count", "$apply", "$format"}

// graphJSON renders a Graph document. It deliberately bypasses
// routing.ErrorResponse, which lowercases whole bodies for navikt
// compatibility and would turn InvalidAuthenticationToken into mush.
func graphJSON(status int, v any) routing.Response {
	return routing.Response{
		Status: status,
		Header: http.Header{"Content-Type": []string{"application/json;charset=UTF-8"}},
		Body:   jsonx.Render(v),
	}
}

// randomUUID returns a random (version 4) UUID, for the request ids Graph
// echoes in innerError.
func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

// graphErrorResponse renders a Graph-shaped error. A 401 also carries the
// RFC 6750 challenge, and the caller's client-request-id is echoed back when
// it sent one, as real Graph does.
func (h *Handler) graphErrorResponse(req *oauth2.Request, e *graphError) routing.Response {
	clientRequestID := req.Header.Get("client-request-id")
	if clientRequestID == "" {
		clientRequestID = randomUUID()
	}
	body := jsonx.Obj{{Name: "error", V: jsonx.Obj{
		{Name: "code", V: e.Code},
		{Name: "message", V: e.Message},
		{Name: "innerError", V: jsonx.Obj{
			{Name: "date", V: h.now().UTC().Format("2006-01-02T15:04:05")},
			{Name: "request-id", V: randomUUID()},
			{Name: "client-request-id", V: clientRequestID},
		}},
	}}}
	resp := graphJSON(e.Status, body)
	if e.Status == http.StatusUnauthorized {
		resp.Header.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	return resp
}

// graphBaseURL is the public root of the Graph surface for this request.
func (c *Config) graphBaseURL(req *oauth2.Request) string {
	return origin(req) + "/" + c.BasePath + "/" + c.GraphBase()
}

// graphContext builds an @odata.context URL for a metadata suffix such as
// "users" or "users/$entity".
func (c *Config) graphContext(req *oauth2.Request, suffix string) string {
	return c.graphBaseURL(req) + "/v1.0/$metadata#" + suffix
}

// parseTop reads $top: a positive integer clamped to the configured maximum.
// An absent, non-numeric or non-positive value falls back to the default,
// never an error — matching Graph, which ignores a malformed $top.
func (c *Config) parseTop(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		n = 0
	}
	return c.PageSize(n)
}

// parseSkip reads $skiptoken, an opaque integer offset in this emulator.
// Anything that is not a non-negative integer starts from the beginning.
func parseSkip(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// rejectUnsupportedOptions fails a request that uses a query option this
// emulator does not implement.
func rejectUnsupportedOptions(req *oauth2.Request) *graphError {
	q := req.URL.Query()
	for _, opt := range unsupportedOptions {
		if _, ok := q[opt]; ok {
			return unsupportedQuery("The query option '" + opt + "' is not supported by this emulator.")
		}
	}
	return nil
}

// nextLink builds @odata.nextLink: the same request with $skiptoken advanced.
// Every other parameter is preserved — notably $top and $select, so the page
// size and shape stay stable across continuations. OData's $-prefixed keys
// stay literal; only values are percent-encoded.
func (c *Config) nextLink(req *oauth2.Request, nextSkip int) string {
	q := req.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		if k != "$skiptoken" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		for _, v := range q[k] {
			parts = append(parts, k+"="+url.QueryEscape(v))
		}
	}
	parts = append(parts, "$skiptoken="+strconv.Itoa(nextSkip))
	return origin(req) + req.URL.Path + "?" + strings.Join(parts, "&")
}

// applySelect narrows an entity to the requested properties. `id` always
// survives, as it does in Graph, and so does the entity's own context. An
// unknown property is an error rather than a silent omission, because a
// caller that misspells a field should hear about it.
func applySelect(entity jsonx.Obj, raw, odataType string) (jsonx.Obj, *graphError) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return entity, nil
	}
	known := make(map[string]string, len(entity))
	for _, f := range entity {
		known[strings.ToLower(f.Name)] = f.Name
	}
	keep := map[string]bool{"id": true, "@odata.context": true}
	for _, want := range strings.Split(raw, ",") {
		want = strings.TrimSpace(want)
		if want == "" {
			continue
		}
		name, ok := known[strings.ToLower(want)]
		if !ok || strings.HasPrefix(name, "@") {
			return nil, unsupportedQuery("Could not find a property named '" + want + "' on type '" + odataType + "'.")
		}
		keep[name] = true
	}
	out := make(jsonx.Obj, 0, len(keep))
	for _, f := range entity {
		if keep[f.Name] {
			out = append(out, f)
		}
	}
	return out, nil
}

// graphEntity answers with a single entity, carrying the $entity context.
func (h *Handler) graphEntity(req *oauth2.Request, cfg *Config, ctxSuffix string, entity jsonx.Obj, odataType string) routing.Response {
	if gerr := rejectUnsupportedOptions(req); gerr != nil {
		return h.graphErrorResponse(req, gerr)
	}
	body := append(jsonx.Obj{{Name: "@odata.context", V: cfg.graphContext(req, ctxSuffix)}}, entity...)
	body, gerr := applySelect(body, req.QueryParam("$select"), odataType)
	if gerr != nil {
		return h.graphErrorResponse(req, gerr)
	}
	return graphJSON(http.StatusOK, body)
}

// graphCollection answers with an OData collection: the ordered items paged by
// $top/$skiptoken, each narrowed by $select, with @odata.nextLink present only
// while rows remain. Collection items carry no context of their own.
func (h *Handler) graphCollection(req *oauth2.Request, cfg *Config, ctxSuffix string, items []jsonx.Obj, odataType string) routing.Response {
	if gerr := rejectUnsupportedOptions(req); gerr != nil {
		return h.graphErrorResponse(req, gerr)
	}
	top := cfg.parseTop(req.QueryParam("$top"))
	skip := parseSkip(req.QueryParam("$skiptoken"))
	total := len(items)
	if skip > total {
		skip = total
	}
	end := skip + top
	if end > total {
		end = total
	}
	page := make(jsonx.Arr, 0, end-skip)
	for _, item := range items[skip:end] {
		narrowed, gerr := applySelect(item, req.QueryParam("$select"), odataType)
		if gerr != nil {
			return h.graphErrorResponse(req, gerr)
		}
		page = append(page, narrowed)
	}
	body := jsonx.Obj{
		{Name: "@odata.context", V: cfg.graphContext(req, ctxSuffix)},
		{Name: "value", V: page},
	}
	if end < total {
		body = append(body, jsonx.Field{Name: "@odata.nextLink", V: cfg.nextLink(req, end)})
	}
	return graphJSON(http.StatusOK, body)
}
