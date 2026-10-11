package entra

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// odataHandler is a handler on the frozen clock with a one-tenant config.
func odataHandler(t *testing.T) *Handler {
	t.Helper()
	h, _ := verifyHandler(t, verifyJSON)
	return h
}

func decodeBody(t *testing.T, resp routing.Response) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(resp.Body), &m); err != nil {
		t.Fatalf("decode %q: %v", resp.Body, err)
	}
	return m
}

func TestParseTopClampAndDefault(t *testing.T) {
	c, err := ParseConfig([]byte(withGraph(`{"defaultPageSize": 100, "maxPageSize": 999}`)))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]int{"": 100, "0": 100, "-1": 100, "abc": 100, "5": 5, "999": 999, "5000": 999}
	for raw, want := range cases {
		if got := c.parseTop(raw); got != want {
			t.Errorf("parseTop(%q) = %d, want %d", raw, got, want)
		}
	}
}

func TestParseSkipInvalidIsZero(t *testing.T) {
	cases := map[string]int{"": 0, "abc": 0, "-3": 0, "0": 0, "7": 7}
	for raw, want := range cases {
		if got := parseSkip(raw); got != want {
			t.Errorf("parseSkip(%q) = %d, want %d", raw, got, want)
		}
	}
}

// nextLink must carry every other parameter forward, or the page size and
// shape change halfway through a continuation.
func TestNextLinkPreservesQueryAndOverridesSkiptoken(t *testing.T) {
	h := odataHandler(t)
	req := graphRequest(t, "http://mock.test/entra/graph/v1.0/users?$top=1&$select=id,displayName&$skiptoken=3", "")
	got := h.conf().nextLink(req, 4)
	want := "http://mock.test/entra/graph/v1.0/users?$select=id%2CdisplayName&$top=1&$skiptoken=4"
	if got != want {
		t.Errorf("nextLink = %q, want %q", got, want)
	}
}

func TestNextLinkAbsentOnLastPage(t *testing.T) {
	h := odataHandler(t)
	items := []jsonx.Obj{{{Name: "id", V: "a"}}, {{Name: "id", V: "b"}}, {{Name: "id", V: "c"}}}
	seen := []string{}
	skip := 0
	for page := 0; page < 5; page++ {
		req := graphRequest(t, "http://mock.test/entra/graph/v1.0/users?$top=2&$skiptoken="+itoa(skip), "")
		body := decodeBody(t, h.graphCollection(req, h.conf(), "users", items, typeUser))
		for _, v := range body["value"].([]any) {
			seen = append(seen, v.(map[string]any)["id"].(string))
		}
		next, more := body["@odata.nextLink"].(string)
		if !more {
			break
		}
		if !strings.Contains(next, "$top=2") {
			t.Fatalf("nextLink lost $top: %s", next)
		}
		skip += 2
	}
	// Every row exactly once, no gaps and no duplicates.
	if strings.Join(seen, ",") != "a,b,c" {
		t.Errorf("paged rows = %v", seen)
	}
}

func TestCollectionSkipPastEndIsEmpty(t *testing.T) {
	h := odataHandler(t)
	items := []jsonx.Obj{{{Name: "id", V: "a"}}}
	req := graphRequest(t, "http://mock.test/entra/graph/v1.0/users?$skiptoken=99", "")
	body := decodeBody(t, h.graphCollection(req, h.conf(), "users", items, typeUser))
	if got := body["value"].([]any); len(got) != 0 {
		t.Errorf("value = %v, want empty", got)
	}
	if _, more := body["@odata.nextLink"]; more {
		t.Error("no nextLink past the end")
	}
}

func TestSelectKeepsIDAndRejectsUnknownProperty(t *testing.T) {
	entity := jsonx.Obj{
		{Name: "@odata.context", V: "ctx"},
		{Name: "id", V: "u1"},
		{Name: "displayName", V: "Jane"},
		{Name: "mail", V: nil},
	}
	got, gerr := applySelect(entity, "displayName", typeUser)
	if gerr != nil {
		t.Fatalf("select: %+v", gerr)
	}
	names := []string{}
	for _, f := range got {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "@odata.context,id,displayName" {
		t.Errorf("selected = %v, want the context, id and displayName", names)
	}
	// Case-insensitive, like OData.
	if _, gerr := applySelect(entity, "DISPLAYNAME, mail", typeUser); gerr != nil {
		t.Errorf("case-insensitive select: %+v", gerr)
	}
	// An empty $select is not a filter at all.
	if got, _ := applySelect(entity, "  ", typeUser); len(got) != len(entity) {
		t.Error("a blank $select must keep everything")
	}
	_, gerr = applySelect(entity, "displayName,nope", typeUser)
	if gerr == nil || gerr.Status != http.StatusBadRequest || gerr.Code != CodeUnsupportedQuery {
		t.Fatalf("unknown property error = %+v", gerr)
	}
	if !strings.Contains(gerr.Message, "'nope'") || !strings.Contains(gerr.Message, typeUser) {
		t.Errorf("message = %q", gerr.Message)
	}
	// The context is not a selectable property.
	if _, gerr := applySelect(entity, "@odata.context", typeUser); gerr == nil {
		t.Error("@odata.context must not be selectable")
	}
}

// Graph error codes are PascalCase; routing.ErrorResponse lowercases whole
// bodies for navikt compatibility, so this surface must not go through it.
func TestGraphErrorBodyIsNotLowercased(t *testing.T) {
	h := odataHandler(t)
	req := graphRequest(t, "http://mock.test/entra/graph/v1.0/me", "")
	resp := h.graphErrorResponse(req, invalidToken())
	if !strings.Contains(resp.Body, `"InvalidAuthenticationToken"`) {
		t.Fatalf("body lost its capitals:\n%s", resp.Body)
	}
	body := decodeBody(t, resp)
	e := body["error"].(map[string]any)
	if e["code"] != CodeInvalidAuthenticationToken || e["message"] != "Access token is empty or invalid." {
		t.Errorf("error = %v", e)
	}
	inner := e["innerError"].(map[string]any)
	for _, k := range []string{"date", "request-id", "client-request-id"} {
		if s, _ := inner[k].(string); s == "" {
			t.Errorf("innerError.%s is empty: %v", k, inner)
		}
	}
	if inner["date"] != "2026-09-21T14:13:20" {
		t.Errorf("date = %v, want the handler clock", inner["date"])
	}
}

func TestGraphErrorEchoesClientRequestID(t *testing.T) {
	h := odataHandler(t)
	req := graphRequest(t, "http://mock.test/entra/graph/v1.0/me", "")
	req.Header.Set("client-request-id", "caller-123")
	body := decodeBody(t, h.graphErrorResponse(req, invalidToken()))
	inner := body["error"].(map[string]any)["innerError"].(map[string]any)
	if inner["client-request-id"] != "caller-123" {
		t.Errorf("client-request-id = %v, want the caller's", inner["client-request-id"])
	}
}

func TestGraphError401SetsWWWAuthenticate(t *testing.T) {
	h := odataHandler(t)
	req := graphRequest(t, "http://mock.test/entra/graph/v1.0/me", "")
	if got := h.graphErrorResponse(req, invalidToken()).Header.Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}
	for _, e := range []*graphError{notFound("x"), forbidden("x"), unsupportedQuery("x")} {
		if got := h.graphErrorResponse(req, e).Header.Get("WWW-Authenticate"); got != "" {
			t.Errorf("%d must not challenge, got %q", e.Status, got)
		}
	}
}

func TestUnsupportedQueryOptions(t *testing.T) {
	h := odataHandler(t)
	for _, opt := range []string{"$filter", "$orderby", "$expand", "$search", "$count"} {
		t.Run(opt, func(t *testing.T) {
			req := graphRequest(t, "http://mock.test/entra/graph/v1.0/users?"+opt+"=x", "")
			resp := h.graphCollection(req, h.conf(), "users", nil, typeUser)
			if resp.Status != http.StatusBadRequest {
				t.Fatalf("status = %d", resp.Status)
			}
			if code := decodeBody(t, resp)["error"].(map[string]any)["code"]; code != CodeUnsupportedQuery {
				t.Errorf("code = %v", code)
			}
		})
	}
}

func TestGraphContextUsesProxyAwareOrigin(t *testing.T) {
	h := odataHandler(t)
	req := graphRequest(t, "http://mock.test/entra/graph/v1.0/users", "")
	req.Header.Set("x-forwarded-proto", "https")
	req.Header.Set("x-forwarded-port", "443")
	if got := h.conf().graphContext(req, "users/$entity"); got != "https://mock.test/entra/graph/v1.0/$metadata#users/$entity" {
		t.Errorf("context = %q", got)
	}
}

func TestEntityCarriesContextAndCollectionItemsDoNot(t *testing.T) {
	h := odataHandler(t)
	req := graphRequest(t, "http://mock.test/entra/graph/v1.0/users", "")
	entity := jsonx.Obj{{Name: "id", V: "u1"}}
	single := decodeBody(t, h.graphEntity(req, h.conf(), "users/$entity", entity, typeUser))
	if single["@odata.context"] != "http://mock.test/entra/graph/v1.0/$metadata#users/$entity" {
		t.Errorf("entity context = %v", single["@odata.context"])
	}
	coll := decodeBody(t, h.graphCollection(req, h.conf(), "users", []jsonx.Obj{entity}, typeUser))
	if coll["@odata.context"] != "http://mock.test/entra/graph/v1.0/$metadata#users" {
		t.Errorf("collection context = %v", coll["@odata.context"])
	}
	if _, has := coll["value"].([]any)[0].(map[string]any)["@odata.context"]; has {
		t.Error("collection items must not carry their own context")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
