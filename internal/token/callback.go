package token

import (
	"regexp"
	"strings"

	"github.com/andychoi/mock-oidc/internal/oauth2"
)

// Callback is the token-customization SPI (OAuth2TokenCallback.kt): it decides
// subject, audience, extra claims, typ header and expiry for a token request.
type Callback interface {
	IssuerID() string
	Subject(*oauth2.TokenRequest) string
	TypeHeader(*oauth2.TokenRequest) string
	Audience(*oauth2.TokenRequest) []string
	AddClaims(*oauth2.TokenRequest) map[string]any
	TokenExpiry() int64
}

const subjectParam = "subject"

// DefaultCallback mirrors DefaultOAuth2TokenCallback.
type DefaultCallback struct {
	Issuer string
	// SubjectValue is the fixed subject; Subject is the interface method.
	SubjectValue string
	Type         string
	// AudienceValue is nil when not explicitly set (empty list is a valid value).
	AudienceValue []string
	Claims        map[string]any
	Expiry        int64
}

// NewDefaultCallback returns the implicit fallback callback for an issuer:
// random subject, typ JWT, 3600s expiry.
func NewDefaultCallback(issuerID string) *DefaultCallback {
	return &DefaultCallback{
		Issuer:       issuerID,
		SubjectValue: randomUUID(),
		Type:         "JWT",
		Expiry:       3600,
	}
}

func (c *DefaultCallback) IssuerID() string { return c.Issuer }

func (c *DefaultCallback) Subject(req *oauth2.TokenRequest) string {
	if req.GrantType == oauth2.GrantClientCredentials {
		return req.ClientID
	}
	return c.SubjectValue
}

func (c *DefaultCallback) TypeHeader(*oauth2.TokenRequest) string { return c.Type }

func (c *DefaultCallback) Audience(req *oauth2.TokenRequest) []string {
	switch {
	case c.AudienceValue != nil:
		return c.AudienceValue
	case len(req.Audience) > 0:
		return req.Audience
	case req.Scope != "":
		return req.ScopesWithoutOIDC()
	default:
		return []string{"default"}
	}
}

func (c *DefaultCallback) AddClaims(req *oauth2.TokenRequest) map[string]any {
	claims := map[string]any{"tid": c.Issuer}
	for k, v := range c.Claims {
		claims[k] = v
	}
	if req.GrantType == oauth2.GrantAuthorizationCode {
		claims["azp"] = req.ClientID
	}
	return claims
}

func (c *DefaultCallback) TokenExpiry() int64 { return c.Expiry }

// Mapping mirrors RequestMapping: match a form parameter by exact value, "*"
// or full regex, and contribute claims + typ header.
type Mapping struct {
	RequestParam string
	Match        string
	Claims       map[string]any
	TypeHeader   string

	matchRegex *regexp.Regexp
	regexTried bool
}

func (m *Mapping) regex() *regexp.Regexp {
	if !m.regexTried {
		m.regexTried = true
		if m.Match != "*" {
			if re, err := regexp.Compile(m.Match); err == nil {
				m.matchRegex = re
			}
			// invalid regex: exact-string matching only, like upstream
		}
	}
	return m.matchRegex
}

func (m *Mapping) isMatch(form map[string][]string, req *oauth2.TokenRequest, extra map[string]string) bool {
	var values []string
	if vs := form[m.RequestParam]; len(vs) > 0 {
		values = vs
	} else if m.RequestParam == "client_id" {
		if req.ClientID != "" {
			values = []string{req.ClientID}
		}
	} else if v, ok := extra[m.RequestParam]; ok {
		values = []string{v}
	}
	for _, v := range values {
		if m.Match == "*" || m.Match == v {
			return true
		}
		if re := m.regex(); re != nil && anchored(re).MatchString(v) {
			return true
		}
	}
	return false
}

// anchored wraps a compiled regex so it matches the entire value,
// equivalent to Kotlin matchEntire.
func anchored(re *regexp.Regexp) *regexp.Regexp {
	pattern := `\A(?:` + re.String() + `)\z`
	if wrapped, err := regexp.Compile(pattern); err == nil {
		return wrapped
	}
	return re
}

// MappingCallback mirrors RequestMappingTokenCallback: per-issuer list of
// request mappings; the first match contributes claims/typ header.
type MappingCallback struct {
	IssuerIDValue string
	Mappings      []*Mapping
	Expiry        int64
}

func (c *MappingCallback) IssuerID() string { return c.IssuerIDValue }

func (c *MappingCallback) TokenExpiry() int64 { return c.Expiry }

// WithExtraMatchParams returns a view that supplements matching with extra
// key/values (e.g. subject = login username), used only when the token request
// has no such form parameter.
func (c *MappingCallback) WithExtraMatchParams(extra map[string]string) Callback {
	return &mappingWithExtra{c: c, extra: extra}
}

func (c *MappingCallback) resolve(req *oauth2.TokenRequest, extra map[string]string) (map[string]any, string) {
	var matched *Mapping
	for _, m := range c.Mappings {
		if m.isMatch(req.Form, req, extra) {
			matched = m
			break
		}
	}
	claims := map[string]any{}
	if matched != nil {
		for k, v := range matched.Claims {
			claims[k] = v
		}
	}
	// Template variable precedence: extra < form params < client_id.
	params := map[string]string{}
	for k, v := range extra {
		params[k] = v
	}
	for k, vs := range req.Form {
		params[k] = strings.Join(vs, " ")
	}
	params["clientId"] = req.ClientID
	params["client_id"] = req.ClientID
	templated := templateValues(claims, params)

	typ := "JWT"
	if matched != nil && matched.TypeHeader != "" {
		typ = matched.TypeHeader
	}
	return templated, typ
}

func (c *MappingCallback) Subject(req *oauth2.TokenRequest) string {
	claims, _ := c.resolve(req, nil)
	s, _ := claims["sub"].(string)
	return s
}

func (c *MappingCallback) TypeHeader(req *oauth2.TokenRequest) string {
	_, typ := c.resolve(req, nil)
	return typ
}

func (c *MappingCallback) Audience(req *oauth2.TokenRequest) []string {
	claims, _ := c.resolve(req, nil)
	return audienceFrom(claims["aud"])
}

func (c *MappingCallback) AddClaims(req *oauth2.TokenRequest) map[string]any {
	claims, _ := c.resolve(req, nil)
	return claims
}

type mappingWithExtra struct {
	c     *MappingCallback
	extra map[string]string
}

func (w *mappingWithExtra) IssuerID() string { return w.c.IssuerID() }

func (w *mappingWithExtra) Subject(req *oauth2.TokenRequest) string {
	claims, _ := w.c.resolve(req, w.extra)
	s, _ := claims["sub"].(string)
	return s
}

func (w *mappingWithExtra) TypeHeader(req *oauth2.TokenRequest) string {
	_, typ := w.c.resolve(req, w.extra)
	return typ
}

func (w *mappingWithExtra) Audience(req *oauth2.TokenRequest) []string {
	claims, _ := w.c.resolve(req, w.extra)
	return audienceFrom(claims["aud"])
}

func (w *mappingWithExtra) AddClaims(req *oauth2.TokenRequest) map[string]any {
	claims, _ := w.c.resolve(req, w.extra)
	return claims
}

func (w *mappingWithExtra) TokenExpiry() int64 { return w.c.TokenExpiry() }

func audienceFrom(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// templateValues replaces ${var} occurrences in string claim values.
func templateValues(claims map[string]any, params map[string]string) map[string]any {
	out := make(map[string]any, len(claims))
	for k, v := range claims {
		if s, ok := v.(string); ok {
			for name, val := range params {
				s = strings.ReplaceAll(s, "${"+name+"}", val)
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}
