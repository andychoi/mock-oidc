package oauth2

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// MaxBodyBytes mirrors the 1 MiB body cap enforced by the Netty pipeline upstream.
const MaxBodyBytes = 1 << 20

// ErrBodyTooLarge is returned by FromHTTPRequest when the body exceeds MaxBodyBytes.
var ErrBodyTooLarge = fmt.Errorf("request body exceeds %d bytes", MaxBodyBytes)

// Request is the Go equivalent of OAuth2HttpRequest: a normalized request with
// the raw body kept as a string and a proxy-aware view of the URL.
type Request struct {
	Method string
	Header http.Header
	// URL is the original request URL (path + query); scheme/host come from the
	// transport (or Host header) at capture time.
	URL    *url.URL
	scheme string
	Body   string

	form url.Values
}

// FromHTTPRequest reads the body (capped at MaxBodyBytes) and captures scheme
// and host information needed for proxy-aware URL derivation.
func FromHTTPRequest(r *http.Request) (*Request, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	var body []byte
	var err error
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
		if err != nil {
			return nil, err
		}
		if len(body) > MaxBodyBytes {
			return nil, ErrBodyTooLarge
		}
	}
	u := *r.URL
	if !u.IsAbs() {
		// Server-side request URLs are path-only; keep them that way and derive
		// scheme/host/port from headers (see ProxyAwareURL).
		u.Scheme = ""
		u.Host = ""
	}
	header := r.Header
	if header == nil {
		header = http.Header{}
	}
	if r.Host != "" && header.Get("Host") == "" {
		// net/http keeps the Host in r.Host, not r.Header; mirror it so the
		// proxy-aware URL derivation sees it like the Kotlin server does.
		header = header.Clone()
		header.Set("Host", r.Host)
	}
	return &Request{
		Method: r.Method,
		Header: header,
		URL:    &u,
		scheme: scheme,
		Body:   string(body),
	}, nil
}

// ProxyAwareURL returns scheme://host[:port] with the original path and query,
// honoring x-forwarded-proto, the Host header and x-forwarded-port the same way
// as OAuth2HttpRequest.proxyAwareUrl (which never elides explicit ports but lets
// the URL builder drop scheme-default ports).
func (r *Request) ProxyAwareURL() *url.URL {
	scheme := r.Header.Get("x-forwarded-proto")
	if scheme == "" {
		scheme = r.scheme
	}
	host, hostPort := parseHostHeader(r.Header.Get("Host"))

	port := -1
	if p := r.Header.Get("x-forwarded-port"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	if port == -1 && hostPort != -1 {
		port = hostPort
	}
	if port == -1 && r.Header.Get("x-forwarded-proto") != "" {
		if r.Header.Get("x-forwarded-proto") == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	hostPortStr := ""
	if port != -1 && !(scheme == "http" && port == 80) && !(scheme == "https" && port == 443) {
		hostPortStr = host + ":" + strconv.Itoa(port)
	} else {
		hostPortStr = host
	}

	u := *r.URL
	u.Scheme = scheme
	u.Host = hostPortStr
	return &u
}

func parseHostHeader(h string) (host string, port int) {
	port = -1
	if h == "" {
		return "localhost", -1
	}
	if i := strings.LastIndex(h, ":"); i != -1 {
		if v, err := strconv.Atoi(h[i+1:]); err == nil {
			return h[:i], v
		}
	}
	return h, -1
}

// trimmedPath is the URL path with leading/trailing slashes removed, the same
// normalization used by HttpUrlExtensions.
func (r *Request) trimmedPath() string {
	return strings.Trim(r.URL.Path, "/")
}

// IssuerID derives the issuer id from the request path: everything before a
// known endpoint suffix (mirrors HttpUrlExtensions.issuerId, quirks included:
// a bare "/token" at the root does not strip the suffix and yields "token").
func (r *Request) IssuerID() string {
	path := r.trimmedPath()
	for _, e := range Endpoints {
		if strings.HasSuffix(path, e) {
			return path[:strings.Index(path, e)]
		}
	}
	return path
}

// baseURL is scheme://host[:port] of the proxy-aware URL, no path.
func (r *Request) baseURL() string {
	u := r.ProxyAwareURL()
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// IssuerURL returns the issuer URL for this request: base URL + /issuerId,
// with no trailing slash (empty issuerId yields the bare base URL).
func (r *Request) IssuerURL() string {
	return r.endpointURL("")
}

// EndpointURL returns <issuer><suffix>, e.g. .../oidc/token.
func (r *Request) EndpointURL(suffix string) string {
	return r.endpointURL(suffix)
}

func (r *Request) endpointURL(suffix string) string {
	id := r.IssuerID()
	parts := make([]string, 0, 2)
	if id != "" {
		parts = append(parts, id)
	}
	s := strings.Trim(suffix, "/")
	if s != "" {
		parts = append(parts, s)
	}
	base := r.baseURL()
	if len(parts) == 0 {
		return base
	}
	return base + "/" + strings.Join(parts, "/")
}

// Form lazily parses the request body as a form parameter multimap. Values are
// URL-decoded; repeated keys are kept. This mirrors nimbus
// HTTPRequest.bodyAsFormParameters (used for token requests) and is also used
// where upstream uses the single-value Parameters view — the two differ only
// for malformed input upstream.
func (r *Request) Form() url.Values {
	if r.form != nil {
		return r.form
	}
	r.form = url.Values{}
	if r.Body == "" {
		return r.form
	}
	for _, pair := range strings.Split(r.Body, "&") {
		if !strings.Contains(pair, "=") {
			continue
		}
		kv := strings.SplitN(pair, "=", 2)
		r.form.Add(decodeFormValue(kv[0]), decodeFormValue(kv[1]))
	}
	return r.form
}

// FormParam returns the last value of a form parameter (the single-value view
// upstream uses for username/claims/token/grant_type).
func (r *Request) FormParam(name string) string {
	vs := r.Form()[name]
	if len(vs) == 0 {
		return ""
	}
	return vs[len(vs)-1]
}

func decodeFormValue(s string) string {
	d, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return d
}

// QueryParam returns a query string parameter of the request URL.
func (r *Request) QueryParam(name string) string {
	return r.URL.Query().Get(name)
}

// BasicAuth decodes an Authorization: Basic header, returning
// (username, password, true) when present.
func (r *Request) BasicAuth() (string, string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return "", "", false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	return user, pass, ok
}
