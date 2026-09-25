package debugger

import (
	"crypto/x509"
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

//go:embed templates/debugger.html.tmpl templates/debugger_callback.html.tmpl templates/error.html.tmpl
var templateFS embed.FS

// OwnURL resolves the server's own bound URL for a path (httpServer.url(path)):
// the base the server actually listens on, switched to loopback for wildcard
// binds, so the debugger's token exchange never targets a client-controlled
// host.
type OwnURL func(path string) string

// TrustPool resolves the server's own TLS certificate pool (nil for plain
// HTTP); the internal token exchange then trusts exactly the server's own
// certificate.
type TrustPool func() *x509.CertPool

// Handler serves /debugger and /debugger/callback.
type Handler struct {
	sessions  *sessionManager
	ownURL    OwnURL
	trustPool TrustPool
	client    *http.Client
}

// New builds the debugger handler.
func New(ownURL OwnURL, trustPool TrustPool) *Handler {
	return &Handler{
		sessions:  newSessionManager(),
		ownURL:    ownURL,
		trustPool: trustPool,
		client:    &http.Client{},
	}
}

// Register wires the routes into the router. Handlers catch their own errors
// and render the HTML error page (the nested exceptionHandler upstream).
func (h *Handler) Register(rt *routing.Router) {
	rt.Get(oauth2.Debugger, h.wrap(h.form))
	rt.Post(oauth2.Debugger, h.wrap(h.submit))
	rt.Any(oauth2.DebuggerCallback, h.wrap(h.callback))
}

func (h *Handler) wrap(fn func(*oauth2.Request) routing.Response) routing.Handler {
	return func(req *oauth2.Request) (resp routing.Response) {
		defer func() {
			if rec := recover(); rec != nil {
				resp = h.errorResponse(req, rec)
			}
		}()
		return fn(req)
	}
}

func (h *Handler) errorResponse(req *oauth2.Request, rec any) routing.Response {
	session := h.sessions.session(req)
	message := fmt.Sprint(rec)
	if err, ok := rec.(error); ok {
		message = err.Error()
	}
	tmpl, terr := template.ParseFS(templateFS, "templates/error.html.tmpl")
	if terr != nil {
		return routing.HTML("debugger error: " + message)
	}
	var body strings.Builder
	data := map[string]string{
		"debugger_url": req.EndpointURL(oauth2.Debugger),
		"stacktrace":   message,
	}
	if terr := tmpl.Execute(&body, data); terr != nil {
		return routing.HTML("debugger error: " + message)
	}
	resp := routing.Response{Status: 500, Header: http.Header{}}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Add("Set-Cookie", session.asCookie(h.sessions))
	resp.Body = body.String()
	return resp
}

// form renders the debugger entry form with prefilled authorization request
// parameters (GET /debugger).
func (h *Handler) form(req *oauth2.Request) routing.Response {
	callbackURL := req.EndpointURL(oauth2.DebuggerCallback)
	prefill := url.Values{}
	prefill.Set("client_id", "debugger")
	prefill.Set("response_type", "code")
	prefill.Set("redirect_uri", callbackURL)
	prefill.Set("response_mode", "query")
	prefill.Set("scope", "openid somescope")
	prefill.Set("state", "1234")
	prefill.Set("nonce", "5678")

	authorizeURL := req.EndpointURL(oauth2.Authorization) + "?" + prefill.Encode()

	tmpl, err := template.ParseFS(templateFS, "templates/debugger.html.tmpl")
	if err != nil {
		panic(err)
	}
	var body strings.Builder
	err = tmpl.Execute(&body, map[string]any{
		"authorize_url":      authorizeURL,
		"token_url":          req.EndpointURL(oauth2.Token),
		"client_auth_method": "CLIENT_SECRET_BASIC",
		"client_id":          prefill.Get("client_id"),
		"client_secret":      "someSecret",
		"scope":              prefill.Get("scope"),
		"response_type":      prefill.Get("response_type"),
		"response_mode":      prefill.Get("response_mode"),
		"state":              prefill.Get("state"),
		"nonce":              prefill.Get("nonce"),
		"redirect_uri":       callbackURL,
	})
	if err != nil {
		panic(err)
	}
	return routing.HTML(body.String())
}

// submit redirects to this server's own authorize endpoint with the submitted
// parameters, stashing them in the encrypted session cookie. The redirect
// target derives from the request URL, never the submitted form (SSRF fix).
func (h *Handler) submit(req *oauth2.Request) routing.Response {
	callbackURL := req.EndpointURL(oauth2.DebuggerCallback)

	// Authorize URL query: the raw body pairs minus internal fields, plus the
	// server-derived redirect_uri.
	var kept []string
	for _, pair := range strings.Split(req.Body, "&") {
		if pair == "" {
			continue
		}
		rawKey := pair
		if i := strings.Index(pair, "="); i != -1 {
			rawKey = pair[:i]
		}
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		switch key {
		case "authorize_url", "token_url", "client_secret", "client_auth_method", "redirect_uri":
			continue
		}
		kept = append(kept, pair)
	}
	kept = append(kept, "redirect_uri="+url.QueryEscape(callbackURL))
	authorizeURL := req.EndpointURL(oauth2.Authorization) + "?" + strings.Join(kept, "&")

	session := h.sessions.session(req)
	form := map[string]string{}
	for k, vs := range req.Form() {
		if len(vs) > 0 {
			form[k] = vs[len(vs)-1]
		}
	}
	session.putAll(form)
	session.putAll(map[string]string{"redirect_uri": callbackURL})

	resp := routing.Redirect(authorizeURL)
	resp.Header.Add("Set-Cookie", session.asCookie(h.sessions))
	return resp
}

// callback exchanges the code through the token endpoint and renders the
// request/response pair (ANY /debugger/callback).
func (h *Handler) callback(req *oauth2.Request) routing.Response {
	session := h.sessions.session(req)

	tokenEndpointURL := req.EndpointURL(oauth2.Token)
	targetURL := h.ownURL(tokenEndpointPath(req.IssuerID()))

	code := req.QueryParam("code")
	if code == "" {
		code = req.FormParam("code")
	}
	if code == "" {
		panic(fmt.Errorf("no code parameter present"))
	}

	clientID, err := session.get("client_id")
	if err != nil {
		panic(err)
	}
	clientSecret, err := session.get("client_secret")
	if err != nil {
		panic(err)
	}
	authMethod, err := session.get("client_auth_method")
	if err != nil {
		panic(err)
	}
	if authMethod != "CLIENT_SECRET_BASIC" && authMethod != "CLIENT_SECRET_POST" {
		panic(fmt.Errorf("invalid client_auth_method %q", authMethod))
	}

	scope, err := session.get("scope")
	if err != nil {
		panic(err)
	}
	redirectURI, err := session.get("redirect_uri")
	if err != nil {
		panic(err)
	}

	body := "grant_type=authorization_code" +
		"&code=" + code +
		"&scope=" + url.QueryEscape(scope) +
		"&redirect_uri=" + url.QueryEscape(redirectURI)
	if authMethod == "CLIENT_SECRET_POST" {
		body += "&client_id=" + url.QueryEscape(clientID) + "&client_secret=" + url.QueryEscape(clientSecret)
	}

	// The request goes to the server's bound address while the headers
	// reproduce the externally visible URL, so the issued token carries the
	// issuer a real client would see.
	tokenURL, perr := url.Parse(tokenEndpointURL)
	if perr != nil {
		panic(perr)
	}
	httpReq, err := http.NewRequest(http.MethodPost, targetURL, strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Host", hostHeader(tokenURL, false))
	httpReq.Header.Set("x-forwarded-proto", tokenURL.Scheme)
	httpReq.Header.Set("x-forwarded-port", portOf(tokenURL))
	if authMethod == "CLIENT_SECRET_BASIC" {
		httpReq.Header.Set("Authorization", "Basic "+base64Basic(clientID, clientSecret))
	}

	client := h.client
	if pool := h.trustPool(); pool != nil {
		client = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfigFor(pool)}}
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	dump := tokenRequestDump(tokenURL, authMethod, clientID, clientSecret, body)

	tmpl, err := template.ParseFS(templateFS, "templates/debugger_callback.html.tmpl")
	if err != nil {
		panic(err)
	}
	var html strings.Builder
	if err := tmpl.Execute(&html, map[string]string{
		"token_request":  dump,
		"token_response": string(respBody),
	}); err != nil {
		panic(err)
	}
	return routing.HTML(html.String())
}

// tokenRequestDump renders the request the way Client.kt's TokenRequest
// toString does.
func tokenRequestDump(tokenURL *url.URL, authMethod, clientID, clientSecret, body string) string {
	var b strings.Builder
	b.WriteString("POST " + tokenURL.EscapedPath() + " HTTP/1.1\n")
	b.WriteString("Host: " + hostHeader(tokenURL, true) + "\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\n")
	if authMethod == "CLIENT_SECRET_BASIC" {
		b.WriteString("Authorization: Basic " + base64Basic(clientID, clientSecret) + "\n")
	}
	b.WriteString("\n\n" + body)
	return b.String()
}

func hostHeader(u *url.URL, includeDefaultPort bool) string {
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	if includeDefaultPort || !((u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443")) {
		return host + ":" + port
	}
	return host
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

// tokenEndpointPath mirrors HttpUrl.tokenEndpointPath: /<issuerId>/token (or
// /token for the root issuer).
func tokenEndpointPath(issuerID string) string {
	if issuerID == "" {
		return oauth2.Token
	}
	return "/" + issuerID + oauth2.Token
}
