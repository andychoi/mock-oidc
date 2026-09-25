// Package server assembles the route table (the Go equivalent of
// OAuth2HttpRequestHandler.authorizationServer) from the config, grant
// handlers and endpoint packages.
package server

import (
	"crypto/x509"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/cors"
	"github.com/andychoi/mock-oidc/internal/debugger"
	"github.com/andychoi/mock-oidc/internal/grant"
	"github.com/andychoi/mock-oidc/internal/introspect"
	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/login"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
	"github.com/andychoi/mock-oidc/internal/userinfo"
)

// discoveryAlgs is the id_token_signing_alg_values_supported list emitted by
// the upstream server (EC family first, then the RSA family incl. PS*).
var discoveryAlgs = []string{"ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}

// Server wires everything together for one OAuth2Config.
type Server struct {
	config    *config.OAuth2Config
	tp        *token.TokenProvider
	login     *login.Handler
	authCode  *grant.AuthorizationCode
	refresh   *grant.RefreshTokenManager
	grants    map[string]grant.Handler
	callbacks callbackQueue
	router    *routing.Router

	// ownBase resolves the server's own bound base URL for the debugger's
	// server-to-server token exchange (nil disables the debugger).
	ownBase func() string
	// trustPool is the server's own TLS certificate pool (nil for plain HTTP).
	trustPool *x509.CertPool
}

// Option configures a Server at construction.
type Option func(*Server)

// WithOwnBase sets the lazy resolver for the server's own bound base URL.
func WithOwnBase(fn func() string) Option { return func(s *Server) { s.ownBase = fn } }

// WithTrustPool sets the server's own TLS trust pool (self or keystore cert).
func WithTrustPool(pool *x509.CertPool) Option { return func(s *Server) { s.trustPool = pool } }

// callbackQueue mirrors the LinkedBlockingQueue peek/poll-by-issuer behavior.
type callbackQueue struct {
	mu    sync.Mutex
	items []token.Callback
}

func (q *callbackQueue) enqueue(cb token.Callback) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, cb)
}

// pollIfIssuerMatches removes and returns the head callback when its issuerId
// matches; otherwise returns nil (the callback stays queued).
func (q *callbackQueue) pollIfIssuerMatches(issuerID string) token.Callback {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) > 0 && q.items[0].IssuerID() == issuerID {
		cb := q.items[0]
		q.items = q.items[1:]
		return cb
	}
	return nil
}

// New builds a Server for the config.
func New(cfg *config.OAuth2Config, opts ...Option) *Server {
	refresh := grant.NewRefreshTokenManager()
	s := &Server{
		config:   cfg,
		tp:       cfg.TokenProvider,
		login:    &login.Handler{LoginPagePath: cfg.LoginPagePath},
		authCode: grant.NewAuthorizationCode(cfg.TokenProvider, refresh),
		refresh:  refresh,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.grants = map[string]grant.Handler{
		oauth2.GrantAuthorizationCode: s.authCode.TokenResponse,
		oauth2.GrantClientCredentials: grant.ClientCredentials(s.tp),
		oauth2.GrantJWTBearer:         grant.JWTBearer(s.tp),
		oauth2.GrantTokenExchange:     grant.TokenExchange(s.tp),
		oauth2.GrantRefreshToken:      grant.Refresh(s.tp, refresh, cfg.RotateRefreshToken, s.callbacks.pollIfIssuerMatches),
		oauth2.GrantPassword:          grant.Password(s.tp),
	}
	s.router = s.buildRouter()
	return s
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler { return s.router }

// AddRouteFront registers a route that takes precedence over built-ins
// (the additionalRoutes parameter of MockOAuth2Server).
func (s *Server) AddRouteFront(method, path string, h routing.Handler) {
	s.router.AddFront(method, path, h)
}

// EnqueueTokenCallback queues a library callback for the next matching token
// request (issuer-scoped, FIFO).
func (s *Server) EnqueueTokenCallback(cb token.Callback) {
	s.callbacks.enqueue(cb)
}

// TokenProvider exposes the token provider (library API for IssueToken).
func (s *Server) TokenProvider() *token.TokenProvider { return s.tp }

func (s *Server) buildRouter() *routing.Router {
	rt := routing.New()
	rt.AddResponseInterceptor(cors.Interceptor)

	rt.Get(oauth2.OAuth2WellKnown, s.wellKnown)
	rt.Get(oauth2.OIDCWellKnown, s.wellKnown)
	rt.Get(oauth2.JWKS, s.jwks)

	rt.Get(oauth2.Authorization, s.authorizeGet)
	rt.Post(oauth2.Authorization, s.authorizePost)

	rt.Get(oauth2.Token, func(*oauth2.Request) routing.Response {
		resp := routing.Response{Status: 405, Header: http.Header{}}
		resp.Body = "unsupported method"
		return resp
	})
	rt.Post(oauth2.Token, s.token)

	rt.Any(oauth2.EndSession, s.endSession)
	rt.Post(oauth2.Revoke, s.revoke)
	rt.Get(oauth2.UserInfo, userinfo.Handler(s.tp))
	rt.Post(oauth2.Introspect, introspect.Handler(s.tp))

	rt.Options(func(*oauth2.Request) routing.Response { return routing.Response{Status: 204, Header: http.Header{}} })

	if s.config.StaticAssetsPath != "" {
		rt.Get("/static/*", s.staticAsset)
	}
	rt.Get("/favicon.ico", func(*oauth2.Request) routing.Response {
		return routing.Response{Status: 200, Header: http.Header{}}
	})

	if s.ownBase != nil {
		debugger.New(s.ownURL, func() *x509.CertPool { return s.trustPool }).Register(rt)
	}
	return rt
}

// SetOwnBase replaces the own-base resolver; call before serving starts.
func (s *Server) SetOwnBase(fn func() string) { s.ownBase = fn }

// SetTrustPool sets the server's own TLS certificate pool; call before serving
// starts so the debugger's internal exchange trusts the server certificate.
func (s *Server) SetTrustPool(pool *x509.CertPool) { s.trustPool = pool }

// ownURL resolves the server's own URL for a path, switching wildcard binds to
// loopback so the debugger's exchange is connectable.
func (s *Server) ownURL(path string) string {
	base := s.ownBase()
	u, err := url.Parse(base)
	if err != nil {
		return base + path
	}
	host := u.Hostname()
	if host == "0.0.0.0" || host == "::" || host == "" {
		if u.Port() != "" {
			u.Host = "localhost:" + u.Port()
		} else {
			u.Host = "localhost"
		}
	}
	return u.String() + path
}

func (s *Server) wellKnown(req *oauth2.Request) routing.Response {
	doc := jsonx.Obj{
		{Name: "issuer", V: req.IssuerURL()},
		{Name: "authorization_endpoint", V: req.EndpointURL(oauth2.Authorization)},
		{Name: "end_session_endpoint", V: req.EndpointURL(oauth2.EndSession)},
		{Name: "revocation_endpoint", V: req.EndpointURL(oauth2.Revoke)},
		{Name: "token_endpoint", V: req.EndpointURL(oauth2.Token)},
		{Name: "userinfo_endpoint", V: req.EndpointURL(oauth2.UserInfo)},
		{Name: "jwks_uri", V: req.EndpointURL(oauth2.JWKS)},
		{Name: "introspection_endpoint", V: req.EndpointURL(oauth2.Introspect)},
		{Name: "response_types_supported", V: []string{"code", "none", "id_token", "token"}},
		{Name: "response_modes_supported", V: []string{"query", "fragment", "form_post"}},
		{Name: "subject_types_supported", V: []string{"public"}},
		{Name: "id_token_signing_alg_values_supported", V: discoveryAlgs},
		{Name: "code_challenge_methods_supported", V: []string{"plain", "S256"}},
	}
	return routing.JSON(doc)
}

func (s *Server) jwks(req *oauth2.Request) routing.Response {
	return routing.JSONString(s.tp.PublicJWKS(req.IssuerID()))
}

func (s *Server) authorizeGet(req *oauth2.Request) routing.Response {
	ar, err := oauth2.ParseAuthRequest(req.URL.Query())
	if err != nil {
		panic(err)
	}
	if s.config.InteractiveLogin || ar.IsPrompt() {
		html, oerr := s.login.LoginHTML(req)
		if oerr != nil {
			panic(oerr)
		}
		return routing.HTML(html)
	}
	return s.authenticationSuccess(req, ar, nil)
}

func (s *Server) authorizePost(req *oauth2.Request) routing.Response {
	ar, err := oauth2.ParseAuthRequest(req.URL.Query())
	if err != nil {
		panic(err)
	}
	lg, oerr := s.login.LoginSubmit(req)
	if oerr != nil {
		panic(oerr)
	}
	return s.authenticationSuccess(req, ar, &lg)
}

// authenticationSuccess mints the code and renders the 302 (or form_post
// auto-submit page) carrying code and state.
func (s *Server) authenticationSuccess(req *oauth2.Request, ar *oauth2.AuthRequest, lg *login.Login) routing.Response {
	code, oerr := s.authCode.AuthorizationCodeResponse(ar, lg)
	if oerr != nil {
		panic(oerr)
	}
	if ar.ResponseMode == "form_post" {
		return routing.HTML(formPostHTML(ar.RedirectURI, code, ar.State))
	}
	location, oerr := ar.SuccessRedirectURL(code)
	if oerr != nil {
		panic(oerr)
	}
	return routing.Redirect(location)
}

func (s *Server) token(req *oauth2.Request) routing.Response {
	grantType := strings.TrimSpace(req.FormParam("grant_type"))
	if grantType == "" {
		panic(oauth2.MissingParameter("grant_type"))
	}
	if grantType == oauth2.GrantTokenExchange {
		if oerr := tokenExchangeClientAuthPrecheck(req); oerr != nil {
			panic(oerr)
		}
	}
	tr, oerr := oauth2.ParseTokenRequest(req)
	if oerr != nil {
		panic(oerr)
	}
	issuerID := req.IssuerID()
	if grantType == oauth2.GrantTokenExchange {
		if oerr := oauth2.ValidateTokenExchangeClientAssertion(req, tr, req.IssuerURL()); oerr != nil {
			panic(oerr)
		}
	}

	var cb token.Callback
	if grantType == oauth2.GrantRefreshToken {
		// the refresh handler resolves stored/enqueued callbacks itself
		cb = token.NewDefaultCallback(issuerID)
	} else {
		cb = s.tokenCallbackFromQueueOrDefault(issuerID)
	}

	handler := s.grants[grantType]
	if handler == nil {
		panic(oauth2.UnsupportedGrantType(grantType))
	}
	return handler(req, tr, req.IssuerURL(), issuerID, cb)
}

// tokenExchangeClientAuthPrecheck applies the clientAuthentication() gate
// before grant-parameter parsing, so a token exchange without any client auth
// fails with the same error upstream emits.
func tokenExchangeClientAuthPrecheck(req *oauth2.Request) *oauth2.Error {
	if _, _, ok := req.BasicAuth(); ok {
		return nil
	}
	form := req.Form()
	if form.Get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" && form.Get("client_assertion") != "" {
		return nil
	}
	return oauth2.InvalidRequest("invalid request")
}

func (s *Server) tokenCallbackFromQueueOrDefault(issuerID string) token.Callback {
	if cb := s.callbacks.pollIfIssuerMatches(issuerID); cb != nil {
		return cb
	}
	for _, mcb := range s.config.TokenCallbacks {
		if mcb.IssuerID() == issuerID {
			return mcb
		}
	}
	return token.NewDefaultCallback(issuerID)
}

func (s *Server) endSession(req *oauth2.Request) routing.Response {
	if uri := req.QueryParam("post_logout_redirect_uri"); uri != "" {
		if state := req.QueryParam("state"); state != "" {
			return routing.Redirect(uri + "?state=" + state)
		}
		return routing.Redirect(uri)
	}
	return routing.HTML("logged out")
}

func (s *Server) revoke(req *oauth2.Request) routing.Response {
	hint := req.FormParam("token_type_hint")
	if hint != "refresh_token" {
		display := hint
		if display == "" {
			display = "null"
		}
		panic(oauth2.UnsupportedTokenType("unsupported token type: " + display))
	}
	s.refresh.Remove(req.FormParam("token"))
	return routing.Response{Status: 200, Header: http.Header{}}
}

// staticAsset serves files under /static/* from the configured root with the
// upstream's path handling: everything before the first path segment after
// the issuer is dropped, and the normalized path must stay inside the root.
func (s *Server) staticAsset(req *oauth2.Request) routing.Response {
	segments := strings.Split(strings.Trim(req.URL.Path, "/"), "/")
	if len(segments) > 1 {
		segments = segments[1:]
	}
	rel := filepath.Clean(strings.Join(segments, "/"))
	root, err := filepath.Abs(s.config.StaticAssetsPath)
	if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return routing.NotFound("not found")
	}
	full := filepath.Join(root, rel)
	if !strings.HasPrefix(full, root+string(filepath.Separator)) && full != root {
		return routing.NotFound("not found")
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return routing.NotFound("not found")
	}
	contentType := mime.TypeByExtension(filepath.Ext(full))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	resp := routing.Response{Status: 200, Header: http.Header{}}
	resp.Header.Set("Content-Type", contentType)
	resp.BodyBytes = data
	return resp
}

// formPostHTML renders the auto-submitting form_post response page.
func formPostHTML(redirectURI, code, state string) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html>\n<head><title>Submit</title></head>\n")
	b.WriteString("<body onload=\"document.forms[0].submit()\">\n")
	b.WriteString(`<form method="post" action="` + htmlEscape(redirectURI) + `">`)
	b.WriteString(`<input type="hidden" name="code" value="` + htmlEscape(code) + `"/>`)
	if state != "" {
		b.WriteString(`<input type="hidden" name="state" value="` + htmlEscape(state) + `"/>`)
	}
	b.WriteString("\n<noscript><button type=\"submit\">Continue</button></noscript>\n</form>\n</body>\n</html>")
	return b.String()
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return r.Replace(s)
}
