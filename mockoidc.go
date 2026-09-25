// Package mockoidc is the importable library facade — the Go equivalent of
// the MockOAuth2Server test class. Start it on a random port in tests, or use
// cmd/mock-oidc for the standalone server.
package mockoidc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"

	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/httpserver"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/server"
	"github.com/andychoi/mock-oidc/internal/token"
)

// Server is a running mock OIDC server instance.
type Server struct {
	srv      *server.Server
	http     *http.Server
	listener net.Listener
	tlsSetup *httpserver.TLS
}

// Option configures a Server at construction.
type Option func(*Server)

// WithRoutes registers additional routes that take precedence over the
// built-in authorization server routes (MockOAuth2Server's vararg routes).
func WithRoutes(method, path string, h routing.Handler) Option {
	return func(s *Server) {
		s.srv.AddRouteFront(method, path, h)
	}
}

// New creates a server for the config (nil means library defaults:
// non-interactive login, RS256). When cfg.SSL is set the server serves TLS
// (self-signed localhost certificate unless a keystore is configured).
func New(cfg *config.OAuth2Config, opts ...Option) (*Server, error) {
	if cfg == nil {
		kp, err := token.DefaultKeyProvider("RS256")
		if err != nil {
			return nil, err
		}
		cfg = &config.OAuth2Config{TokenProvider: token.NewTokenProvider(kp, nil)}
	}
	if cfg.TokenProvider == nil {
		kp, err := token.DefaultKeyProvider("RS256")
		if err != nil {
			return nil, err
		}
		cfg.TokenProvider = token.NewTokenProvider(kp, nil)
	}

	s := &Server{}
	if cfg.SSL != nil {
		setup, err := httpserver.NewTLS(httpserver.Options{
			KeyPassword:      cfg.SSL.KeyPassword,
			KeystoreFile:     cfg.SSL.KeystoreFile,
			KeystoreType:     cfg.SSL.KeystoreType,
			KeystorePassword: cfg.SSL.KeystorePassword,
		})
		if err != nil {
			return nil, err
		}
		s.tlsSetup = setup
	}

	s.srv = server.New(cfg,
		server.WithOwnBase(func() string { return s.baseURL() }),
		server.WithTrustPool(s.tlsPool()),
	)
	for _, opt := range opts {
		opt(s)
	}
	s.http = &http.Server{Handler: s.srv.Handler()}
	return s, nil
}

// Start binds and serves on the address (":0" picks a random port).
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if s.tlsSetup != nil {
		ln = tls.NewListener(ln, s.tlsSetup.Config)
	}
	s.listener = ln
	go func() { _ = s.http.Serve(ln) }()
	return nil
}

// Stop shuts the server down.
func (s *Server) Stop() error {
	if s.http == nil {
		return nil
	}
	return s.http.Close()
}

func (s *Server) baseURL() string {
	if s.listener == nil {
		return ""
	}
	scheme := "http"
	if s.tlsSetup != nil {
		scheme = "https"
	}
	addr := s.listener.Addr().String()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return scheme + "://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port))
}

func (s *Server) tlsPool() *x509.CertPool {
	if s.tlsSetup == nil {
		return nil
	}
	return s.tlsSetup.TrustPool()
}

// URL returns the base URL of the running server.
func (s *Server) URL() string {
	return s.baseURL()
}

// IssuerURL returns the issuer URL for an issuerId.
func (s *Server) IssuerURL(issuerID string) string {
	if issuerID == "" {
		return s.URL()
	}
	return s.URL() + "/" + issuerID
}

// EnqueueTokenCallback queues a token callback for the next token request on
// a matching issuer (FIFO, library API like enqueueCallback).
func (s *Server) EnqueueTokenCallback(cb *token.DefaultCallback) {
	s.srv.EnqueueTokenCallback(cb)
}

// IssueToken mints a signed access token for the issuer with the given claims
// (systemTime-aware), like MockOAuth2Server.issueToken.
func (s *Server) IssueToken(issuerID string, claims map[string]any, expiry int64) string {
	if expiry == 0 {
		expiry = 3600
	}
	cb := token.NewDefaultCallback(issuerID)
	cb.Claims = claims
	cb.Expiry = expiry
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		cb.SubjectValue = sub
	}
	return s.srv.TokenProvider().IssueToken(s.IssuerURL(issuerID), issuerID, cb)
}
