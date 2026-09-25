// Command mock-oidc is the standalone mock OIDC server (the Go equivalent of
// StandaloneMockOAuth2Server.kt): env-based config, /isalive route, optional
// TLS from httpServer.ssl in the config.
package main

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/andychoi/mock-oidc/internal/config"
	"github.com/andychoi/mock-oidc/internal/httpserver"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/server"
)

func main() {
	level := slog.LevelInfo
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	cfg, err := config.LoadStandalone(os.Getenv)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	var tlsSetup *httpserver.TLS
	if cfg.SSL != nil {
		tlsSetup, err = httpserver.NewTLS(httpserver.Options{
			KeyPassword:      cfg.SSL.KeyPassword,
			KeystoreFile:     cfg.SSL.KeystoreFile,
			KeystoreType:     cfg.SSL.KeystoreType,
			KeystorePassword: cfg.SSL.KeystorePassword,
		})
		if err != nil {
			slog.Error("failed to configure TLS", "error", err)
			os.Exit(1)
		}
	}

	// ownBase is resolved lazily by the debugger at request time; it is filled
	// in once the listener exists. The server reads it through this stable
	// closure so reassignment below is visible.
	ownBase := func() string { return "" }
	srv := server.New(cfg, server.WithOwnBase(func() string { return ownBase() }))
	srv.AddRouteFront(http.MethodGet, "/isalive", func(*oauth2.Request) routing.Response {
		resp := routing.Response{Status: 200, Header: http.Header{}}
		resp.Body = "alive and well"
		return resp
	})

	addr := net.JoinHostPort(os.Getenv("SERVER_HOSTNAME"), strconv.Itoa(listenPort()))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("failed to bind", "addr", addr, "error", err)
		os.Exit(1)
	}
	bindHost, bindPort, _ := net.SplitHostPort(ln.Addr().String())
	scheme := "http"
	if tlsSetup != nil {
		ln = tls.NewListener(ln, tlsSetup.Config)
		scheme = "https"
		srv.SetTrustPool(tlsSetup.TrustPool())
	}
	base := scheme + "://" + net.JoinHostPort(loopbackIfWildcard(bindHost), bindPort)
	ownBase = func() string { return base }

	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() {
		slog.Info("starting mock-oidc", "addr", addr, "base", base,
			"interactiveLogin", cfg.InteractiveLogin, "tls", tlsSetup != nil)
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	slog.Info("shutting down")
	_ = httpSrv.Close()
}

func loopbackIfWildcard(host string) string {
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "127.0.0.1"
	}
	return host
}

func listenPort() int {
	if p := os.Getenv("SERVER_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			return v
		}
	}
	if p := os.Getenv("PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			return v
		}
	}
	return 8080
}
