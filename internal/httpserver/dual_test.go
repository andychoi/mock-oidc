package httpserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedPEM writes a throwaway cert/key for oidc.dev.test + 127.0.0.1 and
// returns their paths plus a pool trusting the cert.
func selfSignedPEM(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "oidc.dev.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"oidc.dev.test"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	c, _ := x509.ParseCertificate(der)
	pool.AddCert(c)
	return certFile, keyFile, pool
}

// TestDualServesPlainAndTLS: one port, both protocols — a plain HTTP request
// and a TLS request to the same listener both reach the handler.
func TestDualServesPlainAndTLS(t *testing.T) {
	certFile, keyFile, pool := selfSignedPEM(t)
	setup, err := NewTLS(Options{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dual := Dual(ln, setup.Config)
	go func() { _ = http.Serve(dual, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})) }()

	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := plain.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("plain fetch: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Errorf("plain: status %d body %q", resp.StatusCode, body)
	}

	secure := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	resp, err = secure.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("TLS fetch: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Errorf("tls: status %d body %q", resp.StatusCode, body)
	}
}

// TestDualSilentClientDoesNotStallAccept: a client that connects and sends
// nothing must not block other connections (the peek is lazy on first Read).
func TestDualSilentClientDoesNotStallAccept(t *testing.T) {
	certFile, keyFile, _ := selfSignedPEM(t)
	setup, err := NewTLS(Options{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = http.Serve(Dual(ln, setup.Config), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})) }()

	silent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("plain fetch behind a silent client: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
}

// TestRequestIsTLSBehindDual: TLS traffic served through the sniffing wrapper
// must be reported as https even though net/http never sees the *tls.Conn —
// discovery advertises issuer/endpoint URLs from exactly this signal.
func TestRequestIsTLSBehindDual(t *testing.T) {
	certFile, keyFile, pool := selfSignedPEM(t)
	setup, err := NewTLS(Options{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, fmt.Sprintf("%v", RequestIsTLS(r)))
	})
	srv := NewServer(handler)
	go func() { _ = srv.Serve(Dual(ln, setup.Config)) }()

	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := plain.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("plain fetch: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "false" {
		t.Errorf("plain: RequestIsTLS = %q, want false", body)
	}

	secure := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	resp, err = secure.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("TLS fetch: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "true" {
		t.Errorf("tls: RequestIsTLS = %q, want true", body)
	}
}

// TestDualCloseWithoutResolving: a connection closed before its first Read
// must not wedge the listener.
func TestDualCloseWithoutResolving(t *testing.T) {
	certFile, keyFile, _ := selfSignedPEM(t)
	setup, err := NewTLS(Options{CertFile: certFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = http.Serve(Dual(ln, setup.Config), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})) }()

	dead, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = dead.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("plain fetch after an unresolve-close: %v", err)
	}
	resp.Body.Close()
}
