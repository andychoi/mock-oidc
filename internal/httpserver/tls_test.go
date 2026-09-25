package httpserver

import (
	"crypto/tls"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelfSignedTLS(t *testing.T) {
	setup, err := NewTLS(Options{})
	if err != nil {
		t.Fatal(err)
	}

	leaf := setup.Certificates[0]
	if leaf.Subject.CommonName != "localhost" {
		t.Errorf("CN = %q", leaf.Subject.CommonName)
	}
	foundSAN := map[string]bool{}
	for _, n := range leaf.DNSNames {
		foundSAN[n] = true
	}
	hasLoopbackIP := false
	for _, ip := range leaf.IPAddresses {
		if ip.String() == "127.0.0.1" {
			hasLoopbackIP = true
		}
	}
	if !foundSAN["localhost"] || !hasLoopbackIP {
		t.Errorf("SANs: dns=%v ips=%v", leaf.DNSNames, leaf.IPAddresses)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) < 364*24*time.Hour {
		t.Errorf("cert validity too short: %v", leaf.NotAfter.Sub(leaf.NotBefore))
	}

	// serve real TLS and fetch with the trust pool
	ln, err := tls.Listen("tcp", "127.0.0.1:0", setup.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secure"))
	}))

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: setup.TrustPool()}}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("TLS fetch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status %d", resp.StatusCode)
	}
}

func TestKeystoreTLS(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available to build a PKCS12 fixture")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.pem")
	certFile := filepath.Join(dir, "cert.pem")
	p12File := filepath.Join(dir, "keystore.p12")
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command(openssl, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	run("req", "-x509", "-newkey", "rsa:2048", "-keyout", keyFile, "-out", certFile,
		"-days", "2", "-nodes", "-subj", "/CN=localhost")
	// default openssl >= 3 output (PBES2/AES + SHA-256 MAC) must load — that is
	// also what keytool writes since JDK 18.
	run("pkcs12", "-export", "-out", p12File, "-inkey", keyFile, "-in", certFile,
		"-passout", "pass:store-secret")

	setup, err := NewTLS(Options{KeystoreFile: p12File, KeystoreType: "PKCS12", KeystorePassword: "store-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if setup.Certificates[0].Subject.CommonName != "localhost" {
		t.Errorf("CN = %q", setup.Certificates[0].Subject.CommonName)
	}

	// wrong password fails
	if _, err := NewTLS(Options{KeystoreFile: p12File, KeystoreType: "PKCS12", KeystorePassword: "wrong"}); err == nil {
		t.Errorf("wrong keystore password should fail")
	}

	// JKS rejected with a helpful message
	if _, err := NewTLS(Options{KeystoreFile: p12File, KeystoreType: "JKS"}); err == nil ||
		!strings.Contains(err.Error(), "keytool -importkeystore") {
		t.Errorf("JKS should be rejected with conversion hint: %v", err)
	}

	// missing file
	if _, err := NewTLS(Options{KeystoreFile: filepath.Join(dir, "nope.p12"), KeystoreType: "PKCS12"}); err == nil {
		t.Errorf("missing keystore should fail")
	}
}
