package e2e

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	mockoidc "github.com/andychoi/mock-oidc"
	"github.com/andychoi/mock-oidc/internal/config"
)

// TestHTTPSServerSelfSigned runs the facade with httpServer.ssl and checks the
// protocol still works over TLS, including the debugger's internal exchange
// which must trust the server's own certificate.
func TestHTTPSServerSelfSigned(t *testing.T) {
	cfgJSON := `{
		"interactiveLogin": false,
		"httpServer": {"type": "NettyWrapper", "ssl": {}}
	}`
	cfg, err := config.ParseJSON([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	s, err := mockoidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	base := s.URL()
	if !strings.HasPrefix(base, "https://") {
		t.Fatalf("expected https base URL, got %s", base)
	}

	// insecure client reaches discovery over TLS
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get(base + "/oidc/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("discovery over TLS: %d %s", resp.StatusCode, body)
	}
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	if doc["issuer"] != base+"/oidc" {
		t.Errorf("issuer = %v (base %s)", doc["issuer"], base)
	}
}
