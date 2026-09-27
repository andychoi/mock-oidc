package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andychoi/mock-oidc/internal/entra"
)

// The repo's real config must parse unchanged (the core compatibility case).
const repoConfig = `{
  "interactiveLogin": true,
  "loginPagePath": "/config/mock-oidc-login.html",
  "httpServer": "NettyWrapper",
  "tokenCallbacks": [
    {
      "issuerId": "oidc",
      "tokenExpiry": 3600,
      "requestMappings": [
        { "requestParam": "grant_type", "match": "authorization_code",
          "claims": { "tid": "mock-tenant-id" } }
      ]
    }
  ]
}`

func TestParseRepoConfig(t *testing.T) {
	cfg, err := ParseJSON([]byte(repoConfig))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InteractiveLogin || cfg.LoginPagePath != "/config/mock-oidc-login.html" {
		t.Errorf("interactiveLogin/loginPagePath: %+v", cfg)
	}
	if len(cfg.TokenCallbacks) != 1 {
		t.Fatalf("tokenCallbacks: %d", len(cfg.TokenCallbacks))
	}
	cb := cfg.TokenCallbacks[0]
	if cb.IssuerID() != "oidc" || cb.TokenExpiry() != 3600 {
		t.Errorf("callback: %s %d", cb.IssuerID(), cb.TokenExpiry())
	}
	if len(cb.Mappings) != 1 || cb.Mappings[0].Match != "authorization_code" {
		t.Errorf("mappings: %+v", cb.Mappings)
	}
	if cfg.TokenProvider == nil {
		t.Fatalf("token provider must default")
	}
}

func TestHTTPServerBothShapesIgnored(t *testing.T) {
	for _, json := range []string{
		`{"interactiveLogin":false,"httpServer":"NettyWrapper"}`,
		`{"interactiveLogin":false,"httpServer":{"type":"NettyWrapper","ssl":{"keystoreFile":"/tmp/x"}}}`,
	} {
		if _, err := ParseJSON([]byte(json)); err != nil {
			t.Errorf("httpServer shape rejected: %v (%s)", err, json)
		}
	}
}

func TestSSLConfig(t *testing.T) {
	// string form: no TLS
	cfg, err := ParseJSON([]byte(`{"httpServer":"NettyWrapper"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSL != nil {
		t.Errorf("string httpServer should not enable TLS")
	}

	// object form without ssl: no TLS
	cfg, err = ParseJSON([]byte(`{"httpServer":{"type":"NettyWrapper"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSL != nil {
		t.Errorf("httpServer object without ssl should not enable TLS")
	}

	// object form with ssl: TLS settings parsed
	cfg, err = ParseJSON([]byte(`{"httpServer":{"type":"NettyWrapper","ssl":{"keyPassword":"kp","keystoreFile":"/keys/server.p12","keystoreType":"PKCS12","keystorePassword":"sp"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSL == nil {
		t.Fatal("ssl block not parsed")
	}
	if cfg.SSL.KeyPassword != "kp" || cfg.SSL.KeystoreFile != "/keys/server.p12" ||
		cfg.SSL.KeystoreType != "PKCS12" || cfg.SSL.KeystorePassword != "sp" {
		t.Errorf("ssl settings: %+v", cfg.SSL)
	}

	// empty ssl object: self-signed mode
	cfg, err = ParseJSON([]byte(`{"httpServer":{"type":"NettyWrapper","ssl":{}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSL == nil || cfg.SSL.KeystoreFile != "" {
		t.Errorf("empty ssl block should mean self-signed: %+v", cfg.SSL)
	}
}

func TestTokenProviderConfig(t *testing.T) {
	cfg, err := ParseJSON([]byte(`{"tokenProvider":{"keyProvider":{"algorithm":"ES256"},"systemTime":"2026-01-02T03:04:05Z"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.TokenProvider.PublicJWKS("x"); got == "" || cfg.TokenProvider.KeyProvider().Algorithm() != "ES256" {
		t.Errorf("ES256 provider not built")
	}
	if _, err := ParseJSON([]byte(`{"tokenProvider":{"keyProvider":{"algorithm":"HS256"}}}`)); err == nil {
		t.Errorf("unsupported algorithm must be rejected")
	}
}

func TestLoadStandaloneEnvPrecedence(t *testing.T) {
	dir := t.TempDir()
	fileCfg := `{"interactiveLogin":true,"loginPagePath":"/from/file"}`
	path := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(path, []byte(fileCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// JSON_CONFIG wins over JSON_CONFIG_PATH
	cfg, err := LoadStandalone(func(k string) string {
		switch k {
		case "JSON_CONFIG":
			return `{"interactiveLogin":false}`
		case "JSON_CONFIG_PATH":
			return path
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InteractiveLogin {
		t.Errorf("JSON_CONFIG should take precedence")
	}

	// file config used when no inline
	cfg, err = LoadStandalone(func(k string) string {
		if k == "JSON_CONFIG_PATH" {
			return path
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InteractiveLogin || cfg.LoginPagePath != "/from/file" {
		t.Errorf("file config: %+v", cfg)
	}

	// fallback: interactiveLogin true
	cfg, err = LoadStandalone(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InteractiveLogin {
		t.Errorf("standalone fallback should be interactiveLogin=true")
	}
}

func TestParseJSONEntraBlock(t *testing.T) {
	cfg, err := ParseJSON([]byte(`{"entra": {"tenants": [{"tid": "11111111-1111-1111-1111-111111111111"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Entra == nil || cfg.Entra.BasePath != "entra" {
		t.Fatalf("Entra = %+v", cfg.Entra)
	}
}

func TestParseJSONWithoutEntraLeavesItNil(t *testing.T) {
	cfg, err := ParseJSON([]byte(`{"interactiveLogin": true}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Entra != nil {
		t.Fatal("Entra must be nil when not configured")
	}
}

func TestParseJSONInvalidEntraFails(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"entra": {"tenants": []}}`)); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadStandaloneEntraConfigPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "entra.json")
	if err := os.WriteFile(p, []byte(`{"tenants": [{"tid": "11111111-1111-1111-1111-111111111111"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"JSON_CONFIG": `{"interactiveLogin": true}`, "ENTRA_CONFIG_PATH": p}
	cfg, err := LoadStandalone(func(k string) string { return env[k] })
	if err != nil || cfg.Entra == nil || !cfg.InteractiveLogin {
		t.Fatalf("inline JSON + entra file: cfg=%+v err=%v", cfg, err)
	}
	fallback := map[string]string{"JSON_CONFIG_PATH": filepath.Join(dir, "missing.json"), "ENTRA_CONFIG_PATH": p}
	cfg, err = LoadStandalone(func(k string) string { return fallback[k] })
	if err != nil || cfg.Entra == nil || !cfg.InteractiveLogin {
		t.Fatalf("fallback config + entra file: cfg=%+v err=%v", cfg, err)
	}
	missing := map[string]string{"JSON_CONFIG": `{}`, "ENTRA_CONFIG_PATH": filepath.Join(dir, "nope.json")}
	if _, err := LoadStandalone(func(k string) string { return missing[k] }); err == nil {
		t.Fatal("a missing ENTRA_CONFIG_PATH file must be an error")
	}
}

func TestEntraDemoFileParses(t *testing.T) {
	data, err := os.ReadFile("../../entra-demo.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entra.ParseConfig(data); err != nil {
		t.Fatalf("entra-demo.json: %v", err)
	}
}
