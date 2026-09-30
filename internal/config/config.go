// Package config loads the server configuration from the environment and the
// OAuth2Config JSON document, keeping the schema of the Kotlin server
// (mock-oidc.json compatibility).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/andychoi/mock-oidc/internal/entra"
	"github.com/andychoi/mock-oidc/internal/token"
)

// OAuth2Config mirrors no.nav.security.mock.oauth2.OAuth2Config.
type OAuth2Config struct {
	InteractiveLogin   bool   `json:"interactiveLogin"`
	LoginPagePath      string `json:"loginPagePath"`
	StaticAssetsPath   string `json:"staticAssetsPath"`
	RotateRefreshToken bool   `json:"rotateRefreshToken"`

	// TokenProvider is built by parseTokenProvider; nil means defaults.
	TokenProvider *token.TokenProvider

	// TokenCallbacks holds the config-driven MappingCallbacks.
	TokenCallbacks []*token.MappingCallback `json:"tokenCallbacks"`

	// httpServer is accepted for schema compatibility (string or object) and
	// ignored except for its optional ssl block, which enables TLS.
	HTTPServer json.RawMessage `json:"httpServer"`

	// SSL is set when httpServer.ssl is configured.
	SSL *SSLSettings

	// Entra enables Entra mode when set (the "entra" JSON block or
	// ENTRA_CONFIG_PATH); nil keeps the server navikt-only.
	Entra *entra.Config `json:"-"`
}

// SSLSettings mirrors the Kotlin SslConfig JSON shape, extended with a PEM
// certificate/key pair (certificateFile/privateKeyFile) as an alternative to
// the PKCS12 keystore — e.g. an mkcert local-CA certificate for
// https://oidc.dev.test. Setting both forms is a fatal boot error.
type SSLSettings struct {
	KeyPassword      string `json:"keyPassword"`
	KeystoreFile     string `json:"keystoreFile"`
	KeystoreType     string `json:"keystoreType"`
	KeystorePassword string `json:"keystorePassword"`
	CertificateFile  string `json:"certificateFile"`
	PrivateKeyFile   string `json:"privateKeyFile"`
}

type tokenProviderConfig struct {
	KeyProvider *keyProviderConfig `json:"keyProvider"`
	SystemTime  string             `json:"systemTime"`
}

type keyProviderConfig struct {
	InitialKeys string `json:"initialKeys"`
	Algorithm   string `json:"algorithm"`
}

// tokenCallbacksJSON is the intermediate shape; MappingCallback has no JSON
// tags because its fields are protocol-ish, so decode explicitly.
type tokenCallbacksJSON struct {
	IssuerID        string              `json:"issuerId"`
	TokenExpiry     int64               `json:"tokenExpiry"`
	RequestMappings []requestMappingDTO `json:"requestMappings"`
}

type requestMappingDTO struct {
	RequestParam string         `json:"requestParam"`
	Match        string         `json:"match"`
	Claims       map[string]any `json:"claims"`
	TypeHeader   string         `json:"typeHeader"`
}

type rawConfig struct {
	InteractiveLogin   *bool                `json:"interactiveLogin"`
	LoginPagePath      string               `json:"loginPagePath"`
	StaticAssetsPath   string               `json:"staticAssetsPath"`
	RotateRefreshToken bool                 `json:"rotateRefreshToken"`
	TokenProvider      *tokenProviderConfig `json:"tokenProvider"`
	TokenCallbacks     []tokenCallbacksJSON `json:"tokenCallbacks"`
	HTTPServer         json.RawMessage      `json:"httpServer"`
	Entra              json.RawMessage      `json:"entra"`
}

// ParseJSON parses an OAuth2Config JSON document.
func ParseJSON(data []byte) (*OAuth2Config, error) {
	var raw rawConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid config JSON: %w", err)
	}

	cfg := &OAuth2Config{
		InteractiveLogin:   raw.InteractiveLogin != nil && *raw.InteractiveLogin,
		LoginPagePath:      raw.LoginPagePath,
		StaticAssetsPath:   raw.StaticAssetsPath,
		RotateRefreshToken: raw.RotateRefreshToken,
		HTTPServer:         raw.HTTPServer,
	}

	// The httpServer object form may carry an ssl block; everything else about
	// it is ignored (single net/http backend).
	if len(raw.HTTPServer) > 0 {
		var server struct {
			SSL *SSLSettings `json:"ssl"`
		}
		if err := json.Unmarshal(raw.HTTPServer, &server); err == nil {
			cfg.SSL = server.SSL
		}
	}

	// token provider
	algorithm := "RS256"
	var initialKeys []byte
	var systemTime *time.Time
	if raw.TokenProvider != nil {
		if raw.TokenProvider.KeyProvider != nil {
			if a := raw.TokenProvider.KeyProvider.Algorithm; a != "" {
				algorithm = a
			}
			if k := raw.TokenProvider.KeyProvider.InitialKeys; k != "" {
				initialKeys = []byte(k)
			}
		}
		if raw.TokenProvider.SystemTime != "" {
			st, err := time.Parse(time.RFC3339, raw.TokenProvider.SystemTime)
			if err != nil {
				return nil, fmt.Errorf("invalid tokenProvider.systemTime: %w", err)
			}
			systemTime = &st
		}
	}
	var kp *token.KeyProvider
	var err error
	if len(initialKeys) > 0 {
		var key *token.SigningKey
		key, err = token.ParsePrivateJWK(initialKeys)
		if err == nil {
			kp, err = token.NewKeyProviderFromInitial(key, algorithm)
		}
	} else {
		kp, err = token.DefaultKeyProvider(algorithm)
	}
	if err != nil {
		return nil, err
	}
	cfg.TokenProvider = token.NewTokenProvider(kp, systemTime)

	// token callbacks
	for _, cb := range raw.TokenCallbacks {
		if cb.IssuerID == "" {
			return nil, fmt.Errorf("tokenCallbacks entry missing issuerId")
		}
		expiry := cb.TokenExpiry
		if expiry == 0 {
			expiry = 3600
		}
		mcb := &token.MappingCallback{IssuerIDValue: cb.IssuerID, Expiry: expiry}
		for _, m := range cb.RequestMappings {
			typ := m.TypeHeader
			if typ == "" {
				typ = "JWT"
			}
			mcb.Mappings = append(mcb.Mappings, &token.Mapping{
				RequestParam: m.RequestParam,
				Match:        m.Match,
				Claims:       m.Claims,
				TypeHeader:   typ,
			})
		}
		cfg.TokenCallbacks = append(cfg.TokenCallbacks, mcb)
	}

	if len(raw.Entra) > 0 && string(raw.Entra) != "null" {
		ec, err := entra.ParseConfig(raw.Entra)
		if err != nil {
			return nil, err
		}
		cfg.Entra = ec
	}
	return cfg, nil
}

// loadBaseStandalone mirrors StandaloneConfig: JSON_CONFIG env (inline JSON)
// wins, then JSON_CONFIG_PATH (default config.json, missing file tolerated),
// then the fallback config {interactiveLogin: true}.
func loadBaseStandalone(getenv func(string) string) (*OAuth2Config, error) {
	if inline := getenv("JSON_CONFIG"); inline != "" {
		return ParseJSON([]byte(inline))
	}
	path := getenv("JSON_CONFIG_PATH")
	if path == "" {
		path = "config.json"
	}
	data, err := os.ReadFile(path)
	if err == nil {
		return ParseJSON(data)
	}
	// Missing/unreadable file falls back to the standalone default, like upstream.
	kp, kerr := token.DefaultKeyProvider("RS256")
	if kerr != nil {
		return nil, kerr
	}
	return &OAuth2Config{InteractiveLogin: true, TokenProvider: token.NewTokenProvider(kp, nil)}, nil
}

// LoadStandalone mirrors StandaloneConfig: JSON_CONFIG env (inline JSON) wins,
// then JSON_CONFIG_PATH (default config.json, missing file tolerated), then
// the fallback config {interactiveLogin: true}. ENTRA_CONFIG_PATH, when set,
// enables Entra mode from a separate file (it overrides an "entra" block).
func LoadStandalone(getenv func(string) string) (*OAuth2Config, error) {
	cfg, err := loadBaseStandalone(getenv)
	if err != nil {
		return nil, err
	}
	if p := getenv("ENTRA_CONFIG_PATH"); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("ENTRA_CONFIG_PATH: %w", err)
		}
		ec, err := entra.ParseConfig(data)
		if err != nil {
			return nil, err
		}
		cfg.Entra = ec
	}
	return cfg, nil
}
