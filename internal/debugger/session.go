// Package debugger implements the OAuth2 Client Debugger UI
// (debugger/DebuggerRequestHandler.kt): a form that drives this server's own
// authorization code flow, with the intermediate client state kept in a JWE
// (dir + A128GCM) encrypted cookie, and a callback that exchanges the code and
// renders the request/response pair.
package debugger

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/andychoi/mock-oidc/internal/oauth2"
)

const sessionCookieName = "debugger-session"

// sessionManager holds the per-server 128-bit session encryption key
// (SessionManager.kt).
type sessionManager struct {
	key []byte // 16 bytes, AES-128
}

func newSessionManager() *sessionManager {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &sessionManager{key: key}
}

// session loads the session map from the request cookie (decryption failures
// are logged and treated as an absent session, like upstream).
func (m *sessionManager) session(req *oauth2.Request) *session {
	params := map[string]string{}
	if cookie := cookieValue(req, sessionCookieName); cookie != "" {
		if decrypted, err := m.decrypt(cookie); err == nil {
			if err := json.Unmarshal([]byte(decrypted), &params); err != nil {
				params = map[string]string{}
			}
		}
	}
	return &session{params: params}
}

type session struct{ params map[string]string }

func (s *session) putAll(m map[string]string) {
	for k, v := range m {
		s.params[k] = v
	}
}

// get mirrors the Kotlin operator get: missing keys are an error.
func (s *session) get(key string) (string, error) {
	v, ok := s.params[key]
	if !ok {
		return "", fmt.Errorf("could not get %s from session.", key)
	}
	return v, nil
}

func (s *session) asCookie(m *sessionManager) string {
	plaintext, err := json.Marshal(s.params)
	if err != nil {
		return ""
	}
	jwe, err := m.encrypt(string(plaintext))
	if err != nil {
		return ""
	}
	return sessionCookieName + "=" + jwe + "; HttpOnly; Path=/"
}

func cookieValue(req *oauth2.Request, name string) string {
	for _, c := range req.Header.Values("Cookie") {
		for _, part := range strings.Split(c, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == name {
				return v
			}
		}
	}
	return ""
}

// encrypt produces a compact JWE with alg=dir, enc=A128GCM:
// base64(header)..base64(iv).base64(ciphertext).base64(tag).
func (m *sessionManager) encrypt(plaintext string) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"dir","enc":"A128GCM"}`))

	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, []byte(plaintext), []byte(header))
	ct := sealed[:len(sealed)-gcm.Overhead()]
	tag := sealed[len(sealed)-gcm.Overhead():]

	parts := []string{
		header,
		"",
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ct),
		base64.RawURLEncoding.EncodeToString(tag),
	}
	return strings.Join(parts, "."), nil
}

func (m *sessionManager) decrypt(jwe string) (string, error) {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return "", fmt.Errorf("invalid JWE")
	}
	header := parts[0]
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	ct, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return "", err
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, iv, append(ct, tag...), []byte(header))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
