// Package grant implements the token grant handlers and their caches,
// mirroring no.nav.security.mock.oauth2.grant.
package grant

import (
	"sync"

	"github.com/andychoi/mock-oidc/internal/token"
)

// RefreshTokenManager mirrors RefreshTokenManager.kt: refresh token -> callback,
// with keycloak-js compatible plain-JWT refresh tokens when a nonce was used.
type RefreshTokenManager struct {
	mu    sync.Mutex
	cache map[string]token.Callback
}

// NewRefreshTokenManager returns an empty manager.
func NewRefreshTokenManager() *RefreshTokenManager {
	return &RefreshTokenManager{cache: map[string]token.Callback{}}
}

// Get returns the stored callback for a refresh token.
func (m *RefreshTokenManager) Get(refreshToken string) token.Callback {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cache[refreshToken]
}

// Remove deletes a refresh token (revocation).
func (m *RefreshTokenManager) Remove(refreshToken string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cache, refreshToken)
}

// RefreshToken mints and stores a refresh token for the callback: an unsigned
// JWT carrying jti+nonce when nonce is set, else the bare jti.
func (m *RefreshTokenManager) RefreshToken(cb token.Callback, nonce string) string {
	jti := token.RandomUUID()
	refreshToken := jti
	if nonce != "" {
		refreshToken = plainJWT(jti, nonce)
	}
	m.mu.Lock()
	m.cache[refreshToken] = cb
	m.mu.Unlock()
	return refreshToken
}

// Rotate removes the old token and mints a new one with the stored callback
// (or the fallback if the old token is unknown). The new token is always an
// opaque jti — the nonce is not carried over, mirroring upstream.
func (m *RefreshTokenManager) Rotate(refreshToken string, fallback token.Callback) string {
	m.mu.Lock()
	cb, ok := m.cache[refreshToken]
	delete(m.cache, refreshToken)
	m.mu.Unlock()
	if !ok {
		cb = fallback
	}
	return m.RefreshToken(cb, "")
}

// plainJWT builds an alg:none JWT: base64(header).base64(claims). with the
// trailing empty-signature dot.
func plainJWT(jti, nonce string) string {
	return "eyJhbGciOiJub25lIn0." +
		b64url(`{"jti":"`+jti+`","nonce":"`+nonce+`"}`) +
		"."
}
