package entra

import (
	"fmt"
	"sync"

	"github.com/andychoi/mock-oidc/internal/token"
)

// KeySet is the RS256 key set shared by every emulated tenant, like Entra's
// common signing keys. The newest key signs; one previous key stays published
// so tokens signed before a rotation still verify.
type KeySet struct {
	mu   sync.RWMutex
	keys []*token.SigningKey // oldest first
	seq  int
}

// NewKeySet returns a key set with one active key (kid "entra-1").
func NewKeySet() *KeySet {
	ks := &KeySet{}
	ks.Rotate()
	return ks
}

// Rotate adds a new active key and returns its kid.
func (k *KeySet) Rotate() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.seq++
	key, err := token.GenerateSigningKey(fmt.Sprintf("entra-%d", k.seq), "RS256")
	if err != nil {
		panic(err) // RS256 is always a supported algorithm
	}
	k.keys = append(k.keys, key)
	if len(k.keys) > 2 {
		k.keys = k.keys[len(k.keys)-2:]
	}
	return key.Kid
}

// ActiveKid returns the kid of the signing key.
func (k *KeySet) ActiveKid() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keys[len(k.keys)-1].Kid
}

// Sign signs claims with the active key (typ JWT).
func (k *KeySet) Sign(claims map[string]any) string {
	k.mu.RLock()
	key := k.keys[len(k.keys)-1]
	k.mu.RUnlock()
	return token.SignJWT(key, claims, "JWT")
}

// JWKS renders all published keys, oldest first.
func (k *KeySet) JWKS() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return token.PublicJWKSOf(k.keys...)
}
