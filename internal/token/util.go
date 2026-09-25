package token

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// RandomUUID returns a random RFC 4122 v4 UUID string.
func RandomUUID() string { return randomUUID() }

// randomUUID returns a random RFC 4122 v4 UUID string.
func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	hexed := hex.EncodeToString(b[:])
	return hexed[0:8] + "-" + hexed[8:12] + "-" + hexed[12:16] + "-" + hexed[16:20] + "-" + hexed[20:32]
}

// RandomAuthorizationCode mints a nimbus-equivalent authorization code:
// 32 random bytes, base64url without padding (43 chars).
func RandomAuthorizationCode() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
