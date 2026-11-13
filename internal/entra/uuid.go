package entra

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fixed namespaces so derived IDs are stable across machines and restarts.
var (
	oidNamespace   = mustUUID("5d1c3b36-6f0e-4d4e-9a39-2d2f1f5e0c01")
	groupNamespace = mustUUID("8f6a3c52-1b7e-4a55-9d0e-6c1a9b0e2f11")
	appNamespace   = mustUUID("d47b2e60-9a3c-4f1d-b8e5-7c2a6d3f4b19")
)

// UUIDv5 returns the name-based (SHA-1) UUID of name in namespace ns, lowercase.
func UUIDv5(ns [16]byte, name string) string {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	sum := h.Sum(nil)
	var u [16]byte
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50 // version 5
	u[8] = (u[8] & 0x3f) | 0x80 // RFC variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// GroupObjectID is the stable object ID emitted for a group name in a tenant
// whose groupClaimFormat is "object_id".
func GroupObjectID(tid, name string) string {
	return UUIDv5(groupNamespace, strings.ToLower(tid)+":"+name)
}

// RandomGUID returns a random (version 4) GUID, lowercase — the shape Entra
// hands out as application (client) IDs, object IDs and secret IDs.
func RandomGUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("entra: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// RandomSecretValue returns an Entra-shaped client secret value: a short
// random prefix, a tilde, and a base64url body (real Entra secrets read like
// "VG8Q~eF8x_-...").
func RandomSecretValue() string {
	p := make([]byte, 3)
	if _, err := rand.Read(p); err != nil {
		panic("entra: crypto/rand failed: " + err.Error())
	}
	for i := range p {
		p[i] = 'a' + p[i]%26
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("entra: crypto/rand failed: " + err.Error())
	}
	return string(p) + "8Q~" + base64.RawURLEncoding.EncodeToString(b)
}

func mustUUID(s string) [16]byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		panic("entra: bad UUID literal " + s)
	}
	var u [16]byte
	copy(u[:], b)
	return u
}
