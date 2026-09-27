package entra

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// Fixed namespaces so derived IDs are stable across machines and restarts.
var (
	oidNamespace   = mustUUID("5d1c3b36-6f0e-4d4e-9a39-2d2f1f5e0c01")
	groupNamespace = mustUUID("8f6a3c52-1b7e-4a55-9d0e-6c1a9b0e2f11")
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

func mustUUID(s string) [16]byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		panic("entra: bad UUID literal " + s)
	}
	var u [16]byte
	copy(u[:], b)
	return u
}
