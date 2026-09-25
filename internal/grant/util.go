package grant

import "encoding/base64"

// b64url encodes without padding (JWKS/JWT style).
func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
