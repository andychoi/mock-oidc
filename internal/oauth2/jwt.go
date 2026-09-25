package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ParseJWTClaims parses the payload of a compact-serialized JWT without
// verifying the signature. Accepts both signed (h.p.s) and plain (h.p.) forms.
func ParseJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid JWT: expected compact serialization")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("invalid JWT claims: %w", err)
	}
	return claims, nil
}

// numericDate extracts a NumericDate claim that may be a float64 (from
// encoding/json) or a json.Number.
func numericDate(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i, true
		}
	case int64:
		return t, true
	case int:
		return int64(t), true
	}
	return 0, false
}

func stringClaim(v any) string {
	s, _ := v.(string)
	return s
}

// AudienceList normalizes an aud claim (string or array) to a string list.
func AudienceList(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
