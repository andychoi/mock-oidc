// Package introspect implements POST /introspect (Introspect.kt): RFC 7662-ish
// token introspection requiring any Authorization header.
package introspect

import (
	"strings"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
)

// Handler introspects the token form parameter against the issuer's key.
func Handler(tp *token.TokenProvider) routing.Handler {
	return func(req *oauth2.Request) routing.Response {
		if !authenticated(req) {
			panic(oauth2.InvalidClient("The client authentication was invalid"))
		}
		claims := verifyToken(req, tp)
		if claims == nil {
			return routing.JSON(jsonx.Obj{{Name: "active", V: false}})
		}

		obj := jsonx.Obj{
			{Name: "active", V: true},
		}
		add := func(name string, v any) {
			if v != nil {
				obj = append(obj, jsonx.Field{Name: name, V: v})
			}
		}
		add("scope", stringClaim(claims, "scope"))
		add("client_id", stringClaim(claims, "client_id"))
		add("username", stringClaim(claims, "username"))
		tt := stringClaim(claims, "token_type")
		if tt == "" {
			tt = "Bearer"
		}
		obj = append(obj, jsonx.Field{Name: "token_type", V: tt})
		add("exp", epoch(claims, "exp"))
		add("iat", epoch(claims, "iat"))
		add("nbf", epoch(claims, "nbf"))
		add("sub", stringClaim(claims, "sub"))
		// aud: single-element lists are written unwrapped, like upstream.
		if aud := oauth2.AudienceList(claims["aud"]); len(aud) == 1 {
			obj = append(obj, jsonx.Field{Name: "aud", V: aud[0]})
		} else if len(aud) > 1 {
			obj = append(obj, jsonx.Field{Name: "aud", V: aud})
		}
		add("iss", stringClaim(claims, "iss"))
		add("jti", stringClaim(claims, "jti"))
		return routing.JSON(obj)
	}
}

func verifyToken(req *oauth2.Request, tp *token.TokenProvider) map[string]any {
	tok := req.FormParam("token")
	if tok == "" {
		return nil
	}
	claims, err := tp.Verify(req.IssuerURL(), tok)
	if err != nil {
		return nil
	}
	return claims
}

// authenticated requires a Bearer or Basic Authorization header with a value.
func authenticated(req *oauth2.Request) bool {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	for _, prefix := range []string{"Bearer ", "Basic "} {
		if parts := strings.Split(auth, prefix); len(parts) == 2 && parts[1] != "" {
			return true
		}
	}
	return false
}

func stringClaim(claims map[string]any, name string) string {
	s, _ := claims[name].(string)
	return s
}

func epoch(claims map[string]any, name string) any {
	switch t := claims[name].(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	}
	return nil
}
