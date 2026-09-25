// Package userinfo implements GET /userinfo (UserInfo.kt): claims from the
// Bearer token, verified against the issuer's key.
package userinfo

import (
	"strings"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
)

// Handler verifies the bearer token and returns its claims.
func Handler(tp *token.TokenProvider) routing.Handler {
	return func(req *oauth2.Request) routing.Response {
		claims, err := verifyBearerToken(req, tp)
		if err != nil {
			panic(err)
		}
		return routing.JSON(jsonx.FromMap(claims))
	}
}

func verifyBearerToken(req *oauth2.Request, tp *token.TokenProvider) (map[string]any, *oauth2.Error) {
	auth := req.Header.Get("Authorization")
	parts := strings.Split(auth, "Bearer ")
	if len(parts) != 2 {
		return nil, oauth2.InvalidToken("missing bearer token")
	}
	bearer := parts[len(parts)-1]
	claims, err := tp.Verify(req.IssuerURL(), bearer)
	if err != nil {
		return nil, oauth2.InvalidToken(err.Description)
	}
	return claims, nil
}
