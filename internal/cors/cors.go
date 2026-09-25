// Package cors implements the automatic CORS response interceptor
// (http/CorsInterceptor.kt): when the request carries an Origin header, the
// response reflects it and allows credentials.
package cors

import (
	"net/http"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
)

// Interceptor reflects the request origin on the response.
func Interceptor(req *oauth2.Request, resp routing.Response) routing.Response {
	origin := req.Header.Get("Origin")
	if origin == "" {
		return resp
	}
	if req.Method == http.MethodOptions {
		if h := req.Header.Get("Access-Control-Request-Headers"); h != "" {
			resp.Header.Set("Access-Control-Allow-Headers", h)
		}
		resp.Header.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	}
	resp.Header.Set("Access-Control-Allow-Origin", origin)
	resp.Header.Set("Access-Control-Allow-Credentials", "true")
	return resp
}
