// Package routing implements the suffix-based route table and the response
// helpers with Jackson-style JSON rendering, mirroring OAuth2HttpRouter.kt and
// OAuth2HttpResponse.kt.
package routing

import (
	"net/http"
	"strings"

	"github.com/andychoi/mock-oidc/internal/jsonx"
	"github.com/andychoi/mock-oidc/internal/oauth2"
)

// Response is the normalized handler response (OAuth2HttpResponse).
type Response struct {
	Status    int
	Header    http.Header
	Body      string
	BodyBytes []byte
}

func newResponse(status int) Response { return Response{Status: status, Header: http.Header{}} }

// JSON renders a document (jsonx.Obj/Arr/map/scalar) pretty-printed with the
// upstream Jackson style.
func JSON(v any) Response {
	resp := newResponse(200)
	resp.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp.Body = jsonx.Render(v)
	return resp
}

// JSONString returns a pre-rendered JSON document as-is.
func JSONString(s string) Response {
	resp := newResponse(200)
	resp.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp.Body = s
	return resp
}

// HTML returns a 200 HTML response.
func HTML(content string) Response {
	resp := newResponse(200)
	resp.Header.Set("Content-Type", "text/html;charset=UTF-8")
	resp.Body = content
	return resp
}

// Redirect returns a 302 with a Location header.
func Redirect(location string) Response {
	resp := newResponse(302)
	resp.Header.Set("Location", location)
	return resp
}

// NotFound returns a 404.
func NotFound(body string) Response {
	resp := newResponse(404)
	resp.Body = body
	return resp
}

// MethodNotAllowed returns the 405 body used by noMatch.
func MethodNotAllowed() Response {
	resp := newResponse(405)
	resp.Body = "method not allowed"
	return resp
}

// ErrorResponse renders an oauth2.Error as lowercase error JSON, coercing 302
// statuses to 400 like oauth2Error().
func ErrorResponse(err *oauth2.Error) Response {
	status := err.Status
	if status == 302 {
		status = 400
	}
	code := err.Code
	if code == "" {
		code = "server_error"
	}
	obj := jsonx.Obj{}
	if err.Description != "" {
		obj = append(obj, jsonx.Field{Name: "error_description", V: err.Description})
	}
	obj = append(obj, jsonx.Field{Name: "error", V: code})
	resp := newResponse(status)
	resp.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp.Body = strings.ToLower(jsonx.Render(obj))
	return resp
}

// TokenResponse renders the OAuth2TokenResponse with upstream field order and
// null-omission: token_type, issued_token_type, id_token, access_token,
// refresh_token, expires_in, scope.
func TokenResponse(tokenType, issuedTokenType, idToken, accessToken, refreshToken string, expiresIn int, scope string) Response {
	obj := jsonx.Obj{{Name: "token_type", V: tokenType}}
	if issuedTokenType != "" {
		obj = append(obj, jsonx.Field{Name: "issued_token_type", V: issuedTokenType})
	}
	if idToken != "" {
		obj = append(obj, jsonx.Field{Name: "id_token", V: idToken})
	}
	obj = append(obj, jsonx.Field{Name: "access_token", V: accessToken})
	if refreshToken != "" {
		obj = append(obj, jsonx.Field{Name: "refresh_token", V: refreshToken})
	}
	obj = append(obj, jsonx.Field{Name: "expires_in", V: expiresIn})
	if scope != "" {
		obj = append(obj, jsonx.Field{Name: "scope", V: scope})
	}
	return JSON(obj)
}
