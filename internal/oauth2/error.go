// Package oauth2 carries the protocol-level types shared by the rest of the
// server: the OAuth2 error model, the request abstraction with proxy-aware
// URL/issuer derivation, and parsing of authentication/token requests.
package oauth2

import "net/http"

// Error is the RFC-style OAuth error carried through handlers and rendered as
// lowercase JSON by the router (mirrors no.nav.security.mock.oauth2.OAuth2Exception).
type Error struct {
	Code        string
	Description string
	Status      int
}

func (e *Error) Error() string {
	if e.Description != "" {
		return e.Description
	}
	return e.Code
}

func newError(code, description string, status int) *Error {
	return &Error{Code: code, Description: description, Status: status}
}

func InvalidRequest(description string) *Error {
	return newError("invalid_request", description, http.StatusBadRequest)
}

func InvalidClient(description string) *Error {
	return newError("invalid_client", description, http.StatusUnauthorized)
}

func InvalidGrant(description string) *Error {
	return newError("invalid_grant", description, http.StatusBadRequest)
}

func InvalidToken(description string) *Error {
	return newError("invalid_token", description, http.StatusUnauthorized)
}

func UnsupportedTokenType(description string) *Error {
	return newError("unsupported_token_type", description, http.StatusBadRequest)
}

func ServerError(message string) *Error {
	return newError("server_error", message, http.StatusInternalServerError)
}

func NotFound(description string) *Error {
	return newError("not_found", description, http.StatusNotFound)
}

// MissingParameter mirrors the Kotlin top-level missingParameter helper.
func MissingParameter(name string) *Error {
	return InvalidRequest("missing required parameter " + name)
}

// MissingOrEmptyParameter mirrors the nimbus parser wording observed on 6.0.2,
// e.g. `invalid request: missing or empty code parameter`.
func MissingOrEmptyParameter(name string) *Error {
	return InvalidRequest("invalid request: missing or empty " + name + " parameter")
}

// UnsupportedGrantType mirrors the Kotlin top-level invalidGrant helper.
func UnsupportedGrantType(grantType string) *Error {
	return InvalidGrant("grant_type " + grantType + " not supported.")
}
