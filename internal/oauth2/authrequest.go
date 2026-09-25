package oauth2

import (
	"net/url"
	"strings"
)

// AuthRequest is a parsed OIDC authentication request (the /authorize query),
// equivalent to nimbus AuthenticationRequest.
type AuthRequest struct {
	ResponseType        []string
	ClientID            string
	RedirectURI         string
	Scope               []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              []string
	ResponseMode        string
}

// ParseAuthRequest validates and parses the query parameters with the same
// required-parameter rules as nimbus AuthenticationRequest.parse. Error
// descriptions match the lowercased messages observed on the 6.0.2 server.
func ParseAuthRequest(query url.Values) (*AuthRequest, *Error) {
	rt := query.Get("response_type")
	if rt == "" {
		return nil, InvalidRequest("invalid request: missing response_type parameter")
	}
	responseTypes := strings.Fields(rt)
	for _, v := range responseTypes {
		switch v {
		case "code", "id_token", "token", "none":
		default:
			return nil, &Error{
				Code:        "unsupported_response_type",
				Description: "unsupported response type: unsupported response_type parameter: unsupported openid connect response type value",
				Status:      400,
			}
		}
	}
	scope := query.Get("scope")
	if scope == "" {
		return nil, InvalidRequest("invalid request: missing scope parameter")
	}
	clientID := query.Get("client_id")
	if clientID == "" {
		return nil, InvalidRequest("invalid request: missing client_id parameter")
	}
	redirectURI := query.Get("redirect_uri")
	if redirectURI == "" {
		return nil, InvalidRequest("invalid request: missing redirect_uri parameter")
	}
	if has(responseTypes, "id_token") && query.Get("nonce") == "" {
		return nil, InvalidRequest("invalid request: missing nonce parameter: required for response_type=" + rt)
	}

	return &AuthRequest{
		ResponseType:        responseTypes,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               strings.Fields(scope),
		State:               query.Get("state"),
		Nonce:               query.Get("nonce"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
		Prompt:              strings.Fields(query.Get("prompt")),
		ResponseMode:        query.Get("response_mode"),
	}, nil
}

// ImpliesCodeFlow mirrors nimbus ResponseType.impliesCodeFlow: exactly "code".
func (a *AuthRequest) ImpliesCodeFlow() bool {
	return len(a.ResponseType) == 1 && a.ResponseType[0] == "code"
}

// IsPrompt mirrors AuthenticationRequest.isPrompt: any of login/consent/select_account.
func (a *AuthRequest) IsPrompt() bool {
	for _, p := range a.Prompt {
		if p == "login" || p == "consent" || p == "select_account" {
			return true
		}
	}
	return false
}

// SuccessRedirectURL builds the redirect_uri with code (and state when present)
// appended as query parameters, mirroring AuthenticationSuccessResponse.toURI.
func (a *AuthRequest) SuccessRedirectURL(code string) (string, *Error) {
	u, err := url.Parse(a.RedirectURI)
	if err != nil {
		return "", InvalidRequest("invalid redirect_uri: " + err.Error())
	}
	q := u.Query()
	q.Set("code", code)
	if a.State != "" {
		q.Set("state", a.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func has(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
