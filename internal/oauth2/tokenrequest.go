package oauth2

import (
	"net/url"
	"strings"
	"time"
)

// Grant type identifiers.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantClientCredentials = "client_credentials"
	GrantPassword          = "password"
	GrantRefreshToken      = "refresh_token"
	GrantJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
)

// Client authentication methods.
const (
	AuthMethodNone          = ""
	AuthMethodBasic         = "client_secret_basic"
	AuthMethodPrivateKeyJWT = "private_key_jwt"
)

const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// OIDC reserved scopes, excluded when deriving audience from scopes
// (mirrors nimbus OIDCScopeValue.values()).
var oidcScopes = map[string]bool{
	"openid":         true,
	"profile":        true,
	"email":          true,
	"address":        true,
	"offline_access": true,
}

// TokenRequest is the parsed /token request, equivalent to nimbus TokenRequest.
type TokenRequest struct {
	GrantType string
	// ClientID is the resolved client id: Basic auth user when present, else the
	// client_id form parameter. ClientAuthMethod records how it was obtained.
	ClientID         string
	ClientAuthMethod string

	// Form is the raw (decoded) multimap of the request body; used for callback
	// requestMappings matching.
	Form url.Values

	Scope     string // raw scope parameter, echoed in the response
	ScopeList []string

	// authorization_code
	Code         string
	RedirectURI  string
	CodeVerifier string

	// refresh_token
	RefreshToken string

	// password
	Username string
	Password string

	// jwt-bearer
	Assertion string

	// token exchange
	SubjectToken     string
	SubjectTokenType string
	Audience         []string // repeated aud parameters
}

// ScopesWithoutOIDC filters out the OIDC reserved scopes.
func (t *TokenRequest) ScopesWithoutOIDC() []string {
	var out []string
	for _, s := range t.ScopeList {
		if !oidcScopes[s] {
			out = append(out, s)
		}
	}
	return out
}

// ParseTokenRequest parses and validates a token request the way nimbus
// TokenRequest.parse does, with the error wording observed on the 6.0.2
// server. Token-exchange client-assertion validation is separate
// (ValidateTokenExchangeClientAssertion) because it needs issuer URL context.
func ParseTokenRequest(r *Request) (*TokenRequest, *Error) {
	form := r.Form()

	grantType := strings.TrimSpace(form.Get("grant_type"))
	if grantType == "" {
		return nil, MissingParameter("grant_type")
	}

	clientID, authMethod := resolveClientAuth(r, form)

	switch grantType {
	case GrantClientCredentials:
		if authMethod == AuthMethodNone {
			return nil, InvalidClient("client authentication failed: missing client authentication")
		}
	case GrantPassword:
		if authMethod == AuthMethodNone {
			return nil, InvalidClient("client authentication failed")
		}
	default:
		if clientID == "" {
			return nil, InvalidClient("client authentication failed")
		}
	}

	tr := &TokenRequest{
		GrantType:        grantType,
		ClientID:         clientID,
		ClientAuthMethod: authMethod,
		Form:             form,
		Scope:            form.Get("scope"),
	}
	tr.ScopeList = strings.Fields(tr.Scope)

	switch grantType {
	case GrantAuthorizationCode:
		tr.Code = form.Get("code")
		if tr.Code == "" {
			return nil, MissingOrEmptyParameter("code")
		}
		tr.RedirectURI = form.Get("redirect_uri")
		tr.CodeVerifier = form.Get("code_verifier")
	case GrantRefreshToken:
		tr.RefreshToken = form.Get("refresh_token")
		if tr.RefreshToken == "" {
			return nil, MissingOrEmptyParameter("refresh_token")
		}
	case GrantPassword:
		tr.Username = form.Get("username")
		if tr.Username == "" {
			return nil, MissingOrEmptyParameter("username")
		}
		tr.Password = form.Get("password")
		if tr.Password == "" {
			return nil, MissingOrEmptyParameter("password")
		}
	case GrantJWTBearer:
		tr.Assertion = form.Get("assertion")
		if tr.Assertion == "" {
			return nil, MissingOrEmptyParameter("assertion")
		}
	case GrantTokenExchange:
		tr.SubjectToken = form.Get("subject_token")
		if tr.SubjectToken == "" {
			return nil, MissingOrEmptyParameter("subject_token")
		}
		tr.SubjectTokenType = form.Get("subject_token_type")
		tr.Audience = form["aud"]
	}
	return tr, nil
}

// resolveClientAuth mirrors nimbus ClientAuthentication.parse: Basic auth
// header first, then a private_key_jwt client assertion, else public client.
func resolveClientAuth(r *Request, form url.Values) (string, string) {
	if user, _, ok := r.BasicAuth(); ok {
		if d, err := url.QueryUnescape(user); err == nil {
			user = d
		}
		return user, AuthMethodBasic
	}
	if form.Get("client_assertion_type") == clientAssertionTypeJWTBearer && form.Get("client_assertion") != "" {
		return form.Get("client_id"), AuthMethodPrivateKeyJWT
	}
	return form.Get("client_id"), AuthMethodNone
}

// ValidateTokenExchangeClientAssertion applies requirePrivateKeyJwt from
// NimbusExtensions.kt: for the token-exchange grant with a private_key_jwt
// client authentication, the assertion must have iss == sub == client_id, a
// single accepted audience (issuer URL or token endpoint URL) and an expiry
// no more than 120 seconds ahead.
func ValidateTokenExchangeClientAssertion(r *Request, tr *TokenRequest, issuerURL string) *Error {
	if tr.ClientAuthMethod != AuthMethodPrivateKeyJWT {
		// Upstream requires *some* form of client authentication for token exchange.
		if tr.ClientAuthMethod == AuthMethodNone {
			return InvalidRequest("invalid request")
		}
		return nil
	}

	assertion := tr.Form.Get("client_assertion")
	claims, err := ParseJWTClaims(assertion)
	if err != nil {
		return InvalidRequest("request must contain a valid client_assertion.")
	}

	now := time.Now().Unix()
	exp, _ := numericDate(claims["exp"])
	if exp-now > 120 {
		return InvalidRequest("invalid client_assertion: expiry must be less than 120 seconds")
	}
	if stringClaim(claims["iss"]) != tr.ClientID {
		return InvalidRequest("invalid client_assertion: issuer must match client_id '" + tr.ClientID + "'")
	}
	if stringClaim(claims["sub"]) != tr.ClientID {
		return InvalidRequest("invalid client_assertion: subject must match client_id '" + tr.ClientID + "'")
	}
	aud := AudienceList(claims["aud"])
	if len(aud) == 0 {
		return InvalidRequest("invalid client_assertion: audience cannot be empty")
	}
	if len(aud) > 1 {
		return InvalidRequest("invalid client_assertion: audience must not contain more than one element")
	}
	accepted := map[string]bool{issuerURL: true, r.ProxyAwareURL().String(): true}
	if !accepted[aud[0]] {
		return InvalidRequest("invalid client_assertion: audience should be " + issuerURL)
	}
	return nil
}
