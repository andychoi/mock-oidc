package entra

import (
	"embed"
	"html/template"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/andychoi/mock-oidc/internal/oauth2"
	"github.com/andychoi/mock-oidc/internal/routing"
	"github.com/andychoi/mock-oidc/internal/token"
)

//go:embed templates/picker.html.tmpl
var templatesFS embed.FS

var pickerTmpl = template.Must(template.ParseFS(templatesFS, "templates/picker.html.tmpl"))

// codeTTL mirrors Entra's roughly 10-minute authorization code lifetime.
const codeTTL = 10 * time.Minute

type authCode struct {
	req      *oauth2.AuthRequest
	tid      string // the user's tenant
	username string
	segment  string // tenant path segment the code was issued on
	expires  time.Time
}

type codeStore struct {
	mu    sync.Mutex
	codes map[string]authCode
}

func newCodeStore() *codeStore { return &codeStore{codes: map[string]authCode{}} }

// put stores a code and drops expired ones: abandoned sign-ins (refused
// consent, injected errors, flows that stop at the redirect) are never taken,
// so without this sweep the map would grow until restart.
func (s *codeStore) put(code string, c authCode, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.codes {
		if v.expires.Before(now) {
			delete(s.codes, k)
		}
	}
	s.codes[code] = c
}

// take removes and returns a code: codes are single-use even when redemption fails.
func (s *codeStore) take(code string) (authCode, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[code]
	delete(s.codes, code)
	return c, ok
}

type pickerUser struct{ Username, Name, Email string }

type pickerTenant struct {
	TID, Name string
	Users     []pickerUser
}

type pickerPage struct {
	Heading    string
	Action     string // form target: the current request URI (query preserved)
	Submit     string // value of the hidden "action" field on account buttons
	ShowCancel bool
	Tenants    []pickerTenant
}

// pickerTenants lists the accounts selectable in a scope: one tenant, or all
// tenants for organizations/common.
func (h *Handler) pickerTenants(sc scope) []pickerTenant {
	var out []pickerTenant
	for i := range h.cfg.Tenants {
		t := &h.cfg.Tenants[i]
		if !sc.Multi() && t.TID != sc.Tenant.TID {
			continue
		}
		pt := pickerTenant{TID: t.TID, Name: t.Name}
		for _, u := range h.cfg.UsersIn(t.TID) {
			pt.Users = append(pt.Users, pickerUser{Username: u.Username, Name: u.Name, Email: u.Email})
		}
		out = append(out, pt)
	}
	return out
}

func renderPicker(p pickerPage) routing.Response {
	var b strings.Builder
	if err := pickerTmpl.Execute(&b, p); err != nil {
		return routing.ErrorResponse(oauth2.ServerError("picker template: " + err.Error()))
	}
	return routing.HTML(b.String())
}

func (h *Handler) authorizeGet(req *oauth2.Request, sc scope) routing.Response {
	ar, oerr := oauth2.ParseAuthRequest(req.URL.Query())
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	if !ar.ImpliesCodeFlow() {
		return unsupportedResponseType(ar)
	}
	if rm := ar.ResponseMode; rm != "" && rm != "query" {
		return unsupportedResponseMode(rm)
	}
	return renderPicker(pickerPage{Heading: "Pick an account", Action: req.URL.RequestURI(), Submit: "signin", Tenants: h.pickerTenants(sc)})
}

func (h *Handler) authorizePost(req *oauth2.Request, sc scope) routing.Response {
	ar, oerr := oauth2.ParseAuthRequest(req.URL.Query())
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	if !ar.ImpliesCodeFlow() {
		return unsupportedResponseType(ar)
	}
	if rm := ar.ResponseMode; rm != "" && rm != "query" {
		return unsupportedResponseMode(rm)
	}
	t, u, oerr := h.postedUser(req, sc)
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	switch u.Error {
	case ErrInteractionRequired:
		return errorRedirect(ar.RedirectURI, ar.State, "interaction_required",
			"AADSTS50076: Due to a configuration change made by your administrator, or because you moved to a new location, you must use multi-factor authentication to access the resource.")
	case ErrAccessDenied:
		return errorRedirect(ar.RedirectURI, ar.State, "access_denied",
			"AADSTS50105: The signed in user is not assigned to a role for the application.")
	}
	if t.ConsentRequired && !h.consents.Has(ar.ClientID, t.TID) {
		return errorRedirect(ar.RedirectURI, ar.State, "consent_required",
			"AADSTS65001: The user or administrator has not consented to use the application with ID '"+ar.ClientID+"'.")
	}
	now := h.now()
	code := token.RandomAuthorizationCode()
	h.codes.put(code, authCode{req: ar, tid: t.TID, username: u.Username, segment: sc.Segment, expires: now.Add(codeTTL)}, now)
	loc, oerr := ar.SuccessRedirectURL(code)
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	return routing.Redirect(loc)
}

// postedUser resolves the account chosen on the picker (form fields tid and
// username) within the request scope. Shared with admin consent.
func (h *Handler) postedUser(req *oauth2.Request, sc scope) (*Tenant, *User, *oauth2.Error) {
	u := h.cfg.User(req.FormParam("tid"), req.FormParam("username"))
	if u == nil {
		return nil, nil, oauth2.InvalidRequest("AADSTS50034: The user account does not exist in this directory.")
	}
	if !sc.Multi() && u.TID != sc.Tenant.TID {
		return nil, nil, oauth2.InvalidRequest("AADSTS50020: User account from tenant '" + u.TID + "' does not exist in tenant '" + sc.Tenant.TID + "'.")
	}
	return h.cfg.Tenant(u.TID), u, nil
}

func unsupportedResponseType(ar *oauth2.AuthRequest) routing.Response {
	return errorRedirect(ar.RedirectURI, ar.State, "unsupported_response_type",
		"AADSTS70005: response_type '"+strings.Join(ar.ResponseType, " ")+"' is not supported by the mock; use 'code'.")
}

// unsupportedResponseMode rejects response modes other than query with a 400
// instead of an error redirect: a form_post client only accepts POST at the
// redirect_uri, so it could not receive a GET error redirect either.
func unsupportedResponseMode(mode string) routing.Response {
	return routing.ErrorResponse(oauth2.InvalidRequest(
		"AADSTS90005: response_mode '" + mode + "' is not supported by the mock; use 'query' or omit the parameter."))
}

// errorRedirect sends the browser back to the client with an OAuth error.
func errorRedirect(redirectURI, state, code, description string) routing.Response {
	return redirectWith(redirectURI, map[string]string{"error": code, "error_description": description, "state": state})
}

// redirectWith appends the non-empty params to redirectURI's query.
func redirectWith(redirectURI string, params map[string]string) routing.Response {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return routing.ErrorResponse(oauth2.InvalidRequest("invalid redirect_uri: " + err.Error()))
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return routing.Redirect(u.String())
}
