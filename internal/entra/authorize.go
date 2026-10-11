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

type pickerUser struct {
	Username, Name, Email string
	// Match marks the account a login_hint named, so a person sees which one
	// the client asked for even when the shortcut did not fire.
	Match bool
}

type pickerTenant struct {
	TID, Name string
	Users     []pickerUser
}

type pickerPage struct {
	Heading    string
	Action     string // form target: the current request URI (query preserved)
	Submit     string // value of the hidden "action" field on account buttons
	ShowCancel bool
	Hint       string // the login_hint, echoed so the client's intent is visible
	Tenants    []pickerTenant
}

// authHints are the account-selection parameters. They are read straight from
// the query rather than added to oauth2.AuthRequest, so the shared parser the
// navikt-compatible routes use is untouched.
type authHints struct {
	LoginHint  string
	DomainHint string
	Prompt     []string
}

func readHints(req *oauth2.Request) authHints {
	q := req.URL.Query()
	return authHints{
		LoginHint:  strings.TrimSpace(q.Get("login_hint")),
		DomainHint: strings.TrimSpace(q.Get("domain_hint")),
		Prompt:     strings.Fields(q.Get("prompt")),
	}
}

func (a authHints) has(p string) bool {
	for _, v := range a.Prompt {
		if v == p {
			return true
		}
	}
	return false
}

// forcesPicker reports whether the client insists on an interactive choice.
func (a authHints) forcesPicker() bool { return a.has("select_account") || a.has("login") }

// silent reports a prompt=none request: no UI may be shown.
func (a authHints) silent() bool { return a.has("none") }

// matchesHint reports whether a hint names this account. Entra hints carry a
// UPN, but an email or the configured username is accepted too, so a fixture
// is reachable by whichever name a test has at hand.
func (u *User) matchesHint(t *Tenant, hint string) bool {
	if hint == "" {
		return false
	}
	hint = strings.ToLower(hint)
	return strings.ToLower(u.PrincipalName(t)) == hint ||
		(u.Email != "" && strings.ToLower(u.Email) == hint) ||
		strings.ToLower(u.Username) == hint
}

// inScope reports whether a tenant is selectable for this request: the one
// tenant of a tenant-specific path, or -- on organizations/common -- every
// tenant, narrowed by domain_hint when it names one.
func (h *Handler) inScope(cfg *Config, sc scope, t *Tenant, hints authHints) bool {
	if !sc.Multi() {
		return t.TID == sc.Tenant.TID
	}
	if hints.DomainHint == "" || !cfg.domainHintMatchesAny(hints.DomainHint) {
		return true
	}
	return t.hasDomain(hints.DomainHint)
}

func (t *Tenant) hasDomain(domain string) bool {
	for _, d := range t.Domains {
		if strings.EqualFold(d, domain) {
			return true
		}
	}
	return false
}

// domainHintMatchesAny reports whether any tenant carries the domain. A hint
// that matches nothing is ignored rather than emptying the picker, which is
// how Entra treats an unusable domain_hint.
func (c *Config) domainHintMatchesAny(domain string) bool {
	for i := range c.Tenants {
		if c.Tenants[i].hasDomain(domain) {
			return true
		}
	}
	return false
}

// hintMatches returns the accounts in scope that login_hint names.
func (h *Handler) hintMatches(cfg *Config, sc scope, hints authHints) []*User {
	if hints.LoginHint == "" {
		return nil
	}
	var out []*User
	for i := range cfg.Tenants {
		t := &cfg.Tenants[i]
		if !h.inScope(cfg, sc, t, hints) {
			continue
		}
		for _, u := range cfg.UsersIn(t.TID) {
			if u.matchesHint(t, hints.LoginHint) {
				out = append(out, u)
			}
		}
	}
	return out
}

// pickerTenants lists the accounts selectable in a scope: one tenant, or all
// tenants for organizations/common, narrowed by domain_hint and marking the
// account login_hint named.
func (h *Handler) pickerTenants(cfg *Config, sc scope, hints authHints) []pickerTenant {
	var out []pickerTenant
	for i := range cfg.Tenants {
		t := &cfg.Tenants[i]
		if !h.inScope(cfg, sc, t, hints) {
			continue
		}
		pt := pickerTenant{TID: t.TID, Name: t.Name}
		for _, u := range cfg.UsersIn(t.TID) {
			pt.Users = append(pt.Users, pickerUser{Username: u.Username, Name: u.Name,
				Email: u.Email, Match: u.matchesHint(t, hints.LoginHint)})
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
	cfg := h.conf()
	hints := readHints(req)
	// A login_hint naming exactly one account stands in for a session: it is
	// what lets a relying party test run without a browser. ignoreLoginHint
	// turns the shortcut off, and prompt=select_account/login overrides it.
	matches := h.hintMatches(cfg, sc, hints)
	resolved := len(matches) == 1 && !cfg.IgnoreLoginHint
	if hints.silent() {
		if resolved {
			return h.issueCode(req, ar, sc, cfg, matches[0])
		}
		// Divergence, documented in docs/entra/02-graph-design.md section 7:
		// this mock keeps no session, so a resolvable login_hint is the only
		// thing a silent request can succeed on.
		return errorRedirect(ar.RedirectURI, ar.State, "interaction_required",
			"AADSTS50058: A silent sign-in request was sent but no user is signed in.")
	}
	if resolved && !hints.forcesPicker() {
		return h.issueCode(req, ar, sc, cfg, matches[0])
	}
	return renderPicker(pickerPage{Heading: "Pick an account", Action: req.URL.RequestURI(),
		Submit: "signin", Hint: hints.LoginHint, Tenants: h.pickerTenants(cfg, sc, hints)})
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
	_, u, oerr := h.postedUser(req, sc)
	if oerr != nil {
		return routing.ErrorResponse(oerr)
	}
	return h.issueCode(req, ar, sc, h.conf(), u)
}

// issueCode applies the per-account checks and mints an authorization code.
// It is shared by the picker submit and the login_hint shortcut, so a hinted
// sign-in is held to exactly the same rules as a clicked one.
func (h *Handler) issueCode(req *oauth2.Request, ar *oauth2.AuthRequest, sc scope, cfg *Config, u *User) routing.Response {
	t := cfg.Tenant(u.TID)
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
	cfg := h.conf()
	u := cfg.User(req.FormParam("tid"), req.FormParam("username"))
	if u == nil {
		return nil, nil, oauth2.InvalidRequest("AADSTS50034: The user account does not exist in this directory.")
	}
	if !sc.Multi() && u.TID != sc.Tenant.TID {
		return nil, nil, oauth2.InvalidRequest("AADSTS50020: User account from tenant '" + u.TID + "' does not exist in tenant '" + sc.Tenant.TID + "'.")
	}
	return cfg.Tenant(u.TID), u, nil
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
