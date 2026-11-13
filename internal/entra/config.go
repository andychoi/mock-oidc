// Package entra implements the opt-in Microsoft Entra ID emulation ("Entra
// mode"): per-tenant and multi-tenant (organizations/common) v2.0 endpoints, a
// key set shared by all tenants, v2.0 ID token claims, group claims with
// overage, admin consent and error injection. It is mounted under
// /{basePath}/ and never changes the navikt-compatible routes.
// Design: docs/entra/00-design.md.
package entra

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Group claim formats.
const (
	FormatName     = "name"
	FormatObjectID = "object_id"
)

// Injectable user errors.
const (
	ErrInteractionRequired = "interaction_required"
	ErrAccessDenied        = "access_denied"
	ErrInvalidGrant        = "invalid_grant"
)

// MFAPasskey makes the picker submit stop at a simulated passkey step.
const MFAPasskey = "passkey"

// Multi-tenant path segments.
const (
	ScopeOrganizations = "organizations"
	ScopeCommon        = "common"
)

// Config is the Entra mode configuration (the "entra" JSON block or the file
// at ENTRA_CONFIG_PATH).
type Config struct {
	BasePath          string       `json:"basePath"`
	DefaultGroupLimit int          `json:"defaultGroupLimit"`
	TokenExpiry       int64        `json:"tokenExpiry"`
	IgnoreLoginHint   bool         `json:"ignoreLoginHint"`
	Graph             *GraphConfig `json:"graph"`
	Tenants           []Tenant     `json:"tenants"`
	Consents          []Consent    `json:"consents"`
	Apps              []App        `json:"apps"`
	Users             []User       `json:"users"`
}

// App is an optional client registration. Entra mode accepts any client_id on
// every flow; an entry here supplies the app roles an app-only token carries
// (§8 of the Graph design) and the claims mappings its ID tokens get (§7 of
// the org directory design). A registration that declares redirect URIs or
// client secrets opts in to having them enforced on the authorize and token
// endpoints (docs/entra/05-app-registrations-design.md).
type App struct {
	ClientID string         `json:"clientId"`
	TID      string         `json:"tid"`
	Roles    []string       `json:"roles"`
	Claims   []ClaimMapping `json:"claims"`

	// Registration metadata, rendered by the Entra admin center page. Every
	// field is optional; object ID, sign-in audience and display name are
	// derived when empty.
	Name           string        `json:"name"`
	ObjectID       string        `json:"objectId"`
	SignInAudience string        `json:"signInAudience"`
	RedirectURIs   []RedirectURI `json:"redirectUris"`
	Secrets        []AppSecret   `json:"secrets"`
	CreatedOn      string        `json:"createdOn"`
}

// Sign-in audiences (the registration form's Supported account types).
const (
	AudienceMyOrg     = "AzureADMyOrg"        // single tenant (app has a tid)
	AudienceMultiOrgs = "AzureADMultipleOrgs" // any tenant (tid stays empty)
)

// Redirect URI platforms (the Authentication blade's platform types).
const (
	PlatformWeb              = "web"
	PlatformSPA              = "spa"
	PlatformMobileAndDesktop = "mobileAndDesktop"
)

// RedirectURI is one configured redirect URI and its platform.
type RedirectURI struct {
	Platform string `json:"platform"`
	URI      string `json:"uri"`
}

// AppSecret is a client secret of the Certificates & secrets blade. Entra
// shows the value exactly once; this mock also keeps it in the clear (and in
// the admin snapshot) so a lost value never blocks a dev flow.
type AppSecret struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Value       string `json:"value"`
	Expires     string `json:"expires"`   // RFC 3339
	CreatedOn   string `json:"createdOn"` // RFC 3339
}

// ClaimMapping adds one directory attribute to the ID tokens issued to an app,
// the way an Entra claims-mapping policy does. Source names a user attribute
// (see claimSources).
type ClaimMapping struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// Tenant is one emulated Entra tenant.
type Tenant struct {
	TID              string   `json:"tid"`
	Name             string   `json:"name"`
	Domains          []string `json:"domains"`
	GroupClaimFormat string   `json:"groupClaimFormat"`
	GroupLimit       int      `json:"groupLimit"`
	ConsentRequired  bool     `json:"consentRequired"`
	Groups           []Group  `json:"groups"`
}

// Group is optional metadata for a group name used by this tenant's users.
// Membership itself lives on the user (User.Groups); a name used by a user but
// not declared here still becomes a Graph group, with empty metadata. A group
// with a MembershipRule is a dynamic group: its members are computed from the
// rule and cannot be assigned statically.
type Group struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	MailNickname    string `json:"mailNickname"`
	Mail            string `json:"mail"`
	OID             string `json:"oid"`
	SecurityEnabled *bool  `json:"securityEnabled"`
	MailEnabled     *bool  `json:"mailEnabled"`
	MembershipRule  string `json:"membershipRule"`

	rule rule // compiled MembershipRule; immutable, so snapshots may share it
}

// Dynamic reports whether the group's membership is rule-based.
func (g *Group) Dynamic() bool { return g.MembershipRule != "" }

// Consent is a pre-granted admin consent of a client in a tenant.
type Consent struct {
	ClientID string `json:"clientId"`
	TID      string `json:"tid"`
}

// User is one account in a tenant.
type User struct {
	Username      string   `json:"username"`
	TID           string   `json:"tid"`
	OID           string   `json:"oid"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	EmailVerified *bool    `json:"emailVerified"`
	Groups        []string `json:"groups"`
	AMR           []string `json:"amr"`
	Admin         bool     `json:"admin"`
	Error         string   `json:"error"`
	MFA           string   `json:"mfa"`

	// Account profile. These feed the Graph account surface and the matching
	// optional token claims; every one of them is optional.
	GivenName         string   `json:"givenName"`
	Surname           string   `json:"surname"`
	UPN               string   `json:"upn"`
	AccountEnabled    *bool    `json:"accountEnabled"`
	JobTitle          string   `json:"jobTitle"`
	OfficeLocation    string   `json:"officeLocation"`
	BusinessPhones    []string `json:"businessPhones"`
	MobilePhone       string   `json:"mobilePhone"`
	PreferredLanguage string   `json:"preferredLanguage"`
	Roles             []string `json:"roles"`
	WIDs              []string `json:"wids"`
	Manager           string   `json:"manager"`

	// Organization data: the attributes HR sync fills in and dynamic group
	// rules match on.
	Department          string   `json:"department"`
	CompanyName         string   `json:"companyName"`
	EmployeeID          string   `json:"employeeId"`
	ExtensionAttributes ExtAttrs `json:"onPremisesExtensionAttributes"`

	dynamicGroups []string // memberships computed from dynamic group rules by normalize
}

// ExtAttrs is the subset of Graph's onPremisesExtensionAttributes this
// emulator supports: extensionAttribute1-3 (Entra has 1-15). Strict decoding
// rejects the others.
type ExtAttrs struct {
	ExtensionAttribute1 string `json:"extensionAttribute1"`
	ExtensionAttribute2 string `json:"extensionAttribute2"`
	ExtensionAttribute3 string `json:"extensionAttribute3"`
}

var (
	guidRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	basePathRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// ParseConfig decodes (rejecting unknown fields), normalizes and validates an
// Entra config.
func ParseConfig(data []byte) (*Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("entra config: %w", err)
	}
	if err := c.normalize(); err != nil {
		return nil, fmt.Errorf("entra config: %w", err)
	}
	return &c, nil
}

func (c *Config) normalize() error {
	c.BasePath = strings.Trim(c.BasePath, "/")
	if c.BasePath == "" {
		c.BasePath = "entra"
	}
	if !basePathRE.MatchString(c.BasePath) {
		return fmt.Errorf("basePath %q must be one path segment of [A-Za-z0-9_-]", c.BasePath)
	}
	if c.DefaultGroupLimit <= 0 {
		c.DefaultGroupLimit = 200
	}
	if c.TokenExpiry <= 0 {
		c.TokenExpiry = 3600
	}
	if err := c.normalizeGraph(); err != nil {
		return err
	}
	if len(c.Tenants) == 0 {
		return errors.New("at least one tenant is required")
	}
	tenants := map[string]bool{}
	for i := range c.Tenants {
		t := &c.Tenants[i]
		t.TID = strings.ToLower(strings.TrimSpace(t.TID))
		if !guidRE.MatchString(t.TID) {
			return fmt.Errorf("tenant %q: tid must be a GUID", t.TID)
		}
		if tenants[t.TID] {
			return fmt.Errorf("tenant %s: duplicate tid", t.TID)
		}
		tenants[t.TID] = true
		switch t.GroupClaimFormat {
		case "":
			t.GroupClaimFormat = FormatName
		case FormatName, FormatObjectID:
		default:
			return fmt.Errorf("tenant %s: groupClaimFormat must be %q or %q", t.TID, FormatName, FormatObjectID)
		}
		if t.GroupLimit <= 0 {
			t.GroupLimit = c.DefaultGroupLimit
		}
		if t.Name == "" {
			t.Name = t.TID
		}
		if err := normalizeGroups(t); err != nil {
			return err
		}
	}
	apps := map[string]bool{}
	for i := range c.Apps {
		a := &c.Apps[i]
		a.ClientID = strings.TrimSpace(a.ClientID)
		a.TID = strings.ToLower(strings.TrimSpace(a.TID))
		if a.ClientID == "" {
			return fmt.Errorf("app %d: clientId is required", i)
		}
		if apps[a.ClientID] {
			return fmt.Errorf("app %s: duplicate clientId", a.ClientID)
		}
		apps[a.ClientID] = true
		if a.TID != "" && !tenants[a.TID] {
			return fmt.Errorf("app %s: unknown tid %q", a.ClientID, a.TID)
		}
		if err := normalizeRegistration(a); err != nil {
			return err
		}
		if err := normalizeClaims(a); err != nil {
			return err
		}
	}
	for i := range c.Consents {
		cs := &c.Consents[i]
		cs.TID = strings.ToLower(strings.TrimSpace(cs.TID))
		if cs.ClientID == "" || !tenants[cs.TID] {
			return fmt.Errorf("consent %d: clientId and a configured tid are required", i)
		}
	}
	users := map[string]bool{}
	oids := map[string]string{} // tid/oid -> username
	for i := range c.Users {
		u := &c.Users[i]
		u.TID = strings.ToLower(strings.TrimSpace(u.TID))
		if u.Username == "" {
			return fmt.Errorf("user %d: username is required", i)
		}
		if !tenants[u.TID] {
			return fmt.Errorf("user %s: unknown tid %q", u.Username, u.TID)
		}
		key := u.TID + "/" + u.Username
		if users[key] {
			return fmt.Errorf("user %s: duplicate username in tenant %s", u.Username, u.TID)
		}
		users[key] = true
		switch u.Error {
		case "", ErrInteractionRequired, ErrAccessDenied, ErrInvalidGrant:
		default:
			return fmt.Errorf("user %s: error must be %s, %s or %s", u.Username, ErrInteractionRequired, ErrAccessDenied, ErrInvalidGrant)
		}
		switch u.MFA {
		case "", MFAPasskey:
		default:
			return fmt.Errorf("user %s: mfa must be empty or %s, got %q", u.Username, MFAPasskey, u.MFA)
		}
		u.OID = strings.ToLower(u.OID)
		if u.OID != "" && !guidRE.MatchString(u.OID) {
			return fmt.Errorf("user %s: oid must be a GUID", u.Username)
		}
		if u.OID == "" {
			u.OID = UUIDv5(oidNamespace, u.TID+":"+u.Username)
		}
		if prev, dup := oids[u.TID+"/"+u.OID]; dup {
			return fmt.Errorf("user %s: oid %s already used by %s", u.Username, u.OID, prev)
		}
		oids[u.TID+"/"+u.OID] = u.Username
		if u.Name == "" {
			u.Name = u.Username
		}
		if err := normalizeProfile(u); err != nil {
			return err
		}
	}
	// Managers resolve against the whole user set, so they need a second pass.
	// A manager may be named by username, object ID or UPN; it is stored as
	// the username.
	for i := range c.Users {
		u := &c.Users[i]
		if u.Manager == "" {
			continue
		}
		if !users[u.TID+"/"+u.Manager] {
			if m := c.UserByUPNOrOID(u.TID, u.Manager); m != nil {
				u.Manager = m.Username
			}
		}
		if u.Manager == u.Username {
			return fmt.Errorf("user %s: manager cannot be the user itself", u.Username)
		}
		if !users[u.TID+"/"+u.Manager] {
			return fmt.Errorf("user %s: unknown manager %q in tenant %s", u.Username, u.Manager, u.TID)
		}
	}
	// Dynamic memberships depend on every attribute and on the manager chain,
	// so they are computed last.
	return c.evaluateDynamicGroups()
}

// evaluateDynamicGroups rejects static members of dynamic groups and computes
// every user's dynamic memberships, in the tenant's declared group order.
func (c *Config) evaluateDynamicGroups() error {
	for i := range c.Users {
		u := &c.Users[i]
		u.dynamicGroups = nil
		t := c.Tenant(u.TID)
		for _, name := range u.Groups {
			if g := t.groupMeta(name); g != nil && g.Dynamic() {
				return fmt.Errorf("user %s: group %q is dynamic; its members come from its membershipRule", u.Username, name)
			}
		}
		for j := range t.Groups {
			g := &t.Groups[j]
			if g.Dynamic() && g.rule.match(c, t, u) {
				u.dynamicGroups = append(u.dynamicGroups, g.Name)
			}
		}
	}
	return nil
}

// normalizeGroups validates a tenant's declared group metadata.
func normalizeGroups(t *Tenant) error {
	seen := map[string]bool{}
	oids := map[string]string{} // oid -> group name
	for i := range t.Groups {
		g := &t.Groups[i]
		g.Name = strings.TrimSpace(g.Name)
		if g.Name == "" {
			return fmt.Errorf("tenant %s: group %d: name is required", t.TID, i)
		}
		if seen[g.Name] {
			return fmt.Errorf("tenant %s: duplicate group %q", t.TID, g.Name)
		}
		seen[g.Name] = true
		g.OID = strings.ToLower(strings.TrimSpace(g.OID))
		if g.OID != "" && !guidRE.MatchString(g.OID) {
			return fmt.Errorf("tenant %s: group %s: oid must be a GUID", t.TID, g.Name)
		}
		oid := t.GroupOID(g.Name)
		if prev, dup := oids[oid]; dup {
			return fmt.Errorf("tenant %s: group %s: oid %s already used by group %s", t.TID, g.Name, oid, prev)
		}
		oids[oid] = g.Name
		g.MembershipRule = strings.TrimSpace(g.MembershipRule)
		g.rule = nil
		if g.Dynamic() {
			r, err := parseRule(g.MembershipRule)
			if err != nil {
				return fmt.Errorf("tenant %s: group %s: membershipRule: %w", t.TID, g.Name, err)
			}
			g.rule = r
		}
	}
	return nil
}

// reservedClaims are the claims Entra mode emits itself; a claims mapping may
// not overwrite them.
var reservedClaims = map[string]bool{
	"iss": true, "aud": true, "iat": true, "nbf": true, "exp": true, "tid": true, "oid": true,
	"sub": true, "ver": true, "name": true, "preferred_username": true, "uti": true, "nonce": true,
	"email": true, "xms_edov": true, "amr": true, "given_name": true, "family_name": true,
	"roles": true, "wids": true, "groups": true, "_claim_names": true, "_claim_sources": true,
	"scp": true, "azp": true, "appid": true, "idp": true,
}

// normalizeClaims validates an app's claims mappings.
func normalizeClaims(a *App) error {
	seen := map[string]bool{}
	for i := range a.Claims {
		m := &a.Claims[i]
		m.Name = strings.TrimSpace(m.Name)
		m.Source = strings.TrimSpace(m.Source)
		if m.Name == "" {
			return fmt.Errorf("app %s: claims[%d]: name is required", a.ClientID, i)
		}
		if reservedClaims[m.Name] {
			return fmt.Errorf("app %s: claim %q is emitted by Entra mode itself", a.ClientID, m.Name)
		}
		if seen[m.Name] {
			return fmt.Errorf("app %s: duplicate claim %q", a.ClientID, m.Name)
		}
		seen[m.Name] = true
		if _, ok := claimSources[strings.ToLower(m.Source)]; !ok {
			return fmt.Errorf("app %s: claim %s: unsupported source %q", a.ClientID, m.Name, m.Source)
		}
	}
	return nil
}

// normalizeRegistration validates an app's registration metadata and fills in
// the derived fields: display name (defaults to the clientId), object ID (a
// stable UUIDv5, like a user OID), and sign-in audience (from the tid).
func normalizeRegistration(a *App) error {
	if a.Name == "" {
		a.Name = a.ClientID
	}
	a.ObjectID = strings.ToLower(strings.TrimSpace(a.ObjectID))
	if a.ObjectID != "" && !guidRE.MatchString(a.ObjectID) {
		return fmt.Errorf("app %s: objectId must be a GUID", a.ClientID)
	}
	if a.ObjectID == "" {
		a.ObjectID = UUIDv5(appNamespace, "app:"+a.ClientID)
	}
	switch a.SignInAudience {
	case "":
		if a.TID != "" {
			a.SignInAudience = AudienceMyOrg
		} else {
			a.SignInAudience = AudienceMultiOrgs
		}
	case AudienceMyOrg, AudienceMultiOrgs:
	default:
		return fmt.Errorf("app %s: signInAudience must be %q or %q", a.ClientID, AudienceMyOrg, AudienceMultiOrgs)
	}
	if a.SignInAudience == AudienceMyOrg && a.TID == "" {
		return fmt.Errorf("app %s: signInAudience %q requires a tid", a.ClientID, AudienceMyOrg)
	}
	if a.SignInAudience == AudienceMultiOrgs && a.TID != "" {
		return fmt.Errorf("app %s: signInAudience %q cannot carry a tid", a.ClientID, AudienceMultiOrgs)
	}
	if a.CreatedOn != "" {
		if _, err := time.Parse(time.RFC3339, a.CreatedOn); err != nil {
			return fmt.Errorf("app %s: createdOn must be an RFC 3339 timestamp", a.ClientID)
		}
	}
	uris := map[string]bool{}
	for i := range a.RedirectURIs {
		r := &a.RedirectURIs[i]
		r.Platform = strings.TrimSpace(r.Platform)
		r.URI = strings.TrimSpace(r.URI)
		if r.URI == "" {
			return fmt.Errorf("app %s: redirectUris[%d]: uri is required", a.ClientID, i)
		}
		switch r.Platform {
		case PlatformWeb, PlatformSPA, PlatformMobileAndDesktop:
		case "":
			r.Platform = PlatformWeb
		default:
			return fmt.Errorf("app %s: redirectUris[%d]: platform must be %q, %q or %q",
				a.ClientID, i, PlatformWeb, PlatformSPA, PlatformMobileAndDesktop)
		}
		if err := validRedirectURI(r.Platform, r.URI); err != nil {
			return fmt.Errorf("app %s: redirectUris[%d]: %w", a.ClientID, i, err)
		}
		if uris[r.URI] {
			return fmt.Errorf("app %s: duplicate redirect uri %q", a.ClientID, r.URI)
		}
		uris[r.URI] = true
	}
	ids := map[string]bool{}
	for i := range a.Secrets {
		s := &a.Secrets[i]
		s.ID = strings.ToLower(strings.TrimSpace(s.ID))
		s.Description = strings.TrimSpace(s.Description)
		s.Value = strings.TrimSpace(s.Value)
		if s.ID == "" || !guidRE.MatchString(s.ID) {
			return fmt.Errorf("app %s: secrets[%d]: id must be a GUID", a.ClientID, i)
		}
		if ids[s.ID] {
			return fmt.Errorf("app %s: duplicate secret id %s", a.ClientID, s.ID)
		}
		ids[s.ID] = true
		if s.Value == "" {
			return fmt.Errorf("app %s: secrets[%d]: value is required", a.ClientID, i)
		}
		if _, err := time.Parse(time.RFC3339, s.Expires); err != nil {
			return fmt.Errorf("app %s: secrets[%d]: expires must be an RFC 3339 timestamp", a.ClientID, i)
		}
		if s.CreatedOn != "" {
			if _, err := time.Parse(time.RFC3339, s.CreatedOn); err != nil {
				return fmt.Errorf("app %s: secrets[%d]: createdOn must be an RFC 3339 timestamp", a.ClientID, i)
			}
		}
	}
	return nil
}

// validRedirectURI enforces per-platform URI shapes. Web and SPA redirects are
// https URLs (http is allowed on localhost, Entra's dev exception and what
// every e2e callback uses); mobile-and-desktop redirects are loopback http
// URLs or custom (non-http) schemes such as msal<id>://auth.
func validRedirectURI(platform, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return errors.New("not an absolute URI")
	}
	switch platform {
	case PlatformWeb, PlatformSPA:
		if (u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))) && u.Host != "" {
			return nil
		}
		return errors.New("web and spa redirect uris must be https URLs (http is allowed on localhost)")
	case PlatformMobileAndDesktop:
		if u.Scheme == "http" && isLoopback(u.Hostname()) {
			return nil
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil // custom scheme, e.g. msal4b1db123-...://auth (whose host is "auth")
		}
		return errors.New("mobileAndDesktop redirect uris must be custom schemes or http loopback URLs")
	}
	return nil
}

// isLoopback reports whether a URI host is a loopback name or address.
func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// RedirectAllowed reports whether redirectURI may be used by this app. An app
// without registered redirect URIs accepts anything (the permissive default
// every unregistered client gets); one with registrations requires an exact
// match, like Entra.
func (a *App) RedirectAllowed(uri string) bool {
	if len(a.RedirectURIs) == 0 {
		return true
	}
	for _, r := range a.RedirectURIs {
		if r.URI == uri {
			return true
		}
	}
	return false
}

// normalizeProfile validates and lowercases the optional account fields.
func normalizeProfile(u *User) error {
	u.UPN = strings.ToLower(strings.TrimSpace(u.UPN))
	u.Manager = strings.TrimSpace(u.Manager)
	for i, w := range u.WIDs {
		w = strings.ToLower(strings.TrimSpace(w))
		if !guidRE.MatchString(w) {
			return fmt.Errorf("user %s: wids[%d] must be a GUID", u.Username, i)
		}
		u.WIDs[i] = w
	}
	return nil
}

// Tenant returns the configured tenant for tid (case-insensitive), or nil.
func (c *Config) Tenant(tid string) *Tenant {
	tid = strings.ToLower(tid)
	for i := range c.Tenants {
		if c.Tenants[i].TID == tid {
			return &c.Tenants[i]
		}
	}
	return nil
}

// User returns the user with username in tenant tid, or nil.
func (c *Config) User(tid, username string) *User {
	tid = strings.ToLower(tid)
	for i := range c.Users {
		if c.Users[i].TID == tid && c.Users[i].Username == username {
			return &c.Users[i]
		}
	}
	return nil
}

// AppByID returns the registration with clientId, whatever tenant it is bound
// to, or nil. Enforcement (redirect URIs) and the admin UI key apps by
// clientId alone; the tenant-scoped lookup is Config.App in appcreds.go.
func (c *Config) AppByID(clientID string) *App {
	for i := range c.Apps {
		if c.Apps[i].ClientID == clientID {
			return &c.Apps[i]
		}
	}
	return nil
}

// UsersIn returns the users of tenant tid, or of all tenants when tid is "".
func (c *Config) UsersIn(tid string) []*User {
	tid = strings.ToLower(tid)
	var out []*User
	for i := range c.Users {
		if tid == "" || c.Users[i].TID == tid {
			out = append(out, &c.Users[i])
		}
	}
	return out
}
