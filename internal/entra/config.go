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
	"regexp"
	"strings"
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
// every flow; an entry here only supplies the app roles an app-only token
// carries (§8 of the Graph design).
type App struct {
	ClientID string   `json:"clientId"`
	TID      string   `json:"tid"`
	Roles    []string `json:"roles"`
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
// not declared here still becomes a Graph group, with empty metadata.
type Group struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	MailNickname    string `json:"mailNickname"`
	Mail            string `json:"mail"`
	OID             string `json:"oid"`
	SecurityEnabled *bool  `json:"securityEnabled"`
	MailEnabled     *bool  `json:"mailEnabled"`
}

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
	for i := range c.Apps {
		a := &c.Apps[i]
		a.ClientID = strings.TrimSpace(a.ClientID)
		a.TID = strings.ToLower(strings.TrimSpace(a.TID))
		if a.ClientID == "" {
			return fmt.Errorf("app %d: clientId is required", i)
		}
		if a.TID != "" && !tenants[a.TID] {
			return fmt.Errorf("app %s: unknown tid %q", a.ClientID, a.TID)
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
		u.OID = strings.ToLower(u.OID)
		if u.OID != "" && !guidRE.MatchString(u.OID) {
			return fmt.Errorf("user %s: oid must be a GUID", u.Username)
		}
		if u.OID == "" {
			u.OID = UUIDv5(oidNamespace, u.TID+":"+u.Username)
		}
		if u.Name == "" {
			u.Name = u.Username
		}
		if err := normalizeProfile(u); err != nil {
			return err
		}
	}
	// Managers resolve against the whole user set, so they need a second pass.
	for i := range c.Users {
		u := &c.Users[i]
		if u.Manager == "" {
			continue
		}
		if u.Manager == u.Username {
			return fmt.Errorf("user %s: manager cannot be the user itself", u.Username)
		}
		if !users[u.TID+"/"+u.Manager] {
			return fmt.Errorf("user %s: unknown manager %q in tenant %s", u.Username, u.Manager, u.TID)
		}
	}
	return nil
}

// normalizeGroups validates a tenant's declared group metadata.
func normalizeGroups(t *Tenant) error {
	seen := map[string]bool{}
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
	}
	return nil
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
