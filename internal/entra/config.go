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
	BasePath          string    `json:"basePath"`
	DefaultGroupLimit int       `json:"defaultGroupLimit"`
	TokenExpiry       int64     `json:"tokenExpiry"`
	Tenants           []Tenant  `json:"tenants"`
	Consents          []Consent `json:"consents"`
	Users             []User    `json:"users"`
}

// Tenant is one emulated Entra tenant.
type Tenant struct {
	TID              string   `json:"tid"`
	Name             string   `json:"name"`
	Domains          []string `json:"domains"`
	GroupClaimFormat string   `json:"groupClaimFormat"`
	GroupLimit       int      `json:"groupLimit"`
	ConsentRequired  bool     `json:"consentRequired"`
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
