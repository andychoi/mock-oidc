package entra

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrNotFound is returned by Store mutations that reference an unknown tenant
// or user.
var ErrNotFound = errors.New("not found")

// Store holds the mutable Entra-mode configuration as copy-on-write
// snapshots: every request reads one immutable *Config via Snapshot (a single
// atomic load, no locks on the hot path), writers deep-copy, mutate and
// re-normalize the whole config, then publish the new snapshot. normalize()
// doubles as the mutation validator, so a runtime-edited config keeps every
// startup invariant (GUID tids, unique usernames, consent/user tenant
// references, error enum, OID derivation) — the same errors, same order.
type Store struct {
	seed *Config // the parsed startup config (Reset target)
	mu   sync.Mutex
	cur  atomic.Pointer[Config]
}

// NewStore publishes a deep copy of seed.
func NewStore(seed *Config) *Store {
	s := &Store{seed: seed}
	s.cur.Store(cloneConfig(seed))
	return s
}

// Snapshot returns the current immutable configuration.
func (s *Store) Snapshot() *Config { return s.cur.Load() }

// Reset restores the startup configuration.
func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cur.Store(cloneConfig(s.seed))
}

// mutate applies fn to a deep copy of the current snapshot and publishes it
// when fn succeeds and the result still normalizes.
func (s *Store) mutate(fn func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneConfig(s.cur.Load())
	if err := fn(next); err != nil {
		return err
	}
	if err := next.normalize(); err != nil {
		return err
	}
	s.cur.Store(next)
	return nil
}

// SetGraphEnabled turns the Graph surface on or off at runtime. It goes
// through the same copy-on-write publish as every other edit, so the change is
// visible to the next request's snapshot and is undone by Reset.
func (s *Store) SetGraphEnabled(v bool) error {
	return s.mutate(func(c *Config) error {
		if c.Graph == nil {
			c.Graph = &GraphConfig{}
		}
		c.Graph.Enabled = boolPtr(v)
		return nil
	})
}

func normTID(tid string) string { return strings.ToLower(strings.TrimSpace(tid)) }

// CreateTenant adds a tenant (duplicate tids are rejected by normalize).
func (s *Store) CreateTenant(t Tenant) error {
	return s.mutate(func(c *Config) error {
		c.Tenants = append(c.Tenants, t)
		return nil
	})
}

// UpdateTenant replaces the non-tid fields of tenant tid; t.TID may be empty
// or equal (case-insensitive) — renaming a tid would orphan its users and
// consents, so it is rejected.
func (s *Store) UpdateTenant(tid string, t Tenant) error {
	tid = normTID(tid)
	if t.TID != "" && normTID(t.TID) != tid {
		return fmt.Errorf("tid cannot be changed")
	}
	t.TID = tid
	return s.mutate(func(c *Config) error {
		for i := range c.Tenants {
			if c.Tenants[i].TID == tid {
				c.Tenants[i] = t
				return nil
			}
		}
		return fmt.Errorf("tenant %s: %w", tid, ErrNotFound)
	})
}

// DeleteTenant removes the tenant; its users and seed consents are dropped
// from the snapshot by the cascade below (the caller purges runtime consents
// via ConsentStore.RemoveTenant). The last tenant cannot be deleted.
func (s *Store) DeleteTenant(tid string) error {
	tid = normTID(tid)
	return s.mutate(func(c *Config) error {
		kept := c.Tenants[:0]
		found := false
		for _, t := range c.Tenants {
			if t.TID == tid {
				found = true
				continue
			}
			kept = append(kept, t)
		}
		if !found {
			return fmt.Errorf("tenant %s: %w", tid, ErrNotFound)
		}
		c.Tenants = kept
		users := c.Users[:0]
		for _, u := range c.Users {
			if u.TID != tid {
				users = append(users, u)
			}
		}
		c.Users = users
		consents := c.Consents[:0]
		for _, cs := range c.Consents {
			if cs.TID != tid {
				consents = append(consents, cs)
			}
		}
		c.Consents = consents
		return nil
	})
}

// CreateUser adds a user (tenant existence, uniqueness and OID derivation are
// enforced by normalize).
func (s *Store) CreateUser(u User) error {
	return s.mutate(func(c *Config) error {
		c.Users = append(c.Users, u)
		return nil
	})
}

// UpdateUser replaces the identity fields of the user username in tenant tid;
// tid and username are immutable (rename = delete + create, keeping auth-code
// references unambiguous).
func (s *Store) UpdateUser(tid, username string, u User) error {
	tid = normTID(tid)
	if u.TID != "" && normTID(u.TID) != tid {
		return fmt.Errorf("tid cannot be changed")
	}
	u.TID = tid
	return s.mutate(func(c *Config) error {
		for i := range c.Users {
			if c.Users[i].TID == tid && c.Users[i].Username == username {
				u.Username = username
				c.Users[i] = u
				return nil
			}
		}
		return fmt.Errorf("user %s in tenant %s: %w", username, tid, ErrNotFound)
	})
}

// DeleteUser removes the user username from tenant tid.
func (s *Store) DeleteUser(tid, username string) error {
	tid = normTID(tid)
	return s.mutate(func(c *Config) error {
		users := c.Users[:0]
		found := false
		for _, u := range c.Users {
			if u.TID == tid && u.Username == username {
				found = true
				continue
			}
			users = append(users, u)
		}
		if !found {
			return fmt.Errorf("user %s in tenant %s: %w", username, tid, ErrNotFound)
		}
		c.Users = users
		// Reports of the deleted user lose their manager rather than making
		// the whole mutation fail validation.
		for i := range c.Users {
			if c.Users[i].TID == tid && c.Users[i].Manager == username {
				c.Users[i].Manager = ""
			}
		}
		return nil
	})
}

// CreateApp adds an app registration and returns it as stored: an empty
// clientId gets a generated GUID (the New registration form), normalize derives
// the object ID and sign-in audience. now stamps CreatedOn when unset.
func (s *Store) CreateApp(a App, now time.Time) (App, error) {
	if a.ClientID == "" {
		a.ClientID = RandomGUID()
	}
	if a.CreatedOn == "" {
		a.CreatedOn = now.UTC().Format(time.RFC3339)
	}
	if err := s.mutate(func(c *Config) error {
		c.Apps = append(c.Apps, a)
		return nil
	}); err != nil {
		return App{}, err
	}
	stored := s.Snapshot().AppByID(a.ClientID)
	if stored == nil { // unreachable: mutate published a config containing it
		return App{}, fmt.Errorf("app %s: %w", a.ClientID, ErrNotFound)
	}
	return *stored, nil
}

// UpdateApp replaces the registration fields of app clientID (name, tid,
// sign-in audience, redirect URIs, roles, claims). clientId is immutable — it
// keys consents and issued tokens; object ID and CreatedOn keep their stored
// values when the body omits them; secrets are managed by AddAppSecret and
// DeleteAppSecret and are preserved regardless of the body.
func (s *Store) UpdateApp(clientID string, a App) error {
	if a.ClientID != "" && a.ClientID != clientID {
		return fmt.Errorf("clientId cannot be changed")
	}
	return s.mutate(func(c *Config) error {
		for i := range c.Apps {
			if c.Apps[i].ClientID != clientID {
				continue
			}
			a.ClientID = clientID
			if a.ObjectID == "" {
				a.ObjectID = c.Apps[i].ObjectID
			}
			if a.CreatedOn == "" {
				a.CreatedOn = c.Apps[i].CreatedOn
			}
			a.Secrets = c.Apps[i].Secrets
			c.Apps[i] = a
			return nil
		}
		return fmt.Errorf("app %s: %w", clientID, ErrNotFound)
	})
}

// DeleteApp removes the app registration and the seed consents naming it (the
// caller purges runtime consents via ConsentStore.RemoveClient).
func (s *Store) DeleteApp(clientID string) error {
	return s.mutate(func(c *Config) error {
		kept := c.Apps[:0]
		found := false
		for _, a := range c.Apps {
			if a.ClientID == clientID {
				found = true
				continue
			}
			kept = append(kept, a)
		}
		if !found {
			return fmt.Errorf("app %s: %w", clientID, ErrNotFound)
		}
		c.Apps = kept
		consents := c.Consents[:0]
		for _, cs := range c.Consents {
			if cs.ClientID != clientID {
				consents = append(consents, cs)
			}
		}
		c.Consents = consents
		return nil
	})
}

// AddAppSecret adds a client secret to app clientID and returns it with its
// one-time value. expires is either an Entra relative duration ("6m", "12m",
// "24m" — months) or an absolute RFC 3339 timestamp.
func (s *Store) AddAppSecret(clientID, description, expires string, now time.Time) (AppSecret, error) {
	exp, err := secretExpiry(expires, now)
	if err != nil {
		return AppSecret{}, fmt.Errorf("app %s: %w", clientID, err)
	}
	sec := AppSecret{
		ID:          RandomGUID(),
		Description: strings.TrimSpace(description),
		Value:       RandomSecretValue(),
		Expires:     exp.UTC().Format(time.RFC3339),
		CreatedOn:   now.UTC().Format(time.RFC3339),
	}
	if err := s.mutate(func(c *Config) error {
		for i := range c.Apps {
			if c.Apps[i].ClientID == clientID {
				c.Apps[i].Secrets = append(c.Apps[i].Secrets, sec)
				return nil
			}
		}
		return fmt.Errorf("app %s: %w", clientID, ErrNotFound)
	}); err != nil {
		return AppSecret{}, err
	}
	return sec, nil
}

// DeleteAppSecret removes one secret of app clientID by its secret ID.
func (s *Store) DeleteAppSecret(clientID, secretID string) error {
	return s.mutate(func(c *Config) error {
		for i := range c.Apps {
			if c.Apps[i].ClientID != clientID {
				continue
			}
			kept := c.Apps[i].Secrets[:0]
			found := false
			for _, sec := range c.Apps[i].Secrets {
				if sec.ID == secretID {
					found = true
					continue
				}
				kept = append(kept, sec)
			}
			if !found {
				return fmt.Errorf("app %s: secret %s: %w", clientID, secretID, ErrNotFound)
			}
			c.Apps[i].Secrets = kept
			return nil
		}
		return fmt.Errorf("app %s: %w", clientID, ErrNotFound)
	})
}

// secretExpiry resolves a secret's expiry: "6m", "12m" and "24m" count months
// from now (the New client secret dialog), anything else must be RFC 3339.
func secretExpiry(expires string, now time.Time) (time.Time, error) {
	switch strings.TrimSpace(expires) {
	case "6m":
		return now.AddDate(0, 6, 0), nil
	case "12m":
		return now.AddDate(1, 0, 0), nil
	case "24m":
		return now.AddDate(2, 0, 0), nil
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(expires))
	if err != nil {
		return time.Time{}, errors.New("expires must be 6m, 12m, 24m or an RFC 3339 timestamp")
	}
	return t, nil
}

// cloneConfig deep-copies the slice fields so published snapshots never share
// backing arrays with a future mutation.
func cloneConfig(c *Config) *Config {
	out := &Config{
		BasePath:          c.BasePath,
		DefaultGroupLimit: c.DefaultGroupLimit,
		TokenExpiry:       c.TokenExpiry,
		IgnoreLoginHint:   c.IgnoreLoginHint,
		Graph:             c.Graph.clone(),
		Tenants:           make([]Tenant, len(c.Tenants)),
		Consents:          append([]Consent(nil), c.Consents...),
		Apps:              make([]App, len(c.Apps)),
		Users:             make([]User, len(c.Users)),
	}
	for i, t := range c.Tenants {
		out.Tenants[i] = t
		out.Tenants[i].Domains = append([]string(nil), t.Domains...)
		out.Tenants[i].Groups = make([]Group, len(t.Groups))
		for j, g := range t.Groups {
			out.Tenants[i].Groups[j] = g
			out.Tenants[i].Groups[j].SecurityEnabled = copyBool(g.SecurityEnabled)
			out.Tenants[i].Groups[j].MailEnabled = copyBool(g.MailEnabled)
		}
	}
	for i, a := range c.Apps {
		out.Apps[i] = a
		out.Apps[i].Roles = append([]string(nil), a.Roles...)
		out.Apps[i].Claims = append([]ClaimMapping(nil), a.Claims...)
		out.Apps[i].RedirectURIs = append([]RedirectURI(nil), a.RedirectURIs...)
		out.Apps[i].Secrets = append([]AppSecret(nil), a.Secrets...)
	}
	for i, u := range c.Users {
		out.Users[i] = u
		out.Users[i].Groups = append([]string(nil), u.Groups...)
		out.Users[i].AMR = append([]string(nil), u.AMR...)
		out.Users[i].BusinessPhones = append([]string(nil), u.BusinessPhones...)
		out.Users[i].Roles = append([]string(nil), u.Roles...)
		out.Users[i].WIDs = append([]string(nil), u.WIDs...)
		out.Users[i].dynamicGroups = append([]string(nil), u.dynamicGroups...)
		out.Users[i].EmailVerified = copyBool(u.EmailVerified)
		out.Users[i].AccountEnabled = copyBool(u.AccountEnabled)
	}
	return out
}
