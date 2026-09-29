package entra

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
		return nil
	})
}

// cloneConfig deep-copies the slice fields so published snapshots never share
// backing arrays with a future mutation.
func cloneConfig(c *Config) *Config {
	out := &Config{
		BasePath:          c.BasePath,
		DefaultGroupLimit: c.DefaultGroupLimit,
		TokenExpiry:       c.TokenExpiry,
		Tenants:           make([]Tenant, len(c.Tenants)),
		Consents:          append([]Consent(nil), c.Consents...),
		Users:             make([]User, len(c.Users)),
	}
	for i, t := range c.Tenants {
		out.Tenants[i] = t
		out.Tenants[i].Domains = append([]string(nil), t.Domains...)
	}
	for i, u := range c.Users {
		out.Users[i] = u
		out.Users[i].Groups = append([]string(nil), u.Groups...)
		out.Users[i].AMR = append([]string(nil), u.AMR...)
	}
	return out
}
