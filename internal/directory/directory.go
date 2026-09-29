// Package directory holds the navikt-mode login directory: the users shown
// as quick-picks on the custom login page, seeded from the canonical
// demo-users.json via USER_DIRECTORY_PATH. The directory only feeds the login
// page — the server still accepts any username (navikt parity); maintaining
// it here keeps the page's hardcoded mirror in sync with one source.
package directory

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// User is one directory entry (the demo-users.json shape).
type User struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}

// Directory is an in-memory, mutex-guarded user list with a seed for Reset.
type Directory struct {
	mu    sync.RWMutex
	seed  []User
	users []User
}

// LoadFile reads the seed directory from a JSON file (missing file returns an
// empty, unseeded directory — the login page then shows the manual form only).
func LoadFile(path string) (*Directory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Directory{}, nil
		}
		return nil, fmt.Errorf("user directory: %w", err)
	}
	var users []User
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, fmt.Errorf("user directory %s: %w", path, err)
	}
	return New(users), nil
}

// New builds a directory seeded with users.
func New(seed []User) *Directory {
	d := &Directory{seed: append([]User(nil), seed...)}
	d.users = append([]User(nil), seed...)
	return d
}

// List returns the users sorted by username.
func (d *Directory) List() []User {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := append([]User(nil), d.users...)
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// Get returns the user with username, or nil.
func (d *Directory) Get(username string) *User {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for i := range d.users {
		if d.users[i].Username == username {
			u := d.users[i]
			return &u
		}
	}
	return nil
}

// Upsert inserts or replaces the user (keyed by username).
func (d *Directory) Upsert(u User) error {
	u.Username = strings.TrimSpace(u.Username)
	if u.Username == "" {
		return fmt.Errorf("username is required")
	}
	u.Groups = compact(u.Groups)
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.users {
		if d.users[i].Username == u.Username {
			d.users[i] = u
			return nil
		}
	}
	d.users = append(d.users, u)
	return nil
}

// Delete removes the user username.
func (d *Directory) Delete(username string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	kept := d.users[:0]
	found := false
	for _, u := range d.users {
		if u.Username == username {
			found = true
			continue
		}
		kept = append(kept, u)
	}
	if !found {
		return fmt.Errorf("user %s: not found", username)
	}
	d.users = kept
	return nil
}

// Reset restores the seed directory.
func (d *Directory) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users = append([]User(nil), d.seed...)
}

// compact trims and drops empty group names.
func compact(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
