package entra

import (
	"sort"
	"strings"
	"unicode"
)

// DirGroup is one group as the Graph surface sees it. Groups are not a
// separate config entity: membership lives on the user (User.Groups) and a
// tenant's groups are the union of the names its users use and the names it
// declares metadata for. The object ID is the one GroupObjectID already emits
// for "object_id" group claims, so a claim value and a Graph group are the
// same identifier.
type DirGroup struct {
	OID             string
	Name            string
	Description     string
	MailNickname    string
	Mail            string
	SecurityEnabled bool
	MailEnabled     bool
	MembershipRule  string // non-empty for a dynamic group
}

// Enabled reports whether the account may sign in. Unset means enabled.
func (u *User) Enabled() bool {
	return u.AccountEnabled == nil || *u.AccountEnabled
}

// PrincipalName is the user's UPN: the configured one, else the value the
// preferred_username claim has always used (email, else username@domain,
// else username).
func (u *User) PrincipalName(t *Tenant) string {
	if u.UPN != "" {
		return u.UPN
	}
	return preferredUsername(t, u)
}

// MemberGroups is the user's effective membership: the statically assigned
// group names followed by the dynamic ones, without duplicates. Every
// membership consumer (the groups claim, memberOf, members) reads this.
func (u *User) MemberGroups() []string {
	if len(u.dynamicGroups) == 0 {
		return u.Groups
	}
	out := make([]string, 0, len(u.Groups)+len(u.dynamicGroups))
	seen := map[string]bool{}
	for _, list := range [][]string{u.Groups, u.dynamicGroups} {
		for _, name := range list {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// DynamicGroups returns the names of the dynamic groups the user's attributes
// currently match.
func (u *User) DynamicGroups() []string { return u.dynamicGroups }

// MailOrEmpty is the user's mailbox address, which Graph reports as null when
// there is none.
func (u *User) MailOrEmpty() string { return u.Email }

// mailNickname derives Graph's mailNickname from a display name: the
// alphanumeric characters, lowercased.
func mailNickname(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// groupMeta returns the declared metadata for a group name in a tenant.
func (t *Tenant) groupMeta(name string) *Group {
	for i := range t.Groups {
		if t.Groups[i].Name == name {
			return &t.Groups[i]
		}
	}
	return nil
}

// dirGroup builds the Graph view of one group name in a tenant.
func (c *Config) dirGroup(t *Tenant, name string) DirGroup {
	g := DirGroup{
		OID:             GroupObjectID(t.TID, name),
		Name:            name,
		MailNickname:    mailNickname(name),
		SecurityEnabled: true,
	}
	meta := t.groupMeta(name)
	if meta == nil {
		return g
	}
	if meta.OID != "" {
		g.OID = meta.OID
	}
	g.Description = meta.Description
	g.Mail = meta.Mail
	g.MembershipRule = meta.MembershipRule
	if meta.MailNickname != "" {
		g.MailNickname = meta.MailNickname
	}
	if meta.SecurityEnabled != nil {
		g.SecurityEnabled = *meta.SecurityEnabled
	}
	if meta.MailEnabled != nil {
		g.MailEnabled = *meta.MailEnabled
	}
	return g
}

// sortGroups orders groups by object ID, so offset paging is deterministic.
func sortGroups(gs []DirGroup) []DirGroup {
	sort.Slice(gs, func(i, j int) bool { return gs[i].OID < gs[j].OID })
	return gs
}

// GroupsIn returns every group of a tenant: the names its users belong to,
// plus the names it declares metadata for, ordered by object ID.
func (c *Config) GroupsIn(tid string) []DirGroup {
	t := c.Tenant(tid)
	if t == nil {
		return nil
	}
	seen := map[string]bool{}
	out := []DirGroup{}
	add := func(name string) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, c.dirGroup(t, name))
	}
	for i := range t.Groups {
		add(t.Groups[i].Name)
	}
	for _, u := range c.UsersIn(t.TID) {
		for _, name := range u.MemberGroups() {
			add(name)
		}
	}
	return sortGroups(out)
}

// GroupByID resolves a group of a tenant by object ID or display name.
func (c *Config) GroupByID(tid, id string) *DirGroup {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	lower := strings.ToLower(id)
	for _, g := range c.GroupsIn(tid) {
		if strings.ToLower(g.OID) == lower || g.Name == id {
			out := g
			return &out
		}
	}
	return nil
}

// GroupsOf returns the groups a user belongs to, ordered by object ID.
func (c *Config) GroupsOf(u *User) []DirGroup {
	t := c.Tenant(u.TID)
	if t == nil {
		return nil
	}
	seen := map[string]bool{}
	out := []DirGroup{}
	for _, name := range u.MemberGroups() {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, c.dirGroup(t, name))
	}
	return sortGroups(out)
}

// GroupIDsOf returns just the object IDs of a user's groups, in the same
// order as GroupsOf. This is what getMemberObjects answers.
func (c *Config) GroupIDsOf(u *User) []string {
	groups := c.GroupsOf(u)
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		ids = append(ids, g.OID)
	}
	return ids
}

// MembersOf returns the users in a group of a tenant, ordered by object ID.
func (c *Config) MembersOf(tid, groupID string) []*User {
	g := c.GroupByID(tid, groupID)
	if g == nil {
		return nil
	}
	out := []*User{}
	for _, u := range c.UsersIn(tid) {
		for _, name := range u.MemberGroups() {
			if name == g.Name {
				out = append(out, u)
				break
			}
		}
	}
	return sortUsers(out)
}

// sortUsers orders users by object ID, so offset paging is deterministic.
func sortUsers(us []*User) []*User {
	sort.Slice(us, func(i, j int) bool { return us[i].OID < us[j].OID })
	return us
}

// UsersOrderedIn returns a tenant's users ordered by object ID.
func (c *Config) UsersOrderedIn(tid string) []*User { return sortUsers(c.UsersIn(tid)) }

// UserByOID returns the user with that object ID in a tenant, or nil.
func (c *Config) UserByOID(tid, oid string) *User {
	tid, oid = strings.ToLower(tid), strings.ToLower(strings.TrimSpace(oid))
	if oid == "" {
		return nil
	}
	for _, u := range c.UsersIn(tid) {
		if u.OID == oid {
			return u
		}
	}
	return nil
}

// UserByUPNOrOID resolves a user by object ID or user principal name, the two
// keys real Graph accepts in /users/{id}. The username is accepted too, so a
// fixture is reachable by the name it is configured under.
func (c *Config) UserByUPNOrOID(tid, key string) *User {
	if u := c.UserByOID(tid, key); u != nil {
		return u
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	lower := strings.ToLower(key)
	t := c.Tenant(tid)
	if t == nil {
		return nil
	}
	for _, u := range c.UsersIn(t.TID) {
		if strings.ToLower(u.PrincipalName(t)) == lower || u.Username == key {
			return u
		}
	}
	return nil
}

// ManagerOf returns the user's manager, or nil.
func (c *Config) ManagerOf(u *User) *User {
	if u.Manager == "" {
		return nil
	}
	return c.User(u.TID, u.Manager)
}

// DirectReports returns the users managed by u, ordered by object ID.
func (c *Config) DirectReports(u *User) []*User {
	out := []*User{}
	for _, other := range c.UsersIn(u.TID) {
		if other.Manager == u.Username {
			out = append(out, other)
		}
	}
	return sortUsers(out)
}
