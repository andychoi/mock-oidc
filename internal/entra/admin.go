package entra

import "github.com/andychoi/mock-oidc/internal/jsonx"

// This file exposes the Entra-mode state and the admin actions the admin UI
// (internal/adminui) renders. Mutations run through the copy-on-write Store,
// so a runtime-edited config keeps every startup invariant; edits are
// in-memory only and Reset restores the config seed.

// AdminSnapshot renders the full Entra-mode state for the admin UI: the
// current tenants and users, the current consents, and the published key
// kids.
func (h *Handler) AdminSnapshot() any {
	cfg := h.conf()
	tenants := jsonx.Arr{}
	for _, t := range cfg.Tenants {
		tenants = append(tenants, jsonx.Obj{
			{Name: "tid", V: t.TID},
			{Name: "name", V: t.Name},
			{Name: "domains", V: t.Domains},
			{Name: "groupClaimFormat", V: t.GroupClaimFormat},
			{Name: "groupLimit", V: t.GroupLimit},
			{Name: "consentRequired", V: t.ConsentRequired},
			{Name: "groups", V: tenantGroups(t)},
		})
	}
	users := jsonx.Arr{}
	for _, u := range cfg.Users {
		users = append(users, jsonx.Obj{
			{Name: "username", V: u.Username},
			{Name: "tid", V: u.TID},
			{Name: "oid", V: u.OID},
			{Name: "name", V: u.Name},
			{Name: "email", V: u.Email},
			{Name: "emailVerified", V: u.EmailVerified},
			{Name: "groups", V: u.Groups},
			{Name: "dynamicGroups", V: u.DynamicGroups()},
			{Name: "amr", V: u.AMR},
			{Name: "admin", V: u.Admin},
			{Name: "error", V: u.Error},
			{Name: "givenName", V: u.GivenName},
			{Name: "surname", V: u.Surname},
			{Name: "upn", V: u.UPN},
			{Name: "accountEnabled", V: u.Enabled()},
			{Name: "jobTitle", V: u.JobTitle},
			{Name: "officeLocation", V: u.OfficeLocation},
			{Name: "businessPhones", V: u.BusinessPhones},
			{Name: "mobilePhone", V: u.MobilePhone},
			{Name: "preferredLanguage", V: u.PreferredLanguage},
			{Name: "roles", V: u.Roles},
			{Name: "wids", V: u.WIDs},
			{Name: "manager", V: u.Manager},
			{Name: "department", V: u.Department},
			{Name: "companyName", V: u.CompanyName},
			{Name: "employeeId", V: u.EmployeeID},
			{Name: "onPremisesExtensionAttributes", V: jsonx.Obj{
				{Name: "extensionAttribute1", V: u.ExtensionAttributes.ExtensionAttribute1},
				{Name: "extensionAttribute2", V: u.ExtensionAttributes.ExtensionAttribute2},
				{Name: "extensionAttribute3", V: u.ExtensionAttributes.ExtensionAttribute3},
			}},
		})
	}
	consents := jsonx.Arr{}
	for _, c := range h.consents.List() {
		consents = append(consents, jsonx.Obj{
			{Name: "clientId", V: c.ClientID},
			{Name: "tid", V: c.TID},
		})
	}
	apps := jsonx.Arr{}
	for _, a := range cfg.Apps {
		apps = append(apps, jsonx.Obj{
			{Name: "clientId", V: a.ClientID},
			{Name: "tid", V: a.TID},
			{Name: "roles", V: a.Roles},
		})
	}
	return jsonx.Obj{
		{Name: "basePath", V: cfg.BasePath},
		{Name: "defaultGroupLimit", V: cfg.DefaultGroupLimit},
		{Name: "tokenExpiry", V: cfg.TokenExpiry},
		{Name: "ignoreLoginHint", V: cfg.IgnoreLoginHint},
		{Name: "graph", V: jsonx.Obj{
			{Name: "enabled", V: cfg.GraphOn()},
			{Name: "basePath", V: cfg.GraphBase()},
			{Name: "userinfo", V: cfg.UserInfoOn()},
			{Name: "appOnly", V: cfg.AppOnlyOn()},
			{Name: "overageSelfHosted", V: cfg.OverageSelfHosted()},
		}},
		{Name: "apps", V: apps},
		{Name: "tenants", V: tenants},
		{Name: "users", V: users},
		{Name: "consents", V: consents},
		{Name: "keys", V: jsonx.Obj{
			{Name: "activeKid", V: h.keys.ActiveKid()},
			{Name: "publishedKids", V: h.keys.PublishedKids()},
		}},
	}
}

// tenantGroups renders a tenant's declared groups: the object ID a group
// claim will carry (oid), plus the configured metadata as-is, so the admin UI
// can round-trip it on a tenant save without pinning derived values.
func tenantGroups(t Tenant) jsonx.Arr {
	out := jsonx.Arr{}
	for _, g := range t.Groups {
		oid := g.OID
		if oid == "" {
			oid = GroupObjectID(t.TID, g.Name)
		}
		out = append(out, jsonx.Obj{
			{Name: "name", V: g.Name},
			{Name: "description", V: g.Description},
			{Name: "oid", V: oid},
			{Name: "configuredOid", V: g.OID},
			{Name: "mailNickname", V: g.MailNickname},
			{Name: "mail", V: g.Mail},
			{Name: "securityEnabled", V: g.SecurityEnabled},
			{Name: "mailEnabled", V: g.MailEnabled},
			{Name: "membershipRule", V: g.MembershipRule},
		})
	}
	return out
}

// AdminGraphEnabled reports whether the Graph surface is serving.
func (h *Handler) AdminGraphEnabled() bool { return h.conf().GraphOn() }

// AdminSetGraphEnabled turns the Graph surface on or off at runtime.
func (h *Handler) AdminSetGraphEnabled(v bool) error { return h.store.SetGraphEnabled(v) }

// AdminCreateTenant adds a tenant (validation errors return as-is).
func (h *Handler) AdminCreateTenant(t Tenant) error { return h.store.CreateTenant(t) }

// AdminUpdateTenant replaces the editable fields of tenant tid.
func (h *Handler) AdminUpdateTenant(tid string, t Tenant) error { return h.store.UpdateTenant(tid, t) }

// AdminDeleteTenant removes a tenant, its users and its consents.
func (h *Handler) AdminDeleteTenant(tid string) error {
	if err := h.store.DeleteTenant(tid); err != nil {
		return err
	}
	h.consents.RemoveTenant(tid)
	return nil
}

// AdminCreateUser adds a user.
func (h *Handler) AdminCreateUser(u User) error { return h.store.CreateUser(u) }

// AdminUpdateUser replaces the editable fields of the user username in tid.
func (h *Handler) AdminUpdateUser(tid, username string, u User) error {
	return h.store.UpdateUser(tid, username, u)
}

// AdminDeleteUser removes the user username from tenant tid.
func (h *Handler) AdminDeleteUser(tid, username string) error {
	return h.store.DeleteUser(tid, username)
}

// AdminRevokeConsent removes one consent (seeded consents return on Reset).
func (h *Handler) AdminRevokeConsent(clientID, tid string) { h.consents.Remove(clientID, tid) }

// AdminResetToSeed restores tenants, users and consents to the config seed
// (signing keys are untouched). Broader than the consents-only _entra/reset
// test endpoint, which keeps its documented contract.
func (h *Handler) AdminResetToSeed() {
	h.store.Reset()
	h.consents.Reset()
}

// AdminRotateKeys rotates the signing key set and returns the new kid (same
// as POST _entra/rotate-keys).
func (h *Handler) AdminRotateKeys() string { return h.keys.Rotate() }
