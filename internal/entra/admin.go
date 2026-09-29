package entra

import "github.com/andychoi/mock-oidc/internal/jsonx"

// This file exposes the read-mostly state and the two mutation actions the
// admin UI (internal/adminui) renders, via the adminui.EntraState interface.
// Slicing through an interface keeps entra free of adminui/config/server
// imports (see docs/entra/01-plan.md).

// AdminSnapshot renders the full Entra-mode state for the admin UI: the
// configured tenants and users, the current consents, and the published key
// kids. Values already public via config files and the /_entra test API.
func (h *Handler) AdminSnapshot() any {
	tenants := jsonx.Arr{}
	for _, t := range h.cfg.Tenants {
		tenants = append(tenants, jsonx.Obj{
			{Name: "tid", V: t.TID},
			{Name: "name", V: t.Name},
			{Name: "domains", V: t.Domains},
			{Name: "groupClaimFormat", V: t.GroupClaimFormat},
			{Name: "groupLimit", V: t.GroupLimit},
			{Name: "consentRequired", V: t.ConsentRequired},
		})
	}
	users := jsonx.Arr{}
	for _, u := range h.cfg.Users {
		users = append(users, jsonx.Obj{
			{Name: "username", V: u.Username},
			{Name: "tid", V: u.TID},
			{Name: "oid", V: u.OID},
			{Name: "name", V: u.Name},
			{Name: "email", V: u.Email},
			{Name: "groups", V: u.Groups},
			{Name: "amr", V: u.AMR},
			{Name: "admin", V: u.Admin},
			{Name: "error", V: u.Error},
		})
	}
	consents := jsonx.Arr{}
	for _, c := range h.consents.List() {
		consents = append(consents, jsonx.Obj{
			{Name: "clientId", V: c.ClientID},
			{Name: "tid", V: c.TID},
		})
	}
	return jsonx.Obj{
		{Name: "basePath", V: h.cfg.BasePath},
		{Name: "defaultGroupLimit", V: h.cfg.DefaultGroupLimit},
		{Name: "tokenExpiry", V: h.cfg.TokenExpiry},
		{Name: "tenants", V: tenants},
		{Name: "users", V: users},
		{Name: "consents", V: consents},
		{Name: "keys", V: jsonx.Obj{
			{Name: "activeKid", V: h.keys.ActiveKid()},
			{Name: "publishedKids", V: h.keys.PublishedKids()},
		}},
	}
}

// AdminResetConsents restores the seed consents (same as POST _entra/reset).
func (h *Handler) AdminResetConsents() { h.consents.Reset() }

// AdminRotateKeys rotates the signing key set and returns the new kid (same as
// POST _entra/rotate-keys).
func (h *Handler) AdminRotateKeys() string { return h.keys.Rotate() }
