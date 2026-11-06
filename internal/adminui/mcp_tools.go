package adminui

import (
	"encoding/json"
	"reflect"

	"github.com/andychoi/mock-oidc/internal/directory"
	"github.com/andychoi/mock-oidc/internal/entra"
	"github.com/andychoi/mock-oidc/internal/jsonx"
)

type owner uint8

const (
	ownerSettings owner = iota + 1
	ownerDirectory
	ownerEntra
)

type effect uint8

const (
	reads    effect = iota + 1 // readOnlyHint
	writes                     // neither hint: additive or reversible edit
	destroys                   // destructiveHint
)

type toolCtx struct {
	entra    *entra.Handler
	dir      *directory.Directory
	settings Settings
	origin   string
}

type tool struct {
	name        string
	description string
	owner       owner
	effect      effect
	schema      jsonx.Obj
	call        func(c toolCtx, args json.RawMessage) (jsonx.Obj, error)
}

func defineTool[In any](name, description string, o owner, e effect, fn func(toolCtx, In) (jsonx.Obj, error)) tool {
	spec := specFor(reflect.TypeFor[In]())
	return tool{
		name: name, description: description, owner: o, effect: e, schema: spec.schema,
		call: func(c toolCtx, args json.RawMessage) (jsonx.Obj, error) {
			var in In
			if err := strictDecode(args, spec, &in); err != nil {
				return nil, err
			}
			return fn(c, in)
		},
	}
}

var registry = []tool{
	defineTool("settings_get", "Read the live runtime toggles (interactiveLogin, rotateRefreshToken, entra, graph).",
		ownerSettings, reads, settingsGet),
	defineTool("settings_set", "Turn one runtime toggle on or off. In-memory; a restart restores the config.",
		ownerSettings, writes, settingsSet),

	defineTool("directory_list", "List the login-page directory users.",
		ownerDirectory, reads, directoryList),
	defineTool("directory_upsert_user", "Create or replace a login-page directory user, keyed by username.",
		ownerDirectory, writes, directoryUpsert),
	defineTool("directory_delete_user", "Delete a login-page directory user.",
		ownerDirectory, destroys, directoryDelete),
	defineTool("directory_reset", "Restore the login-page directory to its startup seed.",
		ownerDirectory, destroys, directoryReset),

	defineTool("entra_get_state", "Snapshot of Entra mode: apps, tenants with group object IDs, users, consents and signing key IDs.",
		ownerEntra, reads, entraGetState),
	defineTool("entra_create_tenant", "Add an Entra tenant.",
		ownerEntra, writes, entraCreateTenant),
	defineTool("entra_update_tenant", "Replace the editable fields of the Entra tenant tid.",
		ownerEntra, writes, entraUpdateTenant),
	defineTool("entra_delete_tenant", "Delete an Entra tenant with its users and consents.",
		ownerEntra, destroys, entraDeleteTenant),
	defineTool("entra_create_user", "Add a user to an Entra tenant.",
		ownerEntra, writes, entraCreateUser),
	defineTool("entra_update_user", "Replace the fields of the Entra user username in tenant tid.",
		ownerEntra, writes, entraUpdateUser),
	defineTool("entra_delete_user", "Delete an Entra user.",
		ownerEntra, destroys, entraDeleteUser),
	defineTool("entra_revoke_consent", "Revoke one app's consent in a tenant. Revoking an absent consent succeeds.",
		ownerEntra, destroys, entraRevokeConsent),
	defineTool("entra_reset", "Restore Entra tenants, users and consents to the config seed. Signing keys are kept.",
		ownerEntra, destroys, entraReset),
	defineTool("entra_rotate_keys", "Rotate the Entra signing key and return the new key ID.",
		ownerEntra, writes, entraRotateKeys),
	defineTool("entra_mint_token", "Issue access and ID tokens for a configured, enabled Entra user without the sign-in page.",
		ownerEntra, writes, entraMintToken),
}

type noInput struct{}

type settingsSetInput struct {
	Name  string `json:"name" mcp:"required" enum:"interactiveLogin,rotateRefreshToken,entra,graph" desc:"toggle name"`
	Value bool   `json:"value" mcp:"required"`
}

type directoryUserInput struct {
	User directory.User `json:"user" mcp:"required"`
}

type usernameInput struct {
	Username string `json:"username" mcp:"required"`
}

type tenantCreateInput struct {
	Tenant entra.Tenant `json:"tenant" mcp:"required"`
}

type tenantUpdateInput struct {
	TID    string       `json:"tid" mcp:"required" desc:"current tenant ID"`
	Tenant entra.Tenant `json:"tenant" mcp:"required" desc:"the tenant's new fields"`
}

type tidInput struct {
	TID string `json:"tid" mcp:"required" desc:"tenant ID"`
}

type userCreateInput struct {
	User entra.User `json:"user" mcp:"required"`
}

type userUpdateInput struct {
	TID      string     `json:"tid" mcp:"required" desc:"current tenant ID"`
	Username string     `json:"username" mcp:"required" desc:"current username"`
	User     entra.User `json:"user" mcp:"required" desc:"the user's new fields"`
}

type userKeyInput struct {
	TID      string `json:"tid" mcp:"required" desc:"tenant ID"`
	Username string `json:"username" mcp:"required"`
}

type consentInput struct {
	ClientID string `json:"clientId" mcp:"required"`
	TID      string `json:"tid" mcp:"required" desc:"tenant ID"`
}

type mintInput struct {
	TID      string `json:"tid" mcp:"required" desc:"tenant ID"`
	Username string `json:"username" mcp:"required"`
	ClientID string `json:"clientId" desc:"audience app; default mock"`
	Scope    string `json:"scope" desc:"space-separated scopes; default openid profile email"`
}

var statusOK = jsonx.Obj{{Name: "status", V: "ok"}}

func settingsGet(c toolCtx, _ noInput) (jsonx.Obj, error) {
	return settingsObj(c.settings.AdminSettings()), nil
}

func settingsSet(c toolCtx, in settingsSetInput) (jsonx.Obj, error) {
	return statusOK, c.settings.AdminSetSetting(in.Name, in.Value)
}

func directoryList(c toolCtx, _ noInput) (jsonx.Obj, error) {
	return jsonx.Obj{{Name: "users", V: directoryArr(c.dir)}}, nil
}

func directoryUpsert(c toolCtx, in directoryUserInput) (jsonx.Obj, error) {
	return statusOK, c.dir.Upsert(in.User)
}

func directoryDelete(c toolCtx, in usernameInput) (jsonx.Obj, error) {
	return statusOK, c.dir.Delete(in.Username)
}

func directoryReset(c toolCtx, _ noInput) (jsonx.Obj, error) {
	c.dir.Reset()
	return statusOK, nil
}

func entraGetState(c toolCtx, _ noInput) (jsonx.Obj, error) {
	return c.entra.AdminSnapshot().(jsonx.Obj), nil
}

func entraCreateTenant(c toolCtx, in tenantCreateInput) (jsonx.Obj, error) {
	return statusOK, c.entra.AdminCreateTenant(in.Tenant)
}

func entraUpdateTenant(c toolCtx, in tenantUpdateInput) (jsonx.Obj, error) {
	return statusOK, c.entra.AdminUpdateTenant(in.TID, in.Tenant)
}

func entraDeleteTenant(c toolCtx, in tidInput) (jsonx.Obj, error) {
	return statusOK, c.entra.AdminDeleteTenant(in.TID)
}

func entraCreateUser(c toolCtx, in userCreateInput) (jsonx.Obj, error) {
	return statusOK, c.entra.AdminCreateUser(in.User)
}

func entraUpdateUser(c toolCtx, in userUpdateInput) (jsonx.Obj, error) {
	return statusOK, c.entra.AdminUpdateUser(in.TID, in.Username, in.User)
}

func entraDeleteUser(c toolCtx, in userKeyInput) (jsonx.Obj, error) {
	return statusOK, c.entra.AdminDeleteUser(in.TID, in.Username)
}

func entraRevokeConsent(c toolCtx, in consentInput) (jsonx.Obj, error) {
	c.entra.AdminRevokeConsent(in.ClientID, in.TID)
	return statusOK, nil
}

func entraReset(c toolCtx, _ noInput) (jsonx.Obj, error) {
	c.entra.AdminResetToSeed()
	return statusOK, nil
}

func entraRotateKeys(c toolCtx, _ noInput) (jsonx.Obj, error) {
	return jsonx.Obj{{Name: "kid", V: c.entra.AdminRotateKeys()}}, nil
}

func entraMintToken(c toolCtx, in mintInput) (jsonx.Obj, error) {
	tok, err := c.entra.AdminMintToken(c.origin, entra.MintInput{
		TID: in.TID, Username: in.Username, ClientID: in.ClientID, Scope: in.Scope,
	})
	if err != nil {
		return nil, err
	}
	return tok.Obj(), nil
}

func (a *Handler) available(t tool) bool {
	switch t.owner {
	case ownerSettings:
		return a.settings != nil
	case ownerDirectory:
		return a.dir != nil
	case ownerEntra:
		return a.entra != nil
	}
	return false
}

func (a *Handler) toolDefs() jsonx.Arr {
	out := jsonx.Arr{}
	for _, t := range registry {
		if !a.available(t) {
			continue
		}
		out = append(out, jsonx.Obj{
			{Name: "name", V: t.name},
			{Name: "description", V: t.description},
			{Name: "inputSchema", V: t.schema},
			{Name: "annotations", V: jsonx.Obj{
				{Name: "readOnlyHint", V: t.effect == reads},
				{Name: "destructiveHint", V: t.effect == destroys},
			}},
		})
	}
	return out
}

func (a *Handler) lookupTool(name string) (tool, bool) {
	for _, t := range registry {
		if t.name == name && a.available(t) {
			return t, true
		}
	}
	return tool{}, false
}

func (a *Handler) runTool(t tool, origin string, args json.RawMessage) jsonx.Obj {
	out, err := t.call(toolCtx{entra: a.entra, dir: a.dir, settings: a.settings, origin: origin}, args)
	if err != nil {
		return jsonx.Obj{
			{Name: "resultType", V: "complete"},
			{Name: "content", V: jsonx.Arr{jsonx.Obj{{Name: "type", V: "text"}, {Name: "text", V: err.Error()}}}},
			{Name: "isError", V: true},
		}
	}
	return jsonx.Obj{
		{Name: "resultType", V: "complete"},
		{Name: "content", V: jsonx.Arr{jsonx.Obj{{Name: "type", V: "text"}, {Name: "text", V: jsonx.Render(out)}}}},
		{Name: "structuredContent", V: out},
		{Name: "isError", V: false},
	}
}
