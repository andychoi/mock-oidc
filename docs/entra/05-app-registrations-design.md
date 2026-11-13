# Entra mode: app registrations

Entra mode accepts any `client_id` and secret on every flow, so a relying party needs no setup.
That permissiveness is also a gap: an integration test cannot check that a real Entra tenant
would reject the wrong redirect URI or the wrong client secret. App registrations close that gap
the way Entra does. A registration is created in the admin center page, and the fields it
declares are then enforced on the authorize and token endpoints.

This document covers the registration model, the enforcement rules, the admin center page, and
the admin API. Sign-in and tokens are in [`00-design.md`](00-design.md). App-only tokens and the
Graph API are in [`02-graph-design.md`](02-graph-design.md).

## 1. Model

An entry in `apps[]` (`internal/entra/config.go`) is an app registration:

| Field | JSON | Meaning |
| --- | --- | --- |
| `ClientID` | `clientId` | The application (client) ID. Generated as a GUID when the admin center or the API creates an app with the field empty. Immutable afterwards. |
| `Name` | `name` | Display name. Defaults to the client ID. |
| `TID` | `tid` | The home tenant for a single-tenant app. Empty for a multitenant app, which applies to every tenant. |
| `SignInAudience` | `signInAudience` | `AzureADMyOrg` (single tenant, `tid` set) or `AzureADMultipleOrgs` (any tenant, `tid` empty). Derived from `tid` when empty, and cross-checked against it. |
| `ObjectID` | `objectId` | The application object's ID. Derived as `UUIDv5(appNamespace, "app:"+clientId)` when empty, like a user OID. |
| `RedirectURIs` | `redirectUris` | `{platform, uri}` entries. `platform` is `web`, `spa`, or `mobileAndDesktop`; an empty platform defaults to `web`. |
| `Secrets` | `secrets` | Client secrets: `{id, description, value, expires, createdOn}`. `id` is a GUID, `expires` and `createdOn` are RFC 3339. |
| `Roles` | `roles` | App roles, carried as the `roles` claim of app-only tokens (§8 of the Graph design). |
| `Claims` | `claims` | Claims mappings added to ID tokens (§7 of the org directory design). |
| `CreatedOn` | `createdOn` | RFC 3339, stamped when the app is created at runtime. |

Redirect URI shapes follow Entra: `web` and `spa` URIs are https URLs, with `http` allowed on
`localhost`, `127.0.0.1`, and `::1` so e2e callbacks work; `mobileAndDesktop` URIs are loopback
http URLs or custom schemes such as `msal<id>://auth`. Duplicate URIs and duplicate client IDs
are rejected.

An app registration that declares nothing beyond `clientId`, `roles`, and `claims` behaves
exactly as before. Registration is opt-in per app, per field.

## 2. Enforcement

Two rules, both keyed to what the registration declares:

- **Redirect URIs** (`internal/entra/authorize.go`). When the request's `client_id` matches a
  registered app and that app lists at least one redirect URI, the request's `redirect_uri`
  must match one entry exactly. A mismatch returns `AADSTS50011` as a 400 error page, never an
  error redirect, because the browser must not be sent to a URI the app never registered. The
  check runs before the account picker and covers the POST sign-in path too.
- **Client secrets** (`internal/entra/token.go`, `appcreds.go`). When the tenant-scoped app
  lookup (`Config.App`) finds an app that has secrets, the token request must carry a matching
  `client_secret` form parameter or Basic auth password. A missing, wrong, or expired secret
  returns `invalid_client` 401 with `AADSTS7000215`. The check covers the authorization-code
  exchange and `client_credentials`.

Everything else stays permissive: an unregistered `client_id`, an app bound to another tenant,
and an app with no redirect URIs or no secrets all pass as before. Error bodies go through
`routing.ErrorResponse`, so they are lowercased like every other Entra-mode error.

Not enforced: the tenant binding itself. A single-tenant app's `signInAudience` is stored and
displayed, but authorize does not reject the app in another tenant. That is a deliberate
non-goal for this iteration.

## 3. Admin center page

`internal/adminui/static/portal/` holds a single-page replica of the Microsoft Entra admin
center's App registrations experience, served at `/admin/portal/`. It is dependency-free like
the rest of the admin UI, uses the same strict CSP, and renders through `textContent` only. The
shell (top bar, left menu, breadcrumb, gray command bar buttons) matches the real admin center;
nav entries that are not part of the mock are dimmed with a "Not part of the mock" tooltip, and
the wordmark carries a `mock` tag.

Pages:

- **App registrations list** (`#/apps`): All, Owned, and Deleted tabs, search by name or client
  ID, and the columns Display name, Application (client) ID, Directory (tenant) ID, and Created
  on. Deleted is always empty; this mock has no soft delete.
- **New registration** (`#/apps/new`): Name, Supported account types as the current portal's
  dropdown wording (single tenant per configured tenant, or Multiple Entra ID tenants; the
  personal-account options are disabled), and an optional redirect URI with a platform select.
  Register posts to the admin API and routes to the new app's Overview.
- **Overview**: the Essentials panel (Name, Application (client) ID, Directory (tenant) ID,
  Object ID, Supported account types, Status, Created on) with copy buttons on the GUIDs, an
  Endpoints dialog with this app's issuer and endpoint URLs, and Delete.
- **Authentication**: redirect URIs per platform with an Add a platform dialog, per-row
  removal, and a Save and Discard bar.
- **Certificates & secrets**: New client secret dialog (description, 6, 12, or 24 month
  expiry) that shows the value once with a copy button, and the secrets table.
- **App roles** and **Token configuration**: editors for `roles[]` and `claims[]` over the
  same Save and Discard bar.

Branding & properties, API permissions, Expose an API, Owners, and API usage appear in the
app menu but are dimmed.

## 4. Admin API and MCP

Routes under `/admin/api/`, same method and content-type gates as the rest of the admin API
(`internal/adminui/adminui.go`):

| Route | Effect |
| --- | --- |
| `POST entra/apps` | Registers an app. Returns the stored registration, not `{status: ok}`, because the caller needs the generated client ID and object ID. |
| `PUT entra/apps/{clientId}` | Replaces name, tid, signInAudience, redirectUris, roles, and claims. Secrets in the body are ignored and preserved. |
| `DELETE entra/apps/{clientId}` | Deletes the registration and its seed consents, and purges runtime consents. |
| `POST entra/apps/{clientId}/secrets` | Body `{description, expires}`. Returns the new secret with its one-time value. `expires` is `6m`, `12m`, `24m`, or an RFC 3339 timestamp. |
| `DELETE entra/apps/{clientId}/secrets/{secretId}` | Deletes one secret. |

The same operations are MCP tools at `/admin/mcp`: `entra_create_app`, `entra_update_app`,
`entra_delete_app`, `entra_add_app_secret`, and `entra_delete_app_secret`. `entra_add_app_secret`
returns the value so an agent can drive a full client-secret test setup.

## 5. Deliberate divergences

- Secret values are stored in the clear and appear in the admin snapshot and the
  Certificates & secrets table (masked, with a reveal button). Real Entra shows a value exactly
  once. This mock keeps it because everything is in-memory dev state and a lost value should
  never block a flow.
- `POST entra/apps` returns the created object where tenants and users return `{status: ok}`.
- The Created on column shows the registration time of the in-memory object. Reset restores
  the config seed, whose apps carry no `createdOn`.

## 6. Seed

`entra-demo.json` registers `iam` with two redirect URIs (a `web` https callback and a `spa`
localhost callback) and names both apps. Neither seed app carries secrets, so the demo
configuration keeps its permissive token behavior. Registering redirect URIs on `iam` means
authorize requests for that client ID now need a listed URI; use a different `client_id` for
flows that must accept any redirect URI.
