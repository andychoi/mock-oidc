# Entra mode: sign-in and tokens

Entra mode emulates enough of Microsoft Entra ID v2.0 to test an OIDC relying party end to end
against several tenants. It exists because the IAM project (`../iam`, ADR-0007) has no real
Entra test tenant. This document covers sign-in, tokens, consent, and configuration. The Graph
API, `userinfo`, selection hints, and app-only tokens are in
[`02-graph-design.md`](02-graph-design.md). Org attributes, dynamic groups, `$filter`, and claims
mapping are in [`04-org-directory-design.md`](04-org-directory-design.md).

Entra mode is opt-in. With no Entra config, the server keeps the navikt 6.0.2 contract (C1 to C9
in [`../plan/00-overview.md`](../plan/00-overview.md)).

## 1. Scope

Emulated:

- Tenant-specific sign-in (`/{tid}/…`) and multi-tenant sign-in (`/organizations/…`,
  `/common/…`), whose discovery `issuer` is the template `…/{tenantid}/v2.0`.
- One signing key set shared by all tenants, with rotation.
- Entra v2.0 ID token claims, including `tid`, `oid`, pairwise `sub`, `ver`, `xms_edov`, and
  `amr`.
- Group claims as display names or object IDs, and group overage.
- Admin consent and the consent-missing error.
- Per-user error injection, a disabled account, and a simulated passkey step.

Not emulated: real Conditional Access, Microsoft's UI and exact error wording, app registrations
(any `client_id` and secret work), refresh-token redemption, implicit and hybrid flows,
`form_post` and `fragment` response modes, tenant lookup by domain name in the path, SAML, and
WS-Fed.

## 2. Architecture

`internal/entra` imports `oauth2`, `routing`, `jsonx`, and `token`. It never imports `config`,
`server`, or `adminui`. Its sign-in files:

| File | Contents |
|---|---|
| `config.go` | Config types, `ParseConfig`, and `normalize`, which validates and fills defaults |
| `store.go` | The copy-on-write config store behind runtime edits (§6) |
| `uuid.go` | UUIDv5 for derived user and group object IDs |
| `keys.go` | `KeySet`: shared RS256 keys, rotation, signing, JWKS |
| `claims.go` | Issuer, pairwise `sub`, ID and access token claims, groups and overage |
| `consent.go` | Consent store, seeded from config, in memory |
| `handler.go` | `Handler`, `RoutePattern`, `Handle` (dispatch), discovery, logout |
| `authorize.go` | Account picker, sign-in submit, selection hints, passkey step, code store |
| `token.go` | Token endpoint |
| `adminconsent.go` | Admin consent page and submit |
| `testapi.go` | `/_entra/*` test endpoints |
| `admin.go` | Operations the admin UI and MCP tools call |
| `templates/` | Picker and passkey pages |

`internal/routing` matches routes by path suffix, so `/entra/{tid}/oauth2/v2.0/token` would
otherwise reach the navikt `/token` handler. `server.buildRouter` registers one front route,
`AddFront("", eh.RoutePattern(), s.gateEntra(eh))`, for `/{basePath}/*`. It runs before every
built-in route, and `Handle` parses the path itself. `gateEntra` applies the runtime on/off
toggle (§6). Entra paths get the same CORS headers as navikt paths, and `Handle` answers
`OPTIONS` with 204.

Real Entra signs every tenant's tokens with one key set. The navikt `token.KeyProvider` has one
key per issuer, so Entra mode keeps its own `KeySet`: RS256 keys with `kid` `entra-1`,
`entra-2`, and so on. The newest key signs. `Rotate` adds a key and keeps at most one previous key
published. `KeySet` uses `token.GenerateSigningKey`, `token.SignJWT`, and `token.PublicJWKSOf`, the
same code the navikt keys use.

## 3. Endpoints

All paths are under `{origin}/{basePath}`, and `basePath` defaults to `entra`. `{origin}` is the
proxy-aware `scheme://host[:port]` from `oauth2.Request.ProxyAwareURL()`, the same one the navikt
issuer uses, so `x-forwarded-*` headers work. `{t}` is a tenant GUID (case-insensitive, normalized
to lowercase), `organizations`, or `common`.

| Method | Path | Behavior |
|---|---|---|
| GET | `/{t}/v2.0/.well-known/openid-configuration` | Discovery (§3.1) |
| GET | `/{t}/discovery/v2.0/keys` | Shared JWKS with all published keys |
| GET | `/{t}/oauth2/v2.0/authorize` | Account picker, or a code at once for a resolvable `login_hint` (§3.2) |
| POST | `/{t}/oauth2/v2.0/authorize` | Sign-in submit (form `tid`, `username`), then 302 with `code` or `error` |
| POST | `/{t}/oauth2/v2.0/token` | Token endpoint (§3.3) |
| any | `/{t}/oauth2/v2.0/logout` | 302 to `post_logout_redirect_uri` (with `state`), else a "signed out" page |
| GET | `/{t}/v2.0/adminconsent` | Admin consent page. `client_id` and `redirect_uri` are required. `state` and `scope` are echoed. |
| POST | `/{t}/v2.0/adminconsent` | Admin consent submit (§3.4) |
| OPTIONS | any | 204 |

Two first segments never resolve as a tenant: `_entra` (the test API, §3.5) and the Graph
segment (`graph` by default, while Graph is on). Any other `{t}` that is not a configured GUID,
`organizations`, or `common` gets 400 `invalid_request` "AADSTS90002: Tenant '{t}' not found."
Unknown sub-paths get 404.

### 3.1 Discovery

| Field | Tenant `{tid}` | `organizations` or `common` |
|---|---|---|
| `issuer` | `{origin}/{base}/{tid}/v2.0` | `{origin}/{base}/{tenantid}/v2.0`, with a literal `{tenantid}` |
| `authorization_endpoint`, `token_endpoint`, `end_session_endpoint`, `jwks_uri` | under `/{base}/{tid}/…` | under `/{base}/{organizations or common}/…` |

The document also carries `response_types_supported`
`["code","id_token","code id_token","id_token token"]` and `response_modes_supported`
`["query","fragment","form_post"]`, copied from Entra although only `code` and `query` work.
It also has `subject_types_supported` `["pairwise"]`, `id_token_signing_alg_values_supported`
`["RS256"]`, `scopes_supported`, `token_endpoint_auth_methods_supported`, `claims_supported`,
`request_uri_parameter_supported` `false`, `tenant_region_scope` `"NA"`, and
`cloud_instance_name` `"microsoftonline.com"`. While Graph and `graph.userinfo` are on, which is
the default, it advertises `userinfo_endpoint` `{origin}/{base}/graph/oidc/userinfo`.

### 3.2 Authorize

`oauth2.ParseAuthRequest` parses the query, with the same required parameters as the navikt
server. A `response_type` other than `code` redirects with `error=unsupported_response_type`
"AADSTS70005". A value that is not a valid response type at all gets 400 from the parser. A
`response_mode` other than `query` or none gets 400 `invalid_request` "AADSTS90005", because a
`form_post` client could not receive an error redirect either.

GET renders the account picker. It lists the tenant's users for `/{tid}`, or every user grouped
by tenant for `organizations` and `common`. Each account is a form that posts `tid` and
`username` back to the same URL with the query kept. There is no password. `login_hint`,
`domain_hint`, and `prompt` change this; see
[`02-graph-design.md`](02-graph-design.md#7-account-selection-hints).

POST runs these checks in order:

| # | Check | Result |
|---|---|---|
| 1 | The posted user exists in the posted `tid` | Else 400 `invalid_request` "AADSTS50034: The user account does not exist in this directory." |
| 2 | On a `/{tid}` route, the posted `tid` is the route tenant | Else 400 `invalid_request` "AADSTS50020: …" |
| 3 | User `error` is `interaction_required` | Redirect `error=interaction_required` "AADSTS50076: …" |
| 4 | User `error` is `access_denied` | Redirect `error=access_denied` "AADSTS50105: …" |
| 4a | A picker submit (any `action` except `passkey-approve` and `passkey-deny`) for a user with `mfa` `passkey` | 200 passkey page instead of a code |
| 5 | Tenant `consentRequired` and no consent for (`client_id`, `tid`) | Redirect `error=consent_required` "AADSTS65001: …" |
| 6 | All checks pass | A single-use code with a 10-minute TTL, redirected as `code` (with `state`) |

The passkey page simulates the step. There is no WebAuthn and no authenticator. **Use passkey**
posts `action=passkey-approve` and runs checks 3 to 6. **Cancel** posts `action=passkey-deny`
and redirects `error=access_denied` "AADSTS500121: Authentication failed during strong
authentication request." That code and wording are not checked against real Entra. The token's
`amr` is the user's configured `amr`. The demo `passkey` user sets `["fido", "mfa"]`, and `fido`
as Entra's value is an assumption. A GET with a resolved `login_hint` (including `prompt=none`)
skips the page. `prompt=login` and `prompt=select_account` force the picker, and so the page.

Error redirects carry `error`, `error_description`, and `state`. Real Entra shows some of these
errors as a page instead. The mock redirects so relying parties can test their error handling.

### 3.3 Token

`grant_type` must be `authorization_code`, or 400 `unsupported_grant_type` "AADSTS70003". The one
exception is `client_credentials` while `graph.appOnly` is on
([`02-graph-design.md` §8](02-graph-design.md#8-app-only-tokens)). `oauth2.ParseTokenRequest`
parses the request, so `client_id` is required. Any client secret works.

A code is taken out of the store before any check, so a failed redemption also uses it up. Each
failed check returns 400 `invalid_grant`:

| Check | Message |
|---|---|
| Code unknown, used, or expired | "AADSTS70008: The provided authorization code or refresh token has expired or was already used." |
| Redeemed on a tenant path other than the one it was issued on or the user's own `tid` | "authorization code was issued for tenant path '…'" |
| `client_id` differs from the authorize request | "client_id does not match the authorization request" |
| `redirect_uri` differs from the authorize request | "redirect_uri does not match the authorization request" |
| `code_challenge` was sent and `code_verifier` is missing or wrong (`S256` or `plain`) | "AADSTS501481: The Code_Verifier does not match the code_challenge supplied in the authorization request." |
| The user or tenant was deleted after the code was issued | "AADSTS50034: The user account does not exist in this directory." |
| User `error` is `invalid_grant`, or `accountEnabled` is `false` | "AADSTS50057: The user account is disabled." |

The JSON response has these fields in order: `token_type` `Bearer`, `scope`, `expires_in`,
`ext_expires_in`, `access_token`, `refresh_token`, and `id_token`. `refresh_token` appears only
when `offline_access` was requested. It is opaque, and the server cannot redeem it.

### 3.4 Admin consent

- `action=cancel` redirects `error=access_denied` "AADSTS65004: User declined to consent to
  access the app."
- Any other `action` accepts. The posted user goes through checks 1 and 2 of §3.2, which answer
  400 on failure. A user without `admin: true` gets a redirect with `error=access_denied`
  "AADSTS90094: …". On success the server grants consent for (`client_id`, user's `tid`) and
  redirects with `admin_consent=True&tenant={tid}&state=…`, plus `scope` when sent.

### 3.5 Test API

| Method | Path | Behavior |
|---|---|---|
| GET | `/_entra/consents` | Granted consents |
| POST | `/_entra/reset` | Consents back to the config seed. Tenants, users, and keys stay as they are. |
| POST | `/_entra/rotate-keys` | Adds a signing key and returns `{"kid": "entra-N"}` |
| GET | `/_entra/groups?tid=` | `{group name: object ID}` for the groups the tenant's users belong to |
| GET | `/_entra/users?tid=` | The tenant's users as Graph sees them |
| POST | `/_entra/mint-token` | Tokens without the picker (below) |

`mint-token` reads `tid`, `username`, `clientId` (default `mock`), and `scope` (default
`openid profile email`) from the form or the query. It returns `access_token`, `id_token`,
`token_type`, `expires_in`, and `scope`. An unknown tenant gets 400 "AADSTS90002", and an unknown
user gets 400 "AADSTS50034". A user with `accountEnabled: false` or `error: invalid_grant` gets
400 `invalid_grant` "AADSTS50057", as at the token endpoint. The MCP tool `entra_mint_token`
calls the same code.

## 4. Tokens

### 4.1 ID token claims

| Claim | Value |
|---|---|
| `iss` | `{origin}/{base}/{tid}/v2.0`, always the user's tenant, also for `organizations` and `common` |
| `aud` | `client_id` |
| `iat`, `nbf`, `exp` | Now, now, and now plus `tokenExpiry` |
| `tid` | The user's tenant GUID, lowercase |
| `oid` | The configured `oid`, else `UUIDv5(oidNamespace, tid + ":" + username)` |
| `sub` | Pairwise: base64url(SHA-256(`client_id` + ":" + `oid`)), 43 characters. Stable per client, different across clients. |
| `ver` | `"2.0"` |
| `name` | User `name`, default the username |
| `preferred_username` | User `email`, else `username@{first tenant domain}`, else the username |
| `nonce` | When sent to authorize |
| `email` | Only when the user has an email and the scope contains `email` |
| `xms_edov` | Only when the user sets `emailVerified` |
| `amr` | Only when the user sets `amr` |
| `given_name`, `family_name`, `roles`, `wids` | Only when the user sets `givenName`, `surname`, `roles`, or `wids` |
| `groups` | See §4.2 |
| `uti` | A random 22-character string |
| Mapped claims | From `apps[].claims` ([`04-org-directory-design.md` §7](04-org-directory-design.md#7-org-data-in-tokens-claims-mapping)) |

Header: `{"kid":"entra-N","typ":"JWT","alg":"RS256"}`.

### 4.2 Groups and overage

A user's groups are `User.MemberGroups()`: the static `groups` plus the dynamic groups whose
rule matches, without duplicates or blanks.

- A user with no groups gets no `groups` claim.
- When the count is at most the tenant's `groupLimit` (default `defaultGroupLimit`, which
  defaults to 200), `groups` holds names (`groupClaimFormat: "name"`, the default) or object IDs
  (`"object_id"`). `(*Tenant).GroupOID` gives the object ID: the group's configured `oid`, else
  `UUIDv5(groupNamespace, tid + ":" + name)`. Graph and the test API use the same ID.
- Above the limit there is no `groups` claim. The token carries
  `"_claim_names": {"groups": "src1"}` and
  `"_claim_sources": {"src1": {"endpoint": "…/users/{oid}/getMemberObjects"}}`. The endpoint is
  this server's Graph (`{origin}/{base}/graph/v1.0/…`) while Graph is on. It is
  `https://graph.microsoft.com/v1.0/…` when Graph is off or `graph.overageEndpoint` is
  `microsoft`.

### 4.3 Access token

The access token has the ID token claims except `nonce` and the mapped claims. `aud` is
`00000003-0000-0000-c000-000000000000` (Microsoft Graph), and `azp` and `appid` are both the
`client_id`. `scp` lists the requested scopes with resource prefixes stripped
(`https://graph.microsoft.com/User.Read` becomes `User.Read`) and without `offline_access`. The
emulated Graph and `userinfo` accept only tokens that carry `appid`, so they reject ID tokens.

## 5. Configuration

Entra mode turns on with an `"entra"` object in the main JSON config (`JSON_CONFIG` or
`JSON_CONFIG_PATH`, or `config.ParseJSON` in the library) or with `ENTRA_CONFIG_PATH` naming a
separate file. The file wins when both are set. Unknown fields are rejected, so a typo fails at
startup.

```json
{
  "basePath": "entra",
  "defaultGroupLimit": 200,
  "tokenExpiry": 3600,
  "ignoreLoginHint": false,
  "tenants": [
    { "tid": "11111111-1111-1111-1111-111111111111", "name": "Corp",
      "domains": ["corp.example"], "groupClaimFormat": "name" },
    { "tid": "22222222-2222-2222-2222-222222222222", "name": "Customer X",
      "domains": ["customer-x.example"], "groupClaimFormat": "object_id",
      "consentRequired": true, "groupLimit": 3 }
  ],
  "consents": [ { "clientId": "iam-multitenant", "tid": "11111111-1111-1111-1111-111111111111" } ],
  "users": [
    { "username": "jane", "tid": "11111111-1111-1111-1111-111111111111", "name": "Jane Kim",
      "email": "jane@corp.example", "emailVerified": true, "groups": ["AMS Engineers"],
      "amr": ["pwd", "mfa"], "admin": true },
    { "username": "blocked", "tid": "22222222-2222-2222-2222-222222222222", "error": "interaction_required" },
    { "username": "pk", "tid": "11111111-1111-1111-1111-111111111111", "mfa": "passkey" }
  ]
}
```

The `graph` block, `apps`, `tenants[].groups`, and the Graph and org user fields (`upn`,
`accountEnabled`, `givenName`, `manager`, `department`, and others) are described in
[`02-graph-design.md` §4](02-graph-design.md#4-configuration) and
[`04-org-directory-design.md` §2](04-org-directory-design.md#2-config). `entra-demo.json` uses
most of them.

`normalize` rejects the config at startup when any of these fail:

- There is at least one tenant. Each `tid` is a GUID and unique.
- `basePath` matches `^[A-Za-z0-9_-]+$` after trimming slashes.
- `groupClaimFormat` is `name` or `object_id`.
- Each consent has a `clientId` and a configured `tid`.
- Each user has a `username` that is unique in its tenant, and a configured `tid`.
- `error` is `interaction_required`, `access_denied`, or `invalid_grant`. `mfa` is empty or
  `passkey`.
- A user `oid` is a GUID. No two users in a tenant share an `oid`, whether configured or derived.
- A declared group has a name that is unique in its tenant. A group `oid` is a GUID, and no two
  declared groups in a tenant share one.
- A `membershipRule` parses, with at most 32 levels of nesting. A user does not list a dynamic
  group in `groups`.
- A `manager` exists in the same tenant and is not the user.
- Each `wids` entry is a GUID. Each app has a `clientId` and, when set, a configured `tid`.

## 6. Runtime changes and the off switch

The parsed config seeds a copy-on-write store (`internal/entra/store.go`). Each request reads one
immutable snapshot. An admin edit copies the config, runs `normalize` again with the same checks
and messages as startup, and publishes the result. Edits are in memory only. A restart returns to
the config file, and `POST /admin/api/entra/reset` restores tenants, users, and consents from the
seed. Signing keys are not reset.

Rules beyond the startup checks:

- `tid` and `username` cannot change after create. To rename, delete and create.
- Deleting a tenant deletes its users and consents. The last tenant cannot be deleted.
- Revoking a seeded consent removes it until the next reset.

The admin setting `entra` turns Entra mode off at runtime
(`POST /admin/api/settings` with `{"name": "entra", "value": false}`). The router cannot remove
the front route, so `gateEntra` answers every `/{basePath}/…` request like an unrouted path:
`OPTIONS` gets 204 and everything else gets 405. A server without Entra config would instead let
`/{basePath}/{tid}/oauth2/v2.0/token` reach the navikt `/token` suffix route. The 405 is
deliberate: "turned off" is its own state, not "never configured".

## 7. Decisions

| Decision | Why |
|---|---|
| A separate `internal/entra` package behind one front route | No shared code path with the navikt handlers, so compatibility is easy to check |
| One key set shared across tenants | Real Entra does this, and the per-issuer `KeyProvider` cannot |
| Deterministic `oid` and group object IDs (UUIDv5) | Fixtures stay stable across restarts and machines, so tests can hard-code IDs |
| Error redirects instead of error pages | Relying parties can assert their error handling |
| No refresh-token grant | The IAM never refreshes upstream Entra tokens |
| Test API under `/_entra/` | Tests reset state and rotate keys without a restart |

Real Conditional Access, Microsoft's UI, and the exact claims of a real tenant (for example,
whether a v2.0 ID token includes `amr`) still need a real tenant. The IAM plans a pre-launch smoke
test for them.
