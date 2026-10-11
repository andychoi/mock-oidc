# Entra Mode — Account Graph API (Design)

| | |
|---|---|
| Status | Proposed (2026-10-11). Plan: [`03-graph-plan.md`](03-graph-plan.md) |
| Builds on | [`00-design.md`](00-design.md) (Entra mode), which lists Microsoft Graph as a non-goal. This design lifts that non-goal for the **account-related** surface only |
| Benchmarked against | [`cmaneu/entra-local`](https://github.com/cmaneu/entra-local) (TypeScript/Fastify + SQLite, ~54k lines), [`nazriel/ms-oidc-mock`](https://github.com/nazriel/ms-oidc-mock) (Rust/axum, ~8.6k lines) |
| Hard constraints | Opt-in and additive. No new module dependencies. Every existing test passes **unmodified** |

## 1. Why

Entra mode emulates sign-in, but a relying party that signs in with Entra almost always then calls
Microsoft Graph for the account: `/me` to fill a profile, `/me/memberOf` for authorization,
`/users` to sync a directory. Today mock-oidc issues a Graph-audience access token that nothing can
consume, and the group-overage claim it emits points at **the real** `graph.microsoft.com`, so a
test RP that follows it leaves the test environment and fails. The loop does not close.

Both benchmarked projects close it, and both treat a small read-only Graph as the thing that makes
an Entra mock usable rather than a curiosity.

## 2. Benchmark

### 2.1 What the two projects have that we do not

| Capability | entra-local | ms-oidc-mock | mock-oidc today |
|---|---|---|---|
| Graph `/v1.0/me` | yes | yes (as its *userinfo*) | — |
| Graph `/v1.0/users`, `/users/{id}` | yes, paged | — | — |
| Graph `/v1.0/groups`, `/groups/{id}/members` | yes, paged | — | — |
| `memberOf` for a user | yes (`/me/memberOf`, `/users/{id}/memberOf`) | — | — |
| `getMemberObjects` (resolves group overage) | — | — | — |
| OIDC `userinfo` | yes (`/graph/oidc/userinfo`) | conflated with `/v1.0/me` | — (deliberately omitted) |
| Bearer validation of its own access token | yes (JWKS + `iss` + `aud` + `ver:"2.0"`) | yes (token lookup table) | — |
| OData envelope (`@odata.context`, `value[]`, `@odata.nextLink`) | yes | `@odata.context` only | — |
| Graph error body (`{error:{code,message}}`) + `WWW-Authenticate` | yes | — | — |
| Rich account fields (`givenName`, `surname`, `userPrincipalName`, `accountEnabled`, `jobTitle`, …) | yes | yes | only `name`, `email` |
| `roles` claim from user config | — (app-role registry) | yes | — |
| App-only token (`client_credentials`) + `roles`, no `oid` | yes | — | rejected (`unsupported_grant_type`) |
| `scp` as short names (`User.Read`, not the resource URI) | yes | — | echoes raw requested scopes |
| `login_hint` / `prompt` account preselection | preselect in picker, `prompt=none`/`select_account` | auto-select the hinted account, `ignore_login_hint` toggle | — |
| Multiple tenants | yes (store has `tenants`) but Graph is not tenant-scoped | single tenant | yes, and Graph must be |

### 2.2 Logic and edge cases worth borrowing verbatim

From **entra-local** (`src/graph/handlers.ts`, `specs/…10-minimal-graph.md`):

1. **Authorization model.** Possession of a valid Graph-audience token is sufficient; no
   fine-grained `scp`/`roles` enforcement. `/me` additionally requires a **delegated** token (one
   carrying `oid`) — an app-only token gets `403 Authorization_RequestDenied`. Collections accept
   either. This is a documented divergence from real Graph (which enforces `User.Read`,
   `User.Read.All`, `Group.Read.All`) and the right trade-off for a dev tool.
2. **Accept our own `ver:"2.0"` token.** The validator must not expect Microsoft's v1 Graph token
   shape; a mock that signs v2 tokens and then rejects them on its own Graph is the obvious trap.
3. **`@odata.nextLink` preserves every other query parameter** and overrides only `$skiptoken`, so
   the page size stays stable across continuations. `$`-prefixed keys stay literal; only values are
   percent-encoded.
4. **`$top` clamping**: default 100, max 999, non-integer or `< 1` falls back to the default
   (never an error). `$skiptoken` is an opaque non-negative integer offset; invalid → `0`.
5. **`nextLink` only when rows remain** — the last page omits it. Collections are ordered by `id`
   so offset paging is deterministic.
6. **`/users/{id}` resolves by object id *or* UPN** — real Graph accepts both, and SDK samples use
   the UPN.
7. **Single entity carries `@odata.context` with the `$entity` suffix; collection items omit their
   own context.**
8. **Graph errors are a different error surface from OAuth**: `{"error":{"code","message"}}`, never
   the OAuth `{error, error_description}` body, and never an HTML page.
9. **`userinfo` rejects a user whose account is disabled** (`accountEnabled: false` → `401`), and
   rejects an app-only token with `403 insufficient_scope`.
10. **`scp` carries short names** (`User.Read`), with the resource prefix stripped, and
    `offline_access` excluded — it is a grant scope, not an API permission. The token response's
    `scope` field still echoes everything.
11. **Graph delegated scopes are auto-consented and need no registration**, so a client requesting
    `User.Read` is not rejected as `invalid_scope`.

From **ms-oidc-mock**:

12. **`login_hint` resolves an account and skips the picker**, with a config switch
    (`ignore_login_hint`) to force the picker anyway — this is what makes headless RP tests possible.
13. **A richer `/me` payload**: `jobTitle`, `officeLocation`, `businessPhones`, `mobilePhone`,
    `preferredLanguage` — cheap fixture fields that real Graph consumers read.
14. **`roles` straight off the user fixture**, with no app-role registry. For a mock this beats
    entra-local's app-registration machinery.

### 2.3 Borrowed with changes, and declined

| Their choice | Ours | Why |
|---|---|---|
| ms-oidc-mock serves the **Graph `/me` shape at `userinfo`** | `userinfo` returns OIDC claims; the Graph shape lives at `/graph/v1.0/me` | Real Entra has both, and they differ. Conflating them teaches an RP the wrong contract |
| Overage `endpoint` → `graph.microsoft.com` (ours today; neither project emits overage at all) | → **our own** `…/graph/v1.0/users/{oid}/getMemberObjects` when Graph is on | A test RP must be able to follow it. Switchable back via `overageEndpoint: "microsoft"` |
| entra-local Graph is **not tenant-scoped** (one directory) | every collection is scoped to the **token's `tid`** | We are multi-tenant by design; a Corp token must not enumerate Customer X |
| entra-local pairwise `sub` = `sha256(userId\|appId\|tenantId)` | keep ours: `sha256(clientID + ":" + oid)` | Already shipped and tested; the tenant is implied by the oid |
| entra-local app registrations, scopes, secrets, app roles, portal | none | mock-oidc accepts any `client_id`/secret everywhere; an app registry would be a second product |
| entra-local device code flow, refresh-token redemption, SQLite persistence | none | Not account-related; refresh redemption is already a documented non-goal |
| entra-local `$select`-less Graph | minimal `$select` | Graph SDKs and the MSAL samples send `$select` on nearly every call; ignoring it silently returns fields the caller did not ask for |
| entra-local writes via its admin REST API | our admin UI already owns mutation | One mutation surface, already copy-on-write |

## 3. Architecture

```
internal/entra/
├── graphconfig.go   GraphConfig (the "graph" block), defaults, validation
├── directory.go     Group entities derived from the config: GroupsIn, GroupByID, MembersOf, GroupsOf
├── verify.go        KeySet.Verify + ValidateAccessToken (iss/aud/ver/exp/nbf/kid), typed failures
├── odata.go         OData envelope, $top/$skiptoken paging, $select, Graph error bodies
├── graph.go         Graph route table and the account handlers
├── userinfo.go      GET|POST /graph/oidc/userinfo
└── appcreds.go      client_credentials (app-only) grant, gated by graph.appOnly
```

Mounted under the **existing** front route: `graph` becomes a reserved first segment next to
`_entra`, so `Handle` dispatches `/{basePath}/graph/...` before tenant resolution. There is no
ambiguity — tenant segments must be GUIDs, `organizations`, or `common`.

```
/{basePath}/graph/v1.0/...        Graph account endpoints   (tenant comes from the token's tid)
/{basePath}/graph/oidc/userinfo   OIDC UserInfo
```

This mirrors real Graph, which is one tenant-agnostic host whose responses are scoped by the
caller's token — not a per-tenant endpoint family. It also keeps the router contract intact: one
front route with a `*` pattern, suffix routes untouched.

## 4. Configuration

A new optional `"graph"` block inside the `entra` block. **Its presence enables the feature**; no
block means today's behavior, byte for byte.

```json
{
  "entra": {
    "graph": {
      "enabled": true,
      "basePath": "graph",
      "overageEndpoint": "self",
      "userinfo": true,
      "appOnly": false,
      "defaultPageSize": 100,
      "maxPageSize": 999,
      "clockSkew": 60
    },
    "tenants": [
      { "tid": "11111111-1111-1111-1111-111111111111", "name": "Corp", "domains": ["corp.example"],
        "groups": [ { "name": "AMS Engineers", "description": "Engineering", "securityEnabled": true } ] }
    ],
    "users": [
      { "username": "jane", "tid": "11111111-1111-1111-1111-111111111111",
        "name": "Jane Kim", "givenName": "Jane", "surname": "Kim",
        "upn": "jane@corp.example", "email": "jane@corp.example",
        "accountEnabled": true, "jobTitle": "Staff Engineer", "officeLocation": "Seoul",
        "businessPhones": ["+82-2-555-0100"], "mobilePhone": "+82-10-555-0101",
        "preferredLanguage": "en-US", "roles": ["Portal.Admin"],
        "wids": ["62e90394-69f5-4237-9190-012177145e10"],
        "manager": "sora", "groups": ["AMS Engineers", "PMO"], "admin": true }
    ]
  }
}
```

### New fields

| Field | Default | Effect |
|---|---|---|
| `graph.enabled` | `true` when the block is present | `false` keeps the block but serves 404s, like the runtime toggle |
| `graph.basePath` | `graph` | the reserved segment; same charset rule as `entra.basePath` |
| `graph.overageEndpoint` | `self` | `self` → our `getMemberObjects`; `microsoft` → today's `graph.microsoft.com` URL |
| `graph.userinfo` | `true` | serve **and advertise** `userinfo_endpoint` in discovery |
| `graph.appOnly` | `false` | enable the `client_credentials` grant (app-only Graph tokens) |
| `graph.defaultPageSize` / `maxPageSize` | 100 / 999 | `$top` default and clamp |
| `graph.clockSkew` | 60 (seconds) | leeway on `exp`/`nbf` when validating a Bearer token |
| `tenant.groups[]` | derived | metadata (`description`, `mailNickname`, `securityEnabled`, `mailEnabled`, explicit `oid`) for a group name; names used by a user but not declared are auto-created |
| `user.givenName`, `surname` | — | `given_name` / `family_name` claims and Graph fields |
| `user.upn` | `preferred_username` rule | Graph `userPrincipalName`; also overrides `preferred_username` when set |
| `user.accountEnabled` | `true` | `false` → Graph shows it, `userinfo` 401s, and the token endpoint fails with AADSTS50057 (the ergonomic form of `error: "invalid_grant"`) |
| `user.jobTitle`, `officeLocation`, `businessPhones`, `mobilePhone`, `preferredLanguage` | — | Graph profile fields |
| `user.roles` | — | `roles` claim in the ID **and** access token |
| `user.wids` | — | `wids` claim (tenant-wide directory roles; Global Administrator is `62e90394-69f5-4237-9190-012177145e10`) |
| `user.manager` | — | a username in the same tenant; `/users/{id}/manager` and `/directReports` |

Every one of these is additive: `ParseConfig` rejects unknown fields, so a config written for today
still parses, and a config using the new fields fails loudly on an old binary.

## 5. Endpoints

All under `{origin}/{basePath}/{graph.basePath}`. `{origin}` is the proxy-aware origin, as
everywhere else in Entra mode. Every endpoint requires `Authorization: Bearer <access_token>`.

| Method | Path | Returns |
|---|---|---|
| GET | `/v1.0/me` | the token's user (`microsoft.graph.user` subset) |
| GET | `/v1.0/me/memberOf` | the user's groups (collection) |
| GET | `/v1.0/me/transitiveMemberOf` | same as `memberOf` (our groups are flat) |
| GET | `/v1.0/me/manager` | the user's manager, or 404 `Request_ResourceNotFound` |
| GET | `/v1.0/me/directReports` | users whose `manager` is this user |
| POST | `/v1.0/me/getMemberObjects` | `{"value": ["<group oid>", …]}` — **resolves group overage** |
| POST | `/v1.0/me/getMemberGroups` | same shape, group ids only |
| GET | `/v1.0/users` | the token tenant's users (collection, paged) |
| GET | `/v1.0/users/{id\|upn}` | one user |
| GET | `/v1.0/users/{id}/memberOf`, `/transitiveMemberOf`, `/manager`, `/directReports` | as for `/me` |
| POST | `/v1.0/users/{id}/getMemberObjects`, `/getMemberGroups` | as for `/me` |
| GET | `/v1.0/groups` | the token tenant's groups (collection, paged) |
| GET | `/v1.0/groups/{id}` | one group |
| GET | `/v1.0/groups/{id}/members` | the group's member users |
| GET | `/v1.0/me/photo`, `/me/photo/$value` | 404 `ImageNotFound` (clients probe it) |
| GET/POST | `/oidc/userinfo` | OIDC claims (§5.3) |
| OPTIONS | any | 204 |
| any | anything else under the Graph base | 404 `Request_ResourceNotFound`, Graph error body |

### 5.1 Bearer validation

In order: a `Bearer` scheme and a non-empty token; three JWS parts; `kid` present in the **current**
`KeySet` (so a token signed before a rotation still verifies while its key is published); RS256
signature; `aud` == `00000003-0000-0000-c000-000000000000`; `ver` == `"2.0"`; `iss` ==
`Issuer(origin, basePath, claims.tid)` for the token's own `tid` (so the proxy-aware origin matches
and a token minted for another host is rejected); `nbf` ≤ now and now < `exp`, each with
`clockSkew`. Any failure → `401 InvalidAuthenticationToken` with
`WWW-Authenticate: Bearer error="invalid_token"`.

Then the token's `tid` must still name a configured tenant, and (for a delegated token) `oid` must
still resolve to a user in it — a runtime admin delete between mint and call gives `401`, matching
entra-local's "the user could not be found".

### 5.2 Shapes

```jsonc
// user
{ "@odata.context": "{origin}/{base}/graph/v1.0/$metadata#users/$entity",
  "id": "<oid>", "displayName": "Jane Kim", "userPrincipalName": "jane@corp.example",
  "mail": "jane@corp.example", "givenName": "Jane", "surname": "Kim",
  "jobTitle": "Staff Engineer", "officeLocation": "Seoul",
  "businessPhones": ["+82-2-555-0100"], "mobilePhone": null,
  "preferredLanguage": "en-US", "accountEnabled": true }

// group
{ "@odata.context": "{origin}/{base}/graph/v1.0/$metadata#groups/$entity",
  "id": "<group oid>", "displayName": "AMS Engineers", "description": null,
  "mailNickname": "amsengineers", "mail": null,
  "mailEnabled": false, "securityEnabled": true }

// collection
{ "@odata.context": "{origin}/{base}/graph/v1.0/$metadata#users",
  "value": [ /* entities without their own @odata.context */ ],
  "@odata.nextLink": "{origin}/{base}/graph/v1.0/users?$top=1&$skiptoken=1" }

// error
{ "error": { "code": "InvalidAuthenticationToken",
             "message": "Access token is empty or invalid.",
             "innerError": { "date": "2026-10-11T00:00:00", "request-id": "<uuid>",
                             "client-request-id": "<uuid>" } } }
```

Missing values are `null` for single-valued fields and `[]` for `businessPhones` — Graph emits the
key rather than omitting it, and SDK deserializers rely on that. Graph error codes are PascalCase,
so these bodies must **not** go through `routing.ErrorResponse` (which lowercases the whole body for
navikt compatibility); `internal/entra` renders them directly.

`memberOf` collections use the `directoryObjects` context suffix, like real Graph.

### 5.3 UserInfo

`GET|POST /{base}/{graph.basePath}/oidc/userinfo` → OIDC claims, not the Graph shape:
`sub` (the token's pairwise sub), `oid`, `tid`, `name`, `preferred_username`, and `given_name`,
`family_name`, `email` when set. `Cache-Control: no-store`. An app-only token → `403
insufficient_scope`; anything else invalid → `401 invalid_token` with `WWW-Authenticate` — RFC 6750
style with a matching JSON body, as in entra-local. Advertised as `userinfo_endpoint` in discovery
**only** while `graph.userinfo` is on, which is why today's discovery (and the test that asserts
`userinfo_endpoint` is absent) is untouched.

### 5.4 Query options

| Option | Behavior |
|---|---|
| `$top` | default `defaultPageSize`, clamped to `[1, maxPageSize]`; invalid → default |
| `$skiptoken` | non-negative integer offset; invalid → `0` |
| `$select` | comma list of known fields; `id` is always included; an unknown property → `400 Request_UnsupportedQuery` with Graph's "Could not find a property named …" message |
| `$filter`, `$orderby`, `$expand`, `$search`, `$count` | `400 Request_UnsupportedQuery` — an explicit refusal beats silently returning the unfiltered set |

## 6. Token changes

These apply to Entra mode only (already opt-in), and none of them change a response that an
existing test asserts:

1. **Group overage resolves locally.** With Graph on, `_claim_sources.src1.endpoint` becomes
   `{origin}/{base}/graph/v1.0/users/{oid}/getMemberObjects`. With Graph off, or
   `overageEndpoint: "microsoft"`, it stays the real Graph URL.
2. **`scp` carries short names** with the resource prefix stripped
   (`https://graph.microsoft.com/User.Read` → `User.Read`) and `offline_access` dropped. The token
   response's `scope` field is unchanged.
3. **`azp` and `appid`** are added to the access token (both the `client_id`), as real Entra emits
   and as entra-local assembles.
4. **`given_name` / `family_name` / `roles` / `wids`** appear when the user configures them.
5. **`accountEnabled: false`** fails the token endpoint with AADSTS50057, the same as
   `error: "invalid_grant"`.

## 7. Account selection hints

Borrowed from both projects, because without them every RP test needs a browser:

- **`login_hint`** matching exactly one account in scope (by UPN, email, or username) issues the
  code immediately, skipping the picker. `prompt=select_account|login` forces the picker anyway, and
  `graph`-independent config `ignoreLoginHint: true` disables the shortcut entirely. A hint that
  matches nothing or several accounts falls back to the picker with the hint pre-filled and the
  matching account highlighted (entra-local).
- **`domain_hint`** on `organizations`/`common` narrows the picker to tenants carrying that domain;
  if exactly one account remains the shortcut applies.
- **`prompt=none`** issues the code when `login_hint` resolves one account, else redirects
  `error=interaction_required` "AADSTS50058: A silent sign-in request was sent but no user is signed
  in." *Divergence:* we have no session cookie, so a resolvable `login_hint` **is** the session.

## 8. App-only tokens

Gated by `graph.appOnly` (default off, so the existing test asserting that `client_credentials` is
`unsupported_grant_type` keeps passing). When on, `grant_type=client_credentials` with
`scope=https://graph.microsoft.com/.default` on a **tenant-specific** path mints an access token
with `tid` from the path, `sub` = `azp` = `appid` = `client_id`, `roles` from
`entra.apps[].roles`, and no `oid`/`scp`. On `organizations`/`common` it is a 400 `invalid_request`
(real Entra's exact code there is unverified — see §10). Such a token reads `/users` and `/groups`
and gets `403 Authorization_RequestDenied` on `/me`, exactly as in entra-local.

## 9. Decisions

| Decision | Why |
|---|---|
| Graph is a sub-feature gated by an optional `"graph"` block, default **off** | The repo forbids editing existing tests; three of them encode today's "no userinfo, no Graph, no client credentials". Opt-in keeps them green and keeps the navikt contract irrelevant to this change. The demo config and compose file turn it on, so the lived default is "on" |
| One tenant-agnostic `/graph/` base, scoped by the token's `tid` | Mirrors real Graph, and keeps the single front route |
| Read-only | The admin UI already owns mutation, with copy-on-write and re-validation. Two write paths would be two sources of truth |
| Group entities derived from user `groups[]`, ids from the existing `GroupObjectID` | No config break, and the ids already in `object_id` group claims and `/_entra/groups` are the same ids Graph returns — an RP can match a claim to a Graph object |
| Flat groups: `transitiveMemberOf` == `memberOf` | Nested groups are a directory feature, not an account feature. Documented |
| No Graph permission enforcement | Follows entra-local; mock-oidc accepts any client everywhere, so enforcing `User.Read.All` would be theater |
| Graph errors bypass `routing.ErrorResponse` | Graph codes are PascalCase; the lowercasing is a navikt behavior that must not leak into a Graph body |

## 10. What still needs real Entra

The exact `AADSTS` code for `client_credentials` against `/common`; whether a real v2 ID token
carries `wids` for a non-admin; real Graph's exact `innerError` field set; whether real Graph 400s or
ignores an unknown `$orderby`. Each is a fixture to confirm against a real tenant in the IAM's
pre-launch smoke test, then fold back here.
