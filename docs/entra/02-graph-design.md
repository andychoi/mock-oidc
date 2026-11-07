# Entra mode: account Graph API

Entra mode serves a read-only emulation of the account part of Microsoft Graph, OIDC
`userinfo`, account-selection hints, and app-only tokens. A relying party that signs in with
Entra usually calls Graph next: `/me` for a profile, `/me/memberOf` for authorization, `/users` to
sync a directory, and `getMemberObjects` to resolve group overage. This surface lets those calls
stay inside the test environment.

Sign-in and tokens are in [`00-design.md`](00-design.md). Org attributes, dynamic groups,
`$filter`, and `$expand=manager` are in [`04-org-directory-design.md`](04-org-directory-design.md).

## 1. Scope

Emulated: `/me`, `/users`, `/groups`, group membership, the manager chain, `getMemberObjects`
and `getMemberGroups`, OIDC `userinfo`, `$top`, `$skiptoken`, `$select`, a `$filter` subset,
`$expand=manager`, `login_hint`, `domain_hint`, `prompt`, and the `client_credentials` grant.

Not emulated: Graph writes, nested groups, Graph permission checks, `$orderby`, `$search`,
`$count`, and Graph beyond accounts and groups.

## 2. Sources

Two open-source Entra mocks shaped this design.
[`cmaneu/entra-local`](https://github.com/cmaneu/entra-local) contributed the authorization model
(any valid Graph-audience token reads, and `/me` needs a delegated token), the OData paging
rules, Graph error bodies, `userinfo` at `/graph/oidc/userinfo`, and short-name `scp`.
[`nazriel/ms-oidc-mock`](https://github.com/nazriel/ms-oidc-mock) contributed the `login_hint`
shortcut with a switch to turn it off, the richer `/me` profile fields, and `roles` read straight
from the user fixture.

Three choices differ from both. Graph is scoped to the token's tenant, because a Corp token must
not list Customer X. `userinfo` returns OIDC claims, not the Graph `/me` shape, because real Entra
has both and they differ. There is no app registry, because mock-oidc accepts any client.

## 3. Architecture

| File in `internal/entra` | Contents |
|---|---|
| `graphconfig.go` | `GraphConfig` (the `graph` block), defaults, validation |
| `graph.go` | Graph route table and handlers |
| `directory.go` | Users and groups as Graph sees them: `(*Tenant).GroupOID`, `(*User).MemberGroups`, `GroupsIn`, `GroupByID`, `MembersOf`, `GroupsOf`, `ManagerOf`, `DirectReports` |
| `odata.go` | OData envelope, paging, `$select`, Graph error bodies |
| `filter.go` | `$filter` parser and evaluator |
| `verify.go` | `KeySet.Verify` and `ValidateAccessToken` |
| `userinfo.go` | `GET` and `POST /graph/oidc/userinfo` |
| `appcreds.go` | The `client_credentials` grant |
| `authorize.go` | Selection hints |

Graph uses the existing Entra front route. Its segment (`graph` by default) is reserved next to
`_entra`, so `Handle` sends `/{basePath}/graph/...` to Graph before it resolves a tenant. Tenant
segments are GUIDs, `organizations`, or `common`, so the two cannot clash. While Graph is off,
the segment is not reserved and resolves as an unknown tenant.

```
/{basePath}/graph/v1.0/...        Graph account endpoints (tenant from the token's tid)
/{basePath}/graph/oidc/userinfo   OIDC UserInfo
```

Real Graph is one host for every tenant, and the caller's token scopes each response. This
layout copies that.

## 4. Configuration

Graph is on whenever Entra mode is on. The optional `graph` block inside the `entra` block tunes
it. `appOnly` is the one feature that is off by default (§8).

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
      { "username": "sora", "tid": "11111111-1111-1111-1111-111111111111", "name": "Sora Lee" },
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

| Field | Default | Effect |
|---|---|---|
| `graph.enabled` | `true` | `false` removes the routes and `userinfo_endpoint`, frees the segment, and points the overage claim at `graph.microsoft.com`. The admin setting `graph` changes it at runtime. |
| `graph.basePath` | `graph` | The reserved segment. Lowercased. One segment of `[A-Za-z0-9_-]`. It cannot be `_entra`, `organizations`, `common`, a GUID, or the Entra `basePath`. |
| `graph.overageEndpoint` | `self` | `self` points the overage claim at this server's `getMemberObjects`. `microsoft` points it at `graph.microsoft.com`. |
| `graph.userinfo` | `true` | Serves and advertises `userinfo_endpoint` |
| `graph.appOnly` | `false` | Turns on the `client_credentials` grant (§8) |
| `graph.defaultPageSize`, `maxPageSize` | 100, 999 | `$top` default and clamp. A default above the maximum is clamped down. |
| `graph.clockSkew` | 60 seconds | Leeway on `exp` and `nbf`. An explicit `0` means none. A negative value is rejected. |
| `tenant.groups[]` | none | Group metadata: `name`, `description`, `mailNickname`, `mail`, `securityEnabled` (default `true`), `mailEnabled`, `oid`, and `membershipRule`. A configured `oid` must be a GUID, unique in the tenant, and is used in Graph and in `object_id` group claims alike. Group names that users list but nobody declares are created automatically. |
| `user.givenName`, `surname` | none | `given_name` and `family_name` claims, and Graph fields |
| `user.upn` | `email`, else `username@{first tenant domain}`, else the username | Graph `userPrincipalName`, and `preferred_username` in tokens and `userinfo` ([`00-design.md` §4.1](00-design.md#41-id-token-claims)) |
| `user.accountEnabled` | `true` | `false` shows in Graph, makes `userinfo` and Graph calls with that user's token answer 401, and fails the token endpoint with AADSTS50057. `error: "invalid_grant"` has the same effect. |
| `user.jobTitle`, `officeLocation`, `businessPhones`, `mobilePhone`, `preferredLanguage` | none | Graph profile fields |
| `user.roles` | none | `roles` claim in the ID and access tokens |
| `user.wids` | none | `wids` claim, tenant-wide directory roles. Global Administrator is `62e90394-69f5-4237-9190-012177145e10`. |
| `user.manager` | none | A username, object ID, or UPN in the same tenant, stored as the username |
| `user.department`, `companyName`, `employeeId`, `onPremisesExtensionAttributes`, `apps[].claims` | none | Org directory: [`04-org-directory-design.md`](04-org-directory-design.md) |

## 5. Endpoints

All paths are under `{origin}/{basePath}/{graph.basePath}`, with the proxy-aware origin used
everywhere in Entra mode. Every endpoint needs `Authorization: Bearer <access_token>`.

| Method | Path | Returns |
|---|---|---|
| GET | `/v1.0/me` | The token's user (`microsoft.graph.user` subset) |
| GET | `/v1.0/me/memberOf`, `/transitiveMemberOf` | The user's groups. Groups are flat, so both are the same. |
| GET | `/v1.0/me/manager` | The user's manager, or 404 `Request_ResourceNotFound` |
| GET | `/v1.0/me/directReports` | Users whose `manager` is this user |
| POST | `/v1.0/me/getMemberObjects`, `/getMemberGroups` | Group object IDs (§5.2). This resolves group overage. |
| GET | `/v1.0/users` | The token tenant's users, paged |
| GET | `/v1.0/users/{id}` | One user by object ID, UPN, or username |
| GET, POST | `/v1.0/users/{id}/…` | The same sub-paths as `/me` |
| GET | `/v1.0/groups` | The token tenant's groups, paged |
| GET | `/v1.0/groups/{id}` | One group by object ID or display name |
| GET | `/v1.0/groups/{id}/members`, `/transitiveMembers` | The group's member users |
| GET | `/v1.0/me/photo`, `/me/photo/$value` | 404 `ImageNotFound`, because clients probe it |
| GET, POST | `/oidc/userinfo` | OIDC claims (§5.3) |
| OPTIONS | any | 204 |

Any other path under `/v1.0/` checks the token first, then answers 404
`Request_ResourceNotFound` with a Graph error body. `/oidc/userinfo` with another method gets 405.

### 5.1 Bearer validation

`ValidateAccessToken` checks, in order:

1. A `Bearer` scheme and a non-empty token with three JWS parts.
2. `alg` is `RS256`, and `kid` names a key in the current `KeySet`. A token signed before a
   rotation still verifies while its key stays published.
3. The RS256 signature.
4. `aud` is `00000003-0000-0000-c000-000000000000`, `ver` is `"2.0"`, and `appid` is not empty.
   Every access token and app-only token carries `appid` and no ID token does, so ID tokens fail
   here. A claims mapping cannot add `appid`.
5. `tid` is not empty, and `iss` is `Issuer(origin, basePath, tid)`. A token minted for another
   host fails.
6. `exp` is present and in the future, and `nbf`, when present, is in the past, each with
   `clockSkew`.
7. `tid` names a configured tenant.
8. For a delegated token (one with `oid`), `oid` names a user in that tenant whose account is
   enabled. Deleting or disabling the user after minting invalidates the token.

Every failure gets the same `401 InvalidAuthenticationToken` "Access token is empty or invalid."
with `WWW-Authenticate: Bearer error="invalid_token"`, so a caller cannot probe the directory
through the message.

### 5.2 Shapes

```jsonc
// user
{ "@odata.context": "{origin}/{base}/graph/v1.0/$metadata#users/$entity",
  "id": "<oid>", "displayName": "Jane Kim", "userPrincipalName": "jane@corp.example",
  "mail": "jane@corp.example", "givenName": "Jane", "surname": "Kim",
  "jobTitle": "Staff Engineer", "officeLocation": "Seoul",
  "businessPhones": ["+82-2-555-0100"], "mobilePhone": "+82-10-555-0101",
  "preferredLanguage": "en-US", "accountEnabled": true }

// group
{ "@odata.context": "{origin}/{base}/graph/v1.0/$metadata#groups/$entity",
  "id": "<group oid>", "displayName": "AMS Engineers", "description": "Engineering",
  "mailNickname": "amsengineers", "mail": null,
  "mailEnabled": false, "securityEnabled": true,
  "groupTypes": [], "membershipRule": null, "membershipRuleProcessingState": null }

// collection
{ "@odata.context": "{origin}/{base}/graph/v1.0/$metadata#users",
  "value": [ /* entities without their own @odata.context */ ],
  "@odata.nextLink": "{origin}/{base}/graph/v1.0/users?$top=1&$skiptoken=1" }

// getMemberObjects, getMemberGroups
{ "@odata.context": "{origin}/{base}/graph/v1.0/$metadata#Collection(Edm.String)",
  "value": [ "<group oid>", … ] }

// error
{ "error": { "code": "InvalidAuthenticationToken",
             "message": "Access token is empty or invalid.",
             "innerError": { "date": "2026-10-11T00:00:00", "request-id": "<uuid>",
                             "client-request-id": "<uuid>" } } }
```

- A missing single value is `null`, and a missing `businessPhones` is `[]`. Graph emits the key,
  and SDK deserializers rely on it.
- `memberOf`, `directReports`, and `members` collections use the `directoryObjects` context
  suffix, like real Graph.
- `getMemberObjects` and `getMemberGroups` ignore `securityEnabledOnly`. A body that is not JSON
  gets 400 `Request_BadRequest`.
- Group IDs come from `(*Tenant).GroupOID`, so a group's configured `oid` is the same in Graph,
  in `object_id` group claims, and in `/_entra/groups`. Memberships come from
  `User.MemberGroups()`, with static and dynamic groups and no duplicates.
- `innerError.client-request-id` echoes the request's `client-request-id` header.
- Graph error codes are PascalCase, so these bodies never go through `routing.ErrorResponse`,
  which lowercases bodies for navikt compatibility.

### 5.3 UserInfo

`GET` or `POST /{base}/{graph.basePath}/oidc/userinfo` returns OIDC claims, not the Graph shape:
`sub` (the token's pairwise `sub`), `oid`, `tid`, `name`, `preferred_username` (the UPN when set),
and `given_name`, `family_name`, and `email` when set. Responses carry `Cache-Control: no-store`.
An app-only token gets `403 insufficient_scope`. Any token that fails §5.1, including an ID token,
gets `401 invalid_token` with `WWW-Authenticate` and the description "The access token is
invalid or expired." Discovery advertises the endpoint as `userinfo_endpoint` while
`graph.userinfo` is on.

### 5.4 Query options

| Option | Behavior |
|---|---|
| `$top` | Default `defaultPageSize`, clamped to `[1, maxPageSize]`. An invalid value uses the default. |
| `$skiptoken` | A non-negative integer offset. An invalid value is `0`. `@odata.nextLink` keeps every other parameter and appears only while rows remain. Collections are ordered by `id`. |
| `$select` | A comma list of known properties. `id` is always included. The server checks the list before filtering and paging, so an unknown property gets `400 Request_UnsupportedQuery` "Could not find a property named …" even on an empty page. Without `$select`, the `$select`-only org properties are left out, as in Graph. |
| `$filter` | Collections only. A subset of `eq`, `ne`, `in`, `startsWith`, `any`, `and`, `or`, and `not`, nested at most 32 levels; see [`04-org-directory-design.md` §5](04-org-directory-design.md#5-filter-collections-only) |
| `$expand` | `manager` only, on `/me`, `/users/{id}`, and `/users`; see [`04-org-directory-design.md` §6](04-org-directory-design.md#6-expandmanager) |
| `$orderby`, `$search`, `$count`, `$apply`, `$format` | `400 Request_UnsupportedQuery` "The query option '…' is not supported by this emulator." |

Every refused option, every `$filter` failure, and `$filter` on a single entity get
`400 Request_UnsupportedQuery`. The emulator never ignores an option it does not support.

## 6. Token changes

These change Entra tokens whether Graph is on or off, except the overage endpoint:

1. `scp` carries short names with the resource prefix stripped
   (`https://graph.microsoft.com/User.Read` becomes `User.Read`) and without `offline_access`.
   The token response's `scope` field keeps every requested scope.
2. The access token carries `azp` and `appid`, both set to the `client_id`.
3. `given_name`, `family_name`, `roles`, and `wids` appear when the user sets them.
4. `accountEnabled: false` fails the token endpoint with AADSTS50057, the same as
   `error: "invalid_grant"`.
5. The group-overage endpoint points at this server's
   `{origin}/{base}/graph/v1.0/users/{oid}/getMemberObjects` while Graph is on and
   `overageEndpoint` is `self`. Otherwise it is the real Graph URL.

## 7. Account selection hints

Without these, every relying-party test needs a browser.

- `login_hint` that matches exactly one account in scope, by UPN, email, or username, issues the
  code on the GET and skips the picker and the passkey step. `prompt=select_account` and
  `prompt=login` show the picker anyway. `"ignoreLoginHint": true` in the `entra` block turns the
  shortcut off. A hint that matches no account or several shows the picker with the hint named and
  any matching account marked.
- `domain_hint` on `organizations` or `common` narrows the picker to tenants that list that
  domain. A domain that matches no tenant is ignored. It has no effect on tenant paths, and on its
  own it never skips the picker.
- `prompt=none` issues the code when `login_hint` resolves one account and `ignoreLoginHint` is
  off. Otherwise it redirects with `error=interaction_required` "AADSTS50058: A silent sign-in
  request was sent but no user is signed in." This is a divergence from real Entra: the mock keeps
  no session cookie, so a resolvable `login_hint` stands in for the session.

## 8. App-only tokens

`graph.appOnly` turns this on, and it needs Graph on too. It is off by default because
`client_credentials` changes who can get a token at all, and most relying-party tests want it
refused. While it is off, the grant gets 400 `unsupported_grant_type` "AADSTS70003".

When on, `grant_type=client_credentials` on a tenant-specific path mints an access token:

- `client_id` comes from the form or from Basic auth. Without it, 400 `invalid_client`
  "AADSTS900023".
- Each requested scope must end in `/.default` or be `.default`. No scope also works. Any other
  scope gets 400 `invalid_request` "AADSTS1002012". The token's `aud` is always Graph.
- The token has `tid` from the path, `sub`, `azp`, and `appid` set to the `client_id`, `roles` from
  the matching `entra.apps[]` entry, and no `oid` or `scp`. The response has `token_type`,
  `expires_in`, `ext_expires_in`, and `access_token`, with no `scope`.
- On `organizations` or `common` the grant gets 400 `invalid_request`, because no tenant is named.

An app-only token reads `/users` and `/groups` and gets `403 Authorization_RequestDenied` on
`/me`, like a directory-sync job.

## 9. Decisions

| Decision | Why |
|---|---|
| Graph is on by default with Entra mode | An Entra mock whose Graph must be turned on is one whose Graph nobody uses. Before Graph existed, discovery had no `userinfo_endpoint` because there was nowhere to point it. Now it has one. |
| One tenant-agnostic `/graph/` base, scoped by the token's `tid` | Real Graph works this way, and it keeps the single front route |
| Read-only | The admin UI already owns edits, with copy-on-write and validation. Two write paths would be two sources of truth. |
| Group IDs from `(*Tenant).GroupOID` | The ID in an `object_id` group claim is the ID Graph returns, so a relying party can match a claim to a Graph object |
| Flat groups: `transitiveMemberOf` equals `memberOf` | Nested groups are a directory feature, not an account feature |
| No Graph permission checks | mock-oidc accepts any client everywhere, so checking `User.Read.All` would prove nothing |
| Graph errors bypass `routing.ErrorResponse` | Graph codes are PascalCase, and the lowercasing is navikt behavior |

## 10. What still needs real Entra

Open questions to check against a real tenant: the exact `AADSTS` code for `client_credentials`
on `/common`, whether a real v2 ID token carries `wids` for a non-admin, the exact `innerError`
fields, and whether real Graph refuses or ignores an unsupported `$orderby`.
