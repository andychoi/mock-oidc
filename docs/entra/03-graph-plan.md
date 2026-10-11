# Entra Mode — Account Graph API Implementation Plan

**Goal:** Add an opt-in, read-only Microsoft Graph **account** surface to Entra mode
(`/me`, `/users`, `/groups`, `memberOf`, `getMemberObjects`), an OIDC `userinfo` endpoint, a Bearer
validator for our own access tokens, richer account fixtures, account-selection hints, and optional
app-only tokens — so an RP can sign in **and then read the account**, entirely inside the mock.

**Spec:** [`02-graph-design.md`](02-graph-design.md). Read it first; this plan implements it
section by section. Entra mode itself: [`00-design.md`](00-design.md), [`01-plan.md`](01-plan.md).

## Global constraints

- `go 1.27`, **no new module dependencies** (`go.mod`/`go.sum` unchanged).
- **Additive and opt-in.** Without an `entra.graph` block, every response is byte-for-byte what it
  is today. All existing tests must pass **unmodified** — in particular these three, which encode
  today's behavior and must not be touched:
  - `internal/e2e/entra_test.go` `TestEntraDiscoveryPerTenant` — `userinfo_endpoint` must be absent
  - `internal/e2e/entra_test.go` `TestEntraUnsupportedGrantIsEntraError` — `client_credentials` → 400
  - `internal/entra/claims_test.go` `TestGroupOverageBoundary` — overage endpoint shape
- `internal/entra` keeps its import rule: stdlib, `internal/oauth2`, `internal/routing`,
  `internal/jsonx`, `internal/token`. Never `internal/config` or `internal/server`.
- Graph error bodies must **not** pass through `routing.ErrorResponse` (it lowercases the body for
  navikt compatibility; Graph codes are PascalCase).
- CI gates: `gofmt -l .` empty (excluding `docs/`), `go vet ./...`, `go build ./...`,
  `go test ./...`; plus `go test -race ./...` before finishing.
- US English in comments and docs. Commit messages end with `Co-authored by AI`.

## Review focus

1. **Nothing leaks when Graph is off.** No `userinfo_endpoint`, no `/graph/*` route, overage
   endpoint unchanged, `client_credentials` still rejected. *(Task 8 `TestGraphAbsentWhenNotConfigured`.)*
2. **Tenant isolation.** A Corp delegated token must not see Customer X users or groups anywhere —
   `/users`, `/groups`, `/users/{id}`, `memberOf`, `getMemberObjects`. *(Task 5 `TestGraphTenantIsolation`.)*
3. **Token validation is real.** A tampered signature, a wrong `aud`, a wrong origin's `iss`, an
   expired token, and a token signed by a dropped key each 401. A token signed before a rotation
   still works while its key is published. *(Task 2 `TestValidateAccessToken*`.)*
4. **The overage loop closes.** The `_claim_sources` endpoint in a real issued token, fetched with
   that token's own access token, returns that user's group ids. *(Task 7 `TestGraphResolvesGroupOverage`.)*
5. **Proxy-aware origin everywhere.** Behind `x-forwarded-*`, `@odata.context`, `@odata.nextLink`,
   the overage endpoint, and the `iss` the validator expects all use the same origin.
   *(Task 5 `TestGraphHonorsForwardedHeaders`.)*
6. **Concurrency.** Graph reads take one config snapshot per request and must stay race-free against
   admin mutations and key rotation. *(Task 10, run with `-race`.)*

## File map

| File | Responsibility | Task |
|---|---|---|
| `internal/entra/graphconfig.go` (+test) | `GraphConfig`, defaults, validation, `Config.GraphOn()` | 1 |
| `internal/entra/config.go` | new `User`/`Tenant` fields, normalize/validate, `manager` resolution | 1 |
| `internal/entra/store.go` | clone the new fields; cascade on delete | 1 |
| `internal/entra/verify.go` (+test) | `KeySet.Verify`, `ValidateAccessToken`, typed failures | 2 |
| `internal/entra/directory.go` (+test) | group entities, membership, deterministic ordering | 3 |
| `internal/entra/odata.go` (+test) | envelope, `$top`/`$skiptoken`/`$select`, Graph errors | 4 |
| `internal/entra/graph.go` (+test) | Graph route table and account handlers | 5 |
| `internal/entra/handler.go` | reserve the `graph` segment; gate on `GraphOn` | 5 |
| `internal/entra/userinfo.go` (+test) | `/oidc/userinfo`; discovery advertisement | 6 |
| `internal/entra/claims.go` | overage endpoint, `scp` short names, `azp`/`appid`, `given_name`/`family_name`/`roles`/`wids` | 7 |
| `internal/entra/authorize.go`, `templates/picker.html.tmpl` | `login_hint`, `domain_hint`, `prompt` | 8 |
| `internal/entra/appcreds.go` (+test), `token.go` | `client_credentials` (app-only) | 9 |
| `internal/entra/admin.go`, `testapi.go`, `internal/adminui/static/` | new fields in the admin UI; `/_entra` additions | 10 |
| `internal/e2e/entra_graph_test.go` | end-to-end suite | 5 (extended 6–9) |
| `entra-demo.json`, `README.md`, `docs/entra/00-design.md`, `CLAUDE.md` | wiring and docs | 10 |

---

### Task 1: Account model and the `graph` config block

**Files:** create `internal/entra/graphconfig.go`, `internal/entra/graphconfig_test.go`; modify
`internal/entra/config.go`, `internal/entra/config_test.go`, `internal/entra/store.go`,
`internal/entra/store_test.go`.

**Produces**

```go
type GraphConfig struct {
	Enabled         *bool  `json:"enabled"`         // nil → true (presence enables)
	BasePath        string `json:"basePath"`        // default "graph"
	OverageEndpoint string `json:"overageEndpoint"` // "self" (default) | "microsoft"
	UserInfo        *bool  `json:"userinfo"`        // nil → true
	AppOnly         bool   `json:"appOnly"`
	DefaultPageSize int    `json:"defaultPageSize"` // default 100
	MaxPageSize     int    `json:"maxPageSize"`     // default 999
	ClockSkew       int64  `json:"clockSkew"`       // seconds, default 60
}

func (c *Config) GraphOn() bool     // Graph != nil && *Enabled
func (c *Config) UserInfoOn() bool  // GraphOn() && *Graph.UserInfo
func (c *Config) GraphBase() string // Graph.BasePath, or "graph"

type Group struct {                  // tenant.groups[] metadata, all optional
	Name, Description, MailNickname, Mail, OID string
	SecurityEnabled, MailEnabled               *bool
}
```

New `Config.Graph *GraphConfig`, new `Tenant.Groups []Group`, and on `User`: `GivenName`,
`Surname`, `UPN`, `AccountEnabled *bool`, `JobTitle`, `OfficeLocation`, `BusinessPhones []string`,
`MobilePhone`, `PreferredLanguage`, `Roles []string`, `WIDs []string`, `Manager string`.

**Normalization** (inside the existing `normalize`, so runtime admin edits re-run it):
`graph.basePath` trimmed of slashes, default `graph`, must match `basePathRE`, and must not equal
`entra.basePath`, `_entra`, `organizations`, or `common`; `overageEndpoint` ∈ `self|microsoft`
(default `self`); page sizes and `clockSkew` default when `<= 0`, `defaultPageSize` clamped to
`maxPageSize`; `user.upn` lowercased; `user.wids` lowercased and GUID-checked; `user.manager`, when
set, must name another user in the same tenant and must not be the user itself; `tenant.groups[]`
names non-empty and unique per tenant, explicit `oid` lowercased and GUID-checked.

- [ ] **Step 1: failing tests** in `graphconfig_test.go` and `config_test.go`
  - `TestGraphConfigDefaults` — `{"graph":{}}` → on, basePath `graph`, overage `self`, userinfo on,
    appOnly off, 100/999/60.
  - `TestGraphConfigDisabled` — `{"graph":{"enabled":false}}` → `GraphOn() == false`.
  - `TestGraphOffWhenAbsent` — today's config → `GraphOn() == false`, `UserInfoOn() == false`.
  - `TestGraphConfigRejects` — table: basePath colliding with `entra.basePath`/`_entra`/
    `organizations`/`common`, bad basePath charset, bad `overageEndpoint`, unknown field.
  - `TestUserProfileFieldsNormalize` — `upn` lowercased, `accountEnabled` nil → treated as true by
    the accessor, `wids` GUID-checked, unknown `manager` rejected, self-`manager` rejected.
  - `TestTenantGroupsValidate` — duplicate group name rejected, bad explicit `oid` rejected.
  - `TestStoreClonesProfileFields` — `UpdateUser` with the new fields round-trips and the previous
    snapshot is unchanged (copy-on-write).
- [ ] **Step 2: run to verify failure** — `go test ./internal/entra/ -run 'Graph|Profile|TenantGroups|StoreClones' -v`
- [ ] **Step 3: implement** `graphconfig.go` and extend `config.go` / `store.go` (`cloneConfig` must
  deep-copy the new slices — `BusinessPhones`, `Roles`, `WIDs`, `Tenant.Groups`).
- [ ] **Step 4: run** `go test ./internal/entra/ -v && gofmt -l internal/entra && go vet ./internal/entra/`
- [ ] **Step 5: full suite** `go test ./...` — every existing test unmodified and green.
- [ ] **Step 6: commit** `feat(entra): graph config block and richer account fixtures`

---

### Task 2: Bearer access-token validation

**Files:** create `internal/entra/verify.go`, `internal/entra/verify_test.go`.

**Produces**

```go
// KeySet
func (k *KeySet) Verify(jwt string) (header, claims map[string]any, ok bool)

type TokenKind int // TokenDelegated (has oid) | TokenAppOnly

type Caller struct {
	Claims map[string]any
	TID    string
	OID    string // "" for app-only
	Sub    string
	Kind   TokenKind
}

// ValidateAccessToken verifies a Bearer token minted by this handler.
func (h *Handler) ValidateAccessToken(req *oauth2.Request, bearer string) (*Caller, *graphError)
```

Order of checks per design §5.1: scheme/non-empty → 3 parts → `kid` published → RS256 signature →
`aud == graphAppID` → `ver == "2.0"` → `iss == Issuer(origin(req), cfg.BasePath, claims.tid)` →
`nbf <= now+skew`, `now-skew < exp`. Then `cfg.Tenant(tid) != nil`, and for a delegated token the
`oid` must resolve to a user in that tenant **and** that user must be `accountEnabled`. Every
failure is the same opaque `401 InvalidAuthenticationToken` (never leak which check failed).

Reuse `internal/token`'s hashing helpers; do **not** reuse `TokenProvider.Verify` (it is bound to
the per-issuer `KeyProvider`). If verification needs a public-key accessor on `SigningKey`, add it
to `internal/token/sign.go` rather than reaching into the struct from `entra`.

- [ ] **Step 1: failing tests**
  - `TestKeySetVerifyRoundTrip`, `TestKeySetVerifyRejectsTamperedPayload`.
  - `TestKeySetVerifyAcceptsPreviousKeyUntilDropped` — sign, rotate once → still verifies; rotate
    twice → fails (the key is no longer published).
  - `TestValidateAccessTokenHappyPath` — delegated token → `Caller{TID, OID, Kind: TokenDelegated}`.
  - `TestValidateAccessTokenRejects` — table: no header, `Basic` scheme, empty bearer, two-part
    token, unknown `kid`, wrong `aud`, `ver: "1.0"`, `iss` from another origin, `exp` in the past,
    `nbf` in the future, `tid` of a deleted tenant, `oid` of a deleted user, disabled user.
  - `TestValidateAccessTokenClockSkew` — 30s-expired token passes with the default 60s skew, fails
    with `clockSkew: 0`.
- [ ] **Step 2: run to verify failure**
- [ ] **Step 3: implement** `verify.go`
- [ ] **Step 4: run** `go test ./internal/entra/ -run 'Verify|ValidateAccessToken' -v`
- [ ] **Step 5: commit** `feat(entra): validate our own Graph-audience access tokens`

---

### Task 3: Directory view — group entities and membership

**Files:** create `internal/entra/directory.go`, `internal/entra/directory_test.go`.

Groups exist today only as names on users. Graph needs entities with stable ids. Derive them:
the union of `tenant.groups[].name` and every `user.groups[]` name in the tenant; id is the explicit
`oid` when set, else the existing `GroupObjectID(tid, name)` — the same id already emitted by
`object_id` group claims and `/_entra/groups`, so an RP can match a claim to a Graph object.

**Produces**

```go
type DirGroup struct { OID, Name, Description, MailNickname, Mail string; SecurityEnabled, MailEnabled bool }

func (c *Config) GroupsIn(tid string) []DirGroup          // ordered by OID
func (c *Config) GroupByID(tid, id string) *DirGroup       // by oid or displayName
func (c *Config) GroupsOf(u *User) []DirGroup              // the user's groups, ordered by OID
func (c *Config) MembersOf(tid, groupID string) []*User    // ordered by OID
func (c *Config) UserByOID(tid, oid string) *User
func (c *Config) UserByUPNOrOID(tid, key string) *User     // Graph accepts either
func (c *Config) DirectReports(u *User) []*User
func (c *Config) ManagerOf(u *User) *User
func (u *User) Enabled() bool                              // AccountEnabled == nil || *AccountEnabled
func (u *User) PrincipalName(t *Tenant) string             // UPN, else today's preferred_username rule
func mailNickname(name string) string                      // lowercase, non-alphanumerics dropped
```

- [ ] **Step 1: failing tests**
  - `TestGroupsInUnionOfDeclaredAndUsed` — a name only on a user appears with `description: ""`;
    declared metadata wins; result ordered by OID; no duplicates.
  - `TestGroupIDMatchesGroupClaim` — `GroupsOf(user)[i].OID == GroupObjectID(tid, name)`, and with
    `groupClaimFormat: "object_id"` equals the value in `IDTokenClaims`.
  - `TestGroupLookupByIDAndDisplayName`, `TestMembersOfOrdering`.
  - `TestUserByUPNOrOIDAcceptsBoth` and is case-insensitive on the UPN.
  - `TestGroupsAreTenantScoped` — the same group name in two tenants has different ids and disjoint
    members.
  - `TestManagerAndDirectReports`, `TestEnabledDefaultsTrue`, `TestPrincipalNameFallsBackToPreferredUsername`.
- [ ] **Step 2: run to verify failure**
- [ ] **Step 3: implement** `directory.go`
- [ ] **Step 4: run** `go test ./internal/entra/ -v`
- [ ] **Step 5: commit** `feat(entra): derive group entities and membership from the config`

---

### Task 4: OData plumbing — envelope, paging, `$select`, Graph errors

**Files:** create `internal/entra/odata.go`, `internal/entra/odata_test.go`.

**Produces**

```go
type graphError struct { Status int; Code, Message string }

func (h *Handler) graphErrorResponse(e *graphError) routing.Response // + WWW-Authenticate on 401
func graphContext(origin, base, graphBase, suffix string) string     // …/v1.0/$metadata#<suffix>
func parseTop(raw string, cfg *GraphConfig) int                      // default, clamp [1, max]
func parseSkip(raw string) int                                       // >= 0, invalid → 0
func nextLink(req *oauth2.Request, origin, nextSkip string) string   // preserves every other param
func applySelect(entity jsonx.Obj, raw string, known map[string]bool) (jsonx.Obj, *graphError)
func collection(req, origin, ctxSuffix string, total int, page []jsonx.Obj) routing.Response
```

Edge cases to encode (all from entra-local's spec, §2.2 of the design):
`@odata.nextLink` appears only when `skip+top < total` and preserves `$top` and `$select`; `$`-keys
stay literal, values percent-encoded; single entities carry `@odata.context`, collection items do
not; `businessPhones` renders `[]` and single-valued gaps render `null`; `$filter`/`$orderby`/
`$expand`/`$search`/`$count` → `400 Request_UnsupportedQuery`; an unknown `$select` property →
`400 Request_UnsupportedQuery`; `id` survives any `$select`.

- [ ] **Step 1: failing tests**
  - `TestParseTopClampAndDefault` (table: absent, `0`, `-1`, `abc`, `5`, `5000`).
  - `TestParseSkipInvalidIsZero`.
  - `TestNextLinkPreservesQueryAndOverridesSkiptoken`, `TestNextLinkAbsentOnLastPage`.
  - `TestSelectKeepsIDAndRejectsUnknownProperty`.
  - `TestGraphErrorBodyIsNotLowercased` — the rendered body contains
    `"InvalidAuthenticationToken"` with its capitals, and `innerError` has `date`, `request-id`,
    `client-request-id`.
  - `TestGraphError401SetsWWWAuthenticate`.
  - `TestUnsupportedQueryOptions` (table over `$filter`, `$orderby`, `$expand`, `$search`, `$count`).
- [ ] **Step 2: run to verify failure**
- [ ] **Step 3: implement** `odata.go`
- [ ] **Step 4: run** `go test ./internal/entra/ -run 'Top|Skip|NextLink|Select|GraphError|Unsupported' -v`
- [ ] **Step 5: commit** `feat(entra): OData envelope, paging and Graph error bodies`

---

### Task 5: Account endpoints

**Files:** create `internal/entra/graph.go`, `internal/entra/graph_test.go`,
`internal/e2e/entra_graph_test.go`; modify `internal/entra/handler.go`.

In `Handle`, reserve the Graph segment before tenant resolution — next to the existing `_entra`
branch, and only while `GraphOn()`:

```go
if cfg := h.conf(); cfg.GraphOn() && segs[1] == cfg.GraphBase() {
	return h.graph(req, segs[2:])
}
```

With Graph off the segment is not reserved, so `/{base}/graph/...` resolves as a tenant and gives
today's `AADSTS90002`. Every handler then: `h.ValidateAccessToken` → tenant from `caller.TID` →
dispatch. Routes and shapes per design §5; `/me*` requires `caller.Kind == TokenDelegated`, else
`403 Authorization_RequestDenied`.

- [ ] **Step 1: failing unit tests** (`graph_test.go`, in-package, minting tokens through the
      handler's own `KeySet`)
  - `TestGraphMeShape` — all documented fields present, `null`/`[]` for gaps, `@odata.context` ends
    `$metadata#users/$entity`.
  - `TestGraphMeRequiresDelegatedToken` — app-only → 403 `Authorization_RequestDenied`.
  - `TestGraphUserByOIDAndUPN`, `TestGraphUnknownUserIs404` (`Request_ResourceNotFound`).
  - `TestGraphUsersPaging` — `$top=1` over 3 users: 3 pages, `nextLink` preserves `$top=1`, last
    page has none, no duplicates or gaps across pages.
  - `TestGraphMemberOfUsesDirectoryObjectsContext`, `TestGraphTransitiveMemberOfMatchesMemberOf`.
  - `TestGraphGroupMembers`, `TestGraphUnknownGroupIs404`.
  - `TestGraphGetMemberObjects` — POST, body `{"securityEnabledOnly":true}` and an empty body both
    return `{"value":[ids]}` ordered like `GroupsOf`.
  - `TestGraphGetMemberGroups` — same shape.
  - `TestGraphManagerAndDirectReports`, `TestGraphPhotoIs404`.
  - `TestGraphUnknownPathIsGraph404` — body is a Graph error, not `routing.NotFound` text.
  - `TestGraphOptionsIs204`.
  - **`TestGraphTenantIsolation`** — a Corp token on `/users`, `/groups`, `/users/{customer oid}`,
    `/groups/{customer group id}`, `/groups/{customer group id}/members` sees only Corp (404 for
    cross-tenant ids, never another tenant's data).
- [ ] **Step 2: failing e2e tests** (`internal/e2e/entra_graph_test.go`, new `entraGraphConfig`
      const with `"graph": {}` and profile fields on `jane`/`sam`)
  - `TestGraphEndToEndMe` — authorize → redeem → `GET /entra/graph/v1.0/me` with the access token.
  - `TestGraphRejectsIDToken` — the `id_token` as a Bearer → 401 (wrong `aud`).
  - **`TestGraphHonorsForwardedHeaders`** — with `x-forwarded-proto/port`, `@odata.context` and
    `@odata.nextLink` carry the forwarded origin, and the token minted under those headers
    validates (and one minted without them does not).
- [ ] **Step 3: run to verify failure**
- [ ] **Step 4: implement** `graph.go` and the `handler.go` branch
- [ ] **Step 5: run** `go test ./internal/entra/ ./internal/e2e/ -v`
- [ ] **Step 6: commit** `feat(entra): read-only Graph account endpoints`

---

### Task 6: OIDC UserInfo

**Files:** create `internal/entra/userinfo.go`, `internal/entra/userinfo_test.go`; modify
`internal/entra/handler.go` (discovery).

`GET|POST /{base}/{graphBase}/oidc/userinfo` per design §5.3. Add `userinfo_endpoint` to discovery
**only** while `UserInfoOn()`, so `TestEntraDiscoveryPerTenant` stays green unmodified.

- [ ] **Step 1: failing tests**
  - `TestUserInfoClaims` — `sub` equals the token's `sub` (pairwise), plus `oid`, `tid`, `name`,
    `preferred_username`, and `given_name`/`family_name`/`email` when set; absent when not.
  - `TestUserInfoPostMatchesGet`, `TestUserInfoNoStore` (`Cache-Control: no-store`).
  - `TestUserInfoAppOnlyIs403` — `insufficient_scope`, RFC 6750 header and matching JSON body.
  - `TestUserInfoInvalidTokenIs401`, `TestUserInfoDisabledUserIs401`.
  - `TestDiscoveryAdvertisesUserInfoOnlyWhenEnabled` — with `"graph":{}` present and with
    `"userinfo":false`.
- [ ] **Step 2: run to verify failure**
- [ ] **Step 3: implement** `userinfo.go`, extend `discovery`
- [ ] **Step 4: run** `go test ./internal/entra/ ./internal/e2e/ -v`
- [ ] **Step 5: commit** `feat(entra): OIDC userinfo endpoint`

---

### Task 7: Close the overage loop; token claim fidelity

**Files:** modify `internal/entra/claims.go`, `internal/entra/token.go`; extend
`internal/entra/claims_test.go` (**add** cases, never edit the existing ones) and the e2e suite.

Per design §6: overage endpoint → self when Graph is on (`overageEndpoint: "microsoft"` restores
today's URL; with Graph off nothing changes, which is what keeps `TestGroupOverageBoundary` green);
`scp` short names with `offline_access` dropped; `azp`/`appid` on the access token;
`given_name`/`family_name`/`roles`/`wids` when configured; `accountEnabled: false` → AADSTS50057.

`TokenInput` gains the fields the overage URL needs (`GraphBase string`, `OverageSelf bool`) — keep
`IDTokenClaims`/`AccessTokenClaims` pure functions of their input.

- [ ] **Step 1: failing tests**
  - `TestOverageEndpointPointsAtSelfWhenGraphOn` / `…AtMicrosoftWhenConfigured` / `…WhenGraphOff`.
  - `TestScpStripsResourcePrefixAndDropsOfflineAccess` — `openid offline_access
    https://graph.microsoft.com/User.Read` → `scp: "openid User.Read"`, response `scope` unchanged.
  - `TestAccessTokenCarriesAzpAndAppid`.
  - `TestGivenFamilyNameRolesWidsOnlyWhenConfigured`.
  - `TestDisabledAccountFailsTokenEndpoint` — AADSTS50057, same as `error: "invalid_grant"`.
  - **e2e `TestGraphResolvesGroupOverage`** — sign in as a user over the group limit, read
    `_claim_sources.src1.endpoint` out of the real ID token, POST it with the issued access token,
    and compare the ids to `/_entra/groups`.
- [ ] **Step 2: run to verify failure**
- [ ] **Step 3: implement**
- [ ] **Step 4: run** `go test ./...` — `TestGroupOverageBoundary`, `TestAccessTokenClaims` and
      every other existing test still pass **unmodified**.
- [ ] **Step 5: commit** `feat(entra): resolve group overage locally and tighten token claims`

---

### Task 8: Account-selection hints

**Files:** modify `internal/entra/authorize.go`, `internal/entra/templates/picker.html.tmpl`,
`internal/entra/config.go` (`ignoreLoginHint`); extend `handler_test.go` and the e2e suite.

Per design §7: `login_hint` resolving exactly one account in scope issues the code without the
picker; `prompt=select_account|login` or `ignoreLoginHint: true` forces the picker; a non-unique or
unknown hint falls back to the picker with the hint pre-filled and any match highlighted;
`domain_hint` narrows `organizations`/`common` by tenant domain; `prompt=none` issues silently when
the hint resolves, else redirects `interaction_required` with AADSTS50058.

The hint matches on UPN, email, or username, case-insensitively. Error injection still applies
**after** the shortcut — a hinted `mfa` user must still produce `interaction_required`.

- [ ] **Step 1: failing tests**
  - `TestLoginHintAutoIssuesCode`, `TestLoginHintAmbiguousShowsPicker`,
    `TestLoginHintUnknownShowsPickerPrefilled`, `TestLoginHintRespectsPromptSelectAccount`,
    `TestIgnoreLoginHintForcesPicker`.
  - `TestLoginHintStillAppliesErrorInjection`.
  - `TestDomainHintNarrowsMultiTenantPicker`.
  - `TestPromptNoneWithoutHintIsInteractionRequired` (AADSTS50058),
    `TestPromptNoneWithHintIssuesCode`.
  - `TestGraphAbsentWhenNotConfigured` *(belongs to this task's suite only for convenience)* — with
    today's config: `/entra/graph/v1.0/me` → `AADSTS90002`, discovery has no `userinfo_endpoint`,
    `client_credentials` → `unsupported_grant_type`, overage endpoint is the Microsoft URL.
- [ ] **Step 2: run to verify failure**
- [ ] **Step 3: implement**
- [ ] **Step 4: run** `go test ./...`
- [ ] **Step 5: commit** `feat(entra): login_hint, domain_hint and prompt handling`

---

### Task 9: App-only tokens (optional, gated by `graph.appOnly`)

**Files:** create `internal/entra/appcreds.go`, `internal/entra/appcreds_test.go`; modify
`internal/entra/token.go`, `internal/entra/config.go` (`apps[]`).

Per design §8. `Config.Apps []App{ClientID, TID, Roles}` supplies `roles`; any client is otherwise
accepted. The grant stays rejected unless `graph.appOnly` is on, which is what keeps
`TestEntraUnsupportedGrantIsEntraError` green.

- [ ] **Step 1: failing tests**
  - `TestClientCredentialsRejectedUnlessEnabled`.
  - `TestAppOnlyTokenClaims` — `tid` from the path, `sub`/`azp`/`appid` = `client_id`, `roles` from
    config, **no** `oid`, **no** `scp`, `aud` = Graph.
  - `TestAppOnlyTokenOnMultiTenantPathIsRejected`.
  - `TestAppOnlyReadsUsersAndGroupsButNotMe` — 200, 200, 403 `Authorization_RequestDenied`.
- [ ] **Step 2: run to verify failure**
- [ ] **Step 3: implement**
- [ ] **Step 4: run** `go test ./...`
- [ ] **Step 5: commit** `feat(entra): app-only client_credentials tokens for Graph reads`

---

### Task 10: Admin UI, test API, demo config, docs

**Files:** modify `internal/entra/admin.go`, `internal/entra/testapi.go`,
`internal/adminui/*.go`, `internal/adminui/static/*`, `entra-demo.json`, `README.md`,
`docs/entra/00-design.md`, `docs/entra/02-graph-design.md` (status), `CLAUDE.md`.

- [ ] **Step 1** Admin UI: the new account fields in the user form (given/surname, UPN,
      accountEnabled, jobTitle, officeLocation, phones, preferredLanguage, roles, wids, manager) and
      tenant group metadata. Mutations keep going through `store.mutate` so `normalize` re-runs.
- [ ] **Step 2** A `graph` settings toggle alongside `entra`, serving 404s while off, and
      `AdminSnapshot` reporting the Graph state.
- [ ] **Step 3** Test API: `GET /_entra/users?tid=` (the directory as Graph sees it) and
      `POST /_entra/mint-token {tid, username, clientId, scope}` → a usable access token, so an RP
      test suite can exercise Graph without driving the picker. Document that it is a test-only
      endpoint, like the rest of `/_entra/`.
- [ ] **Step 4** `entra-demo.json`: enable `"graph": {}`, give the demo users full profiles, a
      manager chain, group metadata, and keep one over-limit user for the overage demo.
- [ ] **Step 5** README: a "Graph account API" section with `curl` examples (sign in → token →
      `/me` → `/me/memberOf` → `getMemberObjects`), the supported query options, and the documented
      divergences. Update `00-design.md` §Non-goals and §3 to point at `02-graph-design.md`, flip
      that doc's status to Implemented, and update the `CLAUDE.md` "Current work" pointer.
- [ ] **Step 6** Full gates: `gofmt -l . | grep -v '^docs/'` empty, `go vet ./...`,
      `go build ./...`, `go test ./...`, **`go test -race ./...`**.
- [ ] **Step 7: commit** `docs(entra): document the Graph account API; wire the admin UI and demo config`

---

## Rollback

Every task is additive and gated. Reverting Task 1's config block alone disables the whole feature;
reverting Task 7 restores today's overage endpoint and `scp`. No existing file is rewritten — only
extended — so a single `git revert` per task is clean.
