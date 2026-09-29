# Entra Mode — Design

| | |
|---|---|
| Status | Implemented (2026-09-26). Plan: [`01-plan.md`](01-plan.md) |
| Origin | IAM project (`../iam`): ADR-0007 and `docs/idea/01-mock-oidc-entra-mode.md`. There is no Microsoft Entra ID test tenant, so this mock *is* the Entra test environment for the IAM's Entra connector |
| Hard constraint | **Opt-in and additive.** With no Entra config, the server behaves byte-for-byte as today (navikt 6.0.2 contract C1–C9 in [`../plan/00-overview.md`](../plan/00-overview.md)); all existing tests stay green unchanged |
| Dependencies | **None new.** stdlib + existing internal packages |

## 1. Goal

Emulate enough of Microsoft Entra ID (v2.0 endpoints) that an OIDC relying party can be tested
end-to-end against **several Entra tenants**, including:

- tenant-specific sign-in (`/{tid}/…`) and the **multi-tenant "Sign in with Microsoft"** flow
  (`/organizations/…`, `/common/…`) whose discovery `issuer` is the template `…/{tenantid}/v2.0`;
- **one signing key set shared by all tenants**, with rotation;
- Entra v2.0 **ID token claims** (`tid`, `oid`, pairwise `sub`, `ver`, `preferred_username`, optional
  `email`, `xms_edov`, `amr`);
- **group claims** as display names or object IDs, and **group overage**;
- **admin consent** and the **consent-missing** error;
- **error injection** per user (MFA/Conditional Access required, not assigned, disabled).

### Non-goals

Real Conditional Access evaluation; Microsoft's UI and exact error wording; app registrations
(any `client_id`/secret is accepted, as in the rest of mock-oidc); refresh-token redemption; implicit
and hybrid flows (`response_type` other than `code`); `form_post`/`fragment` response modes; tenant
lookup by domain name in the path; Microsoft Graph (`userinfo`, `getMemberObjects`); SAML/WS-Fed.

## 2. Architecture

```
internal/entra/            (new package; imports oauth2, routing, jsonx, token — never config/server)
├── config.go      Config/Tenant/User/Consent types, ParseConfig (normalize + validate), lookups
├── uuid.go        UUIDv5 (deterministic oid / group object IDs)
├── keys.go        KeySet: shared RS256 keys, Rotate, Sign, JWKS
├── claims.go      Issuer, PairwiseSub, IDTokenClaims, AccessTokenClaims, group/overage rules
├── consent.go     ConsentStore (seeded from config, in memory)
├── handler.go     Handler, New, RoutePattern, Handle (dispatch), discovery, keys, logout
├── authorize.go   account picker (GET), sign-in submit (POST), code store, error redirects
├── token.go       token endpoint (authorization_code only)
├── adminconsent.go admin consent page + submit
├── testapi.go     /_entra/* helper endpoints for tests
└── templates/picker.html.tmpl

internal/token/sign.go      (new) exported GenerateSigningKey, SignJWT, PublicJWKSOf
internal/config/config.go   (modify) "entra" JSON key + ENTRA_CONFIG_PATH → OAuth2Config.Entra
internal/server/server.go   (modify) mount entra.Handler as a front route when configured
internal/e2e/entra_test.go  (new) end-to-end suite
entra-demo.json, README.md, docker-compose.yml (modify/add) documentation and local wiring
```

### Why one front route

`internal/routing` matches routes by **path suffix**: `/entra/{tid}/oauth2/v2.0/token` ends in
`/token` and would otherwise hit the built-in token handler. Entra mode therefore registers a single
route with `AddFront("", "/{basePath}/*", handler.Handle)`. The router treats a `*` path as a
full-path regex, so this route matches only paths under `/{basePath}/` and is evaluated before every
built-in route. `Handle` parses the path segments itself. When Entra mode is off, the route isn't
registered, so nothing changes.

The CORS response interceptor still applies (interceptors run for every matched route). `Handle`
answers `OPTIONS` with 204 itself, because the front route also catches preflight requests under
`/{basePath}/`.

### Keys

Real Entra signs every tenant's tokens with one key set published at
`/{tenant}/discovery/v2.0/keys` (same keys for every tenant, including `common`). The built-in
`token.KeyProvider` is one-key-per-issuer (`kid = issuerId`), so Entra mode keeps its **own**
`KeySet`: RS256 keys with `kid` `entra-1`, `entra-2`, …; the newest signs; `Rotate` adds a key and
keeps at most one previous key published. To avoid duplicating crypto code, `internal/token` exports
three helpers extracted from existing code (output of existing endpoints stays byte-identical):

| Export | Extracted from | Used by |
|---|---|---|
| `GenerateSigningKey(kid, alg string) (*SigningKey, error)` | `generateKey` | `entra.KeySet.Rotate` |
| `SignJWT(key *SigningKey, claims map[string]any, typ string) string` | body of `TokenProvider.sign` | `TokenProvider.sign`, `entra.KeySet.Sign` |
| `PublicJWKSOf(keys ...*SigningKey) string` | body of `KeyProvider.PublicJWKS` | `KeyProvider.PublicJWKS`, `entra.KeySet.JWKS` |

## 3. Endpoints

All paths are under `{origin}/{basePath}` (default `basePath` = `entra`). `{origin}` is the
proxy-aware `scheme://host[:port]` from `oauth2.Request.ProxyAwareURL()`, the same derivation the
built-in issuer uses, so `mock-oidc.dev.test:8088` and `x-forwarded-*` work. `{t}` is a tenant GUID
(case-insensitive, normalized to lowercase), `organizations`, or `common`.

| Method | Path | Behavior |
|---|---|---|
| GET | `/{t}/v2.0/.well-known/openid-configuration` | Discovery (§3.1) |
| GET | `/{t}/discovery/v2.0/keys` | Shared JWKS (all current keys) |
| GET | `/{t}/oauth2/v2.0/authorize` | Account picker (§3.2) |
| POST | `/{t}/oauth2/v2.0/authorize` | Sign-in submit (form: `tid`, `username`) → 302 with `code` or `error` |
| POST | `/{t}/oauth2/v2.0/token` | `authorization_code` grant only (§3.3) |
| GET | `/{t}/oauth2/v2.0/logout` | 302 to `post_logout_redirect_uri` (+`state`), else a "signed out" page |
| GET | `/{t}/v2.0/adminconsent` | Admin consent page (`client_id`, `redirect_uri` required; `state`, `scope` echoed) |
| POST | `/{t}/v2.0/adminconsent` | form `action=accept` (+`tid`, `username`) or `action=cancel` (§3.4) |
| OPTIONS | any | 204 |
| GET | `/_entra/consents` | Test API: granted consents |
| POST | `/_entra/reset` | Test API: consents back to the configured seed |
| POST | `/_entra/rotate-keys` | Test API: add a signing key → `{"kid": "entra-N"}` |
| GET | `/_entra/groups?tid=` | Test API: `{group name: object ID}` for that tenant's users' groups |

Unknown `{t}` (not a configured GUID and not `organizations`/`common`) → 400
`invalid_request` "AADSTS90002: Tenant '{t}' not found." Unknown sub-paths → 404.

### 3.1 Discovery

| Field | Tenant `{tid}` | `organizations` / `common` |
|---|---|---|
| `issuer` | `{origin}/{base}/{tid}/v2.0` | `{origin}/{base}/{tenantid}/v2.0` (**literal** `{tenantid}`) |
| `authorization_endpoint`, `token_endpoint`, `end_session_endpoint`, `jwks_uri` | under `/{base}/{tid}/…` | under `/{base}/{organizations\|common}/…` |

Also: `response_types_supported` `["code","id_token","code id_token","id_token token"]`,
`response_modes_supported` `["query","fragment","form_post"]` (mimics Entra; only `query` is
accepted, see §3.2), `subject_types_supported` `["pairwise"]`,
`id_token_signing_alg_values_supported` `["RS256"]`, `scopes_supported`,
`token_endpoint_auth_methods_supported`, `claims_supported`, `request_uri_parameter_supported`
`false`, `tenant_region_scope` `"NA"`, `cloud_instance_name` `"microsoftonline.com"`. No
`userinfo_endpoint` (it would point at real Graph).

### 3.2 Authorize

- Query is parsed with `oauth2.ParseAuthRequest` (same required parameters as the built-in server).
  Only `response_type=code` is supported; anything else → error redirect `unsupported_response_type`.
  Only `response_mode=query` (or omitted) is accepted — codes always ride the redirect query — and
  any other value → 400 `invalid_request`, because a `form_post` client could not receive a GET
  error redirect either.
- **GET** renders the account picker: the tenant's users for `/{tid}`, or all users grouped by
  tenant for `organizations`/`common`. Each account is a form posting `tid` + `username` back to
  the same URL (query preserved). No password.
- **POST** checks, in order:

| # | Check | Result |
|---|---|---|
| 1 | Posted user exists in the posted `tid` | else 400 `invalid_request` "AADSTS50034: The user account does not exist in this directory." |
| 2 | For a `/{tid}` route, posted `tid` equals the route tenant | else 400 `invalid_request` "AADSTS50020: …" |
| 3 | User `error` = `interaction_required` | redirect `error=interaction_required` "AADSTS50076: …" |
| 4 | User `error` = `access_denied` | redirect `error=access_denied` "AADSTS50105: …" |
| 5 | Tenant `consentRequired` and no consent for `(client_id, tid)` | redirect `error=consent_required` "AADSTS65001: …" |
| 6 | OK | new single-use code (10-minute TTL) → redirect `code` (+`state`) |

Error redirects carry `error`, `error_description`, and `state`. (Real Entra shows some of these as
an error page instead of redirecting; redirecting is a deliberate simplification so RPs can test
their error handling.)

### 3.3 Token

`grant_type` must be `authorization_code` (else 400 `unsupported_grant_type` "AADSTS70003: …").
Parsed with `oauth2.ParseTokenRequest`; any client secret is accepted. Checks, all → 400
`invalid_grant`:

| Check | Description |
|---|---|
| Code unknown, used, or expired | "AADSTS70008: The provided authorization code or refresh token has expired or was already used." |
| Redeemed on a different tenant path | allowed only on the path it was issued on, or on the user's own `tid` path |
| `client_id` differs from the authorize request | "client_id does not match the authorization request" |
| `redirect_uri` differs from the authorize request | "redirect_uri does not match the authorization request" |
| PKCE: `code_challenge` was sent and `code_verifier` is missing or wrong (`S256` or `plain`) | "AADSTS501481: The Code_Verifier does not match the code_challenge supplied in the authorization request." |
| User `error` = `invalid_grant` | "AADSTS50057: The user account is disabled." |

Response (JSON, field order): `token_type` `Bearer`, `scope`, `expires_in`, `ext_expires_in`,
`access_token`, `refresh_token` (only if `offline_access` was requested; opaque, not redeemable),
`id_token`.

### 3.4 Admin consent

- `accept`: user must exist in the scope (as in §3.2 checks 1–2) and have `admin: true`, else
  redirect `error=access_denied` "AADSTS90094: …". On success, the consent `(client_id, user tid)`
  is granted and the redirect carries `admin_consent=True&tenant={tid}&state=…` (+`scope` if sent).
- `cancel`: redirect `error=access_denied` "AADSTS65004: User declined to consent to access the app."

## 4. Tokens

### 4.1 ID token claims

| Claim | Value |
|---|---|
| `iss` | `{origin}/{base}/{tid}/v2.0`: **always the user's tenant**, also for `organizations`/`common` |
| `aud` | `client_id` |
| `iat`, `nbf`, `exp` | now, now, now + `tokenExpiry` |
| `tid` | user's tenant GUID (lowercase) |
| `oid` | configured, else `UUIDv5(oidNamespace, tid + ":" + username)` |
| `sub` | pairwise: base64url(SHA-256(`client_id` + ":" + `oid`)), 43 chars; stable per client, differs across clients |
| `ver` | `"2.0"` |
| `name` | user `name` (default: username) |
| `preferred_username` | user `email`, else `username@{first tenant domain}`, else username |
| `nonce` | if sent at authorize |
| `email` | only if the user has an email **and** scope contains `email` |
| `xms_edov` | only if the user sets `emailVerified` (true/false) |
| `amr` | only if the user sets `amr` |
| `groups` | see §4.2 |
| `uti` | random |

Header: `{"kid":"entra-N","typ":"JWT","alg":"RS256"}`.

### 4.2 Groups and overage

- No `groups` claim if the user has no groups.
- If the number of groups is **at most** the tenant's `groupLimit` (default `defaultGroupLimit`, default
  200): `groups` = names (`groupClaimFormat: "name"`, default) or object IDs
  (`"object_id"`: `UUIDv5(groupNamespace, tid + ":" + name)`, stable).
- Above the limit: no `groups`; instead
  `"_claim_names": {"groups": "src1"}` and
  `"_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/v1.0/users/{oid}/getMemberObjects"}}`.

### 4.3 Access token

Same identity claims minus `nonce`, with `aud` = `00000003-0000-0000-c000-000000000000` (Microsoft
Graph) and `scp` = requested scopes joined by spaces. RPs must not validate it, and that is the point.

## 5. Configuration

Enabled by either an `"entra"` object inside the main JSON config (`JSON_CONFIG`/`JSON_CONFIG_PATH`,
library `config.ParseJSON`) or `ENTRA_CONFIG_PATH` pointing at a separate file (wins if both). Unknown
fields are rejected, so typos fail loudly at startup.

```json
{
  "basePath": "entra",
  "defaultGroupLimit": 200,
  "tokenExpiry": 3600,
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
    { "username": "blocked", "tid": "22222222-2222-2222-2222-222222222222", "error": "interaction_required" }
  ]
}
```

Validation (startup error): at least one tenant; `tid` is a GUID and unique; `basePath` matches
`^[A-Za-z0-9_-]+$` after trimming slashes; `groupClaimFormat` ∈ `name|object_id`; consent `clientId`
non-empty and `tid` configured; user `username` non-empty, unique per tenant, `tid` configured;
`error` ∈ `interaction_required|access_denied|invalid_grant`.

### 5.1 Runtime mutation (admin UI)

The parsed config seeds a copy-on-write store (`internal/entra/store.go`): every request reads one
immutable snapshot (atomic load), admin mutations deep-copy, re-normalize (the same validation as
startup, same error messages) and publish. Runtime edits are **in-memory only** — a restart returns
to the config file, and the admin API's `POST /admin/api/entra/reset` restores the seed.

Rules beyond startup validation: `tid` and `username` are immutable after create (rename =
delete + create); deleting a tenant cascades its users and consents; the last tenant cannot be
deleted; revoking a seeded consent removes it until the next reset (documented in the UI).

Entra mode can also be toggled off at runtime (`POST /admin/api/settings {"name":"entra"}`). The
route stays mounted (the router cannot un-register), but while disabled every `/{basePath}/...`
request answers like an unrouted path: OPTIONS 204, anything else 405. **Deliberate divergence**:
a server without Entra config would let e.g. `/{basePath}/{tid}/oauth2/v2.0/token` fall through
to the navikt `/token` suffix route; the disabled gate returns 405 instead — safer, and
"toggled off" is its own documented state, not "never configured".

## 6. Decisions

| Decision | Why |
|---|---|
| Separate `internal/entra` package, single front route | Zero interaction with the navikt-compatible handlers; easy to reason about compatibility |
| Own key set, shared across tenants | Mirrors Entra; the per-issuer `KeyProvider` can't express it |
| Deterministic `oid` and group object IDs (UUIDv5) | Stable fixtures across restarts and machines; RP tests can hard-code expected values |
| Error redirects instead of error pages | RPs can assert their error handling automatically |
| No refresh-token grant | The IAM never refreshes upstream Entra tokens; keeps scope small |
| Test API under `/_entra/` | Lets e2e suites reset state and rotate keys without restarting the container |

## 7. What still needs real Entra

Real Conditional Access, Microsoft's UI, and the exact claim output of a real tenant (for example,
whether a v2.0 ID token includes `amr`). The IAM covers these with a pre-launch smoke test; any
difference found there should become a new fixture or behavior here.
