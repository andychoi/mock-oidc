# 03 — Configuration reference & migration

Part of the [rewrite plan](00-overview.md). Sources: `StandaloneMockOAuth2Server.kt` (env), `OAuth2Config.kt` (schema + deserializers), `token/OAuth2TokenCallback.kt` (`RequestMappingTokenCallback`). **Goal: this repo's `mock-oidc.json` parses and behaves identically under the Go server.**

## Environment variables (standalone binary)

| Var | Semantics | Default |
|-----|-----------|---------|
| `JSON_CONFIG` | Inline `OAuth2Config` JSON; **takes precedence** over `JSON_CONFIG_PATH` | — |
| `JSON_CONFIG_PATH` | Path to JSON config file (missing file → treated as absent) | `config.json` |
| `SERVER_HOSTNAME` | Bind address | wildcard (`0.0.0.0`) |
| `SERVER_PORT` | Listen port | `8080` |
| `PORT` | Fallback listen port (PaaS convention; `SERVER_PORT` wins) | — |
| `LOG_LEVEL` | Log level (`debug/info/warn/error`) → `slog` level | `info` |
| `LOGBACK_CONFIG` | Accepted and ignored (no logback in Go) | — |

When neither `JSON_CONFIG` nor `JSON_CONFIG_PATH` yields JSON, the standalone binary uses the fallback config `{"interactiveLogin": true}` (Kotlin: `StandaloneConfig.oauth2Config()`).

This repo's compose sets only `JSON_CONFIG_PATH=/config/mock-oidc.json` and maps host port 8088 → container 8080; both stay unchanged.

## `OAuth2Config` JSON schema

Parsed with `encoding/json`; unknown fields ignored (matching Jackson's default leniency).

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `interactiveLogin` | bool | `false` (library) / `true` (standalone fallback) | Show login page on GET `/authorize` |
| `loginPagePath` | string? | — | Absolute/relative path to a custom HTML login page, served as-is |
| `staticAssetsPath` | string? | — | Directory served at `/static/*` |
| `rotateRefreshToken` | bool | `false` | Rotate + invalidate refresh token on each refresh |
| `tokenProvider` | object \| *absent* | see below | Custom deserializer upstream; JSON shape below |
| `tokenCallbacks` | array | `[]` | List of `RequestMappingTokenCallback` objects |
| `httpServer` | string \| object | `"MockWebServerWrapper"` | **Accepted, ignored** in Go (single `net/http` backend); must still parse both shapes |

### `tokenProvider`

```json
{
  "keyProvider": { "initialKeys": "<single JWK JSON string>", "algorithm": "RS256" },
  "systemTime": "2026-01-01T00:00:00Z"
}
```

- `initialKeys`: a **single JWK as a JSON string** (not an array) — first issuer draws this key (rebuilt with `kid = issuerId`). Absent → embedded deterministic initial keys.
- `algorithm`: `RS256/384/512`, `ES256/384` only; anything else → startup error (upstream throws `OAuth2Exception`; ES256K/ES512 unsupported).
- `systemTime`: RFC-3339 instant; freezes `iat/nbf/exp` (deterministic tests) but **not** the `expires_in` response field (wall clock).

### `tokenCallbacks[]` (`RequestMappingTokenCallback`)

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `issuerId` | string | *required* | Must equal the issuer path segment (this repo: `oidc`) — otherwise the mapping never matches and `tid` etc. silently fall back |
| `tokenExpiry` | number (seconds) | `3600` | Token `exp` |
| `typeHeader` | string? | — | JWS `typ` header override |
| `audience` | array? | — | Explicit audience (highest precedence) |
| `requestMappings` | array | `[]` | Match rules, below |

### `requestMappings[]`

| Field | Notes |
|-------|-------|
| `requestParam` | Form parameter to match against: any token-request form field, `grant_type` for grant-based matching, or `subject` for the interactive-login username (injected at auth-code exchange) |
| `match` | Exact string, `"*"`, or a **regex matched against the entire value** (`matchEntire`). Invalid regex → log warning, exact-string matching only (never a startup failure) |
| `claims` | Object merged into the token claims |
| `typeHeader` | JWS `typ` override for this mapping |

Multiple mappings: **first match wins** (checked in array order). Claim values support `${var}` templating: `${clientId}`/`${client_id}` → the request's client_id; `${<formParam>}` → any form parameter value; `${subject}` → login username (auth-code flow). Unresolvable placeholders are left as-is (verify against `extensions/Template.kt` golden tests).

The callback for a token request is: **enqueued library callback (issuerId match) → first `tokenCallbacks` entry whose `issuerId` matches → `DefaultOAuth2TokenCallback`**.

## `DefaultOAuth2TokenCallback` behavior (implicit fallback)

`sub` = random UUID (or login username / grant-specific subject), `aud` resolution per [02 — claims construction](02-endpoints-and-flows.md#claims-construction), `tid` = issuerId always, `azp` = client_id for auth-code, expiry 3600 s, `typ` = `JWT`.

## This repo's config (compat case — must parse unchanged)

```json
{
  "interactiveLogin": true,
  "loginPagePath": "/config/mock-oidc-login.html",
  "httpServer": "NettyWrapper",
  "tokenCallbacks": [
    {
      "issuerId": "oidc",
      "tokenExpiry": 3600,
      "requestMappings": [
        { "requestParam": "grant_type", "match": "authorization_code",
          "claims": { "tid": "mock-tenant-id" } }
      ]
    }
  ]
}
```

Go handling notes:

- `httpServer: "NettyWrapper"` string form parses and is ignored (also accept the object form `{"type": ..., "ssl": {...}}` for schema compatibility, ignoring contents).
- `issuerId: "oidc"` equals the issuer path segment → mapping matches every auth-code token request → `tid=mock-tenant-id` (the `tid` claim here overrides the default `tid=issuerId` because callback `addClaims` are applied after the auto-defaults of the *default* callback; explicit mapping claims win — verify with parity harness).
- `loginPagePath` is absolute inside the container (`/config/...`) — file read at startup; missing file → startup failure with clear error (upstream serves 404 at request time; Go port: fail fast, document deviation) — **decision: keep upstream behavior (404 at request time) to avoid breaking anything that mounts late.**

## Library API configuration (Go)

The Go library (`mockoidc` package) accepts the same `OAuth2Config` struct programmatically plus options: `WithAdditionalRoutes(...)`, `WithSystemTime(time.Time)`, and `EnqueueTokenCallback(callback)` mirroring the Kotlin `MockOAuth2Server` API. The JSON schema above is the serialization of that struct — one source of truth.
