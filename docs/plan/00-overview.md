# 00 — Overview: rewriting mock-oauth2-server in Go

Status: draft plan · 2026-09-25
Companion docs: [01-architecture](01-architecture.md) · [02-endpoints-and-flows](02-endpoints-and-flows.md) · [03-config](03-config.md) · [04-testing](04-testing.md) · [05-delivery](05-delivery.md)

## Goal

Replace the third-party Kotlin server [navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) 6.0.2 with a native Go implementation living in **this repo** (`mock-oidc`), so the shared dev OIDC provider is self-owned, hackable, and free of the JVM/Docker-from-GHCR dependency. After the rewrite, `docker compose up` in this repo runs a Go binary built from source, and every documented connection value in the README keeps working unchanged.

Source of truth for behavior: the Kotlin repo checked out at `~/project/infra-repos/mock-oauth2-server` (tag 6.0.2, master). Paths cited below are relative to that repo; Kotlin package `no.nav.security.mock.oauth2` is abbreviated `…`.

## Scope decision

**Full standalone-server parity** with 6.0.2 — everything the server exposes over HTTP:

- All six grant types: authorization code (+ PKCE plain/S256), client credentials, refresh token (+ optional rotation), password, JWT bearer (RFC 7523), token exchange (RFC 8693, incl. `private_key_jwt` client assertion validation)
- Discovery (`/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`), JWKS, userinfo, introspection, revocation, end session
- Interactive login (built-in page + custom `loginPagePath`), `form_post` response mode, debugger UI (JWE session cookie), CORS, proxy-aware issuer URLs, static assets, self-signed HTTPS / user keystore, 1 MiB body cap
- Same JSON config schema and env vars (`JSON_CONFIG`, `JSON_CONFIG_PATH`, …)

Explicitly **out of scope** (JVM-test-library surfaces with no meaning for a Go server):

- `MockWebServerWrapper` backend and the `takeRequest()`/enqueued-raw-`MockResponse` test conveniences (Go library users get the real server on a random port instead)
- Spring Boot / Ktor example apps and the `minStdlibTest` smoke suite
- Maven Central publishing; HSM support does not exist upstream and is not added

## Compatibility contract (the invariants the rewrite must uphold)

These are the externally observable behaviors that consumer apps (`ai-docs`, `flow-spec`, `signflow`, `ai-dev-platform-feature-aws`) and this repo's README depend on. Each is enforced by tests in [04-testing](04-testing.md).

| # | Invariant | Why it matters here |
|---|-----------|---------------------|
| C1 | **Any first path segment is an issuer.** `/{issuerId}/token` works for any `issuerId`; no registration. | `/oidc` is the canonical and only documented issuer. The legacy `/azuread` path is **removed** — dropped from the README, the compatibility contract, and consumer verification ([05](05-delivery.md)). |
| C2 | **Issuer URL is derived per request** from `Host` + `x-forwarded-proto`/`x-forwarded-port` (default 443/80 by proto), no trailing slash: `scheme://host[:port]/issuerId`. | Served as `http://mock-oidc.dev.test:8088/oidc` regardless of bind address. |
| C3 | **`kid` = issuer path segment**; exactly one signing key per issuer; first N issuers draw deterministic initial keys from an embedded key set (rebuilt with `kid=issuerId`), later issuers get freshly generated keys. | README documents `kid` = `oidc`; deterministic keys keep test fixtures stable. |
| C4 | **Open client registration.** Any client_id/secret accepted, via Basic auth or form body; `aud` resolution ends with client-specific echo (see [02](02-endpoints-and-flows.md#claims-construction)); redirect_uri must match between authorize and token exchange. | README: "client id = app name, secret = `<app>-dev-secret`". |
| C5 | **Token shape.** JWT access token + id_token claims: `sub, aud, iss, iat, nbf, exp, jti` (UUID), `nonce` when present, callback claims applied after defaults; auto-claims `tid = issuerId` always and `azp = client_id` for the auth-code grant (added last, not overridable); id_token `aud = [client_id]`; `expires_in` computed against wall clock even when `systemTime` is frozen; default expiry 3600 s. | Tokens carry only standard OIDC claims + `tid=mock-tenant-id` (via `tokenCallbacks`) + `groups` (from login page claims). |
| C6 | **Error responses**: lowercase RFC-style OAuth error JSON (`{"error": "...", "error_description": "..."}`), 302 statuses coerced to 400, unknown paths → 404, known path wrong method → 405. | Consumers parse errors; parity avoids surprises. |
| C7 | **Config compatibility.** `mock-oidc.json` (current file in repo root) parses unchanged: `interactiveLogin`, `loginPagePath`, `httpServer: "NettyWrapper"` (accepted, ignored), `tokenCallbacks[].requestMappings` with regex/`${var}` matching semantics. Env contract `JSON_CONFIG_PATH`, `SERVER_PORT`/`PORT` (default 8080) preserved. Compose file keeps host port **8088**. | Zero-touch rollout: same volumes, same env, same README values. |
| C8 | **Interactive login page contract.** GET `/authorize` renders the custom login page when `interactiveLogin` is on or `prompt=login\|consent\|select_account`; the page POSTs `username` (+ optional `claims` JSON) back to the same URL; any password accepted; mapping claims win over login claims. | `mock-oidc-login.html` + `demo-users.json` keep working as mounted. |
| C9 | **Refresh semantics.** Opaque refresh token (or unsigned JWT with `jti`+`nonce` when a nonce was present); strict validation — unknown/cross-issuer/revoked → `400 invalid_grant`; optional rotation; revocation only for `token_type_hint=refresh_token`. | Apps doing refresh flows must not silently break. |

## Current state

**This repo** (2 commits, clean tree): `README.md`, `docker-compose.yml` (service `mock-oidc` from `ghcr.io/navikt/mock-oauth2-server:6.0.2`, ports `8088:8080`, read-only mounts of `./mock-oidc.json` and `./mock-oidc-login.html` into `/config`, env `JSON_CONFIG_PATH=/config/mock-oidc.json`, deliberately standalone off the shared docker networks), `mock-oidc.json`, `mock-oidc-login.html` (self-contained quick-pick login page with embedded user directory mirroring `demo-users.json`), `demo-users.json` (11 users). No Go code, no `.gitignore`, no CI.

**Kotlin source**: single Gradle module; HTTP layer is a hand-rolled `OAuth2HttpServer` abstraction (OkHttp MockWebServer for tests, raw Netty for standalone); OAuth2/OIDC protocol handling via `com.nimbusds:oauth2-oidc-sdk`, JWT via nimbus-jose-jwt, templates via FreeMarker, self-signed certs via BouncyCastle. Key entry points: `…/StandaloneMockOAuth2Server.kt` (env + fallback config `{interactiveLogin: true}`), `…/http/OAuth2HttpRequestHandler.kt` (route table + grant dispatch), `…/token/OAuth2TokenProvider.kt` (claims + signing), `…/token/KeyProvider.kt` (per-issuer key model).

## Milestones

Each milestone lands green (tests + parity harness) before the next starts. Detail in [05-delivery](05-delivery.md).

| Milestone | Contents | Exit criteria |
|-----------|----------|---------------|
| M1 — Skeleton | Go module, config loading (env + JSON), HTTP server + suffix routing, discovery, JWKS, client-credentials grant, `/isalive` | Discovery/JWKS byte-compatible with 6.0.2 for same issuer; client-credentials token verifies with `go-oidc` |
| M2 — Interactive flows | Authorization code + PKCE, interactive/custom login, refresh (+ rotation), end session, token callbacks (`requestMappings`) | Full auth-code flow with real RP library against both servers passes identically |
| M3 — Token APIs | Userinfo, CORS interceptor, introspection, revocation, static assets, favicon, body cap, error-shape polish | e2e suites for each endpoint; parity harness green |
| M4 — Remaining grants | Token exchange (RFC 8693 + `private_key_jwt`), JWT bearer, password grant | Ported Kotlin e2e cases pass |
| M5 — Debugger + TLS | Debugger UI (JWE A128GCM session cookie), self-signed HTTPS, user keystore (PKCS12/JKS→PKCS12 note), `systemTime` freeze | Debugger round-trip works; HTTPS serves |
| M6 — Delivery | Multi-stage Dockerfile, compose switch to local build, README refresh, `.gitignore`, parity sign-off | `docker compose up` on host port 8088 serves `http://mock-oidc.dev.test:8088/oidc` with unchanged connection values; consumers re-verified |

## Risks and mitigations

- **Behavioral drift in edge cases** (claim precedence, error wording, PKCE failure invalidating codes) → port the upstream e2e/unit suites (04) and run the side-by-side parity harness through M6.
- **JKS keystore support**: Go stdlib reads PKCS12, not JKS. Plan: support PKCS12 natively; JKS only if `keytool -importkeystore` at startup proves necessary — record as a known deviation otherwise.
- **FreeMarker vs `html/template` differences** in built-in pages: built-in pages are cosmetic (this repo mounts its own login page); parity required for form field names and POST target only.
- **nimbus SDK implicit behaviors** (e.g. exact `error_description` strings, `aud` claim type string-vs-array normalization): captured as golden files in the parity harness rather than prose.
