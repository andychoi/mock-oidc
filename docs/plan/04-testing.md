# 04 — Testing & parity strategy

Part of the [rewrite plan](00-overview.md). Principle: **port the upstream test intent, verify against upstream behavior.** Kotlin suites live in `src/test/kotlin/no/nav/security/mock/oauth2/` (cited per section).

## Layers

1. **Unit tests** per `internal/` package (fast, table-driven).
2. **E2E tests** against a real `mockoidc.Server` on `127.0.0.1:0` (random port) — plain `net/http` client, no framework. This replaces both upstream's e2e suite and its MockWebServer-based tests (the Go library *is* the real server).
3. **Independent RP verification** with `github.com/coreos/go-oidc/v3` (+ `golang.org/x/oauth2`) — a real relying party performing discovery, auth-code, ID-token validation, userinfo. This is the closest analog of upstream's Spring Boot/Ktor example-app tests and catches protocol drift no hand-rolled client would.
4. **Parity harness** (`test/parity/`, go:build tag `parity`): runs the same scripted requests against the 6.0.2 container and the Go server, diffs normalized responses.

## Unit test ports

| Upstream suite | Go target | Coverage |
|---|---|---|
| `OAuth2ConfigTest` | `internal/config` | JSON → config (both `httpServer` shapes, tokenCallbacks, algorithms incl. unsupported → error, systemTime), env precedence `JSON_CONFIG` > `JSON_CONFIG_PATH` > fallback `{interactiveLogin:true}`, missing file tolerance. Include this repo's `mock-oidc.json` as a fixture that must parse. |
| `token/KeyProviderTest`, `KeyGeneratorTest` | `internal/token` | initial-key reuse per issuer, `kid=issuerId` rebuild, fresh generation after deque exhausted, RSA≥2048 / EC P-256/P-384, unsupported algorithm rejection |
| `token/OAuth2TokenProviderTest` | `internal/token` | claims construction (sub/aud/iss/iat/nbf/exp/jti/nonce), callback-claims-override, `systemTime` freeze, sign/verify round-trip RSA + ES256, wrong algorithm config → error, `expiresIn` from wall clock |
| `token/OAuth2TokenCallbackTest` (638 lines) | `internal/token` | **port as table-driven cases**: exact/`*`/regex matching, invalid-regex fallback to exact, `${clientId}`/`${client_id}`/form-param/`${subject}` templating, first-match-wins, audience precedence (explicit > request param > non-OIDC scopes > `default`), tid/azp auto-claims |
| `grant/AuthorizationCodeHandlerTest`, `RefreshTokenManagerTest` | `internal/grant` | one-time codes, login-claims `putIfAbsent` merge, PKCE invalidation of login entry, refresh store/rotation/cross-issuer |
| `http/*Test` (router, request parsing) | `internal/routing`, `internal/oauth2req` | suffix matching order, 404 vs 405, proxy-aware URL (`x-forwarded-proto/port`, Host), issuerId extraction (incl. root issuer), 1 MiB cap |
| `login/LoginRequestHandlerTest` | `internal/login` | custom page served as-is, missing file, built-in template form contract |
| `debugger/DebuggerRequestHandlerTest` | `internal/debugger` | session cookie round-trip, loopback-only targeting |

## E2E scenarios (port of `e2e/` suite)

- **Well-known**: both endpoints; full field set for an issuer under a path prefix and at root.
- **Auth-code flow**: GET authorize (immediate 302 with code+state) → token exchange; nonce propagation into id_token and access_token; `aud=[client_id]` on id_token; scope echo.
- **Interactive login**: login page on GET when `interactiveLogin` or `prompt=login|consent|select_account`; POST username → `sub`=username; login `claims` JSON merged (mapping claims win); invalid claims JSON tolerated; `requestParam=subject` matching against login username; custom `loginPagePath` page used verbatim; this repo's `mock-oidc-login.html` + `demo-users.json` exercised end-to-end (mount fixture).
- **PKCE**: `plain` and `S256` success; wrong verifier → error **and** code/login unusable afterward.
- **Code reuse** → `invalid_grant` "unknown or already-used authorization code".
- **Refresh**: subject continuity across refresh; rotation on/off; enqueued-callback override (library API); bogus token → 400; cross-issuer refresh → 400; nonce-bearing refresh token (unsigned JWT) shape.
- **Token exchange**: happy path; `client_assertion` audience variants (issuer URL / token endpoint URL / multiple audiences → fail); expired (>120 s) assertion → fail; invalid `assertion_type`.
- **JWT bearer & password grants**: claim carry-over; `sub`=username; mapping on `subject`.
- **Userinfo**: valid Bearer → claims; wrong key/issuer/expired → 401 `invalid_token`.
- **Introspection**: missing auth header → `invalid_client`; valid → `active:true` + claims; garbage → `active:false`.
- **Revocation**: refresh-token removal then refresh fails; wrong hint → `unsupported_token_type`; unknown token → 200.
- **End session**: with/without `post_logout_redirect_uri`, `state` append.
- **CORS**: origin reflection + credentials on success and error responses; OPTIONS preflight headers.
- **Static assets**: served file, content type, traversal attempt (`/static/../mock-oidc.json`) → 404.
- **Errors**: GET /token → 405; unknown path → 404; unknown grant_type → `invalid_grant` "grant_type <v> not supported."; body > 1 MiB → 413.
- **Multi-issuer**: two issuers on one server (e.g. `/oidc` and `/other`) get distinct `kid`s and both verify. `/azuread` is retired and must not appear in docs, fixtures, or tests.
- **`/isalive`** (standalone build only) and `/favicon.ico`.

## Golden files (parity-critical exactness)

Stored under `testdata/golden/`, regenerated from 6.0.2 via the harness, asserted byte-for-byte (modulo timestamps) in CI:

- discovery JSON for a fixed issuer
- JWKS JSON for deterministic initial keys (`kid` fixed by issuerId)
- error JSON bodies for the canonical errors in [02](02-endpoints-and-flows.md#error-responses)
- token-response JSON key set/order (pretty-printed form), id_token/access_token claim sets with frozen `systemTime`

## Parity harness (`test/parity/`)

- Docker (`testcontainers` or plain `docker run`) starts `ghcr.io/navikt/mock-oauth2-server:6.0.2` on a random port.
- Scripted flows (discovery, jwks, client-credentials, auth-code with `systemTime` frozen via config, refresh, introspect, error cases) run against both servers; responses normalized (mask ports/timestamps/jti) and diffed.
- Exit non-zero on diff; `--update-golden` regenerates.
- Run locally through M6; CI runs unit + e2e + golden; parity harness runs on demand (needs Docker).

## Independent RP test (`test/rp/`)

`go-oidc/v3` provider bootstrap from the Go server's discovery → full authorization-code login (programmatically driven: parse login form, POST username) → ID token verification (signature via JWKS, iss/aud/at_hash where applicable) → userinfo fetch. Run the same test against 6.0.2 once to confirm the test itself is server-agnostic.

## What is deliberately not ported

- MockWebServer-specific tests (backend doesn't exist) — covered by e2e on the real server.
- Spring Boot / Ktor example apps — replaced by the `go-oidc` RP test.
- `minStdlibTest` (JVM concern).
