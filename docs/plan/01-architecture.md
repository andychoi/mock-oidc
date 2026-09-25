# 01 — Go architecture

Part of the [rewrite plan](00-overview.md). Kotlin source paths are relative to `~/project/infra-repos/mock-oauth2-server`; package prefix `no.nav.security.mock.oauth2` abbreviated `…`.

## Shape: library + command

The Kotlin project is two things at once — an embedded JVM test class (`MockOAuth2Server`) and a standalone server (`StandaloneMockOAuth2Server.kt`). The Go port keeps the same split, idiomatically:

- **Root package `mockoidc`** (module `github.com/andychoi/mock-oidc`) — the importable library: `Server` with `Start(addr)`, `Stop()`, `URL()`, `IssuerURL(issuerID)`, `IssueToken(...)`, `EnqueueTokenCallback(...)`, `AnyToken(...)`. Go tests elsewhere embed this exactly like JVM tests embed `MockOAuth2Server`.
- **`cmd/mock-oidc`** — thin main: env-based config (`StandaloneConfig` equivalent), `/isalive` extra route, `slog` setup, signal-based shutdown.

## Package layout

```
mock-oidc/
├── go.mod                        # module github.com/andychoi/mock-oidc, Go ≥ 1.23
├── mockoidc.go                   # library API: Server, options, issue/enqueue helpers
├── cmd/mock-oidc/main.go         # standalone entrypoint (env config, /isalive)
├── internal/
│   ├── config/                   # OAuth2Config: env + JSON parsing, validation
│   ├── httpserver/               # Server bootstrap, TLS, body cap, shutdown
│   ├── routing/                  # suffix matcher, route table, 404/405, interceptors
│   ├── oauth2req/                # OAuth2HttpRequest equivalent: proxy-aware URL,
│   │                             #   form/body parsing, issuerId extraction, grant parse
│   ├── token/                    # KeyProvider, KeyGenerator, TokenProvider, callbacks
│   ├── grant/                    # one file per grant handler + code/refresh caches
│   ├── login/                    # interactive login handling, custom login page
│   ├── userinfo/  introspect/    # small endpoint handlers
│   ├── debugger/                 # debugger UI + JWE session cookie
│   ├── cors/                     # CORS response interceptor
│   └── templates/                # go:embed html/templates (login, debugger, error pages)
├── docs/plan/                    # these documents
├── Dockerfile                    # multi-stage (M6)
├── docker-compose.yml            # switched to local build (M6)
├── mock-oidc.json                # unchanged config (compat guarantee)
├── mock-oidc-login.html          # unchanged login page
└── demo-users.json               # unchanged user directory
```

## Kotlin → Go mapping

| Kotlin (source file under `src/main/kotlin/…/`) | Go package | Notes |
|---|---|---|
| `MockOAuth2Server.kt` | `mockoidc` (root) | facade; `additionalRoutes` → route options |
| `StandaloneMockOAuth2Server.kt` | `cmd/mock-oidc` | env vars, fallback config `{interactiveLogin: true}` |
| `OAuth2Config.kt` | `internal/config` | see [03-config](03-config.md) |
| `http/OAuth2HttpServer.kt`, `NettyWrapper`, `MockWebServerWrapper` | `internal/httpserver` | **collapsed into one backend** (net/http); no MockWebServer equivalent — the library *is* the real server on a random port |
| `http/OAuth2HttpRouter.kt` (Route/Builder, noMatch 404/405) | `internal/routing` | suffix matcher instead of prefix mux |
| `http/OAuth2HttpRequest.kt` (`proxyAwareUrl`, `asTokenExchangeRequest`, …) | `internal/oauth2req` | `HttpUrl` (okhttp) → `net/url.URL` helpers |
| `http/OAuth2HttpRequestHandler.kt` | `internal/routing` (route table) + `internal/grant` (dispatch) | route table in 02 doc |
| `http/OAuth2HttpResponse.kt` (`WellKnown`, `OAuth2TokenResponse`, `json()`, `oauth2Error()`) | response helpers in `internal/routing` | pretty-printed JSON, lowercase errors |
| `http/CorsInterceptor.kt` | `internal/cors` | response interceptor on every route incl. errors |
| `http/Ssl.kt` (+ BouncyCastle cert gen) | `internal/httpserver` + `crypto/x509` | self-signed RSA-2048/SHA256, CN+SAN `localhost`/`127.0.0.1`, 365 d |
| `token/KeyProvider.kt`, `token/KeyGenerator.kt` | `internal/token` | per-issuer key model (below) |
| `token/OAuth2TokenProvider.kt` | `internal/token` | claims builder + sign + verify |
| `token/OAuth2TokenCallback.kt` (`DefaultOAuth2TokenCallback`, `RequestMappingTokenCallback`) | `internal/token` | callbacks as an interface + config-driven impl |
| `grant/*.kt` (6 handlers, `RefreshTokenManager`) | `internal/grant` | one file per grant |
| `login/LoginRequestHandler.kt`, `templates/TemplateMapper.kt` + `.ftl` files | `internal/login`, `internal/templates` | FreeMarker → `html/template` |
| `debugger/*` (`SessionManager` JWE, `Client`, `DebuggerRequestHandler`) | `internal/debugger` | loopback URL only (SSRF-safe by construction, keep 6.0.0 behavior) |
| `userinfo/UserInfo.kt`, `introspect/Introspect.kt` | `internal/userinfo`, `internal/introspect` | |
| `extensions/*.kt` (`HttpUrlExtensions`, `NimbusExtensions`, `Template`) | spread into `internal/oauth2req` / `internal/token` | `endsWith`-routing, issuerId, `${var}` templating |

## Library choices

| Concern | Choice | Rationale / replaces |
|---|---|---|
| HTTP server | **stdlib `net/http`** | Replaces Netty *and* MockWebServer. Suffix-based routing means `ServeMux` patterns don't fit directly — implement a small ordered-route table (method + suffix predicate) in `internal/routing`; `ServeMux` still useful for exact routes (`/isalive`, `/favicon.ico`). |
| TLS | `crypto/tls` + `crypto/x509` | Replaces Netty SslHandler + BouncyCastle cert generation. |
| JWT/JWS/JWK | **`github.com/go-jose/go-jose/v4`** | RSA (`RS*`) and EC (`ES*`) sign/verify, JWK(JWKSet) parse/serialize, key generation. Replaces nimbus-jose-jwt. Claims construction/validation is hand-rolled maps (nimbus `JWTClaimsSet` semantics are simple enough — see 02). |
| OAuth2 protocol parsing | **hand-rolled** in `internal/oauth2req` | nimbus `oauth2-oidc-sdk` does request parsing, PKCE, token-exchange types, `ErrorObject`s upstream. In Go these are form-parameter handling + explicit checks; porting them explicitly is clearer than adopting `coreos/go-osin`-style deps. `go-oidc/v3` remains **test-only** as the independent RP. |
| HTML | `html/template` + `go:embed` | Replaces FreeMarker; only built-in pages (custom login pages are user-supplied HTML served as-is). |
| JSON | `encoding/json` | Replaces Jackson 3. Note: upstream responses are **pretty-printed** (`writerWithDefaultPrettyPrinter`) — keep `json.MarshalIndent` for parity where the Kotlin code used `json()` on objects. |
| Logging | `log/slog` | Replaces kotlin-logging/logback; `LOG_LEVEL` env maps to slog level. `LOGBACK_CONFIG` accepted and ignored. |
| Cookies/JWE session | `crypto/aes` (GCM) for debugger session | Upstream uses nimbus JWE `DIR` + `A128GCM` — same primitive, hand-rolled envelope with the same cookie name `debugger-session`. |

No framework (gin/chi/echo): the server is ~15 routes with unusual suffix semantics; stdlib keeps the dependency surface minimal.

## Core designs

### Routing (suffix-based, multi-issuer)

Upstream matches any URL whose path **ends with** the route path (`HttpUrlExtensions.endsWith`), and derives `issuerId()` by stripping the known endpoint suffix and taking the remaining path (root → empty issuerId, which upstream treats as the issuer path `/`… concretely `http://h/token` works with issuer URL `http://h`). Go equivalent:

- `Route{Method, Suffix, Handler}` slice in registration order; a request matches the first route whose method equals (or `ANY`) and whose path ends with the suffix (`/issuer-a/token` ends with `/token`).
- Known endpoint suffixes enumerated once (`/authorize`, `/token`, `/jwks`, `/endsession`, `/revoke`, `/userinfo`, `/introspect`, `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`, `/debugger`, `/debugger/callback`); `issuerId(r)` strips the matched suffix and the leading `/`; remainder is the issuerId (may be `""`).
- No route matched → 404 `no page found at ...`; path matched but method not → 405 (upstream `noMatch` in `OAuth2HttpRouter.kt`).
- Additional routes (library API, `/isalive`) are prepended and win.
- Request body capped at **1 MiB** → 413 (upstream Netty pipeline), enforced by `http.MaxBytesReader` before form parsing.

### Proxy-aware issuer URL

`issuerURL(r *http.Request, issuerID)`:
1. `scheme` = `x-forwarded-proto` header if present else `http` (or `https` when the connection is TLS).
2. `host:port` = `Host` header; if `x-forwarded-port` present, replace/append that port; default port elided by scheme (80/443).
3. Result: `scheme://host[:port]` + `/` + issuerID (issuerID may be empty → no trailing slash).

### Key provider (per-issuer, deterministic first keys)

Port of `token/KeyProvider.kt`:

- Embedded `mock-oauth2-server-keys.json` (the 5 RSA initial keys, copied from upstream resources; EC variant `mock-oauth2-server-keys-ec.json` for ES* configs) via `go:embed`.
- `signingKeys sync.Map[issuerID]jwk.SignKey` — `computeIfAbsent` equivalent via `LoadOrStore` with pre-computed value (avoid double-generation with a per-key `singleflight` or double-checked mutex).
- Key material for a new issuerID: pop from the initial-keys deque → rebuild the JWK with `kid = issuerID` (go-jose: reconstruct `jwk.Key` and set KeyID); deque empty → generate fresh (RSA ≥ 2048 or EC P-256/P-384 per algorithm family).
- `publicJWKSet(issuerID)` = JWKSet containing exactly the one public key (confirmed: `JWKSet(keyProvider.signingKey(issuerId)).toPublicJWKSet()`).
- Supported algorithms: `RS256/384/512`, `ES256/384` (`ES256K`/`ES512` rejected, matching `KeyGenerator`); default `RS256`; unsupported → config-time error.

### Token provider

Port of `token/OAuth2TokenProvider.kt`: claims builder producing `sub, aud, iss, iat, nbf, exp, jti` (+`nonce`), then callback `addClaims` applied **on top** (so callbacks may override), then sign with the issuer key (`typ` header from callback, default `JWT`; `kid` = issuerID). `systemTime` (config) freezes iat/nbf/exp for deterministic tests but **not** `expires_in` in the token response (wall clock — upstream `NimbusExtensions.kt:81`). Verification: parse → check `typ=JWT` → verify signature against issuer's public key → require exact issuer match + `exp` (and `iat` when present), evaluated at `systemTime` when set.

### Concurrency

Upstream relies on `ConcurrentHashMap` for signing keys, auth-code cache, login cache, refresh-token cache, and a `synchronized` peek/poll on the callback queue. Go:

- Key cache: `sync.Map` (above).
- Auth-code and login caches (`grant/AuthorizationCodeHandler.kt`): `sync.Map`; codes are single-use (delete on exchange; PKCE failure also deletes the login entry — keep this).
- Refresh store (`grant/RefreshTokenManager.kt`): `sync.Map[token]callback`.
- Callback queue (library API only): `chan` guarded so peek-by-issuer-poll works — implement as mutex + slice to mirror peek/poll-with-issuer-check semantics exactly.
- net/http spawns a goroutine per request; no shared mutable state beyond the maps above.

### Error handling

One `oauth2Error(w, err)` helper mirroring upstream: `{"error": <code>, "error_description": <msg>}` with lowercased JSON keys, status from the error object (302 coerced to 400). `OAuth2Exception` → typed `*oauth2.Error{Code, Description, Status}` in Go; parse failures → `invalid_request`; everything else → `server_error` with URL-encoded message. The exception handler wraps the whole route table (incl. interceptor re-run on error responses, failures swallowed) — same in Go via deferred recovery in the top handler.

## Deviations from upstream (accepted, to document in code)

1. One HTTP backend only (`net/http`); `httpServer` config field parsed but ignored.
2. JKS keystores not supported for TLS (PKCS12 only); upstream supports both.
3. Built-in FreeMarker pages re-rendered with `html/template` — cosmetic differences allowed; form contract (field names, POST target) must match.
4. `takeRequest()`/enqueued raw responses dropped (JVM test conveniences).
5. Java `KeyStore`-based `initialKeys` semantics identical (JWK JSON string), but only PKCS8/JWK inputs accepted.
