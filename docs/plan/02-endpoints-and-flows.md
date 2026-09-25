# 02 — Endpoints & flows (behavioral spec)

Part of the [rewrite plan](00-overview.md). This is the normative spec the Go implementation must satisfy; each section cites the Kotlin source (`~/project/infra-repos/mock-oauth2-server`, package prefix `…` abbreviated). Where wording is uncertain, the parity harness ([04-testing](04-testing.md)) captures golden output from 6.0.2 and *that* is normative.

## Routing model

Routes match any URL whose path **ends with** the route suffix (`HttpUrlExtensions.endsWith`), registered and evaluated in order; additional routes (library API, `/isalive`) are prepended and win. The first path segment(s) before the matched suffix is the **issuerId** (empty allowed → issuer URL has no path). Source: `http/OAuth2HttpRouter.kt`, `extensions/HttpUrlExtensions.kt`.

- No suffix matches → **404**; a suffix matches but method doesn't → **405**.
- Request bodies larger than **1 MiB** → 413 (Netty pipeline upstream).
- `OPTIONS` on any path → **204** no body (pre-flight, after CORS interceptor adds headers).

## Route table

Source: `http/OAuth2HttpRequestHandler.kt` (route assembly, lines 92–108), `userinfo/UserInfo.kt`, `introspect/Introspect.kt`, `debugger/*`.

| Method | Suffix | Handler |
|--------|--------|---------|
| GET | `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` | discovery metadata |
| GET | `/jwks` | issuer JWKS (exactly one public key) |
| GET | `/authorize` | login page or code redirect (below) |
| POST | `/authorize` | login submit → code redirect |
| GET | `/token` | **405** `unsupported method` (text body) |
| POST | `/token` | grant dispatch |
| ANY | `/endsession` | logout redirect |
| POST | `/revoke` | refresh-token revocation |
| GET | `/userinfo` | claims from Bearer token |
| POST | `/introspect` | token introspection |
| GET/POST | `/debugger` | debugger form / start flow |
| ANY | `/debugger/callback` | debugger code exchange + render |
| GET | `/static/*` | static files (only when `staticAssetsPath` configured) |
| OPTIONS | any | 204 |
| GET | `/favicon.ico` | **200** empty body |
| GET | `/isalive` | 200 `alive and well` (standalone only) |

All JSON responses are **pretty-printed** with `Content-Type: application/json;charset=UTF-8` (upstream `json()` uses `writerWithDefaultPrettyPrinter`).

## Error responses

`http/OAuth2HttpResponse.kt → oauth2Error`: body is OAuth error JSON with **lowercase** keys, e.g.

```json
{ "error" : "invalid_grant", "error_description" : "unknown or already-used authorization code" }
```

- Status comes from the error object; **302 is coerced to 400**.
- Mapping: `OAuth2Exception` → its error object; nimbus `ParseException` → `invalid_request` ("failed to parse request: …"); anything else → `server_error` ("unexpected exception with message: …", message URL-encoded).
- Canonical messages to preserve (sources: `OAuth2Exception.kt`, handlers):
  - unknown/already-used authorization code → `invalid_grant` "unknown or already-used authorization code"
  - non-code response_type at `/authorize` → `invalid_grant` "hybrid og implicit flow not supported (yet)."
  - unknown grant_type → `invalid_grant` "grant_type <value> not supported."
  - missing required parameter → `invalid_request` "missing required parameter <name>"
  - wrong `token_type_hint` at `/revoke` → 400 `unsupported_token_type` "unsupported token type: <hint>"
  - CORS applies to error responses too.

## Issuer URL derivation (per request)

`extensions/HttpUrlExtensions.kt` (`proxyAwareUrl`): `scheme` from `x-forwarded-proto` (else request scheme), host from `Host` header, port from `x-forwarded-port` when present (default elided 80/443 by scheme). Issuer = `scheme://host[:port]/<issuerId>` **without trailing slash**; empty issuerId → `scheme://host[:port]`. This is how `http://mock-oidc.dev.test:8088/oidc` is served from a container bound as `0.0.0.0:8080`.

## Discovery

`http/OAuth2HttpResponse.kt → WellKnown` (verified field list). Served at both well-known suffixes, for the request's issuer:

```json
{
  "issuer" : "<issuer>",
  "authorization_endpoint" : "<issuer>/authorize",
  "end_session_endpoint" : "<issuer>/endsession",
  "revocation_endpoint" : "<issuer>/revoke",
  "token_endpoint" : "<issuer>/token",
  "userinfo_endpoint" : "<issuer>/userinfo",
  "jwks_uri" : "<issuer>/jwks",
  "introspection_endpoint" : "<issuer>/introspect",
  "response_types_supported" : [ "code", "none", "id_token", "token" ],
  "response_modes_supported" : [ "query", "fragment", "form_post" ],
  "subject_types_supported" : [ "public" ],
  "id_token_signing_alg_values_supported" : [ "<EC family…>", "<RSA family…>" ],
  "code_challenge_methods_supported" : [ "plain", "S256" ]
}
```

(`id_token_signing_alg_values_supported` = EC family + RSA family as enumerated by `token/KeyGenerator.kt` — ES256/ES384 + RS256/384/512 in the Go port; exact order captured by golden file.)

## JWKS

GET `/jwks` → JWK Set containing **exactly the one public signing key** for the issuer (`OAuth2TokenProvider.publicJwkSet` = `JWKSet(signingKey(issuerId)).toPublicJWKSet()`). Key model: `kid` = issuerId; first issuers draw from the embedded deterministic initial keys (rebuilt with `kid=issuerId`), then fresh keys are generated. RS256 default; ES256/ES384 configurable.

## Authorization endpoint (OIDC auth-code flow)

Source: `OAuth2HttpRequestHandler.authorization()`, `grant/AuthorizationCodeHandler.kt`, `login/LoginRequestHandler.kt`.

**GET `/authorize`** with standard params (`client_id`, `response_type=code`, `redirect_uri`, `scope`, `state`, `nonce`, optional `code_challenge`/`code_challenge_method`, `prompt`, `response_mode`):

1. Parse as an OIDC `AuthenticationRequest` (missing required params → `invalid_request`).
2. If `interactiveLogin` config is on **or** `prompt` contains `login|consent|select_account` → **200 HTML** login page (custom `loginPagePath` file served as-is with the form target being the current URL; else built-in template). No client validation of any kind.
3. Else → immediate `302` to `redirect_uri?code=<code>&state=<state>` (state only if provided). `response_mode=form_post` → 200 auto-submitting HTML form instead of redirect.

**POST `/authorize`** (login submit; form fields `username` + optional `claims` JSON string; auth params carried in the original query string):

1. Re-parse auth request from URL.
2. Mint single-use `code` (random); cache `code → authRequest` and `code → Login(username, claims)`.
3. `302` (or form_post page) as above.

`response_type` other than code → `invalid_grant` "hybrid og implicit flow not supported (yet)." (Implicit/hybrid are not implemented.)

**POST `/token` exchange** (`grant_type=authorization_code`, `code`, `redirect_uri`, optional `code_verifier`):

1. Look up and **remove** the code (unknown/reused → `invalid_grant` "unknown or already-used authorization code").
2. PKCE (`extensions/…verifyPkce`): if the auth request had `code_challenge`, the token request must carry `code_verifier` matching `plain` or `S256`; on failure the **login cache entry is also invalidated** and the error propagates.
3. Callback resolution: enqueued library callback for issuer → config `tokenCallbacks` mapping → `DefaultOAuth2TokenCallback`. When a login exists, it wraps the callback: mapping `requestParam=subject` becomes matchable against the login username, unmapped subject falls back to `login.username`, and login-page `claims` JSON is merged with `putIfAbsent` (mapping/callback claims win; invalid JSON in `claims` is logged and ignored).
4. Issue **id_token + access_token + refresh_token** (`token_type: Bearer`, `expires_in` from id_token exp vs **wall clock**); echo `scope` if the token request had one. `nonce` propagates into both tokens.

## Claims construction

Source: `token/OAuth2TokenProvider.defaultClaims`, `token/OAuth2TokenCallback.kt` (`DefaultOAuth2TokenCallback`), `AuthorizationCodeHandler.LoginOAuth2TokenCallback`.

Base claims (both token types): `sub` (callback subject), `aud`, `iss` (issuer URL), `iat`/`nbf` = now (`systemTime` if configured), `exp` = now + callback expiry (default 3600 s), `jti` = random UUID; `nonce` if present. Callback `addClaims` applied **after** base claims (can override all of the above). Then auto-claims added last by `DefaultOAuth2TokenCallback`:

- `tid` = issuerId — always, not overridable via user claims.
- `azp` = client_id — for the authorization-code grant, added after user claims (not overridable).

Audience resolution (`DefaultOAuth2TokenCallback.audience`), in order: explicit callback audience → token-request `audience` form param → non-OIDC scopes (scope values outside `openid/profile/email/address/offline_access`) → `["default"]`. **id_token always gets `aud = [client_id]`** regardless. This repo's practical outcome: client id (app name) echoes as `aud`.

## Token endpoint — other grants

`grant_type` dispatch (`OAuth2HttpRequestHandler` lines 64–77). Client auth is never enforced (any Basic/form credentials accepted) except where noted.

- **`client_credentials`** (`grant/ClientCredentialsGrantHandler.kt`): access token only; `sub` = client_id; no id_token/refresh_token.
- **`password`** (`grant/PasswordGrantHandler.kt`): `username` form param becomes `sub`; requestMapping `requestParam=subject`/`${username}` templating can match it.
- **`urn:ietf:params:oauth:grant-type:jwt-bearer`** (`grant/JwtBearerGrantHandler.kt`): `assertion` JWT parsed; its claims carried over and re-signed by the issuer key with refreshed `iss/exp/nbf/iat/jti/aud` (`exchangeAccessToken` semantics — incoming claims otherwise preserved).
- **`urn:ietf:params:oauth:grant-type:token-exchange`** (RFC 8693, `grant/TokenExchangeGrantHandler.kt` + `NimbusExtensions.requirePrivateKeyJwt`): requires client auth via `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` + `client_assertion` JWT validated as `private_key_jwt`: `iss == sub == client_id`, exactly one audience equal to the issuer URL **or** the token endpoint URL, `exp` at most 120 s ahead. `subject_token` JWT is parsed and re-issued with `issued_token_type=urn:ietf:params:oauth:token-type:access_token`. Invalid client assertion → error.
- **`refresh_token`** (`grant/RefreshTokenGrantHandler.kt`, `RefreshTokenManager.kt`):
  - Refresh token minted at auth-code time: opaque random string, **or** an unsigned (alg=none-style plain) JWT carrying `jti`+`nonce` when the auth request had a nonce.
  - On use: resolve stored callback by token — enqueued library callback with matching issuerId takes priority over the stored one; unknown token, revoked token, or token from another issuer → **400 `invalid_grant`**.
  - `rotateRefreshToken=true`: mint a new refresh token and invalidate the old.
  - Response: new access token (+ id_token? follow 6.0.2 golden output) and new refresh token per rotation setting.

## Userinfo

GET `/userinfo` (`userinfo/UserInfo.kt`): Bearer JWT verified against the issuer's key (`typ=JWT`, signature, exact `iss` match, exp/iat at systemTime-if-set); success → 200 JSON of all claims; failure → **401 `invalid_token`**.

## Introspection

POST `/introspect` (`introspect/Introspect.kt`): requires an `Authorization` header (Bearer or Basic — any value; missing → `invalid_client`). Verifies the `token` form param as a JWT against issuer keys + issuer claim: valid → 200 `{"active":true, …standard claims: scope, client_id, username, token_type, exp, iat, nbf, sub, aud, iss, jti}`; invalid → `{"active":false}`.

## Revocation

POST `/revoke`: `token_type_hint` must be `refresh_token` (else 400 `unsupported_token_type`); removes the refresh token from the store; **200 empty** regardless of whether the token existed (RFC 7009 leniency for the hint it supports).

## End session

ANY `/endsession`: `post_logout_redirect_uri` present → 302 to it (append `?state=<state>` when `state` provided); else 200 HTML "logged out". No session invalidation, no front/back-channel logout.

## CORS

`http/CorsInterceptor.kt`: when the request carries an `Origin` header, responses get `Access-Control-Allow-Origin: <origin>`, `Access-Control-Allow-Credentials: true`; for OPTIONS additionally echo `Access-Control-Request-Headers` and allow `POST, GET, OPTIONS`. Applies to success and error responses.

## Static assets

GET `/static/*` (only when `staticAssetsPath` set): path after `/static/` joined to the root, `normalize()`d; must stay under the root (canonical-path prefix check — keep this traversal protection); content type probed from extension; missing → 404 `not found`.

## Debugger UI

`debugger/*` (since 6.0.0 the flow targets only this server's own loopback URL — never client-supplied URLs; preserve that SSRF fix):

- GET `/debugger`: form HTML (client_id, issuerId selection from this server, scopes…).
- POST `/debugger`: stashes form in a `debugger-session` cookie (**JWE, DIR + A128GCM**, same primitive in Go: AES-128-GCM encrypted cookie) and 302s to `/authorize`.
- `/debugger/callback`: exchanges the code server-side via the token endpoint (sending `Host`/`x-forwarded-*` so the issuer matches the externally visible URL), then renders the request/response pair.

## Interactive login page contract (this repo's mount)

The custom page (`mock-oidc-login.html`, mounted read-only) must keep working verbatim: it renders quick-pick users from its embedded directory, POSTs `username` and a hidden `claims` JSON string (built as `name/email/preferred_username/groups/tid`) to **the exact request URL** (auth params preserved in the query string), any password accepted. Unknown usernames (direct POST) fall back to `{name, email: <u>@demo.local, groups: []}` per the page's script — server-side behavior stays generic (`claims` merged with `putIfAbsent`).

## `/isalive` (standalone)

GET `/isalive` → 200 `alive and well` (plain text), registered as an additional route by `cmd/mock-oidc` only — not part of the library.
