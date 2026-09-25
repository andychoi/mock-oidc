# mock-oidc

Shared **dev/test OIDC identity provider** for Andy's local projects — a mock Azure AD.

The server is **native Go, built from this repo**: a faithful port of
[navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) 6.0.2
(the JVM server this repo used to run as a container). Discovery documents,
JWKS (including the deterministic initial keys), grant behavior and error
responses are byte-for-byte compatible with 6.0.2; the rewrite plan and the
compatibility contract live in [docs/plan](docs/plan/00-overview.md).

Runs standalone on host port **8088**, independent of any project's Docker network —
apps reach it like an external IdP, mirroring production.

```
image: built from this repo (docker compose up -d --build)
parity reference: ghcr.io/navikt/mock-oauth2-server:6.0.2
```

## Quick start

```bash
docker compose up -d
# IdP listens on http://localhost:8088
```

### Hostname setup (`mock-oidc.dev.test` — host + Docker)

One hostname for the IdP means the issuer URL, browser redirects, and the `iss`
claim are identical whether the consumer runs on the host or in a container.

**Host apps** (one-time):

```
# /etc/hosts
127.0.0.1 mock-oidc.dev.test
```

**Dockerized consumers** — containers cannot see the host's `/etc/hosts`, so map
the name to the host gateway in each consumer's `docker-compose.yml`:

```yaml
services:
  app:
    extra_hosts:
      - "mock-oidc.dev.test:host-gateway"
```

`host-gateway` is Docker's alias for the host (Docker Desktop maps it to
`host.docker.internal`). Without this line containers fail with
`bad address` for `mock-oidc.dev.test`.

## Connection values (Issuer URL / Client ID / Client Secret)

There is **no client registration and no admin UI** — the mock server accepts any
credentials you choose. To hook an app up, fill in these three values yourself:

| Value | What to use | Rules |
|---|---|---|
| **Issuer URL** | `http://mock-oidc.dev.test:8088/oidc` (or `http://localhost:8088/oidc` without the `/etc/hosts` entry) | The **last path segment defines the issuer** — any path works, but `/oidc` is the convention. Use one hostname consistently; the server echoes it back as `iss`. |
| **Client ID** | Your app's name, e.g. `dochub`, `signflow` | Any non-empty string. It is echoed back as the token's `aud` claim. |
| **Client Secret** | `<app>-dev-secret`, e.g. `dochub-dev-secret` | Any string — the token endpoint accepts arbitrary client credentials (Basic auth or form body). |
| **Redirect URI** | e.g. `http://localhost:3000/api/auth/oidc/callback` | Any URI your app serves. Must be **identical** in the authorize request and the token exchange. |

Sanity-check the issuer (should return JSON with `"issuer": ".../oidc"`):

```bash
curl http://localhost:8088/oidc/.well-known/openid-configuration
```

Your app fetches all other endpoints (authorize/token/jwks/userinfo) from that
discovery document — no further URLs to configure.

Running the consumer **inside Docker**? Containers can't resolve
`mock-oidc.dev.test` on their own — add the `extra_hosts` line from
[Hostname setup](#hostname-setup-mock-oidc-devtest--host--docker) below.

Verified live against 6.0.2: a full authorization-code flow with made-up
`client_id=verify-any-client` / `secret=not-a-real-secret` succeeds, and the
resulting ID token carries `aud`, `groups`, and `tid` as documented below.

## Endpoints (issuer path: `/oidc`)

| Endpoint | URL |
|---|---|
| Discovery | `http://localhost:8088/oidc/.well-known/openid-configuration` |
| Authorize (interactive login) | `http://localhost:8088/oidc/authorize` |
| Token | `http://localhost:8088/oidc/token` |
| JWKS | `http://localhost:8088/oidc/jwks` |
| Userinfo | `http://localhost:8088/oidc/userinfo` |

Issuer: `http://mock-oidc.dev.test:8088/oidc` (or `http://localhost:8088/oidc`).

## Consumer configuration

```env
OIDC_ISSUER_URL=http://mock-oidc.dev.test:8088/oidc
OIDC_CLIENT_ID=dochub            # any value; interactive login accepts all clients
OIDC_CLIENT_SECRET=dochub-dev-secret
OIDC_REDIRECT_URI=http://<app-host>/api/auth/oidc/callback
```

The custom login page (`mock-oidc-login.html`) offers one-click sign-in as any
directory user — **password field accepts any value**.

## User directory

`demo-users.json` is the canonical directory (mirrored in the login page).

| Username | Name | Email | Groups |
|---|---|---|---|
| admin | Admin User | admin@demo.local | platform-admins, dochub-admin |
| alice | Alice Park | alice@demo.local | dochub-user, gitea-maintainers |
| bob | Bob Chen | bob@demo.local | dochub-user, gitea-developers |
| eve | Eve Santos | eve@demo.local | dochub-user, gitea-maintainers |
| frank | Frank Wu | frank@demo.local | dochub-user, gitea-developers |
| grace | Grace Lee | grace@demo.local | *(guest — no groups)* |
| mary | Mary Johnson | mary@acme.com | acme-employees, dochub-user, gitea-developers |
| tim | Tim Miller | tim@acme.com | acme-employees, dochub-user, gitea-developers |
| kevin | Kevin Park | kevin@acme.com | acme-employees, dochub-user, gitea-maintainers |
| tom | Tom Anderson | tom@acme.com | acme-employees, dochub-user, gitea-developers |
| mark | Mark Kim | mark@acme.com | acme-employees, dochub-user, gitea-maintainers |
| andy | Andy Choi | andy@acme.com | platform-admins, acme-admins, dochub-admin |

### Group naming convention (standard claims only)

Tokens carry **standard OIDC claims only** — `name`, `email`, `preferred_username`, `groups`, `tid`.
All RBAC rides the standard `groups` claim with app-prefixed names; each app maps its own prefix:

| Prefix | Consumer | Example mapping |
|---|---|---|
| `dochub-*` | DocHub roles | `dochub-admin` → admin, `dochub-user` → user |
| `gitea-*` | Gitea teams | `gitea-maintainers` → maintainers team |
| `acme-*` | Org membership | `acme-employees`, `acme-admins` |
| `platform-*` | Platform-wide | `platform-admins` → platform admin |

Per-project roles (owner/contributor of project X) are app data — manage them in each
app's own DB/seed scripts, not in the IdP (identity only, same as production Azure AD).

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Service definition (Go build, port 8088 → 8080) |
| `docker-compose.upstream.yml` | Rollback to the upstream 6.0.2 image |
| `mock-oidc.json` | Server config (interactive login, token callback sets `tid` on issuer `oidc`) |
| `mock-oidc-login.html` | Custom login page with user quick-picks |
| `demo-users.json` | Canonical demo user directory |
| `cmd/mock-oidc`, `internal/`, `mockoidc.go` | The Go server (see [docs/plan](docs/plan/)) |

## Consumers

- **ai-docs** (DocHub + Gitea OIDC auth source)
- **flow-spec** (token verification middleware)
- **signflow** (dev OIDC via `dev.sh`)
- **ai-dev-platform-feature-aws** (CoderHub login)

## Development

```bash
go test ./...                       # unit + e2e suites (server on random ports)
go run ./cmd/mock-oidc              # run locally (falls back to ./config.json or JSON_CONFIG env)
JSON_CONFIG='{"interactiveLogin":true}' SERVER_PORT=8099 go run ./cmd/mock-oidc
docker compose up -d --build        # rebuild and restart the shared instance
```

Config precedence is `JSON_CONFIG` env → `JSON_CONFIG_PATH` (default
`config.json`) → built-in default `{interactiveLogin: true}`. The JSON schema
is the mock-oauth2-server one ([reference](docs/plan/03-config.md)).

Parity tip: the behavior of any endpoint can be diffed against upstream 6.0.2
(`docker compose -f docker-compose.upstream.yml up -d` on a spare port) —
discovery and JWKS output should match byte-for-byte after substituting the
host:port.

The Go server is also an importable library for tests:

```go
s, _ := mockoidc.New(nil)           // github.com/andychoi/mock-oidc
_ = s.Start("127.0.0.1:0")
defer s.Stop()
issuer := s.IssuerURL("default")    // point your app's OIDC client here
```

## Notes

- `kid` in JWKS derives from the issuer path segment (`oidc`). Consumers that
  cached an old JWKS re-fetch automatically on unknown `kid` — standard rotation
  behavior, no action needed.
- `tid` in tokens is `mock-tenant-id`, set by the token callback in `mock-oidc.json`.
  Keep the callback's `issuerId` in sync with the issuer path — if it doesn't match,
  the server silently falls back to `tid` = path segment.
- The server was rewritten in Go (2026-09); before that it ran upstream
  mock-oauth2-server 2.1.10 → 6.0.2 as a container. JKS keystores and the JVM
  test-library API are not part of the Go server; everything else matches 6.0.2
  (see the compatibility contract in [docs/plan/00-overview.md](docs/plan/00-overview.md)).
- Keep `demo-users.json` and the login page's `U` array in sync when adding users.
