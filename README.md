# mock-oidc

Shared **dev/test OIDC identity provider** for Andy's local projects — a containerized
[navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) emulating Azure AD.

Runs standalone on host port **8088**, independent of any project's Docker network —
apps reach it like an external IdP, mirroring production.

```
source: https://github.com/navikt/mock-oauth2-server/pkgs/container/mock-oauth2-server (image tag: 6.0.2)
```

## Quick start

```bash
docker compose up -d
# IdP listens on http://localhost:8088
```

Optional hostname (used by consumer configs):

```
# /etc/hosts
127.0.0.1 mock-oidc.dev.test
```

## Endpoints (issuer path: `/azuread`)

| Endpoint | URL |
|---|---|
| Discovery | `http://localhost:8088/azuread/.well-known/openid-configuration` |
| Authorize (interactive login) | `http://localhost:8088/azuread/authorize` |
| Token | `http://localhost:8088/azuread/token` |
| JWKS | `http://localhost:8088/azuread/jwks` |
| Userinfo | `http://localhost:8088/azuread/userinfo` |

Issuer: `http://mock-oidc.dev.test:8088/azuread` (or `http://localhost:8088/azuread`).

## Consumer configuration

```env
OIDC_ISSUER_URL=http://mock-oidc.dev.test:8088/azuread
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
| `docker-compose.yml` | Service definition (port 8088 → 8080) |
| `mock-oidc.json` | mock-oauth2-server config (interactive login, `issuerId: azuread`) |
| `mock-oidc-login.html` | Custom login page with user quick-picks |
| `demo-users.json` | Canonical demo user directory |

## Consumers

- **ai-docs** (DocHub + Gitea OIDC auth source)
- **flow-spec** (token verification middleware)
- **signflow** (dev OIDC via `dev.sh`)
- **ai-dev-platform-feature-aws** (CoderHub login)

## Notes

- Upgraded 2.1.10 → 6.0.2 (majors 3–6 breaking changes reviewed: library API,
  refresh-token strictness, Jackson 3, 1 MiB request cap — none affect this config).
- `kid` in JWKS stays `azuread` (derives from `issuerId`), so consumer JWKS caches survive upgrades.
- Keep `demo-users.json` and the login page's `U` array in sync when adding users.
