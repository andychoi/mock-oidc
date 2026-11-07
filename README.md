# mock-oidc

A shared dev and test OIDC identity provider for local projects. It stands in for Azure AD and,
in Entra mode, for Microsoft Entra ID.

The server is native Go, built from this repo. It ports
[navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) 6.0.2, the JVM server
this repo used to run as a container. Discovery documents, JWKS (including the deterministic
initial keys), grant behavior, and error responses match 6.0.2 byte for byte, with one
deliberate exception: `response_mode=form_post` refuses a `redirect_uri` that is not `http` or
`https`. The compatibility contract is in [docs/plan/00-overview.md](docs/plan/00-overview.md).

The shared instance runs at `https://oidc.dev.test` (port 443), outside any project's Docker
network, so apps reach it like an external IdP. The server terminates TLS itself with a mkcert
certificate. The same listener also serves plain HTTP, and port 8088 stays published for legacy
consumers (`http://mock-oidc.dev.test:8088`). Both ports bind to `127.0.0.1`, so only this
machine can reach the server.

## Quick start

```bash
make tls   # once per clone: mkcert cert into ./tls (gitignored; run `mkcert -install` once per machine)
docker compose -p infra-apps -f ../infra-apps/compose.yaml up -d --build mock-oidc
```

`../infra-apps/compose.yaml` includes this repo's `docker-compose.yml`. Do not run a bare
`docker compose up` here: it moves the container out of the `infra-apps` project. `make up`,
`make down`, `make restart`, `make status`, and `make logs` run the same command for this
service.

### Hostname setup

One hostname means the issuer URL, the browser redirects, and the `iss` claim are the same
whether the consumer runs on the host or in a container.

For host apps, add this line once:

```
# /etc/hosts
127.0.0.1 oidc.dev.test mock-oidc.dev.test
```

Containers cannot see the host's `/etc/hosts`. Map the name to the host gateway in each
consumer's compose file:

```yaml
services:
  app:
    extra_hosts:
      - "oidc.dev.test:host-gateway"
```

Without this line, containers fail with `bad address` for `oidc.dev.test`.

## Connect an app

There is no client registration. The server accepts any client credentials, so you pick the
values:

| Value | What to use | Rules |
|---|---|---|
| Issuer URL | `https://oidc.dev.test/oidc` (or `http://localhost:8088/oidc` without an `/etc/hosts` entry) | The first path segment is the issuer, so any segment works. `/oidc` is the convention. Use one hostname everywhere, because the server echoes it back as `iss`. |
| Client ID | Your app's name, for example `dochub` | Any non-empty string. The token's `aud` claim echoes it. |
| Client secret | `<app>-dev-secret`, for example `dochub-dev-secret` | Any string, sent by Basic auth or in the form body. |
| Redirect URI | For example `http://localhost:3000/api/auth/oidc/callback` | Any URI your app serves. It must be the same in the authorize request and the token exchange. With `response_mode=form_post` it must be `http` or `https`, or the authorize request gets `400 invalid_request`. |

```env
OIDC_ISSUER_URL=https://oidc.dev.test/oidc
OIDC_CLIENT_ID=dochub
OIDC_CLIENT_SECRET=dochub-dev-secret
OIDC_REDIRECT_URI=http://<app-host>/api/auth/oidc/callback
```

Your app reads every other endpoint from the discovery document. To check the issuer, run:

```bash
curl http://localhost:8088/oidc/.well-known/openid-configuration   # "issuer": ".../oidc"
```

| Endpoint | URL |
|---|---|
| Discovery | `https://oidc.dev.test/oidc/.well-known/openid-configuration` |
| Authorize | `https://oidc.dev.test/oidc/authorize` |
| Token | `https://oidc.dev.test/oidc/token` |
| JWKS | `https://oidc.dev.test/oidc/jwks` |
| Userinfo | `https://oidc.dev.test/oidc/userinfo` |

The custom login page (`mock-oidc-login.html`) offers one-click sign-in as any directory user.
The password field accepts any value.

## TLS

`make tls` writes a mkcert PEM pair to `./tls/` with SANs for `oidc.dev.test`,
`mock-oidc.dev.test`, `localhost`, `127.0.0.1`, and `::1`. The config block
`httpServer.ssl.certificateFile` and `privateKeyFile` points the server at it. The listener
reads the first byte of each connection and serves HTTPS or plain HTTP on the same port. A
missing or bad certificate or key stops the server at startup. It never falls back to HTTP only.

## Admin UI

`https://oidc.dev.test/admin/` is a dashboard served by the same process (GitHub Primer theme,
light and dark). It has no authentication, like the rest of the server. Every edit changes
in-memory state only. A restart returns to the config files, and every page has a reset action.

- **Overview** shows server counts, an endpoint table for the root issuer and every
  token-callback issuer, and runtime toggles for interactive login, refresh-token rotation,
  Entra mode, and the Entra Graph API.
- **Entra** (only when configured) edits tenants and users, including the profile fields Graph
  serves. It lists consents with per-row revoke and signing keys with rotation, and has
  **Reset to config**. Edits get the same validation as the config file.
- **Directory** edits the login page's quick-pick users. The login page fetches them live. The
  directory loads from `USER_DIRECTORY_PATH`, or from `./demo-users.json` when that variable is
  unset and the file exists. The login page still accepts any username.

The dashboard calls a JSON API under `/admin/api/`:

| Method | Path | Action |
|---|---|---|
| GET | `overview` | Server counts and toggles |
| GET, POST | `settings` | Read the toggles. Set one with `{"name": "...", "value": true}`. Names: `interactiveLogin`, `rotateRefreshToken`, `entra`, `graph`. |
| GET | `entra` | Entra tenants, users, consents, and keys |
| POST | `entra/reset` | Restore tenants, users, and consents from the config seed. Keys stay. |
| POST | `entra/rotate-keys` | Rotate the signing key |
| POST | `entra/tenants` | Create a tenant |
| PUT, DELETE | `entra/tenants/{tid}` | Update or delete a tenant |
| POST | `entra/users` | Create a user |
| PUT, DELETE | `entra/users/{tid}/{username}` | Update or delete a user |
| DELETE | `entra/consents/{clientId}/{tid}` | Revoke a consent |
| GET | `directory` | Login directory users |
| POST | `directory/users`, `directory/reset` | Add or replace a user, or restore the seed |
| DELETE | `directory/users/{username}` | Delete a user |

`/admin` responses carry no CORS headers, so a page on another origin cannot read them or pass
a preflight. POST and PUT requests need `Content-Type: application/json`, or else `415`. The
one exception is a request with neither `Content-Type` nor `Origin`, which only a non-browser
client sends. `curl -d` sends a form content type, so add the header:

```bash
curl -X POST https://oidc.dev.test/admin/api/settings \
  -H 'Content-Type: application/json' -d '{"name":"interactiveLogin","value":false}'
```

## MCP for AI agents

`/admin/mcp` serves the same admin operations as an MCP server:

```bash
claude mcp add --transport http mock-oidc https://oidc.dev.test/admin/mcp
```

- Settings: `settings_get`, `settings_set` (`interactiveLogin`, `rotateRefreshToken`, `entra`,
  `graph`).
- Login directory, when one is loaded: `directory_list`, `directory_upsert_user`,
  `directory_delete_user`, `directory_reset`.
- Entra, when configured: `entra_get_state`, `entra_create_tenant`, `entra_update_tenant`,
  `entra_delete_tenant`, `entra_create_user`, `entra_update_user`, `entra_delete_user`,
  `entra_revoke_consent`, `entra_reset`, `entra_rotate_keys`, `entra_mint_token`.

The endpoint is Streamable HTTP, stateless, and JSON only. It serves protocol `2026-07-28` and
the `initialize`-based versions `2025-03-26` to `2025-11-25`. Every request needs
`Content-Type: application/json`. Like `/admin/api/`, it has no authentication and sends no CORS
headers, so browser-based MCP clients on another origin cannot call it.

## Entra mode

Entra mode emulates Microsoft Entra ID v2.0 for testing multi-tenant Entra relying parties. Set
`ENTRA_CONFIG_PATH` (compose mounts `entra-demo.json`) or add an `"entra"` block to the JSON
config. With neither, Entra mode is off. Reference:

- Sign-in and tokens: [docs/entra/00-design.md](docs/entra/00-design.md)
- Graph API, `userinfo`, and app-only tokens:
  [docs/entra/02-graph-design.md](docs/entra/02-graph-design.md)
- Org directory, dynamic groups, `$filter`, and claim mapping:
  [docs/entra/04-org-directory-design.md](docs/entra/04-org-directory-design.md)

| Value | Per tenant | "Sign in with Microsoft" (multi-tenant) |
|---|---|---|
| Authority (issuer base) | `https://oidc.dev.test/entra/{tid}/v2.0` | `https://oidc.dev.test/entra/organizations/v2.0` |
| Discovery | `…/entra/{tid}/v2.0/.well-known/openid-configuration` | `issuer` is the template `…/entra/{tenantid}/v2.0` |
| Token `iss` | `…/entra/{tid}/v2.0` | `…/entra/{user's tid}/v2.0` |
| Client ID and secret | any | any |

The demo config `entra-demo.json` has four tenants:

- Corp `11111111-…` emits group names.
- Customer X `22222222-…` emits group object IDs, requires consent, and switches to the overage
  claim above 5 groups.
- Partner P `33333333-…` requires consent.
- Org Chart `44444444-…` has org codes in `extensionAttribute1`, dynamic `GRP_DEPT_…` groups, a
  `Direct Reports for` group, and `org_code` and `department` claims mapped into the `iam`
  app's ID token.

The account picker asks for no password. Demo users cover an injected `interaction_required`
error (`mfa`), a simulated passkey step (`passkey`, which signs in with `amr`
`["fido", "mfa"]`), a disabled account (`disabled`), group overage (`many`), a manager chain
(`leo` and `mina` report to `jane`), and tenant admins for admin consent (`jane`, `custadmin`,
`partneradmin`).

Admin consent: `…/entra/{tid|organizations}/v2.0/adminconsent?client_id=…&redirect_uri=…&state=…`.

The config loader rejects two users in one tenant with the same object ID, and two declared
groups with the same object ID. The admin UI and MCP edits run the same check.

### Sign in without a browser

A `login_hint` that names exactly one account in scope issues the code on the GET and skips the
picker, so a relying-party test can run headless. The hint matches a UPN, an email, or the
configured username:

```bash
curl -si "https://oidc.dev.test/entra/11111111-1111-1111-1111-111111111111/oauth2/v2.0/authorize\
?response_type=code&client_id=iam&redirect_uri=http://app.test/cb&scope=openid&login_hint=jane@corp.demo.local" \
  | grep -i location          # 302 straight to ?code=…
```

`prompt=select_account` or `prompt=login` shows the picker anyway, with the hinted account
marked. `"ignoreLoginHint": true` turns the shortcut off. `domain_hint=` narrows the
`organizations` or `common` picker by tenant domain. `prompt=none` issues the code when the hint
resolves and otherwise redirects with `error=interaction_required` (AADSTS50058). The mock keeps
no session, so a resolvable hint stands in for one.

### Graph account API

Graph is on whenever Entra mode is. `"graph": {"enabled": false}` turns it off. The path never
names the tenant. The server takes the tenant from the caller's token, as real Graph does, and
confines every response to it.

| Method | Path (under `/entra/graph`) | Returns |
|---|---|---|
| GET | `/v1.0/me` | The token's user |
| GET | `/v1.0/me/memberOf`, `/transitiveMemberOf` | The user's groups |
| GET | `/v1.0/me/manager`, `/directReports` | The manager chain |
| POST | `/v1.0/me/getMemberObjects`, `/getMemberGroups` | Group IDs, which resolve group overage |
| GET | `/v1.0/users`, `/users/{id or upn}` | The tenant's accounts |
| GET | `/v1.0/users/{id}/memberOf`, `/manager`, `/directReports` | As for `/me` |
| GET | `/v1.0/groups`, `/groups/{id}`, `/groups/{id}/members` | The tenant's groups |
| GET, POST | `/oidc/userinfo` | OIDC claims, advertised as `userinfo_endpoint` |

```bash
AT=$(curl -s -X POST https://oidc.dev.test/entra/_entra/mint-token \
  -d tid=11111111-1111-1111-1111-111111111111 -d username=jane | jq -r .access_token)
curl -s https://oidc.dev.test/entra/graph/v1.0/me -H "Authorization: Bearer $AT" | jq
curl -s https://oidc.dev.test/entra/graph/v1.0/me/memberOf -H "Authorization: Bearer $AT" | jq '.value[].displayName'
curl -s -X POST https://oidc.dev.test/entra/graph/v1.0/me/getMemberObjects \
  -H "Authorization: Bearer $AT" -d '{"securityEnabledOnly":true}' | jq
```

A group has one object ID everywhere: the `object_id` groups claim, Graph, and the test API all
use the group's configured `oid`, or a derived one when none is configured. With Graph on, the
overage claim's `_claim_sources` endpoint points at this server, not at `graph.microsoft.com`, so
a relying party can follow it inside the test environment. `"overageEndpoint": "microsoft"`
restores Entra's URL.

Graph reads need an access token that this server minted for the Graph audience. ID tokens get
`401 InvalidAuthenticationToken`. `/me` and `userinfo` also need a delegated token. With
`"graph": {"appOnly": true}`, `grant_type=client_credentials` on a tenant-specific path mints an
app-only token, with roles from `apps[]` and no `oid`. That token reads `/users` and `/groups`
and gets `403` on `/me`, like a directory-sync job. The server does not check Graph permissions:
any valid Graph-audience token can read.

Query options:

- `$top` defaults to 100 and is clamped to 999. `$skiptoken` pages.
- `$select` picks properties. An unknown property gets `400`, also inside
  `$expand=manager($select=...)`.
- `$filter` supports a subset on collections: `eq`, `ne`, `in`, `startsWith`, `any`, `and`,
  `or`, and `not`, for example `onPremisesExtensionAttributes/extensionAttribute1 eq 'DEPT001'`.
  Nesting deeper than 32 levels gets `400`.
- `$expand=manager` works on `/me` and `/users`.

`$orderby`, `$search`, `$count`, and anything outside the subset get
`400 Request_UnsupportedQuery`. The server never ignores an option it does not support.

Users carry `department`, `companyName`, `employeeId`, and
`onPremisesExtensionAttributes.extensionAttribute1-3`. Graph returns them only through `$select`,
as v1.0 does. A declared group with a `membershipRule`, such as
`(user.extensionAttribute1 -eq "DEPT001")`, is a dynamic group. Its members are recomputed on
every change, so an admin edit of an org code moves the user between groups on the next token
and Graph call. A rule nested deeper than 32 levels fails to load. `apps[].claims` maps user
attributes into an app's ID token.

### Test API

All paths are under `/entra/_entra/`:

| Method | Path | Action |
|---|---|---|
| GET | `consents` | List granted consents |
| POST | `reset` | Clear runtime consents |
| POST | `rotate-keys` | Rotate the signing key |
| GET | `groups?tid=…` | Map group names to object IDs |
| GET | `users?tid=…` | The directory as Graph sees it |
| POST | `mint-token` | Mint tokens without the picker. Takes `tid`, `username`, and optional `clientId` and `scope`. |

`mint-token` refuses a disabled account or one configured with `"error": "invalid_grant"`, as the
token endpoint does.

### Not emulated

Real Conditional Access, Microsoft's UI and exact error wording, refresh-token redemption,
implicit and hybrid flows, Graph writes, OData beyond the subset above, nested groups
(`transitiveMemberOf` equals `memberOf`), app registrations, device code flow, and Graph beyond
accounts and groups.

## User directory

`demo-users.json` seeds the login directory.

| Username | Name | Email | Groups |
|---|---|---|---|
| admin | Admin User | admin@demo.local | platform-admins, dochub-admin |
| alice | Alice Park | alice@demo.local | dochub-user, gitea-maintainers |
| bob | Bob Chen | bob@demo.local | dochub-user, gitea-developers |
| eve | Eve Santos | eve@demo.local | dochub-user, gitea-maintainers |
| frank | Frank Wu | frank@demo.local | dochub-user, gitea-developers |
| grace | Grace Lee | grace@demo.local | none (guest) |
| mary | Mary Johnson | mary@acme.com | acme-employees, dochub-user, gitea-developers |
| tim | Tim Miller | tim@acme.com | acme-employees, dochub-user, gitea-developers |
| kevin | Kevin Park | kevin@acme.com | acme-employees, dochub-user, gitea-maintainers |
| tom | Tom Anderson | tom@acme.com | acme-employees, dochub-user, gitea-developers |
| mark | Mark Kim | mark@acme.com | acme-employees, dochub-user, gitea-maintainers |
| andy | Andy Choi | andy@acme.com | platform-admins, acme-admins, dochub-admin |
| ams-admin | AMS Admin | admin@acme.test | acme-admins |
| ams-engineer | AMS Engineer | engineer@acme.test | acme-employees |
| ams-customer | AMS Customer | customer@acme.test | none |

### Group naming convention

The login page sends standard OIDC claims only: `name`, `email`, `preferred_username`, `groups`,
and `tid`. Authorization uses the `groups` claim with app-prefixed names, and each app maps its
own prefix:

| Prefix | Consumer | Example mapping |
|---|---|---|
| `dochub-*` | DocHub roles | `dochub-admin` to admin, `dochub-user` to user |
| `gitea-*` | Gitea teams | `gitea-maintainers` to the maintainers team |
| `acme-*` | Org membership | `acme-employees`, `acme-admins` |
| `platform-*` | Platform-wide | `platform-admins` to platform admin |

Per-project roles, such as owner of project X, are app data. Keep them in each app's database or
seed scripts, not in the IdP.

## Files

| File | Purpose |
|---|---|
| `docker-compose.yml` | Service definition: Go build, `127.0.0.1` ports 443 and 8088 to container port 8080 |
| `docker-compose.upstream.yml` | The upstream 6.0.2 image, for comparison |
| `mock-oidc.json` | Server config: interactive login, TLS, and a token callback that sets `tid` on issuer `oidc` |
| `mock-oidc-login.html` | Custom login page with directory quick-picks |
| `demo-users.json` | Login directory seed |
| `entra-demo.json` | Entra mode demo tenants, users, and apps |
| `cmd/mock-oidc`, `internal/`, `mockoidc.go` | The Go server |

## Consumers

- **ams** (E14 OIDC SSO)
- **iam** (Entra mode)

## Development

```bash
go test ./...                       # unit and e2e suites (servers on random ports)
go run ./cmd/mock-oidc              # run locally
JSON_CONFIG='{"interactiveLogin":true}' SERVER_PORT=8099 go run ./cmd/mock-oidc
```

| Variable | Effect |
|---|---|
| `JSON_CONFIG` | Inline JSON config. Wins over `JSON_CONFIG_PATH`. |
| `JSON_CONFIG_PATH` | Config file, default `config.json`. A missing file falls back to `{"interactiveLogin": true}`. |
| `ENTRA_CONFIG_PATH` | Entra config file. Replaces an `"entra"` block in the JSON config. |
| `USER_DIRECTORY_PATH` | Login directory file, default `./demo-users.json` when present |
| `SERVER_PORT`, `PORT` | Listen port, default 8080 |
| `SERVER_HOSTNAME` | Listen host, default all interfaces |
| `LOG_LEVEL` | `debug`, `warn`, or `error`. Default `info`. |

The JSON schema is the mock-oauth2-server one ([reference](docs/plan/03-config.md)).

To compare an endpoint with upstream 6.0.2, stop the shared container and run
`docker compose -f docker-compose.upstream.yml up -d`, which publishes port 8088. Discovery and
JWKS output match byte for byte after you substitute the host and port.

The server is also a library for Go tests:

```go
s, _ := mockoidc.New(nil)           // github.com/andychoi/mock-oidc
_ = s.Start("127.0.0.1:0")
defer s.Stop()
issuer := s.IssuerURL("default")    // point your app's OIDC client here
```

## Notes

- The JWKS `kid` is the issuer path segment (`oidc`).
- `tid` in tokens is `mock-tenant-id`, set by the token callback in `mock-oidc.json`. The
  callback's `issuerId` must match the issuer path. Otherwise `tid` is the path segment.
- The Go server replaced the upstream container in 2026-09. It drops JKS keystores and the JVM
  test-library API. PKCS12 keystores and PEM pairs still work.
