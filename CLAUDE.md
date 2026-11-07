# mock-oidc

Native Go port of navikt/mock-oauth2-server 6.0.2: a shared dev/test OIDC provider (see `README.md`).
Module `github.com/andychoi/mock-oidc`, Go 1.27, stdlib only (plus `go-pkcs12`).

## Entra mode

Opt-in Microsoft Entra ID emulation, needed by the IAM project (`../iam`, ADR-0007) because no real
Entra test tenant exists. Read the reference doc before changing an area. The plans
(`docs/entra/01-plan.md`, `03-graph-plan.md`) are complete and kept as history.

1. Sign-in and tokens: [`docs/entra/00-design.md`](docs/entra/00-design.md)
2. Account Graph API, `userinfo`, selection hints, app-only tokens:
   [`docs/entra/02-graph-design.md`](docs/entra/02-graph-design.md)
3. Org directory: `department` and `extensionAttribute1-3`, dynamic groups (`rule.go`), `$filter`
   (`filter.go`), `$expand=manager`, `apps[].claims` mapping:
   [`docs/entra/04-org-directory-design.md`](docs/entra/04-org-directory-design.md)

The Graph surface (`internal/entra/graph.go`, `odata.go`, `verify.go`, `directory.go`) is on
whenever Entra mode is, mounted on a reserved segment of the same front route and scoped by the
caller's token rather than by the path. Graph error bodies must **not** go through
`routing.ErrorResponse`, which lowercases bodies for navikt compatibility and would destroy
PascalCase codes such as `InvalidAuthenticationToken`.

## Admin UI (`internal/adminui`)

Embedded single-page dashboard at `/admin/` (front routes `/admin` and `/admin/*`, GitHub Primer
theme ported from ai-gateway's admin UI). Maintains runtime state: entra tenants/users via the
copy-on-write `entra.Store` (mutations re-run `Config.normalize`, so runtime edits keep every
startup invariant), consent revoke/reset, key rotation, the login directory
(`internal/directory`, seeded from `USER_DIRECTORY_PATH`/`demo-users.json`), and server settings
toggles (interactiveLogin, rotateRefreshToken and entra are atomics on `*server.Server`, and the
entra toggle gates the front route with 405s; graph lives in the `entra.Store`, so Reset undoes
it). All edits are in-memory; resets restore the config-file seed. `adminui` imports `entra`/`directory` directly; `entra` still imports neither
`adminui` nor `config`. UI changes need no build step. Edit `internal/adminui/static/` and restart.
The same operations are MCP tools at `/admin/mcp` (`mcp.go` transport, `mcp_tools.go` registry; each
tool's schema and decoder derive from its Go input struct).

The admin surface has no authentication, so two rules keep other web pages out. The CORS
interceptor in `server.buildRouter` skips `/admin` and `/admin/*`, and `/admin/api/` POST and PUT
need a JSON content type (`jsonContent`; a request with neither `Content-Type` nor `Origin` also
passes). Keep both when adding admin routes.

## Rules

- **Compatibility is a hard constraint.** Without Entra config, responses stay byte-for-byte identical
  to navikt 6.0.2 (contract C1 to C9 in `docs/plan/00-overview.md`). The one deliberate divergence
  is that `response_mode=form_post` refuses a `redirect_uri` that is not `http` or `https`
  (`docs/plan/02-endpoints-and-flows.md`).
- **Never weaken or remove an existing test's assertions to make new code pass.** Moving a test to
  a new internal API, or onto the HTTP surface, with the same assertions is fine.
- The router matches by **path suffix** (`internal/routing`); new path families must be mounted as a
  front route with a `*` pattern, not as suffix routes.
- Error JSON bodies are lowercased by `routing.ErrorResponse` (upstream behavior).
- No new module dependencies.
- CI gates: `gofmt -l .` empty (excluding `docs/`), `go vet ./...`, `go build ./...`, `go test ./...`;
  also run `go test -race ./...` before finishing.
- US English in comments and docs.

## Commands

```bash
go test ./...                     # all tests
go test ./internal/e2e/ -run Entra -v
docker compose -p infra-apps -f ../infra-apps/compose.yaml up -d --build mock-oidc
                                  # serves https://oidc.dev.test (TLS, make tls first;
                                  # legacy http://mock-oidc.dev.test:8088 still served;
                                  # both ports bind 127.0.0.1)
                                  # (infra-apps umbrella project; never a bare
                                  # `docker compose up` here)
```
