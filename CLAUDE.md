# mock-oidc

Native Go port of navikt/mock-oauth2-server 6.0.2: a shared dev/test OIDC provider (see `README.md`).
Module `github.com/andychoi/mock-oidc`, Go 1.27, stdlib only (plus `go-pkcs12`).

## Entra mode

Opt-in Microsoft Entra ID emulation, needed by the IAM project (`../iam`, ADR-0007) because no real
Entra test tenant exists. All three phases are implemented; read the design before changing any.

1. Sign-in and tokens: [`docs/entra/00-design.md`](docs/entra/00-design.md),
   plan [`docs/entra/01-plan.md`](docs/entra/01-plan.md)
2. Account Graph API, `userinfo`, selection hints, app-only tokens:
   [`docs/entra/02-graph-design.md`](docs/entra/02-graph-design.md),
   plan [`docs/entra/03-graph-plan.md`](docs/entra/03-graph-plan.md)
3. Org directory — `department`/`extensionAttribute1-3`, dynamic groups (`rule.go`), `$filter`
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
toggles (interactiveLogin, rotateRefreshToken, entra on/off — atomics on `*server.Server`, the
entra toggle gates the front route with 405s). All edits are in-memory; resets restore the
config-file seed. `adminui` imports `entra`/`directory` directly; `entra` still imports neither
`adminui` nor `config`. UI changes need no build step — edit `internal/adminui/static/` and restart.

## Rules

- **Compatibility is a hard constraint.** Without Entra config, responses stay byte-for-byte identical
  to navikt 6.0.2 (contract C1–C9 in `docs/plan/00-overview.md`). Never edit existing tests to make
  new code pass.
- The router matches by **path suffix** (`internal/routing`); new path families must be mounted as a
  front route with a `*` pattern, not as suffix routes.
- Error JSON bodies are lowercased by `routing.ErrorResponse` (upstream behavior).
- No new module dependencies.
- CI gates: `gofmt -l .` empty (excluding `docs/`), `go vet ./...`, `go build ./...`, `go test ./...`;
  also run `go test -race ./...` before finishing.
- US English in comments and docs. Commit messages end with `Co-authored by AI`.

## Commands

```bash
go test ./...                     # all tests
go test ./internal/e2e/ -run Entra -v
docker compose -p infra-apps -f ../infra-apps/compose.yaml up -d --build mock-oidc
                                  # serves https://oidc.dev.test (TLS, make tls first;
                                  # legacy http://mock-oidc.dev.test:8088 still served)
                                  # (infra-apps umbrella project — never a bare
                                  # `docker compose up` here)
```
