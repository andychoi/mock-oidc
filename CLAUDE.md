# mock-oidc

Native Go port of navikt/mock-oauth2-server 6.0.2: a shared dev/test OIDC provider (see `README.md`).
Module `github.com/andychoi/mock-oidc`, Go 1.27, stdlib only (plus `go-pkcs12`).

## Current work: Entra mode

Opt-in Microsoft Entra ID emulation, needed by the IAM project (`../iam`, ADR-0007) because no real
Entra test tenant exists.

1. Read the design: [`docs/entra/00-design.md`](docs/entra/00-design.md)
2. Implement task by task: [`docs/entra/01-plan.md`](docs/entra/01-plan.md) (checkboxes track progress)

## Admin UI (`internal/adminui`)

Embedded single-page dashboard at `/admin/` (front routes `/admin` and `/admin/*`, GitHub Primer
theme ported from ai-gateway's admin UI). Read-mostly: renders config/entra state and drives the
same consent/key stores as the `/_entra` test API. Entra state flows through the
`adminui.EntraState` interface (implemented by `*entra.Handler`) so `entra` never imports
`adminui`/`config`. UI changes need no build step — edit `internal/adminui/static/` and restart.

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
docker compose up -d --build      # serves http://mock-oidc.dev.test:8088
```
