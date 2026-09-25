# 05 — Delivery, Docker & rollout

Part of the [rewrite plan](00-overview.md). Covers M6 plus the repo housekeeping that lands alongside it.

## Docker

**Dockerfile** (repo root, multi-stage):

```dockerfile
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mock-oidc ./cmd/mock-oidc

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /mock-oidc /mock-oidc
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/mock-oidc"]
```

- Static binary (no cgo), distroless non-root: smaller and safer than the current JRE image.
- Default port 8080 inside the container (same as upstream image — `SERVER_PORT`/`PORT` env respected by the binary).

**docker-compose.yml** — switch from the GHCR image to a local build, everything else unchanged:

```yaml
services:
  mock-oidc:
    build: .
    ports:
      - "8088:8080"
    volumes:
      - ./mock-oidc.json:/config/mock-oidc.json:ro
      - ./mock-oidc-login.html:/config/mock-oidc-login.html:ro
    environment:
      JSON_CONFIG_PATH: /config/mock-oidc.json
    restart: unless-stopped
```

Kept identical on purpose: host port **8088**, same volume mounts, same env, still standalone (not on `sdlc-net`/`coder-network`) so consumers reach it like an external IdP via `http://mock-oidc.dev.test:8088`.

## Rollout

1. **M6 pre-flight** (before switching compose): parity harness green against 6.0.2 for all flows in [04](04-testing.md); `go-oidc` RP test green; `go vet`, `gofmt`, unit + e2e + golden CI green.
2. **README updates** (same PR as the compose switch):
   - Connection values unchanged: issuer `http://mock-oidc.dev.test:8088/oidc` (or `http://localhost:8088/oidc`), open client registration (`<app>` / `<app>-dev-secret` convention), redirect-uri contract, hostname setup (`/etc/hosts` on host, `extra_hosts: host-gateway` for containers).
   - **Remove every `/azuread` mention** — the "renamed from /azuread … old path still answers" note and the `kid was azuread` aside go away; `kid` is documented simply as `oidc` (derives from the issuer path segment).
   - Add a "development" section: `go test ./...`, parity harness, how to run the binary locally.
   - Update the intro: the server is now Go, built from this repo (drop the mock-oauth2-server version reference).
3. **Consumer verification** — each of `ai-docs`, `flow-spec`, `signflow`, `ai-dev-platform-feature-aws`: confirm discovery + login + token + JWKS against the Go server on port 8088; confirm none still use `/azuread` (grep their configs; the path is retired — any straggler is migrated to `/oidc` at this point, not accommodated).
4. **Cutover**: `docker compose up -d --build` on the host; spot-check `/oidc/.well-known/openid-configuration`, an interactive login round-trip, and a token's `kid`/`tid` claims.
5. **Rollback**: revert the compose file to the pinned `ghcr.io/navikt/mock-oauth2-server:6.0.2` service block (kept in git history; optionally preserved as `docker-compose.upstream.yml` for one release).

## `/azuread` retirement (decision)

The legacy issuer path `/azuread` is **removed**, not merely deprecated:

- Docs/tests/configs never mention it; consumers are audited at cutover (step 3).
- The server keeps upstream's generic any-first-segment-is-an-issuer behavior (core semantics, zero special-casing). `/azuread` therefore isn't *blocked* — it simply loses all documentation, support, and guarantees. If a strict 404 is ever wanted, a small deny-list middleware can be added later; not planned.
- `kid` and `tid` derive from the path segment as before, so for the canonical issuer nothing changes: `kid=oidc`, `tid=mock-tenant-id` (via token callback).

## Repo housekeeping

- **`.gitignore`** (new): `.zcode/`, Go artifacts (`/mock-oidc`, `*.test`, `coverage.out`), `dist/`.
- **CI** (optional, GitHub Actions): `gofmt -l` + `go vet` + `go build` + `go test ./...` on PRs; release workflow builds and pushes the image to GHCR (`ghcr.io/andychoi/mock-oidc`) tagged with version and `latest` when a tag is pushed.
- **Versioning**: start at `v1.0.0` (the Go server's own line; unrelated to upstream 6.0.2, which is recorded in docs as the parity reference).
- Keep `demo-users.json` as the canonical directory; `mock-oidc-login.html` mirrors it — unchanged practice, README already flags the sync requirement.

## Milestone recap

| Milestone | Deliverables | Definition of done |
|---|---|---|
| M1 | module, config (env+JSON), server, suffix routing, discovery, JWKS, client-credentials, `/isalive` | discovery/JWKS golden parity; client-credentials token verifies via `go-oidc` |
| M2 | auth-code + PKCE, interactive/custom login, refresh + rotation, end session, token callbacks | full RP-driven auth-code flow identical on both servers; this repo's login page fixture passes |
| M3 | userinfo, CORS, introspection, revocation, static assets, favicon, body cap, canonical errors | e2e suites green; error golden files match |
| M4 | token exchange (+`private_key_jwt`), JWT bearer, password grant | ported upstream e2e cases green |
| M5 | debugger UI + JWE session cookie, self-signed HTTPS, keystore TLS, `systemTime` | debugger round-trip; HTTPS serves with generated + provided PKCS12 |
| M6 | Dockerfile, compose switch, README (incl. `/azuread` removal), `.gitignore`, CI, consumer audit | steps 1–4 above complete; rollback path documented |

Effort shape: M2 is the largest slice (login UX + caches + callbacks); M1 and M3 are mechanical; M5 is self-contained. Each milestone is a reviewable PR against the plan docs.
