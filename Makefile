# Operates on the shared `infra-apps` umbrella project (../infra-apps/)
# scoped to this service, so Docker Desktop keeps one group for all central
# services. Never a bare `docker compose up` on the local file — it would
# relabel the container into a `mock-oidc` project and split that group.
COMPOSE := docker compose -p infra-apps -f $(HOME)/project/infra-repos/infra-apps/compose.yaml
CONTAINER := infra-apps-mock-oidc-1

# Local TLS certificate for https://oidc.dev.test (mkcert local CA — run
# `mkcert -install` once per machine). The old mock-oidc.dev.test stays in
# the SAN so existing consumers keep working over TLS during migration.
tls:
	mkdir -p tls && chmod 700 tls
	mkcert -cert-file tls/oidc.dev.test.pem -key-file tls/oidc.dev.test-key.pem \
		oidc.dev.test mock-oidc.dev.test localhost 127.0.0.1 ::1
	chmod 600 tls/oidc.dev.test-key.pem

## Lifecycle -------------------------------------------------------------
up:
	$(COMPOSE) up -d --build --wait mock-oidc

down:
	$(COMPOSE) down mock-oidc

restart:
	$(COMPOSE) restart mock-oidc
	$(COMPOSE) ps mock-oidc

status:
	$(COMPOSE) ps mock-oidc

logs:
	$(COMPOSE) logs -f --tail 100 mock-oidc

.PHONY: tls up down restart status logs
