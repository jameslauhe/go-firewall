# go-firewall

An L7 reverse-proxy / WAF that sits in front of an existing API gateway (Nginx, Envoy, Traefik, Kong, ...). It terminates client connections (TLS, HTTP/1.1, HTTP/2, WebSocket), filters and inspects requests, and forwards allowed traffic upstream.

## Features

- **IP allow/deny lists** (CIDR) and **geo-IP allow-listing** (MaxMind `.mmdb`), e.g. restrict traffic to a single country.
- **Rate limiting**, per-IP and per-route, token bucket.
- **WAF rule engine** — data-driven YAML rules (SQLi, XSS, path traversal, command injection out of the box), RE2-compiled for ReDoS-safety.
- **Structured JSON access logs** + **Prometheus metrics** on a private listener.
- **Admin dashboard** (private listener, bearer-token auth) for live log viewing and runtime IP-list/WAF-rule management, with no restart required.
- SIGHUP-triggered WAF rule reload; SIGTERM/SIGINT graceful shutdown.

See `configs/config.example.yaml` for the full configuration surface and `configs/rules/default.yaml` for the seed WAF rule set.

## Build & run

```sh
make build
./bin/go-firewall -config configs/config.example.yaml
```

Or directly:

```sh
go build -o bin/go-firewall ./cmd/go-firewall
```

## Test

```sh
make test        # go test -race -cover ./...
```

## Docker

```sh
make docker       # builds go-firewall:dev
docker run --rm -p 8080:8080 -p 8443:8443 \
  -e GOFIREWALL_ADMIN_TOKEN=change-me \
  go-firewall:dev
```

The image is a multi-stage build (`golang:1.24-alpine` → `distroless/static-debian12:nonroot`); see `build/package/Dockerfile`.

## Admin dashboard

Bound to `127.0.0.1` by default (`admin.address` in config) and gated by a bearer token read from the environment variable named in `admin.auth_token_env` — set it before starting:

```sh
export GOFIREWALL_ADMIN_TOKEN=$(openssl rand -hex 32)
```

Then visit `http://127.0.0.1:9091/admin/` and enter the token.

## Config reload

- WAF rules: edit `waf.rules_file` and send `SIGHUP` to the process — the ruleset hot-swaps with no dropped connections. A malformed reload is rejected and the previous ruleset keeps serving.
- Everything else: restart the process (full config hot-reload is not yet supported).
