# go-firewall

An L7 reverse-proxy / WAF that sits in front of an existing API gateway (Nginx, Envoy, Traefik, Kong, ...). It terminates client connections (TLS, HTTP/1.1, HTTP/2, WebSocket), filters and inspects requests, and forwards allowed traffic upstream.

## Features

- **IP allow/deny lists** (CIDR, linear-scan or set-based matching depending on list size) and **geo-IP allow-listing** (MaxMind `.mmdb`), e.g. restrict traffic to a single country.
- **Trusted-proxy X-Forwarded-For support** — resolves the real client IP from XFF only when the raw TCP peer is an explicitly configured trusted proxy/LB; otherwise (the default) only the raw peer is ever trusted.
- **Rate limiting**, per-IP and per-route, token bucket.
- **WAF rule engine** — data-driven YAML rules (SQLi, XSS, path traversal, command injection out of the box), RE2-compiled for ReDoS-safety.
- **Structured JSON access logs** + **Prometheus metrics** on a private listener.
- **Admin dashboard** (private listener, bearer-token auth) for live log viewing and runtime IP-list/WAF-rule management, with no restart required; edits optionally persist to disk (`admin.state_file`) and survive a restart.
- **SIGHUP-triggered config reload** for WAF rules, IP lists (including geo), and rate limits — no restart, no dropped connections; SIGTERM/SIGINT graceful shutdown.

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

By default, IP-list and WAF-rule edits made through the dashboard are in-memory only and reset on restart. Set `admin.state_file` to a writable path to persist them:

```yaml
admin:
  state_file: "/var/lib/go-firewall/state.json"
```

In the container image, mount a writable volume at that path (the distroless image has no shell to create directories at runtime):

```sh
docker run --rm -p 8080:8080 -p 8443:8443 \
  -e GOFIREWALL_ADMIN_TOKEN=change-me \
  -v $(pwd)/data:/var/lib/go-firewall \
  go-firewall:dev
```

## Config reload

Sending `SIGHUP` to a running process reloads, with no restart and no dropped connections:

- `waf.rules_file` (the WAF ruleset)
- `ip_lists` (allow/deny CIDRs and geo settings)
- `rate_limit` (default and per-route thresholds)

Any admin-dashboard edits (live-added/removed CIDRs, per-rule WAF overrides) are preserved across a SIGHUP reload — only the base values from the config/rules files are replaced. A malformed new config is rejected in full (nothing is partially applied) and every component keeps serving its previous state.

Listener addresses, TLS certs, upstream addresses, and the admin/metrics listener addresses are not reloadable — changing those requires a restart.
