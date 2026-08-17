# go-firewall

An L7 reverse-proxy / WAF that sits in front of an existing API gateway (Nginx, Envoy, Traefik, Kong, ...). It terminates client connections, filters and inspects requests, and forwards allowed traffic upstream.

## Status

Under active development. See `configs/config.example.yaml` for the full configuration surface.

## Build & run

```sh
go build -o bin/go-firewall ./cmd/go-firewall
./bin/go-firewall -config configs/config.example.yaml
```

## Test

```sh
go test -race ./...
```
