# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 GOOS=linux go build \
      -ldflags="-s -w -X github.com/jameslauhe/go-firewall/internal/version.Version=${VERSION} -X github.com/jameslauhe/go-firewall/internal/version.Commit=${COMMIT}" \
      -o /out/go-firewall ./cmd/go-firewall

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/go-firewall /go-firewall
COPY configs/rules/default.yaml /etc/go-firewall/rules/default.yaml
COPY configs/config.example.yaml /etc/go-firewall/config.yaml
USER nonroot:nonroot
EXPOSE 8080 8443 9090 9091
ENTRYPOINT ["/go-firewall"]
CMD ["-config", "/etc/go-firewall/config.yaml"]
