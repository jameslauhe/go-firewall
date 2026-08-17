VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X github.com/jameslauhe/go-firewall/internal/version.Version=$(VERSION) -X github.com/jameslauhe/go-firewall/internal/version.Commit=$(COMMIT)

.PHONY: build test lint fmt vet docker run clean

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/go-firewall ./cmd/go-firewall

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -l -w .

vet:
	go vet ./...

docker:
	docker build -f build/package/Dockerfile --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t go-firewall:$(VERSION) .

run: build
	./bin/go-firewall -config configs/config.example.yaml

clean:
	rm -rf bin/
