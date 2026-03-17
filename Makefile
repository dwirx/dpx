BINARY ?= dpx
PKG ?= ./cmd/dpx
DIST_DIR ?= dist
VERSION ?= dev

.PHONY: build test release clean

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) $(PKG)

test:
	go test ./...

release:
	VERSION=$(VERSION) DIST_DIR=$(DIST_DIR) ./scripts/release.sh

clean:
	rm -rf $(BINARY) dopx $(DIST_DIR)
