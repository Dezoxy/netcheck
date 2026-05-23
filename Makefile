BIN_DIR := bin
BINARY  := $(BIN_DIR)/netcheck
PKG     := .
ARGS    ?=
WEB_DIR := web

# VERSION is auto-derived from git for local builds. `make build VERSION=...`
# overrides. goreleaser sets its own value via ldflags in .goreleaser.yml.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X netcheck/cmd.Version=$(VERSION)

.DEFAULT_GOAL := build

.PHONY: app build run verify install uninstall fmt vet test coverage clean web-build winres help

## app: build the React assets + Go binary, then run the local web app
# Leaves ./bin/netcheck behind so you can re-run without rebuilding next time.
app: web-build build
	./$(BINARY) app $(ARGS)

## build: compile the binary into ./bin/ (version stamped from git describe)
build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## run: build, then run with ARGS="..." (e.g. make run ARGS="route google.com")
run: build
	./$(BINARY) $(ARGS)

## verify: format check, vet, build, and print version
verify: fmt vet build
	./$(BINARY) version

## install: install into $GOBIN (or ~/go/bin), so `netcheck` is on PATH
install:
	go install -ldflags "$(LDFLAGS)" $(PKG)
	@echo "Installed to $$(go env GOBIN 2>/dev/null || echo $$(go env GOPATH)/bin)/netcheck"
	@echo "Ensure that directory is on your PATH."

## uninstall: remove the installed binary from $GOBIN / ~/go/bin
uninstall:
	@bin="$$(go env GOBIN)"; \
	if [ -z "$$bin" ]; then bin="$$(go env GOPATH)/bin"; fi; \
	rm -f "$$bin/netcheck" && echo "Removed $$bin/netcheck"

## fmt: gofmt the source tree (fails if anything needs formatting)
fmt:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

## vet: run go vet
vet:
	go vet ./...

## test: run go test
test:
	go test ./...

## coverage: run tests with coverage and print a per-package summary
coverage:
	go test -coverprofile=coverage.out ./...
	@echo
	@go tool cover -func=coverage.out | tail -30

## web-build: rebuild the embedded React/PWA assets (npm ci only if needed)
# Two-step pattern so we don't pay the ~15s npm-ci cost on every build:
#   - $(WEB_NM) (web/node_modules) is rebuilt only when package-lock.json
#     changes — npm ci refuses to mutate the lockfile, so this stays clean.
#   - vite always rebuilds (it's fast, ~1s, and outputs to internal/webui/dist
#     which Go embeds at compile time).
WEB_NM := $(WEB_DIR)/node_modules/.install-stamp

$(WEB_NM): $(WEB_DIR)/package-lock.json $(WEB_DIR)/package.json
	cd $(WEB_DIR) && npm ci
	@mkdir -p $(WEB_DIR)/node_modules && touch $(WEB_NM)

web-build: $(WEB_NM)
	cd $(WEB_DIR) && npm run build
	@# Defensive sweep: vite's emptyOutDir handles its own clean, but macOS
	@# Finder / iCloud Drive can drop "index 2.html" style conflict copies
	@# into internal/webui/dist after the fact. Those get embedded into the
	@# binary via go:embed, so clear them here.
	@find internal/webui/dist -type f -name '* [0-9].*' -delete 2>/dev/null || true

## winres: generate Windows version-info .syso files for amd64 and arm64
winres:
	@command -v go-winres >/dev/null 2>&1 || go install github.com/tc-hib/go-winres@latest
	go-winres make --arch amd64,arm64 --file-version git-tag --product-version git-tag

## clean: remove bin/, coverage, and generated .syso files
clean:
	rm -rf $(BIN_DIR) coverage.out
	rm -f rsrc_windows_*.syso

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/^## /  /'
