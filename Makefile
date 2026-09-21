BIN_DIR := bin
BINARY  := $(BIN_DIR)/netcheck
PKG     := .
ARGS    ?=
WEB_DIR := web

# VERSION is auto-derived from git for local builds. `make build VERSION=...`
# overrides. goreleaser sets its own value via ldflags in .goreleaser.yml.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/Dezoxy/netcheck/cmd.Version=$(VERSION)

.DEFAULT_GOAL := build

.PHONY: app build run verify install uninstall fmt vet test coverage clean web-build winres help

## app: clean previous build, rebuild React assets + Go binary, run the local web app
# `clean` runs first so the embedded UI bundle is always a fresh build — no
# chance of serving a stale `internal/webui/dist` from a previous run. The
# Go build cache lives outside ./bin (in $GOCACHE) so the rebuild is still
# fast despite the wipe.
app: clean web-build build
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

## clean: remove bin/, coverage, generated .syso files, and web build state
clean:
	rm -rf $(BIN_DIR) coverage.out
	rm -f rsrc_windows_*.syso
	rm -f $(WEB_DIR)/*.tsbuildinfo
	rm -rf $(WEB_DIR)/dist

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/^## /  /'

# ── Architecture (docs/architecture, from Dezoxy/architecture-base) ─────────
# Every target runs locally with Docker. Prefixed `arch-` because this Makefile
# already owns test, clean and help. The PDF workflow runs `make arch-pdf`, so
# these pins apply on GitHub too. STRUCTURIZR_IMAGE matches architecture-base
# and the sibling models (Hopin, Argus, Notification Digest); keep it equal to
# the Structurizr viewer you render this workspace in.
STRUCTURIZR_IMAGE ?= structurizr/structurizr:2026.09.19
# Pandoc with LaTeX and the Eisvogel template, for arch-pdf (~2 GB).
PANDOC_IMAGE      ?= pandoc/extra:3.11.0.0-debian
ARCH_DIR  ?= docs/architecture
GENERATED := $(ARCH_DIR)/generated
PORT      ?= 8080
STRUCTURIZR := docker run --rm -v "$(CURDIR)/$(ARCH_DIR):/w:ro"

.PHONY: arch-validate arch-inspect arch-check arch-docs arch-view arch-export arch-pdf arch-clean

## arch-validate: parse the architecture workspace with the pinned Structurizr image
arch-validate:
	$(STRUCTURIZR) $(STRUCTURIZR_IMAGE) validate -workspace /w/workspace.dsl

## arch-inspect: list model findings; fails on any ERROR line
arch-inspect:
	@out="$$($(STRUCTURIZR) $(STRUCTURIZR_IMAGE) inspect -workspace /w/workspace.dsl 2>&1)"; \
	printf '%s\n' "$$out"; \
	if printf '%s\n' "$$out" | grep -q 'ERROR'; then echo "inspect: errors found" >&2; exit 1; fi

## arch-check: arch-validate + arch-inspect; run before committing a model change
arch-check: arch-validate arch-inspect

## arch-docs: fail when documentation contradicts the tree (links, indexes, ADRs, views, IDs, headings, 80-col prose)
arch-docs:
	python3 scripts/check_docs_consistency.py

## arch-view: browse the model at http://localhost:8080/workspace/1 (PORT=... to change)
arch-view:
	docker run --rm -p $(PORT):8080 -v "$(CURDIR)/$(ARCH_DIR):/usr/local/structurizr" $(STRUCTURIZR_IMAGE) local

## arch-export: every view as SVG, PNG and Mermaid, plus workspace JSON, into docs/architecture/generated
arch-export:
	mkdir -p $(GENERATED)
	chmod 777 $(GENERATED)
	$(STRUCTURIZR) -v "$(CURDIR)/$(GENERATED):/out" $(STRUCTURIZR_IMAGE) export -workspace /w/workspace.dsl -format json -output /out
	$(STRUCTURIZR) -v "$(CURDIR)/$(GENERATED):/out" $(STRUCTURIZR_IMAGE) export -workspace /w/workspace.dsl -format mermaid -output /out
	$(STRUCTURIZR) -v "$(CURDIR)/$(GENERATED):/out" $(STRUCTURIZR_IMAGE)-playwright export -workspace /w/workspace.dsl -format svg -output /out
	$(STRUCTURIZR) -v "$(CURDIR)/$(GENERATED):/out" $(STRUCTURIZR_IMAGE)-playwright export -workspace /w/workspace.dsl -format png -output /out
	@echo "exported $$(ls $(GENERATED) | wc -l | tr -d ' ') files to $(GENERATED)"

## arch-pdf: the Documentation tab and every view as one PDF in docs/architecture/generated
arch-pdf:
	STRUCTURIZR_IMAGE=$(STRUCTURIZR_IMAGE) PANDOC_IMAGE=$(PANDOC_IMAGE) ARCH_DIR=$(ARCH_DIR) scripts/architecture-pdf.sh

## arch-clean: delete docs/architecture/generated (exports and PDFs; gitignored)
arch-clean:
	rm -rf $(GENERATED)
