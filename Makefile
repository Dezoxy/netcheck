BIN_DIR := bin
BINARY  := $(BIN_DIR)/netcheck
PKG     := .
ARGS    ?=

# VERSION is auto-derived from git for local builds. `make build VERSION=...`
# overrides. goreleaser sets its own value via ldflags in .goreleaser.yml.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X netcheck/cmd.Version=$(VERSION)

.DEFAULT_GOAL := build

.PHONY: build run verify install uninstall fmt vet test coverage clean help

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

## clean: remove the local bin/ directory and coverage artifacts
clean:
	rm -rf $(BIN_DIR) coverage.out

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/^## /  /'
