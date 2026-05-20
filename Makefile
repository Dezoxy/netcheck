BIN_DIR := bin
BINARY  := $(BIN_DIR)/netcheck
PKG     := .
ARGS    ?=

.DEFAULT_GOAL := build

.PHONY: build run verify install uninstall fmt vet test clean help

## build: compile the binary into ./bin/
build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BINARY) $(PKG)

## run: build, then run with ARGS="..." (e.g. make run ARGS="route google.com")
run: build
	./$(BINARY) $(ARGS)

## verify: format check, vet, build, and print version
verify: fmt vet build
	./$(BINARY) version

## install: install into $GOBIN (or ~/go/bin), so `netcheck` is on PATH
install:
	go install $(PKG)
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

## clean: remove the local bin/ directory
clean:
	rm -rf $(BIN_DIR)

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/^## /  /'
