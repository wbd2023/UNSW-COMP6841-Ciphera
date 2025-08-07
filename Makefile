SHELL := /usr/bin/env bash
GO ?= go

# Detect host OS from Go's view (more reliable than uname on some shells)
GOOS := $(shell $(GO) env GOOS)
ifeq ($(GOOS),windows)
$(error This Makefile targets Linux/macOS. On Windows, use WSL or Git Bash, or use the instructions in the README)
endif

BIN_DIR := bin
CIPHERA := $(BIN_DIR)/ciphera
RELAY   := $(BIN_DIR)/relay
PKGS := ./...

# Tool availability
HAVE_PKILL := $(shell command -v pkill >/dev/null 2>&1 && echo yes || echo no)

.PHONY: all build clean fmt vet lint tidy test-go test-bash relay run-relay stop-relay print-platform

all: build

print-platform:
	@echo "GOOS=$(GOOS)"

build: ## Build ciphera and relay
	@mkdir -p "$(BIN_DIR)"
	$(GO) build -mod=vendor -o "$(CIPHERA)" ./cmd/ciphera
	$(GO) build -mod=vendor -o "$(RELAY)"   ./cmd/relay

clean: ## Remove build artefacts
	rm -rf "$(BIN_DIR)"

fmt: ## go fmt
	$(GO) fmt $(PKGS)

vet: ## go vet
	$(GO) vet $(PKGS)

lint: ## golangci-lint if available
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install with: make install-lint"; \
	fi

install-lint: ## Install golangci-lint
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | \
		sh -s -- -b "$$(go env GOPATH)/bin" v1.58.0
	@echo "Ensure $$GOPATH/bin is on your PATH."

tidy: ## go mod tidy
	$(GO) mod tidy

test-go: ## Run all Go unit tests (*_test.go)
	# $(GO) test ./...

test-bash: build ## Run all Bash test scripts
	set -e; \
	for f in ./scripts/tests/*.sh; do \
		echo ""; \
		echo "---------- Running $$f ----------"; \
		bash "$$f"; \
		echo "--------------------------------------------------"; \
	done

relay: build ## Build only relay
	@:

run-relay: build ## Start relay in background
	@# Stop any running relay (pkill if available, otherwise pgrep+kill)
	@if [ "$(HAVE_PKILL)" = "yes" ]; then \
		pkill -f "$(RELAY)" >/dev/null 2>&1 || true; \
	else \
		pgrep -f "$(RELAY)" 2>/dev/null | xargs -r kill || true; \
	fi
	@"$(RELAY)" > /tmp/ciphera-relay.log 2>&1 & \
	 echo $$! > /tmp/ciphera-relay.pid; \
	 echo "Relay started (pid $$(cat /tmp/ciphera-relay.pid)) at http://127.0.0.1:8080"

stop-relay: ## Stop background relay
	@if [ -f /tmp/ciphera-relay.pid ]; then \
		kill "$$(cat /tmp/ciphera-relay.pid)" >/dev/null 2>&1 || true; \
		rm -f /tmp/ciphera-relay.pid; \
		echo "Relay stopped"; \
	else \
		echo "No relay pid file found"; \
	fi
