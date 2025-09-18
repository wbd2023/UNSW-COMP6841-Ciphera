SHELL := /usr/bin/env bash
GO    ?= go

# Platform info
GOOS   := $(shell $(GO) env GOOS)
GOARCH := $(shell $(GO) env GOARCH)

# Warn (don’t hard fail) on native Windows shells
ifeq ($(OS),Windows_NT)
  $(warning This Makefile targets Linux/macOS. On Windows, prefer WSL or Git-Bash.)
endif

# Paths and binaries
BIN_DIR := bin
CIPHERA := $(BIN_DIR)/ciphera
RELAY   := $(BIN_DIR)/relay

# Expand packages via 'go list' to avoid vendor surprises
PKGS := $(shell $(GO) list ./...)

# Environment checks and module mode
HAVE_PKILL  := $(shell command -v pkill >/dev/null 2>&1 && echo yes || echo no)
HAVE_VENDOR := $(shell [ -d vendor ] && echo yes || echo no)
MODFLAG     := $(if $(filter yes,$(HAVE_VENDOR)),-mod=vendor,)

# Optional flags
GOFLAGS   ?=
LDFLAGS   ?=
TESTFLAGS ?= -race -shuffle=on -count=1

.PHONY: all help print-platform \
        fmt vet lint install-lint tidy \
        build \
        test test-go test-bash \
        run-relay stop-relay \
        clean

# Default goal
all: build

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "}; /^[a-zA-Z0-9_.-]+:.*?## / {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

print-platform:
	@echo "GOOS=$(GOOS) GOARCH=$(GOARCH)"

# Code quality
fmt: ## go fmt
	$(GO) fmt $(PKGS)

vet: ## go vet
	$(GO) vet $(PKGS)

lint: ## golangci-lint (optional)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found. Run: make install-lint"; \
	fi

install-lint: ## Install golangci-lint
	@curl -sSfL https://raw.githubusercontent.com/golangci-lint/golangci-lint/master/install.sh | \
		sh -s -- -b "$$($(GO) env GOPATH)/bin" v1.58.0

# Dependency management
tidy: ## go mod tidy
	$(GO) mod tidy

# Build
build: ## Build ciphera and relay
	@mkdir -p "$(BIN_DIR)"
	$(GO) build $(GOFLAGS) $(MODFLAG) -ldflags '$(LDFLAGS)' -o "$(CIPHERA)" ./cmd/ciphera
	$(GO) build $(GOFLAGS) $(MODFLAG) -ldflags '$(LDFLAGS)' -o "$(RELAY)"   ./cmd/relay

# Tests
test: test-go test-bash ## Run all tests

test-go: ## Run Go unit tests
	$(GO) test $(TESTFLAGS) ./...

test-bash: build ## Run Bash integration scripts
	@set -e; \
	for f in ./scripts/tests/*.sh; do \
		echo ""; \
		echo "---------- Running $$f ----------"; \
		bash "$$f"; \
		echo "--------------------------------------------------"; \
	done

# Runtime helpers
run-relay: build ## Start relay in background
	@if [ "$(HAVE_PKILL)" = "yes" ]; then \
		pkill -f "$(RELAY)" >/dev/null 2>&1 || true; \
	else \
		pids=$$(pgrep -f "$(RELAY)" || true); \
		[ -z "$$pids" ] || kill $$pids >/dev/null 2>&1 || true; \
	fi
	@nohup "$(RELAY)" > /tmp/ciphera-relay.log 2>&1 & \
	 echo $$! > /tmp/ciphera-relay.pid; \
	 echo "Relay started (pid $$(cat /tmp/ciphera-relay.pid)) at http://127.0.0.1:8080"

stop-relay: ## Stop relay if running
	@if [ -f /tmp/ciphera-relay.pid ]; then \
		kill "$$(cat /tmp/ciphera-relay.pid)" >/dev/null 2>&1 || true; \
		rm -f /tmp/ciphera-relay.pid; \
		echo "Relay stopped"; \
	else \
		echo "No relay running"; \
	fi

# Clean-up
clean: ## Remove build artefacts and relay state
	rm -rf "$(BIN_DIR)"
	rm -f /tmp/ciphera-relay.pid /tmp/ciphera-relay.log
