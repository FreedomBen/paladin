# symcrypt — build, test, and install
#
# Thin wrapper over Cargo for the common developer and packaging tasks.
# `make` (no target) prints the auto-generated help below. Installation paths
# follow the usual GNU conventions and honour DESTDIR for staged/package builds.

PREFIX  ?= /usr/local
DESTDIR ?=
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man
MAN1DIR ?= $(MANDIR)/man1

CARGO   ?= cargo
INSTALL ?= install

# The CLI package `symcrypt-cli` builds a binary named `symcrypt`.
CLI_PKG     := symcrypt-cli
BIN         := symcrypt
MAN1        := crates/symcrypt-cli/symcrypt.1
RELEASE_BIN := target/release/$(BIN)

# Extra arguments for `make run`, e.g. `make run ARGS="-e file.txt"`.
ARGS ?=

.DEFAULT_GOAL := help

.PHONY: all build release check test lint fmt fmt-check ci doc run install uninstall clean help

all: build ## Build the whole workspace (alias for `build`)

build: ## Build the whole workspace (debug)
	$(CARGO) build

release: ## Build the whole workspace (optimized)
	$(CARGO) build --release

check: ## Type-check the workspace without producing binaries
	$(CARGO) check --all-targets

test: ## Run the full test suite
	$(CARGO) test

lint: ## Lint with clippy, treating warnings as errors
	$(CARGO) clippy --all-targets --all-features -- -D warnings

fmt: ## Format the source with rustfmt
	$(CARGO) fmt

fmt-check: ## Check formatting without modifying files
	$(CARGO) fmt --check

ci: fmt-check lint test ## Run the full CI gate: formatting, lint, and tests

doc: ## Build API documentation for the workspace crates
	$(CARGO) doc --no-deps

run: ## Run the symcrypt CLI; pass ARGS="..." for options
	$(CARGO) run -p $(CLI_PKG) -- $(ARGS)

install: ## Install the symcrypt binary and man page under PREFIX (default /usr/local)
	$(CARGO) build --release -p $(CLI_PKG)
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	$(INSTALL) -m 0755 "$(RELEASE_BIN)" "$(DESTDIR)$(BINDIR)/$(BIN)"
	$(INSTALL) -d "$(DESTDIR)$(MAN1DIR)"
	$(INSTALL) -m 0644 "$(MAN1)" "$(DESTDIR)$(MAN1DIR)/$(BIN).1"

uninstall: ## Remove the installed binary and man page
	rm -f "$(DESTDIR)$(BINDIR)/$(BIN)"
	rm -f "$(DESTDIR)$(MAN1DIR)/$(BIN).1"

clean: ## Remove build artifacts (cargo clean)
	$(CARGO) clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "symcrypt — available targets:\n\n"} \
		/^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' \
		$(MAKEFILE_LIST)
	@printf "\nPaths: PREFIX=%s  BINDIR=%s  MAN1DIR=%s\n" "$(PREFIX)" "$(BINDIR)" "$(MAN1DIR)"
