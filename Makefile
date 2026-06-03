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

# The TUI package `symcrypt-tui` builds a binary of the same name.
TUI_PKG         := symcrypt-tui
TUI_BIN         := symcrypt-tui
TUI_MAN1        := docs/symcrypt-tui.1
TUI_RELEASE_BIN := target/release/$(TUI_BIN)

# The GTK package `symcrypt-gtk` builds a binary of the same name. A desktop
# GUI has no man page; instead it ships a .desktop entry, an icon, and AppStream
# metainfo into the usual XDG data directories.
GTK_PKG         := symcrypt-gtk
GTK_BIN         := symcrypt-gtk
GTK_RELEASE_BIN := target/release/$(GTK_BIN)
GTK_DESKTOP     := data/org.symcrypt.Gtk.desktop
GTK_ICON        := data/icons/hicolor/scalable/apps/org.symcrypt.Gtk.svg
GTK_METAINFO    := data/org.symcrypt.Gtk.metainfo.xml
APPDIR          := $(PREFIX)/share/applications
ICONDIR         := $(PREFIX)/share/icons/hicolor/scalable/apps
METAINFODIR     := $(PREFIX)/share/metainfo

# Extra arguments passed through to `make run` and `make e2e`, e.g.
# `make run ARGS="-e file.txt"` or `make e2e ARGS="-n /round_trip/"`.
ARGS ?=

# Packaging with nfpm (https://nfpm.goreleaser.com): one .deb and one .rpm per
# binary. VERSION is read from the workspace manifest; ARCH uses nfpm's Go-style
# names (amd64, arm64) and is mapped to the right label for each format. Both are
# exported so the configs in packaging/ can reference them via $${VERSION}/$${ARCH}.
NFPM        ?= nfpm
DISTDIR     ?= dist
ARCH        ?= amd64
VERSION     := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
PKG_CONFIGS := packaging/nfpm-cli.yaml packaging/nfpm-tui.yaml packaging/nfpm-gtk.yaml
export VERSION
export ARCH

.DEFAULT_GOAL := help

.PHONY: all build release check test e2e lint fmt fmt-check ci doc run run-tui run-gtk install install-tui install-gtk uninstall uninstall-tui uninstall-gtk package package-deb package-rpm check-nfpm clean help

all: build ## Build the whole workspace (alias for `build`)

build: ## Build the whole workspace (debug)
	$(CARGO) build

release: ## Build the whole workspace (optimized)
	$(CARGO) build --release

check: ## Type-check the workspace without producing binaries
	$(CARGO) check --all-targets

test: ## Run the full test suite
	$(CARGO) test

e2e: ## Run the end-to-end CLI test suite (tests/e2e); pass ARGS="..."
	tests/e2e/run.sh $(ARGS)

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

run-tui: ## Run the symcrypt-tui terminal app
	$(CARGO) run -p $(TUI_PKG)

run-gtk: ## Run the symcrypt-gtk desktop app (needs GTK4 + libadwaita)
	$(CARGO) run -p $(GTK_PKG)

install: ## Install the symcrypt binary and man page under PREFIX (default /usr/local)
	$(CARGO) build --release -p $(CLI_PKG)
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	$(INSTALL) -m 0755 "$(RELEASE_BIN)" "$(DESTDIR)$(BINDIR)/$(BIN)"
	$(INSTALL) -d "$(DESTDIR)$(MAN1DIR)"
	$(INSTALL) -m 0644 "$(MAN1)" "$(DESTDIR)$(MAN1DIR)/$(BIN).1"

install-tui: ## Install the symcrypt-tui binary and man page under PREFIX
	$(CARGO) build --release -p $(TUI_PKG)
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	$(INSTALL) -m 0755 "$(TUI_RELEASE_BIN)" "$(DESTDIR)$(BINDIR)/$(TUI_BIN)"
	$(INSTALL) -d "$(DESTDIR)$(MAN1DIR)"
	$(INSTALL) -m 0644 "$(TUI_MAN1)" "$(DESTDIR)$(MAN1DIR)/$(TUI_BIN).1"

install-gtk: ## Install the symcrypt-gtk binary, .desktop, icon, and metainfo under PREFIX
	$(CARGO) build --release -p $(GTK_PKG)
	$(INSTALL) -d "$(DESTDIR)$(BINDIR)"
	$(INSTALL) -m 0755 "$(GTK_RELEASE_BIN)" "$(DESTDIR)$(BINDIR)/$(GTK_BIN)"
	$(INSTALL) -d "$(DESTDIR)$(APPDIR)"
	$(INSTALL) -m 0644 "$(GTK_DESKTOP)" "$(DESTDIR)$(APPDIR)/org.symcrypt.Gtk.desktop"
	$(INSTALL) -d "$(DESTDIR)$(ICONDIR)"
	$(INSTALL) -m 0644 "$(GTK_ICON)" "$(DESTDIR)$(ICONDIR)/org.symcrypt.Gtk.svg"
	$(INSTALL) -d "$(DESTDIR)$(METAINFODIR)"
	$(INSTALL) -m 0644 "$(GTK_METAINFO)" "$(DESTDIR)$(METAINFODIR)/org.symcrypt.Gtk.metainfo.xml"

uninstall: ## Remove the installed binary and man page
	rm -f "$(DESTDIR)$(BINDIR)/$(BIN)"
	rm -f "$(DESTDIR)$(MAN1DIR)/$(BIN).1"

uninstall-tui: ## Remove the installed symcrypt-tui binary and man page
	rm -f "$(DESTDIR)$(BINDIR)/$(TUI_BIN)"
	rm -f "$(DESTDIR)$(MAN1DIR)/$(TUI_BIN).1"

uninstall-gtk: ## Remove the installed symcrypt-gtk binary, .desktop, icon, and metainfo
	rm -f "$(DESTDIR)$(BINDIR)/$(GTK_BIN)"
	rm -f "$(DESTDIR)$(APPDIR)/org.symcrypt.Gtk.desktop"
	rm -f "$(DESTDIR)$(ICONDIR)/org.symcrypt.Gtk.svg"
	rm -f "$(DESTDIR)$(METAINFODIR)/org.symcrypt.Gtk.metainfo.xml"

package: package-deb package-rpm ## Build .deb and .rpm packages for every binary (needs nfpm)

package-deb: release check-nfpm | $(DISTDIR) ## Build the .deb packages into DISTDIR (needs nfpm)
	@for cfg in $(PKG_CONFIGS); do \
		echo "  nfpm  $${cfg}  ->  deb"; \
		$(NFPM) package --config "$${cfg}" --packager deb --target "$(DISTDIR)"; \
	done

package-rpm: release check-nfpm | $(DISTDIR) ## Build the .rpm packages into DISTDIR (needs nfpm)
	@for cfg in $(PKG_CONFIGS); do \
		echo "  nfpm  $${cfg}  ->  rpm"; \
		$(NFPM) package --config "$${cfg}" --packager rpm --target "$(DISTDIR)"; \
	done

check-nfpm:
	@command -v $(NFPM) >/dev/null 2>&1 || { \
		echo "error: '$(NFPM)' not found on PATH."; \
		echo "       Install nfpm: https://nfpm.goreleaser.com/install/"; \
		exit 1; }

$(DISTDIR):
	mkdir -p "$(DISTDIR)"

clean: ## Remove build artifacts (cargo clean) and built packages
	$(CARGO) clean
	rm -rf "$(DISTDIR)"

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "symcrypt — available targets:\n\n"} \
		/^[a-zA-Z0-9_-]+:.*## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' \
		$(MAKEFILE_LIST)
	@printf "\nPaths: PREFIX=%s  BINDIR=%s  MAN1DIR=%s\n" "$(PREFIX)" "$(BINDIR)" "$(MAN1DIR)"
	@printf "       APPDIR=%s\n       ICONDIR=%s\n       METAINFODIR=%s\n" "$(APPDIR)" "$(ICONDIR)" "$(METAINFODIR)"
	@printf "\nPackaging: VERSION=%s  ARCH=%s  DISTDIR=%s  (needs nfpm)\n" "$(VERSION)" "$(ARCH)" "$(DISTDIR)"
