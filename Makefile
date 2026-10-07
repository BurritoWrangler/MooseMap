# MooseMap — build & run shortcuts.
#
# MooseMap is a native desktop application. Common flow on a fresh Kali VM:
#   make setup     # install scanning tools, Rust, Node, and desktop deps
#   make build     # build the standalone desktop app (.deb / AppImage)
#   make run       # launch the app in a native window
#
# Advanced: `make headless` runs the server-only mode for remote/SSH use.
#
# Authorized use only. Only scan assets you are permitted to test.

CARGO    ?= cargo
NPM      ?= npm
FRONTEND := frontend
ADDR     ?= 127.0.0.1:8080

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Install scanning tools, Rust, Node, and desktop-app deps (Kali/Debian)
	./scripts/setup-kali.sh --desktop

# --- The desktop app (primary) ------------------------------------------------

.PHONY: build
build: ## Build the standalone desktop app bundle (.deb / AppImage)
	@$(MAKE) app-icons || echo "continuing with existing icons"
	$(CARGO) tauri build

.PHONY: install
install: ## Build AND install the app (.deb) so it appears in the applications menu
	./scripts/install-app.sh

.PHONY: install-appimage
install-appimage: ## Build AND install the portable AppImage (user-level, no sudo)
	./scripts/install-app.sh --appimage

.PHONY: uninstall
uninstall: ## Remove the installed MooseMap app (.deb and/or AppImage)
	./scripts/install-app.sh --uninstall

.PHONY: run
run: ## Launch MooseMap in a native window
	@if [ -x target/release/moosemap-desktop ]; then \
	  target/release/moosemap-desktop; \
	else \
	  echo "no release build found; launching via cargo (debug)…"; \
	  $(CARGO) run -p moosemap-desktop; \
	fi

.PHONY: dev
dev: ## Run the desktop app in dev mode (hot-reload GUI in a native window)
	$(CARGO) tauri dev

.PHONY: app-icons
app-icons: ## Regenerate app icons from assets/moosemap.svg
	@$(CARGO) tauri --version >/dev/null 2>&1 || { \
	  echo "tauri-cli not found; run: make setup  (or ./scripts/setup-kali.sh --desktop)"; exit 1; }
	$(CARGO) tauri icon assets/moosemap.svg --output src-tauri/icons

# --- Advanced: headless / server mode (no window; for remote/SSH use) ---------

.PHONY: headless
headless: frontend ## Run the server only (browser GUI at http://ADDR; for remote use)
	$(CARGO) run -p moosemap-cli -- serve --addr $(ADDR)

.PHONY: frontend
frontend: ## Build the web GUI into frontend/dist (used by headless mode)
	@if ! command -v $(NPM) >/dev/null 2>&1; then \
	  echo "npm not found — run 'make setup' to install Node.js"; exit 1; \
	fi
	cd $(FRONTEND) && $(NPM) install && $(NPM) run build

# --- Diagnostics & housekeeping -----------------------------------------------

.PHONY: doctor
doctor: ## Check which scanning tools are installed and resolve correctly
	$(CARGO) run -q -p moosemap-cli -- tools

.PHONY: test
test: ## Run the full Rust test suite
	$(CARGO) test --workspace

.PHONY: lint
lint: ## Type-check the frontend (requires Node)
	cd $(FRONTEND) && $(NPM) run lint

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
	rm -rf $(FRONTEND)/dist $(FRONTEND)/node_modules src-tauri/gen
