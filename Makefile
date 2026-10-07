# MooseMap — build & run shortcuts.
#
# Common flow on a fresh Kali VM:
#   make setup     # install scanning tools, Rust, Node
#   make build     # build the GUI + release binary
#   make run       # launch the server and open the GUI
#
# Authorized use only. Only scan assets you are permitted to test.

CARGO    ?= cargo
NPM      ?= npm
BIN      := target/release/moosemap
FRONTEND := frontend
ADDR     ?= 127.0.0.1:8080

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: setup
setup: ## Install scanning tools, Rust, and Node (Kali/Debian)
	./scripts/setup-kali.sh

.PHONY: frontend
frontend: ## Build the web GUI into frontend/dist
	@if ! command -v $(NPM) >/dev/null 2>&1; then \
	  echo "npm not found — install Node.js (make setup) to build the GUI"; exit 1; \
	fi
	cd $(FRONTEND) && $(NPM) install && $(NPM) run build

.PHONY: build
build: frontend ## Build the GUI and the release binary
	$(CARGO) build --release

.PHONY: run
run: ## Run the server (serves the GUI, opens a browser)
	@if [ ! -f "$(BIN)" ]; then \
	  echo "release binary not built; running via cargo (debug)"; \
	  $(CARGO) run -p moosemap-cli -- serve --addr $(ADDR); \
	else \
	  $(BIN) serve --addr $(ADDR); \
	fi

.PHONY: install-desktop
install-desktop: ## Add MooseMap to the applications menu (icon + launcher)
	./scripts/install-desktop.sh

.PHONY: uninstall-desktop
uninstall-desktop: ## Remove the applications-menu entry
	./scripts/install-desktop.sh --uninstall

.PHONY: dev
dev: ## Run backend (cargo) + frontend dev server; use two terminals
	@echo "Terminal 1:  $(CARGO) run -p moosemap-cli -- serve"
	@echo "Terminal 2:  cd $(FRONTEND) && $(NPM) run dev   # http://localhost:5173"

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
	rm -rf $(FRONTEND)/dist $(FRONTEND)/node_modules
