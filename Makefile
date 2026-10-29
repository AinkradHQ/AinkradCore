CARGO ?= cargo

.PHONY: build test lint format format-check contract e2e e2e-b audit test-linux-arm64 build-linux-x86_64
build: lint ; $(CARGO) build --workspace
test: lint ; $(CARGO) test --workspace
lint: format-check ; $(CARGO) clippy --workspace --all-targets -- -D warnings
format: ; $(CARGO) fmt --all
format-check: ; $(CARGO) fmt --all --check
# The client API contract (E10.1); `make test` fails while api/openapi.json is stale.
contract: ; mkdir -p api && $(CARGO) run -q -p ainkrad-core-server -- openapi > api/openapi.json
# The Phase A end-to-end run with a real harness (HARNESS=opencode|claude); see scripts/e2e.sh.
e2e: ; scripts/e2e.sh
# Phase B end-to-end: scripted agents, then OpenCode as the developer; see scripts/e2e-b.sh.
e2e-b: ; scripts/e2e-b.sh
# Supply chain (E1-01.3): advisories, licences, bans, sources; see deny.toml.
audit: ; $(CARGO) deny check
# Linux runs in Docker with the pinned toolchain (E1-01.4). Colima/Docker on Apple silicon runs arm64 natively.
RUST_IMAGE ?= rust:1.99.1
DOCKER_RUN = docker run --rm -v $(CURDIR):/src -w /src -e CARGO_TARGET_DIR=/cache/target -v ainkrad-core-cargo:/usr/local/cargo/registry -v ainkrad-core-target-$(1):/cache
test-linux-arm64: ; $(call DOCKER_RUN,arm64) --platform linux/arm64 $(RUST_IMAGE) sh -c 'rustup show >/dev/null && cargo test --workspace'
build-linux-x86_64: ; $(call DOCKER_RUN,amd64) --platform linux/amd64 $(RUST_IMAGE) sh -c 'rustup show >/dev/null && cargo build --workspace'
