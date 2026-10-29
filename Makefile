CARGO ?= cargo

.PHONY: clients clients-check clients-smoke schema-compat schema-compat-selftest build test lint format format-check contract audit test-linux-arm64 build-linux-x86_64 run build-citadel test-citadel
build: lint ; $(CARGO) build --workspace
test: lint ; $(CARGO) test --workspace
lint: format-check ; $(CARGO) clippy --workspace --all-targets -- -D warnings
format: ; $(CARGO) fmt --all
format-check: ; $(CARGO) fmt --all --check
# The contract (E10.1, E1-05.1): api/openapi.json, events.schema.json, runner.schema.json; `make test` fails while openapi.json is stale.
contract: ; scripts/contract.sh api
# Generated clients (E1-05): Swift, Kotlin, C#, TS under clients/*/generated; generators are pinned in
# scripts/contract-swift.sh and scripts/contract-clients.sh. Swift also runs its fixture-decode tests.
clients: ; scripts/contract-swift.sh clients && scripts/contract-clients.sh gen clients
clients-check: ; scripts/clients-check.sh
clients-smoke: ; scripts/contract-clients.sh smoke clients && cd clients/swift && swift test
# Additive-only gate (E1-05.4): api/ against the newest v* tag, else origin/development. The selftest
# proves it on mutations of the contract (needs Docker, so it is not part of `make test`).
schema-compat: ; scripts/schema-compat.sh
schema-compat-selftest: ; scripts/schema-compat-selftest.sh
# Supply chain (E1-01.3): advisories, licences, bans, sources; see deny.toml.
audit: ; $(CARGO) deny check
# Linux runs in Docker with the pinned toolchain (E1-01.4). Colima/Docker on Apple silicon runs arm64 natively.
RUST_IMAGE ?= rust:1.99.1
DOCKER_RUN = docker run --rm -v $(CURDIR):/src -w /src -e CARGO_TARGET_DIR=/cache/target -v ainkrad-core-cargo:/usr/local/cargo/registry -v ainkrad-core-target-$(1):/cache
test-linux-arm64: ; $(call DOCKER_RUN,arm64) --platform linux/arm64 $(RUST_IMAGE) sh -c 'rustup show >/dev/null && cargo test --workspace'
build-linux-x86_64: ; $(call DOCKER_RUN,amd64) --platform linux/amd64 $(RUST_IMAGE) sh -c 'rustup show >/dev/null && cargo build --workspace'
# The parked Citadel monolith (P1.11), its own workspace; not part of `build`/`test`.
CITADEL = --manifest-path modules/citadel/Cargo.toml --workspace
build-citadel: ; $(CARGO) build $(CITADEL)
test-citadel: ; $(CARGO) test $(CITADEL)
# Local run (E1-01.5): loopback only, state in ./state (gitignored); `Run/run.sh run` comes here.
run: ; mkdir -p state && $(CARGO) run -p ainkrad-core-server -- serve state/core.db
