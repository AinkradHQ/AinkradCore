CARGO ?= cargo

.PHONY: perf test-web e1-exit e1-exit-faults soak clients clients-check clients-smoke schema-compat schema-compat-selftest build test lint format format-check contract audit test-linux-arm64 build-linux-x86_64 clean-linux run build-citadel test-citadel release-dry release-repro release-test fuzz-smoke audit-fuzz
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
# One build-cache volume PER CHECKOUT (named from the checkout's path). A volume shared between checkouts let cargo
# reuse another checkout's newer build of the same crate (git archive stamps files with the commit time, so the
# sources look older than the artifacts), which gave false passes and false failures. The registry cache is safe to share.
LINUX_VOL ?= ainkrad-core-target-$(shell printf %s '$(CURDIR)' | shasum | cut -c1-12)
DOCKER_RUN = docker run --rm -v $(CURDIR):/src -w /src -e CARGO_TARGET_DIR=/cache/target -v ainkrad-core-cargo:/usr/local/cargo/registry -v $(LINUX_VOL)-$(1):/cache
test-linux-arm64: ; $(call DOCKER_RUN,arm64) --platform linux/arm64 $(RUST_IMAGE) sh -c 'rustup show >/dev/null && cargo test --workspace'
build-linux-x86_64: ; $(call DOCKER_RUN,amd64) --platform linux/amd64 $(RUST_IMAGE) sh -c 'rustup show >/dev/null && cargo build --workspace'
# Frees this checkout's Linux build caches (they are several GB); run it when you are done with a checkout.
clean-linux: ; docker volume rm -f $(LINUX_VOL)-arm64 $(LINUX_VOL)-amd64
# A real browser with a virtual authenticator (E1-08.4): pairs, signs in, steps up, streams and is revoked over
# CDP. Not part of `test` (a browser is heavy). Chromium: $CHROME, else Playwright's cached chrome-headless-shell.
test-web: ; $(CARGO) test -p ainkrad-core-server --test web_passkey -- --ignored --nocapture
# The E1 exit gate (E1-14): the six steps against a Core the script starts (PASS/FAIL table), and the fault suite
# on the real binaries (Core kill -9 with a command in flight, runner kill + revoke, proxy cut, wrong Core, expired
# certificate, read-only database, stalled events client), one at a time. Neither is part of `test`.
e1-exit: ; $(CARGO) build -p ainkrad-core-server -p ainkrad-ctl -p ainkrad-runner && scripts/e1-exit.sh
e1-exit-faults: ; $(CARGO) test -p ainkrad-ctl --test it fault -- --ignored --test-threads=1 --nocapture
# Event bus soak (E1-04.5): 10k events/min to 20 clients, one stalled, for an hour; flat memory and
# only the stalled client closed. Not part of `test`. `CORE_SOAK_SECS=300 make soak` for five minutes.
soak: ; CORE_SOAK_SECS=$${CORE_SOAK_SECS:-3600} $(CARGO) test -p ainkrad-core-server --test soak -- --ignored --nocapture
# Performance budgets (E1-19.1): the real release binary on loopback, 200 clients; see crates/server/tests/perf.rs for the
# budgets. About three minutes of measuring after the build; `CORE_PERF_IDLE_SECS=10 make perf` shortens the idle windows.
perf: ; ulimit -n 4096 && $(CARGO) test --release -p ainkrad-core-server --test perf -- --ignored --nocapture
# The parked Citadel monolith (P1.11), its own workspace; not part of `build`/`test`.
CITADEL = --manifest-path modules/citadel/Cargo.toml --workspace
build-citadel: ; $(CARGO) build $(CITADEL)
test-citadel: ; $(CARGO) test $(CITADEL)
# Local run (E1-01.5): state in ./state (gitignored); `Run/run.sh run` comes here. The default listener is a
# Unix socket (state/core.sock); for HTTP on loopback use `make run LISTEN=loopback:7700`.
LISTEN ?= unix:state/core.sock
run: ; mkdir -p state && $(CARGO) run -p ainkrad-core-server -- serve state/core.db --listen $(LISTEN)
# Signed release pipeline (E1-15), DRY RUN only: builds, checksums, a throwaway-key signature, the macOS codesign check
# and the SBOM under dist/<version>/. It tags, notarises and publishes nothing. `RELEASE_TARGETS="linux-arm64"` picks targets
# (linux-x86_64 runs under emulation and is slow). `release-repro` builds twice from nothing and compares hashes.
release-dry: ; scripts/release/dry.sh
release-repro: ; scripts/release/repro.sh
release-test: ; scripts/release/test-install.sh
# Fuzzing (E1-17.2): its own workspace in fuzz/, nightly only, so `make build` never needs it.
fuzz-smoke: ; scripts/fuzz/run.sh $${FUZZ_SECS:-30}
audit-fuzz: ; $(CARGO) deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml check
