# AinkradCore — Agent Guide

Server-first core of Ainkrad: one Rust binary that owns state and work; every UI is a thin client.
Started 2026-10-28 as a **fresh repo** (no Citadel history, no Citadel data) from a one-time source
snapshot of `AinkradHQ/AinkradCitadel` `f314b36`. Plans, decisions and Jira live in the project docs,
not here.

## Read first

1. `~/Home/Projects/Ainkrad/Docs/MEMORY.md`, then `Docs/Plans/2026-10-28-ainkrad-core-plan.md`.
2. The phase plan you are working on: `Docs/Plans/2026-10-28-ainkrad-core-e1-plan.md` (E1) or `…-e2-plan.md` (E2).
   Every item has an ID (`E1-07`) that is the prefix of its Jira summary (project `KAN`).
3. `Docs/Specs/2026-10-28-ainkrad-core-adr.md` — decisions D1–D10.

## Layout

`crates/core` (platform primitives: ids, audit, device keys, settings registry) · `crates/server`
(`ainkrad-core-server`, the platform: client API gate, device keys and pairing, rate limits, events, audit, settings,
store and backup, push transport, scheduler, `Module` mounting; one fresh migration baseline `core_0001`) ·
`crates/runner` (`ainkrad-runner`) · `crates/harness` · `crates/proto` · `crates/providers` · `api/` (generated
OpenAPI, committed) · `scripts/`. The run engine, MCP server and runner hub are not in the Core yet: runners
reconnect through the hub rebuilt in E1-11.

`modules/citadel/{core,server}` (`citadel-core`, `citadel-server`) is a **parked, complete copy** of the Citadel
monolith (P1.11), kept as the reference for the Citadel port (E2-13). It is its own cargo workspace, excluded
from the Core one, and shares `crates/{proto,harness,providers,runner}` by path. Build and test it with
`make build-citadel` / `make test-citadel`; neither is part of `make build`/`make test`. Its contract is
`modules/citadel/api/openapi.json`. No Core crate may depend on anything under `modules/` (`crates/server/tests/dependency_direction.rs`).

## Rules

- **No documentation in this repo** — docs go to `Docs/<bucket>/` of the Ainkrad project. Only this file
  and `CLAUDE.md` live here.
- Gates before any report: `make build` (fmt check + clippy `-D warnings` + build) and `make test`; `make contract`
  after any API change (then the schema workflow below). Linux arm64: `make test-linux-arm64`.
- **Schema workflow** (E1-05; the contract is `api/openapi.json` + `events.schema.json` + `runner.schema.json`, and
  `clients/{swift,kotlin,csharp,ts}/generated`, all committed). To add or change an endpoint:
  1. Change the Rust type and `#[utoipa::path]`, register it in `crates/server/src/api/v1.rs` (route) and `api/v1/spec.rs` (paths);
     an event or runner type needs `schemars::JsonSchema` too. Bump `API_MINOR` (`api/v1/types.rs`) for any change.
     Declare its scope in `api/v1/scopes.rs` `ROUTES` (deny by default); a route that deletes, widens access or weakens
     security also goes in `DESTRUCTIVE` (a module's in `Module::destructive`): it then needs a step-up and the contract
     marks it `x-ainkrad-destructive: true`.
  2. `make contract`, then `make clients` (needs Docker; the Swift generator builds once into `~/.cache/ainkrad-core-tools`).
  3. `make schema-compat` (vs the newest `v*` tag, else `origin/development`): fails on a removed/narrowed/newly required
     field. New response fields are `Option` / not in `required`.
  4. `make test`, `make clients-check`, `make clients-smoke`; commit the Rust change and all generated output together.
  Generator versions are pinned in `scripts/contract-swift.sh` and `scripts/contract-clients.sh`; `make schema-compat-selftest` proves the gate.
- Workspace is edition 2024 with `unsafe_code = forbid`. The one future exception is `crates/sys` (E2-09.1).
- PRs target `development`; never commit to `main`/`staging`/`development` directly (the first commit is the
  only exception). Merge commits, never squash or rebase; delete the branch after merge. **Merging needs an
  explicit instruction.**
- Conventional Commits with a scope, prose subjects. **No AI/tool attribution** in commits or PRs.
- No secrets in the repo; schema changes are additive-only within a major; new response fields are `required = false`.
- Toolchain: `rust-toolchain.toml` pins 1.99.1. If `cargo` is not on `PATH`, use
  `~/.rustup/toolchains/1.99.1-aarch64-apple-darwin/bin`.
- Under zsh use `bash -c` for loops; assert every scripted replacement matched.
