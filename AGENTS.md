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
  after any API change. Linux arm64: `make test-linux-arm64`.
- Workspace is edition 2024 with `unsafe_code = forbid`. The one future exception is `crates/sys` (E2-09.1).
- PRs target `development`; never commit to `main`/`staging`/`development` directly (the first commit is the
  only exception). Merge commits, never squash or rebase; delete the branch after merge. **Merging needs an
  explicit instruction.**
- Conventional Commits with a scope, prose subjects. **No AI/tool attribution** in commits or PRs.
- No secrets in the repo; schema changes are additive-only within a major; new response fields are `required = false`.
- Toolchain: `rust-toolchain.toml` pins 1.99.1. If `cargo` is not on `PATH`, use
  `~/.rustup/toolchains/1.99.1-aarch64-apple-darwin/bin`.
- Under zsh use `bash -c` for loops; assert every scripted replacement matched.
