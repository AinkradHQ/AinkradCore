#!/usr/bin/env bash
# E1-15.4: `self-verify` for an installed binary: scripts/release/self-verify.sh <binary> --from <dir|url> [--pubkey FILE]
# Checks the binary's SHA-256 against the signed SHA256SUMS of its release. The Rust subcommand (`ainkrad-core-server
# self-verify`, the same check with the key compiled in) needs a change to `main.rs`, which belongs to another lane.
set -euo pipefail
bin=${1:?binary}; shift
exec "$(dirname "$0")/install.sh" --verify-only "$bin" "$@"
