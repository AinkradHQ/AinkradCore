#!/usr/bin/env bash
# E1-17.2: scripts/fuzz/run.sh <seconds per target> [target...]  (default: all four)
# Runs each cargo-fuzz target for the given time on a scratch corpus seeded from fuzz/seeds/<target> (committed, read-only),
# so the growing corpus never lands in git. Crashes land in fuzz/artifacts/<target>/. Nightly only, (`rustup toolchain
# install nightly --profile minimal`, `cargo install cargo-fuzz`). The 1 h scheduled run is `scripts/fuzz/run.sh 3600`.
set -euo pipefail
cd "$(dirname "$0")/../.."
secs=${1:?seconds}; shift || true
targets=${*:-signed_request v2_frame pairing_payload spki_key}
scratch=${FUZZ_CORPUS:-fuzz/corpus}
# The nightly toolchain first on PATH (a pinned stable `cargo` may be ahead of the rustup proxy), cargo-fuzz from ~/.cargo/bin.
PATH="$(dirname "$(rustup which --toolchain nightly rustc)"):$HOME/.cargo/bin:$PATH"
export PATH
rc=0
for t in $targets; do
  mkdir -p "$scratch/$t"
  echo "== $t (${secs}s)"
  (cd fuzz && cargo fuzz run "$t" "corpus/$t" "seeds/$t" -- -max_total_time="$secs" -print_final_stats=1 2>&1 | tail -25) || rc=1
done
exit $rc
