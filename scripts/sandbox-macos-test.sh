#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "Running the ignored Seatbelt enforcement test in this normal Terminal session."
echo "The agent environment cannot nest sandbox-exec; this script must be run by the owner."
test "$(uname -s)" = Darwin || { echo "ERROR: this script requires macOS" >&2; exit 1; }
/usr/bin/sandbox-exec -p '(version 1)(allow default)' /usr/bin/true
cargo test -p ainkrad-harness sandbox::tests -- --ignored --nocapture --test-threads=1
if [ -n "${AINKRAD_TEST_RAMDIR:-}" ]; then
  cargo test -p ainkrad-runner v2::agent::tests -- --ignored --nocapture --test-threads=1
else
  echo "NOT RUN: secret file lifecycle probes require AINKRAD_TEST_RAMDIR on a verified RAM disk." >&2
fi
