#!/usr/bin/env bash
# The drift gate (E1-05.2): regenerates every client into a temp dir and fails if the committed
# clients/*/generated differs. Fix: `make clients` and commit.
set -euo pipefail
cd "$(dirname "$0")/.."
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
mkdir -p "$t"/{swift,kotlin,csharp,ts}
scripts/contract-swift.sh "$t" >/dev/null
scripts/contract-clients.sh gen "$t" >/dev/null
bad=0
for l in swift kotlin csharp ts; do
  diff -r "$t/$l/generated" "clients/$l/generated" >/dev/null || { echo "clients-check: clients/$l/generated is stale" >&2; bad=1; }
done
[ "$bad" = 0 ] && echo "clients-check: committed clients match api/openapi.json"
exit "$bad"
