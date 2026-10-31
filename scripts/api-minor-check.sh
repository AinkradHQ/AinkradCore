#!/usr/bin/env bash
# Fails when a contract file (api/*.json) differs from the baseline without a higher API_MINOR
# (types.rs). Baseline: origin/development (BASE_REF overrides). openapi.json's own version
# string is ignored, so a bump alone is not a change. Skips loudly if the baseline is missing.
set -euo pipefail
cd "$(dirname "$0")/.."
ref="${BASE_REF:-origin/development}"
types=crates/server/src/api/v1/types.rs
git rev-parse -q --verify "$ref" >/dev/null || { echo "api-minor-check: SKIPPED, no $ref" >&2; exit 0; }
minor() { sed -n 's/^pub const API_MINOR: u32 = \([0-9]*\);.*/\1/p'; }
now=$(minor < $types); was=$(git show "$ref:$types" | minor)
norm() { python3 -c 'import json,sys; d=json.load(sys.stdin); d.get("info",{}).pop("version",None); print(json.dumps(d,sort_keys=True))'; }
changed=""
for f in openapi.json events.schema.json runner.schema.json; do
  a=$(git show "$ref:api/$f" 2>/dev/null | norm || true); b=$(norm < "api/$f")
  [ "$a" = "$b" ] || changed="$changed $f"
done
if [ -n "$changed" ] && [ "$now" -le "$was" ]; then
  echo "api-minor-check: contract changed ($changed ) vs $ref but API_MINOR is $now (base $was): bump it" >&2
  exit 1
fi
echo "api-minor-check: ok (API_MINOR $now, base $was)"
