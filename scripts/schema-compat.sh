#!/usr/bin/env bash
# Breaking-change gate (E1-05.4): the working tree's api/*.json against the baseline, which is the
# newest `v*` tag, else origin/development. Two checks, both must pass:
#   - oasdiff v1.11.7 (pinned image) on openapi.json: removed paths/operations/fields, new required
#     request fields, narrowed types, removed enum values, ... (`--fail-on ERR`)
#   - scripts/schema_compat.py on all three files: the same classes plus "a field made required"
#     and "a new field is required" (every new field is required = false), which oasdiff allows on
#     responses.
#   Allowed breaks: exact messages listed in api/compat-allow.txt (ours) and
#   api/compat-allow-oasdiff.txt (oasdiff's --err-ignore), one deliberate change at a time.
#   scripts/schema-compat.sh [--base <baseline dir> [<new dir>]]   (the selftest's way in)
set -euo pipefail
cd "$(dirname "$0")/.."
OASDIFF=tufin/oasdiff@sha256:d6f1e645251cc1da527311955347d8ce8bd2b7ed09bcce07176b2577b8daf19c
new="$(pwd)/api"
if [ "${1:-}" = "--base" ]; then
  base="$(cd "$2" && pwd)"; label="$2"; [ -z "${3:-}" ] || new="$(cd "$3" && pwd)"
else
  ref="$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo origin/development)"
  base="$(mktemp -d)"; trap 'rm -rf "$base"' EXIT; label="$ref"
  for f in openapi.json events.schema.json runner.schema.json; do
    git show "$ref:api/$f" > "$base/$f" 2>/dev/null || rm -f "$base/$f"
  done
fi
[ -f "$base/openapi.json" ] || { echo "schema-compat: no baseline openapi.json in $label" >&2; exit 1; }
echo "schema-compat: comparing api/ with $label"
# A one-change allow-list (see api/compat-allow.txt): oasdiff's own exact-message ignore file.
ignore=(); [ -f "$new/compat-allow-oasdiff.txt" ] && ignore=(--err-ignore /new/compat-allow-oasdiff.txt)
docker run --rm -v "$base:/base:ro" -v "$new:/new:ro" "$OASDIFF" \
  breaking /base/openapi.json /new/openapi.json --fail-on ERR ${ignore[@]+"${ignore[@]}"}
python3 scripts/schema_compat.py "$base" "$new"
echo "schema-compat: no breaking change"
