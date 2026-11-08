#!/usr/bin/env bash
# Breaking-change gate (E1-05.4, C-21): every contract file listed in scripts/contracts.list (the three
# api/ files, Citadel's openapi.core.json and any module's modules/<name>/api/*.json) in the working tree
# against the baseline, which is the BASE_REF if set (CI: the pull request's base commit), else the newest
# `v*` tag, else origin/development. Two checks, both must pass:
#   - oasdiff v1.11.7 (pinned image) on every OpenAPI file present on both sides: removed
#     paths/operations/fields, new required request fields, narrowed types, removed enum values, ...
#     (`--fail-on ERR`)
#   - scripts/schema_compat.py on all of them: the same classes plus "a field made required" and "a new
#     field is required" (every new field is required = false), which oasdiff allows on responses, and
#     "a contract file was removed".
#   A contract file with no baseline (a new module's) is accepted as new; once merged it is the baseline.
#   Allowed breaks: exact messages listed in api/compat-allow.txt (ours) and
#   api/compat-allow-oasdiff.txt (oasdiff's --err-ignore), one deliberate change at a time.
#   scripts/schema-compat.sh [--base <baseline root> [<new root>]]   (the selftest's way in; a root holds api/ and modules/)
set -euo pipefail
cd "$(dirname "$0")/.."
OASDIFF=tufin/oasdiff@sha256:d6f1e645251cc1da527311955347d8ce8bd2b7ed09bcce07176b2577b8daf19c
new="$(pwd)"
paths() { (cd "$1" && for f in api/*.json modules/*/api/*.json; do [ -f "$f" ] && echo "$f"; done; true) | scripts/contracts.sh; }
if [ "${1:-}" = "--base" ]; then
  base="$(cd "$2" && pwd)"; label="$2"; [ -z "${3:-}" ] || new="$(cd "$3" && pwd)"
else
  ref="${BASE_REF:-$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo origin/development)}"
  base="$(mktemp -d)"; trap 'rm -rf "$base"' EXIT; label="$ref"
  git ls-tree -r --name-only "$ref" | scripts/contracts.sh | while IFS= read -r f; do
    mkdir -p "$base/$(dirname "$f")"; git show "$ref:$f" > "$base/$f"
  done
fi
[ -f "$base/api/openapi.json" ] || { echo "schema-compat: no baseline api/openapi.json in $label" >&2; exit 1; }
files=(); while IFS= read -r f; do files+=("$f"); done < <({ paths "$base"; paths "$new"; } | sort -u)
echo "schema-compat: comparing ${#files[@]} contract files with $label"
# A one-change allow-list (see api/compat-allow.txt): oasdiff's own exact-message ignore file.
ignore=(); [ -f "$new/api/compat-allow-oasdiff.txt" ] && ignore=(--err-ignore /new/api/compat-allow-oasdiff.txt)
for f in "${files[@]}"; do
  [ -f "$base/$f" ] && [ -f "$new/$f" ] || continue
  jq -e 'has("openapi")' "$new/$f" >/dev/null || continue
  docker run --rm -v "$base:/base:ro" -v "$new:/new:ro" "$OASDIFF" \
    breaking "/base/$f" "/new/$f" --fail-on ERR ${ignore[@]+"${ignore[@]}"}
done
python3 scripts/schema_compat.py "$base" "$new" "${files[@]}"
echo "schema-compat: no breaking change"
