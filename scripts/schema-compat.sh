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
#   The registry is the only source of file names: every file of either tree goes through it. The baseline
#   is read with the BASELINE's registry (falling back to ours if it has none yet), so a change cannot
#   un-gate its own contract: a baseline contract that the new registry no longer matches fails ("dropped
#   from the contract registry"). A contract with no baseline (a new module's) is accepted as new. A symlinked
#   contract path fails, and so does a file under modules/*/api/ that the registry does not gate.
#   Allowed breaks: exact messages listed in api/compat-allow.txt (ours) and
#   api/compat-allow-oasdiff.txt (oasdiff's --err-ignore), one deliberate change at a time.
#   scripts/schema-compat.sh [--base <baseline root> [<new root>]]   (the selftest's way in; a root holds api/, modules/, scripts/contracts.list)
set -euo pipefail
cd "$(dirname "$0")/.."
OASDIFF=tufin/oasdiff@sha256:d6f1e645251cc1da527311955347d8ce8bd2b7ed09bcce07176b2577b8daf19c
command -v jq >/dev/null || { echo "schema-compat: jq is required" >&2; exit 1; }
new="$(pwd)"; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
die() { echo "schema-compat: $*" >&2; exit 1; }
# NUL records "f <path>" / "l <path>" (l = symlink) of a directory tree or of a git ref (no C-quoting).
lister() {
  if [ "$1" = --ref ]; then
    git -c core.quotePath=false ls-tree -r -z "$2" | while IFS= read -r -d '' rec; do
      m=f; [[ "$rec" == 120000* ]] && m=l; printf '%s %s\0' "$m" "${rec#*$'\t'}"
    done
  else
    (cd "$1" && find . \( -name .git -o -name target -o -name node_modules \) -prune -o \( -type f -o -type l \) -print0) |
      while IFS= read -r -d '' p; do p=${p#./}; m=f; [ -L "$1/$p" ] && m=l; printf '%s %s\0' "$m" "$p"; done
  fi
}
# scan <side> <registry> [check-stray]: records on stdin -> $tmp/<side>.files (NUL list of contract paths)
scan() {
  : > "$tmp/$1.all"
  while IFS= read -r -d '' rec; do
    p=${rec#* }
    if [ "${rec%% *}" = l ]; then
      case "$p" in api|api/*|modules/*) die "$1 tree: symlinked contract path $p (a symlink hides what is gated)" ;; esac
      continue
    fi
    printf '%s\0' "$p" >> "$tmp/$1.all"
  done
  scripts/contracts.sh -z --list "$2" < "$tmp/$1.all" > "$tmp/$1.files"
  if [ "${3:-}" = stray ]; then
    scripts/contracts.sh -z --stray --list "$2" < "$tmp/$1.all" | tr '\0' '\n' > "$tmp/stray"
    [ ! -s "$tmp/stray" ] || die "off-convention file under modules/*/api/, never gated (use modules/<name>/api/<file>.json, or exclude it in scripts/contracts.list): $(head -3 "$tmp/stray" | tr '\n' ' ')"
  fi
}
newlist="$new/scripts/contracts.list"; [ -f "$newlist" ] || newlist=scripts/contracts.list
if [ "${1:-}" = "--base" ]; then
  base="$(cd "$2" && pwd)"; label="$2"; [ -z "${3:-}" ] || { new="$(cd "$3" && pwd)"; newlist="$new/scripts/contracts.list"; [ -f "$newlist" ] || newlist=scripts/contracts.list; }
  baselist="$base/scripts/contracts.list"; [ -f "$baselist" ] || baselist="$newlist"
  scan base "$baselist" < <(lister "$base")
else
  ref="${BASE_REF:-$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo origin/development)}"
  base="$tmp/base"; label="$ref"; baselist="$tmp/base.list"
  git show "$ref:scripts/contracts.list" > "$baselist" 2>/dev/null || cp "$newlist" "$baselist"
  scan base "$baselist" < <(lister --ref "$ref")
  while IFS= read -r -d '' f; do
    mkdir -p "$base/$(dirname "$f")"; git show "$ref:$f" > "$base/$f"
  done < "$tmp/base.files"
fi
scan new "$newlist" stray < <(lister "$new")
[ -f "$base/api/openapi.json" ] || die "no baseline api/openapi.json in $label"
bfiles=(); while IFS= read -r -d '' f; do bfiles+=("$f"); done < "$tmp/base.files"
nfiles=(); while IFS= read -r -d '' f; do nfiles+=("$f"); done < "$tmp/new.files"
has() { local n=$1; shift; local x; for x in "$@"; do [ "$x" = "$n" ] && return 0; done; return 1; }
files=(); dropped=()
for f in ${bfiles[@]+"${bfiles[@]}"}; do
  if has "$f" ${nfiles[@]+"${nfiles[@]}"} || [ ! -e "$new/$f" ]; then files+=("$f"); else dropped+=("!$f"); fi
done
for f in ${nfiles[@]+"${nfiles[@]}"}; do has "$f" ${bfiles[@]+"${bfiles[@]}"} || files+=("$f"); done
echo "schema-compat: comparing ${#files[@]} contract files with $label"
# A one-change allow-list (see api/compat-allow.txt): oasdiff's own exact-message ignore file.
ignore=(); [ -f "$new/api/compat-allow-oasdiff.txt" ] && ignore=(--err-ignore /new/api/compat-allow-oasdiff.txt)
for f in "${files[@]}"; do
  [ -f "$base/$f" ] && [ -f "$new/$f" ] || continue
  rc=0; jq -e 'has("openapi")' "$new/$f" >/dev/null || rc=$?
  case "$rc" in 0) ;; 1) continue ;; *) die "jq failed (exit $rc) on $f" ;; esac
  docker run --rm -v "$base:/base:ro" -v "$new:/new:ro" "$OASDIFF" \
    breaking "/base/$f" "/new/$f" --fail-on ERR ${ignore[@]+"${ignore[@]}"}
done
python3 scripts/schema_compat.py "$base" "$new" "${files[@]}" ${dropped[@]+"${dropped[@]}"}
echo "schema-compat: no breaking change"
