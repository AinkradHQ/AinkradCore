#!/usr/bin/env bash
# Filters repo-relative paths on stdin to the contract files listed in scripts/contracts.list.
#   git ls-files | scripts/contracts.sh            every contract file
#   git ls-files | scripts/contracts.sh --minor    only those whose change needs an API_MINOR bump
set -euo pipefail
list="$(dirname "$0")/contracts.list"
want=""; [ "${1:-}" = "--minor" ] && want=api-minor
# shellcheck disable=SC2053  # the patterns are globs on purpose
while IFS= read -r p; do
  [[ "$p" == *.json ]] || continue
  hit=0; out=0
  while read -r pat tag _; do
    case "$pat" in ''|'#'*) continue ;; esac
    if [[ "$pat" == '!'* ]]; then [[ "$p" == ${pat#!} ]] && out=1; continue; fi
    [[ "$p" == $pat && "${p//[^\/]}" == "${pat//[^\/]}" ]] && { [ -z "$want" ] || [ "$tag" = "$want" ]; } && hit=1
  done < "$list"
  [ "$hit" = 1 ] && [ "$out" = 0 ] && echo "$p"
done
exit 0
