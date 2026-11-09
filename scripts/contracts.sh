#!/usr/bin/env bash
# Filters repo-relative paths on stdin to the contract files listed in scripts/contracts.list.
#   git ls-files | scripts/contracts.sh            every contract file
#   git ls-files | scripts/contracts.sh --minor    only those whose change needs an API_MINOR bump
#   ... | scripts/contracts.sh --stray             files under modules/*/api/ that the registry would NOT gate
#                                                  (not a .json directly in api/, e.g. .JSON, .yaml, api/v1/x.json)
#   --list <file>  use another registry (the baseline's); -z  NUL-separated input and output
set -euo pipefail
list="$(dirname "$0")/contracts.list"; want=""; stray=0; z=0
while [ $# -gt 0 ]; do
  case "$1" in --minor) want=api-minor ;; --stray) stray=1 ;; --list) list=$2; shift ;; -z) z=1 ;; esac
  shift
done
delim=$'\n'; [ "$z" = 1 ] && delim=''
# shellcheck disable=SC2053  # the patterns are globs on purpose
while IFS= read -r -d "$delim" p; do
  [[ "$p" == *.json || ( "$stray" = 1 && "$p" =~ ^modules/[^/]+/api/ ) ]] || continue
  hit=0; out=0
  while read -r pat tag _; do
    case "$pat" in ''|'#'*) continue ;; esac
    if [[ "$pat" == '!'* ]]; then [[ "$p" == ${pat#!} ]] && out=1; continue; fi
    [[ "$p" == $pat && "${p//[^\/]}" == "${pat//[^\/]}" ]] && { [ -z "$want" ] || [ "$tag" = "$want" ]; } && hit=1
  done < "$list"
  [ "$out" = 0 ] || continue
  if [ "$stray" = 1 ]; then [ "$hit" = 0 ] && [[ "$p" =~ ^modules/[^/]+/api/ ]] || continue
  else [ "$hit" = 1 ] || continue; fi
  if [ "$z" = 1 ]; then printf '%s\0' "$p"; else printf '%s\n' "$p"; fi
done
exit 0
