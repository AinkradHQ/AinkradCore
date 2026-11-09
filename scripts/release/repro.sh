#!/usr/bin/env bash
# E1-15.1 proof: scripts/release/repro.sh [targets]: the same commit built twice into separate, empty target dirs must give
# identical SHA-256s. Prints both sets and exits non-zero on any difference.
set -euo pipefail
cd "$(dirname "$0")/../.."
targets=${*:-${RELEASE_TARGETS:-linux-arm64}}
rm -rf dist/_repro; mkdir -p dist/_repro
for t in $targets; do
  for run in a b; do
    # A fresh target dir per run: nothing is shared, so equality is not a cache effect.
    [ "$t" = macos-arm64 ] && rm -rf "target/dist-$run"
    scripts/release/build.sh "$t" "dist/_repro/$run" "$run"
  done
done
(cd dist/_repro/a && shasum -a 256 */*) > dist/_repro/a.sums
(cd dist/_repro/b && shasum -a 256 */*) > dist/_repro/b.sums
rc=0
while read -r ha file; do
  hb=$(awk -v f="$file" '$2 == f { print $1 }' dist/_repro/b.sums)
  if [ "$ha" = "$hb" ]; then echo "identical  $file  $ha"; else echo "DIFFERENT  $file  a=$ha b=$hb"; rc=1; fi
done < dist/_repro/a.sums
[ $rc = 0 ] && echo "REPRODUCIBLE: identical hashes" || echo "NOT REPRODUCIBLE: see above"
exit $rc
