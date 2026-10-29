#!/usr/bin/env bash
# E1-15.2: scripts/release/sign.sh <dist-dir> <minisign-secret-key>
# SHA256SUMS over every artefact in <dist-dir> (after any codesign: that rewrites the Mach-O), then ONE minisign
# signature over that file. The signature is what install.sh and self-verify.sh trust; the artefacts are covered
# through their hashes. The real key is offline (see the custody plan in the PR); this script only runs where it is.
set -euo pipefail
d=${1:?dist dir}; key=${2:?secret key}
cd "$d"
ver=$(basename "$PWD")
# Everything that ships: binaries only (no keys, sums, signatures or the SBOM directory).
shopt -s nullglob
files=(ainkrad-core-server-* ainkrad-runner-*)
[ ${#files[@]} -gt 0 ] || { echo "no artefacts in $d" >&2; exit 1; }
rm -f SHA256SUMS SHA256SUMS.minisig
shasum -a 256 "${files[@]}" | LC_ALL=C sort -k2 > SHA256SUMS
minisign -S -s "$key" -m SHA256SUMS -x SHA256SUMS.minisig -t "ainkrad-core $ver"
echo "signed $(wc -l < SHA256SUMS | tr -d ' ') artefacts: $d/SHA256SUMS{,.minisig}"
