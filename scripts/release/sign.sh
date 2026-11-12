#!/usr/bin/env bash
# E1-15.2: scripts/release/sign.sh <dist-dir> <minisign-secret-key>
# SHA256SUMS over every artefact in <dist-dir> (after any codesign: that rewrites the Mach-O), then ONE minisign
# signature over that file. The signature is what install.sh and self-verify.sh trust; the artefacts are covered
# through their hashes. The real key is offline (see the custody plan in the PR); this script only runs where it is.
set -euo pipefail
d=${1:?dist dir}; key=${2:?secret key}
cd "$d"
ver=$(basename "$PWD")
# Everything that ships: binaries, the macOS runner zip (matched by ainkrad-runner-*), the installer bundle and get.sh (which runs it) only (no keys, sums, signatures or the SBOM directory).
shopt -s nullglob
[ -f get.sh ] || { echo "sign.sh: $d/get.sh is missing: get.sh ships in the signed sums (scripts/release/dry.sh puts it there)" >&2; exit 1; }
# The macOS runner zip is part of every release (scripts/release/mac-zip.sh); AINKRAD_RELEASE_NO_MAC=1 waives it for a partial dry run only.
[ -f "ainkrad-runner-$ver-macos-arm64.zip" ] || [ "${AINKRAD_RELEASE_NO_MAC:-}" = 1 ] || { echo "sign.sh: $d/ainkrad-runner-$ver-macos-arm64.zip is missing: the macOS runner zip ships in every release (scripts/release/mac-zip.sh)" >&2; exit 1; }
files=(ainkrad-core-server-* ainkrad-runner-* ainkradctl-* ainkrad-ptyhost-* ainkrad-core-installer-* get.sh)
[ ${#files[@]} -gt 0 ] || { echo "no artefacts in $d" >&2; exit 1; }
rm -f SHA256SUMS SHA256SUMS.minisig
shasum -a 256 "${files[@]}" | LC_ALL=C sort -k2 > SHA256SUMS
minisign -S -s "$key" -m SHA256SUMS -x SHA256SUMS.minisig -t "ainkrad-core $ver"
echo "signed $(wc -l < SHA256SUMS | tr -d ' ') artefacts: $d/SHA256SUMS{,.minisig}"
