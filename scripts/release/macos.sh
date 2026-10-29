#!/usr/bin/env bash
# E1-15.3, macOS sign + notarise DRY RUN: scripts/release/macos.sh <binary>...
# Signs with the Developer ID only when that identity is in the keychain, then verifies with codesign and spctl.
# Notarisation is PRINTED, never run: nothing is submitted to Apple. `CODESIGN_TIMESTAMP=1` (the real release) adds
# Apple's secure timestamp, which notarisation requires and which contacts timestamp.apple.com; the dry run signs
# with `--timestamp=none` and contacts nobody.
set -uo pipefail
ID="Developer ID Application: ULINK sp. z o.o. (RT9AA68C38)"
if ! security find-identity -v -p codesigning | grep -qF "$ID"; then
  echo "macos: identity '$ID' is not in the keychain: skipping signing (nothing to verify)"; exit 0
fi
ts=--timestamp=none; [ "${CODESIGN_TIMESTAMP:-0}" = 1 ] && ts=--timestamp
rc=0
for bin in "$@"; do
  echo "== $bin"
  codesign --force --options runtime "$ts" -s "$ID" "$bin" || { echo "codesign FAILED"; rc=1; continue; }
  codesign --verify --strict --verbose=2 "$bin" && echo "codesign --verify --strict: OK"
  # A bare Mach-O is assessed by Gatekeeper's notarisation lookup: refused until Apple has notarised it. Expected here.
  if spctl --assess --type execute -vv "$bin"; then echo "spctl: accepted"; else echo "spctl: REJECTED (expected in the dry run: not notarised)"; fi
done
cat <<NOTE

NOT RUN (the release step is gated). To notarise, once Ahmed approves a release:
  ditto -c -k --keepParent <binary> <binary>.zip          # one zip per binary, or all in one directory zip
  xcrun notarytool submit <binary>.zip --keychain-profile ainkrad-notary --wait
  xcrun notarytool log <submission-id> --keychain-profile ainkrad-notary
A bare Mach-O cannot be stapled; Gatekeeper checks the ticket online. Re-run this script with CODESIGN_TIMESTAMP=1 first.
NOTE
exit $rc
