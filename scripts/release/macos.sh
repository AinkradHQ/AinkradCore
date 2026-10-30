#!/usr/bin/env bash
# E1-15.3, macOS sign + notarise DRY RUN: scripts/release/macos.sh <binary>...
# Signs with the Developer ID named by MACOS_SIGN_ID when that identity is in the keychain (ad hoc otherwise), then verifies with codesign
# and spctl.
# Then RUNS each signed binary (`--help`): a signature that verifies can still be refused at launch (a
# dylib the hardened runtime will not map), and only running it shows that. `MACOS_SIGN_ID=-` signs ad hoc
# (no keychain identity, nothing real), for a dry run on any Mac.
# Notarisation is PRINTED, never run: nothing is submitted to Apple. `CODESIGN_TIMESTAMP=1` (the real release) adds
# Apple's secure timestamp, which notarisation requires and which contacts timestamp.apple.com; the dry run signs
# with `--timestamp=none` and contacts nobody.
set -uo pipefail
# The Developer ID identity comes from the environment only (MACOS_SIGN_ID="Developer ID Application: <name> (<team>)"); no
# identity lives in the repo. Unset means ad hoc (`-`), which is what a dry run on any Mac uses.
ID=${MACOS_SIGN_ID:--}
if [ "$ID" != - ] && ! security find-identity -v -p codesigning | grep -qF "$ID"; then
  [ "${CODESIGN_TIMESTAMP:-0}" = 1 ] && { echo "macos: identity '$ID' is not in the keychain: a release cannot sign"; exit 1; }
  echo "macos: identity '$ID' is not in the keychain: signing ad hoc instead (MACOS_SIGN_ID=-)"; ID=-
fi
ts=--timestamp=none; [ "${CODESIGN_TIMESTAMP:-0}" = 1 ] && ts=--timestamp
rc=0
for bin in "$@"; do
  echo "== $bin"
  codesign --force --options runtime "$ts" -s "$ID" "$bin" || { echo "codesign FAILED"; rc=1; continue; }
  codesign --verify --strict --verbose=2 "$bin" && echo "codesign --verify --strict: OK"
  # Every dylib must be the system's: anything else (Homebrew, a build dir) is missing or refused elsewhere.
  if otool -L "$bin" | tail -n +2 | awk '{print $1}' | grep -vE '^(/usr/lib/|/System/Library/)'; then
    echo "otool: links a non-system library (above): FAILED"; rc=1
  fi
  # `--help` (a usage exit is fine); a library dyld refuses kills it before main with SIGABRT (134).
  "$bin" --help >/dev/null 2>&1; code=$?
  if [ $code -lt 128 ]; then echo "runs: --help exited $code"; else echo "the signed binary does NOT start (exit $code):"; "$bin" --help 2>&1 | head -3; rc=1; fi
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
