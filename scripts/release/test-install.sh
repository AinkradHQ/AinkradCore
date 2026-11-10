#!/usr/bin/env bash
# E1-15.4 tests, no root, a temp prefix: a good release installs; a flipped byte, an edited SHA256SUMS, a foreign key
# and a missing signature are each refused with a non-zero exit and an EMPTY prefix. Throwaway keys only.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
case "$(uname -s)-$(uname -m)" in Linux-aarch64) t=linux-arm64 ;; Linux-x86_64) t=linux-x86_64 ;; Darwin-arm64) t=macos-arm64 ;; esac
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT; fail=0
minisign -G -W -f -p "$w/a.pub" -s "$w/a.key" >/dev/null; minisign -G -W -f -p "$w/b.pub" -s "$w/b.key" >/dev/null
mkdir -p "$w/dist/9.9.9"
for b in ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost; do printf '#!/bin/sh\necho %s\n' "$b" > "$w/dist/9.9.9/$b-9.9.9-$t"; done
printf 'x' > "$w/dist/9.9.9/ainkrad-runner-9.9.9-other-target"
printf '#!/bin/sh\n' > "$w/dist/9.9.9/get.sh" # get.sh ships in the signed sums since the guided installer
"$here/sign.sh" "$w/dist/9.9.9" "$w/a.key" >/dev/null
fresh() { rm -rf "$w/run" "$w/prefix"; cp -R "$w/dist/9.9.9" "$w/run"; }
inst() { "$here/install.sh" --from "$w/run" --pubkey "${1:-$w/a.pub}" --prefix "$w/prefix" >"$w/out" 2>&1; }
# refused NAME PUBKEY|"" REASON-REGEX: refused for THAT reason (not just "something failed"), prefix left empty
refused() {
  if inst "${2:-}"; then echo "FAIL $1: installed"; fail=1
  elif [ -e "$w/prefix" ] && [ -n "$(ls -A "$w/prefix" 2>/dev/null)" ]; then echo "FAIL $1: prefix not empty"; fail=1
  elif ! tail -1 "$w/out" | grep -qE "${3:?refused needs the expected reason}"; then echo "FAIL $1: refused for the wrong reason: $(tail -1 "$w/out") (wanted: $3)"; fail=1
  else echo "ok   $1: refused ($(tail -1 "$w/out" | sed 's#/[^ ]*/##g'))"; fi; }
fresh; inst && [ -x "$w/prefix/bin/ainkrad-runner" ] && [ -x "$w/prefix/bin/ainkradctl" ] && [ -x "$w/prefix/bin/ainkrad-ptyhost" ] && [ "$("$w/prefix/bin/ainkrad-core-server")" = ainkrad-core-server ] \
  && [ ! -e "$w/prefix/bin/.ainkrad-runner.new" ] && echo "ok   good release installs" || { echo "FAIL good release"; cat "$w/out"; fail=1; }
fresh; printf 'Z' | dd of="$w/run/ainkrad-runner-9.9.9-$t" bs=1 seek=5 conv=notrunc 2>/dev/null; refused "flipped artefact byte" "" "ainkrad-runner-9.9.9-.* does not match its signed checksum"
fresh; printf 'Z' | dd of="$w/run/ainkradctl-9.9.9-$t" bs=1 seek=5 conv=notrunc 2>/dev/null; refused "flipped ainkradctl byte" "" "ainkradctl-9.9.9-.* does not match its signed checksum"
fresh; printf 'Z' | dd of="$w/run/ainkrad-ptyhost-9.9.9-$t" bs=1 seek=5 conv=notrunc 2>/dev/null; refused "flipped ainkrad-ptyhost byte" "" "ainkrad-ptyhost-9.9.9-.* does not match its signed checksum"
# A release without the CLI or ptyhost, even if correctly signed, is refused whole (nothing half-installed).
for gone in ainkradctl ainkrad-ptyhost; do
  rm -rf "$w/short"; cp -R "$w/dist/9.9.9" "$w/short"; rm "$w/short/$gone-9.9.9-$t"; "$here/sign.sh" "$w/short" "$w/a.key" >/dev/null
  rm -rf "$w/run" "$w/prefix"; cp -R "$w/short" "$w/run"; refused "signed set without $gone" "" "the signed sums have no $gone for $t"
done
# Atomic set: a failure at any step leaves the complete OLD set (or nothing on a fresh prefix), exit != 0, no .old/.stage litter.
setsum() { for b in ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost; do cat "$w/prefix/bin/$b" 2>/dev/null; echo "|$b"; done; }
for at in 1 2 3 4; do
  fresh; mkdir -p "$w/prefix/bin"
  for b in ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost; do echo "OLD $b" > "$w/prefix/bin/$b"; done
  before=$(setsum)
  if AINKRAD_INSTALL_FAIL_AT=$at inst; then echo "FAIL fail-at-$at (old set): installed"; fail=1
  elif ! grep -q "could not install .*restored the previous binaries" "$w/out"; then echo "FAIL fail-at-$at (old set): failed for the wrong reason: $(tail -1 "$w/out")"; fail=1
  elif [ "$(setsum)" != "$before" ] || [ "$(ls -A "$w/prefix/bin" | wc -l)" -ne 4 ]; then echo "FAIL fail-at-$at (old set): prefix changed"; ls -A "$w/prefix/bin"; tail -2 "$w/out"; fail=1
  else echo "ok   failure at step $at restores the old set"; fi
  fresh
  if AINKRAD_INSTALL_FAIL_AT=$at inst; then echo "FAIL fail-at-$at (fresh): installed"; fail=1
  elif ! grep -q "could not install" "$w/out"; then echo "FAIL fail-at-$at (fresh): failed for the wrong reason: $(tail -1 "$w/out")"; fail=1
  elif [ -n "$(ls -A "$w/prefix/bin")" ]; then echo "FAIL fail-at-$at (fresh): bin not empty"; fail=1
  else echo "ok   failure at step $at leaves a fresh prefix empty"; fi
done
fresh; mkdir -p "$w/prefix/bin"; echo "OLD" > "$w/prefix/bin/ainkradctl"; inst && [ "$("$w/prefix/bin/ainkradctl")" = ainkradctl ] && [ "$(ls -A "$w/prefix/bin" | wc -l)" -eq 4 ] \
  && echo "ok   upgrade replaces the set, no .old left" || { echo "FAIL upgrade"; fail=1; }
fresh; sed -i.bak -e '1s/^0/1/' -e t -e '1s/^./0/' "$w/run/SHA256SUMS"; refused "edited SHA256SUMS" "" "SHA256SUMS signature does not verify"
fresh; refused "foreign public key" "$w/b.pub" "SHA256SUMS signature does not verify"
fresh; rm "$w/run/SHA256SUMS.minisig"; refused "missing signature" "" "no SHA256SUMS.minisig in"
fresh; "$here/self-verify.sh" "$w/run/ainkrad-runner-9.9.9-$t" --from "$w/run" --pubkey "$w/a.pub" >/dev/null && echo "ok   self-verify accepts" || { echo "FAIL self-verify accepts"; fail=1; }
printf 'Z' | dd of="$w/run/ainkrad-runner-9.9.9-$t" bs=1 seek=5 conv=notrunc 2>/dev/null
if "$here/self-verify.sh" "$w/run/ainkrad-runner-9.9.9-$t" --from "$w/run" --pubkey "$w/a.pub" >"$w/sv" 2>&1; then echo "FAIL self-verify tampered"; fail=1
elif tail -1 "$w/sv" | grep -q "is not in the signed sums"; then echo "ok   self-verify refuses a tampered binary (not in the signed sums)"
else echo "FAIL self-verify tampered: wrong reason: $(tail -1 "$w/sv")"; fail=1; fi
exit $fail
