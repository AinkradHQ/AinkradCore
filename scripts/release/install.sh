#!/usr/bin/env bash
# E1-15.4: verify, then install. Nothing is written to the prefix unless the signature AND every checksum hold.
#   install.sh --from <dir|https-url> [--prefix DIR] [--pubkey FILE] [--target T] [--verify-only FILE]
# 1. minisign -V over SHA256SUMS with the pinned public key (refuses on any mismatch).
# 2. SHA-256 of each artefact for this target against the signed sums.
# 3. Only then `install` into <prefix>/bin via a temp file and rename. Needs `minisign` (brew/apt install minisign).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
from= prefix=${HOME}/.local pub=${AINKRAD_RELEASE_PUBKEY:-$here/ainkrad-release.pub} target= only=
while [ $# -gt 0 ]; do case $1 in
  --from) from=$2; shift 2 ;; --prefix) prefix=$2; shift 2 ;; --pubkey) pub=$2; shift 2 ;;
  --target) target=$2; shift 2 ;; --verify-only) only=$2; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;;
esac; done
die() { echo "install: REFUSED: $*" >&2; exit 1; }
[ -n "$from" ] || die "--from is required"
[ -f "$pub" ] || die "no public key at $pub (the release key is generated offline; pass --pubkey)"
command -v minisign >/dev/null || die "minisign is not installed"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fetch() { case $from in http://*) die "plain http is refused" ;; https://*) curl -fsSL --proto '=https' --tlsv1.3 -o "$tmp/$1" "$from/$1" ;; *) cp "$from/$1" "$tmp/$1" ;; esac; }
fetch SHA256SUMS; fetch SHA256SUMS.minisig
minisign -Vq -p "$pub" -x "$tmp/SHA256SUMS.minisig" -m "$tmp/SHA256SUMS" || die "the SHA256SUMS signature does not verify"
echo "signature OK ($(sed -n 's/^trusted comment: //p' "$tmp/SHA256SUMS.minisig"))"
if [ -n "$only" ]; then
  h=$(sha "$only"); grep -q "^$h  " "$tmp/SHA256SUMS" || die "$only is not in the signed sums"
  echo "self-verify OK: $only ($h)"; exit 0
fi
if [ -z "$target" ]; then
  case "$(uname -s)-$(uname -m)" in Linux-aarch64) target=linux-arm64 ;; Linux-x86_64) target=linux-x86_64 ;; Darwin-arm64) target=macos-arm64 ;; *) die "no build for $(uname -sm)" ;; esac
fi
names=$(awk -v t="-$target" '{ n=$2; if (substr(n, length(n)-length(t)+1) == t) print n }' "$tmp/SHA256SUMS")
[ -n "$names" ] || die "no artefact for $target in the signed sums"
for n in $names; do
  fetch "$n"
  want=$(awk -v n="$n" '$2 == n { print $1 }' "$tmp/SHA256SUMS")
  [ "$(sha "$tmp/$n")" = "$want" ] || die "$n does not match its signed checksum"
done
mkdir -p "$prefix/bin"
for n in $names; do
  bin=${n%%-[0-9]*}   # ainkrad-runner-0.1.0-linux-arm64 -> ainkrad-runner
  install -m 755 "$tmp/$n" "$prefix/bin/.$bin.new" && mv -f "$prefix/bin/.$bin.new" "$prefix/bin/$bin"
  echo "installed $prefix/bin/$bin"
done
