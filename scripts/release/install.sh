#!/usr/bin/env bash
# E1-15.4: verify, then install. Nothing is written to the prefix unless the signature AND every checksum hold.
#   install.sh --from <dir|https-url> [--prefix DIR] [--pubkey FILE] [--target T] [--verify-only FILE] [--scripts DIR]
# 1. minisign -V over SHA256SUMS with the pinned public key (refuses on any mismatch).
# 2. SHA-256 of each artefact for this target against the signed sums.
# 3. Only then install all four (ainkrad-core-server, ainkrad-runner, ainkradctl, ainkrad-ptyhost) into <prefix>/bin as one set:
#    stage them in a temp dir inside <prefix>/bin (same filesystem), then rename into place in that order, keeping each previous
#    binary as <name>.old until all four are in; any failure restores the originals (or removes the new ones on a fresh prefix) and
#    exits non-zero. The macos-arm64 release is ONE zip (ainkrad-runner-<ver>-macos-arm64.zip: ainkrad-runner + ainkrad-ptyhost, unsigned
#    by Apple: the Mac app re-signs them): when a target has no four-binary set but has that zip, the zip is verified against the signed
#    sums, then those two are installed the same way. ainkrad-ptyhost sits beside ainkrad-runner, where the runner looks for it. Needs `minisign` (brew/apt install minisign).
# --scripts DIR (the self-updater, after a healthy update): instead of binaries, put the updater's own scripts (update.sh, install.sh,
# model.sh) from the release's signed installer bundle into DIR, each as a temp file renamed into place (a running copy keeps its
# old inode, so bash reading it is not disturbed). The pinned key is never replaced this way.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
from= prefix= pub=${AINKRAD_RELEASE_PUBKEY:-$here/ainkrad-release.pub} target= only= part= scripts=
while [ $# -gt 0 ]; do case $1 in
  --from) from=$2; shift 2 ;; --prefix) prefix=$2; shift 2 ;; --pubkey) pub=$2; shift 2 ;;
  --target) target=$2; shift 2 ;; --only) part=$2; shift 2 ;; --verify-only) only=$2; shift 2 ;; --scripts) scripts=$2; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;;
esac; done
die() { echo "install: REFUSED: $*" >&2; exit 1; }
[ -n "$from" ] || die "--from is required"
[ -f "$pub" ] || die "no public key at $pub (the release key is generated offline; pass --pubkey)"
command -v minisign >/dev/null || die "minisign is not installed"
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
tmp=$(mktemp -d); stage=; trap 'rm -rf "$tmp" ${stage:+"$stage"}' EXIT
fetch() { case $from in http://*) die "plain http is refused" ;; https://*) curl -fsSL --proto '=https' --tlsv1.3 -o "$tmp/$1" "$from/$1" ;; *) cp "$from/$1" "$tmp/$1" 2>/dev/null || die "no $1 in $from" ;; esac; }
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
zipname=$(awk -v t="-$target.zip" '{ n=$2; if (n ~ /^ainkrad-runner-[0-9]/ && substr(n, length(n)-length(t)+1) == t) print n }' "$tmp/SHA256SUMS")
[ -n "$names" ] || [ -n "$zipname" ] || die "no artefact for $target in the signed sums"
verify() {  # verify NAME: fetch it and hold it to its signed checksum
  fetch "$1"
  [ "$(sha "$tmp/$1")" = "$(awk -v n="$1" '$2 == n { print $1 }' "$tmp/SHA256SUMS")" ] || die "$1 does not match its signed checksum"
}
if [ -n "$scripts" ]; then
  bundle=$(awk '$2 ~ /^ainkrad-core-installer-[0-9][0-9A-Za-z.+-]*\.tar\.gz$/ { print $2 }' "$tmp/SHA256SUMS")
  [ -n "$bundle" ] && [ "$(echo "$bundle" | wc -l)" -eq 1 ] || die "the signed sums have no single installer bundle"
  verify "$bundle"
  top=${bundle%.tar.gz} want="update.sh install.sh model.sh"
  mkdir "$tmp/s"
  # Only these named members are taken out; model.sh is optional (older bundles have none).
  for f in $want; do tar -xzf "$tmp/$bundle" -C "$tmp/s" "$top/scripts/release/$f" 2>/dev/null || true; done
  for f in update.sh install.sh; do [ -f "$tmp/s/$top/scripts/release/$f" ] || die "$bundle has no $f"; done
  for f in $want; do
    src=$tmp/s/$top/scripts/release/$f
    [ -e "$src" ] || [ -L "$src" ] || continue
    { [ -f "$src" ] && [ ! -L "$src" ]; } || die "$f in $bundle is not a plain file"
    new=$(mktemp "$scripts/.$f.XXXXXX") || die "cannot place $f in $scripts"
    { install -m 0755 "$src" "$new" && mv -f "$new" "$scripts/$f"; } || { rm -f "$new"; die "cannot place $f in $scripts"; }
    echo "installed $scripts/$f"
  done
  exit 0
fi
# --only core|runner (E12): a mode installs only its own programs, so a Core update never swaps the runner under a running task.
case $part in
  '') order="ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost" ;;
  core) order="ainkrad-core-server ainkradctl" ;;
  runner) order="ainkrad-runner ainkrad-ptyhost" ;;
  *) die "--only is core or runner" ;;
esac
mkdir "$tmp/z"
if [ -z "$names" ]; then
  # Zip mode: only the two named members are taken out (no path from the archive is ever used).
  [ "$part" != core ] || die "a macOS target has no Core programs"
  order="ainkrad-runner ainkrad-ptyhost"
  verify "$zipname"
  command -v unzip >/dev/null || die "unzip is not installed"
  # shellcheck disable=SC2086  # $order is two words
  unzip -q -j "$tmp/$zipname" $order -d "$tmp/z" 2>/dev/null || die "$zipname does not hold $order"
else
  # The heavy-job shim (E15-3) goes beside the runner, where it looks for it; optional, so an older release still installs.
  # (no `grep -q`: under pipefail its early exit can SIGPIPE the echo and read as "absent")
  if [ "${part:-}" != core ] && echo "$names" | grep -x "ainkrad-job-[0-9].*-$target" >/dev/null; then order="$order ainkrad-job"; fi
  # A release is all four: a set without the CLI (first-device step) or ptyhost (terminals) is refused, not half-installed.
  for b in $order; do
    echo "$names" | grep -qx "$b-[0-9].*-$target" || die "the signed sums have no $b for $target"
  done
  for b in $order; do verify "$(echo "$names" | grep -x "$b-[0-9].*-$target" | head -1)"; done
  for b in $order; do cp "$tmp/$(echo "$names" | grep -x "$b-[0-9].*-$target" | head -1)" "$tmp/z/$b"; done
fi
# The default prefix is ~/.local; a caller with no HOME (the systemd updater) must pass --prefix.
[ -n "$prefix" ] || { [ -n "${HOME:-}" ] || die "no HOME: pass --prefix"; prefix=$HOME/.local; }
bindir=$prefix/bin
mkdir -p "$bindir"
stage=$(mktemp -d "$bindir/.stage.XXXXXX") || die "cannot stage in $bindir"
for b in $order; do
  install -m 755 "$tmp/z/$b" "$stage/$b" || die "cannot stage $b in $bindir"
done
placed= moved=
rollback() {
  for b in $placed; do rm -f "$bindir/$b"; done
  for b in $moved; do mv -f "$bindir/$b.old" "$bindir/$b"; done
}
step=0
for b in $order; do
  step=$((step + 1))
  # AINKRAD_INSTALL_FAIL_AT=<n> makes step n fail; it exists for test-install.sh only.
  [ "${AINKRAD_INSTALL_FAIL_AT:-}" != "$step" ] || { rollback; die "could not install $b; restored the previous binaries in $bindir"; }
  if [ -e "$bindir/$b" ]; then
    { rm -f "$bindir/$b.old" && mv -f "$bindir/$b" "$bindir/$b.old"; } || { rollback; die "could not install $b; restored the previous binaries in $bindir"; }
    moved="$moved $b"
  fi
  mv -f "$stage/$b" "$bindir/$b" || { rollback; die "could not install $b; restored the previous binaries in $bindir"; }
  placed="$placed $b"
done
for b in $order; do rm -f "$bindir/$b.old"; echo "installed $bindir/$b"; done
