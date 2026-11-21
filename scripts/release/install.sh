#!/usr/bin/env bash
# E1-15.4: verify, then install. Nothing is written to the prefix unless the signature AND every checksum hold.
#   install.sh --from <dir|https-url> [--prefix DIR] [--pubkey FILE] [--target T] [--verify-only FILE] [--scripts DIR] [--units DIR]
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
# --units DIR (the self-updater, Core mode): the same, for the host helper's systemd units (deploy/systemd/ainkrad-host.socket,
# ainkrad-host@.service) into DIR, mode 0644. A bundle without them installs none (older releases).
# ainkrad-host (the root host helper) and ainkrad-job (the runner's heavy-job shim) are optional members of a set: installed with
# the Core's and the runner's programs when the signed sums have them, so an older release still installs.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
from= prefix= pub=${AINKRAD_RELEASE_PUBKEY:-$here/ainkrad-release.pub} target= only= part= scripts= units=
while [ $# -gt 0 ]; do case $1 in
  --from) from=$2; shift 2 ;; --prefix) prefix=$2; shift 2 ;; --pubkey) pub=$2; shift 2 ;;
  --target) target=$2; shift 2 ;; --only) part=$2; shift 2 ;; --verify-only) only=$2; shift 2 ;; --scripts) scripts=$2; shift 2 ;; --units) units=$2; shift 2 ;; *) echo "unknown option $1" >&2; exit 2 ;;
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
if [ -n "$scripts$units" ]; then
  bundle=$(awk '$2 ~ /^ainkrad-core-installer-[0-9][0-9A-Za-z.+-]*\.tar\.gz$/ { print $2 }' "$tmp/SHA256SUMS")
  [ -n "$bundle" ] && [ "$(echo "$bundle" | wc -l)" -eq 1 ] || die "the signed sums have no single installer bundle"
  verify "$bundle"
  top=${bundle%.tar.gz}
  # The whole (verified) bundle into an empty dir; it must hold exactly one top folder, named for the bundle; files are then
  # picked from the tree by exact path. Not GNU tar: under the updater unit's RestrictSUIDSGID=yes it fails every member
  # (ENOSYS from openat2). Python's tarfile, by hand: only plain files and folders, no absolute or `..` path, no link, no mode
  # bits beyond 0755 (python3 is already required by update.sh).
  mkdir "$tmp/s"
  command -v python3 >/dev/null || die "python3 is not installed"
  python3 -I - "$tmp/$bundle" "$tmp/s" 2>"$tmp/tar.err" <<'PY' || die "$bundle does not unpack: $(tail -c 200 "$tmp/tar.err")"
import os, sys, tarfile
src, dst = sys.argv[1], sys.argv[2]
with tarfile.open(src, "r:gz") as t:
    for m in t:
        name = os.path.normpath(m.name)
        if name == "." or name.startswith(("/", "..")) or not (m.isfile() or m.isdir()):
            continue   # never a link, a device or a path outside; the caller refuses what it needed and did not get
        if os.path.basename(name).startswith("._"):
            continue   # macOS tar's AppleDouble metadata (a bundle made on a Mac), never a file of ours
        out = os.path.join(dst, name)
        if m.isdir():
            os.makedirs(out, mode=0o755, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(out), mode=0o755, exist_ok=True)
        with t.extractfile(m) as f, open(out, "xb") as o:
            o.write(f.read())
        os.chmod(out, m.mode & 0o755)
PY
  [ "$(ls -A "$tmp/s")" = "$top" ] && [ -d "$tmp/s/$top" ] && [ ! -L "$tmp/s/$top" ] || die "$bundle does not hold the single folder $top"
  place() { # place SRC DIR NAME MODE: a plain file, as a temp file renamed into place
    { [ -f "$1" ] && [ ! -L "$1" ]; } || die "$3 in $bundle is not a plain file"
    new=$(mktemp "$2/.$3.XXXXXX") || die "cannot place $3 in $2"
    { install -m "$4" "$1" "$new" && mv -f "$new" "$2/$3"; } || { rm -f "$new"; die "cannot place $3 in $2"; }
    echo "installed $2/$3"
  }
  if [ -n "$scripts" ]; then
    # model.sh is optional (older bundles have none).
    for f in update.sh install.sh; do src=$tmp/s/$top/scripts/release/$f; [ -e "$src" ] || [ -L "$src" ] || die "$bundle has no $top/scripts/release/$f"; done
    for f in update.sh install.sh model.sh; do
      src=$tmp/s/$top/scripts/release/$f
      [ -e "$src" ] || [ -L "$src" ] || continue
      place "$src" "$scripts" "$f" 0755
    done
  fi
  if [ -n "$units" ]; then
    for f in ainkrad-host.socket ainkrad-host@.service; do
      src=$tmp/s/$top/deploy/systemd/$f
      [ -e "$src" ] || [ -L "$src" ] || continue
      place "$src" "$units" "$f" 0644
    done
  fi
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
  if [ "${part:-}" != runner ] && echo "$names" | grep -x "ainkrad-host-[0-9].*-$target" >/dev/null; then order="$order ainkrad-host"; fi
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
