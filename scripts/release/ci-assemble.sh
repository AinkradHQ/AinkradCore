#!/usr/bin/env bash
# E12-4b: scripts/release/ci-assemble.sh <build-dir> <out-dir> <minisign-secret-key>
# <build-dir>/<target>/{ainkrad-core-server,ainkrad-runner,ainkradctl,ainkrad-ptyhost} (what build.sh made, one dir per target) become the
# signed release dir <out-dir> (= dist/<version>): the Linux binaries named as install.sh expects, the macOS runner zip, the installer
# bundle, get.sh stamped with the version, then SHA256SUMS + the minisign signature (sign.sh). Then the signed release is
# installed once with the PINNED public key: a CI key that is not the project's release key fails here, before anything is published.
set -euo pipefail
cd "$(dirname "$0")/../.."
build=${1:?build dir}; out=${2:?out dir}; key=${3:?secret key file}
here=scripts/release
ver=$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)
case $(basename "$out") in "$ver") ;; *) echo "ci-assemble: out dir must be named $ver (sign.sh reads the version from it)" >&2; exit 2 ;; esac
rm -rf "$out"; mkdir -p "$out"
for t in linux-arm64 linux-x86_64; do
  # ainkrad-job (the runner's heavy-job shim) and ainkrad-host (the root host helper) are Linux-only.
  for b in ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost ainkrad-job ainkrad-host; do cp "$build/$t/$b" "$out/$b-$ver-$t"; done
done
$here/mac-zip.sh "$build/macos-arm64" "$out" "$ver"
git archive --format=tar.gz --prefix="ainkrad-core-installer-$ver/" -o "$out/ainkrad-core-installer-$ver.tar.gz" HEAD \
  scripts/install.sh scripts/install scripts/host scripts/release/install.sh scripts/release/update.sh scripts/release/model.sh scripts/release/ainkrad-release.pub deploy/install-core-linux.sh deploy/install-linux.sh deploy/systemd deploy/shell
git show HEAD:scripts/get.sh | sed "s/^\( *\)MIN_VERSION=[0-9.]*/\1MIN_VERSION=$ver/" > "$out/get.sh"; chmod 755 "$out/get.sh"
grep -q "^ *MIN_VERSION=$ver " "$out/get.sh" || { echo "ci-assemble: get.sh was not stamped with $ver" >&2; exit 1; }
$here/sign.sh "$out" "$key"
# The pinned key must verify what the CI key signed.
p=$(mktemp -d); trap 'rm -rf "$p"' EXIT
$here/install.sh --from "$out" --pubkey "$here/ainkrad-release.pub" --prefix "$p" --target linux-x86_64 --verify-only "$out/ainkrad-runner-$ver-linux-x86_64"
ls -l "$out"
