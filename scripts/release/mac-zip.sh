#!/usr/bin/env bash
# The macOS runner release asset: scripts/release/mac-zip.sh <bin-dir> <out-dir> <version>
# <out-dir>/ainkrad-runner-<version>-macos-arm64.zip holding exactly `ainkrad-runner` and `ainkrad-ptyhost` (from build.sh's
# macos-arm64 output). NOT signed or notarised with an Apple identity: the Mac app re-signs the helpers with its own when
# it bundles them. Byte-identical for the same inputs: fixed member order, mtimes from SOURCE_DATE_EPOCH, no extra attributes.
# Prints the zip's SHA-256 (the app's scripts/runner.pin value).
set -euo pipefail
bin=${1:?bin dir}; out=${2:?out dir}; ver=${3:?version}
case $ver in *[!0-9A-Za-z.+-]* | '') echo "mac-zip: bad version '$ver'" >&2; exit 2 ;; esac
for b in ainkrad-runner ainkrad-ptyhost; do [ -f "$bin/$b" ] || { echo "mac-zip: no $b in $bin" >&2; exit 1; }; done
command -v zip >/dev/null || { echo "mac-zip: zip is not installed" >&2; exit 1; }
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct)}"
mkdir -p "$out"; out=$(cd "$out" && pwd); zipf=$out/ainkrad-runner-$ver-macos-arm64.zip
st=$(mktemp -d); trap 'rm -rf "$st"' EXIT
for b in ainkrad-runner ainkrad-ptyhost; do
  install -m 755 "$bin/$b" "$st/$b"
  touch -t "$(date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S 2>/dev/null || date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)" "$st/$b"
done
rm -f "$zipf"
(cd "$st" && TZ=UTC zip -X -q "$zipf" ainkrad-runner ainkrad-ptyhost)
echo "mac-zip: $zipf"
echo "mac-zip: sha256 $(shasum -a 256 "$zipf" | cut -d' ' -f1)"
