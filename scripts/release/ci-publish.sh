#!/usr/bin/env bash
# E12-4b: scripts/release/ci-publish.sh <dist/version> <minisign-secret-key>
# Uploads the signed release dir to ainkrad.io (R2, through the guarded upload route), then publishes the signed manifest LAST, so a
# manifest never names files that are not there yet. Env: RELEASE_UPLOAD_TOKEN (from the `release` environment), RELEASE_BASE
# (default https://ainkrad.io/releases). Prints no secret. The GitHub release (the mirror) is made by the workflow.
set -euo pipefail
cd "$(dirname "$0")/../.."
dir=${1:?dist dir}; key=${2:?secret key file}
: "${RELEASE_UPLOAD_TOKEN:?}"; base=${RELEASE_BASE:-https://ainkrad.io/releases}
ver=$(basename "$dir")
put() { # put KEY FILE
  curl -fsS --proto '=https' --tlsv1.3 --retry 3 -X PUT -H "Authorization: Bearer $RELEASE_UPLOAD_TOKEN" \
    --data-binary "@$2" -o /dev/null "$base/upload/$1"
}
for f in "$dir"/*; do
  [ -f "$f" ] || continue
  put "core/$ver/$(basename "$f")" "$f"
  echo "uploaded core/$ver/$(basename "$f")"
done
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT
curl -fsS --proto '=https' -o "$w/prev.json" "$base/manifest.json" || echo '{}' > "$w/prev.json"
scripts/release/manifest.sh "$ver" "$base" "$w/manifest.json" "$w/prev.json"
minisign -S -s "$key" -m "$w/manifest.json" -x "$w/manifest.json.minisig" -t "ainkrad manifest $ver"
minisign -Vq -p scripts/release/ainkrad-release.pub -x "$w/manifest.json.minisig" -m "$w/manifest.json"   # the pinned key must verify it
put manifest.json "$w/manifest.json"
put manifest.json.minisig "$w/manifest.json.minisig"
echo "manifest.json now names core and runner $ver"
