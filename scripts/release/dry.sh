#!/usr/bin/env bash
# E1-15 `make release-dry`: scripts/release/dry.sh  (RELEASE_TARGETS="linux-arm64 linux-x86_64 macos-arm64")
# Build the shipped binaries per target, codesign the macOS ones (when the identity is present), SHA256SUMS, a
# minisign signature with a THROWAWAY key, the SBOM, then run install.sh and self-verify against the result.
# It tags nothing, notarises nothing and publishes nothing.
set -euo pipefail
cd "$(dirname "$0")/../.."
here=scripts/release
ver=$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)
targets=${RELEASE_TARGETS:-linux-arm64 linux-x86_64 macos-arm64}
out=dist/$ver
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export CITADEL_GIT_SHA=${CITADEL_GIT_SHA:-$(git rev-parse --short=12 HEAD)}
rm -rf "$out"; mkdir -p "$out" dist/.build
for t in $targets; do
  $here/build.sh "$t" dist/.build "${BUILD_TAG:-a}"
  for b in ainkrad-core-server ainkrad-runner; do cp "dist/.build/$t/$b" "$out/$b-$ver-$t"; done
done
case " $targets " in *" macos-arm64 "*) $here/macos.sh "$out"/*-macos-arm64 ;; esac
# A throwaway key: the real one is offline and Ahmed's (custody plan, E1-15.2). Generated per dry run, never kept.
key=$(mktemp -d)/dry.key
minisign -G -W -f -p "$out/dry-run-test.pub" -s "$key" >/dev/null
$here/sign.sh "$out" "$key"
rm -f "$key"
$here/sbom.sh "$out"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) host=macos-arm64 ;;
  Linux-aarch64) host=linux-arm64 ;;
  Linux-x86_64) host=linux-x86_64 ;;
esac
p=$(mktemp -d)
$here/install.sh --from "$out" --pubkey "$out/dry-run-test.pub" --prefix "$p" --target "$host" 2>&1 | tail -4
$here/self-verify.sh "$p/bin/ainkrad-runner" --from "$out" --pubkey "$out/dry-run-test.pub"
rm -rf "$p" dist/.build
echo; echo "release-dry: $out (nothing tagged, notarised or published)"; cat "$out/SHA256SUMS"
