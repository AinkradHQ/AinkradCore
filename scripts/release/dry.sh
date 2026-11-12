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
  # macOS ships as ONE zip (runner + ptyhost, no Apple signature), exactly like the real release; the other three binaries stay unshipped.
  [ "$t" = macos-arm64 ] && { $here/mac-zip.sh "dist/.build/$t" "$out" "$ver"; continue; }
  for b in ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost; do cp "dist/.build/$t/$b" "$out/$b-$ver-$t"; done
done
# The installer bundle scripts/get.sh runs after it has verified it against the signed sums, and get.sh itself (the
# one-line install fetches it from the release: .../releases/latest/download/get.sh; it carries the pinned key and is in the signed sums).
git archive --format=tar.gz --prefix="ainkrad-core-installer-$ver/" -o "$out/ainkrad-core-installer-$ver.tar.gz" HEAD \
  scripts/install.sh scripts/install scripts/host scripts/release/install.sh deploy/install-core-linux.sh deploy/install-linux.sh deploy/systemd deploy/shell
# From the same commit as the bundle, stamped with this version as the floor against downgrades; signed with the sums.
git show HEAD:scripts/get.sh | sed "s/^\( *\)MIN_VERSION=[0-9.]*/\1MIN_VERSION=$ver/" > "$out/get.sh"; chmod 755 "$out/get.sh"
grep -q "^ *MIN_VERSION=$ver " "$out/get.sh" || { echo "release-dry: get.sh was not stamped with $ver" >&2; exit 1; }
# The Apple codesign/launch check runs on COPIES of the macOS binaries: the shipped zip stays unsigned.
case " $targets " in *" macos-arm64 "*) m=$(mktemp -d); cp dist/.build/macos-arm64/* "$m/"; $here/macos.sh "$m"/*; rm -rf "$m" ;; *) export AINKRAD_RELEASE_NO_MAC=1 ;; esac
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
if [ "$host" = macos-arm64 ] && [ -f "$out/ainkrad-runner-$ver-macos-arm64.zip" ]; then
  # A Mac checks the target it ships: the zip is verified against the signed sums and unpacked (runner + ptyhost only).
  $here/install.sh --from "$out" --pubkey "$out/dry-run-test.pub" --prefix "$p" --target macos-arm64 2>&1 | tail -3
  [ "$(ls "$p/bin" | tr '\n' ' ')" = "ainkrad-ptyhost ainkrad-runner " ] || { echo "release-dry: the macos zip did not install exactly runner + ptyhost" >&2; exit 1; }
  "$p/bin/ainkrad-runner" --version
else
  $here/install.sh --from "$out" --pubkey "$out/dry-run-test.pub" --prefix "$p" --target "$host" 2>&1 | tail -5
  # The installed set runs (ptyhost has no --version: it must sit beside the runner, where the runner finds it).
  for b in ainkrad-core-server ainkrad-runner ainkradctl; do "$p/bin/$b" --version; done
  [ -x "$p/bin/ainkrad-ptyhost" ] || { echo "release-dry: ainkrad-ptyhost is not installed beside ainkrad-runner" >&2; exit 1; }
  $here/self-verify.sh "$p/bin/ainkrad-runner" --from "$out" --pubkey "$out/dry-run-test.pub"
fi
rm -rf "$p" dist/.build
echo; echo "release-dry: $out (nothing tagged, notarised or published)"; cat "$out/SHA256SUMS"
