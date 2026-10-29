#!/usr/bin/env bash
# One target's shipped binaries (E1-15.1): scripts/release/build.sh <linux-arm64|linux-x86_64|macos-arm64> <out-dir> [tag]
# Deterministic: --locked, the `dist` profile (codegen-units=1, strip), SOURCE_DATE_EPOCH and the commit
# pinned from outside, every build-machine path remapped. `tag` names the scratch target dir, so two builds
# of the same commit (a, b) share nothing and their equality proves reproducibility.
set -euo pipefail
target=${1:?target}; out=${2:?out dir}; tag=${3:-a}
cd "$(dirname "$0")/../.."
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct)}"
: "${CITADEL_GIT_SHA:=$(git rev-parse --short=12 HEAD)}"
export SOURCE_DATE_EPOCH CITADEL_GIT_SHA
image=${RUST_IMAGE:-rust:1.99.1}
bins=(ainkrad-core-server ainkrad-runner)
cmd="cargo build --profile dist --locked -p ainkrad-core-server -p ainkrad-runner"
mkdir -p "$out/$target"
case $target in
macos-arm64)
  td=${DIST_TARGET_DIR:-$PWD/target/dist-$tag}
  sysroot=$(rustc --print sysroot)
  export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$sysroot=/rustup"
  CARGO_TARGET_DIR=$td $cmd
  for b in "${bins[@]}"; do cp "$td/dist/$b" "$out/$target/$b"; done ;;
linux-*)
  arch=${target#linux-}; case $arch in arm64) plat=linux/arm64 ;; x86_64) plat=linux/amd64 ;; *) exit 2 ;; esac
  # One cache volume per checkout and arch, named as the Makefile's `clean-linux` frees them.
  vol=ainkrad-core-target-$(printf %s "$PWD" | shasum | cut -c1-12)-${plat#linux/}
  docker run --rm --platform "$plat" -v "$PWD:/src:ro" -w /src -v "$(cd "$out" && pwd):/out" \
    -v ainkrad-core-cargo:/usr/local/cargo/registry -v "$vol:/cache" \
    -e CARGO_TARGET_DIR=/cache/dist-$tag -e SOURCE_DATE_EPOCH -e CITADEL_GIT_SHA -e CARGO_PROFILE_DIST_STRIP \
    -e RUSTFLAGS="--remap-path-prefix=/src=. --remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/usr/local/rustup=/rustup" \
    "$image" sh -c "rustup show >/dev/null && $cmd && for b in ${bins[*]}; do cp /cache/dist-$tag/dist/\$b /out/$target/\$b; done" ;;
*) echo "unknown target $target" >&2; exit 2 ;;
esac
