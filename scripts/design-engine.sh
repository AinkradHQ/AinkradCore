#!/usr/bin/env bash
# DesignEngine (V2-02, T6): the C header and the xcframework the Mac app links (V3-02).
#   scripts/design-engine.sh header        regenerate modules/design/ffi/include/DesignEngine.h (cbindgen, pinned)
#   scripts/design-engine.sh check-header  fail when the committed header differs from a fresh one
#   scripts/design-engine.sh build [OUT]   release static libs for arm64 + x86_64 (`--features metal`) -> one
#                                          universal libDesignEngine.a + header + module map ->
#                                          OUT/DesignEngine.xcframework (default target/engine) and OUT/SHA256SUMS
# Reproducible: source paths are remapped, Cargo.lock is --locked, and Skia (T6) is the rust-skia prebuilt archive for
# each target, downloaded into $SKIA_CACHE and checked against the sha256 pinned below before skia-bindings sees it
# (`SKIA_BINARIES_URL=file://...`, the variable skia-bindings 0.157 reads; `{key}` is filled in by it). A download or
# hash failure stops the build. skia-bindings' fallback, a Skia source build, is off: design-ffi enables its
# `no-compile` feature, so a missing archive fails instead of compiling Skia. Two builds from different checkouts
# give the same SHA256SUMS (proof: build twice, `diff` the two SHA256SUMS).
# Needs: macOS with the Xcode command-line tools (lipo, xcodebuild -create-xcframework; Xcode 16 is enough), rustup
# targets aarch64-apple-darwin + x86_64-apple-darwin, cbindgen $CBINDGEN_VERSION for the header.
set -euo pipefail
cd "$(dirname "$0")/.."
CBINDGEN_VERSION=0.29.0
# Skia prebuilt archives: skia-binaries-<rust-skia hash>-<target>-<features>.tar.gz from
# github.com/rust-skia/skia-binaries release $SKIA_TAG (the features skia-safe gets from design-ffi --features metal).
SKIA_TAG=0.157.0
SKIA_KEY_PREFIX=30669978c3f39a73e8a7
SKIA_KEY_FEATURES=ganesh-jpegd-jpege-metal-pdf-textlayout
skia_sha256() {
  case "$1" in
    aarch64-apple-darwin) echo b728765cc1889a5f6c5e2b3c2db305244831e27d846bbc90a739b73e88b09289 ;;
    x86_64-apple-darwin) echo 9d0a6976211c1df80cd4302b501d701bea56a08a047b6010a0b9a320ade4ddba ;;
    *) echo "no pinned Skia archive for $1" >&2; exit 1 ;;
  esac
}

# Download (once) and verify the archive for target $1 into $SKIA_CACHE.
skia_fetch() {
  local f="skia-binaries-$SKIA_KEY_PREFIX-$1-$SKIA_KEY_FEATURES.tar.gz" want got
  want=$(skia_sha256 "$1")
  if [ ! -f "$SKIA_CACHE/$f" ]; then
    curl -fsSL --retry 3 -o "$SKIA_CACHE/$f.part" \
      "https://github.com/rust-skia/skia-binaries/releases/download/$SKIA_TAG/$f" \
      || { rm -f "$SKIA_CACHE/$f.part"; echo "Skia download failed: $f" >&2; exit 1; }
    mv "$SKIA_CACHE/$f.part" "$SKIA_CACHE/$f"
  fi
  got=$(shasum -a 256 "$SKIA_CACHE/$f" | awk '{print $1}')
  if [ "$got" != "$want" ]; then
    rm -f "$SKIA_CACHE/$f"
    echo "Skia archive $f: sha256 $got, pinned $want" >&2
    exit 1
  fi
}
FFI=modules/design/ffi
HDR=$FFI/include/DesignEngine.h

gen() { # OUT
  local v
  v=$(cbindgen --version 2>/dev/null | awk '{print $2}')
  if [ "$v" != "$CBINDGEN_VERSION" ]; then
    echo "need cbindgen $CBINDGEN_VERSION (cargo install cbindgen --version $CBINDGEN_VERSION --locked), have ${v:-none}" >&2
    exit 1
  fi
  cbindgen --quiet --config "$FFI/cbindgen.toml" --crate design-ffi --output "$1" "$FFI"
}

case "${1:-}" in
  header) gen "$HDR" ;;
  check-header)
    t=$(mktemp)
    gen "$t"
    if ! diff -u "$HDR" "$t"; then
      rm -f "$t"
      echo "DesignEngine.h is stale: scripts/design-engine.sh header" >&2
      exit 1
    fi
    rm -f "$t"
    ;;
  build)
    out=${2:-target/engine}
    SKIA_CACHE=${SKIA_CACHE:-$HOME/.cache/ainkrad-skia/$SKIA_TAG}
    mkdir -p "$SKIA_CACHE"
    for t in aarch64-apple-darwin x86_64-apple-darwin; do skia_fetch "$t"; done
    export SKIA_BINARIES_URL="file://$SKIA_CACHE/skia-binaries-{key}.tar.gz"
    unset FORCE_SKIA_BUILD FORCE_SKIA_BINARIES_DOWNLOAD SKIA_LIBRARY_SEARCH_PATH SKIA_SOURCE_DIR
    export RUSTFLAGS="--remap-path-prefix=$PWD=/ainkrad --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
    libs=()
    for t in aarch64-apple-darwin x86_64-apple-darwin; do
      cargo build --release --locked --manifest-path modules/design/Cargo.toml -p design-ffi --features metal --target "$t"
      libs+=("modules/design/target/$t/release/libdesign_ffi.a")
    done
    rm -rf "$out"
    mkdir -p "$out/lib" "$out/include"
    lipo -create "${libs[@]}" -output "$out/lib/libDesignEngine.a"
    cp "$HDR" "$out/include/"
    printf 'module DesignEngine {\n  header "DesignEngine.h"\n  export *\n}\n' > "$out/include/module.modulemap"
    xcodebuild -create-xcframework -library "$out/lib/libDesignEngine.a" -headers "$out/include" \
      -output "$out/DesignEngine.xcframework" > /dev/null
    (cd "$out" && find DesignEngine.xcframework -type f | LC_ALL=C sort | xargs shasum -a 256 > SHA256SUMS)
    cat "$out/SHA256SUMS"
    ;;
  *) sed -n '2,14p' "$0"; exit 2 ;;
esac
