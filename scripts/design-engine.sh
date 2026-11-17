#!/usr/bin/env bash
# DesignEngine (V2-02, T6): the C header and the xcframework the Mac app links (V3-02).
#   scripts/design-engine.sh header        regenerate modules/design/ffi/include/DesignEngine.h (cbindgen, pinned)
#   scripts/design-engine.sh check-header  fail when the committed header differs from a fresh one
#   scripts/design-engine.sh build [OUT]   release static libs for arm64 + x86_64 (`--features metal`) -> one
#                                          universal libDesignEngine.a + header + module map ->
#                                          OUT/DesignEngine.xcframework (default target/engine) and OUT/SHA256SUMS
# Reproducible: source paths are remapped, Cargo.lock is --locked, Skia comes from the pinned prebuilt binaries, so two
# builds from different checkouts give the same SHA256SUMS (proof: build twice, `diff` the two SHA256SUMS).
# Needs: macOS with the Xcode command-line tools (lipo, xcodebuild -create-xcframework; Xcode 16 is enough), rustup
# targets aarch64-apple-darwin + x86_64-apple-darwin, cbindgen $CBINDGEN_VERSION for the header.
set -euo pipefail
cd "$(dirname "$0")/.."
CBINDGEN_VERSION=0.29.0
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
  *) sed -n '2,11p' "$0"; exit 2 ;;
esac
