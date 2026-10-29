#!/usr/bin/env bash
# Generates the Swift client (E1-05.2) from api/openapi.json into <clients-dir>/swift/generated and
# fails on any generator warning (E0.4): swift-openapi-generator drops a property it cannot express
# with only a warning, so a clean log is the check.
#
#   scripts/contract-swift.sh [<clients-dir>]        (default: clients; swift/ inside is written)
#
# Generator: swift-openapi-generator 1.14.2 (apple/swift-openapi-generator, tag 1.14.2), built once into
# $GENERATOR_HOME (default ~/.cache/ainkrad-core-tools); or set GENERATOR to a binary of that version.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-clients}/swift"
GENERATOR_HOME="${GENERATOR_HOME:-$HOME/.cache/ainkrad-core-tools}"
if [ -z "${GENERATOR:-}" ]; then
  src="$GENERATOR_HOME/swift-openapi-generator-1.14.2"
  if [ ! -x "$src/.build/release/swift-openapi-generator" ]; then
    mkdir -p "$GENERATOR_HOME"
    git clone -q --depth 1 -b 1.14.2 https://github.com/apple/swift-openapi-generator "$src"
    (cd "$src" && swift build -c release >&2)
  fi
  GENERATOR="$src/.build/release/swift-openapi-generator"
fi
log="$(mktemp)"; trap 'rm -f "$log"' EXIT
rm -rf "$out/generated"
mkdir -p "$out/generated"
"$GENERATOR" generate --config "$(pwd)/clients/swift/openapi-generator-config.yaml" \
  --output-directory "$out/generated" api/openapi.json > "$log" 2>&1 || { cat "$log" >&2; exit 1; }
if grep -i "warning\|error" "$log"; then
  echo "contract-swift: the generator was not clean" >&2
  exit 1
fi
echo "contract-swift: clean; Swift client in $out/generated"
