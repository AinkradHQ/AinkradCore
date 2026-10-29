#!/usr/bin/env bash
# Generates the Swift client from api/openapi.json and fails on any generator warning (E0.4):
# swift-openapi-generator drops a property it cannot express with only a warning, so a clean
# log is the check. The plugin repo (E11.2) runs the same generator on a pinned copy.
#
#   GENERATOR=<swift-openapi-generator 1.14.2 binary> scripts/contract-swift.sh [<out-dir>]
#
# Build the generator once: git clone -b 1.14.2 https://github.com/apple/swift-openapi-generator
# && swift build -c release. The output (default: a new temp dir) is left for inspection.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${GENERATOR:?set GENERATOR to a swift-openapi-generator 1.14.2 binary}"
out="${1:-$(mktemp -d)}"
mkdir -p "$out/Generated"
printf 'generate: [types, client]\naccessModifier: public\nnamingStrategy: idiomatic\n' \
  > "$out/openapi-generator-config.yaml"
"$GENERATOR" generate --config "$out/openapi-generator-config.yaml" \
  --output-directory "$out/Generated" api/openapi.json > "$out/gen.log" 2>&1
if grep -i "warning\|error" "$out/gen.log"; then
  echo "contract-swift: the generator was not clean (see $out/gen.log)" >&2
  exit 1
fi
echo "contract-swift: clean; Swift client in $out/Generated"
