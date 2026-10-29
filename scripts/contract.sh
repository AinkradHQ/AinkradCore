#!/usr/bin/env bash
# Emits the three contract files (E1-05.1) into <out-dir> (default api/): openapi.json (client API,
# OpenAPI 3.1), events.schema.json (event stream) and runner.schema.json (runner wire protocol).
# Output is deterministic; each file is written only after its generator succeeded.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-api}"
mkdir -p "$out"
cargo build -q -p ainkrad-core-server -p ainkrad-proto --examples
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
cargo run -q -p ainkrad-core-server -- openapi > "$t/openapi.json"
cargo run -q -p ainkrad-core-server --example events_schema > "$t/events.schema.json"
cargo run -q -p ainkrad-proto --example runner_schema > "$t/runner.schema.json"
cp "$t"/*.json "$out/"
