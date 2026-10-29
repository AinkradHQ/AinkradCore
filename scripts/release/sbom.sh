#!/usr/bin/env bash
# E1-15.4 SBOM: scripts/release/sbom.sh <dist-dir>  ->  <dist-dir>/sbom/<crate>.cdx.json for the two shipped binaries,
# then a sanity check: valid CycloneDX JSON, and every crate `cargo tree` resolves for the binary is a component.
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${1:?dist dir}/sbom; mkdir -p "$out"
for crate in ainkrad-core-server ainkrad-runner; do
  dir=crates/${crate#ainkrad-}; [ "$crate" = ainkrad-core-server ] && dir=crates/server
  cargo cyclonedx --manifest-path "$dir/Cargo.toml" --format json --describe binaries --target all -q
  # cargo-cyclonedx writes beside the manifest; take it from there and leave the tree clean.
  f=$(ls "$dir"/*.cdx.json); mv "$f" "$out/$crate.cdx.json"
  python3 -I - "$out/$crate.cdx.json" "$crate" <<'PY'
import json, subprocess, sys
path, crate = sys.argv[1:]
bom = json.load(open(path))
assert bom["bomFormat"] == "CycloneDX", bom.get("bomFormat")
names = {(c["name"], c.get("version")) for c in bom.get("components", [])}
tree = subprocess.check_output(["cargo", "tree", "-p", crate, "--locked", "-e", "normal,build", "--prefix", "none", "--target", "all"], text=True)
want = {(l.split()[0], l.split()[1].lstrip("v")) for l in tree.splitlines() if l.strip()}
missing = {w for w in want if w not in names and not w[0].startswith("ainkrad")}
print(f"{crate}: {len(names)} components, {len(want)} crates in the tree, missing {len(missing)}")
assert not missing, sorted(missing)[:10]
PY
done
