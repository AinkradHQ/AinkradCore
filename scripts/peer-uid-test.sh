#!/usr/bin/env bash
# Handshake spec §17.25 with a real second OS user (KAN-251): builds the `peer_uid` test as you,
# then runs only that test binary as root, which serves admin.sock and sends a claim as `nobody`.
# sudo asks for your password here; nothing else runs as root (no cargo, no target/ writes).
#   scripts/peer-uid-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
bin="$(cargo test -p ainkrad-core-server --test peer_uid --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import json,sys
for l in sys.stdin:
    m = json.loads(l)
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["name"] == "peer_uid":
        print(m["executable"])')"
[ -x "$bin" ] || { echo "peer-uid-test: the test binary was not built" >&2; exit 1; }
sudo "$bin" --ignored --exact another_uid_on_the_admin_socket_cannot_claim_a_bootstrap_pairing --nocapture
