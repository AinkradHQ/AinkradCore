#!/usr/bin/env bash
# E12-4b: scripts/release/manifest.sh <version> <url-prefix> <out manifest.json> [existing manifest.json]
# The latest-versions manifest the Core and runner updaters read (update.sh): one entry per channel, `core` and `runner`
# (they ship together, from the one dist dir whose SHA256SUMS install.sh verifies), the targets that release has,
# `generated` (never goes backwards: a replayed older manifest is refused by the updaters) and `expires` (90 days).
# The caller signs it with `minisign -S -l` (legacy, non-prehashed: the ainkrad.io Worker verifies it with plain Ed25519).
# URGENT=1 marks the core entry urgent. No other channel than `stable` yet.
set -euo pipefail
ver=${1:?version}; prefix=${2:?url prefix, no trailing slash}; out=${3:?out}; prev=${4:-}
case $ver in *[!0-9A-Za-z.+-]* | '') echo "manifest: bad version" >&2; exit 2 ;; esac
case $prefix in https://*) ;; /*) ;; *) echo "manifest: the prefix is an https URL" >&2; exit 2 ;; esac
URGENT=${URGENT:-0} python3 -I - "$ver" "$prefix" "$out" "$prev" "${TARGETS:-linux-x86_64 linux-arm64 macos-arm64}" <<'PY'
import json, os, sys, time
ver, prefix, out, prev, targets = sys.argv[1:6]
old = {}
if prev:
    try: old = json.load(open(prev))
    except Exception: old = {}
now = int(time.time())
gen = max(now, int(old.get("generated", 0)) + 1)
entry = {"version": ver, "url": f"{prefix}/core/{ver}", "targets": targets.split()}
if os.environ.get("URGENT") == "1": entry["urgent"] = True   # the app now needs this Core: install off-window
m = {"schema": 1, "generated": gen, "expires": now + 90 * 86400,
     "channels": {"stable": {"core": entry, "runner": dict(entry)}}}
# the app entry belongs to the app release (its own workflow writes it): keep whatever is there
app = old.get("channels", {}).get("stable", {}).get("app")
if app: m["channels"]["stable"]["app"] = app
json.dump(m, open(out, "w"), indent=2, sort_keys=True); open(out, "a").write("\n")
PY
