#!/usr/bin/env bash
# The Brain's and Lore's local model (multilingual-e5-small, MIT), pinned by revision and SHA-256: the same three files as
# crates/embed/src/local.rs FILES (test-update.sh holds the two lists equal). Installed to /usr/local/lib/ainkrad/model.sh;
# deploy/install-core-linux.sh runs it on install and update.sh on every Core-mode run.
#   model.sh DIR [FROM]   (DIR: the Core's model directory, /var/lib/ainkrad/core/models/e5-small)
# Runs AS the Core user (ainkrad), never root: DIR is inside the Core's own home, where root following a planted link
# could be made to write anywhere. Each file is fetched (or copied from FROM, a directory of the same files) to a temp
# name, held to its pin, and only then renamed into place, so a partial or swapped file never sits under the real name.
# The Core re-checks every hash when it loads the model. Idempotent: files that already match are kept. Prints
# "model: installed" when it changed something, "model: present" when not; exits non-zero on any failure.
set -euo pipefail
dir=${1:?model directory} from=${2:-}
rev=614241f622f53c4eeff9890bdc4f31cfecc418b3
base=https://huggingface.co/intfloat/multilingual-e5-small/resolve/$rev
pins="config.json:69137736cab8b8903a07fe8afaafdda25aac55415a12a55d1bffa9f581abf959
tokenizer.json:0b44a9d7b51c3c62626640cda0e2c2f70fdacdc25bbbd68038369d14ebdf4c39
model.safetensors:1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477"
# Test hooks only (test-update.sh): throwaway pins and a local source. Never set by the installer or the unit.
if [ "${AINKRAD_MODEL_TEST:-}" = 1 ]; then pins=${MODEL_TEST_PINS:-$pins} base=${MODEL_TEST_BASE:-$base}; fi
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
umask 022
mkdir -p "$dir"
tmp=; trap 'rm -f ${tmp:+"$tmp"}' EXIT
changed=0
for p in $pins; do
  name=${p%%:*} want=${p##*:}
  [ -f "$dir/$name" ] && [ ! -L "$dir/$name" ] && [ "$(sha "$dir/$name")" = "$want" ] && continue
  tmp=$(mktemp "$dir/.$name.XXXXXX")
  if [ -n "$from" ] && [ -f "$from/$name" ]; then cp "$from/$name" "$tmp"
  else
    case $base in
      https://*) curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --max-time 1800 -o "$tmp" "$base/$name" ;;
      /*) cp "$base/$name" "$tmp" ;;
      *) echo "model: bad source" >&2; exit 1 ;;
    esac
  fi
  [ "$(sha "$tmp")" = "$want" ] || { echo "model: $name does not match its pinned SHA-256" >&2; exit 1; }
  chmod 0644 "$tmp" && mv -f "$tmp" "$dir/$name"; tmp=; changed=1
done
if [ "$changed" = 1 ]; then echo "model: installed"; else echo "model: present"; fi
