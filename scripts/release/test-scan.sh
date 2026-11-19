#!/usr/bin/env bash
# E12-6: scan-real-data.py finds a token, an email and a host even after the file was deleted (history), and ignores documentation emails.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); w=$(mktemp -d); trap 'rm -rf "$w"' EXIT
git -C "$w" init -q
printf 'host=192.168.1.173\nok=a@example.com\nme@real-person.dev\nkey=ghp_%s\n' "$(printf 'a%.0s' $(seq 1 36))" > "$w/a.txt"
git -C "$w" add -A; git -C "$w" -c user.email=x@example.com -c user.name=t commit -qm x
git -C "$w" rm -q a.txt; git -C "$w" -c user.email=x@example.com -c user.name=t commit -qm rm
out=$(python3 -I "$here/../scan-real-data.py" --history "$w")
for r in token email host; do echo "$out" | grep -q "^$r	history:" || { echo "FAIL: no $r finding in history"; exit 1; }; done
[ "$(echo "$out" | grep -c '^email')" = 1 ] || { echo "FAIL: a documentation email was reported"; exit 1; }
echo "$out" | grep -q 'ghp_aaaa' && { echo "FAIL: a whole token was printed"; exit 1; }
echo "ok   scan-real-data finds history findings, skips documentation emails, masks values"
