#!/usr/bin/env bash
# E12-3 tests for update.sh: no root, a scratch tree, a fake systemctl, throwaway keys. Covers: an update installs;
# a failed health check rolls binaries AND database back; a bad signature, a downgrade, a replayed manifest and an
# expired manifest each change nothing; `auto` outside the night window only records what is available.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
case "$(uname -s)-$(uname -m)" in Linux-aarch64) t=linux-arm64 ;; Linux-x86_64) t=linux-x86_64 ;; Darwin-arm64) t=macos-arm64 ;; esac
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT; fail=0
minisign -G -W -f -p "$w/a.pub" -s "$w/a.key" >/dev/null; minisign -G -W -f -p "$w/b.pub" -s "$w/b.key" >/dev/null
bins="ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost"
stub() { printf '#!/bin/sh\necho "%s %s"\n' "$1" "$2"; }   # `--version` prints "<name> <ver>"
release() { # release VER [KEY]: a signed dist dir at $w/rel/core/VER
  local v=$1 d=$w/rel/core/$1; rm -rf "$d"; mkdir -p "$d"
  for b in $bins; do stub "$b" "$v" >"$d/$b-$v-$t"; done; printf '#!/bin/sh\n' >"$d/get.sh"
  AINKRAD_RELEASE_NO_MAC=1 "$here/sign.sh" "$d" "${2:-$w/a.key}" >/dev/null
}
manifest() { # manifest VER GENERATED EXPIRES [KEY]
  printf '{"schema":1,"generated":%s,"expires":%s,"channels":{"stable":{"core":{"version":"%s","url":"%s/core/%s"},"runner":{"version":"%s","url":"%s/core/%s"}}}}\n' "$2" "$3" "$1" "$w/rel" "$1" "$1" "$w/rel" "$1" >"$w/rel/manifest.json"
  rm -f "$w/rel/manifest.json.minisig"; minisign -S -s "${4:-$w/a.key}" -m "$w/rel/manifest.json" -x "$w/rel/manifest.json.minisig" >/dev/null
}
mkdir -p "$w/lib" "$w/bin"; cp "$here/install.sh" "$w/lib/"; cp "$w/a.pub" "$w/lib/ainkrad-release.pub"
cat >"$w/systemctl" <<SH
#!/bin/sh
case "\$1" in
  stop) rm -f "$w/active" ;;
  start) if [ -e "$w/bad" ] && [ "\$("$w/prefix/bin/ainkrad-core-server" | awk '{print \$2}')" = "\$(cat "$w/bad")" ]; then rm -f "$w/active"; else touch "$w/active"; fi ;;
  is-active) [ -e "$w/active" ] ;;
esac
SH
chmod +x "$w/systemctl"
setup() { # a Core on 1.0.0 with a database
  rm -rf "$w/prefix" "$w/home" "$w/state" "$w/bad"; mkdir -p "$w/prefix/bin" "$w/home" "$w/state"
  for b in $bins; do stub "$b" 1.0.0 >"$w/prefix/bin/$b"; chmod +x "$w/prefix/bin/$b"; done
  echo db-v1 >"$w/home/core.db"; touch "$w/active"
}
run() { AINKRAD_UPDATE_TEST=1 UPD_RUNNER_STATE="$w/rstate" UPD_RUNNER_GAP=0 UPD_LIB="$w/lib" UPD_PREFIX="$w/prefix" UPD_STATE="$w/state" UPD_HOME="$w/home" UPD_BASE="$w/rel" UPD_SYSTEMCTL="$w/systemctl" UPD_HEALTH_TRIES=3 UPD_HEALTH_NEED=2 UPD_HEALTH_SLEEP=0 "$here/update.sh" "${1:-now}" >"$w/out" 2>&1; }
ver() { "$w/prefix/bin/ainkrad-core-server" | awk '{print $2}'; }
st() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" "$w/state/status.json" | head -1; }
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2' wanted '$3'"; fail=1; fi; }
FUT=$(($(date +%s) + 86400))

setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; run now
check "update installs 1.1.0" "$(ver)" 1.1.0; check "status done" "$(st state)" done

setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; echo 1.1.0 >"$w/bad"; echo db-v1 >"$w/home/core.db"
# the new Core dies at start: binaries and database must be the old ones again (the bad flag is for 1.1.0 only)
run now; check "failed health rolls back the binaries" "$(ver)" 1.0.0
check "rollback restores the database" "$(cat "$w/home/core.db")" db-v1; check "status rolled_back" "$(st state)" rolled_back

setup; release 1.1.0 "$w/b.key"; manifest 1.1.0 100 "$FUT"; run now; check "a release signed by another key changes nothing" "$(ver)" 1.0.0
setup; release 1.1.0; manifest 1.1.0 100 "$FUT" "$w/b.key"; run now; check "a manifest signed by another key changes nothing" "$(ver)" 1.0.0; check "bad_signature reported" "$(st error)" bad_signature
setup; release 0.9.0; manifest 0.9.0 100 "$FUT"; run now; check "a downgrade is never installed" "$(ver)" 1.0.0
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; echo 500 >"$w/state/last_generated"; run now; check "a replayed (older) manifest is refused" "$(ver)" 1.0.0; check "manifest_replayed reported" "$(st error)" manifest_replayed
setup; release 1.1.0; manifest 1.1.0 100 1000; run now; check "an expired manifest is refused" "$(ver)" 1.0.0
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; run auto
h=$(date +%H); if [ $((10#$h)) -ge 2 ] && [ $((10#$h)) -lt 5 ]; then :; else check "auto outside the window installs nothing" "$(ver)" 1.0.0; check "auto records what is available" "$(sed -n 's/.*"available":"\([^"]*\)".*/\1/p' "$w/state/status.json")" 1.1.0; fi
# the real manifest generator, end to end: its output is what update.sh accepts
setup; release 1.1.0; "$here/manifest.sh" 1.1.0 "$w/rel" "$w/rel/manifest.json"; rm -f "$w/rel/manifest.json.minisig"
minisign -S -s "$w/a.key" -m "$w/rel/manifest.json" -x "$w/rel/manifest.json.minisig" >/dev/null; run now
check "manifest.sh output installs" "$(ver)" 1.1.0
# the runner: dropped request file -> update.sh runner installs, removes the request, leaves the Core database alone
mkdir -p "$w/rstate"
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; touch "$w/rstate/update-request"; echo db-keep >"$w/home/core.db"; run runner
check "runner mode installs 1.1.0" "$("$w/prefix/bin/ainkrad-runner" | awk '{print $2}')" 1.1.0
check "runner mode removes the request file" "$([ -e "$w/rstate/update-request" ] && echo there || echo gone)" gone
check "runner mode leaves the Core database alone" "$(cat "$w/home/core.db")" db-keep
check "runner status is separate" "$(sed -n 's/.*"state":"\([^"]*\)".*/\1/p' "$w/state/runner-status.json")" done
exit $fail
