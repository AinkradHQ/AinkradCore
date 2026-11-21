#!/usr/bin/env bash
# E12-3 tests for update.sh: no root, a scratch tree, a fake systemctl, throwaway keys. Covers: an update installs;
# a failed health check rolls binaries AND database back; a bad signature, a downgrade, a replayed manifest and an
# expired manifest each change nothing; `auto` outside the night window only records what is available (and says so).
# Every run is as systemd runs it: no HOME. A public Core's health check must send the Core's own host name. The local model
# (model.sh) is installed on Core runs, verified against its pins, kept when present, and skipped with the opt-out file.
# After a healthy update the updater's own scripts come from the release's signed installer bundle, and only from it.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
case "$(uname -s)-$(uname -m)" in Linux-aarch64) t=linux-arm64 ;; Linux-x86_64) t=linux-x86_64 ;; Darwin-arm64) t=macos-arm64 ;; esac
w=$(mktemp -d); trap 'rm -rf "$w"' EXIT; fail=0
minisign -G -W -f -p "$w/a.pub" -s "$w/a.key" >/dev/null; minisign -G -W -f -p "$w/b.pub" -s "$w/b.key" >/dev/null
bins="ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost"
stub() { printf '#!/bin/sh\necho "%s %s"\n' "$1" "$2"; }   # `--version` prints "<name> <ver>"
release() { # release VER [KEY]: a signed dist dir at $w/rel/core/VER
  local v=$1 d=$w/rel/core/$1; rm -rf "$d"; mkdir -p "$d"
  for b in $bins ainkrad-job ainkrad-host; do stub "$b" "$v" >"$d/$b-$v-$t"; done; printf '#!/bin/sh\n' >"$d/get.sh"
  # the installer bundle: the real install.sh, and update.sh/model.sh marked with the version they came from
  local s=$w/bundle/ainkrad-core-installer-$v/scripts/release; rm -rf "$w/bundle"; mkdir -p "$s"
  cp "$here/install.sh" "$s/"; echo "# release $v" >>"$s/install.sh"
  printf '#!/bin/sh\n# release %s\n' "$v" >"$s/update.sh"; printf '#!/bin/sh\necho "model: present"\n# release %s\n' "$v" >"$s/model.sh"
  # the host helper's units, as deploy/systemd ships them (git archive puts everything under the one top folder)
  mkdir -p "$w/bundle/ainkrad-core-installer-$v/deploy/systemd"
  for u in ainkrad-host.socket ainkrad-host@.service; do echo "# release $v" >"$w/bundle/ainkrad-core-installer-$v/deploy/systemd/$u"; done
  if [ "${BUNDLE_DOT:-}" = 1 ]; then tar -czf "$d/ainkrad-core-installer-$v.tar.gz" -C "$w/bundle" .   # members named ./ainkrad-core-installer-…
  else tar -czf "$d/ainkrad-core-installer-$v.tar.gz" -C "$w/bundle" "ainkrad-core-installer-$v"; fi
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
  try-restart) echo "\$2" >>"$w/restarts" ;;
  daemon-reload|enable) echo "\$*" >>"$w/calls" ;;
esac
SH
chmod +x "$w/systemctl"
setup() { # a Core on 1.0.0 with a database
  rm -rf "$w/prefix" "$w/home" "$w/state" "$w/bad"; mkdir -p "$w/prefix/bin" "$w/home" "$w/state"
  # the updater's scripts as installed: a refresh by an earlier case must not leak into this one
  rm -f "$w/lib/update.sh" "$w/lib/model.sh"; cp "$here/install.sh" "$w/lib/"; [ ! -f "$w/model-stub" ] || cp -p "$w/model-stub" "$w/lib/model.sh"
  for b in $bins; do stub "$b" 1.0.0 >"$w/prefix/bin/$b"; chmod +x "$w/prefix/bin/$b"; done
  dbset db-v1; touch "$w/active"
}
# a real SQLite file when sqlite3 exists (update.sh runs PRAGMA integrity_check on the snapshot), else plain text
dbset() { rm -f "$w/home/core.db"; if command -v sqlite3 >/dev/null; then sqlite3 "$w/home/core.db" "create table t(x); insert into t values('$1');"; else echo "$1" >"$w/home/core.db"; fi; }
dbval() { if command -v sqlite3 >/dev/null; then sqlite3 "$w/home/core.db" 'select x from t'; else cat "$w/home/core.db"; fi; }
run() { env -u HOME AINKRAD_UPDATE_TEST=1 ${UNITS_DIR:+UPD_UNITS=$UNITS_DIR} UPD_RUNNER_STATE="$w/rstate" UPD_RUNNER_GAP=0 UPD_LIB="$w/lib" UPD_PREFIX="$w/prefix" UPD_STATE="$w/state" UPD_HOME="$w/home" UPD_BASE="$w/rel" UPD_SYSTEMCTL="$w/systemctl" UPD_HEALTH_TRIES=3 UPD_HEALTH_NEED=2 UPD_HEALTH_SLEEP=0 "$here/update.sh" "${1:-now}" >"$w/out" 2>&1; [ -z "${DEBUG_UPD:-}" ] || cat "$w/out" >&2; }
ver() { "$w/prefix/bin/ainkrad-core-server" | awk '{print $2}'; }
st() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" "$w/state/status.json" | head -1; }
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2' wanted '$3'"; fail=1; fi; }
FUT=$(($(date +%s) + 86400))

setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; run now
check "update installs 1.1.0" "$(ver)" 1.1.0; check "status done" "$(st state)" done

setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; echo 1.1.0 >"$w/bad"; dbset db-v1
# the new Core dies at start: binaries and database must be the old ones again (the bad flag is for 1.1.0 only)
run now; check "failed health rolls back the binaries" "$(ver)" 1.0.0
check "rollback restores the database" "$(dbval)" db-v1; check "status rolled_back" "$(st state)" rolled_back

setup; release 1.1.0 "$w/b.key"; manifest 1.1.0 100 "$FUT"; run now; check "a release signed by another key changes nothing" "$(ver)" 1.0.0
setup; release 1.1.0; manifest 1.1.0 100 "$FUT" "$w/b.key"; run now; check "a manifest signed by another key changes nothing" "$(ver)" 1.0.0; check "bad_signature reported" "$(st error)" bad_signature
setup; release 0.9.0; manifest 0.9.0 100 "$FUT"; run now; check "a downgrade is never installed" "$(ver)" 1.0.0
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; echo 500 >"$w/state/last_generated"; run now; check "a replayed (older) manifest is refused" "$(ver)" 1.0.0; check "manifest_replayed reported" "$(st error)" manifest_replayed
setup; release 1.1.0; manifest 1.1.0 100 1000; run now; check "an expired manifest is refused" "$(ver)" 1.0.0
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; run auto
h=$(date +%H); if [ $((10#$h)) -ge 2 ] && [ $((10#$h)) -lt 5 ]; then :; else check "auto outside the window installs nothing" "$(ver)" 1.0.0; check "auto records what is available" "$(sed -n 's/.*"available":"\([^"]*\)".*/\1/p' "$w/state/status.json")" 1.1.0; fi
# the real manifest generator, end to end: its output is what update.sh accepts
setup; release 1.1.0; "$here/manifest.sh" 1.1.0 "$w/rel" "$w/rel/manifest.json"; rm -f "$w/rel/manifest.json.minisig"
minisign -S -l -s "$w/a.key" -m "$w/rel/manifest.json" -x "$w/rel/manifest.json.minisig" >/dev/null; run now
check "manifest.sh output installs" "$(ver)" 1.1.0
# semver: a pre-release is older than its release, and never replaces it
setup; release 1.0.0-rc1 ; manifest 1.0.0-rc1 100 "$FUT"; run now; check "1.0.0-rc1 is not newer than 1.0.0" "$(ver)" 1.0.0
setup; for b in $bins; do stub "$b" 1.1.0-rc1 >"$w/prefix/bin/$b"; chmod +x "$w/prefix/bin/$b"; done; release 1.1.0; manifest 1.1.0 100 "$FUT"; run now
check "1.1.0 replaces 1.1.0-rc1" "$(ver)" 1.1.0
# a database that is a symlink is refused, the Core is started again, nothing is installed
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; rm "$w/home/core.db"; ln -s /etc/hostname "$w/home/core.db"; run now
check "a symlinked database is refused" "$(st error)" unsafe_database; check "nothing installed after the refusal" "$(ver)" 1.0.0
check "the Core is running again" "$([ -e "$w/active" ] && echo up || echo down)" up
# --only: a Core update leaves the runner's programs alone
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; run now
check "core mode leaves the runner programs alone" "$("$w/prefix/bin/ainkrad-runner" | awk '{print $2}')" 1.0.0
# urgent releases install off-window in auto mode
h=$(date +%H); if [ $((10#$h)) -lt 2 ] || [ $((10#$h)) -ge 5 ]; then
  setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; sed -i.bak 's/"url"/"urgent": true, "url"/' "$w/rel/manifest.json"; rm -f "$w/rel/manifest.json.minisig"
  minisign -S -l -s "$w/a.key" -m "$w/rel/manifest.json" -x "$w/rel/manifest.json.minisig" >/dev/null; run auto
  check "an urgent release installs off-window" "$(ver)" 1.1.0
fi
# recover: the service the run stopped is started again
setup; rm -f "$w/active"; AINKRAD_UPDATE_TEST=1 UPD_SYSTEMCTL="$w/systemctl" UPD_STATE="$w/state" "$here/update.sh" recover-now; check "recover starts the Core" "$([ -e "$w/active" ] && echo up || echo down)" up
# manifest.sh keeps the app entry the app release wrote
printf '{"generated":5,"channels":{"stable":{"app":{"version":"9.9.9"}}}}' >"$w/prev.json"; "$here/manifest.sh" 1.1.0 "$w/rel" "$w/m2.json" "$w/prev.json"
check "manifest.sh keeps the app entry" "$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["channels"]["stable"]["app"]["version"])' "$w/m2.json")" 9.9.9
# the runner: dropped request file -> update.sh runner installs, removes the request, leaves the Core database alone
mkdir -p "$w/rstate"
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; touch "$w/rstate/update-request"; dbset db-keep; run runner
check "runner mode installs 1.1.0" "$("$w/prefix/bin/ainkrad-runner" | awk '{print $2}')" 1.1.0
check "runner mode removes the request file" "$([ -e "$w/rstate/update-request" ] && echo there || echo gone)" gone
check "runner mode leaves the Core database alone" "$(dbval)" db-keep
check "runner status is separate" "$(sed -n 's/.*"state":"\([^"]*\)".*/\1/p' "$w/state/runner-status.json")" done

# a public Core answers only its host name: the health check must ask for it on loopback (a bare 127.0.0.1 is a 403)
mkdir -p "$w/fake"; printf 'AINKRAD_LISTEN=public\nAINKRAD_HOSTNAME=core.example.test\n' >"$w/core.env"
cat >"$w/fake/curl" <<'SH'
#!/bin/sh
case "$*" in *"--resolve core.example.test:443:127.0.0.1 https://core.example.test/healthz"*) echo ok ;; *) echo unknown_host; exit 22 ;; esac
SH
chmod +x "$w/fake/curl"
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; (PATH=$w/fake:$PATH UPD_CORE_ENV=$w/core.env run now)
check "public health check sends the Core's host name" "$(ver)" 1.1.0; check "public health status done" "$(st state)" done
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; printf 'AINKRAD_LISTEN=public\nAINKRAD_HOSTNAME=other.example.test\n' >"$w/core2.env"
(PATH=$w/fake:$PATH UPD_CORE_ENV=$w/core2.env run now); check "a Core that does not answer its name rolls back" "$(st error)" health_failed

# auto outside the window says so: a `wait` event and a journal line
h=$(date +%H); if [ $((10#$h)) -lt 2 ] || [ $((10#$h)) -ge 5 ]; then
  setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; run auto
  check "auto off-window records a wait event" "$(grep -c '"step":"wait"' "$w/state/status.json")" 1
  check "auto off-window says when it installs" "$(grep -c 'between 02:00 and 05:00' "$w/out")" 1
fi

# the model step: a stub records each call; a new model restarts the Core; the opt-out file skips it; runner runs never call it
printf '#!/bin/sh\necho "$1" >>"%s"\necho "model: ${STUB_MODEL:-present}"\n' "$w/model-calls" >"$w/model-stub"; chmod +x "$w/model-stub"
setup; rm -f "$w/model-calls" "$w/restarts"; release 1.0.0; manifest 1.0.0 100 "$FUT"; (STUB_MODEL=installed run now)
check "a Core run installs the model into the Core's home" "$(cat "$w/model-calls" 2>/dev/null)" "$w/home/models/e5-small"
check "a newly installed model restarts the Core" "$(cat "$w/restarts" 2>/dev/null)" ainkrad-core.service
setup; rm -f "$w/model-calls" "$w/restarts"; run now; check "a present model restarts nothing" "$(cat "$w/restarts" 2>/dev/null)" ""
setup; rm -f "$w/model-calls"; touch "$w/no-model"; (UPD_NO_MODEL=$w/no-model run now); check "the opt-out file skips the model" "$(cat "$w/model-calls" 2>/dev/null)" ""
setup; rm -f "$w/model-calls"; run runner; check "a runner run never touches the model" "$(cat "$w/model-calls" 2>/dev/null)" ""
rm -f "$w/model-stub" "$w/lib/model.sh"

# the updater's own scripts: refreshed from the signed bundle after a healthy update, atomically, never otherwise
rel() { sed -n 's/^# release //p' "$w/lib/$1" 2>/dev/null | tail -1; }
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; run now
check "a healthy update refreshes update.sh" "$(rel update.sh)" 1.1.0; check "... install.sh" "$(rel install.sh)" 1.1.0; check "... model.sh" "$(rel model.sh)" 1.1.0
check "refreshed scripts are executable" "$([ -x "$w/lib/update.sh" ] && [ -x "$w/lib/install.sh" ] && echo yes)" yes
check "no temp files left beside them" "$(find "$w/lib" -name '.*' -type f | wc -l | tr -d ' ')" 0
check "the pinned key is never replaced" "$(cmp -s "$w/lib/ainkrad-release.pub" "$w/a.pub" && echo same)" same
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; echo 1.1.0 >"$w/bad"; run now
check "a rolled-back update refreshes nothing" "$(rel update.sh)$(rel install.sh)" ""
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; echo junk >>"$w/rel/core/1.1.0/ainkrad-core-installer-1.1.0.tar.gz"; run now
check "a bundle that misses its signed sum refreshes nothing" "$(rel update.sh)$(rel install.sh)" ""
check "... and the healthy update still counts" "$(st state)" done
check "... and says so" "$(grep -c 'updater scripts were not refreshed' "$w/out")" 1
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; tar -czf "$w/rel/core/1.1.0/ainkrad-core-installer-1.1.0.tar.gz" -C "$w" bundle >/dev/null 2>&1
rm -f "$w/rel/core/1.1.0/SHA256SUMS.minisig"; AINKRAD_RELEASE_NO_MAC=1 "$here/sign.sh" "$w/rel/core/1.1.0" "$w/b.key" >/dev/null 2>&1; manifest 1.1.0 100 "$FUT"; run now
check "a bundle signed by another key refreshes nothing" "$(rel update.sh)" ""
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; run runner
check "a runner update refreshes the scripts too" "$(rel update.sh)" 1.1.0

# model.sh itself, with throwaway pins: installs, is idempotent, refuses a file that does not match, never leaves it in place
shaf() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
mkdir -p "$w/msrc"; echo a >"$w/msrc/config.json"; echo b >"$w/msrc/model.safetensors"
pins="config.json:$(shaf "$w/msrc/config.json") model.safetensors:$(shaf "$w/msrc/model.safetensors")"
m() { env -u HOME AINKRAD_MODEL_TEST=1 MODEL_TEST_PINS="$pins" MODEL_TEST_BASE="$w/msrc" "$here/model.sh" "$w/mdir" 2>&1; }
check "model.sh installs" "$(m)" "model: installed"; check "model.sh is idempotent" "$(m)" "model: present"
check "model files are 0644" "$(ls -l "$w/mdir/model.safetensors" | cut -c1-10)" "-rw-r--r--"
echo tampered >"$w/mdir/config.json"; check "a tampered file is fetched again" "$(m)" "model: installed"
echo wrong >"$w/msrc/model.safetensors"; rm "$w/mdir/model.safetensors"
m >/dev/null; check "a download that misses its pin is refused" "$?" 1
check "the refused file is not in place" "$(ls -A "$w/mdir" | tr '\n' ' ')" "config.json "
# the installer's pins are the loader's pins (crates/embed/src/local.rs FILES)
check "model.sh pins match the Core's loader" "$(grep -oE '[0-9a-f]{64}' "$here/model.sh" | sort | tr '\n' ' ')" \
  "$(grep -oE '"[0-9a-f]{64}"' "$here/../../crates/embed/src/local.rs" | tr -d '"' | sort | tr '\n' ' ')"
check "model.sh revision matches the Core's loader" "$(sed -n 's/^rev=//p' "$here/model.sh")" "$(sed -n 's/^const REV: &str = "\(.*\)";/\1/p' "$here/../../crates/embed/src/local.rs")"
# the bundle as git archive makes it, top folder and all; also with ./-prefixed members: the scripts come out either way
setup; BUNDLE_DOT=1 release 1.1.0; manifest 1.1.0 100 "$FUT"; run now
check "a ./-prefixed bundle refreshes update.sh" "$(rel update.sh)" 1.1.0
setup; release 1.1.0; mkdir -p "$w/bundle/extra"; tar -czf "$w/rel/core/1.1.0/ainkrad-core-installer-1.1.0.tar.gz" -C "$w/bundle" ainkrad-core-installer-1.1.0 extra
AINKRAD_RELEASE_NO_MAC=1 "$here/sign.sh" "$w/rel/core/1.1.0" "$w/a.key" >/dev/null; manifest 1.1.0 100 "$FUT"; run now
check "a bundle with a second top folder refreshes nothing" "$(rel update.sh)" ""
# no tar at all: under the updater unit (RestrictSUIDSGID=yes) GNU tar fails every member, so the bundle is never unpacked with it
mkdir -p "$w/notar"; printf '#!/bin/sh\necho "tar: Cannot mkdir: Function not implemented" >&2; exit 1\n' >"$w/notar/tar"; chmod +x "$w/notar/tar"
mkdir -p "$w/units"; rm -f "$w/units/"*
setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; (PATH=$w/notar:$PATH UNITS_DIR=$w/units run now)
check "with a failing tar the scripts are still refreshed" "$(rel update.sh)$(rel install.sh)" 1.1.01.1.0
check "... and the host units installed" "$(sed -n 's/^# release //p' "$w/units/ainkrad-host.socket")" 1.1.0
# a bundle member that is a link is never written, so a needed script that is one is refused
setup; release 1.1.0; ln -sf /etc/hostname "$w/bundle/ainkrad-core-installer-1.1.0/scripts/release/update.sh"
tar -czf "$w/rel/core/1.1.0/ainkrad-core-installer-1.1.0.tar.gz" -C "$w/bundle" ainkrad-core-installer-1.1.0
AINKRAD_RELEASE_NO_MAC=1 "$here/sign.sh" "$w/rel/core/1.1.0" "$w/a.key" >/dev/null; manifest 1.1.0 100 "$FUT"; run now
check "a linked update.sh in the bundle refreshes nothing" "$(rel update.sh)$(rel install.sh)" ""

# the root host helper: a Core run installs ainkrad-host and its units (enabled once, then only restarted); the runner's job shim
# comes with a runner run. A Core run never touches ainkrad-job, a runner run never ainkrad-host.
mkdir -p "$w/units"; rm -f "$w/units/"* "$w/calls"
setup; rm -f "$w/prefix/bin/ainkrad-host" "$w/prefix/bin/ainkrad-job"; release 1.1.0; manifest 1.1.0 100 "$FUT"; (UNITS_DIR=$w/units run now)
check "a Core update installs ainkrad-host" "$("$w/prefix/bin/ainkrad-host" 2>/dev/null | awk '{print $2}')" 1.1.0
check "... and not ainkrad-job" "$([ -e "$w/prefix/bin/ainkrad-job" ] && echo there || echo absent)" absent
check "... the host units from the bundle" "$(sed -n 's/^# release //p' "$w/units/ainkrad-host.socket" "$w/units/ainkrad-host@.service" | tr '\n' ' ')" "1.1.0 1.1.0 "
check "... the units are 0644" "$(ls -l "$w/units/ainkrad-host.socket" | cut -c1-10)" "-rw-r--r--"
check "... a new socket is enabled and started" "$(tr '\n' ' ' <"$w/calls")" "daemon-reload enable --now ainkrad-host.socket "
rm -f "$w/calls" "$w/restarts"; setup; release 1.1.0; manifest 1.1.0 100 "$FUT"; (UNITS_DIR=$w/units run now)
check "a present socket is only restarted" "$(tr '\n' ' ' <"$w/calls")$(cat "$w/restarts")" "daemon-reload ainkrad-host.socket"
rm -f "$w/units/"*; setup; rm -f "$w/prefix/bin/ainkrad-host" "$w/prefix/bin/ainkrad-job"; release 1.1.0; manifest 1.1.0 100 "$FUT"; (UNITS_DIR=$w/units run runner)
check "a runner update brings ainkrad-job beside the runner" "$("$w/prefix/bin/ainkrad-job" 2>/dev/null | awk '{print $2}')" 1.1.0
check "... and neither ainkrad-host nor its units" "$(ls "$w/prefix/bin/ainkrad-host" "$w/units/"* 2>/dev/null | wc -l | tr -d ' ')" 0
exit $fail
