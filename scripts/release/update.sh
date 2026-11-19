#!/usr/bin/env bash
# E12-3: the Core's self-update. Runs as root from ainkrad-update@<mode>.service (mode: now | auto); installed to
# /usr/local/lib/ainkrad/update.sh beside install.sh and ainkrad-release.pub. Nothing here is told what to install:
#   1. fetch manifest.json + .minisig from the release server, verify with the PINNED key (refuses on any mismatch);
#   2. take the channel's core version; install only if it is NEWER than what runs (never a downgrade), the manifest is not
#      older than the last one accepted (replay) and has not expired;
#   3. snapshot: stop Core, copy the database and the four binaries;
#   4. install: install.sh --from <url> (it re-verifies the signed SHA256SUMS and every file's hash);
#   5. health: start Core, it must stay active and answer /healthz;
#   6. any failure after 3: put the binaries and the database back, start Core, report "rolled_back".
# `auto` (the timer, hourly) only records what is available, and installs only between 02:00 and 05:00 local time.
# Progress is /var/lib/ainkrad/update/status.json (the Core reads it for the app).
set -uo pipefail
mode=${1:-now}; case $mode in now | auto) ;; *) echo "update: mode is now|auto" >&2; exit 2 ;; esac
LIB=/usr/local/lib/ainkrad PREFIX=/usr/local STATE=/var/lib/ainkrad/update HOMEDIR=/var/lib/ainkrad/core
BASE=https://ainkrad.io/releases CHANNEL=stable SYSTEMCTL=/usr/bin/systemctl
[ -r /etc/ainkrad/update.conf ] && . /etc/ainkrad/update.conf   # root-owned: BASE=, CHANNEL=
# Test hooks only (a non-root run against a scratch tree); never set in the unit.
if [ "${AINKRAD_UPDATE_TEST:-}" = 1 ]; then LIB=${UPD_LIB:-$LIB} PREFIX=${UPD_PREFIX:-$PREFIX} STATE=${UPD_STATE:-$STATE} HOMEDIR=${UPD_HOME:-$HOMEDIR} BASE=${UPD_BASE:-$BASE} SYSTEMCTL=${UPD_SYSTEMCTL:-$SYSTEMCTL} HEALTH_URL=${UPD_HEALTH:-} WINDOW=${UPD_WINDOW:-}; fi
umask 022
mkdir -p "$STATE/snapshots" && chmod 755 "$STATE"
exec 9>"$STATE/lock"; command -v flock >/dev/null && { flock -n 9 || exit 0; }   # one update at a time
now() { date +%s; }
events=''; from=''; to=''; avail=''; state=idle; prog=0; err=''
ev() { events="${events:+$events,}{\"at\":$(now),\"step\":\"$1\",\"text\":\"$2\"}"; }   # $1,$2 are fixed words from this file
jv() { if [ -n "$1" ]; then printf '"%s"' "$1"; else printf null; fi; }   # every value is a version, a word or a number from this file
put() { # put STATE PROGRESS [ERROR]: atomically rewrite status.json
  state=$1 prog=$2 err=${3:-}
  printf '{"state":"%s","mode":"%s","from":%s,"to":%s,"available":%s,"progress":%s,"error":%s,"updated_at":%s,"events":[%s]}\n' \
    "$state" "$mode" "$(jv "$from")" "$(jv "$to")" "$(jv "$avail")" "$prog" "$(jv "$err")" "$(now)" "$events" >"$STATE/status.json.tmp" \
    && mv -f "$STATE/status.json.tmp" "$STATE/status.json"
}
verre='^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$'
gt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]; }
fail() { put failed 0 "$1"; echo "update: $1" >&2; exit 1; }
for c in curl minisign python3; do command -v "$c" >/dev/null || fail "missing_$c"; done

cur=$("$PREFIX/bin/ainkrad-core-server" --version 2>/dev/null | awk '{print $NF}')
[[ $cur =~ $verre ]] || fail "unknown_version"
from=$cur
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fetch() { case $BASE in https://*) curl -fsSL --proto '=https' --tlsv1.3 --max-time 30 --max-filesize 1000000 -o "$tmp/$1" "$BASE/$1" ;; /*) cp "$BASE/$1" "$tmp/$1" ;; *) return 1 ;; esac; }
fetch manifest.json && fetch manifest.json.minisig || fail "no_manifest"
minisign -Vq -p "$LIB/ainkrad-release.pub" -x "$tmp/manifest.json.minisig" -m "$tmp/manifest.json" || fail "bad_signature"
read -r new url gen exp < <(python3 -I - "$tmp/manifest.json" "$CHANNEL" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); c = m["channels"][sys.argv[2]]["core"]
print(c["version"], c["url"], int(m["generated"]), int(m["expires"]))
PY
) || fail "bad_manifest"
[[ $new =~ $verre ]] && [[ $gen =~ ^[0-9]+$ ]] && [[ $exp =~ ^[0-9]+$ ]] || fail "bad_manifest"
case $url in "$BASE"/*) ;; *) fail "bad_manifest" ;; esac
[ "$(now)" -le "$exp" ] || fail "manifest_expired"
last=$(cat "$STATE/last_generated" 2>/dev/null || echo 0)
[ "$gen" -ge "$last" ] || fail "manifest_replayed"
echo "$gen" >"$STATE/last_generated"
if ! gt "$new" "$cur"; then put idle 0; echo "update: up to date ($cur)"; exit 0; fi
avail=$new; to=$new
hour=$(date +%H); hour=$((10#$hour))
if [ "$mode" = auto ] && ! { [ -n "${WINDOW:-}" ] || { [ "$hour" -ge 2 ] && [ "$hour" -lt 5 ]; }; }; then put idle 0; exit 0; fi

# 3. snapshot
ev snapshot "Snapshot taken"; put snapshot 0.12
snap="$STATE/snapshots/$cur-$(now)"; mkdir -p "$snap/bin" "$snap/db"; chmod 700 "$snap"
"$SYSTEMCTL" stop ainkrad-core.service || fail "stop_failed"
bins="ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost"
for b in $bins; do [ -e "$PREFIX/bin/$b" ] && cp -p "$PREFIX/bin/$b" "$snap/bin/$b"; done
for f in "$HOMEDIR"/core.db "$HOMEDIR"/core.db-wal "$HOMEDIR"/core.db-shm; do [ -e "$f" ] && cp -p "$f" "$snap/db/"; done
[ -f "$snap/db/core.db" ] && [ -f "$snap/bin/ainkrad-core-server" ] || { "$SYSTEMCTL" start ainkrad-core.service; fail "snapshot_failed"; }

back() { # roll back to the snapshot and say why
  ev install "Went back to $cur"
  for b in $bins; do [ -e "$snap/bin/$b" ] && { cp -p "$snap/bin/$b" "$PREFIX/bin/.$b.rb" && mv -f "$PREFIX/bin/.$b.rb" "$PREFIX/bin/$b"; }; done
  "$SYSTEMCTL" stop ainkrad-core.service
  rm -f "$HOMEDIR"/core.db "$HOMEDIR"/core.db-wal "$HOMEDIR"/core.db-shm
  cp -p "$snap/db/"* "$HOMEDIR/"
  "$SYSTEMCTL" start ainkrad-core.service
  put rolled_back 1 "$1"; echo "update: rolled back ($1)" >&2; exit 1
}

# 4. install (install.sh re-verifies the signed sums and each file)
ev install "Installed $new"; put install 0.5
"$LIB/install.sh" --from "$url" --prefix "$PREFIX" --pubkey "$LIB/ainkrad-release.pub" >"$STATE/install.log" 2>&1 || back install_failed
got=$("$PREFIX/bin/ainkrad-core-server" --version 2>/dev/null | awk '{print $NF}')
[ "$got" = "$new" ] || back wrong_version

# 5. health: active for 20 s and answering
ev health "Health check"; put health 0.85
"$SYSTEMCTL" start ainkrad-core.service || back start_failed
healthy() {
  "$SYSTEMCTL" is-active --quiet ainkrad-core.service || return 1
  local l=${AINKRAD_LISTEN:-}; [ -r /etc/ainkrad/core.env ] && l=$(sed -n 's/^AINKRAD_LISTEN=//p' /etc/ainkrad/core.env | tail -1)
  if [ -n "${HEALTH_URL:-}" ]; then curl -fsS --max-time 3 "$HEALTH_URL" 2>/dev/null | grep -qx ok; return; fi
  case $l in
    public) curl -fksS --max-time 3 https://127.0.0.1/healthz 2>/dev/null | grep -qx ok ;;
    loopback:[0-9]*) curl -fsS --max-time 3 "http://127.0.0.1:${l#loopback:}/healthz" 2>/dev/null | grep -qx ok ;;
    *) return 0 ;;   # a unix socket: "active" is all we can check from here
  esac
}
ok=0; for _ in $(seq 1 "${UPD_HEALTH_TRIES:-20}"); do if healthy; then ok=$((ok + 1)); else ok=0; fi; [ "$ok" -ge "${UPD_HEALTH_NEED:-5}" ] && break; sleep "${UPD_HEALTH_SLEEP:-3}"; done
[ "$ok" -ge "${UPD_HEALTH_NEED:-5}" ] || back health_failed

ev done "Core is on $new"; avail=''; put done 1
# keep the two newest snapshots
ls -1t "$STATE/snapshots" | tail -n +3 | while read -r d; do case $d in *[!0-9A-Za-z._-]* | '') ;; *) rm -rf "${STATE:?}/snapshots/$d" ;; esac; done
echo "update: Core is on $new"
