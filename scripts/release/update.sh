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
# `auto` (the timer, hourly) only records what is available, and installs only between 02:00 and 05:00 local time; outside it
# status.json carries a `wait` event and the journal says when it will install.
# Every Core-mode run also makes sure the pinned local model is installed (model.sh, as the Core user), unless
# /etc/ainkrad/no-model opts out; a newly installed model restarts the Core so it loads it. A model failure never fails the update.
# Progress is /var/lib/ainkrad-update/status.json (the Core reads it for the app).
# `runner` (E12-4, started by ainkrad-update-runner.path when the runner drops <runner state>/update-request): the same steps for
# the runner's programs on this host: no Core stop and no database; after the install it restarts ainkrad-runner.service and
# rolls the binaries back when that does not stay active. Status: runner-status.json.
set -uo pipefail
mode=${1:-now}
recover=0; case $mode in recover-*) recover=1; mode=${mode#recover-} ;; esac   # ExecStopPost: start the service again if this run died mid-way
case $mode in now | auto | runner) ;; *) echo "update: mode is now|auto|runner" >&2; exit 2 ;; esac
kind=core svc=ainkrad-core.service vbin=ainkrad-core-server statusf=status.json bins="ainkrad-core-server ainkradctl"
[ "$mode" = runner ] && { kind=runner svc=ainkrad-runner.service vbin=ainkrad-runner statusf=runner-status.json bins="ainkrad-runner ainkrad-ptyhost"; }
# STATE is root's own directory (the unit's StateDirectory=ainkrad-update: /var/lib/ainkrad-update, 0755 root), NOT inside the
# Core's /var/lib/ainkrad: the Core user must never be able to plant a path, a symlink or a status file the updater trusts.
LIB=/usr/local/lib/ainkrad PREFIX=/usr/local STATE=/var/lib/ainkrad-update HOMEDIR=/var/lib/ainkrad/core
BASE=https://ainkrad.io/releases CHANNEL=stable SYSTEMCTL=/usr/bin/systemctl RUNNER_STATE=/var/lib/ainkrad-runner/core
CORE_ENV=/etc/ainkrad/core.env NO_MODEL=/etc/ainkrad/no-model
[ -r /etc/ainkrad/update.conf ] && . /etc/ainkrad/update.conf   # root-owned: BASE=, CHANNEL=
# Test hooks only (a non-root run against a scratch tree); never set in the unit.
if [ "${AINKRAD_UPDATE_TEST:-}" = 1 ]; then LIB=${UPD_LIB:-$LIB} PREFIX=${UPD_PREFIX:-$PREFIX} STATE=${UPD_STATE:-$STATE} HOMEDIR=${UPD_HOME:-$HOMEDIR} BASE=${UPD_BASE:-$BASE} SYSTEMCTL=${UPD_SYSTEMCTL:-$SYSTEMCTL} RUNNER_STATE=${UPD_RUNNER_STATE:-$RUNNER_STATE} HEALTH_URL=${UPD_HEALTH:-} WINDOW=${UPD_WINDOW:-} CORE_ENV=${UPD_CORE_ENV:-/dev/null} NO_MODEL=${UPD_NO_MODEL:-/nonexistent}; fi
umask 022
if [ "$recover" = 1 ]; then "$SYSTEMCTL" start "$svc" || true; exit 0; fi
# The request file only says "go": removed BEFORE the lock, so a request that arrives while an update runs is not left behind to
# retrigger, and nothing in it is ever read.
[ "$mode" != runner ] || rm -f "$RUNNER_STATE/update-request"
mkdir -p "$STATE/snapshots" && chmod 755 "$STATE"
exec 9>"$STATE/lock"; command -v flock >/dev/null && { flock -n 9 || exit 0; }   # one update at a time
now() { date +%s; }
if [ "$mode" = runner ]; then   # A flood of requests costs one fetch per 5 minutes.
  last=$(cat "$STATE/runner_last" 2>/dev/null || echo 0); [ $(($(now) - last)) -ge "${UPD_RUNNER_GAP:-300}" ] || exit 0
  now >"$STATE/runner_last"
fi
events=''; from=''; to=''; avail=''; state=idle; prog=0; err=''
ev() { events="${events:+$events,}{\"at\":$(now),\"step\":\"$1\",\"text\":\"$2\"}"; }   # $1,$2 are fixed words from this file
jv() { if [ -n "$1" ]; then printf '"%s"' "$1"; else printf null; fi; }   # every value is a version, a word or a number from this file
put() { # put STATE PROGRESS [ERROR]: atomically rewrite status.json
  state=$1 prog=$2 err=${3:-}
  printf '{"state":"%s","mode":"%s","from":%s,"to":%s,"available":%s,"progress":%s,"error":%s,"updated_at":%s,"events":[%s]}\n' \
    "$state" "$mode" "$(jv "$from")" "$(jv "$to")" "$(jv "$avail")" "$prog" "$(jv "$err")" "$(now)" "$events" >"$STATE/$statusf.tmp" \
    && mv -f "$STATE/$statusf.tmp" "$STATE/$statusf"
}
verre='^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.]+)?$'
# semver order: 1.1.0-rc1 < 1.1.0 (sort -V gets that wrong)
gt() { python3 -I - "$1" "$2" <<'PY'
import re, sys
def key(v):
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:[-+.]?(.*))?$", v); a, b, c, pre = m.groups()
    ids = [(0, int(x)) if x.isdigit() else (1, x) for x in re.split(r"[.-]", pre)] if pre else None
    return ((int(a), int(b), int(c)), 1 if ids is None else 0, ids or [])
sys.exit(0 if key(sys.argv[1]) > key(sys.argv[2]) else 1)
PY
}
fail() { put failed 0 "$1"; echo "update: $1" >&2; exit 1; }
for c in curl minisign python3; do command -v "$c" >/dev/null || fail "missing_$c"; done

if [ "$kind" = core ] && [ ! -e "$NO_MODEL" ] && [ -x "$LIB/model.sh" ]; then
  # As the Core user: the model directory is inside its home, where root must not follow a link it could plant.
  as=(setpriv --reuid=ainkrad --regid=ainkrad --init-groups); [ "${AINKRAD_UPDATE_TEST:-}" = 1 ] && as=()
  if m=$(${as[@]+"${as[@]}"} "$LIB/model.sh" "$HOMEDIR/models/e5-small" 2>"$STATE/model.log"); then
    echo "update: $m"
    # The Core looks for the model only at start.
    [ "$m" != "model: installed" ] || "$SYSTEMCTL" try-restart "$svc" || echo "update: could not restart $svc for the model" >&2
  else
    echo "update: the local model did not install: $(tail -1 "$STATE/model.log")" >&2
  fi
fi

cur=$("$PREFIX/bin/$vbin" --version 2>/dev/null | awk '{print $NF}')
[[ $cur =~ $verre ]] || fail "unknown_version"
from=$cur
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fetch() { case $BASE in https://*) curl -fsSL --proto '=https' --tlsv1.3 --max-time 30 --max-filesize 1000000 -o "$tmp/$1" "$BASE/$1" ;; /*) cp "$BASE/$1" "$tmp/$1" ;; *) return 1 ;; esac; }
fetch manifest.json && fetch manifest.json.minisig || fail "no_manifest"
minisign -Vq -p "$LIB/ainkrad-release.pub" -x "$tmp/manifest.json.minisig" -m "$tmp/manifest.json" || fail "bad_signature"
read -r new url gen exp urgent < <(python3 -I - "$tmp/manifest.json" "$CHANNEL" "$kind" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); c = m["channels"][sys.argv[2]][sys.argv[3]]
print(c["version"], c["url"], int(m["generated"]), int(m["expires"]), 1 if c.get("urgent") is True else 0)
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
# `urgent` (the release says the app now needs this Core) may install off-window: no day-long lockout of a newer app.
if [ "$mode" = auto ] && [ "$urgent" != 1 ] && ! { [ -n "${WINDOW:-}" ] || { [ "$hour" -ge 2 ] && [ "$hour" -lt 5 ]; }; }; then
  ev wait "Installs between 02:00 and 05:00"; put idle 0
  echo "update: $new is available; auto installs it between 02:00 and 05:00 local time (now ${hour}h). Now: systemctl start ainkrad-update@now"
  exit 0
fi

# 3. snapshot
ev snapshot "Snapshot taken"; put snapshot 0.12
need=102400   # KiB: 100 MB of room beyond the copies
for f in "$HOMEDIR"/core.db "$HOMEDIR"/core.db-wal "$HOMEDIR"/core.db-shm; do [ -L "$f" ] && fail "unsafe_database"; [ -f "$f" ] && need=$((need + $(wc -c <"$f") / 1024 * 2 + 1)); done
for b in $bins; do [ -f "$PREFIX/bin/$b" ] && need=$((need + $(wc -c <"$PREFIX/bin/$b") / 1024 * 3 + 1)); done
free=$(df -Pk "$STATE" | awk 'NR==2{print $4}'); [ "${free:-0}" -ge "$need" ] || fail "no_space"
free=$(df -Pk "$PREFIX/bin" | awk 'NR==2{print $4}'); [ "${free:-0}" -ge "$need" ] || fail "no_space"
snap="$STATE/snapshots/$cur-$(now)"; mkdir -p "$snap/bin" "$snap/db"; chmod 700 "$snap"
runner_was_active=0; if [ "$kind" = core ] && "$SYSTEMCTL" is-active --quiet ainkrad-runner.service; then runner_was_active=1; fi
[ "$kind" = runner ] || "$SYSTEMCTL" stop "$svc" || fail "stop_failed"
snapfail() { [ "$kind" = runner ] || "$SYSTEMCTL" start "$svc"; fail "$1"; }
for b in $bins; do
  [ -L "$PREFIX/bin/$b" ] && snapfail snapshot_failed
  if [ -e "$PREFIX/bin/$b" ]; then cp -pP "$PREFIX/bin/$b" "$snap/bin/$b" && cmp -s "$PREFIX/bin/$b" "$snap/bin/$b" || snapfail snapshot_failed; fi
done
if [ "$kind" = core ]; then
  for f in "$HOMEDIR"/core.db "$HOMEDIR"/core.db-wal "$HOMEDIR"/core.db-shm; do
    [ -L "$f" ] && snapfail unsafe_database
    if [ -e "$f" ]; then cp -pP "$f" "$snap/db/" && [ "$(wc -c <"$f")" = "$(wc -c <"$snap/db/$(basename "$f")")" ] || snapfail snapshot_failed; fi
  done
  [ -f "$snap/db/core.db" ] || snapfail snapshot_failed
  # a copy that does not open is no snapshot
  if command -v sqlite3 >/dev/null; then [ "$(sqlite3 "$snap/db/core.db" 'PRAGMA integrity_check;' 2>/dev/null | head -1)" = ok ] || snapfail snapshot_corrupt; fi
fi
[ -f "$snap/bin/$vbin" ] || snapfail snapshot_failed

owner=; if [ "$(id -u)" = 0 ] && id ainkrad >/dev/null 2>&1; then owner="-o ainkrad -g ainkrad"; fi
back() { # roll back to the snapshot and say why. A step that fails here is reported, never skipped silently.
  ev install "Went back to $cur"
  for b in $bins; do [ -e "$snap/bin/$b" ] && { cp -pP "$snap/bin/$b" "$PREFIX/bin/.$b.rb" && mv -f "$PREFIX/bin/.$b.rb" "$PREFIX/bin/$b"; } || echo "update: could not restore $b" >&2; done
  "$SYSTEMCTL" stop "$svc"
  if [ "$kind" = core ]; then
    for f in core.db core.db-wal core.db-shm; do
      rm -f "$HOMEDIR/$f"   # removes a planted link itself, never what it points at
      # shellcheck disable=SC2086  # $owner is two flag pairs
      [ ! -e "$snap/db/$f" ] || install $owner -m 0600 "$snap/db/$f" "$HOMEDIR/$f" || echo "update: could not restore $f" >&2
    done
  fi
  "$SYSTEMCTL" start "$svc"
  put rolled_back 1 "$1"; echo "update: rolled back ($1)" >&2; exit 1
}

# 4. install (install.sh re-verifies the signed sums and each file)
ev install "Installed $new"; put install 0.5
"$LIB/install.sh" --only "$kind" --from "$url" --prefix "$PREFIX" --pubkey "$LIB/ainkrad-release.pub" >"$STATE/install.log" 2>&1 || back install_failed
got=$("$PREFIX/bin/$vbin" --version 2>/dev/null | awk '{print $NF}')
[ "$got" = "$new" ] || back wrong_version

# 5. health: active for 20 s and answering
ev health "Health check"; put health 0.85
if [ "$kind" = runner ]; then "$SYSTEMCTL" restart "$svc" || back start_failed; else "$SYSTEMCTL" start "$svc" || back start_failed; fi
healthy() {
  "$SYSTEMCTL" is-active --quiet "$svc" || return 1
  [ "$kind" = core ] || return 0   # a runner: active and staying active is the check (it has no health URL)
  local l=${AINKRAD_LISTEN:-} h; [ -r "$CORE_ENV" ] && l=$(sed -n 's/^AINKRAD_LISTEN=//p' "$CORE_ENV" | tail -1)
  if [ -n "${HEALTH_URL:-}" ]; then curl -fsS --max-time 3 "$HEALTH_URL" 2>/dev/null | grep -qx ok; return; fi
  case $l in
    # The Core answers only its own host name (a 403 unknown_host otherwise), so ask for that name, resolved to loopback.
    # -k: a staging ACME certificate is not trusted, and on loopback the name is all this checks.
    public)
      h=$(sed -n 's/^AINKRAD_HOSTNAME=//p' "$CORE_ENV" 2>/dev/null | tail -1)
      [[ $h =~ ^[A-Za-z0-9.-]+$ ]] || return 1
      curl -fksS --max-time 3 --resolve "$h:443:127.0.0.1" "https://$h/healthz" 2>/dev/null | grep -qx ok ;;
    loopback:[0-9]*) curl -fsS --max-time 3 "http://127.0.0.1:${l#loopback:}/healthz" 2>/dev/null | grep -qx ok ;;
    *) return 0 ;;   # a unix socket: "active" is all we can check from here
  esac
}
ok=0; for _ in $(seq 1 "${UPD_HEALTH_TRIES:-20}"); do if healthy; then ok=$((ok + 1)); else ok=0; fi; [ "$ok" -ge "${UPD_HEALTH_NEED:-5}" ] && break; sleep "${UPD_HEALTH_SLEEP:-3}"; done
[ "$ok" -ge "${UPD_HEALTH_NEED:-5}" ] || back health_failed
# a combined host: the runner was not touched (--only core), but it must still be up after the Core came back
if [ "$runner_was_active" = 1 ] && ! "$SYSTEMCTL" is-active --quiet ainkrad-runner.service; then back runner_down; fi
# 6. the updater's own scripts from the release just verified (its signed installer bundle), so the next run uses them. Not a
# reason to roll back: the new version is installed and healthy; the old scripts stay until the next release.
"$LIB/install.sh" --from "$url" --pubkey "$LIB/ainkrad-release.pub" --scripts "$LIB" >>"$STATE/install.log" 2>&1 ||
  echo "update: the updater scripts were not refreshed (see $STATE/install.log)" >&2

if [ "$kind" = core ]; then lbl=Core; else lbl=Runner; fi; ev done "$lbl is on $new"; avail=''; put done 1
# keep the two newest snapshots
ls -1t "$STATE/snapshots" | tail -n +3 | while read -r d; do case $d in *[!0-9A-Za-z._-]* | '') ;; *) rm -rf "${STATE:?}/snapshots/$d" ;; esac; done
echo "update: $kind is on $new"
