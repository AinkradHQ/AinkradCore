#!/usr/bin/env bash
# The E1 exit gate, REMOTE mode (E1-14.5): the six steps of plan §4 run from this machine with ainkradctl against a
# public Core installed on a Linux host (deploy/install-core-linux.sh) with a FRESH home (no device yet), and a runner
# installed there (deploy/install-linux.sh) but not paired. THROWAWAY CREDENTIALS ONLY.
#   E1_SSH=ubuntu@<host> E1_SSH_KEY=<key> E1_CORE=<dns name> E1_SIGNER=<backup signer fp> \
#   E1_IDENTITY=<age identity file, on this machine> [E1_CA=<roots.pem>, a staging ACME root] \
#   [E1_OCI_NS=<namespace> E1_OCI_BUCKET=<bucket>] scripts/e1-exit-remote.sh
#   1 bootstrap on the host (`sudo -u ainkrad … bootstrap`); this machine claims it through the admin socket, relayed
#     over SSH as the service user (the socket admits only its uid)
#   2 a second device approved by the first; the host's runner paired (`ainkrad-runner pair`) and approved by the second
#   3 the runner's unit started; it connects with the Core pinned
#   4 `run noop` from here; audit rows
#   5 `systemctl kill -s KILL` the Core; systemd restarts it; no gap/dup; the runner reconnects; restart-to-serving time
#   6 `backup` on the host to the bucket (credentials and the age recipient stay there), fetched here with the admin OCI
#     CLI, `restore` here into a fresh dir, compared with the host's live home; the object is deleted afterwards
# Then: idle CPU and RSS of the Core over 60 s. Prints a PASS/FAIL table; exits 1 on any FAIL.
# SC2015: `a && b || fail` is meant; SC2329: steps are called as "step$i"; SC2029: remote commands expand here on purpose.
# shellcheck disable=SC2015,SC2329,SC2029
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${E1_BIN:-$ROOT/target/debug}
SRV=$BIN/ainkrad-core-server CTL=$BIN/ainkradctl
: "${E1_SSH:?}" "${E1_SSH_KEY:?}" "${E1_CORE:?}" "${E1_SIGNER:?}" "${E1_IDENTITY:?}"
NS=${E1_OCI_NS:-axvsrwtenhtg} BUCKET=${E1_OCI_BUCKET:-ainkrad-core-backups}
HOME_R=/var/lib/ainkrad/core RSTATE=/var/lib/ainkrad-runner/core
URL=https://$E1_CORE
W=$(mktemp -d /tmp/e1r.XXXXXX); chmod 700 "$W"
SSHO=(-i "$E1_SSH_KEY" -o BatchMode=yes -o ControlMaster=auto -o "ControlPath=$W/ssh.ctl" -o ControlPersist=120)
r() { ssh "${SSHO[@]}" "$E1_SSH" "$@"; }
PIDS=()
cleanup() {
  local p
  for p in ${PIDS[@]+"${PIDS[@]}"}; do pkill -P "$p" 2>/dev/null || true; kill "$p" 2>/dev/null || true; done
  ssh "${SSHO[@]}" -O exit "$E1_SSH" 2>/dev/null || true
  if [ "${E1_KEEP:-0}" = 1 ]; then echo "e1-exit-remote: kept $W" >&2; else rm -rf "$W"; fi
}
trap cleanup EXIT

CA=() CURL_CA=() RCA=''
if [ -n "${E1_CA:-}" ]; then
  CA=(--ca "$E1_CA") CURL_CA=(--cacert "$E1_CA") RCA='--ca /etc/ainkrad-runner/ca.pem'
fi
PASS_A=$W/pass-a PASS_B=$W/pass-b
openssl rand -hex 24 >"$PASS_A"; openssl rand -hex 24 >"$PASS_B"; chmod 600 "$PASS_A" "$PASS_B"
KS_A=$W/a/keystore.json KS_B=$W/b/keystore.json
a() { "$CTL" --url "$URL" ${CA[@]+"${CA[@]}"} --keystore "$KS_A" --stepup-passphrase-file "$PASS_A" "$@" </dev/null; }
b() { "$CTL" --url "$URL" ${CA[@]+"${CA[@]}"} --keystore "$KS_B" --stepup-passphrase-file "$PASS_B" "$@" </dev/null; }
wait_for() {
  local end=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do [ "$SECONDS" -lt "$end" ] || return 1; sleep 0.2; done
}
field() { sed -n "s/^$2 //p" "$1" | head -n1; }
has_field() { [ -n "$(field "$1" "$2")" ]; }
head_seq() { local s; s=$(a events tail --after 0 --no-follow | tail -n1 | jq -r .seq); echo "${s:-0}"; }
consecutive() {
  jq -s --argjson from "$2" --argjson to "$3" '[.[].seq] as $s | ($s == [range($from + 1; $to + 1)])' "$1" | grep -qx true
}
healthy() { curl -fsS ${CURL_CA[@]+"${CURL_CA[@]}"} --max-time 2 "$URL/healthz"; }
# The admin socket here, relayed per connection to the host's as the service user.
relay() {
  python3 - "$W/admin.sock" "${SSHO[*]}" "$E1_SSH" "$HOME_R/admin.sock" <<'PY' &
import os, socket, subprocess, sys, threading
path, opts, host, remote = sys.argv[1:5]
# On the host: stdio <-> the admin socket (python3, as AppArmor denies nc.openbsd the connect).
PUMP = """import os, socket, sys, threading
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
def up():
    while (d := os.read(0, 65536)):
        s.sendall(d)
    s.shutdown(socket.SHUT_WR)
threading.Thread(target=up, daemon=True).start()
while (d := s.recv(65536)):
    os.write(1, d)"""
srv = socket.socket(socket.AF_UNIX); srv.bind(path); os.chmod(path, 0o600); srv.listen(8)
def serve(c):
    p = subprocess.Popen(["ssh", *opts.split(), host, f"sudo -u ainkrad python3 -c '{PUMP}' {remote}"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    def up():
        while (d := c.recv(65536)):
            p.stdin.write(d)
        p.stdin.close()
    threading.Thread(target=up, daemon=True).start()
    while (d := os.read(p.stdout.fileno(), 65536)):
        c.sendall(d)
    c.close(); p.kill()
while True:
    conn, _ = srv.accept()
    threading.Thread(target=serve, args=(conn,), daemon=True).start()
PY
  PIDS+=("$!")
  wait_for 10 test -S "$W/admin.sock"
}

step1() {
  healthy >/dev/null || { EV="$URL/healthz does not answer"; return 1; }
  relay || { EV="the admin relay did not start"; return 1; }
  mkfifo "$W/boot.in"
  r "sudo -u ainkrad /usr/local/bin/ainkrad-core-server bootstrap $HOME_R/core.db mac" <"$W/boot.in" >"$W/boot.out" 2>"$W/boot.err" &
  local boot=$!; PIDS+=("$boot")
  exec 3>"$W/boot.in"
  wait_for 30 has_field "$W/boot.out" code && wait_for 5 has_field "$W/boot.out" core_fp ||
    { EV="bootstrap printed no code: $(tail -n2 "$W/boot.err")"; return 1; }
  CORE_FP=$(field "$W/boot.out" core_fp)
  mkdir -p "$W/a" "$W/b"
  "$CTL" --socket "$W/admin.sock" --host "$E1_CORE" --keystore "$KS_A" --stepup-passphrase-file "$PASS_A" \
    pair "$(field "$W/boot.out" code)" --core-fp "$CORE_FP" >"$W/pair-a.out" 2>&1 </dev/null &
  local pair=$!; PIDS+=("$pair")
  wait_for 60 has_field "$W/pair-a.out" sas && wait_for 30 has_field "$W/boot.out" sas ||
    { EV="no SAS on both sides: $(tail -n2 "$W/pair-a.out")"; return 1; }
  [ "$(field "$W/pair-a.out" sas)" = "$(field "$W/boot.out" sas)" ] || { EV="the two SAS differ"; return 1; }
  echo y >&3; exec 3>&-
  wait "$boot" && wait "$pair" || { EV="bootstrap or pair failed: $(tail -n2 "$W/pair-a.out")"; return 1; }
  DEV_A=$(field "$W/pair-a.out" device)
  a health >"$W/health-a.out" 2>&1 || { EV="health over $URL failed: $(cat "$W/health-a.out")"; return 1; }
  grep -q "^core_fp $CORE_FP (matches the pinned one)" "$W/health-a.out" || { EV="Core not pinned"; return 1; }
  EV="bootstrap on the host, claimed here via the SSH-relayed admin socket: $DEV_A; SAS matched; health over $URL (TLS verified${RCA:+ against the staging root}) pins $CORE_FP"
}

step2() {
  a device add phone --scopes read,admin,runner >"$W/add-b.out" || { EV="device add (A) failed"; return 1; }
  b pair "$(field "$W/add-b.out" code)" >"$W/pair-b.out" 2>&1 &
  local pb=$!; PIDS+=("$pb")
  wait_for 30 has_field "$W/pair-b.out" sas || { EV="B showed no SAS"; return 1; }
  a device approve "$(field "$W/add-b.out" pairing_id)" "$(field "$W/pair-b.out" sas)" >/dev/null ||
    { EV="A could not approve B"; return 1; }
  wait "$pb" || { EV="B's pairing failed"; return 1; }
  DEV_B=$(field "$W/pair-b.out" device)
  b device add vm --kind runner >"$W/add-r.out" || { EV="B could not start the runner pairing"; return 1; }
  r "sudo -u ainkrad-runner /usr/local/bin/ainkrad-runner pair $URL --code $(field "$W/add-r.out" code) --state $RSTATE $RCA" \
    >"$W/pair-r.out" 2>&1 </dev/null &
  local pr=$!; PIDS+=("$pr")
  runner_sas() { grep -E '^ +[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$' "$W/pair-r.out" | tr -d ' '; }
  wait_for 30 runner_sas || { EV="the runner showed no SAS: $(tail -n2 "$W/pair-r.out")"; return 1; }
  b device approve "$(field "$W/add-r.out" pairing_id)" "$(runner_sas)" >/dev/null || { EV="B could not approve the runner"; return 1; }
  wait "$pr" || { EV="the runner's pairing failed: $(tail -n2 "$W/pair-r.out")"; return 1; }
  RID=$(sed -n 's/^Paired as \(d_[A-Za-z0-9]*\) with the Core \([^;]*\);.*/\1/p' "$W/pair-r.out")
  local pinned; pinned=$(sed -n 's/^Paired as d_[A-Za-z0-9]* with the Core \([^;]*\);.*/\1/p' "$W/pair-r.out")
  [ -n "$RID" ] && [ "$pinned" = "$CORE_FP" ] || { EV="runner pinned '$pinned', Core is $CORE_FP"; return 1; }
  EV="B $DEV_B [read,admin,runner] approved by A; the host's runner $RID [runner] approved by B, pinned $CORE_FP"
}

step3() {
  r "sudo systemctl start ainkrad-runner" || { EV="the runner unit did not start"; return 1; }
  online() { a --json runner show "$RID" | jq -e '.online == true' >/dev/null; }
  wait_for 30 online || { EV="the runner did not come online: $(r 'sudo journalctl -u ainkrad-runner -n 3 --no-pager')"; return 1; }
  a --json runner show "$RID" >"$W/runner-3.json"
  [ "$(jq -c '[.drivers[].commands[]]' "$W/runner-3.json")" = '["noop"]' ] || { EV="exec must stay off"; return 1; }
  RPID=$(r "systemctl show -p MainPID --value ainkrad-runner")
  EV="runner unit (pid $RPID, user ainkrad-runner) online over v2, advertises only noop, version $(jq -r .version "$W/runner-3.json")"
}

step4() {
  local mark; mark=$(head_seq)
  set +e; b run noop "$RID" >"$W/noop-b.out" 2>&1; local bcode=$?; set -e
  [ "$bcode" = 4 ] && grep -q forbidden_scope "$W/noop-b.out" || { EV="B got exit $bcode"; return 1; }
  a device rename "$RID" vm-runner >/dev/null || { EV="rename failed"; return 1; }
  a --json run noop "$RID" >"$W/noop-a.json" && jq -e '.ok == true' "$W/noop-a.json" >/dev/null ||
    { EV="run noop failed: $(cat "$W/noop-a.json")"; return 1; }
  a events tail --after "$mark" --no-follow >"$W/events-4.jsonl"
  jq -e --arg r "$RID" 'select(.payload.action=="runner.command" and .payload.details.runner==$r)' "$W/events-4.jsonl" >/dev/null &&
    jq -e 'select(.payload.action=="device.renamed")' "$W/events-4.jsonl" >/dev/null ||
    { EV="audit rows missing after seq $mark"; return 1; }
  EV="noop from this machine to the host's runner ok in $(jq -r .duration_ms "$W/noop-a.json") ms; B refused (exit 4 forbidden_scope); audit after seq $mark: $(jq -r 'select(.kind=="audit")|.payload.action' "$W/events-4.jsonl" | sort -u | tr '\n' ' ')"
}

step5() {
  local s0; s0=$(head_seq)
  a events tail --after "$s0" >"$W/follow.jsonl" 2>"$W/follow.err" &
  local tail=$!; PIDS+=("$tail")
  a device rename "$DEV_B" phone-1 >/dev/null && a device rename "$DEV_B" phone-2 >/dev/null || { EV="rename failed"; return 1; }
  local before; before=$(head_seq)
  wait_for 15 consecutive "$W/follow.jsonl" "$s0" "$before" || { EV="the tail did not keep up"; return 1; }
  local old; old=$(r "systemctl show -p MainPID --value ainkrad-core")
  local t0; t0=$(python3 -c 'import time; print(time.time())')
  r "sudo systemctl kill -s KILL ainkrad-core"
  sleep 0.2
  wait_for 60 healthy || { EV="the Core did not come back: $(r 'sudo journalctl -u ainkrad-core -n 3 --no-pager')"; return 1; }
  RESTART=$(python3 -c "import time; print(f'{time.time() - $t0:.2f}')")
  local new; new=$(r "systemctl show -p MainPID --value ainkrad-core")
  [ "$new" != "$old" ] || { EV="the Core pid did not change"; return 1; }
  a device rename "$DEV_B" phone-3 >/dev/null || { EV="rename after restart failed"; return 1; }
  reconnected() {
    a --json runner show "$RID" | jq -e '.online == true' >/dev/null &&
      a events tail --after "$before" --no-follow | jq -e --arg r "$RID" 'select(.kind=="runner.connected" and .payload.device_id==$r)' >/dev/null
  }
  wait_for 90 reconnected || { EV="the runner did not reconnect"; return 1; }
  [ "$(r "systemctl show -p MainPID --value ainkrad-runner")" = "$RPID" ] || { EV="the runner process changed"; return 1; }
  local end; end=$(head_seq)
  wait_for 30 consecutive "$W/follow.jsonl" "$s0" "$end" ||
    { EV="followed seqs not consecutive $s0..$end: $(jq -c -s '[.[].seq]' "$W/follow.jsonl")"; return 1; }
  pkill -P "$tail" || true; wait "$tail" 2>/dev/null || true
  a events tail --after "$s0" --no-follow >"$W/replay-5.jsonl"
  consecutive "$W/replay-5.jsonl" "$s0" "$end" && cmp -s <(jq -cS . "$W/follow.jsonl") <(jq -cS . "$W/replay-5.jsonl") ||
    { EV="the replay differs from the followed stream"; return 1; }
  EV="systemctl kill -s KILL (pid $old) at seq $before; systemd restarted it (pid $new), serving again in ${RESTART}s (RestartSec=1s); followed $((s0 + 1))..$end consecutive, = replay; runner pid $RPID reconnected by itself"
}

remote_state() { # device list | audit verify | events min|max|count, of the host's live home
  r "sudo -u ainkrad /usr/local/bin/ainkrad-core-server device list $HOME_R/core.db" >"$W/host.devices"
  r "sudo -u ainkrad /usr/local/bin/ainkrad-core-server audit verify $HOME_R/core.db" >"$W/host.audit"
  r "sudo -u ainkrad python3 -c \"import sqlite3; c=sqlite3.connect('file:$HOME_R/core.db?mode=ro', uri=True); print('|'.join(map(str, c.execute('SELECT min(seq), max(seq), count(*) FROM events').fetchone())))\"" >"$W/host.events"
}

step6() {
  r "sudo systemctl stop ainkrad-runner" # no new events while comparing
  local out; out=$(r "sudo -u ainkrad bash -c 'set -a; . /etc/ainkrad/core.env; . /etc/ainkrad/backup.env; set +a; exec /usr/local/bin/ainkrad-core-server backup --config $HOME_R/config.toml'" 2>"$W/backup.err") ||
    { EV="backup failed: $(tail -n2 "$W/backup.err")"; return 1; }
  remote_state
  OBJECT=$(oci os object list --namespace-name "$NS" --bucket-name "$BUCKET" --prefix core/ | jq -r '.data[].name' | grep "$(basename "$(printf '%s\n' "$out" | tail -n1)")" | head -n1)
  [ -n "$OBJECT" ] || { EV="the backup is not in the bucket"; return 1; }
  oci os object get --namespace-name "$NS" --bucket-name "$BUCKET" --name "$OBJECT" --file "$W/backup.age" >/dev/null ||
    { EV="fetching $OBJECT failed"; return 1; }
  "$SRV" restore "$W/backup.age" --identity "$E1_IDENTITY" --signer "$E1_SIGNER" "$W/restored" >/dev/null ||
    { EV="restore here failed"; return 1; }
  "$SRV" device list "$W/restored/core.db" >"$W/restored.devices"
  "$SRV" audit verify "$W/restored/core.db" >"$W/restored.audit" || { EV="audit verify failed on the restored home"; return 1; }
  sqlite3 -readonly "$W/restored/core.db" 'SELECT min(seq), max(seq), count(*) FROM events' >"$W/restored.events"
  local x
  for x in devices audit events; do cmp -s "$W/host.$x" "$W/restored.$x" || { EV="$x differ: host '$(head -n1 "$W/host.$x")' vs restored '$(head -n1 "$W/restored.$x")'"; return 1; }; done
  oci os object delete --namespace-name "$NS" --bucket-name "$BUCKET" --object-name "$OBJECT" --force >/dev/null
  local left; left=$(oci os object list --namespace-name "$NS" --bucket-name "$BUCKET" | jq '.data | length')
  r "sudo systemctl start ainkrad-runner"
  EV="backup on the host -> bucket object $OBJECT -> fetched and restored here: $(wc -l <"$W/host.devices" | tr -d ' ') device rows, $(head -n1 "$W/host.audit" | cut -c1-70), events $(cat "$W/host.events") identical; object deleted, objects left in the bucket: $left"
}

measure() { # idle CPU % over 60 s, RSS, of the Core (the runner connected and idle)
  local c0 c1 pid
  c0=$(r "systemctl show -p CPUUsageNSec --value ainkrad-core"); sleep 60
  c1=$(r "systemctl show -p CPUUsageNSec --value ainkrad-core")
  pid=$(r "systemctl show -p MainPID --value ainkrad-core")
  CPU=$(python3 -c "print(f'{($c1 - $c0) / 60e9 * 100:.3f}')")
  RSS=$(r "ps -o rss= -p $pid" | awk '{printf "%.1f", $1 / 1024}')
  MEM=$(r "systemctl show -p MemoryCurrent --value ainkrad-core" | awk '{printf "%.1f", $1 / 1048576}')
}

NAMES=("bootstrap on host + pair here" "second device, host runner, scopes" "runner unit connects, pinned" \
  "run noop + audit rows" "kill -9 via systemd, no gap/dup" "backup to bucket -> restore here")
STEPS=() RESULTS=() EVIDENCE=() failed=0 EV=
for i in 1 2 3 4 5 6; do
  EV=
  if [ "$failed" = 0 ] && "step$i"; then r1=PASS; elif [ "$failed" = 0 ]; then r1=FAIL; failed=1; else r1=SKIP EV="an earlier step failed"; fi
  STEPS+=("$i ${NAMES[$((i - 1))]}"); RESULTS+=("$r1"); EVIDENCE+=("$EV")
done
[ "$failed" = 1 ] || measure
printf '\nE1 exit gate (remote %s, %s)\n' "$E1_CORE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%-42s %-5s %s\n' STEP RESULT EVIDENCE
for i in "${!STEPS[@]}"; do printf '%-42s %-5s %s\n' "${STEPS[$i]}" "${RESULTS[$i]}" "${EVIDENCE[$i]}"; done
[ "$failed" = 1 ] || printf 'idle (60 s, runner connected): CPU %s %%, RSS %s MB (cgroup %s MB); restart-to-serving %s s\n' "$CPU" "$RSS" "$MEM" "$RESTART"
exit "$failed"
