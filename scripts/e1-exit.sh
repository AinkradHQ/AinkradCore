#!/usr/bin/env bash
# The E1 exit gate (E1-14.3, plan §4), LOCAL mode: starts its own Core and runner in a fresh temp dir and runs
#   1 init + bootstrap (one-time code on the host) + `ainkradctl pair`
#   2 a second device approved by the first; a third (a real `ainkrad-runner pair`) approved by the second; scopes honoured
#   3 the runner connects over protocol v2 with the Core pinned
#   4 `ainkradctl run noop` answers and the audit rows exist
#   5 `kill -9` the Core mid-stream, restart: `events tail --after` has no gap and no duplicate; the runner reconnects
#   6 backup -> restore into a fresh dir (local file store) -> compare devices, audit head, event range; audit verify
# Prints a PASS/FAIL table with one evidence line per step; exits 1 on any FAIL.
#   scripts/e1-exit.sh            (binaries from target/debug, built if missing; E1_BIN=<dir> to use others)
#   E1_KEEP=1 keeps the temp dir for inspection.
# Freshness: every assertion reads output made after its action (a new file per action, or a byte offset taken
# before the action on a long-lived log). Ports and paths are unique per run, so runs can go in parallel.
# SC2015: `a && b || fail` is meant (fail when either fails); SC2329: steps are called as "step$i".
# shellcheck disable=SC2015,SC2329
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${E1_BIN:-$ROOT/target/debug}
SRV=$BIN/ainkrad-core-server CTL=$BIN/ainkradctl RUN=$BIN/ainkrad-runner
if [ -z "${E1_BIN:-}" ] && { [ ! -x "$SRV" ] || [ ! -x "$CTL" ] || [ ! -x "$RUN" ]; }; then
  (cd "$ROOT" && cargo build -q -p ainkrad-core-server -p ainkrad-ctl -p ainkrad-runner)
fi
for b in "$SRV" "$CTL" "$RUN"; do [ -x "$b" ] || { echo "e1-exit: no $b" >&2; exit 2; }; done
command -v jq >/dev/null && command -v sqlite3 >/dev/null && command -v python3 >/dev/null ||
  { echo "e1-exit: needs jq, sqlite3 and python3" >&2; exit 2; }

# A short path: the Core's admin socket lives in its home and Unix socket paths must stay short.
W=$(mktemp -d /tmp/e1x.XXXXXX)
chmod 700 "$W"
PIDS=()
cleanup() {
  local p
  # A backgrounded function (`a … &`) is a subshell: its children go too.
  for p in ${PIDS[@]+"${PIDS[@]}"}; do pkill -P "$p" 2>/dev/null || true; kill "$p" 2>/dev/null || true; done
  sleep 0.5
  for p in ${PIDS[@]+"${PIDS[@]}"}; do pkill -9 -P "$p" 2>/dev/null || true; kill -9 "$p" 2>/dev/null || true; done
  if [ "${E1_KEEP:-0}" = 1 ]; then echo "e1-exit: kept $W" >&2; else rm -rf "$W"; fi
}
trap cleanup EXIT

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
PORT=$(free_port)
URL=http://127.0.0.1:$PORT
HOME_DIR=$W/home DB=$W/home/core.db SOCK=$W/home/admin.sock
PASS_A=$W/pass-a PASS_B=$W/pass-b
openssl rand -hex 24 >"$PASS_A"; openssl rand -hex 24 >"$PASS_B"; chmod 600 "$PASS_A" "$PASS_B"
KS_A=$W/a/keystore.json KS_B=$W/b/keystore.json RSTATE=$W/runner
a() { "$CTL" --url "$URL" --host "${URL#http://}" --keystore "$KS_A" --stepup-passphrase-file "$PASS_A" "$@" </dev/null; }
b() { "$CTL" --url "$URL" --host "${URL#http://}" --keystore "$KS_B" --stepup-passphrase-file "$PASS_B" "$@" </dev/null; }

STEPS=() RESULTS=() EVIDENCE=() EV=
record() { STEPS+=("$1"); RESULTS+=("$2"); EVIDENCE+=("$3"); }
# wait_for <secs> <cmd...>: until the command succeeds.
wait_for() {
  local end=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do [ "$SECONDS" -lt "$end" ] || return 1; sleep 0.1; done
}
# The value of the first `key value` line of a file.
field() { sed -n "s/^$2 //p" "$1" | head -n1; }
has_field() { [ -n "$(field "$1" "$2")" ]; }
# The newest seq this device sees (0 when none).
head_seq() { local s; s=$(a events tail --after 0 --no-follow | tail -n1 | jq -r .seq); echo "${s:-0}"; }
# The tail's seqs strictly consecutive after $2 (no gap, no duplicate) in file $1, ending at $3.
consecutive() {
  jq -s --argjson from "$2" --argjson to "$3" \
    '[.[].seq] as $s | ($s == [range($from + 1; $to + 1)])' "$1" | grep -qx true
}

serve() { # serve <log>: the Core in the background on $PORT
  rm -f "$SOCK"
  "$SRV" serve --config "$HOME_DIR/config.toml" --listen "loopback:$PORT" 2>>"$1" >/dev/null &
  CORE=$!; PIDS+=("$CORE")
  wait_for 30 test -S "$SOCK" && wait_for 30 curl -fsS "$URL/healthz"
}

step1() {
  SIGNER=$("$SRV" init "$HOME_DIR" 2>"$W/init.err" | tail -n1) || { EV="init failed"; return 1; }
  serve "$W/serve.log" || { EV="the Core did not start: $(tail -n3 "$W/serve.log")"; return 1; }
  mkfifo "$W/boot.in"
  "$SRV" bootstrap "$DB" admin <"$W/boot.in" >"$W/boot.out" 2>"$W/boot.err" &
  local boot=$!; PIDS+=("$boot")
  exec 3>"$W/boot.in"
  wait_for 20 has_field "$W/boot.out" code && wait_for 5 has_field "$W/boot.out" core_fp ||
    { EV="bootstrap printed no code"; return 1; }
  CORE_FP=$(field "$W/boot.out" core_fp)
  mkdir -p "$W/a"
  "$CTL" --socket "$SOCK" --host "127.0.0.1:$PORT" --keystore "$KS_A" --stepup-passphrase-file "$PASS_A" \
    pair "$(field "$W/boot.out" code)" --core-fp "$CORE_FP" >"$W/pair-a.out" 2>&1 </dev/null &
  local pair=$!; PIDS+=("$pair")
  wait_for 20 has_field "$W/pair-a.out" sas && wait_for 20 has_field "$W/boot.out" sas ||
    { EV="no SAS on both sides"; return 1; }
  [ "$(field "$W/pair-a.out" sas)" = "$(field "$W/boot.out" sas)" ] || { EV="the two SAS differ"; return 1; }
  echo y >&3; exec 3>&-
  wait "$boot" && wait "$pair" || { EV="bootstrap or pair failed: $(tail -n2 "$W/pair-a.out")"; return 1; }
  [ "$(field "$W/pair-a.out" status)" = active ] || { EV="device A not active"; return 1; }
  DEV_A=$(field "$W/pair-a.out" device)
  a health >"$W/health-a.out" || { EV="health failed"; return 1; }
  grep -q "^core_fp $CORE_FP (matches the pinned one)" "$W/health-a.out" || { EV="Core not pinned"; return 1; }
  EV="init+bootstrap: $DEV_A active, SAS matched on host and device, Core $CORE_FP pinned"
}

step2() {
  a device add phone --scopes read,admin,runner >"$W/add-b.out" || { EV="device add (A) failed"; return 1; }
  mkdir -p "$W/b"
  b pair "$(field "$W/add-b.out" code)" >"$W/pair-b.out" 2>&1 &
  local pb=$!; PIDS+=("$pb")
  wait_for 20 has_field "$W/pair-b.out" sas || { EV="B showed no SAS"; return 1; }
  a device approve "$(field "$W/add-b.out" pairing_id)" "$(field "$W/pair-b.out" sas)" >"$W/approve-b.out" ||
    { EV="A could not approve B (step-up)"; return 1; }
  wait "$pb" || { EV="B's pairing failed"; return 1; }
  DEV_B=$(field "$W/pair-b.out" device)
  b --json health >"$W/health-b.json" || { EV="B health failed"; return 1; }
  [ "$(jq -c '.scopes | sort' "$W/health-b.json")" = '["admin","read","runner"]' ] ||
    { EV="B scopes $(jq -c .scopes "$W/health-b.json")"; return 1; }
  # B (not A) pairs the runner: its own step-up key, through the passphrase file. A pairing grants only
  # scopes its creator holds, so B needs `runner` to pair a runner; it has no `agent`.
  b device add vm --kind runner >"$W/add-r.out" || { EV="B could not start the runner pairing"; return 1; }
  "$RUN" pair "$URL" --code "$(field "$W/add-r.out" code)" --state "$RSTATE" >"$W/pair-r.out" 2>&1 </dev/null &
  local pr=$!; PIDS+=("$pr")
  runner_sas() { grep -E '^ +[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$' "$W/pair-r.out" | tr -d ' '; }
  wait_for 20 runner_sas || { EV="the runner showed no SAS"; return 1; }
  b device approve "$(field "$W/add-r.out" pairing_id)" "$(runner_sas)" >"$W/approve-r.out" ||
    { EV="B could not approve the runner"; return 1; }
  wait "$pr" || { EV="the runner's pairing failed: $(tail -n2 "$W/pair-r.out")"; return 1; }
  RID=$(sed -n 's/^Paired as \(d_[A-Za-z0-9]*\) with the Core \([^;]*\);.*/\1/p' "$W/pair-r.out")
  local pinned; pinned=$(sed -n 's/^Paired as d_[A-Za-z0-9]* with the Core \([^;]*\);.*/\1/p' "$W/pair-r.out")
  [ -n "$RID" ] && [ "$pinned" = "$CORE_FP" ] || { EV="runner pinned '$pinned', Core is $CORE_FP"; return 1; }
  b --json device show "$RID" >"$W/show-r.json" || { EV="device show runner failed"; return 1; }
  [ "$(jq -c '[.kind,.scopes]' "$W/show-r.json")" = '["runner",["runner"]]' ] ||
    { EV="runner device $(jq -c '[.kind,.scopes]' "$W/show-r.json")"; return 1; }
  EV="B $DEV_B [read,admin,runner] approved by A; runner $RID [runner] approved by B, pinned $CORE_FP"
}

step3() {
  RLOG=$W/runner.log
  "$RUN" connect --state "$RSTATE" >/dev/null 2>"$RLOG" </dev/null &
  RPID=$!; PIDS+=("$RPID")
  online() { a --json runner show "$RID" | jq -e '.online == true' >/dev/null; }
  wait_for 20 online || { EV="the runner did not come online: $(tail -n2 "$RLOG")"; return 1; }
  a --json runner show "$RID" >"$W/runner-3.json"
  [ "$(jq -c '[.drivers[].commands[]]' "$W/runner-3.json")" = '["noop"]' ] ||
    { EV="advertised $(jq -c '.drivers' "$W/runner-3.json") (exec must stay off)"; return 1; }
  EV="runner $RID online over v2 (pid $RPID), advertises only noop, version $(jq -r .version "$W/runner-3.json")"
}

step4() {
  local mark; mark=$(head_seq)
  set +e; b run noop "$RID" >"$W/noop-b.out" 2>&1; local bcode=$?; set -e
  [ "$bcode" = 4 ] && grep -q forbidden_scope "$W/noop-b.out" ||
    { EV="B (no agent scope) got exit $bcode: $(cat "$W/noop-b.out")"; return 1; }
  a device rename "$RID" vm-runner >"$W/rename-r.out" || { EV="renaming the runner failed"; return 1; }
  a --json run noop "$RID" >"$W/noop-a.json" || { EV="run noop failed: $(cat "$W/noop-a.json")"; return 1; }
  jq -e '.ok == true' "$W/noop-a.json" >/dev/null || { EV="noop answered $(cat "$W/noop-a.json")"; return 1; }
  a events tail --after "$mark" --no-follow >"$W/events-4.jsonl"
  jq -e --arg r "$RID" 'select(.kind=="audit" and .payload.action=="runner.command"
      and .payload.details.runner==$r and .payload.details.ok==true)' "$W/events-4.jsonl" >/dev/null ||
    { EV="no runner.command audit row after seq $mark"; return 1; }
  jq -e --arg r "$RID" 'select(.kind=="audit" and .payload.action=="device.renamed")' "$W/events-4.jsonl" >/dev/null ||
    { EV="no device.renamed audit row after seq $mark"; return 1; }
  local actions; actions=$(jq -r 'select(.kind=="audit") | .payload.action' "$W/events-4.jsonl" | sort -u | tr '\n' ' ')
  EV="noop ok in $(jq -r .duration_ms "$W/noop-a.json") ms; B (no agent) refused: exit 4 forbidden_scope; audit rows after seq $mark: $actions"
}

step5() {
  local s0; s0=$(head_seq)
  a events tail --after "$s0" >"$W/follow.jsonl" 2>"$W/follow.err" &
  local tail=$!; PIDS+=("$tail")
  a device rename "$DEV_B" phone-1 >/dev/null && a device rename "$DEV_B" phone-2 >/dev/null ||
    { EV="rename failed"; return 1; }
  local before; before=$(head_seq)
  wait_for 10 consecutive "$W/follow.jsonl" "$s0" "$before" || { EV="the tail did not keep up before the kill"; return 1; }
  local killed_at; killed_at=$(date -u +%H:%M:%SZ)
  kill -9 "$CORE"; wait "$CORE" 2>/dev/null || true
  serve "$W/serve-2.log" || { EV="the Core did not restart: $(tail -n3 "$W/serve-2.log")"; return 1; }
  a device rename "$DEV_B" phone-3 >/dev/null || { EV="rename after restart failed"; return 1; }
  reconnected() {
    a --json runner show "$RID" | jq -e '.online == true' >/dev/null &&
      a events tail --after "$before" --no-follow | jq -e --arg r "$RID" \
        'select(.kind=="runner.connected" and .payload.device_id==$r)' >/dev/null
  }
  wait_for 60 reconnected || { EV="the runner did not reconnect: $(tail -n2 "$RLOG")"; return 1; }
  kill -0 "$RPID" || { EV="the runner process died"; return 1; }
  local end; end=$(head_seq)
  wait_for 15 consecutive "$W/follow.jsonl" "$s0" "$end" ||
    { EV="followed seqs not consecutive $s0..$end: $(jq -c -s '[.[].seq]' "$W/follow.jsonl")"; return 1; }
  pkill -P "$tail" || true; wait "$tail" 2>/dev/null || true
  a events tail --after "$s0" --no-follow >"$W/replay-5.jsonl"
  consecutive "$W/replay-5.jsonl" "$s0" "$end" || { EV="replay after $s0 has a gap or duplicate"; return 1; }
  cmp -s <(jq -cS . "$W/follow.jsonl") <(jq -cS . "$W/replay-5.jsonl") ||
    { EV="the followed stream differs from the replay"; return 1; }
  local n; n=$(wc -l <"$W/follow.jsonl" | tr -d ' ')
  EV="kill -9 at seq $before ($killed_at); followed $((s0 + 1))..$end ($n events) consecutive, = replay; runner pid $RPID reconnected (runner.connected after $before)"
}

step6() {
  kill "$RPID" "$CORE"; wait "$RPID" "$CORE" 2>/dev/null || true
  "$SRV" backup-keygen >"$W/identity.txt"; chmod 600 "$W/identity.txt"
  local recipient; recipient=$(sed -n 's/^# public key: //p' "$W/identity.txt")
  local file; file=$(AINKRAD_BACKUP_RECIPIENT=$recipient "$SRV" backup --config "$HOME_DIR/config.toml" --local-only) ||
    { EV="backup failed"; return 1; }
  "$SRV" restore "$file" --identity "$W/identity.txt" --signer "$SIGNER" "$W/restored" >"$W/restore.out" ||
    { EV="restore failed"; return 1; }
  local x
  for x in "$HOME_DIR" "$W/restored"; do
    "$SRV" device list "$x/core.db" >"$x.devices"
    "$SRV" audit verify "$x/core.db" >"$x.audit" || { EV="audit verify failed on $x"; return 1; }
    sqlite3 -readonly "$x/core.db" 'SELECT min(seq), max(seq), count(*) FROM events' >"$x.events"
  done
  cmp -s "$HOME_DIR.devices" "$W/restored.devices" || { EV="device lists differ"; return 1; }
  cmp -s "$HOME_DIR.audit" "$W/restored.audit" || { EV="audit heads differ"; return 1; }
  cmp -s "$HOME_DIR.events" "$W/restored.events" || { EV="event ranges differ"; return 1; }
  # Not part of PASS: whether a Core served from the restored home is the Core the devices pinned.
  local identity=absent pinned rows; rows=$(wc -l <"$HOME_DIR.devices" | tr -d ' ')
  [ -e "$W/restored/core-identity.p8" ] && identity=present
  HOME_DIR=$W/restored SOCK=$W/restored/admin.sock PORT=$(free_port)
  URL=http://127.0.0.1:$PORT
  if serve "$W/serve-restored.log"; then
    set +e; a health >"$W/health-restored.out" 2>&1; pinned="ctl health exit $?"; set -e
  else pinned="the restored Core did not start"; fi
  EV="restored $(basename "$file"): $rows device rows, $(head -n1 "$W/home.audit" | cut -c1-80), events (min|max|count) $(cat "$W/home.events"): identical; audit verify ok on both. core-identity.p8 restored: $identity; against the restored Core: $pinned"
}

NAMES=("init + bootstrap + pair" "second device, runner device, scopes" "runner connects, Core pinned" \
  "run noop + audit rows" "kill -9, restart, no gap/dup, reconnect" "backup -> restore -> compare")
failed=0
for i in 1 2 3 4 5 6; do
  EV=
  if [ "$failed" = 0 ] && "step$i"; then
    record "$i ${NAMES[$((i - 1))]}" PASS "$EV"
  elif [ "$failed" = 0 ]; then
    record "$i ${NAMES[$((i - 1))]}" FAIL "$EV"; failed=1
  else
    record "$i ${NAMES[$((i - 1))]}" SKIP "an earlier step failed"
  fi
done

printf '\nE1 exit gate (local, %s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%-45s %-5s %s\n' STEP RESULT EVIDENCE
for i in "${!STEPS[@]}"; do printf '%-45s %-5s %s\n' "${STEPS[$i]}" "${RESULTS[$i]}" "${EVIDENCE[$i]}"; done
exit "$failed"
