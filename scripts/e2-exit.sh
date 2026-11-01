#!/usr/bin/env bash
# The E2 exit gate (E2-17, plan §4): the real Core, runner (pty + agents), ptyhost and ainkradctl, no UI.
#   scripts/e2-exit.sh              steps 1-7, prints a PASS/FAIL table, saves an evidence report
#   scripts/e2-exit.sh fault <name> one fault scenario (core_kill runner_kill host_kill network_cut slow_client), or `all`
#   scripts/e2-exit.sh soak         5 terminals + 2 agents idle for E2_SOAK_SECS (default 7200; 86400 for the 24 h run)
# Steps: 1 a terminal (flood, MARK, alt-screen app) and an agent session; 2 kill every client, restart the Core,
# restart the runner; 3 reattach from a different device: screen equals the pre-kill screen and the golden rows,
# MARK present, the agent resumed with a gap-free transcript; 4 cut the network mid-stream: no lost or duplicate
# bytes; 5 kill the agent and a terminal: no zombie, no orphan, worktree kept; 6 sandbox canaries; 7 secrets and
# terminal bytes never in logs or the database, and a teardown that leaves no process.
# The agent is a fake `claude` on the runner's PATH (it ticks, writes files, and probes a canary file and an env
# canary); a real harness is the VM run, after G-SEC. Freshness: every assertion reads output made after its action
# (a new file per action). Binaries: target/debug, or E2_BIN=<dir>; E2_KEEP=1 keeps the temp dir.
# SC2015: `a && b || fail` is meant; SC2329: steps are called as "step$i".
# shellcheck disable=SC2015,SC2329,SC2046,SC2166,SC2012,SC2034
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MODE=${1:-exit} FAULT=${2:-all}
E2_REPORT=${E2_REPORT:-$ROOT/target/e2-exit/report-$MODE-$(date -u +%Y%m%dT%H%M%SZ).md}
mkdir -p "$(dirname "$E2_REPORT")"
BIN=${E2_BIN:-${CARGO_TARGET_DIR:-$ROOT/target}/debug}
SRV=$BIN/ainkrad-core-server CTL=$BIN/ainkradctl RUN=$BIN/ainkrad-runner PTYH=$BIN/ainkrad-ptyhost
REND=$BIN/examples/render TOOLS=$ROOT/scripts/e2-exit-tools.py
if [ -z "${E2_BIN:-}" ] && [ ! -x "$REND" -o ! -x "$PTYH" -o ! -x "$SRV" -o ! -x "$CTL" -o ! -x "$RUN" ]; then
  (cd "$ROOT" && cargo build -q -p ainkrad-core-server -p ainkrad-ctl -p ainkrad-runner -p ainkrad-ptyhost && cargo build -q -p ainkrad-term --example render)
fi
for b in "$SRV" "$CTL" "$RUN" "$PTYH" "$REND"; do [ -x "$b" ] || { echo "e2-exit: no $b" >&2; exit 2; }; done
command -v jq >/dev/null && command -v python3 >/dev/null && command -v openssl >/dev/null ||
  { echo "e2-exit: needs jq, python3 and openssl" >&2; exit 2; }

W=$(mktemp -d /tmp/e2x.XXXXXX)
chmod 700 "$W"
PIDS=()
cleanup() {
  local p
  for p in ${PIDS[@]+"${PIDS[@]}"}; do pkill -P "$p" 2>/dev/null || true; kill "$p" 2>/dev/null || true; done
  # ptyhosts and sandboxed agents run in their own sessions: only their command lines name this run.
  pkill -f "$W" 2>/dev/null || true
  sleep 0.5
  pkill -9 -f "$W" 2>/dev/null || true
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill -9 "$p" 2>/dev/null || true; done
  if [ "${E2_KEEP:-0}" = 1 ]; then echo "e2-exit: kept $W" >&2; else rm -rf "$W"; fi
}
trap cleanup EXIT

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
PORT=$(free_port) PPORT=$(free_port)
URL=http://127.0.0.1:$PORT PURL=http://127.0.0.1:$PPORT
HOME_DIR=$W/home DB=$W/home/core.db SOCK=$W/home/admin.sock RSTATE=$W/runner
PASS_A=$W/pass-a PASS_B=$W/pass-b NONCE=$(openssl rand -hex 6)
openssl rand -hex 24 >"$PASS_A"; openssl rand -hex 24 >"$PASS_B"; chmod 600 "$PASS_A" "$PASS_B"
printf %s "$NONCE" >"$W/nonce"
ENVCANARY=envcanary-$(openssl rand -hex 8) FILECANARY=filecanary-$(openssl rand -hex 8)
mkdir -p "$W/canary" "$W/bin" "$W/tmp" "$W/a" "$W/b"
printf '%s\n' "$FILECANARY" >"$W/canary/id_e2"
KS_A=$W/a/keystore.json KS_B=$W/b/keystore.json
cargs() { echo --url "${3:-$URL}" --host "127.0.0.1:$PORT" --keystore "$1" --stepup-passphrase-file "$2"; }
# shellcheck disable=SC2046
a() { "$CTL" $(cargs "$KS_A" "$PASS_A") "$@" </dev/null; }
# shellcheck disable=SC2046
b() { "$CTL" $(cargs "$KS_B" "$PASS_B") "$@" </dev/null; }

STEPS=() RESULTS=() EVIDENCE=() EV=
record() { STEPS+=("$1"); RESULTS+=("$2"); EVIDENCE+=("$3"); }
wait_for() { local end=$((SECONDS + $1)); shift; until "$@" >/dev/null 2>&1; do [ "$SECONDS" -lt "$end" ] || return 1; sleep 0.2; done; }
field() { sed -n "s/^$2 //p" "$1" | head -n1; }
has_field() { [ -n "$(field "$1" "$2")" ]; }
alive() { kill -0 "$1" 2>/dev/null && ! ps -o stat= -p "$1" 2>/dev/null | grep -q '^Z'; }
fds() { if [ -d "/proc/$1/fd" ]; then ls "/proc/$1/fd" | wc -l; else lsof -p "$1" 2>/dev/null | wc -l; fi; }
rss() { ps -o rss= -p "$1" | tr -d ' '; }
# attach <who a|b> <out> <secs> <terminal> [send]: ainkradctl term attach under a pty, bytes recorded in <out>.
attach() {
  local who=$1 out=$2 secs=$3 t=$4 send=${5:--}
  if [ "$who" = a ]; then set -- $(cargs "$KS_A" "$PASS_A" "${ATTACH_URL:-$URL}"); else set -- $(cargs "$KS_B" "$PASS_B" "${ATTACH_URL:-$URL}"); fi
  python3 "$TOOLS" attach "$out" "$secs" "$send" -- "$CTL" "$@" term attach "$t" </dev/null
}
bg_attach() { attach "$@" & PIDS+=("$!"); }
ctl_pid() { ps -axo pid=,comm=,args= | awk -v t="attach $1" '$2 ~ /ainkradctl$/ && index($0, t) {print $1; exit}'; }
render() { "$REND" 24 80 <"$1"; }

serve() { # serve <log>
  rm -f "$SOCK"
  "$SRV" serve --config "$HOME_DIR/config.toml" --listen "loopback:$PORT" --allow-plain-runner 2>>"$1" >/dev/null &
  CORE=$!; PIDS+=("$CORE")
  wait_for 30 test -S "$SOCK" && wait_for 30 curl -fsS "$URL/healthz"
}
RUNNER_N=0
start_runner() {
  RUNNER_N=$((RUNNER_N + 1)); RLOG=$W/runner-$RUNNER_N.log
  env PATH="$W/bin:$PATH" TMPDIR="$W/tmp" E2_ENV_CANARY="$ENVCANARY" AINKRAD_PTYHOST="$PTYH" \
    "$RUN" connect --state "$RSTATE" --enable-pty --enable-agents >/dev/null 2>"$RLOG" </dev/null &
  RPID=$!; PIDS+=("$RPID")
  online() { a --json runner show "$RID" | jq -e '.online == true' >/dev/null; }
  wait_for 60 online
}

fake_claude() { # the harness stand-in: ticks, writes a file per tick, probes a canary file and an env canary
  local ver; ver=$(sed -n 's/^pub const VERSION: &str = "\(.*\)";/\1/p' "$ROOT/crates/harness/src/claude.rs")
  cat >"$W/bin/claude" <<EOF
#!/bin/sh
case "\$1" in --version) echo "$ver (Claude Code)"; exit 0;; esac
sid=; prev=; for x in "\$@"; do case \$prev in --session-id|--resume) sid=\$x;; esac; prev=\$x; done
printf '{"type":"system","subtype":"init","session_id":"%s"}\n' "\${sid:-00000000-0000-4000-8000-000000000e17}"
k=0
say() { k=\$((k+1)); printf '{"type":"assistant","message":{"id":"m%s-%s","content":[{"type":"text","text":"%s"}],"usage":{"input_tokens":1,"output_tokens":1}}}\n' "\$\$" "\$k" "\$1"; }
say "CWD=\$(pwd)"
if c=\$(cat "$W/canary/id_e2" 2>/dev/null); then say "CANARY-LEAKED \$c"; else say CANARY-READ-DENIED; fi
if env | grep -q '^E2_ENV_CANARY='; then say ENV-CANARY-PRESENT; else say ENV-CANARY-ABSENT; fi
cnt="\${CLAUDE_CONFIG_DIR:-.}/e2-ticks-\${sid:-x}"
n=\$(cat "\$cnt" 2>/dev/null || echo 0)
while :; do n=\$((n+1)); say "TICK-\$n"; echo \$n > "\$cnt"; echo "tick \$n" > "tick-\$n"; sleep ${E2_AGENT_TICK:-1}; done
EOF
  chmod 755 "$W/bin/claude"
}

rig_up() { # Core, device A (admin) and B (terminal+agent), a runner with pty and agents; sets RID
  local out
  SIGNER=$("$SRV" init "$HOME_DIR" 2>"$W/init.err" | tail -n1) || { EV="init failed"; return 1; }
  serve "$W/serve.log" || { EV="the Core did not start: $(tail -n3 "$W/serve.log")"; return 1; }
  mkfifo "$W/boot.in"
  "$SRV" bootstrap "$DB" admin <"$W/boot.in" >"$W/boot.out" 2>"$W/boot.err" &
  local boot=$!; PIDS+=("$boot"); exec 3>"$W/boot.in"
  wait_for 20 has_field "$W/boot.out" code && wait_for 5 has_field "$W/boot.out" core_fp || { EV="bootstrap printed no code"; return 1; }
  CORE_FP=$(field "$W/boot.out" core_fp)
  # shellcheck disable=SC2046
  "$CTL" --socket "$SOCK" --host "127.0.0.1:$PORT" --keystore "$KS_A" --stepup-passphrase-file "$PASS_A" \
    pair "$(field "$W/boot.out" code)" --core-fp "$CORE_FP" >"$W/pair-a.out" 2>&1 </dev/null &
  local pair=$!; PIDS+=("$pair")
  wait_for 20 has_field "$W/pair-a.out" sas && wait_for 20 has_field "$W/boot.out" sas || { EV="no SAS on both sides"; return 1; }
  [ "$(field "$W/pair-a.out" sas)" = "$(field "$W/boot.out" sas)" ] || { EV="the two SAS differ"; return 1; }
  echo y >&3; exec 3>&-
  wait "$boot" && wait "$pair" || { EV="bootstrap or pair failed"; return 1; }
  a device add phone --scopes read,terminal,agent >"$W/add-b.out" || { EV="device add failed"; return 1; }
  b pair "$(field "$W/add-b.out" code)" >"$W/pair-b.out" 2>&1 &
  local pb=$!; PIDS+=("$pb")
  wait_for 20 has_field "$W/pair-b.out" sas || { EV="B showed no SAS"; return 1; }
  a device approve "$(field "$W/add-b.out" pairing_id)" "$(field "$W/pair-b.out" sas)" >/dev/null || { EV="approving B failed"; return 1; }
  wait "$pb" || { EV="B's pairing failed"; return 1; }
  a device add vm --kind runner >"$W/add-r.out" || { EV="runner device add failed"; return 1; }
  "$RUN" pair "$URL" --code "$(field "$W/add-r.out" code)" --state "$RSTATE" >"$W/pair-r.out" 2>&1 </dev/null &
  local pr=$!; PIDS+=("$pr")
  runner_sas() { grep -E '^ +[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$' "$W/pair-r.out" | tr -d ' '; }
  wait_for 20 runner_sas || { EV="the runner showed no SAS"; return 1; }
  a device approve "$(field "$W/add-r.out" pairing_id)" "$(runner_sas)" >/dev/null || { EV="approving the runner failed"; return 1; }
  wait "$pr" || { EV="the runner's pairing failed"; return 1; }
  RID=$(sed -n 's/^Paired as \(d_[A-Za-z0-9]*\) with the Core.*/\1/p' "$W/pair-r.out")
  fake_claude
  start_runner || { EV="the runner did not come online: $(tail -n3 "$RLOG")"; return 1; }
  out=$(a --json runner show "$RID")
  echo "$out" | jq -e '[.drivers[].name] | (index("pty") != null) and (index("agent") != null)' >/dev/null 2>&1 ||
    { EV="the runner does not offer pty and agent: $(echo "$out" | jq -c .drivers)"; return 1; }
  EV="Core pinned $CORE_FP; A admin, B [read,terminal,agent]; runner $RID online with pty+agent (pid $RPID)"
}

new_term() { a --json term new "$RID" --rows 24 --cols 80 "$@" | jq -r .id; }
agent_run() { a --json agent run "$RID" claude go | jq -r .id; }
transcript() { a --json agent tail "$1" --after 0 --no-follow; } # one JSON entry per line
ticks() { transcript "$1" | jq -r '.body | tostring' | grep -o 'TICK-[0-9]*' | cut -d- -f2; }
contiguous() { awk 'NR==1{p=$1;next} $1!=p+1{bad=1} {p=$1} END{exit bad}'; }
term_status() { a --json term ls | jq -r --arg t "$1" '.[] | select(.id==$t) | .status'; }
# The host's pid, or a failure: an empty or non-numeric pid would make every "is it gone" check below pass vacuously.
host_pid() { local p; p=$(jq -r .pid "$RSTATE/terminals/$1.json" 2>/dev/null) || p=; case $p in ''|*[!0-9]*) echo "e2-exit: no host pid for terminal '$1'" >&2; return 1 ;; esac; echo "$p"; }
# A host and every process under it. The shells' own `$$` is in the terminal sandbox's PID namespace (Linux).
tree() { local c; echo "$1"; for c in $(pgrep -P "$1"); do tree "$c"; done; }
agent_state() { a --json agent show "$1" | jq -r .state; }
expect_lines() { seq 1 "$1" | awk '{printf "L%05d\n",$1}'; }
# stream <name> <action>: a gated 3000-line producer, attached through the proxy; the action hits mid-stream;
# the captured L-lines must be exactly L00001..L03000, each once, in order.
stream_fault() {
  local name=$1 action=$2 t out=$W/stream-$1.bin
  rm -f "$W/go-$name"
  t=$(new_term sh -c "echo READY; while [ ! -f $W/go-$name ]; do sleep 0.1; done; i=1; while [ \$i -le 3000 ]; do printf 'L%05d\n' \$i; i=\$((i+1)); [ \$((i%100)) = 0 ] && sleep 0.3; done; echo DONE-$name; sleep 100000")
  local hp; hp=$(host_pid "$t") || { EV="no host pid for $t"; return 1; }
  ATTACH_URL=$PURL
  bg_attach a "$out" 90 "$t"; local ap=$!
  ATTACH_URL=$URL
  wait_for 20 grep -aq READY "$out" || { EV="no READY from $t"; return 1; }
  touch "$W/go-$name"; sleep 2
  case $action in
    cut) kill -USR1 "$PROXY" ;;
    corekill) kill -9 "$CORE"; wait "$CORE" 2>/dev/null || true; serve "$W/serve-$name.log" || { EV="the Core did not restart"; return 1; } ;;
    runnerkill) kill -9 "$RPID"; wait "$RPID" 2>/dev/null || true; start_runner || { EV="the runner did not return"; return 1; } ;;
  esac
  wait_for 60 grep -aq "DONE-$name" "$out" || { EV="no DONE after $action: $(tr -d '\r' <"$out" | grep -a -c '^L') lines"; return 1; }
  pkill -f "term attach $t" 2>/dev/null || true; wait "$ap" 2>/dev/null || true
  tr -d '\r' <"$out" | grep -aE '^L[0-9]{5}$' >"$W/got-$name.txt" || true
  expect_lines 3000 >"$W/want-$name.txt"
  cmp -s "$W/got-$name.txt" "$W/want-$name.txt" ||
    { EV="after $action: $(wc -l <"$W/got-$name.txt" | tr -d ' ') lines, $(sort "$W/got-$name.txt" | uniq -d | wc -l | tr -d ' ') duplicated; first diff: $(diff "$W/got-$name.txt" "$W/want-$name.txt" | head -n2 | tr '\n' ' ')"; return 1; }
  alive "$hp" || { EV="the host $hp died"; return 1; }
  a term kill "$t" >/dev/null 2>&1 || true
  EV="$action mid-stream: 3000 lines, none lost, none duplicated, in order; host $hp alive"
}

PROXY=
start_proxy() { python3 "$TOOLS" proxy "$PPORT" "$PORT" >"$W/proxy.log" 2>&1 & PROXY=$!; PIDS+=("$PROXY"); wait_for 10 grep -q ready "$W/proxy.log"; }

# ---------------------------------------------------------------- steps 1-7
step0() { rig_up && start_proxy; }

step1() {
  T1=$(new_term sh -c "yes 'flood-flood-flood-flood-flood-flood-flood-flood-flood-flood-flood-flood-flood-flood-flood-flood' | head -n 14000; echo MARK-\$(cat $W/nonce); printf '\\033[?1049h\\033[2J\\033[3;5HE2-GOLDEN-ALT\\033[5;5Hrow five\\033[7;10H\\033[1mBOLD\\033[0m\\033[24;1Hstatus'; echo \$\$ >$W/t1.pid; exec sleep 100000") || return 1
  T2=$(new_term sh -c "echo \$\$ >$W/t2.pid; sleep 100000 & echo \$! >$W/t2.child; wait") || return 1
  AS=$(agent_run) || { EV="agent run failed"; return 1; }
  wait_for 30 test -s "$W/t1.pid" && wait_for 30 test -s "$W/t2.child" || { EV="the terminals did not start"; return 1; }
  sleep 2
  attach a "$W/pre.bin" 4 "$T1" >/dev/null || true
  render "$W/pre.bin" >"$W/pre.screen"
  wait_for 30 test "$(ticks "$AS" | wc -l)" -ge 3 || { EV="agent produced no ticks: $(agent_state "$AS")"; return 1; }
  transcript "$AS" >"$W/pre-tr.jsonl"; PRE_SEQ=$(tail -n1 "$W/pre-tr.jsonl" | jq .seq)
  grep -aq "MARK-$NONCE" "$W/pre.bin" || { EV="pre-kill screen lacks the MARK"; return 1; }
  [ "$(sed -n 1p "$W/pre.screen")" = ALT=true ] || { EV="pre-kill screen is not the alt-screen app"; return 1; }
  EV="terminals $T1 (flood+MARK+alt-screen app) and $T2; agent $AS has $(ticks "$AS" | wc -l) ticks (transcript seq $PRE_SEQ); pre-kill screen captured"
}

step2() {
  local hp1 hp2; hp1=$(host_pid "$T1") && hp2=$(host_pid "$T2") || { EV="no host pid for $T1 or $T2"; return 1; }
  pkill -f "term attach" 2>/dev/null || true
  [ -z "$(ctl_pid "$T1")" ] || { EV="a client survived"; return 1; }
  kill -9 "$CORE"; wait "$CORE" 2>/dev/null || true
  serve "$W/serve-2.log" || { EV="the Core did not restart: $(tail -n3 "$W/serve-2.log")"; return 1; }
  kill -9 "$RPID"; wait "$RPID" 2>/dev/null || true
  alive "$hp1" && alive "$hp2" || { EV="a terminal host died with the runner"; return 1; }
  start_runner || { EV="the runner did not come back: $(tail -n3 "$RLOG")"; return 1; }
  EV="clients killed; Core kill -9 + restart; runner kill -9 + restart (pid $RPID); hosts $hp1, $hp2 survived"
}

step3() {
  attach b "$W/post.bin" 4 "$T1" >/dev/null || true
  render "$W/post.bin" >"$W/post.screen"
  cmp -s "$W/pre.screen" "$W/post.screen" || { EV="screen differs from the pre-kill one: $(diff "$W/pre.screen" "$W/post.screen" | head -n3 | tr '\n' '|')"; return 1; }
  [ "$(sed -n 1p "$W/post.screen")" = ALT=true ] && [ "$(sed -n 4p "$W/post.screen")" = "    E2-GOLDEN-ALT" ] &&
    [ "$(sed -n 6p "$W/post.screen")" = "    row five" ] && [ "$(sed -n 8p "$W/post.screen")" = "         BOLD" ] &&
    [ "$(sed -n 25p "$W/post.screen")" = status ] || { EV="screen is not the golden one: $(head -n8 "$W/post.screen" | tr '\n' '|')"; return 1; }
  grep -aq "MARK-$NONCE" "$W/post.bin" || { EV="no MARK-$NONCE after the restarts"; return 1; }
  wait_for 90 test "$(agent_state "$AS")" = running || { EV="agent is $(agent_state "$AS"), not resumed"; return 1; }
  wait_for 30 test "$(ticks "$AS" | wc -l)" -gt "$(ticks_before)" || { EV="agent did not continue"; return 1; }
  transcript "$AS" >"$W/post-tr.jsonl"
  jq -s -e '[.[].seq] as $s | $s == [range(1; ($s|length)+1)]' "$W/post-tr.jsonl" >/dev/null || { EV="transcript seqs have a gap"; return 1; }
  ticks "$AS" | contiguous || { EV="tick numbers have a gap: $(ticks "$AS" | tr '\n' ' ')"; return 1; }
  head -n "$(wc -l <"$W/pre-tr.jsonl")" "$W/post-tr.jsonl" | cmp -s - "$W/pre-tr.jsonl" || { EV="the transcript's earlier entries changed"; return 1; }
  EV="device B: snapshot screen = pre-kill screen = golden rows (alt-screen), MARK-$NONCE present; agent running again, transcript 1..$(tail -n1 "$W/post-tr.jsonl" | jq .seq) gap-free, ticks contiguous"
}
ticks_before() { grep -o 'TICK-[0-9]*' "$W/pre-tr.jsonl" | tail -n1 | cut -d- -f2; }

step4() { stream_fault network_cut cut; }

step5() {
  local cwd rt hp2 sh2 ch2 agentpids before after
  cwd=$(transcript "$AS" | jq -r '.body | tostring' | grep -o 'CWD=[^"]*' | tail -n1 | cut -d= -f2-)
  [ -d "$cwd" ] || { EV="no agent worktree at '$cwd'"; return 1; }
  before=$(cd "$cwd" && ls tick-* | sort | cksum)
  hp2=$(host_pid "$T2") || { EV="no host pid for $T2"; return 1; }
  hp2=$(tree "$hp2" | tr '\n' ' ')
  agentpids=$(pgrep -f "$W/bin/claude" || true); [ -n "$agentpids" ] || { EV="no agent process to kill"; return 1; }
  a agent kill "$AS" >"$W/kill-agent.out" || { EV="agent kill failed: $(cat "$W/kill-agent.out")"; return 1; }
  a term kill "$T2" >"$W/kill-term.out" || { EV="term kill failed"; return 1; }
  # shellcheck disable=SC2086
  gone() { local p; for p in "$@"; do alive "$p" && return 1; done; return 0; }
  # shellcheck disable=SC2086
  wait_for 30 gone $hp2 $agentpids || { EV="processes left after the kills: $(for p in $hp2 $agentpids; do alive "$p" && echo -n "$p "; done)"; return 1; }
  [ "$(agent_state "$AS")" = ended ] || { sleep 3; [ "$(agent_state "$AS")" = ended ] || { EV="agent is $(agent_state "$AS")"; return 1; }; }
  rt=$(ps -axo pid=,ppid=,stat= | awk -v r="$RPID" '$2==r && $3 ~ /^Z/ {print $1}')
  [ -z "$rt" ] || { EV="zombie children of the runner: $rt"; return 1; }
  [ -d "$cwd" ] && after=$(cd "$cwd" && ls tick-* | sort | cksum) && [ "$before" = "$after" ] || { EV="worktree changed after the kill ('$before' vs '$after')"; return 1; }
  [ -z "$(pgrep -f "ainkrad-ptyhost.*$T2" || true)" ] || { EV="a ptyhost for $T2 is left"; return 1; }
  EV="agent killed (state ended) and $T2 closed: host, shell and child ($hp2) and harness gone; no zombie under the runner; worktree $cwd kept ($(ls "$cwd" | wc -l | tr -d ' ') files, unchanged)"
}

step6() {
  local t; t=$(transcript "$AS" | jq -r '.body | tostring')
  [ "$(cat "$W/canary/id_e2")" = "$FILECANARY" ] || { EV="the canary file is unreadable to us (vacuous test)"; return 1; }
  echo "$t" | grep -q CANARY-READ-DENIED || { EV="the sandboxed agent did not report a denial"; return 1; }
  echo "$t" | grep -q "$FILECANARY" && { EV="the agent read the canary file outside its sandbox"; return 1; }
  echo "$t" | grep -q ENV-CANARY-ABSENT || { EV="the agent saw the runner's env canary"; return 1; }
  EV="the agent (sandbox) could not read $W/canary/id_e2 (readable by us); the runner's env canary did not reach it"
}

step7() {
  local v hits=
  for v in "$FILECANARY" "$ENVCANARY" "$(cat "$PASS_A")" "$(cat "$PASS_B")" "MARK-$NONCE" "flood-flood-flood"; do
    # Terminal bytes are transport-only (P2.11); nothing of ours (logs, database, runner transcripts) may hold any of these.
    hits+=$(grep -rlaF --include='*.log' --include='*.err' --include='*.db' --include='*.db-wal' --include='*.jsonl' -- "$v" "$W" 2>/dev/null | tr '\n' ' ' || true)
  done
  [ -z "$hits" ] || { EV="a secret or terminal byte is in: $hits"; return 1; }
  local t1; t1=$(host_pid "$T1") || { EV="no host pid for $T1"; return 1; }
  t1=$(tree "$t1" | tr '\n' ' ')
  a term kill "$T1" >/dev/null 2>&1 || true
  kill "$RPID" "$CORE" "$PROXY" 2>/dev/null; wait "$RPID" "$CORE" 2>/dev/null || true
  left() { pgrep -f "$W" | grep -qv "^$$\$"; }
  wait_for 20 eval '! left' || { EV="processes left after the teardown: $(pgrep -fl "$W" | grep -v "^$$ " | head -n3 | tr '\n' ';')"; return 1; }
  # shellcheck disable=SC2086
  for p in $t1; do alive "$p" && { EV="a T1 process ($p) is left"; return 1; }; done
  EV="no canary, passphrase or terminal byte in any log, database or Core file; after the teardown no process names this run and no terminal child is left"
}

# ---------------------------------------------------------------- faults
fault_core_kill() { stream_fault core_kill corekill; }
fault_runner_kill() { stream_fault runner_kill runnerkill; }
fault_network_cut() { stream_fault network_cut2 cut; }
fault_host_kill() {
  local t hp; t=$(new_term sh -c "sleep 100000"); hp=$(host_pid "$t") || { EV="no host pid for $t"; return 1; }
  bg_attach a "$W/hostkill.bin" 30 "$t"; sleep 2; kill -9 "$hp"
  wait_for 40 eval '[ "$(term_status "$t")" = exited ]' || { EV="$t is '$(term_status "$t")' 40 s after its host was killed"; return 1; }
  pkill -f "term attach $t" 2>/dev/null || true
  alive "$RPID" || { EV="the runner died"; return 1; }
  EV="host $hp kill -9 with a client attached: $t reported exited, the runner stayed up"
}
fault_slow_client() {
  local t out=$W/slow-fast.bin slow=$W/slow-slow.bin r0 r1 sp
  rm -f "$W/go-slow"
  t=$(new_term sh -c "echo READY; while [ ! -f $W/go-slow ]; do sleep 0.1; done; head -c 3000000 /dev/zero | tr '\\\\0' 'x' | fold -w 79; echo DONE-slow; sleep 100000")
  bg_attach a "$slow" 70 "$t"; bg_attach b "$out" 70 "$t"
  wait_for 20 grep -aq READY "$slow" && wait_for 20 grep -aq READY "$out" || { EV="no READY"; return 1; }
  sp=$(ctl_pid "$t" | head -n1); [ -n "$sp" ] && kill -STOP "$sp"
  r0=$(rss "$RPID"); touch "$W/go-slow"
  wait_for 60 grep -aq DONE-slow "$out" || { EV="the fast client never got the end: the slow one held it up"; return 1; }
  r1=$(rss "$RPID")
  [ $((r1 - r0)) -lt 65536 ] || { EV="runner RSS grew $((r1 - r0)) KB behind a stopped client"; return 1; }
  kill -CONT "$sp"
  wait_for 60 grep -aq DONE-slow "$slow" || { EV="the slow client never caught up after it resumed"; return 1; }
  a term kill "$t" >/dev/null 2>&1 || true
  EV="a stopped client behind 3 MB: the fast client finished, runner RSS +$((r1 - r0)) KB, the slow client caught up (a snapshot) once resumed"
}
# The scrollback disk budget (E2-06.2) under a flood: four terminals print 2 MB each into a 1 MiB budget (cap 512 KiB each);
# the one with a client attached keeps its scrollback, the least recently used unattached ones are freed, the total comes
# back within the budget, and the Core, the runner, the evicted terminals and a new terminal all keep working.
fault_disk_full() {
  local sd=$RSTATE/terminals/scrollback budget=1048576 ts=() t i total sa s1 s2 ok= out=$W/df-new.bin
  ring_bytes() { find "$sd" -name "$1.*.ring" -exec cat {} + 2>/dev/null | wc -c | tr -d ' '; }
  ring_total() { find "$sd" -name '*.ring' -exec cat {} + 2>/dev/null | wc -c | tr -d ' '; }
  "$SRV" setting set "$DB" terminal.scrollback_budget_bytes $budget >/dev/null &&
    "$SRV" setting set "$DB" terminal.scrollback_bytes 524288 >/dev/null || { EV="could not set the scrollback limits"; return 1; }
  rm -f "$W/go-df"
  ts+=("$(new_term sh -c "echo READY; while [ ! -f $W/go-df ]; do sleep 0.1; done; head -c 2000000 /dev/zero | tr '\\\\0' x | fold -w 79; echo FLOOD-DONE-0; exec cat")")
  bg_attach a "$W/df-0.bin" 120 "${ts[0]}"
  wait_for 20 grep -aq READY "$W/df-0.bin" || { EV="no READY from the attached terminal"; return 1; }
  for i in 1 2 3; do
    ts+=("$(new_term sh -c "head -c 2000000 /dev/zero | tr '\\\\0' x | fold -w 79; echo FLOOD-DONE-$i; exec cat")")
    sleep 1.2
  done
  touch "$W/go-df"
  # The budget is enforced about once a second: wait for the total to settle inside it.
  total=0; for i in $(seq 1 60); do total=$(ring_total); [ "$total" -le $budget ] && [ "$total" -gt 0 ] && { ok=1; break; }; sleep 1; done
  [ -n "$ok" ] || { EV="the scrollback total is $total bytes, over the $budget budget after 60 s"; return 1; }
  sleep 3; total=$(ring_total)
  [ "$total" -le $budget ] || { EV="the total grew back to $total (budget $budget)"; return 1; }
  sa=$(ring_bytes "${ts[0]}"); s1=$(ring_bytes "${ts[1]}"); s2=$(ring_bytes "${ts[2]}")
  [ "$sa" -gt 100000 ] || { EV="the terminal with a client lost its scrollback ($sa bytes)"; return 1; }
  [ "$s1" -lt 100000 ] || { EV="the least recently used unattached terminal still holds $s1 bytes"; return 1; }
  curl -fsS "$URL/healthz" >/dev/null && alive "$RPID" && alive "$CORE" || { EV="the Core or the runner stopped"; return 1; }
  # Evicted is not dead: the terminal still echoes, and a new one opens and prints.
  attach a "$W/df-1.bin" 8 "${ts[1]}" 'still-here-df\n' >/dev/null 2>&1 || true
  grep -aq 'still-here-df' "$W/df-1.bin" || { EV="the evicted terminal ${ts[1]} does not answer"; return 1; }
  t=$(new_term sh -c "echo ALIVE-NEW-DF; exec cat")
  attach a "$out" 8 "$t" >/dev/null 2>&1 || true
  grep -aq ALIVE-NEW-DF "$out" || { EV="a new terminal printed nothing"; return 1; }
  for t in "${ts[@]}"; do a term kill "$t" >/dev/null 2>&1 || true; done
  pkill -f "term attach" 2>/dev/null || true
  EV="4 terminals x 2 MB into a $budget byte budget: total $total bytes; the attached one kept $sa bytes, the LRU unattached ones were freed ($s1, $s2 bytes); Core, runner, the evicted terminal and a new terminal all answered"
}

run_faults() {
  local names=(core_kill runner_kill host_kill network_cut slow_client disk_full) n
  [ "$FAULT" = all ] || names=("$FAULT")
  step0 || { record "rig" FAIL "$EV"; return; }
  for n in "${names[@]}"; do
    EV=
    if "fault_$n"; then record "fault $n" PASS "$EV"; else record "fault $n" FAIL "$EV"; fi
    echo "FAULT $n: ${RESULTS[-1]} $EV"
  done
}

# ---------------------------------------------------------------- soak
run_soak() {
  local secs=${E2_SOAK_SECS:-7200} every=${E2_SOAK_SAMPLE:-60} t i p end start csv=$W/soak.csv warm
  E2_AGENT_TICK=${E2_AGENT_TICK:-20}; export E2_AGENT_TICK
  step0 || { record "rig" FAIL "$EV"; return; }
  echo "t,proc,rss_kb,fds" >"$csv"
  local terms=()
  for i in 1 2 3 4 5; do terms+=("$(new_term sh -c "while :; do echo hb-$i; sleep 60; done")"); done
  local ag1 ag2; ag1=$(agent_run); ag2=$(agent_run)
  start=$SECONDS; end=$((start + secs))
  while [ "$SECONDS" -lt "$end" ]; do
    t=$((SECONDS - start))
    for p in "core:$CORE" "runner:$RPID"; do echo "$t,${p%%:*},$(rss "${p##*:}"),$(fds "${p##*:}")" >>"$csv"; done
    for i in "${terms[@]}"; do p=$(host_pid "$i"); echo "$t,host-$i,$(rss "$p"),$(fds "$p")" >>"$csv"; done
    sleep "$every"
  done
  warm=$((secs / 10)); [ "$warm" -le 600 ] || warm=600
  EV=$(python3 "$TOOLS" soak-check "$csv" "$warm") && record "soak flat (${secs}s, 5 terminals + 2 agents)" PASS "$(echo "$EV" | tr '\n' ';')" ||
    record "soak flat (${secs}s)" FAIL "$(echo "$EV" | tr '\n' ';')"
  cp "$csv" "${E2_REPORT%.md}.csv" 2>/dev/null || true
  local bad=
  for i in "${terms[@]}"; do [ "$(term_status "$i")" = running ] || bad+="$i "; done
  for i in "$ag1" "$ag2"; do [ "$(agent_state "$i")" = running ] && ticks "$i" | contiguous || bad+="$i "; done
  [ -z "$bad" ] && record "soak end state" PASS "all 5 terminals running, both agents running with gap-free transcripts" ||
    record "soak end state" FAIL "not healthy: $bad"
  local z; z=$(ps -axo pid=,ppid=,stat= | awk -v r="$RPID" '$2==r && $3 ~ /^Z/' | wc -l | tr -d ' ')
  [ "$z" = 0 ] && record "soak zombies" PASS "none under the runner" || record "soak zombies" FAIL "$z zombie(s) under the runner"
}

NAMES=("rig: Core, devices, runner with pty+agents" "1 terminals + agent session" "2 kill clients, restart Core and runner" \
  "3 different device: golden screen, MARK, agent resumed" "4 network cut mid-stream: no lost/duplicate bytes" \
  "5 kill agent and terminal: no zombie/orphan, worktree kept" "6 sandbox canaries" "7 secrets/bytes not in logs; clean teardown")
failed=0
case $MODE in
  fault) run_faults ;;
  soak) run_soak ;;
  *)
    for i in 0 1 2 3 4 5 6 7; do
      EV=
      if [ "$failed" = 0 ] && "step$i"; then record "${NAMES[$i]}" PASS "$EV"
      elif [ "$failed" = 0 ]; then record "${NAMES[$i]}" FAIL "$EV"; failed=1
      else record "${NAMES[$i]}" SKIP "an earlier step failed"; fi
    done ;;
esac
for r in "${RESULTS[@]}"; do [ "$r" = FAIL ] && failed=1; done

{
  printf '# E2 exit gate (%s, %s)\n\n' "$MODE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'Commit %s on %s. Agent: fake harness (real harnesses after G-SEC).\n\n' "$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)" "$(uname -sm)"
  printf '| Step | Result | Evidence |\n|---|---|---|\n'
  for i in "${!STEPS[@]}"; do printf '| %s | %s | %s |\n' "${STEPS[$i]}" "${RESULTS[$i]}" "${EVIDENCE[$i]//|/\\|}"; done
} >"$E2_REPORT"
printf '\nE2 exit gate (%s, %s)\n' "$MODE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '%-58s %-5s %s\n' STEP RESULT EVIDENCE
for i in "${!STEPS[@]}"; do printf '%-58s %-5s %s\n' "${STEPS[$i]}" "${RESULTS[$i]}" "${EVIDENCE[$i]}"; done
echo "report: $E2_REPORT"
exit "$failed"
