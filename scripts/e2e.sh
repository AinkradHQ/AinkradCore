#!/usr/bin/env bash
# Phase A end-to-end (E4.4): seed a company, agent, project and issue with the admin CLI,
# serve on a temp database and a loopback port, start a real runner, and let a real harness
# work the issue through the Citadel MCP server. Then check the run ended with a reason, the
# agent commented and moved the issue, usage was recorded, the transcript was stored and
# redacted, and the audit trail is there. Exits non-zero on any failure.
#
#   make e2e                                  OpenCode, its free model: no login needed
#   HARNESS=claude make e2e                   Claude; needs CLAUDE_CODE_OAUTH_TOKEN set
#   MODEL=<m> TIMEOUT=<secs> KEEP=1 make e2e  another model, wait, keep the scratch dir
#
# Everything lives in a scratch dir under /tmp, outside $HOME: the database, the git repo,
# the runner's home (its harness config dirs) and its work root. The user's own harness
# config is never read.
set -euo pipefail

HARNESS=${HARNESS:-opencode}
case $HARNESS in
opencode) MODEL=${MODEL:-opencode/nemotron-3.5-lightning-free} ;;
claude)
    if [ -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
        echo "e2e: HARNESS=claude needs CLAUDE_CODE_OAUTH_TOKEN in the environment" >&2
        exit 2
    fi
    MODEL=${MODEL:-haiku}
    ;;
*)
    echo "e2e: HARNESS must be opencode or claude" >&2
    exit 2
    ;;
esac
TIMEOUT=${TIMEOUT:-300}
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

ROOT=$(cd "$(mktemp -d /tmp/citadel-e2e.XXXXXX)" && pwd -P)
case "$ROOT/" in "$(cd "$HOME" && pwd -P)"/*)
    echo "e2e: scratch dir $ROOT is inside \$HOME" >&2
    exit 2
    ;;
esac
DB=$ROOT/citadel.db
PIDS=()
OK=0
cleanup() {
    for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    if [ "$OK" = 1 ] && [ "${KEEP:-0}" != 1 ]; then rm -rf "$ROOT"; else echo "e2e: kept $ROOT"; fi
}
trap cleanup EXIT
fail() {
    echo "e2e: FAIL: $*" >&2
    echo "--- server.log (tail)" >&2
    tail -n 20 "$ROOT/server.log" >&2 || true
    echo "--- runner.log (tail)" >&2
    tail -n 20 "$ROOT/runner.log" >&2 || true
    exit 1
}
sql() { sqlite3 -batch -noheader "$DB" "$1"; }
step() { echo "e2e: $*"; }

step "building"
(cd "$REPO_ROOT" && ${CARGO:-cargo} build --workspace -q)
SERVER=$REPO_ROOT/target/debug/ainkrad-core-server
RUNNER=$REPO_ROOT/target/debug/ainkrad-runner
started=$(date +%s)

step "seeding $ROOT"
mkdir -p "$ROOT/home" "$ROOT/tmp"
git_() { env -i PATH="$PATH" HOME="$ROOT/home" GIT_CONFIG_NOSYSTEM=1 git "$@"; }
git_ init -q -b main "$ROOT/repo"
git_ -C "$ROOT/repo" -c user.name=e2e -c user.email=e2e@citadel.invalid \
    commit -q --allow-empty -m "Start the e2e repo"
COMPANY=$("$SERVER" company add "$DB" "E2E Co" 2>/dev/null)
AGENT=$("$SERVER" agent add "$DB" "$COMPANY" "E2E Dev" --harness "$HARNESS" --model "$MODEL" \
    2>/dev/null)
# A new agent waits on its hire approval (E6.4): approve it so it can run.
HIRE=$(sql "SELECT id FROM approvals WHERE kind = 'hire_agent' AND agent_id = $AGENT")
"$SERVER" approval approve "$DB" "$HIRE" 2>/dev/null >/dev/null
PROJECT=$("$SERVER" project add "$DB" "$COMPANY" E2E "E2E project" --repo "$ROOT/repo" \
    --branch main --permission ask 2>/dev/null)
KEY=$("$SERVER" runner add "$DB" e2e-runner 2>/dev/null)
BODY="This is a Citadel end-to-end check. Use only the citadel MCP tools, in this order:
1. call transition with transition \"start\";
2. call comment with body \"e2e: hello from the agent\";
3. call transition with transition \"done\".
Do not edit files or run shell commands. Then reply with one line."
ISSUE=$("$SERVER" issue add "$DB" "$PROJECT" "Report in through Citadel" --body "$BODY" \
    --assignee "$AGENT" 2>/dev/null)

PORT=$(perl -MIO::Socket::INET -e \
    'print IO::Socket::INET->new(Listen => 1, LocalAddr => "127.0.0.1:0")->sockport')
step "serving on 127.0.0.1:$PORT"
"$SERVER" serve "$DB" --bind "127.0.0.1:$PORT" >"$ROOT/server.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
    sleep 0.1
done

step "starting the runner ($HARNESS, $MODEL)"
runner_env=(PATH="$PATH" HOME="$ROOT/home" TMPDIR="$ROOT/tmp" CITADEL_RUNNER_KEY="$KEY")
if [ "$HARNESS" = claude ]; then runner_env+=(CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN"); fi
env -i "${runner_env[@]}" RUST_LOG=info "$RUNNER" "ws://127.0.0.1:$PORT/runner/v1/connect" \
    --tags e2e --git-name "Citadel E2E" --git-email e2e@citadel.invalid \
    >"$ROOT/runner.log" 2>&1 &
PIDS+=($!)

step "waiting for the run (up to ${TIMEOUT}s)"
RUN=""
for _ in $(seq "$TIMEOUT"); do
    RUN=$(sql "SELECT id FROM runs WHERE issue_id = $ISSUE AND state NOT IN
               ('queued', 'claimed', 'running') ORDER BY id LIMIT 1")
    [ -n "$RUN" ] && break
    sleep 1
done
[ -n "$RUN" ] || fail "no run of issue $ISSUE ended within ${TIMEOUT}s"
for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
wait 2>/dev/null || true
PIDS=()
ended=$(date +%s)

IFS='|' read -r STATE REASON RUN_SECS IN OUT CACHE COST <<<"$(sql "SELECT state, terminal_reason,
    round((julianday(ended_at) - julianday(started_at)) * 86400, 1), input_tokens, output_tokens,
    cache_tokens, coalesce(cost_usd_micros, '') FROM runs WHERE id = $RUN")"
ISSUE_STATE=$(sql "SELECT state FROM issues WHERE id = $ISSUE")
COMMENTS=$(sql "SELECT count(*) FROM comments WHERE issue_id = $ISSUE
                AND author_agent_id = $AGENT AND run_id = $RUN")
MOVES=$(sql "SELECT count(*) FROM audit_events WHERE run_id = $RUN
             AND action = 'mcp.transition' AND details LIKE '%\"ok\":true%'")
CHUNKS=$(sql "SELECT count(*) FROM run_events WHERE run_id = $RUN")
LEAKS=$(sql "SELECT count(*) FROM run_events WHERE run_id = $RUN
             AND (instr(payload, 'cit_run_') > 0 OR instr(payload, '$KEY') > 0)")
COSTED=$(sql "SELECT count(*) FROM cost_events WHERE run_id = $RUN
              AND input_tokens + output_tokens > 0")
AUDITED=$(sql "SELECT group_concat(action, ' ') FROM (SELECT DISTINCT action FROM audit_events
               WHERE run_id = $RUN ORDER BY action)")

echo "e2e: run $RUN $STATE ($REASON) in ${RUN_SECS}s; whole e2e $((ended - started))s"
echo "e2e: tokens in $IN, out $OUT, cache $CACHE; cost micros ${COST:-none}"
echo "e2e: issue $ISSUE is $ISSUE_STATE; agent comments $COMMENTS; MCP transitions $MOVES"
echo "e2e: transcript chunks $CHUNKS; audited: $AUDITED"
# Stage timings (E15.6): wake → claim → workspace → harness → first token → end.
sql "SELECT printf('e2e: stages wake→claim %.2fs, claim→workspace %.2fs, workspace→harness %.2fs, ' ||
    'harness→first token %.2fs, first token→end %.2fs; wake→first token %.2fs',
    (julianday(claimed_at) - julianday(woken_at)) * 86400,
    (julianday(started_at) - julianday(claimed_at)) * 86400,
    (julianday(harness_started_at) - julianday(started_at)) * 86400,
    (julianday(first_token_at) - julianday(harness_started_at)) * 86400,
    (julianday(ended_at) - julianday(first_token_at)) * 86400,
    (julianday(first_token_at) - julianday(woken_at)) * 86400) FROM runs WHERE id = $RUN"
sql "SELECT '  comment: ' || body FROM comments WHERE issue_id = $ISSUE"

[ "$STATE" = succeeded ] || fail "run $RUN is $STATE: $REASON"
[ -n "$REASON" ] || fail "run $RUN has no terminal reason"
[ "$COMMENTS" -ge 1 ] || fail "the agent posted no comment through MCP"
[ "$MOVES" -ge 1 ] || fail "the agent made no transition through MCP"
[ "$ISSUE_STATE" != todo ] || fail "issue $ISSUE never moved"
[ $((IN + OUT)) -gt 0 ] && [ "$COSTED" -ge 1 ] || fail "no usage recorded for run $RUN"
[ "$CHUNKS" -gt 0 ] || fail "no transcript stored for run $RUN"
[ "$LEAKS" = 0 ] || fail "a stored transcript chunk holds a token or the runner key"
for action in run.token_issued mcp.comment mcp.transition; do
    case " $AUDITED " in *" $action "*) ;; *) fail "no $action in the audit trail" ;; esac
done
if grep -Eq "cit_run_[0-9a-f]{8}|$KEY" "$ROOT/server.log" "$ROOT/runner.log"; then
    fail "a token or the runner key reached a log"
fi
# Only the runner's `citadel` CLI (bin/, no secret) stays (E15.18).
if [ -n "$(ls -A "$ROOT/tmp/citadel-runs/private" 2>/dev/null | grep -vx bin)" ]; then
    fail "the run's private files outlived it"
fi
OK=1
echo "e2e: PASS"
