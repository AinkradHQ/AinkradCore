#!/usr/bin/env bash
# Phase B end-to-end (E9.5): one scrum project from a CEO intake to a reviewed sprint (see
# crates/server/tests/company/phase_b.rs). Two runs of the same flow:
#
#   1. scripted: every agent is a fake harness playing its script (also part of make test);
#   2. OpenCode: the developer's step is a real OpenCode on its free model, told what to do by
#      the issue body (start, comment, open_pr, done); every other agent stays scripted.
#
# What is real in both: the server, the runner (worktrees, pushes, MCP), the engine, the
# approvals through the admin CLI, the forge poller. What is fake: the forge (a loopback GitHub
# that the poller opens, follows and merges on), and in run 1 every agent. No real GitHub,
# GitLab or Linear is called.
#
#   make e2e-b                       both runs
#   SKIP_OPENCODE=1 make e2e-b       the scripted run only
#   MODEL=<m> make e2e-b             another OpenCode model
#   E2E_CLI=1 make e2e-b             the developer uses the run's citadel CLI (one batch)
#
# The test process runs with a scratch HOME and TMPDIR under /tmp, outside $HOME, so no
# harness reads the user's own config. The scratch dir is kept and its path printed.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
ROOT=$(cd "$(mktemp -d /tmp/citadel-e2e-b.XXXXXX)" && pwd -P)
case "$ROOT/" in "$(cd "$HOME" && pwd -P)"/*)
    echo "e2e-b: scratch dir $ROOT is inside \$HOME" >&2
    exit 2
    ;;
esac
mkdir -p "$ROOT/home" "$ROOT/tmp"
echo "e2e-b: scratch $ROOT (kept)"

echo "e2e-b: building"
BIN=$(cd "$REPO_ROOT" && ${CARGO:-cargo} test -p ainkrad-core-server --test company --no-run \
    --message-format=json 2>/dev/null | perl -MJSON::PP -ne '
        my $m = eval { decode_json($_) } or next;
        print $m->{executable}, "\n"
            if $m->{reason} eq "compiler-artifact" && $m->{target}{name} eq "company"
               && $m->{executable};')
[ -x "$BIN" ] || { echo "e2e-b: no test binary" >&2; exit 1; }

run() {
    env -i PATH="$PATH" HOME="$ROOT/home" TMPDIR="$ROOT/tmp" ${MODEL:+MODEL="$MODEL"} \
        ${E2E_CLI:+E2E_CLI="$E2E_CLI"} \
        "$BIN" "$@" --exact --nocapture --test-threads 1
}

echo "e2e-b: 1/2 scripted"
started=$(date +%s)
run company::phase_b::phase_b_one_scrum_project_from_goal_to_reviewed_sprint
echo "e2e-b: scripted run passed in $(($(date +%s) - started))s"

if [ "${SKIP_OPENCODE:-0}" = 1 ]; then
    echo "e2e-b: PASS (OpenCode run skipped)"
    exit 0
fi
command -v opencode >/dev/null || { echo "e2e-b: opencode is not on PATH" >&2; exit 2; }
echo "e2e-b: 2/2 OpenCode plays the developer (${MODEL:-opencode/nemotron-3.5-lightning-free})"
started=$(date +%s)
run company::phase_b::phase_b_with_opencode --ignored
echo "e2e-b: OpenCode run passed in $(($(date +%s) - started))s"
echo "e2e-b: PASS"
