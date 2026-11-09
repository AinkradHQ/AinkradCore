#!/usr/bin/env bash
# Owner-run Seatbelt enforcement tests. Diagnostic: also writes sandbox denial lines to
# /tmp/ainkrad-seatbelt-diag.txt (send that file and this script's output back).
set -uo pipefail
cd "$(dirname "$0")/.."
test "$(uname -s)" = Darwin || { echo "ERROR: this script requires macOS" >&2; exit 1; }
echo "Running the ignored Seatbelt enforcement tests in this normal Terminal session."
echo "The agent environment cannot nest sandbox-exec; this script must be run by the owner."
if ! command -v cargo >/dev/null 2>&1; then
  for d in "$HOME/.cargo/bin" "$HOME"/.rustup/toolchains/*/bin; do
    [ -x "$d/cargo" ] && PATH="$d:$PATH" && break
  done
  export PATH
fi
command -v cargo >/dev/null 2>&1 || { echo "ERROR: cargo not found (looked in ~/.cargo/bin and ~/.rustup/toolchains)" >&2; exit 1; }
DIAG=/tmp/ainkrad-seatbelt-diag.txt
echo "macOS: $(sw_vers -productVersion) build $(sw_vers -buildVersion) arch $(uname -m)" | tee "$DIAG"
/usr/bin/sandbox-exec -p '(version 1)(allow default)' /usr/bin/true || { echo "ERROR: sandbox-exec preflight failed" >&2; exit 1; }

# Bisect probes: which program dies, and by which signal (shell status 128+N = signal N).
probe() {
  /usr/bin/sandbox-exec -p "$1" "${@:2}" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" -gt 128 ]; then echo "PROBE [$2 ...] killed by signal $((rc - 128)) (status $rc)"; else echo "PROBE [$2 ...] exit $rc"; fi
}
{
  base='(version 1)(deny default)(import "system.sb")(allow process-exec process-fork)(allow file-read* file-map-executable (subpath "/usr") (subpath "/bin") (subpath "/System/Library"))'
  probe '(version 1)(deny default)' /usr/bin/true
  probe "$base" /usr/bin/true
  probe "$base" /bin/bash -c true
  base2="$base"'(allow file-read* (literal "/private/var/db/xcode_select_link") (literal "/var/db/xcode_select_link") (subpath "/Library/Developer/CommandLineTools") (subpath "/Applications/Xcode.app/Contents/Developer"))(allow file-map-executable (subpath "/Library/Developer/CommandLineTools") (subpath "/Applications/Xcode.app/Contents/Developer"))'
  probe "$base2" /usr/bin/python3 -c pass
  probe "$base2" /usr/bin/git --version
  probe "$base2" /usr/bin/make --version
} 2>&1 | tee -a "$DIAG"

START=$(date '+%Y-%m-%d %H:%M:%S')
AINKRAD_SANDBOX_DIAG=1 cargo test -p ainkrad-harness sandbox::tests -- --ignored --nocapture --test-threads=1 2>&1 | tee -a "$DIAG.test"
rc=${PIPESTATUS[0]}
{
  echo "=== sandbox denials since $START ==="
  /usr/bin/log show --start "$START" --predicate 'sender == "Sandbox"' --style compact 2>&1 | grep -i "deny" | head -400
  echo "=== cargo test: $(grep -c . "$DIAG.test") lines, status $rc ==="
  cat "$DIAG.test"
} >> "$DIAG"
rm -f "$DIAG.test"
echo "Diagnostics saved to $DIAG: send that file back."
if [ "$rc" -eq 0 ] && [ -n "${AINKRAD_TEST_RAMDIR:-}" ]; then
  cargo test -p ainkrad-runner v2::agent::tests -- --ignored --nocapture --test-threads=1 || rc=$?
elif [ -z "${AINKRAD_TEST_RAMDIR:-}" ]; then
  echo "NOT RUN: secret file lifecycle probes require AINKRAD_TEST_RAMDIR on a verified RAM disk." >&2
fi
exit "$rc"
