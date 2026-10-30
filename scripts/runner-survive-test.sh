#!/usr/bin/env bash
# E2-15: a terminal host must survive its runner. Kills the runner (SIGKILL) and stops its unit while a detached
# host runs, and asserts the host is still alive; then repeats with the setting that does NOT protect it, and
# asserts the host dies (so the test can fail). No root, no Docker, nothing installed:
#   Linux: a transient `systemd-run --user` unit taking the real unit's kill and seccomp/privilege directives
#          (deploy/systemd/ainkrad-runner.service), with the real ainkrad-ptyhost holding a PTY. A user manager cannot
#          apply PrivateDevices, DevicePolicy, Protect*Kernel*/Clock/Hostname or an empty CapabilityBoundingSet: SURVIVE_SYSTEM=1 (needs `sudo -n`) runs
#          a system unit as the current user instead, with those too, so the PTY is proven under the whole sandbox.
#   macOS: a throwaway LaunchAgent with the real plist's AbandonProcessGroup, and a plain `sleep` for the host.
#   scripts/runner-survive-test.sh [path to ainkrad-ptyhost]     (Linux; default: target/{debug,release}/ainkrad-ptyhost)
# SC2015: `check && ok || bad` is meant (ok never fails); SC2329: cleanup runs from the trap.
# shellcheck disable=SC2015,SC2329,SC2317
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
UNIT=$ROOT/deploy/systemd/ainkrad-runner.service PLIST=$ROOT/deploy/launchd/io.ainkrad.runner.plist
W=$(mktemp -d); fail=0; pids=()
cleanup() { for p in ${pids[@]+"${pids[@]}"}; do kill -KILL "$p" 2>/dev/null; done; rm -rf "$W"; }
trap cleanup EXIT
ok() { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
alive() { kill -0 "$1" 2>/dev/null; }
wait_for() { local n=0; while [ "$n" -lt 50 ]; do [ -e "$1" ] && return 0; n=$((n + 1)); sleep 0.2; done; return 1; }

linux() {
  local SR=(systemd-run --user) SC=(systemctl --user) root_only=''
  if [ "${SURVIVE_SYSTEM:-0}" = 1 ]; then
    sudo -n true || { echo "SURVIVE_SYSTEM=1 needs passwordless sudo"; return 1; }
    SR=(sudo -n systemd-run -p "User=$(id -un)") SC=(sudo -n systemctl) root_only='|PrivateDevices|DevicePolicy|CapabilityBoundingSet|ProtectKernelTunables|ProtectKernelModules|ProtectKernelLogs|ProtectControlGroups|ProtectClock|ProtectHostname'
  fi
  command -v systemd-run >/dev/null && "${SC[@]}" is-system-running >/dev/null 2>&1 ||
    { echo "SKIP: no user systemd here (needs systemd --user); the unit's KillMode is still checked by make install-test"; return 0; }
  local host=${1:-}
  [ -n "$host" ] || for host in "$ROOT/target/debug/ainkrad-ptyhost" "$ROOT/target/release/ainkrad-ptyhost" "${CARGO_TARGET_DIR:-/nonexistent}/debug/ainkrad-ptyhost"; do [ -x "$host" ] && break; done
  [ -x "$host" ] || { echo "no ainkrad-ptyhost binary (cargo build -p ainkrad-ptyhost, or pass its path)"; return 1; }
  local km; km=$(sed -n 's/^KillMode=//p' "$UNIT")
  [ "$km" = process ] && ok "the unit says KillMode=process" || { bad "the unit's KillMode is '$km'"; return 1; }
  # The unit's own directives that act on a terminal host (seccomp, devices, capabilities); path-related ones (ProtectSystem, ProtectHome, PrivateTmp) are left out: they need paths this test does not have.
  local props=() l
  while IFS= read -r l; do props+=(-p "$l"); done < <(grep -E "^(KillMode|NoNewPrivileges|RestrictNamespaces|RestrictAddressFamilies|SystemCallFilter|SystemCallErrorNumber|SystemCallArchitectures|LockPersonality|RestrictRealtime|RestrictSUIDSGID$root_only)=" "$UNIT")
  # The fake runner: starts a host the way the real runner does (spec on stdin, stdout a pipe), then idles as the main process.
  cat >"$W/fakerunner.sh" <<FAKE
#!/usr/bin/env bash
mkdir -p -m 0700 "$W/term"
printf '{"program":"/bin/sleep","args":["600"],"env":{},"size":{"rows":24,"cols":80}}' |
  "$host" serve --dir "$W/term" --id "\$1" >"$W/ready.\$1" 2>/dev/null &
exec sleep 600
FAKE
  chmod +x "$W/fakerunner.sh"
  # start <unit> <id> <kill mode override or ''> <how: sigkill|stop>; prints nothing, sets HOSTPID
  scenario() {
    local u=ainkrad-survive-$$-$1 id=t_$1 mode=$2 how=$3 pp=("${props[@]}") rc
    [ -z "$mode" ] || pp+=(-p "KillMode=$mode") # later property wins
    "${SR[@]}" -q --unit="$u" --collect -p Type=exec "${pp[@]}" "$W/fakerunner.sh" "$id" 2>"$W/err" || {
      # A sandbox the user manager cannot build (no user namespaces): the kill logic alone.
      "${SR[@]}" -q --unit="$u" --collect -p Type=exec -p "KillMode=${mode:-$km}" "$W/fakerunner.sh" "$id" || return 1
      echo "     (sandbox directives not applicable to a user unit here: $(head -c 100 "$W/err"); kill logic only)"; }
    wait_for "$W/term/$id.json" || { bad "$1: the host did not start ($(cat "$W/ready.$id" 2>/dev/null))"; "${SC[@]}" stop "$u" 2>/dev/null; return 1; }
    HOSTPID=$(sed -n 's/.*"pid":\([0-9]*\).*/\1/p' "$W/term/$id.json"); pids+=("$HOSTPID")
    alive "$HOSTPID" || { bad "$1: host $HOSTPID is not running"; return 1; }
    if [ "$how" = sigkill ]; then
      rc=$("${SC[@]}" show -p MainPID --value "$u"); kill -KILL "$rc"
    else "${SC[@]}" stop "$u"; fi
    sleep 2
  }
  scenario kill "" sigkill && { alive "$HOSTPID" && ok "SIGKILL of the runner: the terminal host survives (KillMode=$km)" || bad "SIGKILL of the runner killed the host"; }
  scenario stop "" stop && { alive "$HOSTPID" && ok "systemctl stop: the terminal host survives (KillMode=$km)" || bad "stopping the unit killed the host"; }
  # Control: with the default KillMode the host must die, or this test proves nothing.
  scenario ctl control-group stop && { alive "$HOSTPID" && bad "control: KillMode=control-group left the host running (the test cannot fail)" || ok "control: KillMode=control-group kills the host (the test can fail)"; }
}

mac() {
  command -v launchctl >/dev/null || { echo "SKIP: no launchctl"; return 0; }
  grep -A1 '<key>AbandonProcessGroup</key>' "$PLIST" | grep -q '<true/>' && ok "the plist says AbandonProcessGroup" || { bad "the plist lacks AbandonProcessGroup"; return 1; }
  cat >"$W/fakerunner.sh" <<FAKE
#!/bin/bash
sleep 600 >/dev/null 2>&1 &
echo \$! >"\$1"
exec sleep 600
FAKE
  chmod +x "$W/fakerunner.sh"
  # agent <label> <AbandonProcessGroup true|false>
  agent() {
    local label=io.ainkrad.runner-survive-test-$$-$1 pf=$W/$1.pid
    cat >"$W/$1.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Label</key><string>$label</string>
<key>ProgramArguments</key><array><string>$W/fakerunner.sh</string><string>$pf</string></array>
<key>AbandonProcessGroup</key><$2/><key>RunAtLoad</key><true/></dict></plist>
PL
    launchctl bootstrap "gui/$(id -u)" "$W/$1.plist" || { bad "$1: launchctl bootstrap failed"; return 1; }
    wait_for "$pf" || { bad "$1: the agent did not start"; return 1; }
    HOSTPID=$(cat "$pf"); pids+=("$HOSTPID"); LABEL=$label
  }
  agent keep true || return 1
  # `launchctl bootout` stops the job (SIGTERM, then SIGKILL after ExitTimeOut): what an upgrade or uninstall does.
  launchctl bootout "gui/$(id -u)/$LABEL"; sleep 2
  alive "$HOSTPID" && ok "bootout of the agent: the host survives (AbandonProcessGroup=true)" || bad "bootout killed the host"
  agent drop false || return 1
  launchctl bootout "gui/$(id -u)/$LABEL"; sleep 2
  alive "$HOSTPID" && bad "control: AbandonProcessGroup=false left the host running (the test cannot fail)" || ok "control: AbandonProcessGroup=false kills the host (the test can fail)"
}

case $(uname -s) in Linux) linux "$@" ;; Darwin) mac ;; *) echo "SKIP: $(uname -s)" ;; esac
exit $fail
