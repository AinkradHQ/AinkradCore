#!/usr/bin/env bash
# A runner for ONE user, with no root (E8): `get.sh --runner --user --invite <invite>` runs it after it has verified and installed the
# release into ~/.local/bin. It pairs the runner with the invite (read from the environment or stdin, never argv), then keeps it
# running as a systemd --user service with linger (so it survives logout and reboot); if systemd --user or linger is not
# available, as a user crontab `@reboot` line plus a process started now.
#
# What this is, and is not. The runner is the same unprivileged program as the system one, as the user who ran this. It has terminals
# (inside the runner's own bubblewrap sandbox when this host allows unprivileged user namespaces) and installs the AI tools into
# its own folder. It has NO AI sessions: those need the egress filter, which is a root firewall rule, so a user-level runner leaves them
# off. A host with passwordless sudo gets the system runner (runner-only.sh) instead, which has everything.
#   runner-user.sh --binary <dir> --invite -        (invite on stdin or the terminal; or AINKRAD_PAIR_INVITE)
set -euo pipefail
umask 077
bin='' invite=''
while [ $# -gt 0 ]; do
  case $1 in
    --binary) bin=${2:?}; shift 2 ;;
    --invite) if [ "${2:?}" = - ]; then if [ -t 0 ]; then IFS= read -rsp "invite: " invite; echo >&2; else IFS= read -r invite; fi; else invite=$2; fi; shift 2 ;;
    *) echo "usage: runner-user.sh --binary <dir> --invite -" >&2; exit 2 ;;
  esac
done
die() { printf 'runner: %s\n' "$*" >&2; exit 1; }
invite=${invite:-${AINKRAD_PAIR_INVITE:-}}
case $invite in */?*.?*) ;; *) die "--invite is the runner invite: <host>/<fingerprint>.<secret>" ;; esac
case $invite in *[!A-Za-z0-9_./:-]*) die "--invite has a character a runner invite never has" ;; esac
[ "$(id -u)" != 0 ] || die "this is the no-root install; as root use runner-only.sh"
[ "$(uname -s)" = Linux ] || die "a user runner installs on Linux"
[ -x "$bin/ainkrad-runner" ] || die "no ainkrad-runner in $bin"
host=${invite%%/*}
state=$HOME/.ainkrad-runner/core
mkdir -p "$state"; chmod 0700 "$HOME/.ainkrad-runner" "$state"
printf '%s\n' "$invite" | "$bin/ainkrad-runner" pair "https://$host" --invite - --state "$state" ||
  die "the runner did not pair. An invite works once and for 15 minutes: make a new one in the App"
unset invite AINKRAD_PAIR_INVITE
# Paths go into a unit file, a script and a crontab line: refuse anything that would need escaping there.
case $bin$state in *[!A-Za-z0-9_./-]*) die "the install folder has a character this installer will not put in a service file (letters, digits, . _ / - only)" ;; esac

via_systemd() {
  command -v systemctl >/dev/null || return 1
  [ -n "${XDG_RUNTIME_DIR:-}" ] || { [ -d "/run/user/$(id -u)" ] && export XDG_RUNTIME_DIR=/run/user/$(id -u); }
  systemctl --user show-environment >/dev/null 2>&1 || return 1
  local unit=$HOME/.config/systemd/user
  mkdir -p "$unit"
  cat >"$unit/ainkrad-runner.service" <<UNIT
[Unit]
Description=Ainkrad runner (dials out to the Core)
After=network-online.target
[Service]
Type=exec
ExecStart="$bin/ainkrad-runner" connect --state "$state" --enable-pty
Environment=PATH=$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin
Restart=on-failure
RestartSec=5
KillMode=process
[Install]
WantedBy=default.target
UNIT
  systemctl --user daemon-reload && systemctl --user enable --now ainkrad-runner.service || return 1
  # Linger keeps the service up after logout and starts it at boot. Not every host lets a user set it.
  loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || return 2
  return 0
}

# The cron fallback. The runner exits 75 to be restarted (a new policy, a new AI tool), which systemd's Restart= does for the unit; here
# a small loop does. The loop holds a lock, so the every-five-minutes cron line only starts a copy when none is running (a watchdog
# for a runner that was killed), and @reboot starts it after a restart.
via_cron() {
  command -v crontab >/dev/null || return 1
  local wrap=$HOME/.ainkrad-runner/run.sh log=$HOME/.ainkrad-runner/runner.log
  cat >"$wrap" <<WRAP
#!/bin/sh
if command -v flock >/dev/null 2>&1; then
  exec 9>"$HOME/.ainkrad-runner/run.lock"
  flock -n 9 || exit 0
else
  # No flock: a lock folder holding the wrapper's pid; a dead pid's lock is taken over.
  lock="$HOME/.ainkrad-runner/run.lock.d"
  if ! mkdir "\$lock" 2>/dev/null; then
    pid=\$(cat "\$lock/pid" 2>/dev/null)
    if [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null; then exit 0; fi
    rm -rf "\$lock"
    mkdir "\$lock" 2>/dev/null || exit 0
  fi
  echo \$\$ >"\$lock/pid"
  trap 'rm -rf "\$lock"' EXIT
fi
while :; do
  "$bin/ainkrad-runner" connect --state "$state" --enable-pty
  rc=\$?
  [ "\$rc" = 75 ] || exit "\$rc"
  sleep 1
done
WRAP
  chmod 0700 "$wrap"
  local keep
  keep=$(crontab -l 2>/dev/null | grep -v -e 'ainkrad-runner/run.sh' -e 'ainkrad-runner connect' || true)
  { [ -z "$keep" ] || printf '%s\n' "$keep"; printf '@reboot "%s" >>"%s" 2>&1\n' "$wrap" "$log"
    printf '*/5 * * * * "%s" >>"%s" 2>&1\n' "$wrap" "$log"; } | crontab - || return 1
  setsid nohup "$wrap" >>"$log" 2>&1 </dev/null &
  return 0
}

mode=''
if via_systemd; then mode='systemd --user, with linger'
else
  rc=$?
  if [ "$rc" = 2 ]; then mode='systemd --user (no linger: it stops when the last session of this user ends)'
  elif via_cron; then mode='a user crontab @reboot line'
  else die "neither systemd --user nor crontab is available for this user, so the runner cannot be kept running"
  fi
fi
printf 'The runner is paired with %s and running as this user (%s). Terminals are on; AI sessions need the system install.\n' "$host" "$mode"
