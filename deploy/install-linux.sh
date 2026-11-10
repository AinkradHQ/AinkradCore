#!/usr/bin/env bash
# Installs the ainkrad-runner systemd unit (E1-12.3; protocol v2 since E1-14.5; terminals and pairing E2-15).
# Idempotent; does not start unless --start or --pair. Works on the Core's own host and on a remote Linux host.
#   install-linux.sh [--binary PATH] [--ptyhost PATH] [--pty] [--ca PEM]
#                    [--exec] [--root] [--pair https://<core> --code <CODE>] [--start] [--prefix DIR] [--dry-run]
# --pty      offer terminals (--enable-pty); needs ainkrad-ptyhost (--ptyhost, default: beside --binary). The shell
#            runs as the unprivileged ainkrad-runner user inside the unit's sandbox. Off unless asked.
# --ca       a PEM the runner trusts instead of the system roots (a test Core's CA only).
# --pair     pair as the service user now (waits for the approver; compare the SAS it prints), then start.
# --exec     turn exec.run on (--enable-exec). WARNING: opt-in only; a compromised Core can then run any program as
#            the runner's user (as root with --root). The guided installer never passes it.
# --root     WARNING: opt-in only, never the default. Runs the unit as root with no unit sandbox (drop-in
#            ainkrad-runner.service.d/authority.conf). A compromised Core is then root on this host, root terminals
#            can overwrite /usr/local/bin and /etc/systemd/system, and agent sessions are refused at uid 0. The
#            guided installer never passes it. A re-run without it removes that one file.
# --prefix installs under DIR (a throwaway root, for tests): no user creation, no systemctl.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
binary="$HERE/../target/release/ainkrad-runner" ptyhost='' pty=0 ca='' pair='' code='' prefix='' start=0 dry=0 exec_on=0 root=0
usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --binary) binary=${2:?}; shift 2 ;;
    --ptyhost) ptyhost=${2:?}; shift 2 ;;
    --pty) pty=1; shift ;;
    --exec) exec_on=1; shift ;;
    --root) root=1; shift ;;
    --ca) ca=${2:?}; shift 2 ;;
    --pair) pair=${2:?}; shift 2 ;;
    --code) code=${2:?}; shift 2 ;;
    --prefix) prefix=${2:?}; shift 2 ;;
    --start) start=1; shift ;;
    --dry-run) dry=1; shift ;;
    *) usage ;;
  esac
done
run() { printf '+ %s\n' "$*"; [ "$dry" = 1 ] || "$@"; }
[ "$dry" = 1 ] || [ "$(id -u)" = 0 ] || [ -n "$prefix" ] || { echo "run as root (or --prefix/--dry-run)" >&2; exit 1; }
[ "$dry" = 1 ] || [ -x "$binary" ] || { echo "no runner binary at $binary (cargo build --release -p ainkrad-runner, or --binary)" >&2; exit 1; }
[ -z "$pair" ] || [ -n "$code" ] || { echo "--pair needs --code" >&2; exit 2; }
case $pair in '' | https://*) ;; *) echo "--pair takes an https:// URL" >&2; exit 2 ;; esac
case $code$ca in *[[:space:]]*) echo "--code/--ca must not contain spaces (systemd splits RUNNER_ARGS on them)" >&2; exit 2 ;; esac
if [ "$pty" = 1 ]; then
  ptyhost=${ptyhost:-$(dirname "$binary")/ainkrad-ptyhost}
  [ "$dry" = 1 ] || [ -x "$ptyhost" ] || { echo "--pty needs ainkrad-ptyhost at $ptyhost (cargo build --release -p ainkrad-ptyhost, or --ptyhost)" >&2; exit 1; }
fi

if [ -z "$prefix" ]; then
  # Home is the runner's HOME; its work root is the sibling ainkrad-runner-work (see the unit).
  id ainkrad-runner >/dev/null 2>&1 ||
    run useradd --system --user-group --home-dir /var/lib/ainkrad-runner --no-create-home \
      --shell /usr/sbin/nologin ainkrad-runner
  run install -d -m 0750 -o root -g ainkrad-runner /etc/ainkrad-runner
  # `pair` runs as the user before the unit's StateDirectory exists.
  run install -d -m 0700 -o ainkrad-runner -g ainkrad-runner /var/lib/ainkrad-runner
fi
run install -d "$prefix/usr/local/bin" "$prefix/etc/systemd/system"
run install -m 0755 "$binary" "$prefix/usr/local/bin/ainkrad-runner"
# Beside the runner, where it looks first. Installed whenever it is at hand, so enabling pty later needs no re-install.
[ -n "$ptyhost" ] || [ ! -x "$(dirname "$binary")/ainkrad-ptyhost" ] || ptyhost=$(dirname "$binary")/ainkrad-ptyhost
[ -z "$ptyhost" ] || run install -m 0755 "$ptyhost" "$prefix/usr/local/bin/ainkrad-ptyhost"
run install -m 0644 "$HERE/systemd/ainkrad-runner.service" "$prefix/etc/systemd/system/ainkrad-runner.service"
# runner.env: RUNNER_ARGS from these flags, replaced on every run (so a re-run without --pty turns terminals off).
args=''
[ "$pty" = 1 ] && args="--enable-pty"
[ "$exec_on" = 1 ] && args="${args:+$args }--enable-exec"
[ -z "$ca" ] || args="${args:+$args }--ca $ca"
if [ -n "$prefix" ]; then run install -d "$prefix/etc/ainkrad-runner"; fi
dropin="$prefix/etc/systemd/system/ainkrad-runner.service.d"
envfile="$prefix/etc/ainkrad-runner/runner.env"
# What is installed now, to know after the rewrite whether a running runner must be restarted to pick the change up.
old_args=$(sed -n 's/^RUNNER_ARGS=//p' "$envfile" 2>/dev/null | tail -n1 || true)
old_root=0; [ ! -e "$dropin/authority.conf" ] || old_root=1
if [ "$root" = 1 ]; then
  run install -d "$dropin"
  printf '+ write %s/authority.conf\n' "$dropin"
  if [ "$dry" = 0 ]; then cat >"$dropin/authority.conf" <<'CONF'
# Written by deploy/install-linux.sh --root: the runner is the app's hands on this machine, so it runs as root with
# every capability and no filesystem sandbox. Agent sessions are sandboxed by the runner itself (bubblewrap).
[Service]
User=root
Group=root
NoNewPrivileges=no
CapabilityBoundingSet=
CapabilityBoundingSet=~
AmbientCapabilities=
ProtectSystem=no
ProtectHome=no
PrivateDevices=no
DevicePolicy=auto
ProtectKernelTunables=no
ProtectKernelModules=no
ProtectKernelLogs=no
ProtectControlGroups=no
ProtectClock=no
ProtectHostname=no
RestrictNamespaces=no
SystemCallFilter=
CONF
  fi
else run rm -f "$dropin/authority.conf"; fi
printf '+ write %s: RUNNER_ARGS=%s\n' "$envfile" "$args"
if [ "$dry" = 0 ]; then
  printf '# Written by deploy/install-linux.sh. exec.run is off unless --enable-exec is added here.\nRUNNER_ARGS=%s\n' "$args" >"$envfile"
  chmod 0640 "$envfile"; [ -n "$prefix" ] || chown root:ainkrad-runner "$envfile"
fi
if [ -z "$prefix" ]; then
  run systemctl daemon-reload
  if [ -n "$pair" ]; then
    # Blocks until the approver confirms the SAS (or the code expires); the Core's identity is pinned here.
    pa=(pair "$pair" --code "$code" --state /var/lib/ainkrad-runner/core)
    [ -z "$ca" ] || pa+=(--ca "$ca")
    run runuser -u ainkrad-runner -- /usr/local/bin/ainkrad-runner "${pa[@]}"
    start=1
  fi
  if [ "$start" = 1 ]; then
    [ "$dry" = 1 ] || [ -e /var/lib/ainkrad-runner/core/enrolment.json ] || { echo "pair it first: sudo -u ainkrad-runner ainkrad-runner pair https://<core> --code <CODE> --state /var/lib/ainkrad-runner/core" >&2; exit 1; }
    run systemctl enable ainkrad-runner.service
    # restart: a running runner picks up new flags; its terminal hosts keep running (KillMode=process).
    run systemctl restart ainkrad-runner.service
  else
    echo "installed, not started. Pair it (see the unit's header), then: systemctl enable --now ainkrad-runner"
    # A runner that is already running keeps its old user and flags until restarted: demote (or change) it now.
    if [ "$old_root" != "$root" ] || [ "$old_args" != "$args" ]; then run systemctl try-restart ainkrad-runner.service; fi
  fi
fi
