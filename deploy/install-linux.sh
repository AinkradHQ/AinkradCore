#!/usr/bin/env bash
# Installs the ainkrad-runner systemd unit (E1-12.3; protocol v2 since E1-14.5; terminals and pairing E2-15).
# Idempotent; does not start unless --start or --pair. Works on the Core's own host and on a remote Linux host.
#   install-linux.sh [--binary PATH] [--ptyhost PATH] [--pty] [--ca PEM]
#                    [--pair https://<core> --code <CODE>] [--start] [--prefix DIR] [--dry-run]
# --pty      offer terminals (--enable-pty); needs ainkrad-ptyhost (--ptyhost, default: beside --binary). The shell
#            runs as the unprivileged ainkrad-runner user inside the unit's sandbox. Off unless asked.
# --ca       a PEM the runner trusts instead of the system roots (a test Core's CA only).
# --pair     pair as the service user now (waits for the approver; compare the SAS it prints), then start.
# exec.run stays OFF: add --enable-exec to RUNNER_ARGS in /etc/ainkrad-runner/runner.env yourself if wanted.
# --prefix installs under DIR (a throwaway root, for tests): no user creation, no systemctl.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
binary="$HERE/../target/release/ainkrad-runner" ptyhost='' pty=0 ca='' pair='' code='' prefix='' start=0 dry=0
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --binary) binary=${2:?}; shift 2 ;;
    --ptyhost) ptyhost=${2:?}; shift 2 ;;
    --pty) pty=1; shift ;;
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
[ -z "$ca" ] || args="${args:+$args }--ca $ca"
if [ -n "$prefix" ]; then run install -d "$prefix/etc/ainkrad-runner"; fi
envfile="$prefix/etc/ainkrad-runner/runner.env"
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
  fi
fi
