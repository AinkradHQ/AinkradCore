#!/usr/bin/env bash
# Installs the ainkrad-runner systemd unit (E1-12.3; protocol v2 since E1-14.5). Idempotent; does not start unless --start.
#   install-linux.sh [--binary PATH] [--prefix DIR] [--start] [--dry-run]
# --prefix installs under DIR (a throwaway root, for tests): no user creation, no systemctl.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
binary="$HERE/../target/release/ainkrad-runner" prefix= start=0 dry=0
while [ $# -gt 0 ]; do
  case $1 in
    --binary) binary=${2:?}; shift 2 ;;
    --prefix) prefix=${2:?}; shift 2 ;;
    --start) start=1; shift ;;
    --dry-run) dry=1; shift ;;
    *) sed -n '2,4p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
  esac
done
run() { printf '+ %s\n' "$*"; [ "$dry" = 1 ] || "$@"; }
[ "$dry" = 1 ] || [ "$(id -u)" = 0 ] || [ -n "$prefix" ] || { echo "run as root (or --prefix/--dry-run)" >&2; exit 1; }
[ "$dry" = 1 ] || [ -x "$binary" ] || { echo "no runner binary at $binary (cargo build --release -p ainkrad-runner, or --binary)" >&2; exit 1; }

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
run install -m 0644 "$HERE/systemd/ainkrad-runner.service" "$prefix/etc/systemd/system/ainkrad-runner.service"
if [ -z "$prefix" ]; then
  run systemctl daemon-reload
  if [ "$start" = 1 ]; then
    [ -e /var/lib/ainkrad-runner/core/enrolment.json ] || { echo "pair it first: sudo -u ainkrad-runner ainkrad-runner pair https://<core> --code <CODE> --state /var/lib/ainkrad-runner/core" >&2; exit 1; }
    run systemctl enable --now ainkrad-runner.service
  else
    echo "installed, not started. Pair it (see the unit's header), then: systemctl enable --now ainkrad-runner"
  fi
fi
