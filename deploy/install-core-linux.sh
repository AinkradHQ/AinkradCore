#!/usr/bin/env bash
# Installs the Ainkrad Core and its systemd unit (E1-14.5). Idempotent; never touches /etc/ainkrad/backup.env.
#   install-core-linux.sh [--binary PATH] [--hostname NAME --acme-contact EMAIL] [--acme-directory URL]
#                         [--backup-recipient age1...] [--start] [--dry-run]
# Creates the `ainkrad` user if missing, installs the binary and unit, inits the home /var/lib/ainkrad/core as
# `ainkrad` when it does not exist (printing the backup signer's fingerprint once), and writes /etc/ainkrad/core.env
# when --hostname is given (otherwise an existing one is kept). Starts only with --start.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
binary="$HERE/../target/release/ainkrad-core-server" hostname='' contact='' directory='' recipient='' start=0 dry=0
while [ $# -gt 0 ]; do
  case $1 in
    --binary) binary=${2:?}; shift 2 ;;
    --hostname) hostname=${2:?}; shift 2 ;;
    --acme-contact) contact=${2:?}; shift 2 ;;
    --acme-directory) directory=${2:?}; shift 2 ;;
    --backup-recipient) recipient=${2:?}; shift 2 ;;
    --start) start=1; shift ;;
    --dry-run) dry=1; shift ;;
    *) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
  esac
done
run() { printf '+ %s\n' "$*"; [ "$dry" = 1 ] || "$@"; }
[ "$dry" = 1 ] || [ "$(id -u)" = 0 ] || { echo "run as root (or --dry-run)" >&2; exit 1; }
[ "$dry" = 1 ] || [ -x "$binary" ] || { echo "no Core binary at $binary (--binary)" >&2; exit 1; }
[ -z "$hostname" ] || [ -n "$contact" ] || { echo "--hostname needs --acme-contact" >&2; exit 2; }
case $recipient in ''|age1*) ;; *) echo "--backup-recipient is an age1... public key" >&2; exit 2 ;; esac

home=/var/lib/ainkrad/core
id ainkrad >/dev/null 2>&1 ||
  run useradd --system --user-group --home-dir /var/lib/ainkrad --no-create-home --shell /usr/sbin/nologin ainkrad
run install -d -m 0750 -o ainkrad -g ainkrad /var/lib/ainkrad
run install -d -m 0750 -o root -g ainkrad /etc/ainkrad
run install -m 0755 "$binary" /usr/local/bin/ainkrad-core-server
run install -m 0644 "$HERE/systemd/ainkrad-core.service" /etc/systemd/system/ainkrad-core.service
if [ -n "$hostname" ]; then
  env="AINKRAD_LISTEN=public
AINKRAD_HOSTNAME=$hostname
AINKRAD_ACME_CONTACT=$contact
AINKRAD_LOG_FORMAT=json
AINKRAD_SERVE_ARGS=${directory:+--acme-directory $directory}
${recipient:+AINKRAD_BACKUP_RECIPIENT=$recipient}"
  printf '+ write /etc/ainkrad/core.env:\n%s\n' "$env"
  if [ "$dry" = 0 ]; then
    tmp=$(mktemp /etc/ainkrad/.core.env.XXXXXX)
    printf '%s\n' "$env" >"$tmp" && chown root:ainkrad "$tmp" && chmod 0640 "$tmp" && mv "$tmp" /etc/ainkrad/core.env
  fi
fi
if [ -e "$home/config.toml" ]; then
  echo "home $home exists: kept"
else
  run runuser -u ainkrad -- /usr/local/bin/ainkrad-core-server init "$home"
fi
run systemctl daemon-reload
if [ "$start" = 1 ]; then
  [ "$dry" = 1 ] || [ -r /etc/ainkrad/core.env ] || { echo "no /etc/ainkrad/core.env: pass --hostname" >&2; exit 1; }
  run systemctl enable --now ainkrad-core.service
else
  echo "installed, not started: systemctl enable --now ainkrad-core"
fi
