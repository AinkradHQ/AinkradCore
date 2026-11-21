#!/usr/bin/env bash
# Installs the Ainkrad Core and its systemd unit (E1-14.5). Idempotent; never touches /etc/ainkrad/backup.env.
#   install-core-linux.sh [--binary PATH] [--hostname NAME --acme-contact EMAIL] [--acme-directory URL]
#                         [--backup-recipient age1...] [--no-semantic-model | --semantic-model-from DIR] [--start] [--dry-run]
# Creates the `ainkrad` user if missing, installs the binary and unit, inits the home /var/lib/ainkrad/core as
# `ainkrad` when it does not exist (printing the backup signer's fingerprint once), and writes /etc/ainkrad/core.env
# when --hostname is given (otherwise an existing one is kept), and the pinned local model (about 490 MB; skip it with
# --no-semantic-model, which also keeps the updater from fetching it). Starts only with --start.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
binary="$HERE/../target/release/ainkrad-core-server" hostname='' contact='' directory='' recipient='' semantic=1 from='' start=0 dry=0
while [ $# -gt 0 ]; do
  case $1 in
    --binary) binary=${2:?}; shift 2 ;;
    --hostname) hostname=${2:?}; shift 2 ;;
    --acme-contact) contact=${2:?}; shift 2 ;;
    --acme-directory) directory=${2:?}; shift 2 ;;
    --backup-recipient) recipient=${2:?}; shift 2 ;;
    --semantic-model) semantic=1; shift ;;   # the default; kept so older callers still work
    --no-semantic-model) semantic=0; shift ;;
    --semantic-model-from) from=${2:?}; shift 2 ;;
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
# E15-2: the canonical workspace, shared with the built-in runner through the group ainkrad-ws (setgid, 2770, root-owned).
# The default `workspace.root` setting is this path.
getent group ainkrad-ws >/dev/null 2>&1 || run groupadd --system ainkrad-ws
run usermod -aG ainkrad-ws ainkrad
run install -d -m 2770 -o root -g ainkrad-ws /var/lib/ainkrad-ws
run chmod 2770 /var/lib/ainkrad-ws
run install -d -m 0750 -o root -g ainkrad /etc/ainkrad
run install -m 0755 "$binary" /usr/local/bin/ainkrad-core-server
run install -m 0644 "$HERE/systemd/ainkrad-core.service" /etc/systemd/system/ainkrad-core.service
# E12-3: the self-update (units, the updater, install.sh and the pinned key it verifies with). The timer is enabled below.
run install -d -m 0755 /usr/local/lib/ainkrad
for f in update.sh install.sh model.sh; do run install -m 0755 "$HERE/../scripts/release/$f" "/usr/local/lib/ainkrad/$f"; done
run install -m 0644 "$HERE/../scripts/release/ainkrad-release.pub" /usr/local/lib/ainkrad/ainkrad-release.pub
run install -m 0644 "$HERE/systemd/ainkrad-update@.service" /etc/systemd/system/ainkrad-update@.service
run install -m 0644 "$HERE/systemd/ainkrad-update.timer" /etc/systemd/system/ainkrad-update.timer
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
# The Brain's and Lore's local model (scripts/release/model.sh: pinned revision and SHA-256, run as the Core user inside
# its home). /etc/ainkrad/no-model is the opt-out the updater honours too; without it every Core update re-checks the model.
if [ "$semantic" = 1 ]; then
  run rm -f /etc/ainkrad/no-model
  # Not fatal: the Core runs without it, and the hourly updater fetches it again. FROM must be readable by `ainkrad`.
  run runuser -u ainkrad -- /usr/local/lib/ainkrad/model.sh "$home/models/e5-small" ${from:+"$from"} ||
    echo "the local model did not install (the next update run retries it): Brain sorts by rules, Lore searches text" >&2
else
  run touch /etc/ainkrad/no-model
fi
run systemctl daemon-reload
if [ "$start" = 1 ]; then
  [ "$dry" = 1 ] || [ -r /etc/ainkrad/core.env ] || { echo "no /etc/ainkrad/core.env: pass --hostname" >&2; exit 1; }
  run systemctl enable --now ainkrad-core.service
  run systemctl enable --now ainkrad-update.timer
else
  echo "installed, not started: systemctl enable --now ainkrad-core"
fi
