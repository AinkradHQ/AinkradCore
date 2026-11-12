#!/usr/bin/env bash
# Installs only a runner on this Linux host and pairs it with a runner invite (N17): `get.sh --runner --invite <invite>` runs it
# after it has verified and installed the release. The same runner as the Core's built-in one: unprivileged ainkrad-runner user in
# the unit's sandbox, terminals and agents on, the egress filter on, Node and Claude Code at the pinned versions.
#   sudo scripts/install/runner-only.sh --binary <dir> --invite - [--dry-run]     (invite on stdin or the terminal; or AINKRAD_PAIR_INVITE)
# <dir> holds ainkrad-runner and ainkrad-ptyhost. The invite is single use and lasts 15 minutes; it is its own approval, so there is no
# check code. It reaches `ainkrad-runner pair` on stdin (never argv), and is never written to a file. Nothing of a Core is installed.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
bin='' invite='' dry=0
# A secret flag's value: `-` reads it from the terminal (no echo) or stdin; a literal still works, with a warning (argv shows in `ps`).
secret_arg() {
  local v
  if [ "$2" = - ]; then
    if [ -t 0 ]; then IFS= read -rsp "${1#--}: " v; echo >&2; else IFS= read -r v; fi
  else echo "WARNING: $1 <value> puts the secret in argv (visible in ps and shell history); use '$1 -' or AINKRAD_PAIR_INVITE / AINKRAD_PAIR_CODE in the environment" >&2; v=$2; fi
  printf '%s' "$v"
}
while [ $# -gt 0 ]; do
  case $1 in
    --binary) bin=${2:?}; shift 2 ;;
    --invite) invite=$(secret_arg --invite "${2:?}"); shift 2 ;;
    --dry-run) dry=1; shift ;;
    *) echo "usage: runner-only.sh --binary <dir> --invite - [--dry-run]" >&2; exit 2 ;;
  esac
done
die() { printf 'runner: %s\n' "$*" >&2; exit 1; }
say() { printf '  %s\n' "$*"; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
# shellcheck source=scripts/install/agent-tools.sh
. "$ROOT/scripts/install/agent-tools.sh"

invite=${invite:-${AINKRAD_PAIR_INVITE:-}}
case $invite in
  */?*.?*) ;;
  *) die "--invite is the runner invite from the App: <host>/<fingerprint>.<secret>" ;;
esac
case $invite in *[!A-Za-z0-9_./:-]*) die "--invite has a character a runner invite never has" ;; esac
host=${invite%%/*}
[ -n "$host" ] || die "the invite names no Core"
[ -n "$bin" ] || die "--binary <dir> is required"
if [ "$dry" = 0 ]; then
  [ "$(uname -s)" = Linux ] && [ -d /run/systemd/system ] || die "a runner installs on Linux with systemd here (on a Mac, use the App)"
  [ "$(id -u)" = 0 ] || die "run as root"
  [ -x "$bin/ainkrad-runner" ] && [ -x "$bin/ainkrad-ptyhost" ] || die "no ainkrad-runner and ainkrad-ptyhost in $bin"
fi
a=(--binary "$bin/ainkrad-runner" --ptyhost "$bin/ainkrad-ptyhost" --pty --agents)
if [ "$dry" = 1 ]; then
  say "install Node $NODE_VERSION and claude-code@$CLAUDE_VERSION (DISABLE_AUTOUPDATER=1 in /etc/claude-code/managed-settings.json)"
  AINKRAD_PAIR_INVITE=$invite bash "$ROOT/deploy/install-linux.sh" "${a[@]}" --dry-run
  exit 0
fi
printf 'Installing Node %s and Claude Code %s for agents...\n' "$NODE_VERSION" "$CLAUDE_VERSION"
if ! install_agent_tools; then
  printf 'runner: WARNING: the agent tools did not install (see above); the runner is set up with terminals only\n' >&2
  a=(--binary "$bin/ainkrad-runner" --ptyhost "$bin/ainkrad-ptyhost" --pty)
fi
printf 'Installing the runner service and pairing it with %s...\n' "$host"
AINKRAD_PAIR_INVITE=$invite bash "$ROOT/deploy/install-linux.sh" "${a[@]}" ||
  die "the runner did not install or pair. An invite works once and for 15 minutes: make a new one in the App and run the command again"
systemctl is-active --quiet ainkrad-runner.service || die "the runner is installed but not running: journalctl -u ainkrad-runner -n 30"
printf '\nThe runner is paired with %s and running. It shows in the App under Runners.\n' "$host"
