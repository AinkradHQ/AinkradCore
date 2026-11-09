#!/usr/bin/env bash
# Installs / pairs / removes the ainkrad-runner LaunchAgent for the current user (E1-12.3; protocol v2, terminals,
# pairing: E2-15). Run it from a source checkout or from the unpacked package (scripts/release/mac-package.sh):
#   install.sh install [--binary-dir DIR] [--pty] [--dry-run] [-- extra runner flags]
#   install.sh pair <https://core> --code <CODE> [--ca PEM] [--dry-run]   pair, then load the agent
#   install.sh status
#   install.sh uninstall [--purge] [--dry-run]    --purge also deletes the enrolment (device key) and terminals
# `install` puts ainkrad-runner and ainkrad-ptyhost in ~/.local/bin and writes the agent; it loads it only when
# the runner is already paired (otherwise it would exit and respawn every 30 s). --pty offers terminals: a shell as
# this user, with no sandbox. exec.run stays off unless you pass --enable-exec after `--`.
# SC2015: `test && shift || usage` is meant (shift cannot fail after the test).
# shellcheck disable=SC2015
set -euo pipefail

LABEL=io.ainkrad.runner
HERE=$(cd "$(dirname "$0")" && pwd)
BINDIR="$HOME/.local/bin"
STATE="$HOME/.ainkrad-runner"
AGENT="$HOME/Library/LaunchAgents/$LABEL.plist"
LOGS="$HOME/Library/Logs/AinkradRunner"
DOMAIN="gui/$(id -u)"

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
cmd=${1:-}; [ -n "$cmd" ] && shift || usage
srcdir='' pty=0 dry=0 purge=0 url='' code='' ca='' extra=()
while [ $# -gt 0 ]; do
  case $1 in
    --binary-dir) srcdir=${2:?}; shift 2 ;;
    --pty) pty=1; shift ;;
    --code) code=${2:?}; shift 2 ;;
    --ca) ca=${2:?}; shift 2 ;;
    --purge) purge=1; shift ;;
    --dry-run) dry=1; shift ;;
    --) shift; extra=("$@"); break ;;
    https://*) url=$1; shift ;;
    *) usage ;;
  esac
done
# Prints the command; runs it unless --dry-run.
run() { printf '+ %s\n' "$*"; [ "$dry" = 1 ] || "$@"; }
paired() { [ -e "$STATE/core/enrolment.json" ]; }
load() {
  # bootout first so a re-run reloads the new plist; it fails when nothing is loaded.
  if [ "$dry" = 1 ]; then echo "+ launchctl bootout $DOMAIN/$LABEL (ignored if not loaded)"
  else launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true; fi
  run launchctl bootstrap "$DOMAIN" "$AGENT"
}

case $cmd in
install)
  if [ -z "$srcdir" ]; then
    # The package puts the binaries in bin/ beside this script; a checkout has them in target/release.
    if [ -x "$HERE/bin/ainkrad-runner" ]; then srcdir=$HERE/bin; else srcdir=$HERE/../../target/release; fi
  fi
  [ -x "$srcdir/ainkrad-runner" ] || { echo "no runner binary in $srcdir (cargo build --release -p ainkrad-runner -p ainkrad-ptyhost, or --binary-dir)" >&2; exit 1; }
  [ -x "$srcdir/ainkrad-ptyhost" ] || [ "$pty" = 0 ] || { echo "--pty needs ainkrad-ptyhost in $srcdir" >&2; exit 1; }
  tmpl=$HERE/$LABEL.plist; [ -f "$tmpl" ] || tmpl=$HERE/../../deploy/launchd/$LABEL.plist
  run mkdir -p "$BINDIR" "$LOGS" "$(dirname "$AGENT")"
  # Replace, not overwrite: a running binary is never written into (the new file is a new inode).
  run install -m 0755 "$srcdir/ainkrad-runner" "$BINDIR/ainkrad-runner"
  [ ! -x "$srcdir/ainkrad-ptyhost" ] || run install -m 0755 "$srcdir/ainkrad-ptyhost" "$BINDIR/ainkrad-ptyhost"
  [ "$pty" = 0 ] || extra=(--enable-pty ${extra[@]+"${extra[@]}"})
  if [ "$dry" = 1 ]; then
    echo "+ render $tmpl -> $AGENT (extra args: ${extra[*]:-none})"
  else
    sed -e "s|__HOME__|$HOME|g" "$tmpl" > "$AGENT.tmp"
    for a in ${extra[@]+"${extra[@]}"}; do
      /usr/libexec/PlistBuddy -c "Add :ProgramArguments: string $a" "$AGENT.tmp"
    done
    chmod 0644 "$AGENT.tmp"
    plutil -lint "$AGENT.tmp" >/dev/null
    mv "$AGENT.tmp" "$AGENT"
  fi
  if paired || [ "$dry" = 1 ]; then load
  else echo "installed, not loaded: pair it first: $0 pair https://<core> --code <CODE>"; fi
  ;;
pair)
  [ -n "$url" ] && [ -n "$code" ] || usage
  [ -x "$BINDIR/ainkrad-runner" ] || { echo "run '$0 install' first" >&2; exit 1; }
  [ -f "$AGENT" ] || [ "$dry" = 1 ] || { echo "run '$0 install' first" >&2; exit 1; }
  pa=(pair "$url" --code "$code" --state "$STATE/core")
  [ -z "$ca" ] || pa+=(--ca "$ca")
  # Waits for the approver to confirm the SAS it prints (compare it with theirs); pins the Core's identity.
  run "$BINDIR/ainkrad-runner" "${pa[@]}"
  load
  ;;
status)
  [ -f "$AGENT" ] && echo "agent: $AGENT" || echo "agent: not installed"
  paired && echo "paired: yes ($STATE/core)" || echo "paired: no"
  launchctl print "$DOMAIN/$LABEL" 2>/dev/null | grep -E 'state =|pid =|last exit' || echo "launchd: not loaded"
  grep -q -- --enable-pty "$AGENT" 2>/dev/null && echo "pty: ON (shells as $USER)" || echo "pty: off"
  grep -q -- --enable-exec "$AGENT" 2>/dev/null && echo "exec: ON" || echo "exec: off"
  ;;
uninstall)
  if [ "$dry" = 1 ]; then echo "+ launchctl bootout $DOMAIN/$LABEL (ignored if not loaded)"
  else launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true; fi
  run rm -f "$AGENT" "$BINDIR/ainkrad-runner"
  # Terminal hosts survive the agent on purpose (AbandonProcessGroup); an uninstall ends them.
  run pkill -x ainkrad-ptyhost || true
  run rm -f "$BINDIR/ainkrad-ptyhost"
  [ "$purge" = 0 ] || run rm -rf "$STATE"
  echo "logs kept in $LOGS$([ "$purge" = 1 ] || echo "; the enrolment stays in $STATE (--purge deletes it)")"
  ;;
*) usage ;;
esac
