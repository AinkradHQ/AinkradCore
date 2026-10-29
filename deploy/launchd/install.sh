#!/usr/bin/env bash
# Installs / removes the ainkrad-runner LaunchAgent for the current user (E1-12.3).
#   install.sh install --url wss://core/runner/v1/connect --key-file KEY [--binary PATH]
#                      [--dry-run] [-- extra runner flags: --tags a,b --git-name N --git-email E]
#   install.sh uninstall [--dry-run]
set -euo pipefail

LABEL=io.ainkrad.runner
HERE=$(cd "$(dirname "$0")" && pwd)
DEST_BIN="$HOME/.local/bin/ainkrad-runner"
AGENT="$HOME/Library/LaunchAgents/$LABEL.plist"
LOGS="$HOME/Library/Logs/AinkradRunner"
DOMAIN="gui/$(id -u)"

usage() { sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
cmd=${1:-}; [ -n "$cmd" ] && shift || usage
url= key= binary= dry=0 extra=()
while [ $# -gt 0 ]; do
  case $1 in
    --url) url=${2:?}; shift 2 ;;
    --key-file) key=${2:?}; shift 2 ;;
    --binary) binary=${2:?}; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --) shift; extra=("$@"); break ;;
    *) usage ;;
  esac
done
# Prints the command; runs it unless --dry-run.
run() { printf '+ %s\n' "$*"; [ "$dry" = 1 ] || "$@"; }

case $cmd in
install)
  [ -n "$url" ] && [ -n "$key" ] || usage
  binary=${binary:-$HERE/../../target/release/ainkrad-runner}
  [ -x "$binary" ] || { echo "no runner binary at $binary (cargo build --release -p ainkrad-runner, or --binary)" >&2; exit 1; }
  case $key in /*) ;; *) echo "--key-file must be absolute (launchd starts in /)" >&2; exit 1 ;; esac
  [ -r "$key" ] || { echo "cannot read key file $key" >&2; exit 1; }
  run mkdir -p "$(dirname "$DEST_BIN")" "$LOGS" "$(dirname "$AGENT")"
  run install -m 0755 "$binary" "$DEST_BIN"
  if [ "$dry" = 1 ]; then
    echo "+ render $HERE/$LABEL.plist -> $AGENT (extra args: ${extra[*]:-none})"
  else
    sed -e "s|__HOME__|$HOME|g" -e "s|__RUNNER_URL__|$url|g" -e "s|__KEY_FILE__|$key|g" \
      "$HERE/$LABEL.plist" > "$AGENT.tmp"
    for a in ${extra[@]+"${extra[@]}"}; do
      /usr/libexec/PlistBuddy -c "Add :ProgramArguments: string $a" "$AGENT.tmp"
    done
    chmod 0644 "$AGENT.tmp"
    plutil -lint "$AGENT.tmp" >/dev/null
    mv "$AGENT.tmp" "$AGENT"
  fi
  # bootout first so a re-run reloads the new plist; it fails when nothing is loaded.
  if [ "$dry" = 1 ]; then echo "+ launchctl bootout $DOMAIN/$LABEL (ignored if not loaded)"
  else launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true; fi
  run launchctl bootstrap "$DOMAIN" "$AGENT"
  ;;
uninstall)
  if [ "$dry" = 1 ]; then echo "+ launchctl bootout $DOMAIN/$LABEL (ignored if not loaded)"
  else launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true; fi
  run rm -f "$AGENT" "$DEST_BIN"
  echo "logs kept in $LOGS"
  ;;
*) usage ;;
esac
