#!/bin/sh
# shellcheck disable=SC2034,SC1003,SC2016 # the UI variables are read by the functions below; the clean-up string is eval'd later
# Ainkrad Core: one command to set up a Core on a Linux machine (Debian or Ubuntu, x86_64 or arm64).
#
#   sudo sh -c "$(curl -fsSL https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh)"
#
# NOT `curl ... | sudo sh`: piped into sudo the script cannot read your answers (sudo does not hand the terminal to a command
# whose stdin is a pipe, so the first question stops it with SIGTTIN). It refuses to run that way and prints the command above.
#
# Optional, to skip the two questions (the Mac app can put them in the command):
#   sudo AINKRAD_HOSTNAME=core.example.com AINKRAD_ACME_EMAIL=you@example.com sh -c "$(curl -fsSL URL)"
#
# What it does, in order: checks the machine, installs what the Core needs (curl, minisign, bubblewrap, qrencode) with apt, downloads the signed release, VERIFIES the minisign signature over SHA256SUMS against the
# release key pinned below (any mismatch stops everything; nothing of the release is installed), checks every file
# against the signed sums, installs the Core and runs the guided installer.
# Host hardening (SSH config, firewall, unattended updates, no swap) is OPT-IN and experimental: the default install does not
# touch SSH or the firewall and installs no firewall tooling. `sudo sh -c "$(curl -fsSL URL)" sh --harden` (or AINKRAD_HARDEN=yes) turns it on.
# The one-time connect link and the backup key are shown on the terminal only (/dev/tty), never on stdout, so a
# captured stdout (cloud-init, CI, `> log`, tee) does not keep them. With no terminal they are not created at all
# and the command to run later is printed. They are not in a log or a file of ours; a terminal's own scrollback or
# recording still keeps what it displays (tmux, `script`, `ssh -t host ... > log`).
#
# Verify first, then run (get.sh is itself in the signed SHA256SUMS; the pinned key below is the same as
# scripts/release/ainkrad-release.pub, key id FB3618BCFCA5393E):
#   B=https://github.com/AinkradHQ/AinkradCore/releases/latest/download
#   curl -fsSLO $B/get.sh -O $B/SHA256SUMS -O $B/SHA256SUMS.minisig
#   minisign -Vm SHA256SUMS -P RWQ+OaX8vBg2+zmrma/A8QI/+cL5wvvHoanVJv0v4xHp04w6zIgS/pDA
#   grep ' get.sh$' SHA256SUMS | sha256sum -c -
#   sudo sh get.sh
#
# AINKRAD_RELEASE_URL=<https url or directory> reads another release (the pinned key still applies).
# AINKRAD_GET_VERIFY_ONLY=1 stops after the signature and checksum checks, installing nothing (used by the tests).
# Version floor: a signed release older than MIN_VERSION (the version this get.sh was built from) is refused, so a newer
# get.sh cannot be pointed at an older signed release. That does NOT stop a replay of an OLD get.sh together with its own
# old signed sums: the floor lives in the file being run. The command the Mac app shows therefore carries
#   sudo AINKRAD_MIN_VERSION=<current version> sh -c "$(curl -fsSL URL)"
# and the HIGHER of the two floors applies. The verify-first path below has the same limit: check the version yourself.
#
# The whole script is one function called on the LAST line, so a download cut short runs nothing.

# --- ui-core begin ---
ui_defaults() { # every variable the UI uses; called by ui_init (the only top-level code in this block is function definitions)
  UI_N=0 UI_TITLE='' UI_TEXTFN='' UI_DL='' UI_FANCY=0 UI_UTF=0 UI_W=80 UI_T0='' UI_CLEAN='' UI_LOG='' UI_LOGDIR='' UI_JOBS='' UI_JOB='' UI_RUNS=0
  UI_HINT=0 UI_CURSOR=1 UI_STATE='Nothing has been changed on this machine yet.' UI_RERUN=${AINKRAD_RERUN:-'run the same command again'}
  UI_DEMO=0 # set by --demo AFTER ui_init, never read from the environment
  # numbers from the environment are plain digits or they are ignored (they reach shell arithmetic)
  case ${AINKRAD_STEP_BASE:-0} in '' | *[!0-9]*) UI_BASE=0 ;; *) UI_BASE=${AINKRAD_STEP_BASE:-0} ;; esac
  case ${AINKRAD_STEP_TOTAL:-8} in '' | *[!0-9]* | 0) UI_TOTAL=8 ;; *) UI_TOTAL=${AINKRAD_STEP_TOTAL:-8} ;; esac
  case ${AINKRAD_T0:-} in '' | *[!0-9]*) UI_T0='' ;; *) UI_T0=${AINKRAD_T0:-} ;; esac
  [ "$UI_TOTAL" -le 99 ] && [ "$UI_BASE" -le 99 ] || { UI_BASE=0 UI_TOTAL=8; }
  B='' D='' R='' GR='' RD='' YL='' CY='' OKG='+' XG='x' FULL='#' EMPTY='-' DOT='-' SPIN='| / - \'
}
ui_now() { date +%s; }
ui_ts() { date +%H:%M:%S; }
ui_sleep() { sleep "$1"; }
ui_clean() { # stdin -> stdout, one stream: C0 controls, DEL, C1 controls dropped; for EVERY external string
  if [ "$UI_UTF" = 1 ]; then # C1 controls are the two-byte sequences C2 80..9F; a bare byte 9B is a continuation byte of real text
    LC_ALL=C sed "s/$(printf '\302')[$(printf '\200')-$(printf '\237')]//g" | LC_ALL=C tr -d '\000-\037\177'
  else
    LC_ALL=C sed "s/$(printf '\302')[$(printf '\200')-$(printf '\237')]//g" | LC_ALL=C tr -d '\000-\037\177\233'
  fi
}
ui_clean_lines() { # the same for several lines (newline and tab kept)
  if [ "$UI_UTF" = 1 ]; then
    LC_ALL=C sed "s/$(printf '\302')[$(printf '\200')-$(printf '\237')]//g" | LC_ALL=C tr -d '\000-\010\013-\037\177'
  else
    LC_ALL=C sed "s/$(printf '\302')[$(printf '\200')-$(printf '\237')]//g" | LC_ALL=C tr -d '\000-\010\013-\037\177\233'
  fi
}
ui_init() {
  ui_defaults
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then UI_FANCY=1; fi
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) UI_UTF=1 ;; esac
  UI_W=${COLUMNS:-0}
  case $UI_W in '' | *[!0-9]*) UI_W=0 ;; esac
  [ "$UI_W" -gt 0 ] || UI_W=$(tput cols 2>/dev/null || echo 80)
  case $UI_W in '' | *[!0-9]*) UI_W=80 ;; esac
  [ "$UI_W" -ge 40 ] || UI_W=40
  [ "$UI_W" -le 300 ] || UI_W=300
  [ -n "$UI_T0" ] || UI_T0=$(ui_now)
  if [ "$UI_FANCY" = 1 ]; then
    B=$(printf '\033[1m') D=$(printf '\033[2m') R=$(printf '\033[0m') GR=$(printf '\033[32m')
    RD=$(printf '\033[31m') YL=$(printf '\033[33m') CY=$(printf '\033[36m')
    if [ "$UI_UTF" = 1 ]; then OKG='✓' XG='✗' FULL='█' EMPTY='░' DOT='·' SPIN='⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏'; fi
  fi
}
ui_el_s() { echo $(($(ui_now) - UI_T0)); }
ui_el() { _e=$(ui_el_s); printf '%02d:%02d' $((_e / 60)) $((_e % 60)); }
ui_fit() { # ui_fit TEXT [MAX]: one line, controls dropped, cut to MAX (default: the width minus room for the glyph)
  _max=${2:-$((UI_W - 8))}
  printf '%s' "$1" | ui_clean | cut -c1-"$_max"
}
ui_frame() { # ui_frame I: the I-th spinner glyph
  _n=0; for _g in $SPIN; do _n=$((_n + 1)); done
  _k=$(($1 % _n)); _c=0
  for _g in $SPIN; do if [ "$_c" = "$_k" ]; then printf '%s' "$_g"; return 0; fi; _c=$((_c + 1)); done
}
ui_cursor() { # ui_cursor hide|show: only on a real terminal
  [ "$UI_FANCY" = 1 ] || return 0
  if [ "$1" = hide ]; then printf '\033[?25l'; UI_CURSOR=0; else printf '\033[?25h'; UI_CURSOR=1; fi
}
ui_clean_add() { UI_CLEAN="$UI_CLEAN
$1"; }
ui_kill_tree() { # ui_kill_tree PID SIGNAL: the process and every descendant, deepest first (a job started with & ignores SIGINT)
  for _k in $(ps -A -o pid= -o ppid= 2>/dev/null | awk -v p="$1" '$2 == p { print $1 }'); do ui_kill_tree "$_k" "$2"; done
  kill -s "$2" "$1" 2>/dev/null || true
}
ui_kill_jobs() { # stop the background job(s) of the current wait and wait for them: TERM, 3 s grace, KILL
  [ -n "$UI_JOBS" ] || return 0
  for _j in $UI_JOBS; do ui_kill_tree "$_j" TERM; done
  _g=0
  while [ "$_g" -lt 30 ]; do
    _alive=0; for _j in $UI_JOBS; do if kill -0 "$_j" 2>/dev/null; then _alive=1; fi; done
    [ "$_alive" = 1 ] || break
    sleep 0.1; _g=$((_g + 1))
  done
  for _j in $UI_JOBS; do ui_kill_tree "$_j" KILL; wait "$_j" 2>/dev/null || true; done
  UI_JOBS=''
}
ui_exit() { # the EXIT trap: any job is gone, the cursor is back, then the registered clean-ups
  _rc=$?
  ui_kill_jobs
  ui_cursor show
  if [ "$_rc" = 0 ] && [ -n "$UI_LOGDIR" ]; then rm -rf "$UI_LOGDIR"; fi # the log stays after a failure
  _list=$UI_CLEAN; UI_CLEAN=''
  _old=$IFS; IFS='
'
  for _c in $_list; do [ -z "$_c" ] || eval "$_c" || true; done
  IFS=$_old
  return "$_rc"
}
ui_int() { # INT/TERM: stop the job and its children FIRST, then say honestly what state things are in
  _had=$UI_JOB
  ui_kill_jobs
  ui_cursor show
  [ "$UI_FANCY" != 1 ] || printf '\r\033[K'
  printf '\n %s! Interrupted at step %s of %s (%s).%s\n' "$YL" "$UI_N" "$UI_TOTAL" "$UI_TITLE" "$R"
  [ -z "$_had" ] || printf '   Stopped while: %s. That step may be partly done.\n' "$(printf '%s' "$_had" | ui_clean)"
  printf '   State: %s\n   To continue: %s\n' "$(printf '%s' "$UI_STATE" | ui_clean)" "$UI_RERUN"
  exit "$1"
}
ui_traps() { trap ui_exit EXIT; trap 'ui_int 130' INT; trap 'ui_int 143' TERM; }
ui_rname() { # the roadmap
  case $1 in
    1) echo "Check this machine" ;; 2) echo "Install prerequisites" ;; 3) echo "Download and verify" ;; 4) echo "Install the programs" ;;
    5) echo "Your 2 answers" ;; 6) echo "Set up the Core" ;; 7) echo "Start and get the certificate" ;; 8) echo "Your connect link" ;;
  esac
}
ui_short() { # short names for the "Done so far" line
  case $1 in
    1) echo "Machine" ;; 2) echo "Prerequisites" ;; 3) echo "Download" ;; 4) echo "Programs" ;; 5) echo "Answers" ;; 6) echo "Set up" ;; 7) echo "Certificate" ;;
  esac
}
ui_roadmap() {
  [ "$UI_DEMO" != 1 ] || printf '\n %s*** DEMO: nothing real happens on this machine ***%s\n' "$YL" "$R"
  printf '\n %sAinkrad Core setup%s\n %sHere is what will happen (about 5 minutes):%s\n' "$B" "$R" "$D" "$R"
  _i=$((UI_BASE + 1))
  while [ "$_i" -le $((UI_BASE + UI_TOTAL)) ]; do printf '   %s  %s\n' "$((_i - UI_BASE))" "$(ui_rname "$_i")"; _i=$((_i + 1)); done
}
ui_bar() { # ui_bar N TOTAL: [#####-----]
  _w=10; _f=$(($1 * _w / $2)); _s=''; _j=0
  while [ "$_j" -lt "$_w" ]; do if [ "$_j" -lt "$_f" ]; then _s="$_s$FULL"; else _s="$_s$EMPTY"; fi; _j=$((_j + 1)); done
  printf '[%s]' "$_s"
}
ui_step() { # ui_step N "Title" "why": the persistent header (N is the roadmap number; UI_BASE is subtracted for display)
  UI_N=$1 UI_TITLE=$2; _n=$(($1 - UI_BASE)); _dm=''; [ "$UI_DEMO" != 1 ] || _dm='DEMO · '
  if [ "$UI_FANCY" = 1 ]; then
    printf '\n %s%s%s %sstep %s of %s %s·%s %s%s%s %s·%s %s elapsed\n' "$CY" "$(ui_bar "$_n" "$UI_TOTAL")" "$R" "$_dm" "$_n" "$UI_TOTAL" "$D" "$R" "$B" "$2" "$R" "$D" "$R" "$(ui_el)"
    [ -z "${3:-}" ] || printf '   %s%s%s\n' "$D" "$3" "$R"
    if [ "$_n" -gt 1 ]; then
      _d=''; _i=$((UI_BASE + 1)); while [ "$_i" -lt "$1" ]; do _d="$_d $OKG $(ui_short "$_i") "; _i=$((_i + 1)); done
      if [ "${#_d}" -gt $((UI_W - 20)) ]; then _d=" $OKG $((_n - 1)) steps done, latest: $(ui_rname "$(($1 - 1))")"; fi
      printf '   %sDone so far:%s%s%s\n' "$D" "$GR" "$_d" "$R"
    fi
  else
    printf '[%s] %sstep %s/%s: %s%s\n' "$(ui_ts)" "${_dm:+DEMO }" "$_n" "$UI_TOTAL" "$2" "${3:+ - $3}"
  fi
}
ui_ok() { # a finished thing, in plain words
  _x=$(printf '%s' "$1" | ui_clean)
  if [ "$UI_FANCY" = 1 ]; then printf '\r\033[K   %s%s%s %s\n' "$GR" "$OKG" "$R" "$_x"; else printf '[%s]   ok: %s\n' "$(ui_ts)" "$_x"; fi
}
ui_note() { _x=$(printf '%s' "$1" | ui_clean); if [ "$UI_FANCY" = 1 ]; then printf '   %s%s%s\n' "$D" "$_x" "$R"; else printf '[%s]   %s\n' "$(ui_ts)" "$_x"; fi; }
ui_warn() { _x=$(printf '%s' "$1" | ui_clean); if [ "$UI_FANCY" = 1 ]; then printf '   %s!%s %s\n' "$YL" "$R" "$_x"; else printf '[%s]   WARNING: %s\n' "$(ui_ts)" "$_x"; fi; }
ui_hb_due() { # ui_hb_due LAST NOW: plain mode prints a heartbeat at least every 10 s
  [ $(($2 - $1)) -ge 10 ]
}
ui_logopen() { # a root-only log for the output of long commands (never for anything secret); fails when there is no place for it
  [ -n "$UI_LOG" ] && return 0
  _old=$(umask); umask 077
  [ -n "$UI_LOGDIR" ] || UI_LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}/ainkrad-install.XXXXXX" 2>/dev/null) || UI_LOGDIR=''
  umask "$_old"
  if [ -z "$UI_LOGDIR" ] || [ ! -d "$UI_LOGDIR" ]; then UI_LOGDIR=''; return 1; fi
  UI_LOG=$UI_LOGDIR/install.log
  : >"$UI_LOG" || { UI_LOG=''; return 1; }
}
ui_lastline() { # the last line of a log, dimmed material for the spinner
  [ -s "$1" ] || return 0
  tail -n 1 "$1" 2>/dev/null | ui_clean | sed 's/^ *//'
}
ui_wait() { # ui_wait PID "what is happening" [LOG] [TEXTFN]: until the process ends
  _pid=$1 _msg=$2 _log=${3:-} _fn=${4:-}
  _start=$(ui_now); _last=$_start; _i=0
  ui_cursor hide
  while kill -0 "$_pid" 2>/dev/null; do
    _now=$(ui_now); _s=$((_now - _start))
    _t=$_msg; [ -z "$_fn" ] || _t=$($_fn "$_s")
    if [ "$UI_FANCY" = 1 ]; then
      _e=" (${_s}s)"; [ -z "$_fn" ] || _e=''
      _t2=$(ui_fit "$_t$_e"); _ll=''
      _room=$((UI_W - 9 - ${#_t2}))
      if [ -n "$_log" ] && [ "$_room" -ge 10 ]; then _ll=$(ui_lastline "$_log" | cut -c1-"$_room"); fi
      printf '\r\033[K   %s%s%s %s%s' "$CY" "$(ui_frame "$_i")" "$R" "$_t2" "${_ll:+ $D$_ll$R}"
      _i=$((_i + 1)); ui_sleep 0.1
    else
      if ui_hb_due "$_last" "$_now"; then printf '[%s]   still working: %s (%ss)\n' "$(ui_ts)" "$(printf '%s' "$_t" | ui_clean)" "$_s"; _last=$_now; fi
      ui_sleep 1
    fi
    [ "$_fn" != ui_cert_text ] || ui_hints "$_s" # the DNS / port 443 checklist belongs to the certificate wait only
  done
  [ "$UI_FANCY" != 1 ] || printf '\r\033[K'
  ui_cursor show
}
ui_cert_text() { # the heartbeat of the Let's Encrypt order, by seconds waited
  if [ "$1" -lt 60 ]; then echo "Requesting the certificate from Let's Encrypt... ${1}s"
  elif [ "$1" -lt 120 ]; then echo "Still waiting for Let's Encrypt... ${1}s (slower than usual)"
  else echo "Let's Encrypt is taking very long... ${1}s (see the checklist above; Ctrl-C stops the wait, run the command again to continue)"; fi
}
ui_hints() { # printed once at 60 s and once at 120 s of a certificate wait
  if [ "$1" -ge 120 ] && [ "$UI_HINT" -lt 2 ]; then UI_HINT=2; ui_hint_text 2
  elif [ "$1" -ge 60 ] && [ "$UI_HINT" -lt 1 ]; then UI_HINT=1; ui_hint_text 1; fi
}
ui_hint_text() {
  [ "$UI_FANCY" != 1 ] || printf '\r\033[K'
  if [ "$1" = 1 ]; then
    ui_warn "Over a minute. Check: (1) the DNS A record of the name is this machine's public address, (2) inbound TCP 443 is open in your provider's firewall."
  else
    ui_warn "Over two minutes. Also check: no AAAA record pointing elsewhere; nothing else listens on 443; 'journalctl -u ainkrad-core -n 30' shows the reason."
  fi
}
ui_run() { # ui_run "what is happening" command...: in the background, output to the log, a spinner in front
  _m=$1; shift
  ui_logopen || { ui_warn "cannot create a log directory in ${TMPDIR:-/tmp}, so I will not run: $_m"; return 1; }
  UI_RUNS=$((UI_RUNS + 1)); _rl=$UI_LOGDIR/run.$UI_RUNS; : >"$_rl"
  ( "$@" ) >"$_rl" 2>&1 </dev/null &
  _p=$!
  UI_JOBS=$_p UI_JOB=$_m
  _t0=$(ui_now)
  [ "$UI_FANCY" = 1 ] || printf '[%s]   %s ...\n' "$(ui_ts)" "$(printf '%s' "$_m" | ui_clean)" # plain mode has no spinner: say what starts
  ui_wait "$_p" "$_m" "$_rl" "$UI_TEXTFN"
  UI_TEXTFN=''
  _rc=0; wait "$_p" || _rc=$?
  UI_JOBS='' UI_JOB=''
  { printf '== %s\n' "$_m"; cat "$_rl"; } >>"$UI_LOG" 2>/dev/null
  if [ "$_rc" = 0 ]; then [ "${UI_QUIET:-0}" = 1 ] || ui_ok "$_m ($(($(ui_now) - _t0))s)"
  else
    ui_warn "$_m: failed (exit $_rc). Last lines of its output (all of it: $UI_LOG):"
    tail -n 12 "$_rl" 2>/dev/null | ui_clean_lines | cut -c1-"$((UI_W - 8))" | sed 's/^/        /'
  fi
  rm -f "$_rl"
  return "$_rc"
}
ui_dl_text() { # the heartbeat of a download: the size so far of the file being written ($UI_DL)
  _b=$(wc -c <"$UI_DL" 2>/dev/null | tr -d ' ' || echo 0)
  case $_b in '' | *[!0-9]*) _b=0 ;; esac
  echo "Downloading $(basename "$UI_DL")... $((_b / 1024)) KB so far (${1}s)"
}
ui_stopped() { # ui_stopped "what failed" ["what to do"]: the red card, then exit 1
  ui_kill_jobs
  ui_cursor show
  [ "$UI_FANCY" != 1 ] || printf '\r\033[K'
  printf '\n %s%s%s Stopped at step %s of %s (%s)%s\n' "$RD" "$B" "$XG" "$UI_N" "$UI_TOTAL" "$UI_TITLE" "$R" >&2
  printf '   What failed: %s\n   What to do:  %s\n   Re-run:      %s\n' "$(printf '%s' "$1" | ui_clean)" "${2:-fix the cause above, then run the command below}" "$UI_RERUN" >&2
  [ -z "$UI_LOG" ] || printf '   Log:         %s\n' "$UI_LOG" >&2
  printf '   State:       %s\n' "$(printf '%s' "$UI_STATE" | ui_clean)" >&2
  exit 1
}
# --- ui-core end ---

main() {
  set -eu
  MIN_VERSION=0.0.0 # stamped by scripts/release/dry.sh with the release version this file ships in
  BASE=${AINKRAD_RELEASE_URL:-https://github.com/AinkradHQ/AinkradCore/releases/latest/download}
  # The pinned release key (same as scripts/release/ainkrad-release.pub). Compare the key id with the project's.
  KEY_ID=FB3618BCFCA5393E
  KEY_FILE='untrusted comment: minisign public key FB3618BCFCA5393E
RWQ+OaX8vBg2+zmrma/A8QI/+cL5wvvHoanVJv0v4xHp04w6zIgS/pDA'

  ui_init
  UI_BASE=0 UI_TOTAL=8 UI_T0=$(ui_now)
  shq() { # a value single-quoted for a shell; one with a control character is not shown at all (return 1)
    case $1 in *[![:print:]]*) return 1 ;; esac
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
  }
  rerun_cmd() { # the command the user ran, rebuilt from the variables they set, the version floor and their flags
    _env=''; _args=''
    for _v in AINKRAD_HOSTNAME AINKRAD_ACME_EMAIL AINKRAD_ACME_ENV AINKRAD_HARDEN AINKRAD_FIREWALL AINKRAD_BACKUP_RECIPIENT AINKRAD_RELEASE_URL; do
      eval "_val=\${$_v:-}"
      if [ -n "$_val" ] && _q=$(shq "$_val"); then _env="$_env $_v=$_q"; fi
    done
    _fl=${RERUN_FLOOR:-${AINKRAD_MIN_VERSION:-}}
    case $_fl in '' | 0 | 0.0.0 | *[!0-9.]*) ;; *) _env="$_env AINKRAD_MIN_VERSION=$_fl" ;; esac
    for _a in "$@"; do if _q=$(shq "$_a"); then _args="$_args $_q"; fi; done
    echo "sudo$_env sh -c \"\$(curl -fsSL https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh)\"${_args:+ sh$_args}"
  }
  UI_RERUN=$(rerun_cmd "$@")
  W=''
  ui_clean_add '[ -z "$W" ] || rm -rf "$W"'
  ui_traps
  say() { printf '%s\n' "$*"; }
  die() { ui_stopped "$*"; }
  demo=0
  for a in "$@"; do [ "$a" != --demo ] || demo=1; done
  if [ "$demo" = 1 ]; then
    # A demo of the first four steps: nothing is downloaded, installed or changed (only harmless sleeps). The questions and the
    # end screens: scripts/install.sh --demo from a checkout. It exits 3 so that no script can mistake it for an install.
    UI_DEMO=1; UI_RERUN='sudo sh -c "$(curl -fsSL https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh)" sh --demo'
    ui_roadmap
    ui_step 1 "$(ui_rname 1)" "Needs Linux with systemd, root, and Debian or Ubuntu (apt)."
    ui_run "Looking at this machine (demo)" sleep 1
    ui_step 2 "$(ui_rname 2)" "curl, minisign, bubblewrap, qrencode (demo: nothing is installed)."
    ui_run "Installing the prerequisite packages with apt (demo: not done)" sleep 2
    ui_step 3 "$(ui_rname 3)" "The signature over SHA256SUMS must match the pinned key (demo: nothing is downloaded)."
    ui_run "Downloading and checking the release (demo: not done)" sleep 2
    ui_step 4 "$(ui_rname 4)" "The four programs go to /usr/local/bin (demo: not done)."
    ui_run "Installing the four programs (demo: not done)" sleep 1
    ui_note "DEMO finished: nothing was downloaded, installed or changed. For the questions and the last screens run: scripts/install.sh --demo (from a checkout)."
    [ -z "$UI_LOGDIR" ] || rm -rf "$UI_LOGDIR"
    exit 3
  fi
  # Piped into sudo (curl ... | sudo sh) a script cannot read the terminal: sudo's pty does not make it the foreground process
  # group when sudo's own stdin is a pipe, so the first question would stop it with SIGTTIN and leave a silent prompt.
  # A real root shell may pipe; only the sudo + pipe + terminal combination is refused, before anything is changed.
  if ! [ -t 0 ] && { [ -n "${SUDO_USER:-}" ] || [ -n "${SUDO_COMMAND:-}" ]; } && ( : </dev/tty ) 2>/dev/null; then
    printf '\n %s%s Cannot start: this command was piped into sudo.%s\n' "$RD" "$XG" "$R" >&2
    printf '   A piped script cannot ask you questions through sudo (the terminal is not handed to it), so it would hang at the\n   first question. Nothing was changed. Run this instead:\n\n     %s\n\n' "$UI_RERUN" >&2
    exit 2
  fi
  harden=0
  case ${AINKRAD_HARDEN:-} in '' | no) ;; yes) harden=1 ;; *) die "AINKRAD_HARDEN must be yes or no (got '$AINKRAD_HARDEN')" ;; esac
  for a in "$@"; do [ "$a" != --harden ] || harden=1; done

  ui_roadmap
  case "$(uname -m)" in
    x86_64 | amd64) TARGET=linux-x86_64 ;;
    aarch64 | arm64) TARGET=linux-arm64 ;;
    *) die "no build for $(uname -m) (x86_64 and arm64 only)" ;;
  esac
  if [ "${AINKRAD_GET_VERIFY_ONLY:-}" != 1 ]; then
    ui_step 1 "Check this machine" "Needs Linux with systemd, root, and Debian or Ubuntu (apt)."
    [ "$(uname -s)" = Linux ] || die "this is $(uname -s); Core installs on Linux only"
    [ "$(id -u)" = 0 ] || die "run it as root: sudo sh -c \"\$(curl -fsSL ...)\" (see the command printed below)"
    [ -d /run/systemd/system ] || die "systemd is not running here (a container without systemd?)"
    command -v apt-get >/dev/null || die "apt-get not found: only Debian and Ubuntu are supported by this installer"
    ui_ok "This is Linux $(uname -m) with systemd and apt, and you are root: supported"

    pkgs='ca-certificates curl minisign bubblewrap qrencode openssl iproute2' persist=''
    # Firewall tooling only when hardening was asked for. iptables-persistent clashes with ufw: with ufw installed nothing is
    # added that could remove it; APT::Get::Remove=false makes apt refuse any removal instead of doing it.
    if [ "$harden" = 1 ]; then pkgs="$pkgs iptables"; dpkg -s ufw >/dev/null 2>&1 || persist=iptables-persistent; fi
    ui_step 2 "Install prerequisites" "curl, minisign (checks the release signature), bubblewrap (agent sandbox), qrencode (QR code)$([ "$harden" = 1 ] && echo ', iptables (firewall, --harden)')."
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
    UI_STATE="Nothing of the Core is installed. Some apt packages may be partly installed; if apt complains, run: sudo dpkg --configure -a"
    # shellcheck disable=SC2086 # $pkgs and $persist are plain package names
    apt_install() { apt-get update -q && apt-get install -y -q -o APT::Get::Remove=false --no-install-recommends $pkgs $persist; }
    ui_run "Installing the prerequisite packages with apt (nothing is ever removed)" apt_install ||
      die "could not install the prerequisites with apt-get (the end of its output is above)"
    command -v minisign >/dev/null || die "minisign is not available on this distribution; it is required to verify the release"
  fi

  W=$(mktemp -d)
  printf '%s\n' "$KEY_FILE" >"$W/release.pub"
  fetch() { # fetch NAME: from the release (https url or a directory) into $W; returns 1 on failure
    case $BASE in
      https://*) curl -fsSL --proto '=https' --tlsv1.3 -o "$W/$1" "$BASE/$1" ;;
      http://*) echo "plain http is refused" >&2; return 1 ;;
      *) cp "$BASE/$1" "$W/$1" 2>/dev/null ;;
    esac
  }
  dl() { UI_DL=$W/$1 UI_TEXTFN=ui_dl_text; ui_run "Downloading $1" fetch "$1" || die "cannot download $BASE/$1"; }
  sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

  UI_STATE="Nothing of the Core is installed yet (the prerequisite packages are in place)."
  ui_step 3 "Download and verify" "The signature over SHA256SUMS must match the pinned key $KEY_ID; every file must match the signed sums."
  dl SHA256SUMS
  dl SHA256SUMS.minisig
  ui_run "Checking the release signature against the pinned key $KEY_ID" \
    minisign -Vq -p "$W/release.pub" -x "$W/SHA256SUMS.minisig" -m "$W/SHA256SUMS" ||
    die "the signature does not verify against the pinned release key $KEY_ID. Do not run anything from this download."
  comment=$(sed -n 's/^trusted comment: //p' "$W/SHA256SUMS.minisig")
  ui_ok "The signature is valid ($comment)"
  ver=${comment#ainkrad-core }
  case $ver in '' | "$comment" | *[!0-9.]*) die "the signed release has no version in its trusted comment ('$comment')" ;; esac
  case ${AINKRAD_MIN_VERSION:-0} in '' | *[!0-9.]*) die "AINKRAD_MIN_VERSION must look like 1.2.3" ;; esac
  floor=$(printf '%s\n%s\n' "$MIN_VERSION" "${AINKRAD_MIN_VERSION:-0}" | sort -V | tail -n1)
  RERUN_FLOOR=$floor; UI_RERUN=$(rerun_cmd "$@")
  if [ "$floor" = "$MIN_VERSION" ]; then ui_ok "version floor $floor (from this get.sh's build)"; else ui_ok "version floor $floor (from AINKRAD_MIN_VERSION)"; fi
  [ -n "${AINKRAD_MIN_VERSION:-}" ] || ui_note "(AINKRAD_MIN_VERSION is not set: the command shown by the Mac app is meant to carry it)"
  [ "$(printf '%s\n%s\n' "$floor" "$ver" | sort -V | head -n1)" = "$floor" ] ||
    die "the signed release is $ver, older than $floor (the build's floor or AINKRAD_MIN_VERSION): refused (no downgrade)"
  files=$(awk -v t="-$TARGET" 'substr($2, length($2) - length(t) + 1) == t || $2 ~ /^ainkrad-core-installer-.*\.tar\.gz$/ { print $2 }' "$W/SHA256SUMS")
  [ "$(echo "$files" | grep -c '^ainkrad-core-installer-')" = 1 ] || die "the signed release must have exactly one installer bundle"
  echo "$files" | grep -q "^ainkrad-core-server-.*-$TARGET\$" || die "the signed release has no Core build for $TARGET"
  for f in $files; do
    dl "$f"
    want=$(awk -v f="$f" '$2 == f { print $1 }' "$W/SHA256SUMS")
    [ -n "$want" ] && [ "$(sha "$W/$f")" = "$want" ] || die "$f does not match its signed checksum"
  done
  ui_ok "All $(echo "$files" | wc -l | tr -d ' ') downloaded files match the signed checksums"
  if [ "${AINKRAD_GET_VERIFY_ONLY:-}" = 1 ]; then say "verify-only: release $ver verified, nothing installed"; return 0; fi
  tar -xzf "$W"/ainkrad-core-installer-*.tar.gz -C "$W" || die "the installer bundle is not a tar.gz"
  INST=$(echo "$W"/ainkrad-core-installer-*/)

  UI_STATE="The programs in /usr/local/bin may be partly replaced (the install is all or none and restores the previous set when it fails, but a stop in the middle can leave it half done). Run the command again to finish."
  ui_step 4 "Install the programs" "ainkrad-core-server, ainkrad-runner, ainkradctl and ainkrad-ptyhost go to /usr/local/bin as one set (all or none)."
  # release/install.sh verifies again, with the key pinned here (never the bundle's own copy), then installs atomically.
  ui_run "Installing the four programs to /usr/local/bin" \
    bash "$INST/scripts/release/install.sh" --from "$W" --pubkey "$W/release.pub" --prefix /usr/local --target "$TARGET" ||
    die "installing the programs failed (the previous set, if any, was restored)"
  UI_STATE="The Core programs are in /usr/local/bin; the guided installer did not finish."

  # Only the child gets the terminal (stdin was the pipe: curl ... | sh); this shell keeps reading nothing from it.
  # While the child runs, a Ctrl-C or TERM only marks this shell: the child prints the one honest card, this shell stays silent.
  rc=0 got=0
  export AINKRAD_FROM_GET=1 AINKRAD_STEP_BASE=0 AINKRAD_STEP_TOTAL=8 AINKRAD_T0="$UI_T0" AINKRAD_RERUN="$UI_RERUN"
  trap 'got=130' INT; trap 'got=143' TERM
  if ( : </dev/tty ) 2>/dev/null; then bash "$INST/scripts/install.sh" --binary /usr/local/bin "$@" </dev/tty || rc=$?
  else bash "$INST/scripts/install.sh" --binary /usr/local/bin "$@" </dev/null || rc=$?; fi
  trap 'ui_int 130' INT; trap 'ui_int 143' TERM
  if [ "$rc" = 0 ] && [ "$got" != 0 ]; then rc=$got; fi
  if [ "$rc" != 0 ] && [ -n "$UI_LOG" ]; then ui_note "Log of the prerequisite and download steps: $UI_LOG"; fi
  exit "$rc" # not exec: the trap must still remove the download directory
}

{ main "$@"; }
