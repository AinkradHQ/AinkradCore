# shellcheck shell=sh
# The live terminal UI of the installer: a roadmap, a step header with a progress bar and elapsed time, a spinner line with
# WHAT is happening for every wait (background command, log captured), a heartbeat line in plain mode, a failure card, and a
# clean exit (cursor always restored). Sourced by scripts/install.sh; the block between the markers is POSIX sh and is copied
# verbatim into scripts/get.sh (which cannot source anything): scripts/install/ui-test.sh fails when the two differ.
# Plain mode (no TTY, NO_COLOR, TERM=dumb): timestamped lines, ASCII only, no escape codes, no spinner, a heartbeat every ~10 s.
# Tests replace ui_now (the clock) and ui_sleep (the pause).
# shellcheck disable=SC2034,SC1003

# --- ui-core begin ---
ui_defaults() { # every variable the UI uses; called by ui_init (the only top-level code in this block is function definitions)
  UI_N=0 UI_TITLE='' UI_TEXTFN='' UI_DL='' UI_FANCY=0 UI_UTF=0 UI_W=80 UI_T0='' UI_CLEAN='' UI_LOG='' UI_LOGDIR='' UI_JOBS='' UI_JOB='' UI_RUNS=0
  UI_HINT=0 UI_CURSOR=1 UI_LIVE=0 UI_LAST_EL='' UI_STTY='' UI_STATE='Nothing has been changed on this machine yet.' UI_RERUN=${AINKRAD_RERUN:-'run the same command again'}
  UI_DEMO=0 # set by --demo AFTER ui_init, never read from the environment
  UI_LIVE_ENV=0; [ "${AINKRAD_UI_LIVE:-}" != 1 ] || UI_LIVE_ENV=1 # a progress line already sits right above the cursor (set by get.sh for install.sh)
  # numbers from the environment are plain digits or they are ignored (they reach shell arithmetic)
  case ${AINKRAD_STEP_BASE:-0} in '' | *[!0-9]*) UI_BASE=0 ;; *) UI_BASE=${AINKRAD_STEP_BASE:-0} ;; esac
  case ${AINKRAD_STEP_TOTAL:-8} in '' | *[!0-9]* | 0) UI_TOTAL=8 ;; *) UI_TOTAL=${AINKRAD_STEP_TOTAL:-8} ;; esac
  case ${AINKRAD_T0:-} in '' | *[!0-9]*) UI_T0='' ;; *) UI_T0=${AINKRAD_T0:-} ;; esac
  [ "$UI_TOTAL" -le 99 ] && [ "$UI_BASE" -le 99 ] || { UI_BASE=0 UI_TOTAL=8; }
  B='' D='' R='' GR='' RD='' YL='' CY='' BL='' OKG='+' XG='x' FULL='#' EMPTY='-' DOT='-' SPIN='| / - \'
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
    UI_LIVE=$UI_LIVE_ENV
    B=$(printf '\033[1m') D=$(printf '\033[2m') R=$(printf '\033[0m') GR=$(printf '\033[32m')
    RD=$(printf '\033[31m') YL=$(printf '\033[33m') CY=$(printf '\033[36m') BL=$(printf '\033[94m')
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
ui_tty_fg() { # 0 when this process may read the terminal without being stopped by SIGTTIN (it is in the foreground group); unknown = yes
  _pg=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' '); _tp=$(ps -o tpgid= -p $$ 2>/dev/null | tr -d ' ')
  case $_pg$_tp in '' | *[!0-9]*) return 0 ;; esac
  [ "$_tp" = 0 ] || [ "$_pg" = "$_tp" ]
}
# shellcheck disable=SC2016 # the string is eval'd at exit, when $UI_STTY is known
ui_tty_init() { # flow control off: a stray Ctrl-S must not freeze the screen and look like a hang; the old settings come back at exit
  { ( : </dev/tty ) 2>/dev/null && ui_tty_fg; } || return 0
  _s=$(stty -g </dev/tty 2>/dev/null) || return 0
  stty -ixon </dev/tty 2>/dev/null || return 0
  UI_STTY=$_s; ui_clean_add 'stty "$UI_STTY" </dev/tty 2>/dev/null'
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
    1) echo "Check this machine and your DNS name" ;; 2) echo "Install prerequisites" ;; 3) echo "Download and verify" ;; 4) echo "Install the programs" ;;
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
ui_barline() { # the progress line: bar, step N of M, the title, the elapsed time; always shorter than the terminal is wide
  _n=$((UI_N - UI_BASE)); _dm=''; [ "$UI_DEMO" != 1 ] || _dm='DEMO · '
  if [ "$UI_W" -lt 60 ]; then printf ' %s%s%s %sstep %s of %s %s·%s %s' "$CY" "$(ui_bar "$_n" "$UI_TOTAL")" "$R" "$_dm" "$_n" "$UI_TOTAL" "$D" "$R" "$(ui_el)"; return 0; fi
  _tt=$(printf '%s' "$UI_TITLE" | ui_clean | cut -c1-"$((UI_W - 52))")
  printf ' %s%s%s %sstep %s of %s %s·%s %s%s%s %s·%s %s' "$CY" "$(ui_bar "$_n" "$UI_TOTAL")" "$R" "$_dm" "$_n" "$UI_TOTAL" "$D" "$R" "$B" "$_tt" "$R" "$D" "$R" "$(ui_el)"
}
ui_live_bar() { # redraw the progress line in place; the cursor is on the line below it and ends there again
  printf '\r\033[K\033[1A\r\033[K%s\n' "$(ui_barline)"
}
ui_emit() { # ui_emit TEXT: a line that stays on the screen, put above the live progress line (plain output when there is none)
  if [ "$UI_FANCY" = 1 ] && [ "$UI_LIVE" = 1 ]; then printf '\r\033[K\033[1A\r\033[K%s\n%s\n' "$1" "$(ui_barline)"; else printf '%s\n' "$1"; fi
}
ui_status() { # ui_status TEXT: the live line (it is replaced by the next one); a plain note line in plain mode
  _x=$(printf '%s' "$1" | ui_clean)
  if [ "$UI_FANCY" = 1 ] && [ "$UI_LIVE" = 1 ]; then printf '\r\033[K   %s%s%s' "$D" "$(printf '%s' "$_x" | cut -c1-"$((UI_W - 6))")" "$R"
  else ui_note "$1"; fi
}
ui_live_end() { # the last screens print freely: the progress line stays as it is, the live line below it is cleared
  if [ "$UI_FANCY" = 1 ] && [ "$UI_LIVE" = 1 ]; then printf '\r\033[K'; UI_LIVE=0; fi
}
ui_step() { # ui_step N "Title" "why": fancy = the progress line is redrawn in place (the why text is not shown); plain = one line
  UI_N=$1 UI_TITLE=$2; _n=$(($1 - UI_BASE)); _dm=''; [ "$UI_DEMO" != 1 ] || _dm='DEMO · '
  if [ "$UI_FANCY" = 1 ]; then
    if [ "$UI_LIVE" = 1 ]; then ui_live_bar; else printf '\n%s\n' "$(ui_barline)"; UI_LIVE=1; fi
  else
    printf '[%s] %sstep %s/%s: %s%s\n' "$(ui_ts)" "${_dm:+DEMO }" "$_n" "$UI_TOTAL" "$2" "${3:+ - $3}"
  fi
}
ui_ok() { # a finished thing: the live line while it runs on a terminal (not kept), a line in plain mode
  _x=$(printf '%s' "$1" | ui_clean)
  if [ "$UI_FANCY" = 1 ] && [ "$UI_LIVE" = 1 ]; then printf '\r\033[K   %s%s%s %s' "$GR" "$OKG" "$R" "$(printf '%s' "$_x" | cut -c1-"$((UI_W - 8))")"
  elif [ "$UI_FANCY" = 1 ]; then printf '\r\033[K   %s%s%s %s\n' "$GR" "$OKG" "$R" "$_x"
  else printf '[%s]   ok: %s\n' "$(ui_ts)" "$_x"; fi
}
ui_keep() { # a result that stays on the screen
  _x=$(printf '%s' "$1" | ui_clean)
  if [ "$UI_FANCY" = 1 ]; then ui_emit "   $GR$OKG$R $_x"; else ui_ok "$1"; fi
}
ui_note() { _x=$(printf '%s' "$1" | ui_clean); if [ "$UI_FANCY" = 1 ]; then ui_emit "   $D$_x$R"; else printf '[%s]   %s\n' "$(ui_ts)" "$_x"; fi; }
ui_warn() { _x=$(printf '%s' "$1" | ui_clean); if [ "$UI_FANCY" = 1 ]; then ui_emit "   $YL!$R $_x"; else printf '[%s]   WARNING: %s\n' "$(ui_ts)" "$_x"; fi; }
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
      if [ "$UI_LIVE" = 1 ] && [ "$_s" != "$UI_LAST_EL" ]; then UI_LAST_EL=$_s; ui_live_bar; printf '   %s%s%s %s' "$CY" "$(ui_frame "$_i")" "$R" "$_t2"; fi # the clock on the progress line
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
    _tl=$(tail -n 12 "$_rl" 2>/dev/null | ui_clean_lines | cut -c1-"$((UI_W - 8))" | sed 's/^/        /')
    [ -z "$_tl" ] || ui_emit "$_tl"
  fi
  rm -f "$_rl"
  return "$_rc"
}
ui_dl_text() { # the heartbeat of a download: the size so far of the file being written ($UI_DL), which curl may not have made yet
  _b=$({ wc -c <"$UI_DL"; } 2>/dev/null | tr -d ' ')
  case $_b in '' | *[!0-9]*) echo "Starting the download of $(basename "$UI_DL")... (${1}s)"; return 0 ;; esac
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
ui_defaults # install.sh sources this file; get.sh calls ui_init from main
