# shellcheck shell=sh
# The live terminal UI of the installer: a roadmap, a step header with a progress bar and elapsed time, a spinner line with
# WHAT is happening for every wait (background command, log captured), a heartbeat line in plain mode, a failure card, and a
# clean exit (cursor always restored). Sourced by scripts/install.sh; the block between the markers is POSIX sh and is copied
# verbatim into scripts/get.sh (which cannot source anything): scripts/install/ui-test.sh fails when the two differ.
# Plain mode (no TTY, NO_COLOR, TERM=dumb): timestamped lines, ASCII only, no escape codes, no spinner, a heartbeat every ~10 s.
# Tests replace ui_now (the clock) and ui_sleep (the pause).
# shellcheck disable=SC2034,SC1003

# --- ui-core begin ---
UI_N=0 UI_BASE=${AINKRAD_STEP_BASE:-0} UI_TOTAL=${AINKRAD_STEP_TOTAL:-8} UI_TEXTFN='' UI_DL='' UI_TITLE='' UI_FANCY=0 UI_UTF=0 UI_W=80 UI_T0='' UI_CLEAN='' UI_LOG='' UI_LOGDIR=''
UI_HINT=0 UI_CURSOR=1 UI_STATE='Nothing has been changed on this machine yet.' UI_RERUN=${AINKRAD_RERUN:-'run the same command again'}
B='' D='' R='' GR='' RD='' YL='' CY='' OKG='+' XG='x' FULL='#' EMPTY='-' DOT='-' SPIN='| / - \'
ui_now() { date +%s; }
ui_ts() { date +%H:%M:%S; }
ui_sleep() { sleep "$1"; }
ui_init() {
  UI_FANCY=0
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then UI_FANCY=1; fi
  UI_UTF=0
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) UI_UTF=1 ;; esac
  UI_W=${COLUMNS:-0}
  case $UI_W in '' | *[!0-9]*) UI_W=0 ;; esac
  [ "$UI_W" -gt 0 ] || UI_W=$(tput cols 2>/dev/null || echo 80)
  case $UI_W in '' | *[!0-9]*) UI_W=80 ;; esac
  [ "$UI_W" -ge 40 ] || UI_W=40
  [ -n "$UI_T0" ] || UI_T0=${AINKRAD_T0:-$(ui_now)}
  B='' D='' R='' GR='' RD='' YL='' CY='' OKG='+' XG='x' FULL='#' EMPTY='-' DOT='-' SPIN='| / - \'
  if [ "$UI_FANCY" = 1 ]; then
    B=$(printf '\033[1m') D=$(printf '\033[2m') R=$(printf '\033[0m') GR=$(printf '\033[32m')
    RD=$(printf '\033[31m') YL=$(printf '\033[33m') CY=$(printf '\033[36m')
    if [ "$UI_UTF" = 1 ]; then OKG='✓' XG='✗' FULL='█' EMPTY='░' DOT='·' SPIN='⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏'; fi
  fi
}
ui_el_s() { echo $(($(ui_now) - UI_T0)); }
ui_el() { _e=$(ui_el_s); printf '%02d:%02d' $((_e / 60)) $((_e % 60)); }
ui_fit() { # ui_fit TEXT [MAX]: one line, control characters dropped, cut to MAX (default: the width minus room for the glyph)
  _max=${2:-$((UI_W - 8))}
  printf '%s' "$1" | tr -d '\000-\037' | cut -c1-"$_max"
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
ui_exit() { # the EXIT trap: the cursor is always back, then the registered clean-ups
  _rc=$?
  ui_cursor show
  if [ "$_rc" = 0 ] && [ -n "$UI_LOGDIR" ]; then rm -rf "$UI_LOGDIR"; fi # the log stays after a failure
  _list=$UI_CLEAN; UI_CLEAN=''
  _old=$IFS; IFS='
'
  for _c in $_list; do [ -z "$_c" ] || eval "$_c" || true; done
  IFS=$_old
  return "$_rc"
}
ui_int() { # INT/TERM: a clean line, and what state the machine is in
  ui_cursor show
  [ "$UI_FANCY" != 1 ] || printf '\r\033[K'
  printf '\n %s! Interrupted at step %s of %s (%s).%s\n   State: %s\n   To continue: %s\n' "$YL" "$UI_N" "$UI_TOTAL" "$UI_TITLE" "$R" "$UI_STATE" "$UI_RERUN"
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
  UI_N=$1 UI_TITLE=$2; _n=$(($1 - UI_BASE))
  if [ "$UI_FANCY" = 1 ]; then
    printf '\n %s%s%s step %s of %s %s·%s %s%s%s %s·%s %s elapsed\n' "$CY" "$(ui_bar "$_n" "$UI_TOTAL")" "$R" "$_n" "$UI_TOTAL" "$D" "$R" "$B" "$2" "$R" "$D" "$R" "$(ui_el)"
    [ -z "${3:-}" ] || printf '   %s%s%s\n' "$D" "$3" "$R"
    if [ "$_n" -gt 1 ]; then
      _d=''; _i=$((UI_BASE + 1)); while [ "$_i" -lt "$1" ]; do _d="$_d $OKG $(ui_short "$_i") "; _i=$((_i + 1)); done
      if [ "${#_d}" -gt $((UI_W - 20)) ]; then _d=" $OKG $((_n - 1)) steps done, latest: $(ui_rname "$(($1 - 1))")"; fi
      printf '   %sDone so far:%s%s%s\n' "$D" "$GR" "$_d" "$R"
    fi
  else
    printf '[%s] step %s/%s: %s%s\n' "$(ui_ts)" "$_n" "$UI_TOTAL" "$2" "${3:+ - $3}"
  fi
}
ui_ok() { # a finished thing, in plain words
  if [ "$UI_FANCY" = 1 ]; then printf '\r\033[K   %s%s%s %s\n' "$GR" "$OKG" "$R" "$1"; else printf '[%s]   ok: %s\n' "$(ui_ts)" "$1"; fi
}
ui_note() { if [ "$UI_FANCY" = 1 ]; then printf '   %s%s%s\n' "$D" "$1" "$R"; else printf '[%s]   %s\n' "$(ui_ts)" "$1"; fi; }
ui_warn() { if [ "$UI_FANCY" = 1 ]; then printf '   %s!%s %s\n' "$YL" "$R" "$1"; else printf '[%s]   WARNING: %s\n' "$(ui_ts)" "$1"; fi; }
ui_hb_due() { # ui_hb_due LAST NOW: plain mode prints a heartbeat at least every 10 s
  [ $(($2 - $1)) -ge 10 ]
}
ui_logopen() { # a root-only log for the output of long commands (never for anything secret)
  [ -n "$UI_LOG" ] && return 0
  _old=$(umask); umask 077
  UI_LOGDIR=${UI_LOGDIR:-$(mktemp -d "${TMPDIR:-/tmp}/ainkrad-install.XXXXXX")}
  UI_LOG=$UI_LOGDIR/install.log; : >"$UI_LOG"
  umask "$_old"
}
ui_lastline() { # the last line of a log, dimmed material for the spinner
  [ -s "$1" ] || return 0
  tail -n 1 "$1" 2>/dev/null | tr -d '\000-\037' | sed 's/^ *//'
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
      if ui_hb_due "$_last" "$_now"; then printf '[%s]   still working: %s (%ss)\n' "$(ui_ts)" "$_t" "$_s"; _last=$_now; fi
      ui_sleep 1
    fi
    [ -z "$_fn" ] || ui_hints "$_s"
  done
  [ "$UI_FANCY" != 1 ] || printf '\r\033[K'
  ui_cursor show
}
ui_cert_text() { # the heartbeat of the Let's Encrypt order, by seconds waited
  if [ "$1" -lt 60 ]; then echo "Requesting the certificate from Let's Encrypt... ${1}s"
  elif [ "$1" -lt 120 ]; then echo "Still waiting for Let's Encrypt... ${1}s (slower than usual)"
  else echo "Let's Encrypt is taking very long... ${1}s (see the checklist above; Ctrl-C is safe)"; fi
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
  ui_logopen
  UI_RUNS=$((${UI_RUNS:-0} + 1)); _rl=$UI_LOGDIR/run.$UI_RUNS; : >"$_rl"
  ( "$@" ) >"$_rl" 2>&1 </dev/null &
  _p=$!
  _t0=$(ui_now)
  [ "$UI_FANCY" = 1 ] || printf '[%s]   %s ...\n' "$(ui_ts)" "$_m" # plain mode has no spinner: say what starts
  ui_wait "$_p" "$_m" "$_rl" "$UI_TEXTFN"
  UI_TEXTFN=''
  _rc=0; wait "$_p" || _rc=$?
  { printf '== %s\n' "$_m"; cat "$_rl"; } >>"$UI_LOG" 2>/dev/null
  if [ "$_rc" = 0 ]; then [ "${UI_QUIET:-0}" = 1 ] || ui_ok "$_m ($(($(ui_now) - _t0))s)"
  else
    ui_warn "$_m: failed (exit $_rc). Last lines of its output (all of it: $UI_LOG):"
    tail -n 12 "$_rl" 2>/dev/null | tr -d '\000-\010\013-\037' | cut -c1-"$((UI_W - 8))" | sed 's/^/        /'
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
  ui_cursor show
  [ "$UI_FANCY" != 1 ] || printf '\r\033[K'
  printf '\n %s%s%s Stopped at step %s of %s (%s)%s\n' "$RD" "$B" "$XG" "$UI_N" "$UI_TOTAL" "$UI_TITLE" "$R" >&2
  printf '   What failed: %s\n   What to do:  %s\n   Re-run:      %s\n' "$1" "${2:-fix the cause above, then run the command below}" "$UI_RERUN" >&2
  [ -z "$UI_LOG" ] || printf '   Log:         %s\n' "$UI_LOG" >&2
  printf '   State:       %s\n' "$UI_STATE" >&2
  exit 1
}
# --- ui-core end ---
