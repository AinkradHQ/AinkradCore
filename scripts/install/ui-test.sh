#!/usr/bin/env bash
# Tests for the live installer UI (scripts/install/ui.sh and its copy in get.sh, the question cards, the DNS feedback, the demo):
# spinner and heartbeat with a fake clock, plain output without escape codes, the cursor restored on Ctrl-C (in a real pty),
# the certificate-wait text changing at 60/120 s, the DNS verdicts with stubbed dig/getent/curl, no prompt without its
# "Question n of N" card, and the failure card. No root, macOS or Linux; run by test.sh. Each check fails when its rule breaks.
# SC2015: `check && pass || fail` is meant. SC2030/31/329: stubs and sourced libraries live in subshells on purpose.
# shellcheck disable=SC2015,SC2016,SC2030,SC2031,SC2034,SC2329
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*" >&2; }
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT

# --- get.sh embeds exactly the ui-core of ui.sh (it cannot source anything) ---
blk() { sed -n '/^# --- ui-core begin ---$/,/^# --- ui-core end ---$/p' "$1"; }
[ -n "$(blk "$ROOT/scripts/install/ui.sh")" ] && [ "$(blk "$ROOT/scripts/install/ui.sh")" = "$(blk "$ROOT/scripts/get.sh")" ] && ok || bad "the ui-core block in scripts/get.sh differs from scripts/install/ui.sh (copy it over)"
# and it is plain POSIX sh: dash can load it
if command -v dash >/dev/null; then blk "$ROOT/scripts/install/ui.sh" >"$t/core.sh"; dash -n "$t/core.sh" && ok || bad "ui-core is not valid POSIX sh"; fi

# ui: a fresh shell with the library, a fake clock and no pauses
u() { # snippet: run in plain mode (stdout is a file) unless FANCY=1 is given in the snippet
  ( . "$ROOT/scripts/install/ui.sh"; . "$ROOT/scripts/install/lib.sh"
    FAKE=1000; ui_now() { echo "$FAKE"; }; ui_sleep() { :; }; ui_ts() { echo 12:01:07; }
    ui_init; UI_T0=1000
    eval "$1" ) 2>&1
}

# --- pure pieces ---
[ "$(u 'UI_UTF=0; SPIN="| / - \\"; for i in 0 1 2 3 4; do ui_frame $i; done')" = '|/-\|' ] && ok || bad "ASCII spinner frames are not |/-\\ in a cycle"
[ "$(u 'SPIN="a b c"; for i in 0 1 2 3 4; do ui_frame $i; done')" = abcab ] && ok || bad "ui_frame does not cycle through the glyphs"
u 'FAKE=1034; ui_el' | grep -qx '00:34' && ok || bad "ui_el does not show mm:ss"
u 'FAKE=1125; ui_el' | grep -qx '02:05' && ok || bad "ui_el is wrong past a minute"
u 'ui_hb_due 100 109' && bad "a heartbeat is due after only 9 s" || ok
u 'ui_hb_due 100 110' && ok || bad "no heartbeat is due after 10 s"
[ "$(u 'UI_BASE=0; UI_TOTAL=8; ui_bar 4 8')" = '[#####-----]' ] && ok || bad "the progress bar for step 4 of 8 is not [#####-----]"
[ "$(u 'UI_BASE=0; UI_TOTAL=8; ui_bar 8 8')" = '[##########]' ] && ok || bad "the progress bar is not full at 8 of 8"
[ "$(u 'UI_W=40; ui_fit "$(printf x%.0s $(seq 100))" | wc -c | tr -d " "')" -le 33 ] && ok || bad "ui_fit does not truncate to the terminal width"
u 'ui_roadmap' | grep -c '^   [1-8]  ' | grep -qx 8 && ok || bad "the roadmap does not list the 8 steps"
u 'UI_BASE=0; UI_TOTAL=8; ui_step 3 "Download and verify" "why"' | grep -qx '\[12:01:07\] step 3/8: Download and verify - why' && ok || bad "the plain step line is not '[hh:mm:ss] step 3/8: ...'"

# --- the certificate wait: the text changes at 60 and 120 s, the hint lists print once each ---
a=$(u 'ui_cert_text 34'); b=$(u 'ui_cert_text 70'); c=$(u 'ui_cert_text 130')
{ [ "$a" != "$b" ] && [ "$b" != "$c" ] && [ "$a" != "$c" ]; } && ok || bad "the certificate heartbeat text does not change at 60 s and 120 s"
grep -q '34s' <<<"$a" && grep -q "Let's Encrypt" <<<"$a" && ok || bad "the certificate text lacks the seconds or the name"
h=$(u 'UI_HINT=0; for s in 10 59 60 61 90 119 120 121 200; do ui_hints $s; done')
[ "$(grep -c 'Over a minute' <<<"$h")" = 1 ] && [ "$(grep -c 'Over two minutes' <<<"$h")" = 1 ] && ok || bad "the 60 s / 120 s hint lists are not printed exactly once each: $h"
grep -q 'DNS A record' <<<"$h" && grep -q '443' <<<"$h" && grep -q 'journalctl' <<<"$h" && ok || bad "the hint lists do not say what to check"

# --- plain mode: no escape code anywhere, a heartbeat every ~10 s of a long wait ---
echo 1000 >"$t/clk"
out=$(u 'sleep 1.3 & p=$!; ui_now() { n=$(cat "'"$t"'/clk"); n=$((n + 1)); echo $n >"'"$t"'/clk"; echo $n; }; ui_sleep() { sleep 0.06; }; ui_wait "$p" "Doing a long thing"; wait $p')
[ "$(grep -c '^\[12:01:07\]   still working: Doing a long thing (' <<<"$out")" -ge 1 ] && ok || bad "plain mode printed no heartbeat during a long wait: $out"
grep -q $'\033' <<<"$out" && bad "plain mode printed an escape code" || ok
grep -qE '[|/\\-] Doing' <<<"$out" && bad "plain mode printed a spinner" || ok
all=$( ( . "$ROOT/scripts/install/ui.sh"; ui_init; ui_roadmap; ui_step 2 x y; ui_ok z; ui_warn w; ui_note n; ui_run "a job" true; ui_run "a failing job" false || true ) 2>&1 )
grep -q $'\033' <<<"$all" && bad "plain mode (stdout not a terminal) printed an escape code" || ok
AINKRAD_DEMO_SPEED=0.02 NO_COLOR=1 bash "$ROOT/scripts/install.sh" --demo >"$t/demo.txt" 2>&1 </dev/null
{ [ -s "$t/demo.txt" ] && ! grep -q $'\033' "$t/demo.txt" && grep -q 'step 8/8' "$t/demo.txt" && grep -q 'DEMO finished' "$t/demo.txt"; } && ok || bad "the --demo run in plain mode is broken or has escape codes"
LC_ALL=C grep -q '[^[:print:][:space:]]' "$t/demo.txt" && bad "plain (non-UTF-8) demo output is not ASCII" || ok
grep -q 'secret=' "$t/demo.txt" && bad "the demo printed its link on stdout" || ok

# --- get.sh uses the live UI for every wait (apt, each download, the signature, the install) and fails with the card ---
for w in 'ui_run "Installing the prerequisite packages with apt' 'UI_TEXTFN=ui_dl_text; ui_run "Downloading' 'ui_run "Checking the release signature' 'ui_run "Installing the four programs'; do
  grep -qF "$w" "$ROOT/scripts/get.sh" && ok || bad "get.sh does not run '$w' through ui_run (no spinner for that wait)"
done
mkdir -p "$t/empty2"
g=$( cd "$t/empty2" && AINKRAD_RELEASE_URL=/nonexistent AINKRAD_GET_VERIFY_ONLY=1 NO_COLOR=1 sh "$ROOT/scripts/get.sh" 2>&1 </dev/null )
{ grep -q '\] step 3/8: Download and verify' <<<"$g" && grep -q 'Downloading SHA256SUMS \.\.\.' <<<"$g" && grep -q 'Stopped at step 3 of 8 (Download and verify)' <<<"$g" && grep -q "Re-run:      curl -fsSL https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh | sudo AINKRAD_RELEASE_URL='/nonexistent' sh" <<<"$g"; } && ok || bad "get.sh in plain mode: no step line, no 'what is happening' line or no failure card with the re-run command: $g"
grep -q $'\033' <<<"$g" && bad "get.sh printed an escape code in plain mode" || ok

# --- the failure card ---
card=$(u 'UI_BASE=0; UI_TOTAL=8; UI_N=3; UI_TITLE="Download and verify"; UI_RERUN="curl -fsSL https://x | sudo sh"; UI_STATE="Nothing was installed."; ui_logopen; (ui_stopped "cannot download X" "check the network") ; echo "rc=$?"')
for want in 'Stopped at step 3 of 8 (Download and verify)' 'What failed: cannot download X' 'What to do:  check the network' 'Re-run:      curl -fsSL https://x | sudo sh' 'State:       Nothing was installed.' 'Log:' 'rc=1'; do
  grep -qF -- "$want" <<<"$card" && ok || bad "the failure card lacks '$want'"
done

# --- the DNS verdicts, with stubbed dig / getent / curl / ip ---
dnsrun() { # NAME WANT A AAAA PUB [ip-6-local]
  local out
  out=$( ( . "$ROOT/scripts/install/ui.sh"; . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"
    ui_init; ui_sleep() { :; }
    ANS_A=$3 ANS_AAAA=$4 ANS_PUB=$5
    dig() { if [[ "$*" == *" AAAA "* ]]; then printf '%s' "$ANS_AAAA"; else printf '%s' "$ANS_A"; fi; }
    curl() { printf '%s' "$ANS_PUB"; }
    ip() { printf '%s\n' "${6:-}"; }
    ui_check_dns core.example.com ) 2>&1 )
  grep -qE "$2" <<<"$out" && ok || bad "DNS check: $1 (wanted /$2/): $out"
  grep -q $'\033' <<<"$out" && bad "DNS check printed an escape code in plain mode" || ok
}
dnsrun "A record matches this machine" 'core.example.com points at 203.0.113.7: this machine. Good.' "203.0.113.7" "" "203.0.113.7"
dnsrun "A record points elsewhere" 'points at 198.51.100.9, but this machine is 203.0.113.7. Fix: change the A record to 203.0.113.7' "198.51.100.9" "" "203.0.113.7"
dnsrun "no A record" 'has no DNS A record yet. Fix: at your DNS provider add an A record  core.example.com -> 203.0.113.7' "" "" "203.0.113.7"
dnsrun "a stray AAAA record" 'AAAA\) record 2001:db8::1 that is not on this machine' "203.0.113.7" "2001:db8::1" "203.0.113.7"
dnsrun "AAAA that IS on this machine" 'this machine. Good.' "203.0.113.7" "2001:db8::1" "203.0.113.7" "    inet6 2001:db8::1/64 scope global"
dnsrun "public address unknown" 'could not be looked up, so I cannot compare' "203.0.113.7" "" ""
dnsrun "a warning never stops the install" 'Not blocking now' "198.51.100.9" "" "203.0.113.7"
dnsrun "the third-party lookup is named" 'api.ipify.org' "203.0.113.7" "" "203.0.113.7"

# --- no prompt without its card ---
cardrun() { # KEY: ask with a stubbed reader; the output must have "Question n of N" BEFORE the reader is called
  ( . "$ROOT/scripts/install/ui.sh"; . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"
    set +u; GUIDED=1 DRY=0; ui_init; say() { printf '%s\n' "$*"; }
    default_of() { echo ''; }
    # install.sh defines ask/ui_read; load only those two functions from it
    eval "$(sed -n '/^ui_read() {/p' "$ROOT/scripts/install.sh")" ; eval "$(sed -n '/^ask() {/,/^}/p' "$ROOT/scripts/install.sh")"
    ui_read() { echo "<<READ:$1>>"; eval "$2=\${ANSWER:-}"; }
    UI_Q_N=0 UI_Q_TOTAL=${2:-0}; ANSWER=$3
    ui_check_dns() { :; }
    ask "$1" "A plain label" ) 2>&1
}
o=$(cardrun HOSTNAME 2 core.example.com)
q=$(grep -n 'Question 1 of 2' <<<"$o" | head -1 | cut -d: -f1); r=$(grep -n '<<READ:' <<<"$o" | head -1 | cut -d: -f1)
{ [ -n "$q" ] && [ -n "$r" ] && [ "$q" -lt "$r" ]; } && ok || bad "a prompt was read before (or without) its 'Question 1 of 2' card: $o"
for want in 'A plain label' 'Example:  core.yourdomain.com' 'Default:  \[none\]' 'Waiting for your answer' 'HOSTNAME = core.example.com'; do
  grep -qE -- "$want" <<<"$o" && ok || bad "the question card / echo lacks '$want'"
done
o=$(cardrun BINARY_DIR 0 /tmp); grep -qE '^ *Question 1$' <<<"$o" && ok || bad "an unknown total should print 'Question n' (got: $(grep Question <<<"$o"))"
# an answer that is not accepted gets a plain-words reason and the question is asked again, with a fresh read
reask() { # KEY ANSWER1 ANSWER2
  ( . "$ROOT/scripts/install/ui.sh"; . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"
    set +u; GUIDED=1 DRY=0; ui_init; say() { printf '%s\n' "$*"; }; default_of() { echo ''; }
    eval "$(sed -n '/^ask() {/,/^}/p' "$ROOT/scripts/install.sh")"
    n=0; ui_read() { n=$((n + 1)); if [ "$n" = 1 ]; then eval "$2=\$ANS1"; else eval "$2=\$ANS2"; fi; echo "<<READ$n>>"; }
    ANS1=$2 ANS2=$3 UI_Q_N=0 UI_Q_TOTAL=2; ui_check_dns() { :; }
    ask "$1" "label" ) 2>&1
}
o=$(reask HOSTNAME 203.0.113.4 core.example.com)
{ grep -q 'That is not a DNS name' <<<"$o" && grep -q '<<READ2>>' <<<"$o" && grep -q 'HOSTNAME = core.example.com' <<<"$o"; } && ok || bad "an invalid hostname was not explained in plain words and re-asked: $o"
o=$(reask ACME_CONTACT not-an-email you@example.com)
{ grep -q 'does not look like an email' <<<"$o" && grep -q 'ACME_CONTACT = you@example.com' <<<"$o"; } && ok || bad "an invalid email was not explained and re-asked: $o"
# every ui_read call in install.sh is inside ask (so every prompt has a card)
[ "$(grep -c 'ui_read ' "$ROOT/scripts/install.sh")" -le 4 ] && ok || bad "a prompt outside ask() reads without a card"
n=$(sed -n '/^ask() {/,/^}/p' "$ROOT/scripts/install.sh" | grep -c 'ui_card'); [ "$n" -ge 1 ] && ok || bad "ask() does not print a card"

# --- the cursor is back after Ctrl-C (a real pty), and the screen says what state the host is in ---
python3 -I - "$ROOT" <<'PY' >"$t/pty.out" 2>&1
import os, pty, signal, sys, time, select
root = sys.argv[1]
def run(sig):
    pid, fd = pty.fork()
    if pid == 0:
        signal.signal(signal.SIGINT, signal.SIG_DFL)  # a test started in the background inherits SIGINT ignored, which bash can then never trap
        os.environ.update(TERM="xterm-256color", LANG="en_US.UTF-8", AINKRAD_DEMO_SPEED="3", COLUMNS="90")
        os.execvp("bash", ["bash", root + "/scripts/install.sh", "--demo"])
    data = b""; t0 = time.time(); sent = False
    while True:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try: chunk = os.read(fd, 65536)
            except OSError: break
            if not chunk: break
            data += chunk
        if not sent and b"\x1b[?25l" in data and time.time() - t0 > 2:
            os.kill(pid, sig); sent = True
        if time.time() - t0 > 40: os.kill(pid, 9); break
    try: os.waitpid(pid, 0)
    except ChildProcessError: pass
    return data.decode("utf-8", "replace"), sent
for name, sig in (("INT", signal.SIGINT), ("TERM", signal.SIGTERM)):
    out, sent = run(sig)
    hide = out.rfind("\x1b[?25l"); show = out.rfind("\x1b[?25h")
    print(name, "SENT", int(sent))
    print(name, "HIDDEN", int(hide >= 0))
    print(name, "RESTORED", int(show > hide >= 0))
    print(name, "SAYS", int("Interrupted at step" in out and "State:" in out))
PY
for sg in INT TERM; do
  grep -q "^$sg SENT 1$" "$t/pty.out" || bad "$sg test: the signal was never sent (the pty run did not reach a spinner): $(cat "$t/pty.out")"
  grep -q "^$sg HIDDEN 1$" "$t/pty.out" && ok || bad "$sg: the cursor was never hidden (no spinner ran)"
  grep -q "^$sg RESTORED 1$" "$t/pty.out" && ok || bad "$sg: the cursor was NOT restored after the signal"
  grep -q "^$sg SAYS 1$" "$t/pty.out" && ok || bad "$sg: the screen did not say 'Interrupted at step N' and the host state"
done

# --- the clean-up list runs on exit and the cursor comes back ---
o=$( ( . "$ROOT/scripts/install/ui.sh"; ui_init; ui_clean_add 'echo CLEANED-ONE'; ui_clean_add 'echo CLEANED-TWO'; ui_traps; exit 0 ) 2>&1 )
{ grep -q CLEANED-ONE <<<"$o" && grep -q CLEANED-TWO <<<"$o"; } && ok || bad "the registered clean-ups did not run on exit"
o=$( ( . "$ROOT/scripts/install/ui.sh"; ui_init; UI_FANCY=1; UI_CURSOR=0; ui_traps; exit 0 ) 2>&1 | od -c | tr -d ' \n' )
grep -q '033\[?25h' <<<"$o" && ok || bad "the EXIT trap did not print the show-cursor sequence"
# the log directory is removed on success and kept on failure
ld=$( ( . "$ROOT/scripts/install/ui.sh"; ui_init; ui_logopen; ui_traps; echo "$UI_LOGDIR"; exit 0 ) )
[ ! -e "$ld" ] && ok || bad "the install log was kept after a successful run"
ld=$( ( . "$ROOT/scripts/install/ui.sh"; ui_init; ui_logopen; ui_traps; echo "$UI_LOGDIR"; exit 3 ) )
[ -d "$ld" ] && ok || bad "the install log was removed after a failure"
[ -d "$ld" ] && [ "$(stat -c %a "$ld" 2>/dev/null || stat -f %Lp "$ld")" = 700 ] && ok || bad "the log directory is not root-only (0700)"
rm -rf "$ld"

# --- the spinner in a real terminal: one rewritten line, no scrolling, fits the width ---
python3 -I - "$ROOT" <<'PY' >"$t/spin.out" 2>&1
import os, pty, sys, time, select, re, struct, fcntl, termios
root = sys.argv[1]
pid, fd = pty.fork()
if pid == 0:
    os.environ.update(TERM="xterm-256color", LANG="en_US.UTF-8", COLUMNS="50")
    os.execvp("bash", ["bash", "-c", '. "%s/scripts/install/ui.sh"; ui_init; ui_run "A rather long description of what is going on right now in this step" sleep 1.5; echo END' % root])
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 50, 0, 0))
data = b""
while True:
    r, _, _ = select.select([fd], [], [], 0.3)
    if r:
        try: c = os.read(fd, 65536)
        except OSError: break
        if not c: break
        data += c
    else:
        try:
            if os.waitpid(pid, os.WNOHANG)[0]: break
        except ChildProcessError: break
txt = data.decode("utf-8", "replace")
frames = [f for f in txt.split("\r") if "\x1b[K" in f or f.strip()]
vis = [re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", f) for f in frames]
vis = [v for v in vis if "\u2713" not in v]  # finished lines are not rewritten; only spinner frames must fit
print("FRAMES", len(vis))
print("MAXW", max((len(v.rstrip("\n")) for v in vis), default=0))
print("NEWLINES_IN_SPINNER", txt.count("\n") - 1)
print("CLEAR_EOL", int("\x1b[K" in txt))
PY
grep -q '^FRAMES [0-9]*[1-9][0-9]*$' "$t/spin.out" && ok || bad "the spinner printed no frames: $(cat "$t/spin.out")"
mw=$(sed -n 's/^MAXW //p' "$t/spin.out"); [ -n "$mw" ] && [ "$mw" -le 49 ] && ok || bad "a spinner frame is wider than the terminal ($mw > 49)"
grep -q '^CLEAR_EOL 1$' "$t/spin.out" && ok || bad "the spinner does not clear to the end of the line (flicker or leftovers)"
[ "$(sed -n 's/^NEWLINES_IN_SPINNER //p' "$t/spin.out")" -le 2 ] && ok || bad "the spinner scrolled the screen (it must rewrite one line)"


# ===================== review round 2 =====================
# --- (1) Ctrl-C / TERM stop the background job and its children, and the card tells the truth ---
cat >"$t/jobs.sh" <<EOF
. "$ROOT/scripts/install/ui.sh"; . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"
ui_init; ui_traps; UI_BASE=0; UI_TOTAL=8; UI_N=4; UI_TITLE="Install the programs"; UI_STATE="The programs may be partly replaced."; UI_RERUN="the one-line command"
case "\$1" in
  run) ui_run "Installing the four programs (test)" sh -c 'sleep 31.5; sleep 31.6' ;;
  cert) health() { sleep 31.7; return 1; }; cert_wait ;;
esac
EOF
python3 -I - "$t" <<'PY' >"$t/sig.out" 2>&1
import os, pty, signal, subprocess, sys, time, select
t = sys.argv[1]
def alive(pat):
    out = subprocess.run(["ps", "-A", "-o", "args="], capture_output=True, text=True).stdout
    return [l for l in out.splitlines() if pat in l and "ps -A" not in l]
def run(mode, how):
    pid, fd = pty.fork()
    if pid == 0:
        signal.signal(signal.SIGINT, signal.SIG_DFL)  # a test started in the background inherits SIGINT ignored, which bash can then never trap
        os.environ.update(TERM="xterm-256color", LANG="en_US.UTF-8", COLUMNS="100")
        os.execvp("bash", ["bash", t + "/jobs.sh", mode])
    data = b""; t0 = time.time(); sent = False
    while True:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try: c = os.read(fd, 65536)
            except OSError: break
            if not c: break
            data += c
        if not sent and time.time() - t0 > 2.5:
            if how == "^C": os.write(fd, b"\x03")       # the terminal sends SIGINT to the foreground group
            else: os.kill(pid, signal.SIGTERM)          # a plain kill reaches only the script
            sent = True
        if time.time() - t0 > 30: os.kill(pid, 9); break
    try: os.waitpid(pid, 0)
    except ChildProcessError: pass
    time.sleep(0.5)
    left = alive("sleep 31.")
    for l in left: os.system("pkill -f 'sleep 31\\.' 2>/dev/null")
    return data.decode("utf-8", "replace"), left
for mode, pat in (("run", "sleep 31.5"), ("cert", "sleep 31.7")):
    for how in ("^C", "TERM"):
        out, left = run(mode, how)
        k = f"{mode}-{how}"
        print(k, "SURVIVORS", len(left))
        print(k, "INTERRUPTED", int("Interrupted at step 4 of 8" in out))
        print(k, "HONEST", int(("Stopped while: Installing the four programs (test)" in out and "partly" in out) if mode == "run" else ("Stopped while: waiting for the certificate" in out)))
        print(k, "NOLIE", int("Ctrl-C is safe" not in out and "nothing of the Core is installed" not in out.lower()))
        print(k, "ONECARD", int(out.count("Interrupted at step") == 1))
    # the watchdog of the certificate wait must not outlive it either
    print(mode, "WATCHDOG", len(alive("sleep 240")))
PY
for k in run-^C run-TERM cert-^C cert-TERM; do
  grep -q "^$k SURVIVORS 0$" "$t/sig.out" && ok || bad "$k: a background job (or its child) survived the signal: $(grep "^$k" "$t/sig.out" | tr '\n' ' ')"
  grep -q "^$k INTERRUPTED 1$" "$t/sig.out" && ok || bad "$k: no 'Interrupted at step' card"
  grep -q "^$k HONEST 1$" "$t/sig.out" && ok || bad "$k: the card does not say which step was stopped and that it may be partly done"
  grep -q "^$k NOLIE 1$" "$t/sig.out" && ok || bad "$k: the card claims Ctrl-C is safe or that nothing is installed"
  grep -q "^$k ONECARD 1$" "$t/sig.out" && ok || bad "$k: more than one Interrupted card"
done
grep -q '^cert WATCHDOG 0$' "$t/sig.out" && ok || bad "the certificate wait's watchdog survived a signal"
# get.sh does not print a second card when its child already did
grep -q "trap 'got=130' INT" "$ROOT/scripts/get.sh" && grep -q "if \[ \"\$rc\" = 0 \] && \[ \"\$got\" != 0 \]" "$ROOT/scripts/get.sh" && ok || bad "get.sh does not stay silent while its child handles Ctrl-C"
ln1=$(grep -n "trap 'got=130' INT" "$ROOT/scripts/get.sh" | head -1 | cut -d: -f1); ln2=$(grep -n 'bash "$INST/scripts/install.sh"' "$ROOT/scripts/get.sh" | head -1 | cut -d: -f1)
{ [ -n "$ln1" ] && [ -n "$ln2" ] && [ "$ln1" -lt "$ln2" ]; } && ok || bad "get.sh installs its quiet INT trap after starting the child"

# --- (2) demo only as a flag; it is labelled and never exits 0 ---
mkdir -p "$t/dd"; for n in ainkrad-core-server ainkradctl ainkrad-runner ainkrad-ptyhost; do printf '#!/bin/sh\n' >"$t/dd/$n"; done
o=$(AINKRAD_INSTALL_DEMO=1 AINKRAD_HOSTNAME=core.example.com AINKRAD_ACME_EMAIL=ops@example.com NO_COLOR=1 bash "$ROOT/scripts/install.sh" --dry-run --binary "$t/dd" 2>&1 </dev/null)
{ grep -q 'step 1/4: Your 2 answers' <<<"$o" && ! grep -qi 'DEMO' <<<"$o"; } && ok || bad "AINKRAD_INSTALL_DEMO=1 alone changed what the installer does"
AINKRAD_DEMO_SPEED=0.02 NO_COLOR=1 bash "$ROOT/scripts/install.sh" --demo >"$t/demo2.txt" 2>&1 </dev/null; rc=$?
[ "$rc" = 3 ] && ok || bad "a demo run exited $rc instead of 3"
[ "$(grep -c 'step [0-9]/8' "$t/demo2.txt")" = "$(grep 'step [0-9]/8' "$t/demo2.txt" | grep -c 'DEMO step')" ] && ok || bad "a demo step header is not labelled DEMO"
grep -q '\*\*\* DEMO' "$t/demo2.txt" && grep -q 'exits 3' "$t/demo2.txt" && ok || bad "the demo does not announce itself or say it exits 3"
# get.sh --demo: nothing real (shims record any apt/curl/tar/minisign/dpkg call), exit 3, nothing left behind
mkdir -p "$t/gd/shim" "$t/gd/cwd" "$t/gd/tmp"; : >"$t/gd/viol"
for f in apt-get curl minisign tar dpkg systemctl sudo; do printf '#!/bin/sh\necho "SHIM %s $*" >>"%s"\nexit 99\n' "$f" "$t/gd/viol" >"$t/gd/shim/$f"; chmod +x "$t/gd/shim/$f"; done
o=$( cd "$t/gd/cwd" && PATH="$t/gd/shim:$PATH" TMPDIR="$t/gd/tmp" NO_COLOR=1 sh "$ROOT/scripts/get.sh" --demo 2>&1 </dev/null ); rc=$?
{ [ "$rc" = 3 ] && grep -q 'DEMO' <<<"$o" && grep -q 'nothing was downloaded, installed or changed' <<<"$o"; } && ok || bad "get.sh --demo: rc=$rc or missing the DEMO labels"
[ ! -s "$t/gd/viol" ] && ok || bad "get.sh --demo ran a real command: $(cat "$t/gd/viol")"
[ -z "$(find "$t/gd/cwd" "$t/gd/tmp" -mindepth 1 | head -1)" ] && ok || bad "get.sh --demo left files behind: $(find "$t/gd/cwd" "$t/gd/tmp" -mindepth 1)"

# --- (3) the Re-run line is the real invocation ---
rr=$( cd "$t/empty2" && AINKRAD_RELEASE_URL="/no'pe" AINKRAD_HOSTNAME=core.example.com AINKRAD_ACME_EMAIL=ops@example.com AINKRAD_MIN_VERSION=1.2.3 AINKRAD_HARDEN=yes AINKRAD_ACME_ENV=$'a\001b' NO_COLOR=1 sh "$ROOT/scripts/get.sh" --harden 2>&1 </dev/null | sed -n 's/^   Re-run:      //p' )
want="curl -fsSL https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh | sudo AINKRAD_HOSTNAME='core.example.com' AINKRAD_ACME_EMAIL='ops@example.com' AINKRAD_HARDEN='yes' AINKRAD_RELEASE_URL='/no'\\''pe' AINKRAD_MIN_VERSION=1.2.3 sh -s -- '--harden'"
[ "$rr" = "$want" ] && ok || bad "the Re-run line is not the real invocation (quoting, flags, floor, unsafe value omitted): got [$rr] want [$want]"
rr=$( cd "$t/empty2" && AINKRAD_RELEASE_URL=/nonexistent AINKRAD_MIN_VERSION='1;touch /tmp/pwned-ainkrad' NO_COLOR=1 sh "$ROOT/scripts/get.sh" 2>&1 </dev/null | sed -n 's/^   Re-run:      //p' )
case $rr in *pwned*) bad "an unsafe AINKRAD_MIN_VERSION reached the Re-run line: $rr" ;; *) ok ;; esac

# --- (4) the removal hint ---
sd="$t/saved/scripts"; mkdir -p "$sd"; printf '#!/bin/sh\n' >"$sd/install.sh"; chmod +x "$sd/install.sh"
h=$( . "$ROOT/scripts/install/ui.sh"; . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"; AINKRAD_SAVED_INSTALLER="$t/saved"; INSTALLER_SAVED="$t/saved"; AINKRAD_FROM_GET=1; removal_hint )
{ grep -q 'remove the Core and its data' <<<"$h" && grep -q "$t/saved/scripts/install.sh --uninstall --purge" <<<"$h" && grep -q 'keeps the ainkrad service users' <<<"$h" && grep -q 'backup.env' <<<"$h" && ! grep -q 'curl' <<<"$h"; } && ok || bad "the removal hint should prefer the saved installer and list what it keeps: $h"
h=$( . "$ROOT/scripts/install/ui.sh"; . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"; INSTALLER_SAVED="$t/none"; AINKRAD_FROM_GET=1; removal_hint )
{ grep -q 'checks the download first' <<<"$h" && grep -q 'keeps' <<<"$h"; } && ok || bad "the fallback removal hint is wrong: $h"

# --- (5) numbers from the environment are digits or ignored (no arithmetic injection) ---
rm -f "$t/pwned"
r=$( AINKRAD_STEP_BASE='a[$(touch '"$t"'/pwned)]' AINKRAD_STEP_TOTAL='0' AINKRAD_T0='9[$(touch '"$t"'/pwned)]' bash -c '. "$1"; ui_init; echo "$UI_BASE $UI_TOTAL [$UI_T0]"' _ "$ROOT/scripts/install/ui.sh" 2>&1 )
{ [ ! -e "$t/pwned" ] && grep -q '^0 8 \[[0-9]*\]$' <<<"$r"; } && ok || bad "an environment number was evaluated or not rejected: $r"
r=$( AINKRAD_STEP_TOTAL='4' AINKRAD_STEP_BASE='4' bash -c '. "$1"; ui_init; echo "$UI_BASE $UI_TOTAL"' _ "$ROOT/scripts/install/ui.sh" ); [ "$r" = "4 4" ] && ok || bad "valid step numbers were not kept: $r"

# --- (6) external strings lose every control character, C1 included ---
bad_str=$(printf 'a\033[31mred\033[0m b\177c d\233e f\302\233g h\302\200i \342\200\246 end')
hexof() { od -An -tx1 | tr '\n' ' ' | tr -s ' ' | sed 's/^/ /; s/$/ /'; } # bytes as " 61 1b 5b " so that a byte is matched whole
for fn in ui_ok ui_note ui_warn; do
  out=$( . "$ROOT/scripts/install/ui.sh"; ui_init; "$fn" "$bad_str" | hexof )
  case $out in *" 1b "* | *" 7f "* | *" 9b "* | *" c2 80 "* | *" c2 67 "*) bad "$fn let a control character through: $out" ;; *) ok ;; esac
done
out=$( . "$ROOT/scripts/install/ui.sh"; ui_init; printf '%s' "$bad_str" | ui_clean | hexof )
case $out in *" e2 80 a6 "*) ok ;; *) bad "ui_clean corrupted a legitimate UTF-8 character (the ellipsis): $out" ;; esac
printf 'apt says \033[2J\033[1;1Hgotcha\n' >"$t/log1"
out=$( . "$ROOT/scripts/install/ui.sh"; ui_init; ui_lastline "$t/log1" | hexof ); case $out in *" 1b "*) bad "ui_lastline let an escape code through" ;; *) ok ;; esac
out=$( . "$ROOT/scripts/install/ui.sh"; ui_init; ui_run "a failing job" sh -c 'printf "bad \033[2J line\n"; exit 3' 2>&1 | hexof ); case $out in *" 1b "*) bad "the failure tail let an escape code through" ;; *) ok ;; esac

# --- (7) AAAA values are validated ---
ok_v6=0
( . "$ROOT/scripts/install/lib.sh"; valid_ipv6 2001:db8::1 && valid_ipv6 ::1 && valid_ipv6 fe80::1:2:3:4 && ! valid_ipv6 '*' && ! valid_ipv6 '2001:db8::1;touch x' && ! valid_ipv6 abc && ! valid_ipv6 ':::' && ! valid_ipv6 '' && ! valid_ipv6 $'::1\033[31m' ) && ok || bad "valid_ipv6 accepts or rejects the wrong things"
mkdir -p "$t/globdir" && : >"$t/globdir/FILE"
o=$( cd "$t/globdir" && . "$ROOT/scripts/install/ui.sh"; . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"; ui_init; ui_sleep() { :; }
  dig() { if [[ "$*" == *" AAAA "* ]]; then printf '*\n2001:db8::9\n'; else printf '203.0.113.7\n'; fi; }; curl() { printf '203.0.113.7'; }; ip() { :; }
  ui_check_dns core.example.com 2>&1 )
{ grep -q 'AAAA) record 2001:db8::9' <<<"$o" && ! grep -q 'record FILE' <<<"$o" && ! grep -q 'record \*' <<<"$o"; } && ok || bad "an AAAA answer that is a glob was used or a valid one was dropped: $o"

# --- (8) the certificate checklist belongs to the certificate wait only ---
echo 1000 >"$t/clk"
out=$( . "$ROOT/scripts/install/ui.sh"; ui_init
  ui_now() { n=$(cat "$t/clk"); n=$((n + 30)); echo $n >"$t/clk"; echo $n; }; ui_sleep() { sleep 0.05; }
  UI_HINT=0; UI_DL=$t/ainkrad-x; : >"$UI_DL"; sleep 1 & p=$!; ui_wait "$p" "downloading" "" ui_dl_text; wait $p 2>/dev/null )
grep -q 'Over a minute' <<<"$out" && bad "the certificate checklist was printed during a download wait" || ok
echo 1000 >"$t/clk"
out=$( . "$ROOT/scripts/install/ui.sh"; ui_init
  ui_now() { n=$(cat "$t/clk"); n=$((n + 30)); echo $n >"$t/clk"; echo $n; }; ui_sleep() { sleep 0.05; }
  UI_HINT=0; sleep 1 & p=$!; ui_wait "$p" "cert" "" ui_cert_text; wait $p 2>/dev/null )
grep -q 'Over a minute' <<<"$out" && ok || bad "the certificate checklist was not printed during the certificate wait"

# --- (9) no log directory, no run ---
rm -f "$t/ran"
o=$( . "$ROOT/scripts/install/ui.sh"; ui_init; TMPDIR=/nonexistent-dir ui_run "a job" sh -c "touch $t/ran"; echo "rc=$?" 2>&1 )
{ grep -q 'rc=1' <<<"$o" && grep -q 'cannot create a log directory' <<<"$o" && [ ! -e "$t/ran" ]; } && ok || bad "ui_run ran without a log directory (or did not say why): $o"
[ ! -e /install.log ] && ok || bad "a log was written to /install.log"

# --- the pinned top level of get.sh: only function definitions, comments and the last-line call ---
top=$(awk '/^[a-zA-Z_]+\(\) \{/ { infn = 1 } !infn && !/^[[:space:]]*(#|$)/ { print } /^\}/ { infn = 0 }' "$ROOT/scripts/get.sh" | grep -v '^{ main "\$@"; }$' | head -3)
[ -z "$top" ] && ok || bad "get.sh has top-level code besides function definitions and the last-line call: $top"

echo "ui tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
