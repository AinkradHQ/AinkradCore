#!/usr/bin/env bash
# Regression tests for the "curl ... | sudo sh" hang (0.2.0, 0.2.1): piped into sudo, a script is not given the terminal, so its
# first read from /dev/tty stops it with SIGTTIN and the user sits at a silent prompt. Real ptys (python3 pty); a REAL sudo when
# the machine has passwordless sudo (CI), otherwise the same condition is made by a process group that is not the terminal's
# foreground group. Nothing is installed (stubs, --dry-run, --demo). Run by test.sh; each check fails when its guard is removed.
# SC2015: `check && pass || fail` is meant. shellcheck disable=SC2015,SC2016
# shellcheck disable=SC2015,SC2016
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*" >&2; }
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
command -v python3 >/dev/null || { echo "pty-test: python3 missing: NOT RUN" >&2; exit 0; }

# stubs so the guided installer can ask its question and run its live check with no network and no change
mkdir -p "$t/bin" "$t/shim"
for n in ainkrad-core-server ainkradctl ainkrad-runner ainkrad-ptyhost; do printf '#!/bin/sh\n' >"$t/bin/$n"; chmod +x "$t/bin/$n"; done
printf '#!/bin/sh\nprintf 203.0.113.7\n' >"$t/shim/curl"; printf '#!/bin/sh\ncase "$*" in *AAAA*) ;; *) echo 203.0.113.7 ;; esac\n' >"$t/shim/dig"
chmod +x "$t/shim/curl" "$t/shim/dig"
# a wrapper that is what "curl | sudo sh" would run: the installer, dry, asking its two questions
cat >"$t/run-installer.sh" <<EOF
PATH="$t/shim:\$PATH" exec bash "$ROOT/scripts/install.sh" --dry-run --binary "$t/bin"
EOF
cp "$ROOT/scripts/get.sh" "$t/get.sh"
SUDO=''; if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then SUDO=sudo; fi

cat >"$t/pty.py" <<'PY'
import os, pty, signal, subprocess, sys, time, select, json
# usage: pty.py MODE TIMEOUT SPEC cmd...   MODE: fg (normal foreground pty) | bg (the command runs in a background process group)
mode, timeout, spec = sys.argv[1], float(sys.argv[2]), json.loads(sys.argv[3]); cmd = sys.argv[4:]
pid, fd = pty.fork()
if pid == 0:
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.environ.update(TERM="xterm-256color", LANG="en_US.UTF-8", COLUMNS="100")
    if mode == "bg":
        # the command runs in a NEW process group inside the terminal's session: not the foreground group, the same condition
        # as `curl | sudo sh`, where sudo leaves the command outside the terminal's foreground group
        p = subprocess.Popen(cmd, preexec_fn=lambda: os.setpgid(0, 0))
        while True:
            try: sys.exit(p.wait())
            except KeyboardInterrupt: pass
    os.execvp(cmd[0], cmd)
out = ""; t0 = time.time(); stage = 0; stopped = False; rc = None
while True:
    r, _, _ = select.select([fd], [], [], 0.1)
    if r:
        try: d = os.read(fd, 65536)
        except OSError: d = b""
        if not d: break
        out += d.decode("utf-8", "replace")
    if stage < len(spec["steps"]):
        st = spec["steps"][stage]
        if st["wait"] in out and time.time() - t0 >= st.get("not_before", 0):
            time.sleep(st.get("delay", 0.3)); os.write(fd, st["send"].encode().decode("unicode_escape").encode("latin1")); stage += 1
    try:
        w = os.waitpid(pid, os.WNOHANG)
        if w[0]:
            rc = os.waitstatus_to_exitcode(w[1]); break
        # stopped (SIGTTIN)? /proc is Linux only; ps works on both
        ps = subprocess.run(["ps", "-A", "-o", "stat=,args="], capture_output=True, text=True).stdout.splitlines()
        if any(l.strip().startswith("T") and ("install.sh" in l or "run-installer" in l) for l in ps): stopped = True
    except ChildProcessError: break
    if time.time() - t0 > timeout:
        try: os.killpg(pid, signal.SIGKILL)
        except Exception: pass
        try: os.kill(pid, signal.SIGKILL)
        except Exception: pass
        rc = "TIMEOUT"; break
if rc is None:
    try: rc = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    except ChildProcessError: rc = -1
dur = time.time() - t0
print(json.dumps({"rc": rc, "dur": round(dur, 1), "stopped": stopped, "out": out}))
PY
run() { python3 -I "$t/pty.py" "$@"; }
field() { python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); v=d[sys.argv[1]]; print(v if not isinstance(v,bool) else int(v))' "$1"; }
lt() { python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) < float(sys.argv[2]) else 1)' "$1" "$2"; }
survivors() { ps -A -o args= | grep -E "[r]un-installer.sh|[s]cripts/install.sh --dry-run" | head -3; }

# 1. get.sh piped into sudo (the broken form): refuses at once, nothing changed, exit 2 (never a hang)
if [ -n "$SUDO" ]; then cmd1=(sh -c "cat '$t/get.sh' | sudo sh"); else cmd1=(sh -c "cat '$t/get.sh' | SUDO_USER=tester sh"); fi
r=$(run fg 20 '{"steps":[]}' "${cmd1[@]}")
{ [ "$(field rc <<<"$r")" != TIMEOUT ] && lt "$(field dur <<<"$r")" 10; } && ok || bad "get.sh piped into sudo hung or took long: $(head -c 300 <<<"$r")"
[ "$(field rc <<<"$r")" = 2 ] && ok || bad "get.sh piped into sudo did not exit 2: $(head -c 400 <<<"$r")"
field out <<<"$r" | grep -q 'piped into sudo' && field out <<<"$r" | grep -q 'sudo sh -c "$(curl -fsSL https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh)"' && ok || bad "the fail-fast card lacks the working command: $(field out <<<"$r" | head -c 500)"
field out <<<"$r" | grep -q 'Nothing was changed' && ok || bad "the fail-fast card does not say nothing was changed"

# 2. the working form, `sudo sh -c "$(cat get.sh)"`: no refusal (get.sh --demo: no questions, nothing real; exits 3)
if [ -n "$SUDO" ]; then cmd2=(sh -c "sudo sh -c \"\$(cat '$t/get.sh')\" sh --demo"); else cmd2=(sh -c "SUDO_USER=tester sh -c \"\$(cat '$t/get.sh')\" sh --demo"); fi
r=$(run fg 40 '{"steps":[]}' "${cmd2[@]}")
{ [ "$(field rc <<<"$r")" = 3 ] && ! field out <<<"$r" | grep -q 'piped into sudo'; } && ok || bad "the sudo sh -c \"\$(...)\" form was refused or misbehaved: $(head -c 400 <<<"$r")"

# 3. the installer asked a question in a normal foreground pty: the typed answer is READ and Ctrl-C ends it within 5 s
r=$(run fg 60 '{"steps":[{"wait":"Question 1 of 2","send":"core.example.com\\n","delay":1.0},{"wait":"points at 203.0.113.7: this machine","send":"\\x03","delay":2.0}]}' sh "$t/run-installer.sh")
field out <<<"$r" | grep -q 'Question 1 of 2' && ok || bad "the foreground installer showed no Question 1 of 2: $(field out <<<"$r" | tail -c 300)"
field out <<<"$r" | grep -q 'core.example.com points at 203.0.113.7: this machine' && ok || bad "the typed answer was not read (no DNS result for it): $(field out <<<"$r" | tail -c 300)"
{ ! field out <<<"$r" | grep -q 'HOSTNAME' && ! field out <<<"$r" | grep -q 'Waiting for your answer'; } && ok || bad "the question still shows the variable name or the waiting line"
field out <<<"$r" | grep -q '╭' && field out <<<"$r" | grep -q '╯' && ok || bad "the question is not drawn as a rounded box in a UTF-8 terminal"
{ [ "$(field rc <<<"$r")" != TIMEOUT ] && lt "$(field dur <<<"$r")" 40; } && ok || bad "Ctrl-C did not end the installer: $(head -c 200 <<<"$r")"
sleep 0.5; [ -z "$(survivors)" ] && ok || bad "a process survived Ctrl-C: $(survivors)"

# 4. the defence in depth: the installer does not own the terminal (background group, as under `curl | sudo sh`):
#    it must say so and exit within 10 s instead of being stopped at the first read
r=$(run bg 25 '{"steps":[]}' sh "$t/run-installer.sh")
{ [ "$(field rc <<<"$r")" != TIMEOUT ] && [ "$(field stopped <<<"$r")" = 0 ]; } 2>/dev/null && ok || bad "the installer was STOPPED (SIGTTIN) or hung at its first question: $(head -c 300 <<<"$r")"
{ field out <<<"$r" | grep -q 'does not have the terminal' && field out <<<"$r" | grep -q 'sudo sh -c'; } && ok || bad "no clear message when the terminal is not attached: $(field out <<<"$r" | tail -c 500)"
lt "$(field dur <<<"$r")" 12 && ok || bad "the not-attached refusal took too long"
sleep 0.5; [ -z "$(survivors)" ] && ok || bad "a process survived the refusal: $(survivors)"

# 5. with a REAL sudo (CI): the same wrapper piped into sudo sh must not hang either
if [ -n "$SUDO" ]; then
  r=$(run fg 40 '{"steps":[]}' sh -c "cat '$t/run-installer.sh' | sudo sh")
  { [ "$(field rc <<<"$r")" != TIMEOUT ] && [ "$(field stopped <<<"$r")" = 0 ]; } 2>/dev/null && ok || bad "the installer piped into a real sudo hung (SIGTTIN): $(head -c 300 <<<"$r")"
  field out <<<"$r" | grep -q 'does not have the terminal' && ok || bad "piped into a real sudo: no clear message: $(field out <<<"$r" | tail -c 400)"
else
  echo "pty-test: no passwordless sudo here: the real-sudo checks were NOT RUN (the process-group condition was used instead)" >&2
fi

# 6. flow control is off while the installer runs (a stray Ctrl-S must not look like a freeze) and comes back at exit
r=$(run fg 20 '{"steps":[]}' bash -c '. "'"$ROOT"'/scripts/install/ui.sh"; ui_init; ui_traps; ui_tty_init; echo "IN:$(stty -a </dev/tty | grep -o -e "-\{0,1\}ixon" | head -1)"; ui_exit; echo "OUT:$(stty -a </dev/tty | grep -o -e "-\{0,1\}ixon" | head -1)"')
field out <<<"$r" | grep -q 'IN:-ixon' && ok || bad "stty -ixon was not set while the installer runs: $(field out <<<"$r" | tail -c 200)"
field out <<<"$r" | grep -q 'OUT:ixon' && ok || bad "the terminal's flow control was not restored at exit: $(field out <<<"$r" | tail -c 200)"

# 7. the foreground guard runs before EVERY read from the terminal, not only the first (static: a read without it fails the test)
reads=$(grep -c '</dev/tty' "$ROOT/scripts/install.sh"); guarded=$(grep '</dev/tty' "$ROOT/scripts/install.sh" | grep -c 'need_terminal')
unguarded=$(awk '/read .*<\/dev\/tty/ && !/need_terminal/ { print FILENAME": "FNR": "$0 }' "$ROOT/scripts/install.sh" | grep -v 'ui_read()' | grep -v 'yes_no()' | grep -v 'uninstall' | head -3)
{ grep -q '^ui_read() { need_terminal' "$ROOT/scripts/install.sh" && grep -q '^yes_no() { local a; need_terminal' "$ROOT/scripts/install.sh" && [ -z "$unguarded" ]; } && ok || bad "a read from the terminal is not preceded by need_terminal ($reads reads, $guarded guarded): $unguarded"

# 8. N6: get.sh asks its two questions (pc_ask) in step 1, before anything is installed: a typed answer is read in a real
#    foreground pty (an invalid one is asked again), then the DNS check (stubbed) runs on it
cat >"$t/ask-step1.sh" <<EOF
PATH="$t/shim:\$PATH"; . "$ROOT/scripts/install/ui.sh"; . "$ROOT/scripts/install/precheck.sh"
ui_init; ui_traps
pc_ask AINKRAD_HOSTNAME "What is the public DNS name of this Core?" core.yourdomain.com pc_valid_hostname
pc_ask AINKRAD_ACME_EMAIL "What email should Let's Encrypt use for expiry notices?" you@example.com pc_valid_email
pc_dns "\$AINKRAD_HOSTNAME"
echo "ANSWERS:\$AINKRAD_HOSTNAME:\$AINKRAD_ACME_EMAIL"
EOF
r=$(run fg 40 '{"steps":[{"wait":"What is the public DNS name","send":"not a name\\n","delay":0.5},{"wait":"That is not valid","send":"core.example.com\\n","delay":0.5},{"wait":"What email should","send":"ops@example.com\\n","delay":0.5}]}' sh "$t/ask-step1.sh")
o=$(field out <<<"$r")
{ grep -q 'That is not valid' <<<"$o" && grep -q 'core.example.com points at 203.0.113.7: this machine' <<<"$o" && grep -q 'ANSWERS:core.example.com:ops@example.com' <<<"$o"; } && ok || bad "the step 1 questions were not read in a real pty, or the DNS check did not run on the answer: $(tail -c 400 <<<"$o")"
l_q=$(grep -n 'What is the public DNS name' <<<"$o" | head -1 | cut -d: -f1); l_d=$(grep -n 'points at 203.0.113.7' <<<"$o" | head -1 | cut -d: -f1)
{ [ -n "$l_q" ] && [ -n "$l_d" ] && [ "$l_q" -lt "$l_d" ]; } && ok || bad "the DNS check ran before the question was asked"
sleep 0.5; [ -z "$(survivors)" ] && ok || bad "a process survived the step 1 questions: $(survivors)"

echo "pty tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
