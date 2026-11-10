#!/usr/bin/env bash
# Tests for scripts/get.sh and the guided installer's safety rules, no root, macOS or Linux (run by test.sh): the pinned
# key, the verify-first checks (tampered sums / artefact, wrong key, downgrade, two bundles), a truncated script that must
# execute nothing, secrets that reach the terminal only (never stdout, and no invite at all without a terminal), the SSH
# argv the guided path really gives install-linux.sh. (harden.sh and the runner restart: harden-test.sh.)
# Each check is one that FAILS when the rule it guards is broken (try it: delete the rule, run this file).
# SC2015: `check && pass || fail` is meant.
# SC2031/SC2154/SC2329: the sourced libraries and the stub functions run in subshells on purpose.
# shellcheck disable=SC2015,SC2016,SC2031,SC2154,SC2329
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
GET=$ROOT/scripts/get.sh
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*" >&2; }
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT

# --- the key pinned in get.sh is the release key file ---
pinned=$(sed -n "/KEY_FILE='/,/'\$/p" "$GET" | sed "s/.*KEY_FILE='//; s/'\$//")
[ "$pinned" = "$(cat "$ROOT/scripts/release/ainkrad-release.pub")" ] && ok || bad "the key pinned in get.sh differs from scripts/release/ainkrad-release.pub"
[ "$(grep -c . "$GET" | head -1)" -gt 0 ] && [ "$(tail -n1 "$GET")" = '{ main "$@"; }' ] && ok || bad "the last line of get.sh is not the single call of main"

# --- verify-first: a fake release signed with a throwaway key; get.sh with that key pinned, verify-only ---
if command -v minisign >/dev/null; then
  case "$(uname -m)" in x86_64 | amd64) T=linux-x86_64 ;; *) T=linux-arm64 ;; esac
  minisign -G -W -f -p "$t/a.pub" -s "$t/a.key" >/dev/null
  mkrel() { # DIR: a signed 9.9.9 release
    rm -rf "$1"; mkdir -p "$1/in/ainkrad-core-installer-9.9.9"; : >"$1/in/ainkrad-core-installer-9.9.9/x"
    mkdir "$1/9.9.9"
    for b in ainkrad-core-server ainkrad-runner ainkradctl ainkrad-ptyhost; do printf '#!/bin/sh\necho %s\n' "$b" >"$1/9.9.9/$b-9.9.9-$T"; done
    tar -czf "$1/9.9.9/ainkrad-core-installer-9.9.9.tar.gz" -C "$1/in" ainkrad-core-installer-9.9.9
    cp "$GET" "$1/9.9.9/get.sh"
    bash "$ROOT/scripts/release/sign.sh" "$1/9.9.9" "$t/a.key" >/dev/null
  }
  # get.sh with the throwaway key pinned and MIN_VERSION $2 (the real file is used for the wrong-key case)
  mkget() {
    python3 - "$GET" "$t/a.pub" "$1" "$2" <<'PY'
import re, sys
s = open(sys.argv[1]).read(); pub = open(sys.argv[2]).read().strip().split("\n")
s = s.replace("KEY_ID=FB3618BCFCA5393E", "KEY_ID=" + pub[0].split()[-1])
s = re.sub(r"KEY_FILE='.*?'\n", lambda m: "KEY_FILE='" + pub[0] + "\n" + pub[1] + "'\n", s, count=1, flags=re.S)
s = re.sub(r"^MIN_VERSION=[0-9.]*", "MIN_VERSION=" + sys.argv[4], s, flags=re.M)
open(sys.argv[3], "w").write(s)
PY
  }
  runget() { # SCRIPT RELEASE-DIR [ENV=VALUE]: verify-only, no terminal needed
    ( cd "$t" && env AINKRAD_GET_VERIFY_ONLY=1 AINKRAD_RELEASE_URL="$2" NO_COLOR=1 ${3:+"$3"} sh "$1" ) >"$t/gout" 2>&1 </dev/null
  }
  refused() { # NAME SCRIPT RELEASE-DIR [ENV=VALUE]
    if runget "$2" "$3" "${4:-}"; then bad "get.sh: $1 was accepted"; elif grep -q 'verify-only: release' "$t/gout"; then bad "get.sh: $1 reported success"; else ok; fi
  }
  mkrel "$t/r"; mkget "$t/get-a.sh" 0.0.0
  runget "$t/get-a.sh" "$t/r/9.9.9" && grep -q 'verify-only: release 9.9.9 verified' "$t/gout" && ok || { bad "get.sh: a good signed release was refused"; cat "$t/gout" >&2; }
  # tampered SHA256SUMS
  mkrel "$t/r"; sed -i.b -e '1s/^0/1/' -e t -e '1s/^./0/' "$t/r/9.9.9/SHA256SUMS"; refused "tampered SHA256SUMS" "$t/get-a.sh" "$t/r/9.9.9"
  # tampered artefact
  mkrel "$t/r"; printf 'Z' | dd of="$t/r/9.9.9/ainkrad-runner-9.9.9-$T" bs=1 seek=3 conv=notrunc 2>/dev/null; refused "tampered artefact" "$t/get-a.sh" "$t/r/9.9.9"
  # tampered installer bundle
  mkrel "$t/r"; printf 'Z' | dd of="$t/r/9.9.9/ainkrad-core-installer-9.9.9.tar.gz" bs=1 seek=20 conv=notrunc 2>/dev/null; refused "tampered installer bundle" "$t/get-a.sh" "$t/r/9.9.9"
  # the real get.sh (real pinned key) against a release signed by another key
  mkrel "$t/r"; refused "a release signed with the wrong key" "$GET" "$t/r/9.9.9"
  # downgrade: signed 9.9.9 but this get.sh was built from 9.9.10
  mkrel "$t/r"; mkget "$t/get-new.sh" 9.9.10; refused "a signed release older than the build" "$t/get-new.sh" "$t/r/9.9.9"
  grep -q 'no downgrade' "$t/gout" && ok || bad "get.sh: the downgrade refusal does not say why"
  runget "$t/get-a.sh" "$t/r/9.9.9" && grep -q 'version floor 0.0.0 (from this get.sh' "$t/gout" && grep -q 'AINKRAD_MIN_VERSION is not set' "$t/gout" && ok || bad "get.sh does not print the effective floor and where it came from"
  runget "$t/get-a.sh" "$t/r/9.9.9" AINKRAD_MIN_VERSION=9.9.9 && grep -q 'version floor 9.9.9 (from AINKRAD_MIN_VERSION)' "$t/gout" && ok || bad "get.sh does not say the floor came from AINKRAD_MIN_VERSION"
  # AINKRAD_MIN_VERSION (from the app's command) raises the floor above the one stamped in get.sh; the higher applies
  mkrel "$t/r"; refused "a release below AINKRAD_MIN_VERSION" "$t/get-a.sh" "$t/r/9.9.9" AINKRAD_MIN_VERSION=9.9.10
  runget "$t/get-a.sh" "$t/r/9.9.9" AINKRAD_MIN_VERSION=9.9.9 && ok || bad "get.sh: AINKRAD_MIN_VERSION equal to the release was refused"
  mkrel "$t/r"; refused "a malformed AINKRAD_MIN_VERSION" "$t/get-a.sh" "$t/r/9.9.9" AINKRAD_MIN_VERSION=latest
  mkrel "$t/r"; mkget "$t/get-hi.sh" 9.9.10; refused "AINKRAD_MIN_VERSION lower than the stamped floor must not lower it" "$t/get-hi.sh" "$t/r/9.9.9" AINKRAD_MIN_VERSION=0.0.1
  # exactly one installer bundle
  mkrel "$t/r"; cp "$t/r/9.9.9/ainkrad-core-installer-9.9.9.tar.gz" "$t/r/9.9.9/ainkrad-core-installer-9.9.8.tar.gz"
  bash "$ROOT/scripts/release/sign.sh" "$t/r/9.9.9" "$t/a.key" >/dev/null; refused "two installer bundles" "$t/get-a.sh" "$t/r/9.9.9"
  # get.sh itself is among the signed files
  mkrel "$t/r"; grep -q ' get.sh$' "$t/r/9.9.9/SHA256SUMS" && ok || bad "get.sh is not in the signed SHA256SUMS"
else
  echo "get-test: minisign not installed: verify-first checks NOT RUN" >&2
fi

# --- a truncated get.sh executes nothing (cut at many points, including inside the last line) ---
mkdir "$t/empty"; len=$(wc -c <"$GET" | tr -d ' ')
cuts="1 2 3 7 $((len - 2)) $((len - 3)) $((len - 8)) $((len - 12)) $((len - 15))"
off=60; while [ "$off" -lt "$len" ]; do cuts="$cuts $off"; off=$((off + 61)); done
trunc_bad=0
shells="sh"; command -v dash >/dev/null && shells="sh dash"
for c in $cuts; do
  head -c "$c" "$GET" >"$t/cut.sh"
  for sh in $shells; do
    ( cd "$t/empty" && NO_COLOR=1 AINKRAD_RELEASE_URL=/nonexistent "$sh" "$t/cut.sh" ) >"$t/cout" 2>&1 </dev/null
    if grep -qE 'Ainkrad Core|\[[0-9]/4\]|Stopped:' "$t/cout" || [ -n "$(ls -A "$t/empty")" ]; then trunc_bad=1; bad "get.sh cut at byte $c of $len ran something under $sh"; fi
  done
done
[ "$trunc_bad" = 0 ] && ok

# --- secrets go to the terminal only; no terminal means no invite and no backup key at all ---
R=age1$(printf 'q%.0s' $(seq 58))
mkdir -p "$t/stub" "$t/home"
cat >"$t/stub/ainkrad-core-server" <<EOF
#!/bin/sh
echo "\$*" >>"$t/calls"
case \$1 in
  pairing-invite) echo 'ainkrad://connect?host=h.example.net&fp=FPRINT&secret=TESTSECRET123'; [ -z "\$STUB_FAIL" ] || exit 1 ;;
  backup-keygen) echo '# public key: $R'; echo 'AGE-SECRET-KEY-1TESTIDENTITY' ;;
esac
EOF
chmod 755 "$t/stub/ainkrad-core-server"
cat >"$t/h.sh" <<EOF
. "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"
BIN="$t/stub" ETC="$t/etc" CORE_HOME="$t/home" DRY=0 GUIDED=1 A_HOSTNAME=h.example.net A_BINARY_DIR="$t/stub" SIGNER=sig
say() { printf '%s\n' "\$*"; }; warn() { echo "\$*" >&2; }; die() { echo "die: \$*" >&2; exit 1; }
env_get() { :; }; runuser() { shift 3; "\$@"; }
ui_init
guided_backup_key
rc=0; guided_invite || rc=\$?
[ "\$rc" != 0 ] || guided_show_invite
guided_summary "\$rc" >/dev/null
echo "invite-rc=\$rc"
EOF
python3 -I - "$t" <<'PY' >"$t/pyout" 2>&1
import os, pty, subprocess, sys
t = sys.argv[1]
def calls():
    try: return open(t + "/calls").read()
    except FileNotFoundError: return ""
# 1. no controlling terminal: stdout captured, as cloud-init / CI / `> log` do
open(t + "/calls", "w").close()
r = subprocess.run(["bash", t + "/h.sh"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                   start_new_session=True, text=True)
out = r.stdout
print("NOTTY_LEAK", int("TESTSECRET123" in out or "AGE-SECRET-KEY" in out or "ainkrad://connect" in out))
print("NOTTY_CALLED", int("pairing-invite" in calls() or "backup-keygen" in calls()))
print("NOTTY_CMD", int("pairing-invite" in out and "sudo -u ainkrad" in out))
print("NOTTY_RC", int("invite-rc=2" in out))
# 2. a terminal: the secrets appear there, and not on the redirected stdout
open(t + "/calls", "w").close()
pid, fd = pty.fork()
if pid == 0:
    os.execvp("bash", ["bash", "-c", 'exec bash "$0" > "$1"', t + "/h.sh", t + "/tty-stdout"])
data = b""
while True:
    try: chunk = os.read(fd, 4096)
    except OSError: break
    if not chunk: break
    data += chunk
os.waitpid(pid, 0)
tty = data.decode(errors="replace"); so = open(t + "/tty-stdout").read()
print("TTY_SHOWN", int("TESTSECRET123" in tty and "AGE-SECRET-KEY-1TESTIDENTITY" in tty))
print("TTY_STDOUT_LEAK", int("TESTSECRET123" in so or "AGE-SECRET-KEY" in so or "ainkrad://connect" in so))
print("TTY_CALLED", int("pairing-invite" in calls() and "backup-keygen" in calls()))
# 3. a terminal, but the command exits 1 after printing a link: a refusal, not a success
os.environ["STUB_FAIL"] = "1"
pid, fd = pty.fork()
if pid == 0:
    os.execvp("bash", ["bash", "-c", 'exec bash "$0" > "$1"', t + "/h.sh", t + "/tty-stdout3"])
data = b""
while True:
    try: chunk = os.read(fd, 4096)
    except OSError: break
    if not chunk: break
    data += chunk
os.waitpid(pid, 0)
tty3 = data.decode(errors="replace"); so3 = open(t + "/tty-stdout3").read()
print("FAILLINK_SHOWN", int("TESTSECRET123" in tty3))
print("FAILLINK_RC", int("invite-rc=1" in so3))
PY
grep -q '^NOTTY_LEAK 0$' "$t/pyout" && ok || bad "no terminal: a secret reached stdout"
grep -q '^NOTTY_CALLED 0$' "$t/pyout" && ok || bad "no terminal: the invite or the backup key was created anyway"
grep -q '^NOTTY_CMD 1$' "$t/pyout" && ok || bad "no terminal: the command to run later was not printed"
grep -q '^NOTTY_RC 1$' "$t/pyout" && ok || bad "no terminal: guided_invite did not return 2"
grep -q '^TTY_SHOWN 1$' "$t/pyout" && ok || { bad "with a terminal: the secrets were not shown on it"; cat "$t/pyout" >&2; }
grep -q '^TTY_STDOUT_LEAK 0$' "$t/pyout" && ok || bad "with a terminal: a secret also reached stdout"
grep -q '^TTY_CALLED 1$' "$t/pyout" && ok || bad "with a terminal: the Core commands were not run"
grep -q '^FAILLINK_SHOWN 0$' "$t/pyout" && grep -q '^FAILLINK_RC 1$' "$t/pyout" && ok || bad "a non-zero exit that printed a link was treated as success"

# --- what the guided path really passes to install-linux.sh (argv recorded by a stub) ---
tree=$t/tree; mkdir -p "$tree/scripts" "$tree/deploy"
cp "$ROOT/scripts/install.sh" "$tree/scripts/"; cp -R "$ROOT/scripts/install" "$ROOT/scripts/host" "$tree/scripts/"
cp -R "$ROOT/deploy/systemd" "$ROOT/deploy/install-core-linux.sh" "$tree/deploy/"
printf '#!/bin/sh\necho "$*" >>"%s"\n' "$t/argv" >"$tree/deploy/install-linux.sh"
mkdir "$t/gbin"; for n in ainkrad-core-server ainkradctl ainkrad-runner ainkrad-ptyhost; do printf '#!/bin/sh\n' >"$t/gbin/$n"; done
: >"$t/argv"
AINKRAD_HOSTNAME=core.example.com AINKRAD_ACME_EMAIL=ops@example.com bash "$tree/scripts/install.sh" --dry-run --binary "$t/gbin" >"$t/argv.out" 2>&1 </dev/null
[ -s "$t/argv" ] && grep -q -- '--pty' "$t/argv" && ok || { bad "the stub install-linux.sh was not called with --pty (the check below would prove nothing)"; cat "$t/argv.out" >&2; }
grep -qE -- '--root|--exec' "$t/argv" && bad "the guided path passed --root or --exec to install-linux.sh: $(cat "$t/argv")" || ok



# --- host hardening is OPT-IN: the default install (guided and non-guided) never runs harden.sh ---
dry() { # NAME env...: guided dry run in the recorded tree; output in $t/oo
  ( cd "$t" && env AINKRAD_HOSTNAME=core.example.com AINKRAD_ACME_EMAIL=ops@example.com "$@" bash "$tree/scripts/install.sh" --dry-run --binary "$t/gbin" ) >"$t/oo" 2>&1 </dev/null
}
dryargs() { ( cd "$t" && AINKRAD_HOSTNAME=core.example.com AINKRAD_ACME_EMAIL=ops@example.com bash "$tree/scripts/install.sh" --dry-run --binary "$t/gbin" "$@" ) >"$t/oo" 2>&1 </dev/null; }
dry X=1
grep -q '^+ env .*harden.sh' "$t/oo" && bad "the default guided install runs harden.sh" || ok
grep -q 'Host hardening: skipped (opt-in)' "$t/oo" && ok || bad "the step list does not show hardening as 'skipped (opt-in)'"
grep -qF "Host hardening NOT applied: SSH config and firewall untouched. Use your provider's firewall; re-run with --harden or use the app's Core machine screen later." "$t/oo" && ok || bad "the summary lacks the plain 'hardening NOT applied' message"
grep -qiE 'Firewall   |key-only|automatic security updates|sshd_config|swapoff|sysctl|rejects every other' "$t/oo" && bad "the default guided output claims or touches hardening: $(grep -iE 'Firewall   |key-only|automatic security|sshd_config|swapoff|sysctl|rejects every' "$t/oo" | head -3)" || ok
dryargs --harden; grep -q '^+ env .*harden.sh' "$t/oo" && ok || bad "--harden did not run harden.sh"
grep -q 'NOT applied' "$t/oo" && bad "--harden still says hardening was not applied" || ok
dry AINKRAD_HARDEN=yes; grep -q '^+ env .*harden.sh' "$t/oo" && ok || bad "AINKRAD_HARDEN=yes did not run harden.sh"
dry AINKRAD_HARDEN=no; grep -q '^+ env .*harden.sh' "$t/oo" && bad "AINKRAD_HARDEN=no ran harden.sh" || ok
if dry AINKRAD_HARDEN=maybe; then bad "AINKRAD_HARDEN=maybe was accepted"; else grep -q 'must be yes or no' "$t/oo" && ok || bad "AINKRAD_HARDEN=maybe died without the message"; fi
( cd "$t" && AINKRAD_HARDEN=no AINKRAD_HOSTNAME=core.example.com AINKRAD_ACME_EMAIL=ops@example.com bash "$tree/scripts/install.sh" --harden --dry-run --binary "$t/gbin" ) >"$t/oo" 2>&1 </dev/null
grep -q '^+ env .*harden.sh' "$t/oo" && ok || bad "the --harden flag must win over AINKRAD_HARDEN=no"
# non-guided (--config): HARDEN unset means no; HARDEN=yes still hardens, unchanged
Rk=age1$(printf 'q%.0s' $(seq 58))
printf 'BINARY_DIR=%s\nHOSTNAME=core.example.com\nACME_CONTACT=ops@example.com\nBACKUP=local\nBACKUP_RECIPIENT=%s\n' "$t/gbin" "$Rk" >"$t/ans-default"
{ cat "$t/ans-default"; echo HARDEN=yes; } >"$t/ans-yes"
( cd "$t" && bash "$tree/scripts/install.sh" --config "$t/ans-default" --dry-run ) >"$t/oo" 2>&1 </dev/null
grep -q '^+ env .*harden.sh' "$t/oo" && bad "the default non-guided install runs harden.sh" || { grep -q 'Host hardening skipped' "$t/oo" && ok || bad "the non-guided default does not say hardening was skipped"; }
( cd "$t" && bash "$tree/scripts/install.sh" --config "$t/ans-yes" --dry-run ) >"$t/oo" 2>&1 </dev/null
grep -q '^+ env .*harden.sh' "$t/oo" && ok || bad "HARDEN=yes in an answers file no longer hardens"
# get.sh: no firewall tooling by default, and a bad AINKRAD_HARDEN dies before anything runs
grep -qE "^ *pkgs='[^']*(iptables|ufw)" "$GET" && bad "get.sh installs firewall tooling unconditionally" || ok
out=$(cd "$t/empty" && AINKRAD_HARDEN=maybe sh "$GET" 2>&1); rc=$?
{ [ "$rc" != 0 ] && grep -q 'must be yes or no' <<<"$out" && ! grep -q 'Checking this machine' <<<"$out"; } && ok || bad "get.sh accepted AINKRAD_HARDEN=maybe or ran on ($rc)"

echo "get/guided tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
