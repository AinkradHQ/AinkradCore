#!/usr/bin/env bash
# Tests for scripts/get.sh and the guided installer's safety rules, no root, macOS or Linux (run by test.sh): the pinned
# key, the verify-first checks (tampered sums / artefact, wrong key, downgrade, two bundles), a truncated script that must
# execute nothing, secrets that reach the terminal only (never stdout, and no invite at all without a terminal), the SSH
# lockout guard of harden.sh, the argv the guided path really gives install-linux.sh, and the runner restart.
# Each check is one that FAILS when the rule it guards is broken (try it: delete the rule, run this file).
# SC2015: `check && pass || fail` is meant.
# shellcheck disable=SC2015,SC2016
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
  runget() { # SCRIPT RELEASE-DIR: verify-only, no terminal needed
    ( cd "$t" && AINKRAD_GET_VERIFY_ONLY=1 AINKRAD_RELEASE_URL=$2 NO_COLOR=1 sh "$1" ) >"$t/gout" 2>&1 </dev/null
  }
  refused() { # NAME SCRIPT RELEASE-DIR
    if runget "$2" "$3"; then bad "get.sh: $1 was accepted"; elif grep -q 'verify-only: release' "$t/gout"; then bad "get.sh: $1 reported success"; else ok; fi
  }
  mkrel "$t/r"; mkget "$t/get-a.sh" 0.0.0
  runget "$t/get-a.sh" "$t/r/9.9.9" && grep -q 'verify-only: release 9.9.9 verified' "$t/gout" && ok || { bad "get.sh: a good signed release was refused"; cat "$t/gout" >&2; }
  # tampered SHA256SUMS
  mkrel "$t/r"; sed -i.b '1s/^./0/' "$t/r/9.9.9/SHA256SUMS"; refused "tampered SHA256SUMS" "$t/get-a.sh" "$t/r/9.9.9"
  # tampered artefact
  mkrel "$t/r"; printf 'Z' | dd of="$t/r/9.9.9/ainkrad-runner-9.9.9-$T" bs=1 seek=3 conv=notrunc 2>/dev/null; refused "tampered artefact" "$t/get-a.sh" "$t/r/9.9.9"
  # tampered installer bundle
  mkrel "$t/r"; printf 'Z' | dd of="$t/r/9.9.9/ainkrad-core-installer-9.9.9.tar.gz" bs=1 seek=20 conv=notrunc 2>/dev/null; refused "tampered installer bundle" "$t/get-a.sh" "$t/r/9.9.9"
  # the real get.sh (real pinned key) against a release signed by another key
  mkrel "$t/r"; refused "a release signed with the wrong key" "$GET" "$t/r/9.9.9"
  # downgrade: signed 9.9.9 but this get.sh was built from 9.9.10
  mkrel "$t/r"; mkget "$t/get-new.sh" 9.9.10; refused "a signed release older than the build" "$t/get-new.sh" "$t/r/9.9.9"
  grep -q 'no downgrade' "$t/gout" && ok || bad "get.sh: the downgrade refusal does not say why"
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
for c in $cuts; do
  head -c "$c" "$GET" >"$t/cut.sh"
  ( cd "$t/empty" && NO_COLOR=1 AINKRAD_RELEASE_URL=/nonexistent sh "$t/cut.sh" ) >"$t/cout" 2>&1 </dev/null
  if grep -qE 'Ainkrad Core|\[[0-9]/4\]|Stopped:' "$t/cout" || [ -n "$(ls -A "$t/empty")" ]; then trunc_bad=1; bad "get.sh cut at byte $c of $len ran something"; fi
done
[ "$trunc_bad" = 0 ] && ok

# --- secrets go to the terminal only; no terminal means no invite and no backup key at all ---
R=age1$(printf 'q%.0s' $(seq 58))
mkdir -p "$t/stub" "$t/home"
cat >"$t/stub/ainkrad-core-server" <<EOF
#!/bin/sh
echo "\$*" >>"$t/calls"
case \$1 in
  pairing-invite) echo 'ainkrad://connect?host=h.example.net&fp=FPRINT&secret=TESTSECRET123' ;;
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
PY
grep -q '^NOTTY_LEAK 0$' "$t/pyout" && ok || bad "no terminal: a secret reached stdout"
grep -q '^NOTTY_CALLED 0$' "$t/pyout" && ok || bad "no terminal: the invite or the backup key was created anyway"
grep -q '^NOTTY_CMD 1$' "$t/pyout" && ok || bad "no terminal: the command to run later was not printed"
grep -q '^NOTTY_RC 1$' "$t/pyout" && ok || bad "no terminal: guided_invite did not return 2"
grep -q '^TTY_SHOWN 1$' "$t/pyout" && ok || { bad "with a terminal: the secrets were not shown on it"; cat "$t/pyout" >&2; }
grep -q '^TTY_STDOUT_LEAK 0$' "$t/pyout" && ok || bad "with a terminal: a secret also reached stdout"
grep -q '^TTY_CALLED 1$' "$t/pyout" && ok || bad "with a terminal: the Core commands were not run"

# --- harden.sh: key-only SSH only when it cannot lock the installing user out ---
sshd_case() { # NAME WANT(0|1) KEYS-CONTENT|- LOG PEERS
  local h="$t/sshhome.$RANDOM" rc=0
  mkdir -p "$h/.ssh"; [ "$3" = - ] || printf '%b' "$3" >"$h/.ssh/authorized_keys"
  printf '%b' "$4" >"$h/log"
  ( AINKRAD_HARDEN_SOURCE_ONLY=1 AINKRAD_TEST_HOME=$h AINKRAD_SSH_LOG=$h/log AINKRAD_TEST_PEERS="$5" SUDO_USER=ops
    # shellcheck source=scripts/host/harden.sh
    . "$ROOT/scripts/host/harden.sh"; sshd_safe ) >/dev/null 2>&1 || rc=1
  [ "$rc" = "$2" ] && ok || bad "harden.sh sshd guard: $1 (want rc $2, got $rc)"
}
KEY='ssh-ed25519 AAAAC3Nza test@laptop\n'
PUBLOG='sshd[1]: Accepted publickey for ops from 198.51.100.7 port 5000 ssh2\n'
PWLOG='sshd[1]: Accepted password for ops from 198.51.100.7 port 5000 ssh2\n'
sshd_case "no authorized_keys file" 1 - "$PUBLOG" ""
sshd_case "only comments in authorized_keys" 1 '# nothing\n\n' "$PUBLOG" ""
sshd_case "a key, session logged in with a key" 0 "$KEY" "$PUBLOG" "198.51.100.7"
sshd_case "a key, session logged in with a password" 1 "$KEY" "$PWLOG" "198.51.100.7"
sshd_case "a key, session not in the log" 1 "$KEY" "" "198.51.100.7"
sshd_case "a key, no SSH session (console or cloud-init)" 0 "$KEY" "" ""
# the sshd file is only written inside the guard
g=$(grep -n '^if sshd_safe' "$ROOT/scripts/host/harden.sh" | head -1 | cut -d: -f1); w=$(grep -n '70-ainkrad.conf' "$ROOT/scripts/host/harden.sh" | head -1 | cut -d: -f1)
{ [ -n "$g" ] && [ -n "$w" ] && [ "$g" -lt "$w" ]; } && ok || bad "harden.sh writes the sshd file outside the sshd_safe guard"
grep -q 'iptables -F INPUT' "$ROOT/scripts/host/harden.sh" && bad "harden.sh flushes INPUT again" || ok

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

# --- install-linux.sh restarts a running runner when its flags change (dry run prints the command) ---
bash "$ROOT/deploy/install-linux.sh" --dry-run --pty --binary /x --ptyhost /y >"$t/il1" 2>&1 </dev/null
grep -q 'systemctl try-restart ainkrad-runner' "$t/il1" && ok || bad "install-linux.sh does not try-restart the runner when its args change"
bash "$ROOT/deploy/install-linux.sh" --dry-run --binary /x >"$t/il2" 2>&1 </dev/null
grep -q 'try-restart' "$t/il2" && bad "install-linux.sh restarts the runner although nothing changed" || ok

echo "get/guided tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
