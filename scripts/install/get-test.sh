#!/usr/bin/env bash
# Tests for scripts/get.sh and the guided installer's safety rules, no root, macOS or Linux (run by test.sh): the pinned
# key, the verify-first checks (tampered sums / artefact, wrong key, downgrade, two bundles), a truncated script that must
# execute nothing, secrets that reach the terminal only (never stdout, and no invite at all without a terminal), the SSH
# lockout guard of harden.sh, the argv the guided path really gives install-linux.sh, and the runner restart.
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

# --- harden.sh (sourced with AINKRAD_HARDEN_SOURCE_ONLY=1; the AINKRAD_TEST_* overrides are honoured only then) ---
KEYLINE='ssh-ed25519 AAAAC3Nza test@laptop\n'
hz() { # run a bash snippet with harden.sh sourced in test mode; $1 = snippet; env from the caller
  ( export AINKRAD_HARDEN_SOURCE_ONLY=1; export SUDO_USER=ops
    # shellcheck source=scripts/host/harden.sh
    . "$ROOT/scripts/host/harden.sh"; eval "$1" ) 2>&1
}
sshd_case() { # NAME WANT(0|1) KEYS-CONTENT|- SSHD_T SS-LINES LOG [nossbin]
  local h="$t/sshhome.$RANDOM" rc=0
  mkdir -p "$h/.ssh"; [ "$3" = - ] || printf '%b' "$3" >"$h/.ssh/authorized_keys"
  printf '%b' "$4" >"$h/sshd_t"; printf '%b' "$5" >"$h/ss"; printf '%b' "$6" >"$h/log"
  local snip=sshd_safe
  [ -z "${7:-}" ] || snip='command() { if [ "$1" = -v ] && [ "$2" = ss ]; then return 1; fi; builtin command "$@"; }; unset AINKRAD_TEST_SS; sshd_safe'
  AINKRAD_TEST_HOME=$h AINKRAD_TEST_SSHD_T=$h/sshd_t AINKRAD_TEST_SS=$h/ss AINKRAD_SSH_LOG=$h/log hz "$snip" >/dev/null || rc=1
  [ "$rc" = "$2" ] && ok || bad "harden.sh sshd guard: $1 (want rc $2, got $rc)"
}
SSHT='port 22\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nauthorizedkeyscommand none\ntrustedusercakeys none\n'
SESS='0 0 10.0.0.1:22 198.51.100.7:5000 users:(("sshd",pid=1234,fd=4),("sshd",pid=1200,fd=4))\n'
PUB='Nov 10 06:44:50 h sshd[1200]: Accepted publickey for ops from 198.51.100.7 port 5000 ssh2\n'
PW='Nov 10 06:44:50 h sshd[1200]: Accepted password for ops from 198.51.100.7 port 5000 ssh2\n'
OLDPUB='Nov 09 06:44:50 h sshd[777]: Accepted publickey for ops from 198.51.100.7 port 4000 ssh2\n'
sshd_case "no authorized_keys file" 1 - "$SSHT" "" "$PUB"
sshd_case "only comments in authorized_keys" 1 '# nothing\n\n' "$SSHT" "" "$PUB"
sshd_case "a key, session logged in with a key" 0 "$KEYLINE" "$SSHT" "$SESS" "$PUB"
sshd_case "a key, session logged in with a password" 1 "$KEYLINE" "$SSHT" "$SESS" "$PW"
sshd_case "a key, session not in the log" 1 "$KEYLINE" "$SSHT" "$SESS" ""
sshd_case "a key, this session used a password but the same address had a key login in an older session" 1 "$KEYLINE" "$SSHT" "$SESS" "$PW$OLDPUB"
sshd_case "a key, no SSH session (console or cloud-init)" 0 "$KEYLINE" "$SSHT" "" ""
sshd_case "a key, no ss to look at the sessions (fail closed)" 1 "$KEYLINE" "$SSHT" "" "" nossbin
sshd_case "AuthorizedKeysCommand in use" 1 "$KEYLINE" "${SSHT/authorizedkeyscommand none/authorizedkeyscommand /usr/bin/keys}" "" ""
sshd_case "SSH certificates in use" 1 "$KEYLINE" "${SSHT/trustedusercakeys none/trustedusercakeys /etc/ssh/ca.pub}" "" ""
# a key only in authorized_keys2, and one in a custom AuthorizedKeysFile
h2="$t/h2"; mkdir -p "$h2/.ssh"; printf '%b' "$KEYLINE" >"$h2/.ssh/authorized_keys2"; printf '%b' "$SSHT" >"$h2/sshd_t"; : >"$h2/ss"; : >"$h2/log"
AINKRAD_TEST_HOME=$h2 AINKRAD_TEST_SSHD_T=$h2/sshd_t AINKRAD_TEST_SS=$h2/ss AINKRAD_SSH_LOG=$h2/log hz sshd_safe >/dev/null && ok || bad "harden.sh: a key in authorized_keys2 was not accepted"
h3="$t/h3"; mkdir -p "$h3/.ssh"; printf '%b' "$KEYLINE" >"$h3/.ssh/keys.txt"; printf 'port 22\nauthorizedkeysfile .ssh/keys.txt\nauthorizedkeyscommand none\ntrustedusercakeys none\n' >"$h3/sshd_t"; : >"$h3/ss"; : >"$h3/log"
AINKRAD_TEST_HOME=$h3 AINKRAD_TEST_SSHD_T=$h3/sshd_t AINKRAD_TEST_SS=$h3/ss AINKRAD_SSH_LOG=$h3/log hz sshd_safe >/dev/null && ok || bad "harden.sh: a key in the AuthorizedKeysFile sshd uses was not accepted"
h4="$t/h4"; mkdir -p "$h4/.ssh"; printf '%b' "$KEYLINE" >"$h4/.ssh/authorized_keys2"; : >"$h4/sshd_t"; : >"$h4/ss"; : >"$h4/log"
AINKRAD_TEST_HOME=$h4 AINKRAD_TEST_SSHD_T=$h4/sshd_t AINKRAD_TEST_SS=$h4/ss AINKRAD_SSH_LOG=$h4/log hz sshd_safe >/dev/null && ok || bad "harden.sh: with no sshd -T output the default authorized_keys2 was not read"
# the test overrides are ignored in production (without AINKRAD_HARDEN_SOURCE_ONLY=1 they are unset at the top)
grep -q 'unset AINKRAD_TEST_PEERS AINKRAD_SSH_LOG AINKRAD_TEST_HOME' "$ROOT/scripts/host/harden.sh" && ok || bad "harden.sh no longer drops its test overrides in production"
# production: a copy that prints what is left of the override instead of checking for root
sed 's|^\[ "\$(id -u)" = 0 \] .*|echo "PEERS=${AINKRAD_TEST_PEERS+set}"; exit 0|' "$ROOT/scripts/host/harden.sh" >"$t/harden-prod.sh"
[ "$(AINKRAD_TEST_PEERS=203.0.113.5 AINKRAD_TEST_HOME=/x bash "$t/harden-prod.sh" 2>&1 | grep PEERS=)" = "PEERS=" ] && ok || bad "harden.sh honours AINKRAD_TEST_* overrides outside the install tests"
[ "$(AINKRAD_HARDEN_SOURCE_ONLY=1 AINKRAD_TEST_PEERS=203.0.113.5 bash -c '. "$1"; echo "PEERS=${AINKRAD_TEST_PEERS+set}"' _ "$ROOT/scripts/host/harden.sh")" = "PEERS=set" ] && ok || bad "harden.sh drops the overrides even in test mode"

# --- F2: a non-22 sshd port: the firewall allows it and the peer scan reads it; unknown ports change nothing ---
printf 'port 2222\n' >"$t/t2222"; : >"$t/none"
[ "$(AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none hz ssh_ports)" = 2222 ] && ok || bad "harden.sh: ssh_ports did not read port 2222 from sshd -T"
printf 'LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n' >"$t/l2200"
[ "$(AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/l2200 hz ssh_ports | tr '\n' ' ')" = "2200 2222 " ] && ok || bad "harden.sh: ssh_ports did not add the port sshd really listens on"
fwrun() { # NAME: run apply_firewall with stub tools; log in $t/fw.log; extra setup in $1 (a snippet)
  : >"$t/fw.log"; : >"$t/fw.warn"
  AINKRAD_HARDEN_WARN=$t/fw.warn AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none hz "
    iptables() { echo \"iptables \$*\" >>$t/fw.log; return 0; }; ip6tables() { echo \"ip6tables \$*\" >>$t/fw.log; return 0; }
    netfilter-persistent() { echo netfilter-persistent \$* >>$t/fw.log; }
    $1
    apply_firewall" >/dev/null 2>&1 || true
}
fwrun "fw_persisted() { return 0; }"
grep -q 'iptables -A AINKRAD_IN -p tcp -m state --state NEW --dport 2222 -j ACCEPT' "$t/fw.log" && grep -q 'ip6tables -A AINKRAD_IN -p tcp -m state --state NEW --dport 2222 -j ACCEPT' "$t/fw.log" && ok || bad "harden.sh: the firewall does not allow sshd's port 2222 (IPv4 and IPv6)"
grep -q -- '--dport 22 ' "$t/fw.log" && bad "harden.sh: the firewall allows port 22 although sshd listens on 2222" || ok
grep -q 'netfilter-persistent save' "$t/fw.log" && ok || bad "harden.sh: the iptables rules are not saved"
grep -q -- '-F INPUT' "$t/fw.log" && bad "harden.sh flushes INPUT" || ok
grep -q 'icmp-host-prohibited' "$t/fw.log" && ok || bad "harden.sh: no reject rule in the sanity run (the unknown-ports check below would prove nothing)"
# unknown ports: sshd installed but silent and nothing listening -> no firewall change, a warning
: >"$t/fw.log"; : >"$t/fw.warn"; : >"$t/emptyT"
AINKRAD_HARDEN_WARN=$t/fw.warn AINKRAD_TEST_SSHD_T=$t/emptyT AINKRAD_TEST_SSH_LISTEN=$t/none hz "
  command() { if [ \"\$1\" = -v ] && [ \"\$2\" = sshd ]; then return 0; fi; builtin command \"\$@\"; }
  iptables() { echo \"iptables \$*\" >>$t/fw.log; }; apply_firewall" >/dev/null 2>&1 || true
{ [ ! -s "$t/fw.log" ] && grep -q 'could not determine' "$t/fw.warn"; } && ok || bad "harden.sh changed the firewall although sshd's ports are unknown"
# F1: ufw installed (active or not): its allows (incl. the ssh port) come BEFORE it is enabled; nothing is persisted by iptables
: >"$t/fw.log"
AINKRAD_HARDEN_WARN=$t/fw.warn AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none hz "
  ufw() { echo \"ufw \$*\" >>$t/fw.log; }; fw_persisted() { return 0; }; apply_firewall" >/dev/null 2>&1 || true
a1=$(grep -n 'ufw allow 2222/tcp' "$t/fw.log" | head -1 | cut -d: -f1); e1=$(grep -n 'ufw --force enable' "$t/fw.log" | head -1 | cut -d: -f1)
{ [ -n "$a1" ] && [ -n "$e1" ] && [ "$a1" -lt "$e1" ]; } && ok || bad "harden.sh: with ufw installed the ssh port is not allowed before ufw is enabled"
# F1: rules that will not survive a reboot are said so (and the summary must not claim otherwise)
: >"$t/fw.warn"
AINKRAD_HARDEN_WARN=$t/fw.warn AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none AINKRAD_TEST_RULES_V4=/nonexistent hz "
  iptables() { return 0; }; ip6tables() { return 0; }; command() { if [ \"\$1\" = -v ] && { [ \"\$2\" = ufw ] || [ \"\$2\" = netfilter-persistent ]; }; then return 1; fi; builtin command \"\$@\"; }; apply_firewall" >/dev/null 2>&1 || true
grep -q 'until the next reboot' "$t/fw.warn" && ok || bad "harden.sh: unsaved firewall rules were not reported"

# --- F3: the sshd drop-in is verified with sshd -T; a loser (cloud-init) is removed with a warning ---
dd_="$t/dropin"; mkdir -p "$dd_"; printf 'port 22\npasswordauthentication no\n' >"$t/t_ok"; printf 'port 22\npasswordauthentication yes\n' >"$t/t_bad"
sshdrun() { # SSHD_T-FILE : sshd_safe forced true
  rm -f "$dd_"/*; : >"$t/dd.warn"
  AINKRAD_HARDEN_WARN=$t/dd.warn AINKRAD_TEST_DROPIN=$dd_ AINKRAD_TEST_SSHD_T=$1 hz "sshd_safe() { return 0; }; sshd() { return 0; }; systemctl() { return 0; }; apply_sshd" >/dev/null 2>&1 || true
}
# a real sshd -T is long: a verifying pipe into `grep -q` would die of SIGPIPE under pipefail and wrongly report "not honoured"
{ printf 'port 22\npasswordauthentication no\n'; head -c 300000 /dev/zero | tr '\0' 'x' | fold -w 60 | sed 's/^/filler /'; } >"$t/t_big"
sshdrun "$t/t_big"; { [ -f "$dd_/01-ainkrad.conf" ] && [ ! -s "$t/dd.warn" ]; } && ok || bad "harden.sh: a long sshd -T output made the verification fail (SIGPIPE under pipefail)"
sshdrun "$t/t_ok"; { [ -f "$dd_/01-ainkrad.conf" ] && [ ! -s "$t/dd.warn" ]; } && ok || bad "harden.sh: a verified key-only drop-in was not kept"
sshdrun "$t/t_bad"; { [ ! -f "$dd_/01-ainkrad.conf" ] && grep -q 'did not take' "$t/dd.warn"; } && ok || bad "harden.sh: a drop-in that sshd -T does not honour was kept or not reported"
rm -f "$dd_"/*; : >"$t/dd.warn"; touch "$dd_/70-ainkrad.conf"
AINKRAD_HARDEN_WARN=$t/dd.warn AINKRAD_TEST_DROPIN=$dd_ AINKRAD_TEST_SSHD_T=$t/t_ok hz "sshd_safe() { REASON='no key'; return 1; }; sshd() { return 0; }; systemctl() { return 0; }; apply_sshd" >/dev/null 2>&1 || true
{ [ ! -f "$dd_/01-ainkrad.conf" ] && [ ! -f "$dd_/70-ainkrad.conf" ] && grep -q 'sshd left as it is' "$t/dd.warn"; } && ok || bad "harden.sh: an unsafe host got a drop-in, or the old 70- file was left"
grep -q '01-ainkrad.conf' "$ROOT/scripts/host/harden.sh" && ok || bad "harden.sh does not use the 01- drop-in name"

# --- the firewall summary and the address lookup are printed truthfully / safely ---
fwstate() { # RULES-IN-INPUT(yes|no) V4-FILE-HAS-CHAIN(yes|no): fw_state with stubs
  local f="$t/rules.v4"; : >"$f"; [ "$2" = yes ] && echo AINKRAD_IN >"$f"
  ( . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"; A_HARDEN=yes
    command() { if [ "$1" = -v ] && [ "$2" = ufw ]; then return 1; fi; builtin command "$@"; }
    iptables() { [ "$1" = -S ] && [ "$yes_in" = yes ] && echo '-A INPUT -j AINKRAD_IN'; return 0; }
    ip6tables() { return 0; }
    yes_in=$1 AINKRAD_RULES_V4=$f fw_state )
}
fwstate yes no | grep -q 'until next reboot' && ok || bad "fw_state claims persistence that is not there"
fwstate yes yes | grep -q 'saved for reboot' && ok || bad "fw_state does not report saved rules"
fwstate no no | grep -q 'NOT applied' && ok || bad "fw_state claims a firewall that is not in INPUT"
( . "$ROOT/scripts/install/lib.sh"; [ "$(clean_ip 203.0.113.9)" = 203.0.113.9 ] && [ "$(clean_ip 2001:db8::1)" = 2001:db8::1 ] && [ -z "$(clean_ip $'203.0.113.8\n<script>')" ] && [ -z "$(clean_ip $'\033[31mevil')" ] && [ -z "$(clean_ip 'not an ip')" ] ) && ok || bad "clean_ip lets a non-address through"

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

# --- install-linux.sh restarts a running runner when its user or flags change; a demotion ends the root terminals first ---
il() { bash "$ROOT/deploy/install-linux.sh" --dry-run --prefix "$t/p" --binary /x --ptyhost /y "$@" 2>&1 </dev/null; }
pre="$t/p/etc"; mkdir -p "$pre/ainkrad-runner" "$pre/systemd/system/ainkrad-runner.service.d"
printf 'RUNNER_ARGS=--enable-pty --enable-exec\n' >"$pre/ainkrad-runner/runner.env"; : >"$pre/systemd/system/ainkrad-runner.service.d/authority.conf"
il --pty >"$t/il1"
k=$(grep -n 'systemctl kill --kill-whom=all ainkrad-runner' "$t/il1" | head -1 | cut -d: -f1); r=$(grep -n 'systemctl try-restart ainkrad-runner' "$t/il1" | head -1 | cut -d: -f1)
{ [ -n "$k" ] && [ -n "$r" ] && [ "$k" -lt "$r" ]; } && ok || bad "demoting a root runner does not end its terminals before the restart"
grep -q 'cannot be adopted' "$t/il1" && ok || bad "the demotion does not say why it ends the terminals"
rm -f "$pre/systemd/system/ainkrad-runner.service.d/authority.conf"; printf 'RUNNER_ARGS=--enable-pty\n' >"$pre/ainkrad-runner/runner.env"
il --pty >"$t/il2"; grep -q 'try-restart' "$t/il2" && bad "the runner is restarted although nothing changed" || ok
il >"$t/il3"; { grep -q 'try-restart' "$t/il3" && ! grep -q 'kill-whom' "$t/il3"; } && ok || bad "a flag change must try-restart without killing terminals"

echo "get/guided tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
