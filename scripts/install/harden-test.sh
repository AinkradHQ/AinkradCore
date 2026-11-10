#!/usr/bin/env bash
# Tests for scripts/host/harden.sh, the firewall notice and summary, and the runner restart of deploy/install-linux.sh.
# No root, macOS or Linux, run by test.sh. harden.sh is only ever SOURCED here (AINKRAD_HARDEN_SOURCE_ONLY=1, which also
# turns on its AINKRAD_TEST_* overrides) and every tool that changes a machine (ufw, iptables, ip6tables,
# netfilter-persistent, systemctl, sshd) is a recording stub: an unstubbed call is a violation and fails the run, so this
# file cannot touch the firewall of a machine that has the real tools. `command -v X` answers from $HAVE.
# Each check FAILS when the rule it guards is broken (mutants: see the PR).
# SC2015: `check && pass || fail` is meant. SC2031/SC2154/SC2329: stubs and sourced libraries run in subshells on purpose.
# shellcheck disable=SC2015,SC2016,SC2030,SC2031,SC2120,SC2154,SC2178,SC2269,SC2329
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*" >&2; }
# These tests stub every tool that changes a machine, but they never run as root: a mistake must not be able to change a firewall.
[ "$(id -u)" != 0 ] || { echo "harden-test: refusing to run as root (run it as an ordinary user)" >&2; exit 1; }
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
: >"$t/violation"
# Belt and braces for subshells and `bash -c` children: the real tools are shadowed for the whole run by shims that only record.
mkdir "$t/shim"
for f in ufw iptables ip6tables netfilter-persistent systemctl sshd; do
  printf '#!/bin/sh\necho "SHIM %s $*" >>"%s"\nexit 99\n' "$f" "$t/violation" >"$t/shim/$f"; chmod +x "$t/shim/$f"
done
export PATH="$t/shim:$PATH"

# hz SNIPPET: harden.sh sourced in test mode, with violating default stubs and `command -v` answering from $HAVE
hz() {
  ( export AINKRAD_HARDEN_SOURCE_ONLY=1 AINKRAD_INSTALL_TEST=1 SUDO_USER=ops
    # shellcheck source=scripts/host/harden.sh
    . "$ROOT/scripts/host/harden.sh"
    for f in ufw iptables ip6tables netfilter-persistent systemctl sshd; do
      eval "$f() { echo \"UNSTUBBED $f \$*\" >>\"$t/violation\"; return 99; }"
    done
    command() {
      if [ "$1" = -v ]; then case "$2" in ufw | iptables | ip6tables | netfilter-persistent | ss | journalctl | sshd) case " ${HAVE:-} " in *" $2 "*) return 0 ;; *) return 1 ;; esac ;; esac; fi
      builtin command "$@"
    }
    eval "$1" ) 2>&1
}
KEYLINE='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample test@laptop\n'

# --- the sshd lockout guard ---
sshd_case() { # NAME WANT(0|1) KEYS-CONTENT|- SSHD_T SS-LINES LOG [snippet-prefix]
  local h="$t/sshhome.$RANDOM" rc=0
  mkdir -p "$h/.ssh"; [ "$3" = - ] || printf '%b' "$3" >"$h/.ssh/authorized_keys"
  printf '%b' "$4" >"$h/sshd_t"; printf '%b' "$5" >"$h/ss"; printf '%b' "$6" >"$h/log"
  AINKRAD_TEST_HOME=$h AINKRAD_TEST_SSHD_T=$h/sshd_t AINKRAD_TEST_SS=$h/ss AINKRAD_SSH_LOG=$h/log hz "${7:-}sshd_safe" >/dev/null || rc=1
  [ "$rc" = "$2" ] && ok || bad "sshd guard: $1 (want rc $2, got $rc)"
}
SSHT='port 22\nauthorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\nauthorizedkeyscommand none\ntrustedusercakeys none\n'
SESS='0 0 10.0.0.1:22 198.51.100.7:5000 users:(("sshd",pid=1234,fd=4),("sshd",pid=1200,fd=4))\n'
PUB='Nov 10 06:44:50 h sshd[1200]: Accepted publickey for ops from 198.51.100.7 port 5000 ssh2\n'
PUB98='Nov 10 06:44:50 h sshd-session[1200]: Accepted publickey for ops from 198.51.100.7 port 5000 ssh2\n'
PW='Nov 10 06:44:50 h sshd[1200]: Accepted password for ops from 198.51.100.7 port 5000 ssh2\n'
OLDPUB='Nov 09 06:44:50 h sshd[777]: Accepted publickey for ops from 198.51.100.7 port 4000 ssh2\n'
sshd_case "no authorized_keys file" 1 - "$SSHT" "" "$PUB"
sshd_case "only comments in authorized_keys" 1 '# nothing\n\n' "$SSHT" "" "$PUB"
sshd_case "text that is not a key line" 1 'hello world, not a key\n' "$SSHT" "" "$PUB"
sshd_case "a key with options in front" 0 'command="/bin/true",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample x\n' "$SSHT" "" ""
sshd_case "a key, session logged in with a key (sshd tag)" 0 "$KEYLINE" "$SSHT" "$SESS" "$PUB"
sshd_case "a key, session logged in with a key (OpenSSH 9.8 sshd-session tag)" 0 "$KEYLINE" "$SSHT" "$SESS" "$PUB98"
sshd_case "a key, session logged in with a password" 1 "$KEYLINE" "$SSHT" "$SESS" "$PW"
sshd_case "a key, session not in the log" 1 "$KEYLINE" "$SSHT" "$SESS" ""
sshd_case "this session used a password, the same address had a key login in an older session" 1 "$KEYLINE" "$SSHT" "$SESS" "$PW$OLDPUB"
sshd_case "PID reused: an old key login then a later password login by the same pid" 1 "$KEYLINE" "$SSHT" "$SESS" "$PUB$PW"
sshd_case "PID reused: an old password login then a later key login by the same pid" 0 "$KEYLINE" "$SSHT" "$SESS" "$PW$PUB"
sshd_case "a key, zero SSH sessions (console or cloud-init)" 0 "$KEYLINE" "$SSHT" "" ""
sshd_case "ss is not installed (fail closed)" 1 "$KEYLINE" "$SSHT" "" "" 'HAVE=; unset AINKRAD_TEST_SS; '
sshd_case "ss exists but fails (an error is not 'no sessions')" 1 "$KEYLINE" "$SSHT" "" "" 'HAVE=ss; unset AINKRAD_TEST_SS; ss() { return 1; }; '
sshd_case "AuthorizedKeysCommand in use" 1 "$KEYLINE" "${SSHT/authorizedkeyscommand none/authorizedkeyscommand /usr/bin/keys}" "" ""
sshd_case "SSH certificates in use" 1 "$KEYLINE" "${SSHT/trustedusercakeys none/trustedusercakeys /etc/ssh/ca.pub}" "" ""
h2="$t/h2"; mkdir -p "$h2/.ssh"; printf '%b' "$KEYLINE" >"$h2/.ssh/authorized_keys2"; : >"$h2/empty"
AINKRAD_TEST_HOME=$h2 AINKRAD_TEST_SSHD_T=$h2/empty AINKRAD_TEST_SS=$h2/empty AINKRAD_SSH_LOG=$h2/empty hz sshd_safe >/dev/null && ok || bad "with no sshd -T output the default authorized_keys2 was not read"
h3="$t/h3"; mkdir -p "$h3/.ssh"; printf '%b' "$KEYLINE" >"$h3/.ssh/keys.txt"; printf 'port 22\nauthorizedkeysfile .ssh/keys.txt\nauthorizedkeyscommand none\ntrustedusercakeys none\n' >"$h3/sshd_t"
AINKRAD_TEST_HOME=$h3 AINKRAD_TEST_SSHD_T=$h3/sshd_t AINKRAD_TEST_SS=$h2/empty AINKRAD_SSH_LOG=$h2/empty hz sshd_safe >/dev/null && ok || bad "a key in the AuthorizedKeysFile sshd uses was not accepted"
# executed with SOURCE_ONLY it does nothing; without it the test overrides are dropped
out=$(AINKRAD_HARDEN_SOURCE_ONLY=1 bash "$ROOT/scripts/host/harden.sh" 2>&1); rc=$?
{ [ "$rc" = 0 ] && grep -q 'nothing was done' <<<"$out"; } && ok || bad "harden.sh executed with AINKRAD_HARDEN_SOURCE_ONLY=1 did not stop at once ($rc)"
sed 's|^\[ "\$(id -u)" = 0 \] .*|echo "PEERS=${AINKRAD_TEST_PEERS+set}"; exit 0|' "$ROOT/scripts/host/harden.sh" >"$t/harden-prod.sh"
grep -q '^echo "PEERS=' "$t/harden-prod.sh" && ok || { bad "the production copy of harden.sh was not made (the sed pattern no longer matches): the checks below would prove nothing"; }
[ "$(AINKRAD_TEST_PEERS=203.0.113.5 AINKRAD_TEST_HOME=/x bash "$t/harden-prod.sh" 2>&1 | grep PEERS=)" = "PEERS=" ] && ok || bad "harden.sh honours AINKRAD_TEST_* overrides outside the install tests"
[ "$(AINKRAD_HARDEN_SOURCE_ONLY=1 AINKRAD_TEST_PEERS=203.0.113.5 bash -c '. "$1"; echo "PEERS=${AINKRAD_TEST_PEERS+set}"' _ "$ROOT/scripts/host/harden.sh")" = "PEERS=" ] && ok || bad "harden.sh keeps the test overrides with only AINKRAD_HARDEN_SOURCE_ONLY=1 (AINKRAD_INSTALL_TEST=1 is also required)"
[ "$(AINKRAD_HARDEN_SOURCE_ONLY=1 AINKRAD_INSTALL_TEST=1 AINKRAD_TEST_PEERS=203.0.113.5 bash -c '. "$1"; echo "PEERS=${AINKRAD_TEST_PEERS+set}"' _ "$ROOT/scripts/host/harden.sh")" = "PEERS=set" ] && ok || bad "harden.sh drops the overrides even in test mode"

# --- sshd ports, other listeners, the notice ---
printf 'port 2222\n' >"$t/t2222"; : >"$t/none"
[ "$(AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none hz ssh_ports)" = 2222 ] && ok || bad "ssh_ports did not read port 2222 from sshd -T"
printf 'LISTEN 0 128 0.0.0.0:2200 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n' >"$t/l2200"
[ "$(AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/l2200 hz ssh_ports | tr '\n' ' ')" = "2200 2222 " ] && ok || bad "ssh_ports did not add the port sshd really listens on"
cat >"$t/all" <<'EOF'
tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=900,fd=3))
tcp LISTEN 0 511 *:443 *:* users:(("nginx",pid=1,fd=6))
tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=2,fd=14))
udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:* users:(("wg-quick",pid=3,fd=3))
tcp LISTEN 0 4096 *:6443 *:* users:(("k3s-server",pid=4,fd=7))
udp UNCONN 0 0 10.0.0.2%eth0:68 0.0.0.0:* users:(("systemd-network",pid=5,fd=15))
tcp LISTEN 0 4096 [::1]:9100 [::]:* users:(("exporter",pid=6,fd=3))
EOF
lst=$(AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none AINKRAD_TEST_LISTEN_ALL=$t/all hz other_listeners)
{ grep -q 'udp 51820 wg-quick' <<<"$lst" && grep -q 'tcp 6443 k3s-server' <<<"$lst" && [ "$(wc -l <<<"$lst" | tr -d ' ')" = 2 ]; } && ok || bad "other_listeners is wrong (want exactly wireguard udp 51820 and k3s tcp 6443): $lst"
note=$(AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none AINKRAD_TEST_LISTEN_ALL=$t/all hz firewall_notice)
{ grep -q 'TCP and UDP, IPv4 and IPv6' <<<"$note" && grep -q 'STOP being reachable' <<<"$note" && grep -q 'k3s-server' <<<"$note" && grep -q 'AINKRAD_FIREWALL=no' <<<"$note"; } && ok || bad "the firewall notice does not name what will be rejected and what stops working: $note"
# firewall_decide (guided.sh): asks only when other services listen, default no; AINKRAD_FIREWALL=no never applies
decide() { # NAME WANT ANSWER(y|n|-) LISTEN-FILE [env]  -> FW_CHOICE and whether yes_no was asked
  local f="$t/decide" ; : >"$f"
  ( . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"
    GUIDED=1 DRY=0; ans=$3; say() { echo "$*"; }; have_tty() { [ "$ans" != - ]; }
    yes_no() { echo asked >>"$f"; [ "$ans" = y ]; }
    export AINKRAD_INSTALL_TEST=1 AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none AINKRAD_TEST_LISTEN_ALL=$4
    eval "${5:-}"
    firewall_decide >/dev/null; echo "$FW_CHOICE" >>"$f.out" ) 2>/dev/null
  local got; got=$(tail -n1 "$f.out" 2>/dev/null); rm -f "$f.out"
  [ "$got" = "$2" ] && ok || bad "firewall_decide: $1 (want $2, got '$got')"
}
decide "other services listening, answer y" yes y "$t/all"
decide "other services listening, answer n" no n "$t/all"
decide "other services listening, no terminal: default no" no - "$t/all"
decide "AINKRAD_FIREWALL=no" no y "$t/all" 'export AINKRAD_FIREWALL=no'
printf 'tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=900,fd=3))\n' >"$t/only-ssh"
decide "nothing else listening: applies without asking" yes n "$t/only-ssh"
: >"$t/decide"; ( . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"; GUIDED=1 DRY=0; say() { :; }; have_tty() { return 0; }; yes_no() { echo asked >>"$t/decide"; return 0; }
  export AINKRAD_INSTALL_TEST=1 AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none AINKRAD_TEST_LISTEN_ALL=$t/only-ssh; firewall_decide >/dev/null ) 2>/dev/null
[ ! -s "$t/decide" ] && ok || bad "firewall_decide asked although only ssh/80/443 listen"

# --- the firewall step against stubs ---
fwrun() { # NAME SNIPPET [env assignments in the caller]: apply_firewall, log in $t/fw.log, warnings $t/fw.warn, state $t/fw.state
  : >"$t/fw.log"; : >"$t/fw.warn"; : >"$t/fw.state"
  AINKRAD_HARDEN_WARN=$t/fw.warn AINKRAD_HARDEN_STATE=$t/fw.state AINKRAD_NOTICE_SHOWN=1 AINKRAD_TEST_SSHD_T=$t/t2222 AINKRAD_TEST_SSH_LISTEN=$t/none \
    hz "
    iptables() { echo \"iptables \$*\" >>$t/fw.log; case \$1 in -D) return 1 ;; esac; return 0; }
    ip6tables() { echo \"ip6tables \$*\" >>$t/fw.log; case \$1 in -D) return 1 ;; esac; return 0; }
    netfilter-persistent() { echo netfilter-persistent \$* >>$t/fw.log; }
    ufw() { echo \"ufw \$*\" >>$t/fw.log; }
    $2
    apply_firewall" >"$t/fw.out" 2>&1 || true
}
IPT="iptables ip6tables netfilter-persistent"
HAVE=$IPT AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 fwrun iptables "fw_persisted() { return 0; }"
for fam in iptables ip6tables; do
  grep -q "^$fam -A AINKRAD_NEW -p tcp -m state --state NEW --dport 2222 -j ACCEPT" "$t/fw.log" && ok || bad "the $fam rules do not allow sshd's port 2222"
  grep -q "^$fam -E AINKRAD_NEW AINKRAD_IN" "$t/fw.log" && ok || bad "the $fam chain was not swapped in by rename"
  a=$(grep -n "^$fam -I INPUT 1 -j AINKRAD_NEW" "$t/fw.log" | head -1 | cut -d: -f1); r=$(grep -n "^$fam -A AINKRAD_NEW -j REJECT" "$t/fw.log" | head -1 | cut -d: -f1)
  { [ -n "$a" ] && [ -n "$r" ] && [ "$r" -lt "$a" ]; } && ok || bad "the $fam chain is hooked into INPUT before it is complete"
done
grep -q -- '--dport 22 ' "$t/fw.log" && bad "the firewall allows port 22 although sshd listens on 2222" || ok
grep -q 'netfilter-persistent save' "$t/fw.log" && ok || bad "the iptables rules are not saved"
grep -q -- '-F INPUT' "$t/fw.log" && bad "the firewall flushes INPUT" || ok
grep -q '^ip6tables -A AINKRAD_NEW -p udp -s fe80::/10 --sport 547 --dport 546 -j ACCEPT' "$t/fw.log" && ok || bad "IPv6: DHCPv6 replies are not allowed"
grep -q '^iptables .*546' "$t/fw.log" && bad "IPv4 got the DHCPv6 rule" || ok
grep -q 'firewall=iptables' "$t/fw.state" && grep -q 'Firewall path: iptables (ufw is not installed)' "$t/fw.out" && ok || bad "the iptables path and its reason were not reported"
# a rule that fails part-way: the new chain is never hooked, the old rules stay, a warning says so
HAVE=$IPT AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 fwrun iptables "iptables() { echo \"iptables \$*\" >>$t/fw.log; case \$1 in -D) return 1 ;; esac; case \"\$*\" in *REJECT*) return 1 ;; esac; return 0; }; fw_persisted() { return 0; }"
{ ! grep -q '^iptables -I INPUT 1' "$t/fw.log" && grep -q 'could not be applied completely' "$t/fw.warn" && grep -q 'firewall=failed' "$t/fw.state"; } && ok || bad "a half-built iptables chain was hooked in, or the failure was not reported"
# hooking the new chain fails: it is not renamed over the old one and the failure is reported
HAVE=$IPT AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 fwrun iptables "iptables() { echo \"iptables \$*\" >>$t/fw.log; case \$1 in -D) return 1 ;; -I) return 1 ;; esac; return 0; }; fw_persisted() { return 0; }"
{ ! grep -q '^iptables -E AINKRAD_NEW' "$t/fw.log" && grep -q 'could not be applied completely' "$t/fw.warn"; } && ok || bad "a failed hook of the new chain was ignored (the rename went ahead)"
# the kernel has no IPv6 filtering: skip IPv6 with a warning, IPv4 is still done
HAVE=$IPT AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 fwrun iptables "ip6tables() { echo \"ip6tables \$*\" >>$t/fw.log; return 3; }; fw_persisted() { return 0; }"
{ grep -q '^iptables -E AINKRAD_NEW AINKRAD_IN' "$t/fw.log" && ! grep -q '^ip6tables -N' "$t/fw.log" && grep -q 'ip6tables is not usable' "$t/fw.warn" && grep -q 'ipv6=unfiltered' "$t/fw.state"; } && ok || bad "an unusable ip6tables aborted or half-applied the IPv6 chain, or was not reported"
# AINKRAD_FIREWALL=no: nothing at all
HAVE=$IPT AINKRAD_FIREWALL=no fwrun iptables ""
{ [ ! -s "$t/fw.log" ] && grep -q 'skipped' "$t/fw.warn" && grep -q 'firewall=skipped' "$t/fw.state"; } && ok || bad "AINKRAD_FIREWALL=no still changed the firewall"
# unknown sshd ports: no change
: >"$t/emptyT"
HAVE="$IPT sshd" AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 fwrun unknown ""
: >"$t/fw.log"; AINKRAD_HARDEN_WARN=$t/fw.warn AINKRAD_HARDEN_STATE=$t/fw.state AINKRAD_NOTICE_SHOWN=1 AINKRAD_TEST_SSHD_T=$t/emptyT AINKRAD_TEST_SSH_LISTEN=$t/none HAVE="$IPT sshd" \
  hz "iptables() { echo \"iptables \$*\" >>$t/fw.log; }; apply_firewall" >/dev/null 2>&1 || true
{ [ ! -s "$t/fw.log" ] && grep -q 'could not determine' "$t/fw.warn"; } && ok || bad "the firewall changed although sshd's ports are unknown"
# ufw installed, no saved rules: ssh port allowed BEFORE enable; the reason is printed
HAVE=ufw AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 AINKRAD_TEST_UFW_DEFAULT=/nonexistent fwrun ufw "fw_persisted() { return 0; }"
a1=$(grep -n 'ufw allow 2222/tcp' "$t/fw.log" | head -1 | cut -d: -f1); e1=$(grep -n 'ufw --force enable' "$t/fw.log" | head -1 | cut -d: -f1)
{ [ -n "$a1" ] && [ -n "$e1" ] && [ "$a1" -lt "$e1" ] && grep -q 'ufw default deny incoming' "$t/fw.log"; } && ok || bad "with ufw the ssh port is not allowed before ufw is enabled"
grep -q 'Firewall path: ufw (ufw is installed)' "$t/fw.out" && grep -q 'firewall=ufw' "$t/fw.state" && ok || bad "the ufw path and its reason were not reported"
grep -q '^iptables' "$t/fw.log" && bad "the ufw path also touched iptables" || ok
# ufw installed BUT saved iptables rules exist (Oracle-style): the iptables path, and it says why
printf '*filter\n' >"$t/rules.v4"
HAVE="ufw $IPT" AINKRAD_TEST_RULES_V4=$t/rules.v4 fwrun both "fw_persisted() { return 0; }"
{ grep -q '^iptables -A AINKRAD_NEW' "$t/fw.log" && ! grep -q '^ufw' "$t/fw.log" && grep -q 'saved iptables rules exist' "$t/fw.out"; } && ok || bad "saved iptables rules did not win over an installed ufw"
# ufw with SSH_FROM: the earlier open rule is deleted, the CIDR allowed; iptables with SSH_FROM: no IPv6 ssh
HAVE=ufw AINKRAD_SSH_FROM=203.0.113.0/24 AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 AINKRAD_TEST_UFW_DEFAULT=/nonexistent fwrun ufw "fw_persisted() { return 0; }"
{ grep -q 'ufw delete allow 2222/tcp' "$t/fw.log" && grep -q 'ufw allow from 203.0.113.0/24 to any port 2222 proto tcp' "$t/fw.log"; } && ok || bad "ufw SSH_FROM did not replace the earlier open ssh rule"
HAVE=$IPT AINKRAD_SSH_FROM=203.0.113.0/24 AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 fwrun iptables "fw_persisted() { return 0; }"
{ grep -q '^iptables -A AINKRAD_NEW .*--dport 2222 -s 203.0.113.0/24' "$t/fw.log" && ! grep -q '^ip6tables -A AINKRAD_NEW .*--dport 2222' "$t/fw.log"; } && ok || bad "SSH_FROM: IPv6 ssh must be closed on the iptables path as on the ufw path"
# ufw with IPV6=no says IPv6 is not filtered
printf 'IPV6=no\n' >"$t/ufwdef"
HAVE=ufw AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 AINKRAD_TEST_UFW_DEFAULT=$t/ufwdef fwrun ufw "fw_persisted() { return 0; }"
grep -q 'ipv6=unfiltered' "$t/fw.state" && grep -q 'IPv6 is NOT filtered' "$t/fw.warn" && ok || bad "ufw with IPV6=no did not report that IPv6 is unfiltered"
# rules in force only until reboot are said so
HAVE="iptables ip6tables" AINKRAD_TEST_RULES_V4=/nonexistent/rules.v4 fwrun iptables ""
grep -q 'until the next reboot' "$t/fw.warn" && ok || bad "unsaved firewall rules were not reported"

# --- the sshd drop-in (stubs for sshd and systemctl) ---
dd_="$t/dropin"; mkdir -p "$dd_"; printf 'port 22\npasswordauthentication no\n' >"$t/t_ok"; printf 'port 22\npasswordauthentication yes\n' >"$t/t_bad"
{ printf 'port 22\npasswordauthentication no\n'; head -c 300000 /dev/zero | tr '\0' 'x' | fold -w 60 | sed 's/^/filler /'; } >"$t/t_big"
sshdrun() { # SSHD_T-FILE SNIPPET: sshd_safe forced true unless SNIPPET redefines it
  rm -f "$dd_"/*; : >"$t/dd.warn"; : >"$t/dd.log"
  AINKRAD_HARDEN_WARN=$t/dd.warn AINKRAD_TEST_DROPIN=$dd_ AINKRAD_TEST_SSHD_T=$1 hz "sshd_safe() { return 0; }; sshd() { echo \"sshd \$*\" >>$t/dd.log; return 0; }; systemctl() { echo \"systemctl \$*\" >>$t/dd.log; return 0; }; ${2:+$2;} apply_sshd" >"$t/dd.out" 2>&1 || true
}
sshdrun "$t/t_ok"; { [ -f "$dd_/01-ainkrad.conf" ] && [ ! -s "$t/dd.warn" ]; } && ok || bad "a verified key-only drop-in was not kept"
sshdrun "$t/t_big"; { [ -f "$dd_/01-ainkrad.conf" ] && [ ! -s "$t/dd.warn" ]; } && ok || bad "a long sshd -T output made the verification fail (SIGPIPE under pipefail)"
sshdrun "$t/t_bad"; { [ ! -f "$dd_/01-ainkrad.conf" ] && grep -q 'did not take' "$t/dd.warn"; } && ok || bad "a drop-in that sshd -T does not honour was kept or not reported"
sshdrun "$t/t_ok" 'sshd() { echo "sshd $*" >>'"$t/dd.log"'; case $1 in -t) return 1 ;; esac; }'
{ [ ! -f "$dd_/01-ainkrad.conf" ] && grep -q 'rejected' "$t/dd.warn" && ! grep -q 'systemctl reload' "$t/dd.log"; } && ok || bad "sshd -t failing after the drop-in was written: the drop-in stayed or sshd was reloaded"
sshdrun "$t/t_ok" 'systemctl() { echo "systemctl $*" >>'"$t/dd.log"'; return 1; }'
{ [ ! -f "$dd_/01-ainkrad.conf" ] && grep -q 'could not be reloaded' "$t/dd.warn" && ! grep -q 'harden.*Error\|UNSTUBBED' "$t/dd.out"; } && ok || bad "both reloads failing aborted the script or left the drop-in"
rm -f "$dd_"/*; : >"$t/dd.warn"; touch "$dd_/70-ainkrad.conf"
AINKRAD_HARDEN_WARN=$t/dd.warn AINKRAD_TEST_DROPIN=$dd_ AINKRAD_TEST_SSHD_T=$t/t_ok hz "sshd_safe() { REASON='no key'; return 1; }; apply_sshd" >/dev/null 2>&1 || true
{ [ ! -f "$dd_/01-ainkrad.conf" ] && [ ! -f "$dd_/70-ainkrad.conf" ] && grep -q 'sshd left as it is' "$t/dd.warn"; } && ok || bad "an unsafe host got a drop-in, or the old 70- file was left"

# --- the summary reads the firewall back and does not claim what was not done ---
fwstate() { # RULES(yes|no in INPUT) RULES-FILE-HAS-CHAIN(yes|no) STATE-TEXT [ufw-active]
  local f="$t/rules.v4s" st="$t/hstate"; : >"$f"; [ "$2" = yes ] && echo AINKRAD_IN >"$f"; printf '%s\n' "$3" >"$st"
  ( . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"; A_HARDEN=yes HARDEN_STATE=$st AINKRAD_INSTALL_TEST=1
    command() { if [ "$1" = -v ] && [ "$2" = ufw ] && [ -z "${4:-}" ]; then return 1; fi; builtin command "$@"; }
    if [ -n "${4:-}" ]; then ufw() { echo 'Status: active'; }; fi
    iptables() { [ "$1" = -S ] && [ "$yes_in" = yes ] && echo '-A INPUT -j AINKRAD_IN'; return 0; }
    ip6tables() { return 0; }
    yes_in=$1 AINKRAD_RULES_V4=$f fw_state )
}
fwstate yes no 'firewall=iptables' | grep -q 'until next reboot' && ok || bad "fw_state claims persistence that is not there"
fwstate yes yes 'firewall=iptables' | grep -q 'saved for reboot' && ok || bad "fw_state does not report saved rules"
fwstate no no '' | grep -q 'NOT applied' && ok || bad "fw_state claims a firewall that is not in INPUT"
fwstate no no 'firewall=skipped' x | grep -q 'not changed' && ok || bad "fw_state claims the firewall although the step was skipped (ufw already active)"
fwstate yes yes 'firewall=failed' | grep -q 'NOT applied completely' && ok || bad "fw_state claims success after a failed firewall step"
fwstate yes yes $'firewall=iptables\nipv6=unfiltered' | grep -q 'IPv6 open' && ok || bad "fw_state does not say IPv6 is unfiltered"
# outside test mode the rules file path override is ignored
( . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"; A_HARDEN=yes HARDEN_STATE=/nonexistent
  ufw() { echo 'Status: inactive'; }; iptables() { [ "$1" = -S ] && echo '-A INPUT -j AINKRAD_IN'; return 0; }; ip6tables() { return 0; }
  echo AINKRAD_IN >"$t/forged"; AINKRAD_RULES_V4=$t/forged fw_state ) | grep -q 'until next reboot' && ok || bad "fw_state honours AINKRAD_RULES_V4 outside test mode"
( . "$ROOT/scripts/install/lib.sh"; [ "$(clean_ip 203.0.113.9)" = 203.0.113.9 ] && [ "$(clean_ip 2001:db8::1)" = 2001:db8::1 ] && [ -z "$(clean_ip $'203.0.113.8\n<script>')" ] && [ -z "$(clean_ip $'\033[31mevil')" ] && [ -z "$(clean_ip 'not an ip')" ] ) && ok || bad "clean_ip lets a non-address through"

# --- install.sh harden(): the notice of what stops being reachable comes BEFORE the "Apply it now?" consent ---
( . "$ROOT/scripts/install.sh"
  : >"$t/order"; A_HARDEN=yes GUIDED=0 CONFIG='' DRY=0 A_SSH_FROM='' STAGE=$t
  step() { :; }; say() { :; }; run() { echo run >>"$t/order"; }
  firewall_decide() { echo decide >>"$t/order"; FW_CHOICE=yes; }
  yes_no() { echo consent >>"$t/order"; return 0; }
  harden ) >/dev/null 2>&1
[ "$(tr '\n' ' ' <"$t/order")" = "decide consent run " ] && ok || bad "the non-guided path asked for consent before showing what will stop being reachable (order: $(tr '\n' ' ' <"$t/order"))"
# AINKRAD_FIREWALL must be yes or no
out=$( ( . "$ROOT/scripts/install/lib.sh"; . "$ROOT/scripts/install/guided.sh"; GUIDED=0 DRY=0; die() { echo "die: $*"; exit 3; }; say() { :; }
  AINKRAD_FIREWALL=maybe firewall_decide ) 2>&1 )
grep -q 'must be yes or no' <<<"$out" && ok || bad "AINKRAD_FIREWALL=maybe was accepted"

# --- install-linux.sh: the runner restart sequence, modelled (SIGTERM from kill is a clean exit: no auto-restart) ---
seq() { # NAME WANT-ACTIVE-AFTER WAS-ACTIVE OLD_ROOT ROOT OLD_ARGS ARGS [expected sequence regex]
  : >"$t/sc.log"
  ( export AINKRAD_INSTALL_SOURCE_ONLY=1
    # shellcheck source=deploy/install-linux.sh
    . "$ROOT/deploy/install-linux.sh"
    ACTIVE=$3; prefix='' dry=0 start=0 pair='' old_root=$4 root=$5 old_args=$6 args=$7
    systemctl() {
      echo "systemctl $*" >>"$t/sc.log"
      case $1 in
        is-active) if [ "$ACTIVE" = 1 ]; then return 0; else return 1; fi ;;
        kill) ACTIVE=0 ;;                     # SIGTERM to the main process: a clean exit, Restart=on-failure keeps it down
        restart) ACTIVE=1 ;;
        try-restart) : ;;                     # does nothing on an inactive unit, keeps an active one running
      esac
      return 0
    }
    runner_demote_kill >/dev/null; runner_restart_if_needed >/dev/null
    echo "ACTIVE=$ACTIVE" >>"$t/sc.log" ) 2>/dev/null
  local after; after=$(sed -n 's/^ACTIVE=//p' "$t/sc.log")
  [ "$after" = "$2" ] && { [ -z "${8:-}" ] || grep -qE "$8" <<<"$(tr '\n' '|' <"$t/sc.log")"; } && ok || bad "runner restart: $1 (active after: want $2, got '$after'; log: $(tr '\n' '|' <"$t/sc.log"))"
}
seq "demoting a running root runner leaves it running" 1 1 1 0 '--enable-pty --enable-exec' '--enable-pty' 'is-active.*kill --kill-whom=all.*restart'
seq "demoting a root runner that was stopped leaves it stopped" 0 0 1 0 '--enable-pty' '--enable-pty' 'kill'
seq "a flag change on a running runner try-restarts, no kill" 1 1 0 0 '--enable-pty' '' 'try-restart'
seq "nothing changed: no systemctl at all" 1 1 0 0 '--enable-pty' '--enable-pty'
grep -q 'kill' "$t/sc.log" && bad "an unchanged runner was killed" || ok

# every tool that could change this machine was a stub
[ ! -s "$t/violation" ] && ok || bad "a real tool was called: $(cat "$t/violation")"

echo "harden tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
