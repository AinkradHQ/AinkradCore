#!/usr/bin/env bash
# The checks before anything is installed (N6): busy ports, a host firewall that turns 443 away (the Oracle REJECT rule, ufw, nft),
# the order in get.sh (checks BEFORE apt), the runner unit's work root (N27: the self-test socket paths fit 100 bytes), the base
# tools (N39) and the built-in runner wiring (N8). Stubs stand in for ss / iptables / ufw / nft; nothing is changed.
# shellcheck disable=SC2015,SC2016
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
pass=0 fail=0
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL: $*" >&2; }
PY=$(command -v python3); t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin"

ORACLE='-P INPUT ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p udp -m udp --sport 123 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited'
stub() { # NAME BODY: a stub tool first on PATH
  printf '#!/bin/sh\n%s\n' "$2" >"$t/bin/$1"; chmod +x "$t/bin/$1"
}
# a clean PATH: only the stubs and the basic tools (no real ss / iptables / ufw / nft of this machine)
mkdir -p "$t/base"; for c in sh bash awk sed grep head tr cat printf sort uname id dirname basename ps cut tail wc date mktemp rm; do p=$(command -v "$c") && ln -sf "$p" "$t/base/$c"; done
run() { # SCRIPT: runs in a fresh shell with the stubs, the UI and the precheck block (plain mode)
  PATH="$t/bin:$t/base" NO_COLOR=1 sh -c '. "$1"; . "$2"; ui_init; pc_confirm() { return 1; }; '"$1" _ "$ROOT/scripts/install/ui.sh" "$ROOT/scripts/install/precheck.sh" 2>&1
}
fw() { rm -f "$t/bin/"*; stub iptables "$1"; }

# --- the block in get.sh is the file, and is POSIX ---
if command -v dash >/dev/null; then sed -n '/^# --- precheck begin ---$/,/^# --- precheck end ---$/p' "$ROOT/scripts/install/precheck.sh" >"$t/pc.sh"; dash -n "$t/pc.sh" && ok || bad "precheck is not valid POSIX sh"; fi

# --- iptables: the Oracle image ---
fw "case \$* in '-S INPUT') cat <<'R'
$ORACLE
R
;; esac"
o=$(run 'pc_fw_check 443; echo "rc=$?"; echo "FIX=$PC_FW_FIX"; echo "WHY=$PC_FW_WHY"')
grep -qx 'rc=1' <<<"$o" && ok || bad "the Oracle REJECT rule was not found for 443: $o"
grep -qx 'FIX=iptables -I INPUT 6 -p tcp -m state --state NEW --dport 443 -j ACCEPT' <<<"$o" && ok || bad "the fix is not the exact insert before the REJECT rule: $o"
grep -q 'Oracle' <<<"$o" && ok || bad "the reason does not name the stock Oracle rule: $o"
o=$(run 'pc_fw_check 22; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "port 22 (accepted) was reported as blocked: $o"
o=$(run 'pc_fw_check 80; echo "rc=$?"'); grep -qx 'rc=1' <<<"$o" && ok || bad "port 80 is rejected by the same rule: $o"
# opened: a 443 accept before the reject
fw "case \$* in '-S INPUT') cat <<'R'
$(printf '%s\n' "$ORACLE" | sed '6a\
-A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT')
R
;; esac"
o=$(run 'pc_fw_check 443; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "443 is accepted by a rule but was reported blocked: $o"
# multiport and a range
fw "case \$* in '-S INPUT') printf '%s\n' '-P INPUT ACCEPT' '-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT' '-A INPUT -j REJECT';; esac"
o=$(run 'pc_fw_check 443; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "multiport 80,443 not understood: $o"
fw "case \$* in '-S INPUT') printf '%s\n' '-P INPUT ACCEPT' '-A INPUT -p tcp -m tcp --dport 400:500 -j ACCEPT' '-A INPUT -j DROP';; esac"
o=$(run 'pc_fw_check 443; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "the range 400:500 not understood: $o"
# the policy
fw "case \$* in '-S INPUT') printf '%s\n' '-P INPUT DROP' '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT';; esac"
o=$(run 'pc_fw_check 443; echo "rc=$?"; echo "FIX=$PC_FW_FIX"'); { grep -qx 'rc=1' <<<"$o" && grep -q 'FIX=iptables -A INPUT' <<<"$o"; } && ok || bad "policy DROP without a 443 rule was not caught: $o"
# nothing blocks
fw "case \$* in '-S INPUT') printf '%s\n' '-P INPUT ACCEPT';; esac"
o=$(run 'pc_fw_check 443; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "an open firewall was reported blocked: $o"

# --- ufw ---
rm -f "$t/bin/"*; stub ufw 'printf "Status: active\n\nTo Action From\n-- ------ ----\n22/tcp ALLOW Anywhere\n"'
o=$(run 'pc_fw_check 443; echo "rc=$?"; echo "FIX=$PC_FW_FIX"'); { grep -qx 'rc=1' <<<"$o" && grep -qx 'FIX=ufw allow 443/tcp' <<<"$o"; } && ok || bad "ufw without a 443 rule was not caught: $o"
stub ufw 'printf "Status: active\n\nTo Action From\n-- ------ ----\n443/tcp ALLOW Anywhere\n"'
o=$(run 'pc_fw_check 443; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "ufw with 443 allowed was reported blocked: $o"
stub ufw 'printf "Status: inactive\n"'
o=$(run 'pc_fw_check 443; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "an inactive ufw was reported blocking: $o"

# --- nftables ---
rm -f "$t/bin/"*; stub nft 'printf "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport 22 accept\n\t}\n}\n"'
o=$(run 'pc_fw_check 443; echo "rc=$?"; echo "FIX=$PC_FW_FIX"'); { grep -qx 'rc=1' <<<"$o" && grep -qx 'FIX=nft insert rule inet filter input tcp dport 443 accept' <<<"$o"; } && ok || bad "an nft input chain with policy drop was not caught: $o"
stub nft 'printf "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\ttcp dport { 22, 443 } accept\n\t}\n}\n"'
o=$(run 'pc_fw_check 443; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "nft with 443 accepted was reported blocked: $o"

# --- the whole check: a busy port, a blocked port (no answer), a blocked port (yes), a clean machine ---
rm -f "$t/bin/"*; stub ss 'echo "LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:((\"nginx\",pid=7,fd=6))"'
o=$(run 'pc_checks "443"; echo "rc=$?"; echo "WHAT=$PC_WHAT"; echo "TODO=$PC_TODO"')
{ grep -qx 'rc=1' <<<"$o" && grep -q 'WHAT=port 443 is already in use by another program' <<<"$o" && grep -q 'nginx' <<<"$o" && grep -q 'Nothing was installed' <<<"$o"; } && ok || bad "a busy port 443 did not stop the check: $o"
stub ss 'echo "LISTEN 0 4096 *:443 *:* users:((\"ainkrad-core-server\",pid=7,fd=6))"'
o=$(run 'pc_checks "443"; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "the Core itself on 443 (a re-run) stopped the check: $o"
rm -f "$t/bin/"*; stub iptables "case \$* in '-S INPUT') cat <<'R'
$ORACLE
R
;; esac"
o=$(run 'pc_checks "443"; echo "rc=$?"; echo "TODO=$PC_TODO"')
{ grep -qx 'rc=1' <<<"$o" && grep -q 'iptables -I INPUT 6 -p tcp -m state --state NEW --dport 443 -j ACCEPT' <<<"$o" && grep -q 'Security List' <<<"$o" && grep -q 'Nothing was installed' <<<"$o"; } && ok || bad "a blocked 443 (no consent) did not stop with the exact command and the provider hint: $o"
# consent: the rule is added (the stub flips), then it passes
rm -f "$t/bin/"*; : >"$t/opened"
stub iptables "if [ -s '$t/opened' ]; then printf '%s\n' '-P INPUT ACCEPT'; else case \$* in '-S INPUT') cat <<'R'
$ORACLE
R
;; esac; fi"
o=$(PATH="$t/bin:$t/base" NO_COLOR=1 sh -c '. "$1"; . "$2"; ui_init; F=$3; pc_confirm() { echo ASKED: "$1"; return 0; }; pc_open() { echo OPENED: "$1"; echo yes >"$F"; }; pc_checks 443; echo "rc=$?"' _ "$ROOT/scripts/install/ui.sh" "$ROOT/scripts/install/precheck.sh" "$t/opened" 2>&1)
{ grep -q 'ASKED:.*iptables -I INPUT 6' <<<"$o" && grep -q 'OPENED: iptables -I INPUT 6' <<<"$o" && grep -qx 'rc=0' <<<"$o"; } && ok || bad "with consent the rule was not asked for, added, and re-checked: $o"
# no answer is a no (never an add): pc_confirm without a terminal
o=$(PATH="$t/bin:$t/base" NO_COLOR=1 "$PY" -I -c 'import os,sys; os.setsid(); os.execvp("sh", ["sh","-c",". \"$1\"; . \"$2\"; ui_init; pc_confirm q; echo rc=$?","_",sys.argv[1],sys.argv[2]])' "$ROOT/scripts/install/ui.sh" "$ROOT/scripts/install/precheck.sh" </dev/null 2>&1 || true)
grep -qx 'rc=1' <<<"$o" && ok || bad "pc_confirm said yes without a terminal: $o"
rm -f "$t/bin/"*
o=$(run 'pc_checks "443 80"; echo "rc=$?"'); grep -qx 'rc=0' <<<"$o" && ok || bad "a clean machine (no ss, no firewall tools) did not pass: $o"

# --- get.sh: the machine checks come BEFORE anything is installed; the base tools are in the package list (N39) ---
gs=$ROOT/scripts/get.sh
l_chk=$(grep -n 'pc_checks 443 ||' "$gs" | head -1 | cut -d: -f1);  l_apt=$(grep -n 'ui_run "Installing the prerequisite packages with apt (nothing' "$gs" | head -1 | cut -d: -f1)
{ [ -n "$l_chk" ] && [ -n "$l_apt" ] && [ "$l_chk" -lt "$l_apt" ]; } && ok || bad "get.sh does not run pc_checks before the apt step ($l_chk vs $l_apt)"
for pkg in git curl unzip jq ripgrep build-essential; do grep -q "^    pkgs='.*[ ']${pkg}[ ']" "$gs" && ok || bad "get.sh does not install $pkg with the prerequisites"; done
grep -q 'ui_stopped "\$PC_WHAT" "\$PC_TODO"' "$gs" && ok || bad "get.sh does not stop with the red card when a check fails"

# --- N27: the runner unit's TMPDIR leaves room for the gateway and tools self-test sockets (computed from the real unit and sources) ---
unit=$ROOT/deploy/systemd/ainkrad-runner.service
tmpdir=$(sed -n 's/^Environment=TMPDIR=//p' "$unit")
max=$(sed -n 's/.*const MAX_SOCK_PATH: usize = \([0-9]*\);.*/\1/p' "$ROOT/crates/runner/src/gateway.rs")
idlen=$(sed -n 's/^const SESSION_ID_LEN: usize = \([0-9]*\);/\1/p' "$ROOT/crates/runner/src/gateway/selftest.rs")
gwdir=$(sed -n 's/.*format!("\(ainkrad-gw-\){}".*/\1/p' "$ROOT/crates/runner/src/gateway/selftest.rs" | head -1); [ -n "$gwdir" ] || gwdir=ainkrad-gw-
tldir=ainkrad-tools-
gwsock=$(sed -n 's/.*dir.join("\(gateway.sock\)").*/\1/p' "$ROOT/crates/runner/src/gateway.rs"); tlsock=$(sed -n 's/.*dir.join("\(tools.sock\)").*/\1/p' "$ROOT/crates/runner/src/v2/agent/tools/sock.rs")
{ [ -n "$tmpdir" ] && [ -n "$max" ] && [ -n "$idlen" ] && [ -n "$gwsock" ] && [ -n "$tlsock" ]; } && ok || bad "could not read TMPDIR/MAX_SOCK_PATH/SESSION_ID_LEN/socket names ($tmpdir $max $idlen $gwsock $tlsock)"
plen() { echo $(( ${#1} + 1 + ${#2} + 16 + 8 + idlen + 1 + ${#3} )); } # TMPDIR/<prefix><16 hex>/agents/<id>/<sock>
gl=$(plen "$tmpdir" "$gwdir" "$gwsock"); tl=$(plen "$tmpdir" "$tldir" "$tlsock")
{ [ "$gl" -le "$max" ] && [ "$tl" -le "$max" ]; } && ok || bad "TMPDIR=$tmpdir makes the self-test socket paths $gl (gateway) and $tl (tools) bytes; a unix socket path is at most $max"
old=$(plen /var/lib/ainkrad-runner-work "$tldir" "$tlsock"); [ "$old" -gt "$max" ] && ok || bad "the old work root would have fitted ($old): the test no longer proves anything"
grep -q "^StateDirectory=ainkrad-runner ${tmpdir#/var/lib/}\$" "$unit" && grep -q "^ReadWritePaths=$tmpdir\$" "$unit" && ok || bad "StateDirectory / ReadWritePaths do not match TMPDIR=$tmpdir"

# --- N8: --agents writes the runner's flags and egress policy; the default install writes none of them ---
d="$t/prefix"; mkdir -p "$d"; : >"$t/rb"; chmod +x "$t/rb"; : >"$t/ph"; chmod +x "$t/ph"
bash "$ROOT/deploy/install-linux.sh" --binary "$t/rb" --ptyhost "$t/ph" --pty --agents --prefix "$d" --dry-run >"$t/il.out" 2>&1
grep -q 'RUNNER_ARGS=--enable-pty --enable-agents' "$t/il.out" && grep -q 'AINKRAD_AGENT_NETWORK=filtered' "$t/il.out" && grep -q 'AINKRAD_AGENT_EGRESS_HOSTS=api.anthropic.com' "$t/il.out" && ok || bad "install-linux.sh --agents does not plan RUNNER_ARGS / the egress policy: $(cat "$t/il.out")"
bash "$ROOT/deploy/install-linux.sh" --binary "$t/rb" --ptyhost "$t/ph" --pty --prefix "$d" >"$t/il2.out" 2>&1
{ grep -qx 'RUNNER_ARGS=--enable-pty' "$d/etc/ainkrad-runner/runner.env" && ! grep -q 'AGENT' "$d/etc/ainkrad-runner/runner.env"; } && ok || bad "without --agents runner.env must hold RUNNER_ARGS=--enable-pty only: $(cat "$d/etc/ainkrad-runner/runner.env" 2>&1)"
bash "$ROOT/deploy/install-linux.sh" --binary "$t/rb" --ptyhost "$t/ph" --pty --agents --prefix "$d" >"$t/il3.out" 2>&1
{ grep -qx 'RUNNER_ARGS=--enable-pty --enable-agents' "$d/etc/ainkrad-runner/runner.env" && grep -qx 'AINKRAD_AGENT_NETWORK=filtered' "$d/etc/ainkrad-runner/runner.env" && grep -qx 'AINKRAD_AGENT_EGRESS_HOSTS=api.anthropic.com' "$d/etc/ainkrad-runner/runner.env"; } && ok || bad "runner.env with --agents is wrong: $(cat "$d/etc/ainkrad-runner/runner.env" 2>&1)"
# the installer: on by default for the guided install, off with --no-local-runner; the pinned versions are the ones asked for
grep -q 'NODE_VERSION=22\.' "$ROOT/scripts/install/agent-tools.sh" && grep -q 'CLAUDE_VERSION=2.1.318' "$ROOT/scripts/install/agent-tools.sh" && ok || bad "agent-tools.sh does not pin Node 22 and claude 2.1.318"
grep -q 'DISABLE_AUTOUPDATER' "$ROOT/scripts/install.sh" && grep -q '/etc/claude-code/managed-settings.json' "$ROOT/scripts/install.sh" && ok || bad "install.sh does not turn the claude auto-updater off"
mkdir -p "$t/dd"; for n in ainkrad-core-server ainkradctl ainkrad-runner ainkrad-ptyhost; do printf '#!/bin/sh\n' >"$t/dd/$n"; chmod +x "$t/dd/$n"; done
run_i() { AINKRAD_HOSTNAME=core.example.com AINKRAD_ACME_EMAIL=ops@example.com NO_COLOR=1 bash "$ROOT/scripts/install.sh" --dry-run --binary "$t/dd" "$@" 2>&1 </dev/null; }
o=$(run_i); { grep -q 'runner-enroll-local' <<<"$o" && grep -q 'Node 22.22.1' <<<"$o" && grep -q 'RUNNER_ARGS=--enable-pty --enable-agents' <<<"$o"; } && ok || bad "the default guided dry run does not plan the built-in runner: $(grep -i runner <<<"$o" | head -5)"
o=$(run_i --no-local-runner); { ! grep -q 'runner-enroll-local' <<<"$o" && grep -q 'no-local-runner' <<<"$o"; } && ok || bad "--no-local-runner still plans a runner, or does not say so: $(grep -i runner <<<"$o" | head -5)"

echo "precheck tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
