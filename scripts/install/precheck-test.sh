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

# --- N6: the two questions and the DNS check come BEFORE anything is installed, and the DNS check blocks ---
l_ask=$(grep -n 'pc_ask AINKRAD_HOSTNAME' "$gs" | head -1 | cut -d: -f1); l_mail=$(grep -n 'pc_ask AINKRAD_ACME_EMAIL' "$gs" | head -1 | cut -d: -f1); l_dns=$(grep -n 'pc_dns "\$AINKRAD_HOSTNAME"' "$gs" | head -1 | cut -d: -f1)
{ [ -n "$l_ask" ] && [ -n "$l_mail" ] && [ -n "$l_dns" ] && [ "$l_ask" -lt "$l_apt" ] && [ "$l_mail" -lt "$l_apt" ] && [ "$l_dns" -lt "$l_apt" ]; } && ok || bad "get.sh does not ask both questions and check DNS before the apt step ($l_ask $l_mail $l_dns vs $l_apt)"
{ [ "$l_ask" -lt "$l_dns" ] && [ "$l_chk" -lt "$l_dns" ]; } && ok || bad "get.sh checks DNS before it has the name or the ports"
grep -q 'ui_step 1 "\$(ui_rname 1)" "Needs Linux.*DNS name and email' "$gs" && grep -q '1) echo "Check this machine and your DNS name"' "$gs" && ok || bad "the roadmap text of step 1 does not say it asks for the DNS name and checks it"
for h in core.example.com a.b.c.example.org; do run "pc_valid_hostname $h" >/dev/null && ok || bad "$h refused as a DNS name"; done
for h in localhost 203.0.113.7 'bad_name.example.com' '-x.example.com' ''; do run "pc_valid_hostname '$h'" >/dev/null && bad "'$h' accepted as a DNS name" || ok; done
run 'pc_valid_email ops@example.com' >/dev/null && ok || bad "a plain email was refused"
for e in 'ops' 'ops@' '@example.com' 'a b@example.com' 'ops@localhost'; do run "pc_valid_email '$e'" >/dev/null && bad "'$e' accepted as an email" || ok; done
# a given-up-front answer is used as it is; an invalid one with no terminal stops with nothing installed
o=$(AINKRAD_HOSTNAME=core.example.com run 'pc_ask AINKRAD_HOSTNAME "q" "e" pc_valid_hostname; echo "got=$AINKRAD_HOSTNAME"'); grep -qx 'got=core.example.com' <<<"$o" && grep -q 'given up front' <<<"$o" && ok || bad "an answer from the environment was not taken: $o"
o=$(AINKRAD_HOSTNAME='not a name' PATH="$t/bin:$t/base" NO_COLOR=1 "$PY" -I -c 'import os,sys; os.setsid(); os.execvp("sh", ["sh","-c",". \"$1\"; . \"$2\"; ui_init; pc_ask AINKRAD_HOSTNAME q e pc_valid_hostname; echo NOT-STOPPED","_",sys.argv[1],sys.argv[2]])' "$ROOT/scripts/install/ui.sh" "$ROOT/scripts/install/precheck.sh" </dev/null 2>&1 || true)
{ grep -q 'no terminal to ask on' <<<"$o" && grep -q 'Nothing was installed' <<<"$o" && ! grep -q NOT-STOPPED <<<"$o"; } && ok || bad "a bad answer with no terminal did not stop the installer: $o"
# the DNS check: the A record must be this machine's public address (stubbed dig / curl)
dnsstub() { rm -f "$t/bin/"*; stub dig "case \"\$*\" in *' AAAA '*) printf '%s\n' \"\${AAAA:-}\" ;; *) printf '%s\n' \"\${A:-}\" ;; esac"; stub curl 'echo "${PUB-203.0.113.7}"'; stub ip 'exit 0'; stub getent 'exit 0'; }
dnsstub
o=$(A=203.0.113.7 run 'pc_dns core.example.com; echo "rc=$?"'); { grep -qx 'rc=0' <<<"$o" && grep -q 'points at 203.0.113.7: this machine' <<<"$o"; } && ok || bad "a name pointing at this machine was not accepted: $o"
o=$(A=198.51.100.9 run 'pc_dns core.example.com; echo "rc=$?"'); { ! grep -qx 'rc=0' <<<"$o" && grep -q 'validate the wrong machine' <<<"$o" && grep -q 'Nothing was installed' <<<"$o"; } && ok || bad "a name pointing elsewhere did not stop the installer: $o"
o=$(A='' run 'pc_dns core.example.com; echo "rc=$?"'); { ! grep -qx 'rc=0' <<<"$o" && grep -q 'no DNS A record' <<<"$o"; } && ok || bad "a name with no A record did not stop the installer: $o"
o=$(A=203.0.113.7 AAAA=2001:db8::1 run 'pc_dns core.example.com; echo "rc=$?"'); { ! grep -qx 'rc=0' <<<"$o" && grep -q 'IPv6 (AAAA) record' <<<"$o"; } && ok || bad "a foreign AAAA record did not stop the installer: $o"
o=$(A=203.0.113.7 PUB='' run 'pc_dns core.example.com; echo "rc=$?"'); { grep -qx 'rc=0' <<<"$o" && grep -q 'cannot compare' <<<"$o"; } && ok || bad "an unknown public address must warn, not block: $o"
# install.sh does not look the name up a second time when get.sh has
grep -q 'AINKRAD_DNS_CHECKED' "$ROOT/scripts/install/guided.sh" && grep -q 'export AINKRAD_DNS_CHECKED=1' "$gs" && ok || bad "install.sh would check DNS twice, or get.sh does not say it checked"

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

# --- N20: the Ainkrad shell: zsh and a pinned, read-only profile in every runner install ---
sh_dir=$ROOT/deploy/shell
# shellcheck source=deploy/shell/pins.sh disable=SC2154
( . "$sh_dir/pins.sh"
  for v in OMZ P10K AUTOSUGGESTIONS SYNTAX_HIGHLIGHTING; do
    eval "c=\$${v}_COMMIT s=\$${v}_SHA256"
    printf '%s' "$c" | grep -Eq '^[0-9a-f]{40}$' && printf '%s' "$s" | grep -Eq '^[0-9a-f]{64}$' || exit 1
  done
  printf '%s' "$GITSTATUSD_SHA256_x86_64$GITSTATUSD_SHA256_aarch64" | grep -Eq '^[0-9a-f]{128}$' ) && ok || bad "deploy/shell/pins.sh does not pin every part to a full commit and a SHA-256"
if command -v zsh >/dev/null; then zsh -n "$sh_dir/zshrc" && zsh -n "$sh_dir/p10k.zsh" && ok || bad "the Ainkrad shell profile is not valid zsh"; fi
grep -qiE 'ahmed|melhalaby|/Users/|/home/|oh-my-zsh|@gmail' "$sh_dir/p10k.zsh" && bad "the p10k look holds a personal path, name or tool" || ok
# the app's default terminal font is the system mono: no Nerd Font or powerline glyphs (private use area) in the profile
python3 -c 'import sys; sys.exit(any(0xE000 <= ord(c) <= 0xF8FF for f in sys.argv[1:] for c in open(f, encoding="utf8").read()) or 0)' "$sh_dir/p10k.zsh" "$sh_dir/zshrc" && ! grep -qE 'nerdfont|\\uE0|\\uF[0-9A-F]{3}' "$sh_dir/p10k.zsh" && ok || bad "the Ainkrad shell profile needs a Nerd Font (private-use glyphs or nerdfont mode)"
grep -q 'ZSH_DISABLE_COMPFIX=true' "$sh_dir/zshrc" && ok || bad "the profile does not silence compaudit for the root-owned profile in the sandbox"
grep -q 'terminal shell' "$ROOT/crates/runner/src/v2/session.rs" && ok || bad "the runner's facts do not say which shell its terminals start"
grep -q 'plugins=(git zsh-autosuggestions zsh-syntax-highlighting)' "$sh_dir/zshrc" && grep -q 'zshrc.local' "$sh_dir/zshrc" && grep -q 'GITSTATUS_AUTO_INSTALL=0' "$sh_dir/zshrc" && ok || bad "the zshrc lacks the three plugins, ~/.zshrc.local or the no-download setting"
tail -n 3 "$sh_dir/zshrc" | grep -q 'zshrc.local' && ok || bad "the home .zshrc.local is not sourced last"
d2=$t/prefix2; mkdir -p "$d2"
bash "$ROOT/deploy/install-linux.sh" --binary "$t/rb" --ptyhost "$t/ph" --pty --agents --prefix "$d2" --dry-run >"$t/sh.out" 2>&1
{ grep -q 'apt-get install -y -q --no-install-recommends zsh' "$t/sh.out" && grep -q 'unpack to /usr/local/share/ainkrad/shell/ohmyzsh' "$t/sh.out" && grep -q 'powerlevel10k' "$t/sh.out" && grep -q 'zsh-autosuggestions' "$t/sh.out" && grep -q 'zsh-syntax-highlighting' "$t/sh.out" && grep -q 'as /usr/local/share/ainkrad/shell/.zshrc' "$t/sh.out"; } && ok || bad "install-linux.sh --pty does not plan zsh and the profile: $(cat "$t/sh.out")"
bash "$ROOT/deploy/install-linux.sh" --binary "$t/rb" --prefix "$d2" --dry-run >"$t/sh2.out" 2>&1
grep -q 'ainkrad/shell' "$t/sh2.out" && bad "a runner without terminals still plans the shell profile" || ok
bash "$ROOT/scripts/install/runner-only.sh" --binary "$t/dd" --invite core.example.com/abc.def --dry-run >"$t/sh3.out" 2>&1
grep -q 'ainkrad/shell/.zshrc' "$t/sh3.out" && ok || bad "the runner-only dry run does not plan the Ainkrad shell profile: $(cat "$t/sh3.out")"
o=$(run_i); grep -q 'ainkrad/shell/.zshrc' <<<"$o" && ok || bad "the guided dry run does not plan the Ainkrad shell profile for the built-in runner"
grep -q "xz-utils zsh'" "$gs" && ok || bad "get.sh does not install zsh with the prerequisites"
grep -q 'deploy/shell' "$ROOT/scripts/release/dry.sh" && ok || bad "the installer bundle does not carry deploy/shell"
# a download that does not match its pin installs nothing
mkdir -p "$t/badfrom"
# shellcheck source=deploy/shell/pins.sh
. "$sh_dir/pins.sh"
for c in $OMZ_COMMIT $P10K_COMMIT $AUTOSUGGESTIONS_COMMIT $SYNTAX_HIGHLIGHTING_COMMIT; do echo junk >"$t/badfrom/$c.tar.gz"; done
if AINKRAD_SHELL_NOT_ROOT=1 bash "$sh_dir/install-shell.sh" --dest "$t/shdest/shell" --from "$t/badfrom" >"$t/sh4.out" 2>&1; then bad "a mismatching archive was installed"
else { grep -q 'does not match its pinned SHA-256' "$t/sh4.out" && [ ! -e "$t/shdest/shell" ]; } && ok || bad "a mismatch did not stop cleanly: $(cat "$t/sh4.out")"; fi
# the terminal start: zsh -l with ZDOTDIR, the profile read-only in the sandbox, ZDOTDIR on the allow-list, a logged fallback
grep -q 'spec.env.insert("ZDOTDIR"' "$ROOT/crates/runner/src/v2/pty.rs" && grep -q '"ZDOTDIR"' "$ROOT/crates/runner/src/v2/pty.rs" && grep -q 'SHELL_DIR' "$ROOT/crates/runner/src/v2/termbox.rs" && grep -q 'starting the login shell' "$ROOT/crates/runner/src/v2/pty.rs" && ok || bad "the runner does not start zsh -l with ZDOTDIR, bind the profile read-only and log the fallback"

# --- the outside port probe (N6): a signed POST /v1/probe to the sign-in service; a fake service verifies the signature with openssl ---
if command -v openssl >/dev/null && command -v curl >/dev/null; then
cat >"$t/fake-signin.py" <<'PYEOF'
import base64, hashlib, http.server, json, subprocess, sys, tempfile, os
mode, port_file, log = sys.argv[1], sys.argv[2], sys.argv[3]
def ub(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def der_int(b):
    b = b.lstrip(b"\0") or b"\0"
    if b[0] & 0x80: b = b"\0" + b
    return b"\x02" + bytes([len(b)]) + b
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        h = self.headers
        spki = ub(h["Ainkrad-Key"]); sig = ub(h["Ainkrad-Signature"])
        ok = (self.path == "/v1/probe" and len(spki) == 91 and len(sig) == 64 and h["Ainkrad-Alg"] == "ES256"
              and h["Ainkrad-Core"] == base64.urlsafe_b64encode(hashlib.sha256(spki).digest()).decode().rstrip("=")
              and len(ub(h["Ainkrad-Nonce"])) == 16 and h["Content-Type"] == "application/json")
        msg = "\n".join(["AINKRAD-SVC-V1", h["Ainkrad-Core"], "ES256", "POST", self.path, h["Ainkrad-Timestamp"], h["Ainkrad-Nonce"],
                         base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")])
        d = tempfile.mkdtemp()
        seq = der_int(sig[:32]) + der_int(sig[32:])
        open(d + "/sig", "wb").write(b"\x30" + bytes([len(seq)]) + seq)
        open(d + "/msg", "wb").write(msg.encode())
        pem = "-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(spki).decode() + "-----END PUBLIC KEY-----\n"
        open(d + "/pub", "w").write(pem)
        ok = ok and subprocess.run(["openssl", "dgst", "-sha256", "-verify", d + "/pub", "-signature", d + "/sig", d + "/msg"], capture_output=True).returncode == 0
        open(log, "a").write(("signed-ok " if ok else "signed-BAD ") + body.decode() + "\n")
        ports = json.loads(body)["ports"]
        if not ok: out, code = {"error": {"code": "bad_signature"}}, 401
        elif mode == "down": out, code = {"error": {"code": "internal"}}, 500
        else:
            res = []
            for p in ports:
                closed = mode == "closed443" and p == 443
                res.append({"port": p, "open": False, "ms": 4001, "reason": "timeout"} if closed else
                           {"port": p, "open": False, "ms": 3, "reason": "refused_or_unreachable"} if mode == "refused" else {"port": p, "open": True, "ms": 30})
            out, code = {"ip": "203.0.113.7", "results": res}, 200
        data = json.dumps(out).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(port_file, "w").write(str(s.server_port))
s.serve_forever()
PYEOF
probe() { # MODE: runs pc_probe "443 80" against the fake service in MODE (plain output)
  rm -f "$t/port" "$t/plog"; "$PY" "$t/fake-signin.py" "$1" "$t/port" "$t/plog" & _pid=$!
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s "$t/port" ] && break; sleep 0.2; done
  PATH="$t/base:$(dirname "$(command -v openssl)"):$(dirname "$(command -v curl)")" NO_COLOR=1 AINKRAD_SIGNIN_URL="http://127.0.0.1:$(cat "$t/port")" \
    sh -c '. "$1"; . "$2"; ui_init; pc_probe "443 80"; echo "rc=$?"; echo "WHAT=$PC_WHAT"; echo "TODO=$PC_TODO"' _ "$ROOT/scripts/install/ui.sh" "$ROOT/scripts/install/precheck.sh" 2>&1
  kill "$_pid" 2>/dev/null; wait "$_pid" 2>/dev/null
}
for c in mktemp date sleep openssl; do p=$(command -v "$c") && ln -sf "$p" "$t/base/$c"; done
o=$(probe open); { grep -qx 'rc=0' <<<"$o" && grep -q 'signed-ok {"ports":\[443,80\]}' "$t/plog"; } && ok || bad "an open port was not passed with a verifying signature: $o $(cat "$t/plog" 2>/dev/null)"
o=$(probe refused); grep -qx 'rc=0' <<<"$o" && ok || bad "a refusal (it reached this machine, nothing listens yet) blocked the install: $o"
o=$(probe closed443)
{ grep -qx 'rc=1' <<<"$o" && grep -q 'WHAT=port 443 is closed from the internet' <<<"$o" && grep -q 'TODO=open it in your cloud firewall (OCI: security list / NSG' <<<"$o"; } && ok || bad "a closed 443 was not reported with the cloud-firewall advice: $o"
o=$(probe down); { grep -qx 'rc=0' <<<"$o" && grep -q 'WARNING' <<<"$o"; } && ok || bad "a failing service blocked the install or was silent: $o"
o=$(PATH="$t/base:$(dirname "$(command -v openssl)"):$(dirname "$(command -v curl)")" NO_COLOR=1 AINKRAD_SIGNIN_URL=http://127.0.0.1:9 sh -c '. "$1"; . "$2"; ui_init; pc_probe "443"; echo "rc=$?"' _ "$ROOT/scripts/install/ui.sh" "$ROOT/scripts/install/precheck.sh" 2>&1)
{ grep -qx 'rc=0' <<<"$o" && grep -q 'unreachable' <<<"$o"; } && ok || bad "an unreachable service blocked the install or was silent: $o"
o=$(AINKRAD_SKIP_PROBE=1 PATH="$t/base" NO_COLOR=1 sh -c '. "$1"; . "$2"; ui_init; pc_probe "443"; echo "rc=$?"' _ "$ROOT/scripts/install/ui.sh" "$ROOT/scripts/install/precheck.sh" 2>&1); grep -qx 'rc=0' <<<"$o" && ok || bad "AINKRAD_SKIP_PROBE did not skip: $o"
fi

echo "precheck tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
