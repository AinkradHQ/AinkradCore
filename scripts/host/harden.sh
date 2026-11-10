#!/usr/bin/env bash
# Idempotent hardening for an Ainkrad Core host (E1-16.3). Run as root on a fresh Ubuntu VM:
#   ssh <user>@<host> 'sudo bash -s' < scripts/host/harden.sh
# SSH stays reachable. Key-only SSH is switched on ONLY when it cannot lock the operator out: the installing user
# (SUDO_USER, else root) has a real key line (authorized_keys, authorized_keys2 or the AuthorizedKeysFile sshd really uses),
# the key setup is plain (an AuthorizedKeysCommand or SSH certificates make the guard refuse: it cannot see them), and every
# current SSH session logged in with a key (matched by the sshd process of that connection, the LAST "Accepted" line of
# that process in this boot's sshd log; with no working `ss` it refuses). Otherwise sshd is left exactly as it is and a
# warning says why. Only the INSTALLING user is protected: other accounts that log in with a password only are locked out
# by design once key-only is on. The drop-in is 01-ainkrad.conf (first match wins, so it beats cloud-init's
# 50-cloud-init.conf) and the result is verified with `sshd -T`.
# Firewall (AINKRAD_FIREWALL=no skips the whole step): EVERYTHING inbound except the sshd port(s), 80 and 443 is rejected,
# TCP and UDP, IPv4 and IPv6 (WireGuard, mail, k3s 6443, exporters... stop being reachable); the notice naming the other
# listening services is printed first. Path: iptables when saved rules (/etc/iptables/rules.v4|v6) exist (netfilter-persistent
# owns the firewall there and a ufw chain would lose to it), else ufw when it is installed, else an own chain; the choice and
# its reason are printed. Docker-published ports go through FORWARD and are not affected. If the sshd ports cannot be
# determined nothing is changed. A warning list is also appended to $AINKRAD_HARDEN_WARN, and the outcome to $AINKRAD_HARDEN_STATE.
set -euo pipefail

# AINKRAD_HARDEN_SOURCE_ONLY=1 is for sourcing in the install tests: executed, the script does nothing.
if [ "${AINKRAD_HARDEN_SOURCE_ONLY:-}" = 1 ] && [ "${BASH_SOURCE[0]:-}" = "$0" ]; then
  echo "harden.sh: AINKRAD_HARDEN_SOURCE_ONLY=1 is for tests that source this file; nothing was done" >&2; exit 0
fi
# The AINKRAD_TEST_* overrides exist for the install tests only: honoured with AINKRAD_HARDEN_SOURCE_ONLY=1, else dropped.
if [ "${AINKRAD_HARDEN_SOURCE_ONLY:-}" != 1 ]; then unset AINKRAD_TEST_PEERS AINKRAD_SSH_LOG AINKRAD_TEST_HOME AINKRAD_TEST_SSHD_T AINKRAD_TEST_SS AINKRAD_TEST_SSH_LISTEN AINKRAD_TEST_DROPIN AINKRAD_TEST_RULES_V4 AINKRAD_TEST_LISTEN_ALL AINKRAD_TEST_UFW_DEFAULT; fi

# --- helpers; AINKRAD_HARDEN_SOURCE_ONLY=1 stops after them (the install tests source this file) ---
warn() { echo "WARNING: $*" >&2; [ -z "${AINKRAD_HARDEN_WARN:-}" ] || echo "$*" >>"$AINKRAD_HARDEN_WARN"; }
state() { [ -z "${AINKRAD_HARDEN_STATE:-}" ] || echo "$*" >>"$AINKRAD_HARDEN_STATE"; }
login_user() { echo "${SUDO_USER:-root}"; }
sshd_t() { # sshd's effective configuration (fails when sshd cannot print it)
  if [ -n "${AINKRAD_TEST_SSHD_T+x}" ]; then cat "$AINKRAD_TEST_SSHD_T"; return; fi
  sshd -T 2>/dev/null
}
ss_p() { # established SSH connections with their processes; FAILS when ss is missing or errors (the guard then refuses)
  local port
  if [ -n "${AINKRAD_TEST_SS+x}" ]; then cat "$AINKRAD_TEST_SS"; return; fi
  command -v ss >/dev/null || return 1
  for port in $(ssh_ports); do ss -Htnp state established "( sport = :$port )" 2>/dev/null || return 1; done
}
listening_ssh_ports() { # ports a running sshd listens on (needs ss; the test override is the same text as `ss -Hltnp`)
  { if [ -n "${AINKRAD_TEST_SSH_LISTEN+x}" ]; then cat "$AINKRAD_TEST_SSH_LISTEN"; else ss -Hltnp 2>/dev/null; fi; } |
    grep '"sshd"' | awk '{print $4}' | sed 's/.*://' || true
}
ssh_ports() { # the TCP ports sshd listens on: sshd -T, else the config files, else 22; plus what really listens
  local ports
  ports=$(sshd_t | awk '/^port /{print $2}' || true)
  if [ -z "$ports" ]; then
    ports=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk 'tolower($1)=="port"{print $2}' || true)
  fi
  [ -n "$ports" ] || ports=22
  { printf '%s\n' "$ports"; listening_ssh_ports; } | sort -un
}
ssh_ports_known() { # 0 when the ports above are certain: sshd printed them, a running sshd shows them, or sshd is not installed
  [ -n "$(sshd_t | awk '/^port /{print $2}' || true)" ] || [ -n "$(listening_ssh_ports)" ] || ! command -v sshd >/dev/null
}
other_listeners() { # listening services this firewall will make unreachable: "proto port process" (not ssh/80/443/loopback/DHCP)
  local ports; ports=" $(ssh_ports | tr '\n' ' ') 80 443 68 546 "
  { if [ -n "${AINKRAD_TEST_LISTEN_ALL+x}" ]; then cat "$AINKRAD_TEST_LISTEN_ALL"; else ss -Hltnup 2>/dev/null; fi; } |
    awk -v ports="$ports" '{
      addr = $5; port = addr; sub(/.*:/, "", port);
      if (addr ~ /^127\./ || addr ~ /^\[::1\]/ || addr ~ /^::1/) next;
      if (index(ports, " " port " ")) next;
      proc = $7; sub(/^users:\(\("/, "", proc); sub(/".*/, "", proc);
      print $1, port, proc }' | sort -u || true
}
firewall_notice() { # printed BEFORE the firewall is applied, on every path
  local l; l=$(other_listeners)
  echo "  Firewall: everything inbound is rejected except ssh ($(ssh_ports | tr '\n' ' ' | sed 's/ $//; s/ /, /g')), 80 and 443 -- TCP and UDP, IPv4 and IPv6."
  if [ -n "$l" ]; then
    echo "  These are listening now and will STOP being reachable from other machines:"
    printf '%s\n' "$l" | sed 's/^/    /'
    echo "  To keep them: AINKRAD_FIREWALL=no (skips this step), or open them yourself afterwards."
  fi
}
peer_ip() { sed -E 's/^\[?(.*)\]?:[0-9]+$/\1/; s/^::ffff://; s/\]$//'; }
ssh_peers() { # addresses of the established SSH sessions (on any sshd port), one per line
  if [ -n "${AINKRAD_TEST_PEERS+x}" ]; then printf '%s\n' "$AINKRAD_TEST_PEERS" | tr ' ' '\n'; return; fi
  ss_p | awk '{print $4}' | peer_ip | sort -u || true
}
is_key_line() { # a real authorized_keys entry: [options] keytype base64 [comment]
  grep -qE '(^|[[:space:]])(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/]+=*([[:space:]]|$)' <<<"$1"
}
has_authorized_key() { # USER: a real key line in one of the files sshd reads for that user
  local home f files cfg line
  home=$(getent passwd "$1" | cut -d: -f6 || true)
  [ -z "${AINKRAD_TEST_HOME:-}" ] || home=$AINKRAD_TEST_HOME
  [ -n "$home" ] || return 1
  cfg=$(sshd_t | awk 'tolower($1)=="authorizedkeysfile"{ $1=""; print }' || true)
  files=${cfg:-.ssh/authorized_keys .ssh/authorized_keys2} # what sshd reads; its default is both files
  for f in $files; do
    f=${f//%h/$home}; f=${f//%u/$1}
    case $f in /*) ;; *) f=$home/$f ;; esac
    [ -r "$f" ] || continue
    while IFS= read -r line || [ -n "$line" ]; do
      case $line in '' | '#'*) continue ;; esac
      is_key_line "$line" && return 0
    done <"$f"
  done
  return 1
}
ssh_unseen_auth() { # 0 when sshd also authenticates by something the guard cannot see (a command, certificates)
  local c
  c=$(sshd_t | awk 'tolower($1)=="authorizedkeyscommand" || tolower($1)=="trustedusercakeys" { if ($2 != "none") print $1 }' || true)
  [ -n "$c" ]
}
ssh_log() { # sshd's log of THIS boot with the process id: "sshd[PID]" (OpenSSH >= 9.8: "sshd-session[PID]")
  if [ -n "${AINKRAD_SSH_LOG:-}" ]; then cat "$AINKRAD_SSH_LOG"; return; fi
  if command -v journalctl >/dev/null; then journalctl -b -u ssh -u sshd --no-pager -o short 2>/dev/null | grep 'Accepted ' || true
  else grep 'Accepted ' /var/log/auth.log 2>/dev/null || true; fi
}
sshd_safe() { # 0 when key-only SSH cannot lock the installing user out; else REASON says why
  local u line pid ok log lines last; u=$(login_user); REASON=''
  has_authorized_key "$u" || { REASON="$u has no real key line in authorized_keys (or the file sshd reads)"; return 1; }
  ssh_unseen_auth && { REASON="sshd also uses an AuthorizedKeysCommand or certificates, which this check cannot see"; return 1; }
  lines=$(ss_p) || { REASON="ss is missing or failed, so the current SSH sessions cannot be checked"; return 1; }
  log=$(ssh_log)
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    ok=0
    for pid in $(printf '%s\n' "$line" | grep -oE 'pid=[0-9]+' | cut -d= -f2); do
      # PIDs are reused: only the LAST "Accepted" line of that process counts
      last=$(printf '%s\n' "$log" | grep -E "sshd(-session)?\[$pid\]: Accepted " | tail -n1 || true)
      case $last in *"Accepted publickey for "*) ok=1 ;; esac
    done
    [ "$ok" = 1 ] || { REASON="the SSH session $(printf '%s' "$line" | awk '{print $4}') did not log in with a key (or its process is not in this boot's sshd log)"; return 1; }
  done <<EOF
$lines
EOF
}
rules_v4() { echo "${AINKRAD_TEST_RULES_V4:-/etc/iptables/rules.v4}"; }
rules_v6() { if [ -n "${AINKRAD_TEST_RULES_V4:-}" ]; then echo "$AINKRAD_TEST_RULES_V4.v6"; else echo /etc/iptables/rules.v6; fi; }
saved_rules_exist() { [ -e "$(rules_v4)" ] || [ -e "$(rules_v6)" ]; }
fw_persisted() { # 0 when the firewall will survive a reboot
  if command -v ufw >/dev/null; then grep -q '^Status: active' <<<"$(ufw status 2>/dev/null)" && return 0; fi
  grep -qs AINKRAD_IN "$(rules_v4)"
}
reload_sshd() { systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; }

# apply_sshd: key only, no root password login, but only when that cannot lock you out (see the header).
apply_sshd() {
  local dropdir=${AINKRAD_TEST_DROPIN:-/etc/ssh/sshd_config.d}
  rm -f "$dropdir/70-ainkrad.conf" # the earlier name: it lost to 50-cloud-init.conf
  if ! sshd_safe; then
    warn "sshd left as it is (password login not turned off): $REASON. Add your public key to ~/.ssh/authorized_keys, log in with it, then re-run."
    return 0
  fi
  install -d "$dropdir"
  cat > "$dropdir/01-ainkrad.conf" <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
CONF
  if ! sshd -t; then
    rm -f "$dropdir/01-ainkrad.conf"; warn "sshd -t rejected the key-only settings; sshd left as it was"; return 0
  fi
  if ! reload_sshd; then
    rm -f "$dropdir/01-ainkrad.conf"; warn "sshd could not be reloaded; the key-only settings were removed and sshd is untouched"; return 0
  fi
  # not `sshd_t | grep -q`: grep exits early, the writer gets SIGPIPE and pipefail turns that into a false "no"
  if ! grep -qi '^passwordauthentication no' <<<"$(sshd_t)"; then
    rm -f "$dropdir/01-ainkrad.conf"; reload_sshd || true
    warn "sshd did not take the key-only settings (is there an 'Include $dropdir/*.conf'?): password login is still allowed"
  fi
}

# One address family of the iptables path, built in a NEW chain and swapped in only when complete, so a failure part-way
# leaves the old rules (or none) in force, never a half-built chain. AINKRAD_SSH_FROM (IPv4 CIDRs) limits ssh to those
# networks; with it set IPv6 ssh is closed, as on the ufw path.
fw_family() { # IPTABLES-COMMAND PORTS
  local ipt=$1 ports=$2 icmp=icmp sp port cidr
  [ "$ipt" != ip6tables ] || icmp=ipv6-icmp
  "$ipt" -F AINKRAD_NEW 2>/dev/null && "$ipt" -X AINKRAD_NEW 2>/dev/null || true
  "$ipt" -N AINKRAD_NEW || return 1
  {
    "$ipt" -A AINKRAD_NEW -m state --state RELATED,ESTABLISHED -j ACCEPT &&
    "$ipt" -A AINKRAD_NEW -p "$icmp" -j ACCEPT &&
    "$ipt" -A AINKRAD_NEW -i lo -j ACCEPT || return 1
    if [ "$ipt" = ip6tables ]; then # DHCPv6 replies from the router (NDP is inside ICMPv6 above)
      "$ipt" -A AINKRAD_NEW -p udp -s fe80::/10 --sport 547 --dport 546 -j ACCEPT || return 1
    fi
    for sp in $ports; do
      if [ -n "${AINKRAD_SSH_FROM:-}" ]; then
        [ "$ipt" = iptables ] || continue
        for cidr in ${AINKRAD_SSH_FROM//,/ }; do
          "$ipt" -A AINKRAD_NEW -p tcp -m state --state NEW --dport "$sp" -s "$cidr" -j ACCEPT || return 1
        done
      else "$ipt" -A AINKRAD_NEW -p tcp -m state --state NEW --dport "$sp" -j ACCEPT || return 1; fi
    done
    for port in 80 443; do "$ipt" -A AINKRAD_NEW -p tcp -m state --state NEW --dport "$port" -j ACCEPT || return 1; done
    if [ "$ipt" = iptables ]; then "$ipt" -A AINKRAD_NEW -j REJECT --reject-with icmp-host-prohibited || return 1
    else "$ipt" -A AINKRAD_NEW -j REJECT --reject-with icmp6-adm-prohibited || return 1; fi
  } || { "$ipt" -F AINKRAD_NEW 2>/dev/null; "$ipt" -X AINKRAD_NEW 2>/dev/null; return 1; }
  # swap: hook the complete new chain first, then retire the old one, then give the new one the old name
  "$ipt" -I INPUT 1 -j AINKRAD_NEW || return 1
  while "$ipt" -D INPUT -j AINKRAD_IN 2>/dev/null; do :; done
  "$ipt" -F AINKRAD_IN 2>/dev/null && "$ipt" -X AINKRAD_IN 2>/dev/null || true
  "$ipt" -E AINKRAD_NEW AINKRAD_IN
}

# apply_firewall: see the header. Path: iptables when saved rules exist, else ufw when installed, else iptables.
apply_firewall() {
  local ports sp cidr ipt why path failed=0
  if [ "${AINKRAD_FIREWALL:-yes}" = no ]; then
    warn "the firewall step was skipped (AINKRAD_FIREWALL=no): nothing was changed"; state "firewall=skipped"; return 0
  fi
  ports=$(ssh_ports)
  if ! ssh_ports_known; then
    warn "could not determine sshd's port(s): the firewall was NOT changed"; state "firewall=skipped"; return 0
  fi
  if [ "${AINKRAD_NOTICE_SHOWN:-}" != 1 ]; then firewall_notice; fi
  if saved_rules_exist; then path=iptables; why="saved iptables rules exist (netfilter-persistent owns the firewall; a ufw chain would lose to it)"
  elif command -v ufw >/dev/null; then path=ufw; why="ufw is installed"
  else path=iptables; why="ufw is not installed"; fi
  echo "  Firewall path: $path ($why)."
  if [ "$path" = ufw ]; then
    for sp in $ports; do
      if [ -n "${AINKRAD_SSH_FROM:-}" ]; then
        ufw delete allow "$sp"/tcp >/dev/null 2>&1 || true # the open rule of an earlier run
        for cidr in ${AINKRAD_SSH_FROM//,/ }; do ufw allow from "$cidr" to any port "$sp" proto tcp >/dev/null; done
      else ufw allow "$sp"/tcp >/dev/null; fi
    done
    ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
    ufw default deny incoming >/dev/null
    ufw --force enable >/dev/null
    state "firewall=ufw"
    if grep -qs '^IPV6=no' "${AINKRAD_TEST_UFW_DEFAULT:-/etc/default/ufw}"; then
      warn "ufw is configured with IPV6=no: IPv6 is NOT filtered by this firewall"; state "ipv6=unfiltered"
    fi
  else
    for ipt in iptables ip6tables; do
      if ! command -v "$ipt" >/dev/null || ! "$ipt" -S >/dev/null 2>&1; then
        warn "$ipt is not usable here (missing, or the kernel has no support): that address family is not filtered"; state "ipv6=unfiltered"; continue
      fi
      fw_family "$ipt" "$ports" || {
        warn "the $ipt rules could not be applied completely; the previous rules, if any, are still in force. Check 'iptables -S INPUT'."
        failed=1; continue; }
    done
    if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null || warn "netfilter-persistent save failed"; fi
    if [ "$failed" = 1 ]; then state "firewall=failed"; else state "firewall=iptables"; fi
  fi
  if ! fw_persisted; then warn "the firewall rules are in force only until the next reboot (not saved: no netfilter-persistent or active ufw)"; fi
}
[ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ] || [ "${AINKRAD_HARDEN_SOURCE_ONLY:-}" != 1 ] || return 0
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

# 1. The service account and its directories (state, config). No login shell, no password.
id ainkrad >/dev/null 2>&1 || useradd --system --home-dir /var/lib/ainkrad --create-home --shell /usr/sbin/nologin ainkrad
install -d -o ainkrad -g ainkrad -m 0750 /var/lib/ainkrad /var/lib/ainkrad/backups
install -d -o root -g ainkrad -m 0750 /etc/ainkrad

# 2. sshd: key-only login, only when that cannot lock you out (apply_sshd above).
apply_sshd

# 3. Firewall: everything inbound rejected except sshd port(s), 80 and 443; AINKRAD_FIREWALL=no skips it (apply_firewall above).
apply_firewall

# 4. Services nothing here needs.
for unit in rpcbind.service rpcbind.socket; do
  systemctl disable --now "$unit" 2>/dev/null || true
done

# 5. Security updates apply by themselves; reboots stay manual (a Core restart is an outage).
apt-get install -y -qq unattended-upgrades >/dev/null
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF

# 6. No memory on disk: the Core holds key material in RAM, so a crash must not write a core dump
#    (apport would otherwise copy process memory under /var/crash), and nothing may reach swap.
install -d /etc/sysctl.d /etc/systemd/coredump.conf.d /etc/security/limits.d
cat > /etc/sysctl.d/60-ainkrad-nodump.conf <<'CONF'
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
CONF
printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/10-ainkrad.conf
printf '* hard core 0\n' > /etc/security/limits.d/10-ainkrad-nocore.conf
systemctl disable --now apport.service 2>/dev/null || true
# Stopping apport resets core_pattern, so the sysctl is applied after it.
sysctl --system >/dev/null
rm -rf /var/crash/*
swapoff -a
sed -i -E 's/^([^#].*[[:space:]]swap[[:space:]].*)$/# \1  # disabled by ainkrad harden.sh/' /etc/fstab

# 7. Report what a reviewer needs to see.
echo "--- kvm: $([ -e /dev/kvm ] && echo present || echo absent)"
echo "--- listening:"; ss -tlnp | awk 'NR>1 {print "  " $4}'
echo "--- firewall:"; { ufw status 2>/dev/null | head -12; iptables -S INPUT; iptables -S AINKRAD_IN; ip6tables -S AINKRAD_IN; } 2>/dev/null | sed 's/^/  /' || true
echo "--- service account: $(getent passwd ainkrad | cut -d: -f1,6,7)"
echo "--- core_pattern: $(cat /proc/sys/kernel/core_pattern); suid_dumpable: $(cat /proc/sys/fs/suid_dumpable); swap devices: $(swapon --show --noheadings | wc -l)"
