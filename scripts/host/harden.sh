#!/usr/bin/env bash
# Idempotent hardening for an Ainkrad Core host (E1-16.3). Run as root on a fresh Ubuntu VM:
#   ssh <user>@<host> 'sudo bash -s' < scripts/host/harden.sh
# SSH stays reachable. Key-only SSH is switched on ONLY when it cannot lock the operator out: the installing user
# (SUDO_USER, else root) has a key (authorized_keys, authorized_keys2 or the AuthorizedKeysFile sshd really uses), the key
# setup is plain (an AuthorizedKeysCommand or SSH certificates make the guard refuse: it cannot see them), and every
# current SSH session logged in with a key (matched by the sshd process of that connection in sshd's log; with no `ss`
# it refuses). Otherwise sshd is left exactly as it is and a warning says why. Only the INSTALLING user is protected:
# other accounts that log in with a password only are locked out by design once key-only is on. The drop-in is
# 01-ainkrad.conf (first match wins, so it beats cloud-init's 50-cloud-init.conf) and the result is verified with `sshd -T`.
# Firewall: ufw when it is installed (the allows are added, then it is enabled), else an own iptables chain (IPv4 and IPv6)
# that is saved with netfilter-persistent. Inbound allowed: the sshd port(s) read from sshd, 80 and 443. If the sshd ports
# cannot be determined the reject rule is NOT applied. Docker-published ports go through FORWARD and are not affected;
# inbound UDP (WireGuard...) and any other TCP port are rejected. A warning list is also appended to $AINKRAD_HARDEN_WARN.
set -euo pipefail

# The AINKRAD_TEST_* overrides exist for the install tests only: honoured with AINKRAD_HARDEN_SOURCE_ONLY=1, else dropped.
if [ "${AINKRAD_HARDEN_SOURCE_ONLY:-}" != 1 ]; then unset AINKRAD_TEST_PEERS AINKRAD_SSH_LOG AINKRAD_TEST_HOME AINKRAD_TEST_SSHD_T AINKRAD_TEST_SS AINKRAD_TEST_SSH_LISTEN AINKRAD_TEST_DROPIN AINKRAD_TEST_RULES_V4; fi

# --- helpers; AINKRAD_HARDEN_SOURCE_ONLY=1 stops after them (the install tests source this file) ---
warn() { echo "WARNING: $*" >&2; [ -z "${AINKRAD_HARDEN_WARN:-}" ] || echo "$*" >>"$AINKRAD_HARDEN_WARN"; }
login_user() { echo "${SUDO_USER:-root}"; }
sshd_t() { # sshd's effective configuration (fails when sshd cannot print it)
  if [ -n "${AINKRAD_TEST_SSHD_T+x}" ]; then cat "$AINKRAD_TEST_SSHD_T"; return; fi
  sshd -T 2>/dev/null
}
ss_p() { # established SSH connections with their processes: ss -Htnp for each port
  local port
  if [ -n "${AINKRAD_TEST_SS+x}" ]; then cat "$AINKRAD_TEST_SS"; return; fi
  command -v ss >/dev/null || return 1
  for port in $(ssh_ports); do ss -Htnp state established "( sport = :$port )" 2>/dev/null || true; done
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
peer_ip() { sed -E 's/^\[?(.*)\]?:[0-9]+$/\1/; s/^::ffff://; s/\]$//'; }
ssh_peers() { # addresses of the established SSH sessions (on any sshd port), one per line
  if [ -n "${AINKRAD_TEST_PEERS+x}" ]; then printf '%s\n' "$AINKRAD_TEST_PEERS" | tr ' ' '\n'; return; fi
  ss_p | awk '{print $4}' | peer_ip | sort -u || true
}
has_authorized_key() { # USER: a non-comment line in one of the files sshd reads for that user
  local home f files cfg
  home=$(getent passwd "$1" | cut -d: -f6 || true)
  [ -z "${AINKRAD_TEST_HOME:-}" ] || home=$AINKRAD_TEST_HOME
  [ -n "$home" ] || return 1
  cfg=$(sshd_t | awk 'tolower($1)=="authorizedkeysfile"{ $1=""; print }' || true)
  files=${cfg:-.ssh/authorized_keys .ssh/authorized_keys2} # what sshd reads; its default is both files
  for f in $files; do
    f=${f//%h/$home}; f=${f//%u/$1}
    case $f in /*) ;; *) f=$home/$f ;; esac
    grep -qEv '^[[:space:]]*(#|$)' "$f" 2>/dev/null && return 0
  done
  return 1
}
ssh_unseen_auth() { # 0 when sshd also authenticates by something the guard cannot see (a command, certificates)
  local c
  c=$(sshd_t | awk 'tolower($1)=="authorizedkeyscommand" || tolower($1)=="trustedusercakeys" { if ($2 != "none") print $1 }' || true)
  [ -n "$c" ]
}
ssh_log() { # sshd's recent log with the process id: "sshd[PID]: Accepted publickey for ..."
  if [ -n "${AINKRAD_SSH_LOG:-}" ]; then cat "$AINKRAD_SSH_LOG"; return; fi
  { journalctl -u ssh -u sshd --no-pager -o short --since "-3 days" 2>/dev/null; cat /var/log/auth.log 2>/dev/null; } | grep 'Accepted ' || true
}
sshd_safe() { # 0 when key-only SSH cannot lock the installing user out; else REASON says why
  local u line pid ok log lines; u=$(login_user); REASON=''
  has_authorized_key "$u" || { REASON="$u has no key in authorized_keys (or the file sshd reads)"; return 1; }
  ssh_unseen_auth && { REASON="sshd also uses an AuthorizedKeysCommand or certificates, which this check cannot see"; return 1; }
  lines=$(ss_p) || { REASON="ss is not available, so the current SSH sessions cannot be checked"; return 1; }
  log=$(ssh_log)
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    ok=0
    for pid in $(printf '%s\n' "$line" | grep -oE 'pid=[0-9]+' | cut -d= -f2); do
      printf '%s\n' "$log" | grep -qE "sshd\[$pid\]: Accepted publickey for " && ok=1
    done
    [ "$ok" = 1 ] || { REASON="the SSH session $(printf '%s' "$line" | awk '{print $4}') did not log in with a key (or its process is not in sshd's log)"; return 1; }
  done <<EOF
$lines
EOF
}
fw_persisted() { # 0 when the firewall will survive a reboot
  if command -v ufw >/dev/null; then grep -q '^Status: active' <<<"$(ufw status 2>/dev/null)" && return 0; fi
  grep -qs AINKRAD_IN "${AINKRAD_TEST_RULES_V4:-/etc/iptables/rules.v4}"
}
# apply_sshd: key only, no root password login, but only when that cannot lock you out (see the header).
apply_sshd() {
  local dropdir=${AINKRAD_TEST_DROPIN:-/etc/ssh/sshd_config.d}
  rm -f "$dropdir/70-ainkrad.conf" # the earlier name: it lost to 50-cloud-init.conf
  if sshd_safe; then
    install -d "$dropdir"
    cat > "$dropdir/01-ainkrad.conf" <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
CONF
    if sshd -t; then systemctl reload ssh 2>/dev/null || systemctl reload sshd; fi
    # not `sshd_t | grep -q`: grep exits early, the writer gets SIGPIPE and pipefail turns that into a false "no"
    if ! sshd -t || ! grep -qi '^passwordauthentication no' <<<"$(sshd_t)"; then
      rm -f "$dropdir/01-ainkrad.conf"; sshd -t && { systemctl reload ssh 2>/dev/null || systemctl reload sshd; } || true
      warn "sshd did not take the key-only settings (is there an 'Include $dropdir/*.conf'?): password login is still allowed"
    fi
  else
    warn "sshd left as it is (password login not turned off): $REASON. Add your public key to ~/.ssh/authorized_keys, log in with it, then re-run."
  fi
}

# apply_firewall: new inbound only on the sshd port(s), 80 (ACME HTTP-01) and 443 (Core). ufw if installed, else an own
#    iptables chain for IPv4 and IPv6 ahead of the rules already there (kept, not flushed), saved for the next boot.
#    The Core also listens on loopback only for local tools.
# AINKRAD_SSH_FROM=<cidr>[,<cidr>...] admits new SSH only from those IPv4 networks (scripts/install.sh checks that
# the current session's address is inside first); unset, SSH is open to all. IPv6 SSH is never filtered by it.
apply_firewall() {
  local ports sp cidr ipt icmp port
  ports=$(ssh_ports)
  if ! ssh_ports_known; then
    warn "could not determine sshd's port(s): the firewall was NOT changed"
  elif command -v ufw >/dev/null; then
    for sp in $ports; do
      if [ -n "${AINKRAD_SSH_FROM:-}" ]; then
        for cidr in ${AINKRAD_SSH_FROM//,/ }; do ufw allow from "$cidr" to any port "$sp" proto tcp >/dev/null; done
      else ufw allow "$sp"/tcp >/dev/null; fi
    done
    ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
    ufw default deny incoming >/dev/null
    ufw --force enable >/dev/null
  else
    for ipt in iptables ip6tables; do
      command -v "$ipt" >/dev/null || { warn "no $ipt: that address family is not filtered"; continue; }
      icmp=icmp; [ "$ipt" = ip6tables ] && icmp=ipv6-icmp
      "$ipt" -N AINKRAD_IN 2>/dev/null || "$ipt" -F AINKRAD_IN
      "$ipt" -A AINKRAD_IN -m state --state RELATED,ESTABLISHED -j ACCEPT
      "$ipt" -A AINKRAD_IN -p "$icmp" -j ACCEPT
      "$ipt" -A AINKRAD_IN -i lo -j ACCEPT
      for sp in $ports; do
        if [ -n "${AINKRAD_SSH_FROM:-}" ] && [ "$ipt" = iptables ]; then
          for cidr in ${AINKRAD_SSH_FROM//,/ }; do
            "$ipt" -A AINKRAD_IN -p tcp -m state --state NEW --dport "$sp" -s "$cidr" -j ACCEPT
          done
        else
          "$ipt" -A AINKRAD_IN -p tcp -m state --state NEW --dport "$sp" -j ACCEPT
        fi
      done
      for port in 80 443; do
        "$ipt" -A AINKRAD_IN -p tcp -m state --state NEW --dport "$port" -j ACCEPT
      done
      if [ "$ipt" = iptables ]; then "$ipt" -A AINKRAD_IN -j REJECT --reject-with icmp-host-prohibited
      else "$ipt" -A AINKRAD_IN -j REJECT --reject-with icmp6-adm-prohibited; fi
      # One jump at the top of INPUT, added once; nothing else in INPUT is touched.
      "$ipt" -C INPUT -j AINKRAD_IN 2>/dev/null || "$ipt" -I INPUT 1 -j AINKRAD_IN
    done
    if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null; fi
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

# 3. Firewall: sshd port(s), 80 and 443 in; ufw or an own iptables chain, saved for the next boot (apply_firewall above).
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
