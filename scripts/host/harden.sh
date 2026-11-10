#!/usr/bin/env bash
# Idempotent hardening for an Ainkrad Core host (E1-16.3). Run as root on a fresh Ubuntu VM:
#   ssh <user>@<host> 'sudo bash -s' < scripts/host/harden.sh
# :22 stays open. Key-only SSH is switched on ONLY when it cannot lock the operator out: the installing user (SUDO_USER,
# else root) has a key in authorized_keys AND every current SSH session logged in with a key. Otherwise sshd is left
# exactly as it is and a warning says why. The firewall goes in its own chain; rules already in INPUT are kept.
set -euo pipefail

# --- helpers; AINKRAD_HARDEN_SOURCE_ONLY=1 stops after them (the install tests source this file) ---
login_user() { echo "${SUDO_USER:-root}"; }
has_authorized_key() { # USER: a non-comment, non-blank line in the user's authorized_keys
  local home; home=$(getent passwd "$1" | cut -d: -f6)
  [ -z "${AINKRAD_TEST_HOME:-}" ] || home=$AINKRAD_TEST_HOME
  [ -n "$home" ] && grep -qEv '^[[:space:]]*(#|$)' "$home/.ssh/authorized_keys" 2>/dev/null
}
ssh_peers() { # addresses of the established SSH sessions, one per line
  if [ -n "${AINKRAD_TEST_PEERS+x}" ]; then printf '%s\n' "$AINKRAD_TEST_PEERS" | tr ' ' '\n'; return; fi
  ss -Htn state established '( sport = :22 )' 2>/dev/null | awk '{print $4}' |
    sed -E 's/^\[?(.*)\]?:[0-9]+$/\1/; s/^::ffff://; s/\]$//' | sort -u || true
}
ssh_log() { # sshd's recent "Accepted ..." lines
  if [ -n "${AINKRAD_SSH_LOG:-}" ]; then cat "$AINKRAD_SSH_LOG"; return; fi
  { journalctl -u ssh -u sshd --no-pager -o cat --since "-3 days" 2>/dev/null; cat /var/log/auth.log 2>/dev/null; } | grep 'Accepted ' || true
}
sshd_safe() { # 0 when key-only SSH cannot lock the installing user out; else REASON says why
  local u p log; u=$(login_user); REASON=''
  has_authorized_key "$u" || { REASON="$u has no key in authorized_keys"; return 1; }
  log=$(ssh_log)
  for p in $(ssh_peers); do
    printf '%s\n' "$log" | grep -F "Accepted publickey for " | grep -qF " from $p " ||
      { REASON="the current SSH session from $p did not log in with a key"; return 1; }
  done
}
[ -z "${BASH_SOURCE[0]:-}" ] || [ "${BASH_SOURCE[0]}" = "$0" ] || [ "${AINKRAD_HARDEN_SOURCE_ONLY:-}" != 1 ] || return 0
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

# 1. The service account and its directories (state, config). No login shell, no password.
id ainkrad >/dev/null 2>&1 || useradd --system --home-dir /var/lib/ainkrad --create-home --shell /usr/sbin/nologin ainkrad
install -d -o ainkrad -g ainkrad -m 0750 /var/lib/ainkrad /var/lib/ainkrad/backups
install -d -o root -g ainkrad -m 0750 /etc/ainkrad

# 2. sshd: key only, no root password login, but only when that cannot lock you out (see the header).
if sshd_safe; then
  install -d /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/70-ainkrad.conf <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
CONF
  if sshd -t; then systemctl reload ssh 2>/dev/null || systemctl reload sshd
  else rm -f /etc/ssh/sshd_config.d/70-ainkrad.conf; echo "WARNING: sshd -t rejected the hardening file; sshd left as it was" >&2; fi
else
  echo "WARNING: sshd left as it is (password login not turned off): $REASON. Add your public key to ~/.ssh/authorized_keys, log in with it, then re-run." >&2
fi

# 3. Firewall: new inbound only on 22 (SSH), 80 (ACME HTTP-01) and 443 (Core), IPv4 and IPv6. Own chain, ahead of
#    the rules already there (they are kept, not flushed); with an active ufw it uses ufw instead.
#    The Core also listens on loopback only for local tools.
# AINKRAD_SSH_FROM=<cidr>[,<cidr>...] admits new SSH only from those IPv4 networks (scripts/install.sh checks that
# the current session's address is inside first); unset, SSH is open to all. IPv6 SSH is never filtered by it.
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  if [ -n "${AINKRAD_SSH_FROM:-}" ]; then
    for cidr in ${AINKRAD_SSH_FROM//,/ }; do ufw allow from "$cidr" to any port 22 proto tcp >/dev/null; done
  else ufw allow 22/tcp >/dev/null; fi
  ufw allow 80/tcp >/dev/null; ufw allow 443/tcp >/dev/null
  ufw default deny incoming >/dev/null
else
  for ipt in iptables ip6tables; do
    command -v "$ipt" >/dev/null || { echo "WARNING: no $ipt: that address family is not filtered" >&2; continue; }
    icmp=icmp; [ "$ipt" = ip6tables ] && icmp=ipv6-icmp
    "$ipt" -N AINKRAD_IN 2>/dev/null || "$ipt" -F AINKRAD_IN
    "$ipt" -A AINKRAD_IN -m state --state RELATED,ESTABLISHED -j ACCEPT
    "$ipt" -A AINKRAD_IN -p "$icmp" -j ACCEPT
    "$ipt" -A AINKRAD_IN -i lo -j ACCEPT
    if [ -n "${AINKRAD_SSH_FROM:-}" ] && [ "$ipt" = iptables ]; then
      for cidr in ${AINKRAD_SSH_FROM//,/ }; do
        "$ipt" -A AINKRAD_IN -p tcp -m state --state NEW --dport 22 -s "$cidr" -j ACCEPT
      done
    else
      "$ipt" -A AINKRAD_IN -p tcp -m state --state NEW --dport 22 -j ACCEPT
    fi
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
echo "--- firewall:"; { ufw status 2>/dev/null | head -12; iptables -S INPUT; iptables -S AINKRAD_IN; ip6tables -S AINKRAD_IN; } 2>/dev/null | sed 's/^/  /'
echo "--- service account: $(getent passwd ainkrad | cut -d: -f1,6,7)"
echo "--- core_pattern: $(cat /proc/sys/kernel/core_pattern); suid_dumpable: $(cat /proc/sys/fs/suid_dumpable); swap devices: $(swapon --show --noheadings | wc -l)"
