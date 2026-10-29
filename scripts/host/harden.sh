#!/usr/bin/env bash
# Idempotent hardening for an Ainkrad Core host (E1-16.3). Run as root on a fresh Ubuntu VM:
#   ssh ubuntu@HOST 'sudo bash -s' < scripts/host/harden.sh
# It changes nothing the operator logs in with: sshd keeps key-only login, :22 stays open.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

# 1. The service account and its directories (state, config). No login shell, no password.
id ainkrad >/dev/null 2>&1 || useradd --system --home-dir /var/lib/ainkrad --create-home --shell /usr/sbin/nologin ainkrad
install -d -o ainkrad -g ainkrad -m 0750 /var/lib/ainkrad /var/lib/ainkrad/backups
install -d -o root -g ainkrad -m 0750 /etc/ainkrad

# 2. sshd: key only, no root password login (the cloud image already does this; assert it).
install -d /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/70-ainkrad.conf <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
CONF
sshd -t && systemctl reload ssh

# 3. Firewall: new inbound only on 22 (SSH), 80 (ACME HTTP-01) and 443 (Core). Everything
#    else is rejected. The Core also listens on loopback only for local tools.
iptables -N AINKRAD_IN 2>/dev/null || iptables -F AINKRAD_IN
iptables -A AINKRAD_IN -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A AINKRAD_IN -p icmp -j ACCEPT
iptables -A AINKRAD_IN -i lo -j ACCEPT
for port in 22 80 443; do
  iptables -A AINKRAD_IN -p tcp -m state --state NEW --dport "$port" -j ACCEPT
done
iptables -A AINKRAD_IN -j REJECT --reject-with icmp-host-prohibited
# Route INPUT through the chain exactly once, replacing the image's default rules.
iptables -F INPUT
iptables -A INPUT -j AINKRAD_IN
if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null; fi

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

# 6. Report what a reviewer needs to see.
echo "--- kvm: $([ -e /dev/kvm ] && echo present || echo absent)"
echo "--- listening:"; ss -tlnp | awk 'NR>1 {print "  " $4}'
echo "--- iptables:"; { iptables -S INPUT; iptables -S AINKRAD_IN; } | sed 's/^/  /'
echo "--- service account: $(getent passwd ainkrad | cut -d: -f1,6,7)"
