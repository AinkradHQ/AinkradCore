#!/bin/sh
# Opens or closes the relay's QUIC address-discovery port (UDP 7842) in the host's iptables, and only
# when you run it: the iroh feature is opt-in, so the port stays closed until then.
#   firewall.sh enable | disable
# The cloud layer is separate: add or remove a matching ingress rule (UDP 7842 from anywhere) in the
# security list or network security group that guards the host. TCP 80 and 443 must already be open.
set -eu
PORT=7842
RULE="-p udp --dport $PORT -m comment --comment ainkrad-iroh-relay -j ACCEPT"
case "${1:-}" in
  enable)  iptables -C INPUT $RULE 2>/dev/null || iptables -I INPUT $RULE ;;
  disable) while iptables -C INPUT $RULE 2>/dev/null; do iptables -D INPUT $RULE; done ;;
  *) echo "usage: $0 enable|disable" >&2; exit 2 ;;
esac
# Persist with the host's own mechanism (netfilter-persistent, iptables-save, ...).
