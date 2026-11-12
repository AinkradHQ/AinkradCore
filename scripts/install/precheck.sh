# shellcheck shell=sh
# The checks that must pass BEFORE anything is installed (N6): the two answers (the DNS name and the email), the ports the Core needs
# are free, this machine's own firewall does not turn inbound TCP 443 (and 80 for http-01) away, and the DNS name points at this
# machine (pc_dns, blocking). POSIX sh. The block between the markers is copied verbatim into
# scripts/get.sh (which cannot source anything before the download): scripts/install/ui-test.sh fails when the two differ.
# Sourced by scripts/install.sh for the standalone checks. Needs the ui-core block (ui_tty_fg) in the same shell.
# The tools it asks (ss, iptables, ufw, nft) are looked up on PATH, so tests put stubs first.
# shellcheck disable=SC2034

# --- precheck begin ---
pc_listener() { # pc_listener PORT: the first line about whatever listens on PORT, unless it is the Core itself; nothing when free
  command -v ss >/dev/null 2>&1 || return 0
  _w=$(ss -Hltnp "sport = :$1" 2>/dev/null || true)
  [ -n "$_w" ] || return 0
  if printf '%s\n' "$_w" | grep -q ainkrad-core; then return 0; fi
  printf '%s\n' "$_w" | head -n 1
}
pc_ipt_verdict() { # pc_ipt_verdict PORT: walks `iptables -S INPUT` in order. Prints open | N (a REJECT/DROP rule at position N) | policy | nothing
  iptables -S INPUT 2>/dev/null | awk -v port="$1" '
    /^-P INPUT/ { pol = $3 }
    /^-A INPUT/ {
      n++
      if ($0 !~ / -j (ACCEPT|REJECT|DROP)/) next
      if ($0 ~ / -i lo/ || $0 ~ / -s / || $0 ~ / -d / || $0 ~ / -p (icmp|udp|ipv6-icmp|esp|ah|gre)/) next
      if ($0 ~ /(ESTABLISHED|RELATED)/ && $0 !~ /NEW/) next
      hit = 1
      for (i = 1; i < NF; i++) if ($i == "--dport" || $i == "--dports") {
        hit = 0; m = split($(i + 1), parts, ",")
        for (k = 1; k <= m; k++) { r = split(parts[k], ab, ":"); lo = ab[1] + 0; hi = (r > 1 ? ab[2] : ab[1]) + 0; if (port + 0 >= lo && port + 0 <= hi) hit = 1 }
      }
      if (!hit) next
      if ($0 ~ / -j ACCEPT/) { print "open"; done = 1; exit }
      print n; done = 1; exit
    }
    END { if (!done && pol == "DROP") print "policy" }'
}
pc_nft_verdict() { # pc_nft_verdict PORT: "FAMILY TABLE CHAIN" of an input chain that turns PORT away, nothing when open or unknown
  nft list ruleset 2>/dev/null | awk -v port="$1" '
    /^table / { fam = $2; tab = $3 }
    /^[ \t]*chain / { ch = $2; inin = 0 }
    /hook input/ { inin = 1; where = fam " " tab " " ch; if ($0 ~ /policy drop/) pol = 1 }
    inin && /dport/ && $0 ~ ("[ {,]" port "[ },]") && /accept/ { ok = 1 }
    inin && /(reject|drop)/ && !/dport/ && !/saddr/ && !/iif/ && !/ct state/ { rej = 1 }
    END { if ((pol || rej) && !ok && where != "") print where }'
}
pc_fw_check() { # pc_fw_check PORT: 0 when this host's firewall lets PORT in (or none can be read); else 1 with PC_FW_WHY and PC_FW_FIX set
  PC_FW_WHY='' PC_FW_FIX=''
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    if ufw status 2>/dev/null | grep -Eq "^$1(/tcp)?[[:space:]].*ALLOW"; then return 0; fi
    PC_FW_WHY="ufw is active and has no rule that allows inbound TCP $1"
    PC_FW_FIX="ufw allow $1/tcp"
    return 1
  fi
  if command -v iptables >/dev/null 2>&1 && iptables -S INPUT >/dev/null 2>&1; then
    _v=$(pc_ipt_verdict "$1")
    case $_v in
      '' | open) return 0 ;;
      policy) PC_FW_WHY="the iptables INPUT policy is DROP and no rule accepts TCP $1"; PC_FW_FIX="iptables -A INPUT -p tcp -m state --state NEW --dport $1 -j ACCEPT" ;;
      *) PC_FW_WHY="iptables rule $_v in the INPUT chain rejects inbound TCP $1 (on Oracle Cloud images this is the stock REJECT rule that lets only SSH in)"
         PC_FW_FIX="iptables -I INPUT $_v -p tcp -m state --state NEW --dport $1 -j ACCEPT" ;;
    esac
    return 1
  fi
  if command -v nft >/dev/null 2>&1; then
    _v=$(pc_nft_verdict "$1")
    [ -n "$_v" ] || return 0
    # shellcheck disable=SC2086 # three plain words: family table chain
    set -- "$1" $_v
    PC_FW_WHY="the nftables input chain $4 turns inbound TCP $1 away"
    PC_FW_FIX="nft insert rule $2 $3 $4 tcp dport $1 accept"
    return 1
  fi
  return 0
}
pc_confirm() { # pc_confirm "question": y/N on the terminal; no terminal, or one this process does not own, is a no
  ( : </dev/tty ) 2>/dev/null || return 1
  ui_tty_fg || return 1
  [ "$UI_FANCY" != 1 ] || printf '\r\033[K'
  printf '%s [y/N] ' "$1" >/dev/tty
  _a=''; read -r _a </dev/tty || true
  [ "$UI_FANCY" != 1 ] || [ "$UI_LIVE" != 1 ] || printf '\033[1A\r\033[K'
  case $_a in y | Y | yes) return 0 ;; *) return 1 ;; esac
}
pc_open() { # pc_open FIXCOMMAND: runs it (it came from pc_fw_check, never from outside) and saves it for the next boot when it can
  sh -c "$1" || return 1
  case $1 in iptables*) if command -v netfilter-persistent >/dev/null 2>&1; then netfilter-persistent save >/dev/null 2>&1 || true; fi ;; esac
}
pc_checks() { # pc_checks "443 80": 0 when all is well; else 1 with PC_WHAT (what failed) and PC_TODO (what to do) set
  for _p in $1; do
    _u=$(pc_listener "$_p")
    if [ -n "$_u" ]; then
      PC_WHAT="port $_p is already in use by another program: $_u"
      PC_TODO="stop that program (or move it to another port), then run the command again. Nothing was installed."
      return 1
    fi
    if ! pc_fw_check "$_p"; then
      ui_warn "Port $_p: $PC_FW_WHY."
      if pc_confirm "   Open it now with:  $PC_FW_FIX  ?"; then
        pc_open "$PC_FW_FIX" && pc_fw_check "$_p" && { ui_ok "Port $_p is open in this machine's firewall"; continue; }
        ui_warn "That did not open port $_p."
      fi
      PC_WHAT="this machine's firewall turns inbound TCP $_p away: $PC_FW_WHY"
      PC_TODO="open it with this command: $PC_FW_FIX   (run the installer again afterwards; if this is a cloud server, also open inbound TCP $_p in the provider's firewall: Oracle Security List, Azure Network Security Group, AWS Security Group). Nothing was installed."
      return 1
    fi
    ui_ok "Port $_p is free and this machine's firewall lets it in"
  done
}
pc_urlb() { # stdin -> base64url without padding
  openssl base64 -A | tr '+/' '-_' | tr -d '='
}
pc_probe_call() { # pc_probe_call PORTS OUTFILE: POST /v1/probe to the sign-in service, signed AINKRAD-SVC-V1 with a throw-away ES256 key; 0 on a 2xx
  command -v openssl >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 || return 1
  _d=$(mktemp -d) || return 1
  _body="{\"ports\":[$(printf '%s' "$1" | tr ' ' ',')]}"
  printf '%s' "$_body" >"$_d/body"
  openssl ecparam -name prime256v1 -genkey -noout -out "$_d/k" 2>/dev/null || { rm -rf "$_d"; return 1; }
  openssl ec -in "$_d/k" -pubout -outform DER >"$_d/spki" 2>/dev/null || { rm -rf "$_d"; return 1; }
  _fp=$(openssl dgst -sha256 -binary <"$_d/spki" | pc_urlb)
  _ts=$(date +%s); _nonce=$(openssl rand 16 | pc_urlb)
  printf 'AINKRAD-SVC-V1\n%s\nES256\nPOST\n/v1/probe\n%s\n%s\n%s' "$_fp" "$_ts" "$_nonce" "$(openssl dgst -sha256 -binary <"$_d/body" | pc_urlb)" >"$_d/msg"
  openssl dgst -sha256 -sign "$_d/k" -out "$_d/sig.der" "$_d/msg" 2>/dev/null || { rm -rf "$_d"; return 1; }
  : >"$_d/sig.raw"; _hex=''
  for _i in $(openssl asn1parse -inform DER -in "$_d/sig.der" 2>/dev/null | sed -n 's/.*INTEGER *://p'); do # DER r, s -> 32 bytes each
    _i=$(printf '%s' "$_i" | sed 's/^0*//')
    while [ "${#_i}" -lt 64 ]; do _i=0$_i; done
    _hex=$_hex$_i
  done
  [ "${#_hex}" -eq 128 ] || { rm -rf "$_d"; return 1; }
  # shellcheck disable=SC2059 # the octal escape is the format: a raw byte for the signature file
  while [ -n "$_hex" ]; do _x=${_hex%"${_hex#??}"}; _hex=${_hex#??}; printf "\\$(printf %03o "0x$_x")" >>"$_d/sig.raw"; done
  _sig=$(pc_urlb <"$_d/sig.raw")
  curl -fsS --max-time 15 -X POST "${AINKRAD_SIGNIN_URL:-https://signin.ainkrad.io}/v1/probe" \
    -H 'Content-Type: application/json' -H "Ainkrad-Core: $_fp" -H "Ainkrad-Key: $(pc_urlb <"$_d/spki")" -H 'Ainkrad-Alg: ES256' \
    -H "Ainkrad-Timestamp: $_ts" -H "Ainkrad-Nonce: $_nonce" -H "Ainkrad-Signature: $_sig" \
    --data-binary "@$_d/body" -o "$2" 2>/dev/null
  _rc=$?; rm -rf "$_d"; return "$_rc"
}
pc_probe() { # pc_probe "443 80": 0 when the ports reach this machine from the internet, or the check could not run (the service being down never blocks); else 1 with PC_WHAT and PC_TODO set (N6)
  [ -z "${AINKRAD_SKIP_PROBE:-}" ] || { ui_keep "outside port check skipped (AINKRAD_SKIP_PROBE)"; return 0; }
  _o=$(mktemp) || return 0
  if ! pc_probe_call "$1" "$_o"; then
    rm -f "$_o"; ui_warn "Could not check the ports from the internet (Ainkrad's check service is unreachable). Continuing; make sure inbound TCP $1 is open."
    return 0
  fi
  for _p in $1; do
    # a closed port is a timeout: the cloud firewall drops the packet. A refusal reached this machine (nothing listens before the install).
    if tr '{' '\n' <"$_o" | grep -E "\"port\" *: *${_p}[,}]" | grep -Eq '"open" *: *false.*"reason" *: *"timeout"|"reason" *: *"timeout".*"open" *: *false'; then
      rm -f "$_o"
      PC_WHAT="port $_p is closed from the internet"
      PC_TODO="open it in your cloud firewall (OCI: security list / NSG; Azure: network security group; AWS: security group) for inbound TCP $_p, then run the command again. Nothing was installed."
      return 1
    fi
    ui_ok "Port $_p is reachable from the internet"
  done
  rm -f "$_o"
}
pc_valid_hostname() { # a DNS name of two or more labels; not an IP address
  _h=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case $_h in '' | *'
'*) return 1 ;; esac
  [ "${#_h}" -le 253 ] && printf '%s' "$_h" | grep -Eq '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'
}
pc_valid_email() { # name@example.com
  case $1 in *@* | '') ;; *) return 1 ;; esac
  case $1 in *'
'*) return 1 ;; esac
  printf '%s' "${1%@*}" | grep -Eq '^[A-Za-z0-9._%+-]+$' && pc_valid_hostname "${1##*@}"
}
pc_ask() { # pc_ask VAR "question" "example" VALIDATOR: VAR from the environment when valid, else asked on the terminal until it is; exported
  eval "_v=\${$1:-}"
  if [ -n "$_v" ]; then
    if "$4" "$_v"; then ui_keep "$1 = $_v (given up front)"; export "${1?}"; return 0; fi
    ui_warn "$1 is not valid, so it is asked again"
  fi
  { ( : </dev/tty ) 2>/dev/null && ui_tty_fg; } || ui_stopped "no terminal to ask on, and $1 is not set" "set AINKRAD_HOSTNAME=<dns name> and AINKRAD_ACME_EMAIL=<email> and run the command again. Nothing was installed."
  while :; do
    [ "$UI_FANCY" != 1 ] || printf '\r\033[K'
    printf '\n %s\n   Example: %s\n > ' "$2" "$3" >/dev/tty
    _v=''; read -r _v </dev/tty || ui_stopped "no answer for $1 (the input ended)" "run the command again. Nothing was installed."
    if "$4" "$_v"; then break; fi
    printf '   That is not valid. Try again.\n' >/dev/tty
  done
  eval "$1=\$_v"; export "${1?}"
}
pc_dns_probe() { # pc_dns_probe NAME OUTFILE: "A ip" / "AAAA ip" lines (dig when there is one, else getent); never fails
  { if command -v dig >/dev/null 2>&1; then
      dig +short +time=3 +tries=1 A "$1" 2>/dev/null | grep -E '^[0-9.]+$' | sed 's/^/A /' || true
      dig +short +time=3 +tries=1 AAAA "$1" 2>/dev/null | grep -E '^[0-9a-fA-F:]+$' | sed 's/^/AAAA /' || true
    else
      getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | sort -u | sed 's/^/A /' || true
      getent ahostsv6 "$1" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9a-fA-F:]+$' | sort -u | sed 's/^/AAAA /' || true
    fi; } >"$2"
}
pc_pub_probe() { # pc_pub_probe OUTFILE: this machine's public IPv4 from a third party (api.ipify.org); never fails
  { curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsS4 --max-time 5 https://checkip.amazonaws.com 2>/dev/null || true; } >"$1"
}
pc_dns() { # pc_dns NAME: the A record is this machine's public address and any AAAA record is on it; else the red card (blocking)
  ui_logopen || { ui_warn "cannot create a log directory, so the DNS check is skipped"; return 0; }
  _f=$UI_LOGDIR/dns
  UI_QUIET=1 ui_run "Looking up this machine's public address (a request to api.ipify.org)" pc_pub_probe "$_f.pub" || true
  _pub=$(tr -cd '0-9.' <"$_f.pub" 2>/dev/null | head -c 15)
  printf '%s' "$_pub" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || _pub=''
  UI_QUIET=1 ui_run "Checking that $1 points at ${_pub:-this machine}" pc_dns_probe "$1" "$_f.dns" || true
  _a=$(sed -n 's/^A //p' "$_f.dns" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
  _aaaa=$(sed -n 's/^AAAA //p' "$_f.dns" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
  if [ -z "$_a" ]; then
    ui_stopped "$1 has no DNS A record yet, so Let's Encrypt cannot issue the certificate" "at your DNS provider add an A record  $1 -> ${_pub:-<this machine public IP>}  (TTL 300), wait a minute, then run the command again. Nothing was installed."
  elif [ -z "$_pub" ]; then
    ui_warn "$1 points at $_a, but this machine's public address could not be looked up, so I cannot compare. Make sure that is this machine."
  elif printf ' %s ' "$_a" | grep -q " $_pub "; then ui_keep "$1 points at $_pub: this machine"
  else
    ui_stopped "$1 points at $_a, but this machine is $_pub, so Let's Encrypt would validate the wrong machine" "change the A record to $_pub (or run this installer on $_a), wait a minute, then run the command again. Nothing was installed."
  fi
  _bad6=''
  for _x in $_aaaa; do
    printf '%s' "$_x" | grep -Eq '^[0-9a-fA-F:]{2,45}$' || continue
    ip -6 addr 2>/dev/null | grep -q " $_x/" || _bad6="${_bad6:+$_bad6 }$_x"
  done
  [ -z "$_bad6" ] || ui_stopped "$1 also has an IPv6 (AAAA) record ($_bad6) that is not on this machine, and Let's Encrypt tries IPv6 first" "remove the AAAA record, or point it at this machine, then run the command again. Nothing was installed."
}
# --- precheck end ---
