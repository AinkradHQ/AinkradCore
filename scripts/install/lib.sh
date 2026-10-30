# shellcheck shell=bash
# Validators, the answers-file parser and the prompt helpers of scripts/install.sh. Sourced, never run.
# bash 3.2-safe (macOS /bin/bash runs the tests): no ${x,,}, no mapfile, no associative arrays.

# Every key an answers file may hold, and the default of those that have one ('' = no default; ask/require).
KEYS="BINARY_DIR BUILD HOSTNAME PUBLIC_IP ACME_CONTACT ACME_ENV ACME_CHALLENGE PASSKEYS ALLOW_ORIGINS BACKUP
BACKUP_ENDPOINT BACKUP_REGION BACKUP_BUCKET BACKUP_PREFIX BACKUP_ACCESS_KEY BACKUP_SECRET_KEY BACKUP_SCHEDULE
BACKUP_RECIPIENT RUNNER HARDEN SSH_FROM BOOTSTRAP SELFTEST_BACKUP"
default_of() {
  case $1 in
    BUILD | PASSKEYS | RUNNER | HARDEN) echo no ;;
    ACME_ENV) echo staging ;;
    ACME_CHALLENGE) echo tls-alpn-01 ;;
    BACKUP_PREFIX) echo core/ ;;
    BACKUP_SCHEDULE) echo daily ;;
    BOOTSTRAP) echo later ;;
    SELFTEST_BACKUP) echo no ;;
    *) echo '' ;;
  esac
}
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# --- validators: exit 0 when valid ---
match() { case $1 in *$'\n'*) return 1 ;; esac; printf '%s' "$1" | grep -Eq -- "$2"; } # one line, whole ERE
valid_hostname() { # a DNS name of two or more labels; not an IP address
  local h; h=$(lower "$1")
  [ -n "$h" ] && [ ${#h} -le 253 ] || return 1
  match "$h" '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$'
}
valid_ipv4() {
  match "$1" '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
}
valid_port() { match "$1" '^[1-9][0-9]{0,4}$' && [ "$1" -le 65535 ]; }
valid_https_url() { # https://host[:port][/path], no userinfo, query or spaces
  local rest host port
  case $1 in https://*) rest=${1#https://} ;; *) return 1 ;; esac
  case $rest in *[[:space:]@?#]* | '') return 1 ;; esac
  host=${rest%%/*}; port=''
  case $host in *:*) port=${host##*:}; host=${host%:*} ;; esac
  { [ -z "$port" ] || valid_port "$port"; } && { valid_hostname "$host" || valid_ipv4 "$host"; }
}
valid_email() {
  case $1 in *@*) ;; *) return 1 ;; esac
  match "${1%@*}" '^[A-Za-z0-9._%+-]+$' && valid_hostname "${1##*@}"
}
valid_bucket() { match "$1" '^[A-Za-z0-9][A-Za-z0-9._-]{1,61}[A-Za-z0-9]$' && ! valid_ipv4 "$1"; }
valid_region() { match "$1" '^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$'; }
valid_prefix() { [ -z "$1" ] || match "$1" '^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*/$'; }
valid_key_id() { match "$1" '^[A-Za-z0-9+/=_.-]{8,255}$'; }
valid_secret() { [ ${#1} -ge 8 ] && [ ${#1} -le 512 ] && case $1 in *[[:space:]]*) false ;; *) true ;; esac; }
# 0 an age recipient (public key); 2 a SECRET key (AGE-SECRET-KEY-...), which must never reach this host; 1 else.
age_recipient() {
  case $(printf '%s' "$1" | tr '[:lower:]' '[:upper:]') in *AGE-SECRET-KEY-*) return 2 ;; esac
  match "$1" '^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$'
}
valid_recipient() { age_recipient "$1"; }
valid_origins() { # empty, or comma-separated https:// origins (no path)
  local o rest=$1
  [ -z "$rest" ] && return 0
  while [ -n "$rest" ]; do
    o=${rest%%,*}; [ "$o" = "$rest" ] && rest='' || rest=${rest#*,}
    case $o in https://*/* | *[[:space:]]*) return 1 ;; esac
    valid_https_url "$o" || return 1
  done
}
valid_cidr() { # a.b.c.d/n only: harden.sh writes iptables (IPv4); an IPv6 network would abort it half-way
  python3 -c 'import ipaddress, sys; ipaddress.IPv4Network(sys.argv[1], strict=False)' "$1" 2>/dev/null &&
    case $1 in */*) true ;; *) false ;; esac
}
valid_cidrs() {
  local c rest=$1
  [ -z "$rest" ] && return 0
  while [ -n "$rest" ]; do
    c=${rest%%,*}; [ "$c" = "$rest" ] && rest='' || rest=${rest#*,}
    valid_cidr "$c" || return 1
  done
}
valid_schedule() { match "$1" '^[A-Za-z0-9*:,./~ -]{1,64}$'; }
valid_yesno() { case $1 in yes | no) true ;; *) false ;; esac; }
valid_acme_env() { case $1 in staging | production) true ;; *) false ;; esac; }
valid_challenge() { case $1 in tls-alpn-01 | http-01) true ;; *) false ;; esac; }
valid_backup_mode() { case $1 in bucket | keep | local) true ;; *) false ;; esac; }
valid_bootstrap() { case $1 in now | later) true ;; *) false ;; esac; }
valid_selftest() { case $1 in no | local | bucket) true ;; *) false ;; esac; }
valid_dir() { [ -d "$1" ]; }
valid_any() { true; }
valid_ip_or_empty() { [ -z "$1" ] || valid_ipv4 "$1"; }

# Whether an IP is inside one of the comma-separated CIDRs.
ip_in_cidrs() {
  python3 -c 'import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
sys.exit(0 if any(ip in ipaddress.ip_network(c, strict=False) for c in sys.argv[2].split(",")) else 1)' "$1" "$2" 2>/dev/null
}

# "abcd...wxyz" for review screens: never more than the first and last 2 characters.
mask() { local n=${#1}; if [ "$n" -le 8 ]; then printf '********'; else printf '%s****%s' "${1:0:2}" "${1:$((n - 2))}"; fi; }

# --- the answers file: KEY=VALUE lines, parsed (never sourced). Sets A_<KEY>; errors to stderr, exit 1 ---
parse_answers() {
  local file=$1 line key val n=0 bad=0
  [ -r "$file" ] || { echo "cannot read answers file $file" >&2; return 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line=${line%$'\r'}
    line=${line#"${line%%[![:space:]]*}"} # leading blanks
    case $line in '' | '#'*) continue ;; esac
    case $line in *=*) ;; *) echo "$file:$n: not KEY=VALUE" >&2; bad=1; continue ;; esac
    key=${line%%=*} val=${line#*=}
    case " $(echo "$KEYS" | tr '\n' ' ') " in *" $key "*) ;; *) echo "$file:$n: unknown key $key" >&2; bad=1; continue ;; esac
    case $val in \"*\") val=${val#\"}; val=${val%\"} ;; \'*\') val=${val#\'}; val=${val%\'} ;; esac
    printf -v "A_$key" '%s' "$val"
  done <"$file"
  return "$bad"
}
# The keys still missing (no value, no default) given the choices made; one per line.
missing_keys() {
  local k v
  for k in HOSTNAME ACME_CONTACT BACKUP BACKUP_RECIPIENT; do
    eval "v=\${A_$k:-}"; [ -n "$v" ] || echo "$k"
  done
  [ "${A_BUILD:-no}" = yes ] || [ -n "${A_BINARY_DIR:-}" ] || echo "BINARY_DIR (or BUILD=yes)"
  if [ "${A_BACKUP:-}" = bucket ]; then
    for k in BACKUP_ENDPOINT BACKUP_REGION BACKUP_BUCKET BACKUP_ACCESS_KEY BACKUP_SECRET_KEY; do
      eval "v=\${A_$k:-}"; [ -n "$v" ] || echo "$k"
    done
  fi
}
# The validator for a key.
validator_of() {
  case $1 in
    BINARY_DIR) echo valid_dir ;; BUILD | PASSKEYS | RUNNER | HARDEN) echo valid_yesno ;;
    HOSTNAME) echo valid_hostname ;; PUBLIC_IP) echo valid_ip_or_empty ;; ACME_CONTACT) echo valid_email ;;
    ACME_ENV) echo valid_acme_env ;; ACME_CHALLENGE) echo valid_challenge ;; ALLOW_ORIGINS) echo valid_origins ;;
    BACKUP) echo valid_backup_mode ;; BACKUP_ENDPOINT) echo valid_https_url ;; BACKUP_REGION) echo valid_region ;;
    BACKUP_BUCKET) echo valid_bucket ;; BACKUP_PREFIX) echo valid_prefix ;; BACKUP_ACCESS_KEY) echo valid_key_id ;;
    BACKUP_SECRET_KEY) echo valid_secret ;; BACKUP_SCHEDULE) echo valid_schedule ;;
    BACKUP_RECIPIENT) echo valid_recipient ;; SSH_FROM) echo valid_cidrs ;; BOOTSTRAP) echo valid_bootstrap ;;
    SELFTEST_BACKUP) echo valid_selftest ;; *) echo valid_any ;;
  esac
}
# Fills defaults, then validates every answer; lists every problem (never a secret's value).
check_answers() {
  local k v bad=0 rc
  for k in $KEYS; do
    eval "v=\${A_$k:-}"
    if [ -z "$v" ]; then v=$(default_of "$k"); printf -v "A_$k" '%s' "$v"; fi
    case $k in BINARY_DIR) [ "${A_BUILD:-no}" = yes ] && continue ;; esac
    case $k in BACKUP_ENDPOINT | BACKUP_REGION | BACKUP_BUCKET | BACKUP_PREFIX | BACKUP_ACCESS_KEY | BACKUP_SECRET_KEY)
      [ "${A_BACKUP:-}" = bucket ] || continue ;; esac
    [ -z "$v" ] && case $k in PUBLIC_IP | ALLOW_ORIGINS | SSH_FROM | BACKUP_PREFIX) continue ;; esac
    [ -z "$v" ] && continue # reported by missing_keys
    rc=0; "$(validator_of "$k")" "$v" || rc=$?
    if [ "$rc" = 2 ] && [ "$k" = BACKUP_RECIPIENT ]; then
      echo "$k: that is an age SECRET key. Only the public key (age1...) may be on this host; keep the identity offline" >&2; bad=1
    elif [ "$rc" != 0 ]; then
      case $k in BACKUP_SECRET_KEY | BACKUP_ACCESS_KEY) echo "$k: not a valid value" >&2 ;; *) echo "$k: invalid value '$v'" >&2 ;; esac
      bad=1
    fi
  done
  [ -z "${A_SSH_FROM:-}" ] || [ "${A_HARDEN:-no}" = yes ] || { echo "SSH_FROM needs HARDEN=yes (harden.sh writes the firewall)" >&2; bad=1; }
  return "$bad"
}
