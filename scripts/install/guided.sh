# shellcheck shell=bash
# The guided mode of scripts/install.sh: numbered steps with a plain title and a one-line "why", a progress bar,
# colour and unicode with a plain fallback (no TTY, NO_COLOR, TERM=dumb, non-UTF-8 locale), defaults for every
# answer (only the DNS name and the ACME email are asked), the invite link at the end and a summary box. Sourced.
# SC2034: the A_* answers and the colours are read by install.sh, which sources this file.
# shellcheck disable=SC2034
# bash 3.2-safe, like lib.sh.
#   AINKRAD_HOSTNAME, AINKRAD_ACME_EMAIL  answer those two questions up front (no TTY is then needed)
#   AINKRAD_ACME_ENV=staging              a test certificate instead of a production one

INVITE='' BACKUP_IDENTITY=''

# The symbols for the summary box (the colours and the live UI are in ui.sh: ui_init).
ui_box_init() {
  U_H='-' U_V='|' U_TL='+' U_TR='+' U_BL='+' U_BR='+' QR_T=ASCII
  if [ "$UI_FANCY" = 1 ] && [ "$UI_UTF" = 1 ]; then U_H='─' U_V='│' U_TL='╭' U_TR='╮' U_BL='╰' U_BR='╯' QR_T=UTF8; fi
}
repeat() { local i out=''; for ((i = 0; i < $2; i++)); do out="$out$1"; done; printf '%s' "$out"; }

# trace CMD...: a dim line per action (the full "+ cmd" in a dry run / the classic wizard).
trace() {
  if [ "$GUIDED" = 1 ] && [ "$DRY" = 0 ]; then ui_note "$(printf '%s' "$*" | cut -c1-76)"
  else printf '+ %s\n' "$*"; fi
}

# guided_step TITLE: install.sh's step() titles map to the roadmap (6 set up, 7 start + certificate, 8 link) and a sub-heading.
guided_step() {
  local n sub
  case $1 in
    Checks*) n=6 sub="Checking DNS and the ports" ;;
    Binaries*) n=6 sub="Checking the Core programs run on this CPU" ;;
    "Host hardening skipped"*) n=6 sub="Host hardening: skipped (opt-in). SSH config and firewall are untouched; use your provider's firewall, --harden applies it (experimental)" ;;
    "Host hardening"*) n=6 sub="Host hardening (experimental, opt-in): firewall, key-only SSH where safe, no swap or core dumps, security updates" ;;
    "Core: user"*) n=6 sub="Creating the service account, the Core's home with its keys and database, and its systemd service" ;;
    Backups*) n=6 sub="Setting up daily encrypted backups on this machine" ;;
    Start*) n=7 sub="Starting the Core and getting its HTTPS certificate" ;;
    "Real credentials"*) n=7 sub="Turning on the encrypted secrets store" ;;
    Runner*) n=7 sub="Setting up this Core's own runner (unprivileged user, sandboxed; terminals and agents on, exec.run off)" ;;
    Self-test*) n=7 sub="Checking that everything works" ;;
    "First device"*) n=8 sub="Creating your one-time connect link" ;;
    *) return 0 ;;
  esac
  if [ "$UI_N" != "$n" ]; then
    case $n in
      6) ui_step 6 "$(ui_rname 6)" "Creates the service account, the Core's keys and database, its systemd service and daily backups." ;;
      7) ui_step 7 "$(ui_rname 7)" "Starts the Core, waits for its first HTTPS certificate and checks that it works." ;;
      8) ui_step 8 "$(ui_rname 8)" "A one-time link and code that make the Mac app the owner of this Core." ;;
    esac
  fi
  ui_status "$sub"
}
ok_line() { ui_ok "$*"; }

guided_banner() {
  [ "${AINKRAD_FROM_GET:-}" = 1 ] || ui_roadmap
}

# A terminal to ask on, even when stdin is a pipe (a pipe into sudo is refused by get.sh: the terminal is not handed over).
have_tty() { ( : </dev/tty ) 2>/dev/null; }

# Fill every answer with its guided default; ask only for what cannot be defaulted.
guided_answers() {
  local k v pub
  A_BINARY_DIR=${CLI_BINARY:-${A_BINARY_DIR:-/usr/local/bin}}
  A_HOSTNAME=${A_HOSTNAME:-${AINKRAD_HOSTNAME:-}} A_ACME_CONTACT=${A_ACME_CONTACT:-${AINKRAD_ACME_EMAIL:-}}
  A_ACME_ENV=${AINKRAD_ACME_ENV:-production}
  A_BACKUP=local A_BACKUP_RECIPIENT=${A_BACKUP_RECIPIENT:-} A_RUNNER=yes A_RUNNER_PTY=yes A_HARDEN=no A_REAL_CREDENTIALS=yes
  [ "${NO_LOCAL_RUNNER:-0}" != 1 ] || { A_RUNNER=no A_RUNNER_PTY=no; }
  A_BOOTSTRAP=later A_SELFTEST_BACKUP=no
  [ -n "$A_HOSTNAME" ] && ! valid_hostname "$A_HOSTNAME" && { warn "AINKRAD_HOSTNAME '$A_HOSTNAME' is not a DNS name"; A_HOSTNAME=''; }
  [ -n "$A_ACME_CONTACT" ] && ! valid_email "$A_ACME_CONTACT" && { warn "AINKRAD_ACME_EMAIL is not a valid email"; A_ACME_CONTACT=''; }
  ui_step 5 "$(ui_rname 5)" "Only the public DNS name and an email are needed; everything else has a sensible default."
  UI_Q_N=0 UI_Q_TOTAL=0
  local pre_host='' pre_mail=''
  [ -z "$A_HOSTNAME" ] || pre_host=1
  [ -z "$A_ACME_CONTACT" ] || pre_mail=1
  [ -n "$A_HOSTNAME" ] || UI_Q_TOTAL=$((UI_Q_TOTAL + 1))
  [ -n "$A_ACME_CONTACT" ] || UI_Q_TOTAL=$((UI_Q_TOTAL + 1))
  if [ "$UI_Q_TOTAL" -gt 0 ]; then
    have_tty || die "no terminal to ask on: set AINKRAD_HOSTNAME=<dns name> and AINKRAD_ACME_EMAIL=<email> and run again"
    ui_note "The Core is served over HTTPS with a free Let's Encrypt certificate, so it needs a public DNS name that points at this machine."
    ui_note "There is no IP-only or self-signed mode yet. No name? Any free dynamic-DNS name works: create it first, then answer."
    [ -n "$A_HOSTNAME" ] || ask HOSTNAME "What is the public DNS name of this Core?"
    [ -n "$A_ACME_CONTACT" ] || ask ACME_CONTACT "What email should Let's Encrypt use for expiry notices?"
  fi
  if [ -n "$pre_host" ]; then ui_ok "HOSTNAME = $A_HOSTNAME (given up front)"; ui_after_answer HOSTNAME "$A_HOSTNAME"; fi
  if [ -n "$pre_mail" ]; then ui_ok "ACME_CONTACT = $A_ACME_CONTACT (given up front)"; fi
  if [ "$A_ACME_ENV" = staging ]; then ui_note "Certificate: staging (a test certificate: not trusted by browsers, no rate limits). Production is the default."
  else ui_note "Certificate: production Let's Encrypt (trusted by browsers). AINKRAD_ACME_ENV=staging asks for a test certificate instead (not trusted, no rate limits)."; fi
  for k in $KEYS; do eval "v=\${A_$k:-}"; [ -n "$v" ] || printf -v "A_$k" '%s' "$(default_of "$k")"; done
}

# Secrets (the invite, the backup identity) are printed to the controlling terminal ONLY: never to stdout, which cloud-init,
# CI, `ssh host '...' > log`, tee and tmux scrollback keep. With no terminal they are not made at all.
tty_ok() { ( : >/dev/tty ) 2>/dev/null; }
tty_say() { printf '%s\n' "$*" >/dev/tty; }

# Snapshots are encrypted to an age recipient. Keep the one a previous run chose (once it has made backups); else use
# AINKRAD_BACKUP_RECIPIENT (a public key); else, with a terminal, make a pair here and hold the identity (the only
# decryption key) in a variable, shown once on the terminal and never written to disk; with no terminal, no key is made
# (nobody could see it) and backups stay off until a re-run.
guided_backup_key() {
  local out prev; prev=$(env_get AINKRAD_BACKUP_RECIPIENT)
  # Kept only once a backup exists: a first run that died before showing the identity must not strand the next one.
  if [ -n "$prev" ] && ls "$CORE_HOME"/backups/*.age >/dev/null 2>&1; then A_BACKUP_RECIPIENT=$prev; return 0; fi
  if [ -n "${AINKRAD_BACKUP_RECIPIENT:-}" ]; then
    age_recipient "$AINKRAD_BACKUP_RECIPIENT" || die "AINKRAD_BACKUP_RECIPIENT must be an age public key (age1...), never the secret key"
    A_BACKUP_RECIPIENT=$AINKRAD_BACKUP_RECIPIENT; return 0
  fi
  if [ "$DRY" = 1 ]; then A_BACKUP_RECIPIENT='<generated by backup-keygen>'; return 0; fi
  if ! tty_ok; then
    A_BACKUP_RECIPIENT=''
    say "  No terminal to show a backup key on, so none is made and backups stay off. Re-run this installer from a terminal, or"
    say "  set AINKRAD_BACKUP_RECIPIENT=<age public key>, to turn them on."
    return 0
  fi
  out=$("$A_BINARY_DIR/ainkrad-core-server" backup-keygen 2>/dev/null) || die "backup-keygen failed: is $A_BINARY_DIR/ainkrad-core-server the right binary?"
  A_BACKUP_RECIPIENT=$(printf '%s\n' "$out" | sed -n 's/^# public key: //p')
  BACKUP_IDENTITY=$(printf '%s\n' "$out" | grep -m1 '^AGE-SECRET-KEY-' || true)
  [ -n "$BACKUP_IDENTITY" ] || die "backup-keygen printed no identity (empty or unexpected output)"
  age_recipient "$A_BACKUP_RECIPIENT" || die "backup-keygen gave no usable recipient"
}

# Where get.sh's bundle is kept so the Core can be removed later without downloading anything again.
INSTALLER_SAVED=${AINKRAD_SAVED_INSTALLER:-/usr/local/lib/ainkrad-installer}
save_installer() { # the signed, already verified bundle (get.sh checked it); root-owned
  # shellcheck disable=SC2016 # the script text is for the inner sh
  ui_run "Keeping the installer in $INSTALLER_SAVED (for a later removal or re-run)" \
    sh -c 'rm -rf "$1" && mkdir -p "$1" && cp -R "$2/scripts" "$2/deploy" "$1/" && chmod -R go-w "$1"' _ "$INSTALLER_SAVED" "$ROOT" || true
}
removal_hint() { # what to run to take the Core off again, and what that keeps
  local cmd
  if [ -x "$INSTALLER_SAVED/scripts/install.sh" ]; then cmd="sudo $INSTALLER_SAVED/scripts/install.sh --uninstall --purge"
  elif [ "${AINKRAD_FROM_GET:-}" != 1 ]; then cmd="sudo $0 --uninstall --purge"
  else cmd="sudo sh -c \"\$(curl -fsSL https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh)\" sh --uninstall --purge (it checks the download first)"; fi
  echo "to remove the Core and its data run: $cmd. That keeps the ainkrad service users, /etc/ainkrad/backup.env and the backup bucket, installed apt packages, and SSH and firewall settings."
}

# The certificate wait: the longest silent part. A background poller, a 4-minute watchdog, the spinner in front.
cert_wait() {
  local pid wd rc=0
  ( until health >/dev/null 2>&1; do sleep 2; done ) & pid=$!
  ( sleep 240; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 & wd=$!
  UI_JOBS="$pid $wd" UI_JOB="waiting for the certificate (the Core is installed and may be running)"
  UI_HINT=0
  ui_note "Usually 20-60 s; it needs port 443 reachable and the DNS record pointing here."
  ui_wait "$pid" "Requesting the certificate" "" ui_cert_text
  wait "$pid" 2>/dev/null || rc=$?
  kill "$wd" 2>/dev/null; wait "$wd" 2>/dev/null || true
  UI_JOBS='' UI_JOB=''
  return "$rc"
}
guided_next_steps() { # guided_next_steps INVITE_RC
  printf '\n %sWhat to do next%s\n' "$B" "$R"
  if [ "$1" = 0 ]; then
    printf '   1. Open the Mac app and choose "Use an existing Core".\n   2. Paste the link above (or scan the QR). You are then the owner of this Core.\n'
  else
    printf '   1. Make the connect link as printed above (on a terminal on this machine).\n   2. Open the Mac app, choose "Use an existing Core" and paste that link.\n'
  fi
}

# ui_card N TOTAL "question" "example" "default": the card every question is printed in (TOTAL 0 = unknown). A plain question (no
# variable name); Example and Default only when there is one. On a UTF-8 terminal it is a rounded box in blue, else plain text.
ui_card() {
  local head w line body='' n pad
  head="Question $1"; [ "$2" = 0 ] || head="$head of $2"
  if [ "$UI_FANCY" = 1 ] && [ "$UI_UTF" = 1 ]; then
    w=$((UI_W - 6)); [ "$w" -le 58 ] || w=58
    body=$(printf '%s\n' "$3" | fold -s -w "$w"); [ -z "$4" ] || body="$body
Example: $4"; [ -z "$5" ] || body="$body
Default: $5"
    n=$((w - ${#head} - 1)); [ "$n" -ge 1 ] || n=1
    local out; out=$(printf '\n %s╭─ %s%s%s %s╮%s' "$BL" "$B" "$head" "$R$BL" "$(repeat ─ "$n")" "$R")
    while IFS= read -r line; do
      pad=$((w - ${#line})); [ "$pad" -ge 0 ] || pad=0
      out="$out
 ${BL}│${R} $line$(repeat ' ' "$pad") ${BL}│${R}"
    done <<<"$body"
    out="$out
 ${BL}╰$(repeat ─ $((w + 2)))╯${R}"
    ui_emit "$out"
  else
    body=" $head
   $3"; [ -z "$4" ] || body="$body
   Example:  $4"; [ -z "$5" ] || body="$body
   Default:  $5"
    ui_emit "
$body"
  fi
}
# ui_prompt: the pointer in front of the answer; ui_after_read: the terminal echoed the Return, so the cursor is one line below the live line
ui_prompt() { if [ "$UI_FANCY" = 1 ] && [ "$UI_UTF" = 1 ]; then printf '› '; else printf '> '; fi; }
ui_after_read() { if [ "$UI_FANCY" = 1 ] && [ "$UI_LIVE" = 1 ]; then printf '\033[1A\r\033[K'; fi; }

# --- live checks right after an answer is accepted ---
dns_probe() { # NAME OUTFILE: "A ip" / "AAAA ip" lines (dig when there is one, else getent); never fails
  { if command -v dig >/dev/null; then
      dig +short +time=3 +tries=1 A "$1" 2>/dev/null | grep -E '^[0-9.]+$' | sed 's/^/A /' || true
      dig +short +time=3 +tries=1 AAAA "$1" 2>/dev/null | grep -E '^[0-9a-fA-F:]+$' | sed 's/^/AAAA /' || true
    else
      getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | sort -u | sed 's/^/A /' || true
      getent ahostsv6 "$1" 2>/dev/null | awk '{print $1}' | grep -E '^[0-9a-fA-F:]+$' | sort -u | sed 's/^/AAAA /' || true
    fi; } >"$2"
}
pub_probe() { # OUTFILE: this machine's public IPv4 from a third party (api.ipify.org); never fails
  { curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsS4 --max-time 5 https://checkip.amazonaws.com 2>/dev/null || true; } >"$1"
}
# ui_check_dns NAME: A record against this machine's public address, then the AAAA record. A name that does not point at this
# machine STOPS the install here (the red card), before anything of the Core is set up; a dry run only warns.
ui_dns_fail() { # ui_dns_fail "what failed" "what to do"
  if [ "${DRY:-0}" = 1 ]; then ui_warn "$1 (dry run continues)"; else ui_stopped "$1" "$2"; fi
}
ui_check_dns() {
  local name=$1 pub a aaaa x here f bad6=''
  ui_logopen || { ui_warn "cannot create a log directory, so the DNS check is skipped"; return 0; }
  f=$UI_LOGDIR/dns
  UI_QUIET=1 ui_run "Looking up this machine's public address (a request to api.ipify.org)" pub_probe "$f.pub" || true
  pub=$(clean_ip "$(cat "$f.pub" 2>/dev/null || true)")
  UI_QUIET=1 ui_run "Checking that $name points at ${pub:-this machine}" dns_probe "$name" "$f.dns" || true
  a=$(sed -n 's/^A //p' "$f.dns" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'); aaaa=$(sed -n 's/^AAAA //p' "$f.dns" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
  if [ -z "$a" ]; then
    ui_dns_fail "$name has no DNS A record yet, so Let's Encrypt cannot issue the certificate" "at your DNS provider add an A record  $name -> ${pub:-<this machine public IP>}  (TTL 300), wait a minute, then run the command again. Nothing of the Core was set up."
  elif [ -z "$pub" ]; then
    ui_warn "$name points at $a, but this machine's public address could not be looked up, so I cannot compare. Make sure that is this machine."
  elif printf ' %s ' "$a" | grep -q " $pub "; then ui_keep "$name points at $pub: this machine"
  else
    ui_dns_fail "$name points at $a, but this machine is $pub, so Let's Encrypt would validate the wrong machine" "change the A record to $pub (or run this installer on $a), wait a minute, then run the command again. Nothing of the Core was set up."
  fi
  for x in $aaaa; do
    valid_ipv6 "$x" || continue # only a real IPv6 literal gets this far (no globs, no control characters)
    here=0; ip -6 addr 2>/dev/null | grep -q " $x/" && here=1
    [ "$here" = 1 ] || bad6="${bad6:+$bad6 }$x"
  done
  [ -z "$bad6" ] || ui_dns_fail "$name also has an IPv6 (AAAA) record ($bad6) that is not on this machine, and Let's Encrypt tries IPv6 first" "remove the AAAA record, or point it at this machine, then run the command again. Nothing of the Core was set up."
}
ui_after_answer() { # KEY VALUE
  case $1 in
    HOSTNAME) ui_check_dns "$2" ;;
    ACME_CONTACT) ui_status "Let's Encrypt only uses $2 for expiry and account notices." ;;
  esac
}
ui_example() { # KEY: one example answer
  case $1 in
    HOSTNAME) echo "core.yourdomain.com" ;; ACME_CONTACT) echo "you@example.com" ;; BACKUP_RECIPIENT) echo "age1... (the PUBLIC key)" ;;
    BINARY_DIR) echo "/usr/local/bin" ;; PUBLIC_IP) echo "203.0.113.7" ;; *) echo "" ;;
  esac
}
ui_invalid() { # KEY: why the answer was not accepted, in plain words
  case $1 in
    HOSTNAME) echo "That is not a DNS name. It needs letters, digits, hyphens and at least one dot, for example core.yourdomain.com (an IP address does not work)." ;;
    ACME_CONTACT) echo "That does not look like an email address (name@example.com)." ;;
    *) echo "That is not a valid answer for $1. Try again." ;;
  esac
}

# The Core's invite: `ainkrad-core-server pairing-invite <db> <host> [name]` prints the link (Core fingerprint + a
# one-time secret). Returns 0 with INVITE set; 1 on a refusal or failure; 2 when there is no terminal to show it on,
# in which case NO invite is created (the Core must not hold an unclaimed invite nobody saw).
guided_invite() {
  local out cmd="sudo -u ainkrad $BIN/ainkrad-core-server pairing-invite $CORE_HOME/core.db $A_HOSTNAME owner"
  INVITE=''
  [ "$DRY" = 0 ] || { say "  (dry run) would run: $BIN/ainkrad-core-server pairing-invite $CORE_HOME/core.db $A_HOSTNAME owner"; return 0; }
  if ! tty_ok; then
    say "     No terminal to show the one-time link on, so none was created. The Core is installed and running. In a terminal on this machine run:"
    say "       $cmd"
    return 2
  fi
  # <host> is required (the Core does not store its public host); the Core listens on 443 here, so no :port. stderr is
  # folded in to classify a refusal; only the line that is the link is ever kept.
  # No core.env here: the command needs only the db and the host (and sourcing that file as shell breaks on its flags).
  # A non-zero exit is a refusal even if something that looks like a link was printed.
  out=$(runuser -u ainkrad -- "$BIN/ainkrad-core-server" pairing-invite "$CORE_HOME/core.db" "$A_HOSTNAME" owner 2>&1) || out="REFUSED:$out"
  case $out in
    REFUSED:*[Dd]evice*)
      printf '   %s! this Core already has a paired device, so it will not make a first-owner link%s\n' "$YL" "$R" >&2
      say "     The Core is installed and running. Add more devices from the Mac app that owns it; to start over on this machine,"
      say "     run this installer with --uninstall --purge first."
      return 1 ;;
    REFUSED:*) ;;
    *ainkrad://connect\?*host=*fp=*secret=*) INVITE=$(printf '%s\n' "$out" | grep -m1 '^ainkrad://connect?'); return 0 ;;
  esac
  printf '   %s! the installed ainkrad-core-server could not make the connect link%s\n' "$YL" "$R" >&2
  say "     The Core is installed and running. This release may predate 'pairing-invite'. With a newer one, run:"
  say "       $cmd"
  return 1
}

# The link, the secret alone and a QR: to the terminal only.
guided_show_invite() {
  local secret=${INVITE##*secret=}
  secret=${secret%%&*}
  {
    printf '\n %sConnect the Mac app%s  (one-time; shown only on this terminal, never stored)\n\n   Link:  %s\n   Code:  %s\n\n' "$B" "$R" "$INVITE" "$secret"
    if command -v qrencode >/dev/null; then printf '%s' "$INVITE" | qrencode -t "$QR_T" -m 1 | sed 's/^/   /'
    else printf '   (no QR: qrencode is not installed)\n'; fi
    printf '\n In the app: Set up a new Core, then paste the link (or scan the QR). Running this installer again prints a new link\n and cancels the old one.\n'
  } >/dev/tty
}

box() { # box LINE...: a rounded box, ASCII content only (padding counts bytes)
  local w=66 l
  printf ' %s%s%s%s\n' "$U_TL" "$(repeat "$U_H" "$w")" "$U_TR" ""
  for l in "$@"; do printf ' %s %-*s %s\n' "$U_V" $((w - 2)) "$l" "$U_V"; done
  printf ' %s%s%s\n' "$U_BL" "$(repeat "$U_H" "$w")" "$U_BR"
}

# The firewall rejects everything inbound except ssh/80/443 (TCP and UDP, IPv4 and IPv6): say so BEFORE it is applied, on every
# path, naming the other services that are listening now. Sets FW_CHOICE (yes|no). AINKRAD_FIREWALL=no skips the step. In
# guided mode, when other services are listening, ask y/N (default no; with no terminal the answer is no).
firewall_decide() {
  local listeners notice h=$ROOT/scripts/host/harden.sh
  FW_CHOICE=${AINKRAD_FIREWALL:-yes}
  case $FW_CHOICE in yes | no) ;; *) die "AINKRAD_FIREWALL must be yes or no (got '$FW_CHOICE')" ;; esac
  if [ "$FW_CHOICE" = no ]; then say "  Firewall step skipped (AINKRAD_FIREWALL=no): ports are left as they are."; return 0; fi
  notice=$(AINKRAD_HARDEN_SOURCE_ONLY=1 bash -c '. "$1"; firewall_notice' _ "$h" 2>/dev/null || true)
  [ -z "$notice" ] || printf '%s\n' "$notice"
  listeners=$(AINKRAD_HARDEN_SOURCE_ONLY=1 bash -c '. "$1"; other_listeners' _ "$h" 2>/dev/null || true)
  if [ -n "$listeners" ] && [ "$GUIDED" = 1 ] && [ "$DRY" = 0 ]; then
    if have_tty && yes_no "  Reject those services anyway and apply the firewall?"; then FW_CHOICE=yes
    else FW_CHOICE=no; say "  Firewall step skipped so those services keep working. Open them yourself or re-run and answer y."; fi
  fi
}

# What the host really has now, read back (not what we meant to do).
fw_state() {
  if [ "$A_HARDEN" != yes ]; then echo "not changed (hardening off)"; return; fi
  local v6='' how st rf=/etc/iptables/rules.v4
  [ "${AINKRAD_INSTALL_TEST:-}" != 1 ] || rf=${AINKRAD_RULES_V4:-$rf}
  st=$(cat "${HARDEN_STATE:-/nonexistent}" 2>/dev/null || true)
  case $st in
    *firewall=skipped*) echo "not changed (step skipped, see below)"; return ;;
    *firewall=failed*) echo "NOT applied completely (see below)"; return ;;
  esac
  if command -v ufw >/dev/null && grep -q '^Status: active' <<<"$(ufw status 2>/dev/null)"; then
    case $st in *ipv6=unfiltered*) echo "ufw: ssh/80/443 in, rest denied; IPv6 open" ;; *) echo "ufw: ssh/80/443 in, rest denied" ;; esac
    return
  fi
  if grep -q AINKRAD_IN <<<"$(iptables -S INPUT 2>/dev/null)"; then
    grep -q AINKRAD_IN <<<"$(ip6tables -S INPUT 2>/dev/null)" && v6=' +IPv6'
    how='until next reboot'; grep -qs AINKRAD_IN "$rf" && how='saved for reboot'
    case $st in *ipv6=unfiltered*) v6=''; how="$how; IPv6 open" ;; esac
    echo "ssh/80/443 (IPv4$v6), $how"
  else echo "NOT applied (see below)"; fi
}
ssh_state() {
  if ! command -v sshd >/dev/null; then echo "no sshd here"; elif grep -qi '^passwordauthentication no' <<<"$(sshd -T 2>/dev/null)"; then echo "key-only login (verified)"
  else echo "passwords still allowed (see below)"; fi
}

guided_summary() { # guided_summary INVITE_RC
  local runner=installed fw='(dry run)' sshs='(dry run)' rows=()
  if [ "${A_RUNNER:-yes}" != yes ]; then runner="none (--no-local-runner)"
  elif [ -e /var/lib/ainkrad-runner/core/enrolment.json ]; then runner="built in, enrolled (terminals and agents)"
  else runner="installed, waiting to be paired from the app"; fi
  rows+=("Address     https://$A_HOSTNAME")
  rows+=("Certificate $([ "$A_ACME_ENV" = staging ] && echo 'STAGING (test, not trusted by browsers)' || echo "Let's Encrypt, renews by itself")")
  if [ "$A_HARDEN" = yes ]; then
    [ "$DRY" = 1 ] || { fw=$(fw_state); sshs=$(ssh_state); }
    rows+=("Firewall    $fw" "SSH         $sshs" "Updates     automatic security updates; reboots stay manual")
  else
    rows+=("Hardening   NOT applied (opt-in): SSH, firewall untouched")
  fi
  rows+=("Backups     $([ -n "$A_BACKUP_RECIPIENT" ] && echo "daily, encrypted, in $CORE_HOME/backups" || echo 'OFF (no key; re-run from a terminal)')")
  rows+=("Runner      $runner")
  [ "${A_RUNNER:-yes}" != yes ] || rows+=("            unprivileged user, sandboxed; exec.run off")
  printf '\n'
  box "Ainkrad Core is $([ "$1" = 0 ] && echo 'ready' || echo 'running, but has no connect link yet')" "" "${rows[@]}"
  if [ "$A_HARDEN" != yes ]; then
    say "
 Host hardening NOT applied: SSH config and firewall untouched. Use your provider's firewall; re-run with --harden or use the app's Core machine screen later."
  fi
  if [ -s "${HARDEN_WARN:-/nonexistent}" ]; then
    say "
 Heads-up from host hardening:"
    sed 's/^/   - /' "$HARDEN_WARN"
  fi
  if [ "$DRY" = 0 ] && [ "$A_HARDEN" = yes ] && grep -q AINKRAD_IN <<<"$(iptables -S INPUT 2>/dev/null)"; then
    say "
 The firewall rejects every other inbound TCP port and all inbound UDP (e.g. WireGuard) on this host. Docker-published
 ports go through FORWARD and stay reachable. Your cloud firewall is separate."
  fi
  if [ -n "$BACKUP_IDENTITY" ]; then
    tty_say "
 Backup key (decrypts the backups; shown once on this terminal, never stored; keep it OFF this machine, e.g. in a password manager):
   $BACKUP_IDENTITY"
  fi
  [ "$DRY" = 1 ] || say "
 Backup signer fingerprint: ${SIGNER:-unknown}
 Note it down somewhere safe; restoring a backup needs it. Nothing else needs running on this machine."
}
