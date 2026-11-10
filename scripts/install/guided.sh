# shellcheck shell=bash
# The guided mode of scripts/install.sh: numbered steps with a plain title and a one-line "why", a progress bar,
# colour and unicode with a plain fallback (no TTY, NO_COLOR, TERM=dumb, non-UTF-8 locale), defaults for every
# answer (only the DNS name and the ACME email are asked), the invite link at the end and a summary box. Sourced.
# SC2034: the A_* answers and the colours are read by install.sh, which sources this file.
# shellcheck disable=SC2034
# bash 3.2-safe, like lib.sh.
#   AINKRAD_HOSTNAME, AINKRAD_ACME_EMAIL  answer those two questions up front (no TTY is then needed)
#   AINKRAD_ACME_ENV=staging              a test certificate instead of a production one

GUIDED_TOTAL=10 INVITE='' BACKUP_IDENTITY=''

ui_init() {
  B='' D='' R='' GR='' RD='' YL='' CY=''
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
    B=$'\033[1m' D=$'\033[2m' R=$'\033[0m' GR=$'\033[32m' RD=$'\033[31m' YL=$'\033[33m' CY=$'\033[36m'
  fi
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*) U_OK='✔' U_GO='▸' U_DOT='·' U_FULL='█' U_EMPTY='░' U_H='─' U_V='│' U_TL='╭' U_TR='╮' U_BL='╰' U_BR='╯' QR_T=UTF8 ;;
    *) U_OK='+' U_GO='>' U_DOT='-' U_FULL='#' U_EMPTY='.' U_H='-' U_V='|' U_TL='+' U_TR='+' U_BL='+' U_BR='+' QR_T=ASCII ;;
  esac
}
repeat() { local i out=''; for ((i = 0; i < $2; i++)); do out="$out$1"; done; printf '%s' "$out"; }

# trace CMD...: one dim line per action in guided mode (the full "+ cmd" in a dry run / the classic wizard).
trace() {
  if [ "$GUIDED" = 1 ] && [ "$DRY" = 0 ]; then
    local s="$*"; [ ${#s} -le 76 ] || s="${s:0:73}..."
    printf '   %s%s %s%s\n' "$D" "$U_DOT" "$s" "$R"
  else printf '+ %s\n' "$*"; fi
}

# guided_step TITLE: the title install.sh passes to step() picks the number, plain title and why. Unlisted: silent.
guided_step() {
  local n t w
  case $1 in
    Checks*) n=1 t="Checking this machine" w="The DNS name must point here and ports 80/443 must be free, or no certificate can be issued." ;;
    Binaries*) n=2 t="Checking the Core programs" w="Confirms they run on this CPU and shows their SHA-256 (the release signature was already verified)." ;;
    "Host hardening"*) n=3 t="Securing the machine" w="Firewall to SSH, 80 and 443 only, key-only SSH, no core dumps or swap, automatic security updates." ;;
    "Core: user"*) n=4 t="Installing the Core" w="Creates a service account, the Core's home with its keys and database, and its systemd service." ;;
    Backups*) n=5 t="Setting up backups" w="Encrypted snapshots of the Core every day, kept on this machine (a bucket can be added later)." ;;
    Start*) n=6 t="Starting the Core" w="Enables the service at boot and waits for its first HTTPS certificate (up to a minute or two)." ;;
    "Real credentials"*) n=7 t="Letting the Core hold provider keys" w="Turns on the encrypted secrets store so the app can keep provider and connection keys." ;;
    Runner*) n=8 t="Giving the Core hands on this machine" w="The runner lets the app run commands and terminals here as root; agent sessions stay in a bubblewrap sandbox." ;;
    Self-test*) n=9 t="Checking that everything works" w="Service, HTTPS, certificate and backup timer." ;;
    "First device"*) n=10 t="Creating your connection link" w="A one-time link and code that make the Mac app the owner of this Core." ;;
    *) return 0 ;;
  esac
  local fill=$((n * 20 / GUIDED_TOTAL))
  printf '\n %s%s%s%s  step %s of %s\n %s%s%s %s%s%s\n   %s%s%s\n' "$CY" "$(repeat "$U_FULL" "$fill")" "$D" "$(repeat "$U_EMPTY" $((20 - fill)))" "$n" "$GUIDED_TOTAL" \
    "$R$B" "$U_GO" "$R" "$B" "$t" "$R" "$D" "$w" "$R"
}
ok_line() { printf '   %s%s%s %s\n' "$GR" "$U_OK" "$R" "$*"; }

guided_banner() {
  printf '\n%s Ainkrad Core setup%s\n %sThis installs the Ainkrad Core on this machine and gives you a link to connect the Mac app.\n It needs about five minutes and asks two questions at most. Ctrl-C stops it safely.%s\n' "$B" "$R" "$D" "$R"
}

# A terminal to ask on, even when stdin is a pipe (curl ... | sudo sh).
have_tty() { ( : </dev/tty ) 2>/dev/null; }

# Fill every answer with its guided default; ask only for what cannot be defaulted.
guided_answers() {
  local k v pub
  A_BINARY_DIR=${CLI_BINARY:-${A_BINARY_DIR:-/usr/local/bin}}
  A_HOSTNAME=${A_HOSTNAME:-${AINKRAD_HOSTNAME:-}} A_ACME_CONTACT=${A_ACME_CONTACT:-${AINKRAD_ACME_EMAIL:-}}
  A_ACME_ENV=${AINKRAD_ACME_ENV:-production}
  A_BACKUP=local A_BACKUP_RECIPIENT=${A_BACKUP_RECIPIENT:-} A_RUNNER=yes A_RUNNER_PTY=yes A_HARDEN=yes A_REAL_CREDENTIALS=yes
  A_BOOTSTRAP=later A_SELFTEST_BACKUP=no
  [ -n "$A_HOSTNAME" ] && ! valid_hostname "$A_HOSTNAME" && { warn "AINKRAD_HOSTNAME '$A_HOSTNAME' is not a DNS name"; A_HOSTNAME=''; }
  [ -n "$A_ACME_CONTACT" ] && ! valid_email "$A_ACME_CONTACT" && { warn "AINKRAD_ACME_EMAIL is not a valid email"; A_ACME_CONTACT=''; }
  if [ -z "$A_HOSTNAME" ] || [ -z "$A_ACME_CONTACT" ]; then
    have_tty || die "no terminal to ask on: set AINKRAD_HOSTNAME=<dns name> and AINKRAD_ACME_EMAIL=<email> and run again"
    pub=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)
    printf '\n%s The Core is served over HTTPS with a free Let'"'"'s Encrypt certificate, so it needs a public DNS name that points at\n this machine%s (an A record%s).%s Core does not support an IP-only or self-signed setup yet. No name? Any free dynamic-DNS\n name works: create it first, then come back.%s\n' "$B" "${pub:+ ($pub)}" "$R$D" "$R$D" "$R"
    [ -n "$A_HOSTNAME" ] || ask HOSTNAME "DNS name for this Core, for example core.yourdomain.com"
    [ -n "$A_ACME_CONTACT" ] || ask ACME_CONTACT "Email for the certificate account (expiry notices only)."
  else ok_line "Using $A_HOSTNAME and $A_ACME_CONTACT (given up front)"; fi
  for k in $KEYS; do eval "v=\${A_$k:-}"; [ -n "$v" ] || printf -v "A_$k" '%s' "$(default_of "$k")"; done
}

# Snapshots are encrypted to an age recipient. Keep the one a previous run chose (once it has made backups); else make a pair here and hold the
# identity (the only decryption key) in a variable, shown once in the summary and never written to disk.
guided_backup_key() {
  local out prev; prev=$(env_get AINKRAD_BACKUP_RECIPIENT)
  # Kept only once a backup exists: a first run that died before showing the identity must not strand the next one.
  if [ -n "$prev" ] && ls "$CORE_HOME"/backups/*.age >/dev/null 2>&1; then A_BACKUP_RECIPIENT=$prev; return 0; fi
  if [ "$DRY" = 1 ]; then A_BACKUP_RECIPIENT='<generated by backup-keygen>'; return 0; fi
  out=$("$A_BINARY_DIR/ainkrad-core-server" backup-keygen 2>/dev/null) || die "backup-keygen failed: is $A_BINARY_DIR/ainkrad-core-server the right binary?"
  A_BACKUP_RECIPIENT=$(printf '%s\n' "$out" | sed -n 's/^# public key: //p')
  BACKUP_IDENTITY=$(printf '%s\n' "$out" | grep -m1 '^AGE-SECRET-KEY-')
  age_recipient "$A_BACKUP_RECIPIENT" || die "backup-keygen gave no usable recipient"
}

# The Core's invite (another lane adds `ainkrad-core-server pairing-invite <db> [name]`): its link carries the Core's
# fingerprint and a one-time secret. The output is held in a shell variable only: never in a file, a log or argv.
guided_invite() {
  local out
  INVITE=''
  [ "$DRY" = 0 ] || { say "  (dry run) would run: $BIN/ainkrad-core-server pairing-invite $CORE_HOME/core.db $A_HOSTNAME owner"; return 0; }
  # <host> is required (the Core does not store its public host); the Core listens on 443 here, so no :port. stderr is
  # folded in to classify a refusal; only the line that is the link is ever kept.
  # No core.env here: the command needs only the db and the host (and sourcing that file as shell breaks on its flags).
  out=$(runuser -u ainkrad -- "$BIN/ainkrad-core-server" pairing-invite "$CORE_HOME/core.db" "$A_HOSTNAME" owner 2>&1) || out="REFUSED:$out"
  case $out in
    *ainkrad://connect\?*host=*fp=*secret=*) INVITE=$(printf '%s\n' "$out" | grep -m1 '^ainkrad://connect?') ;;
    REFUSED:*[Dd]evice*)
      printf '   %s! this Core already has a paired device, so it will not make a first-owner link%s\n' "$YL" "$R" >&2
      say "     The Core is installed and running. Add more devices from the Mac app that owns it; to start over on this machine,"
      say "     run this installer with --uninstall --purge first."
      return 1 ;;
    *) printf '   %s! the installed ainkrad-core-server could not make the connect link%s\n' "$YL" "$R" >&2
       say "     The Core is installed and running. This release may predate 'pairing-invite'. With a newer one, run:"
       say "       sudo -u ainkrad $BIN/ainkrad-core-server pairing-invite $CORE_HOME/core.db $A_HOSTNAME owner"
       return 1 ;;
  esac
}

# Prints the link, the secret alone and a QR, to the terminal only.
guided_show_invite() {
  local secret=${INVITE##*secret=}
  secret=${secret%%&*}
  printf '\n %sConnect the Mac app%s  (one-time; shown only here, never stored)\n\n   Link:  %s\n   Code:  %s\n\n' "$B" "$R" "$INVITE" "$secret"
  if command -v qrencode >/dev/null; then printf '%s' "$INVITE" | qrencode -t "$QR_T" -m 1 | sed 's/^/   /'
  else say "   (no QR: qrencode is not installed)"; fi
  say "
 In the app: Set up a new Core, then paste the link (or scan the QR). Running this installer again prints a new link
 and cancels the old one."
}

box() { # box LINE...: a rounded box, ASCII content only (padding counts bytes)
  local w=66 l
  printf ' %s%s%s%s\n' "$U_TL" "$(repeat "$U_H" "$w")" "$U_TR" ""
  for l in "$@"; do printf ' %s %-*s %s\n' "$U_V" $((w - 2)) "$l" "$U_V"; done
  printf ' %s%s%s\n' "$U_BL" "$(repeat "$U_H" "$w")" "$U_BR"
}

guided_summary() { # guided_summary INVITE_RC
  local runner=installed
  [ -e /var/lib/ainkrad-runner/core/enrolment.json ] || runner="installed, waiting to be paired from the app"
  printf '\n'
  box "Ainkrad Core is $([ "$1" = 0 ] && echo 'ready' || echo 'running, but has no connect link yet')" "" \
    "Address     https://$A_HOSTNAME" \
    "Certificate $([ "$A_ACME_ENV" = staging ] && echo 'STAGING (test, not trusted by browsers)' || echo "Let's Encrypt, renews by itself")" \
    "Open ports  22 (SSH), 80, 443; everything else closed" \
    "Updates     automatic security updates; reboots stay manual" \
    "Backups     daily, encrypted, in $CORE_HOME/backups" \
    "Runner      $runner" \
    "Agents      sandboxed (bubblewrap); updates signature-checked"
  if [ -n "$BACKUP_IDENTITY" ]; then
    say "
 Backup key (decrypts the backups; shown once, never stored here; keep it OFF this machine, e.g. in a password manager):
   $BACKUP_IDENTITY"
  fi
  [ "$DRY" = 1 ] || say "
 Backup signer fingerprint: ${SIGNER:-unknown}
 Note it down somewhere safe; restoring a backup needs it. Nothing else needs running on this machine."
}
