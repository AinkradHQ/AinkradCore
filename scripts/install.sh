#!/usr/bin/env bash
# Guided installer for the Ainkrad Core on a Linux + systemd host (E1-16.x). Nothing about your environment lives
# in the repo: the wizard asks for it (or reads an answers file) and writes /etc/ainkrad/core.env (settings) and
# /etc/ainkrad/backup.env (bucket credentials, root:ainkrad 0640). Idempotent: re-run it to change an answer.
#   sudo scripts/install.sh                      guided install (default): asks only the DNS name and ACME email
#   sudo scripts/install.sh --wizard             the classic question-by-question wizard
#   sudo scripts/install.sh --config <answers>   unattended (see deploy/install.answers.example)
#   scripts/install.sh --config <answers> --dry-run   print every action, change nothing (no root needed)
#   --no-local-runner  skip the built-in runner (terminals and agents on this machine); the default is to set one up and start it.
#   --demo shows the whole screen flow with fake delays and changes NOTHING on this machine; it always exits 3 (never a success).
#   --harden (or AINKRAD_HARDEN=yes; only yes|no are accepted) also runs scripts/host/harden.sh: key-only SSH where safe, a firewall
#        that rejects every inbound port but ssh/80/443, unattended updates, no swap/core dumps. EXPERIMENTAL and OFF by default.
#   sudo scripts/install.sh --check [--backup local|bucket]   self-test an existing install
#   sudo scripts/install.sh --uninstall [--purge]   stop, disable, remove units and binaries; --purge also deletes
#        the Core's data after you type its host name. Never touches backup.env or the bucket.
# Options: --binary <dir> (ainkrad-core-server [, ainkradctl, ainkrad-runner, ainkrad-ptyhost]; a signed release puts all four in
# <prefix>/bin with scripts/release/install.sh) overrides BINARY_DIR.
# A runner on this host (RUNNER=yes) is installed with its own hardened unit; RUNNER_PTY=yes offers terminals (a
# shell as the unprivileged runner user, inside the unit's sandbox), RUNNER_PAIR_CODE pairs and starts it.
# A runner on another Linux host: deploy/install-linux.sh. On a Mac: deploy/launchd/install.sh (or the package).
# SC2015: `test && pass || fail` is meant (pass never fails).
# shellcheck disable=SC2015
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Run by get.sh the roadmap is 8 steps (it passes 0/8 and its clock); standalone this installer shows its own steps 5-8 as 1-4.
: "${AINKRAD_STEP_BASE:=4}" "${AINKRAD_STEP_TOTAL:=4}"; export AINKRAD_STEP_BASE AINKRAD_STEP_TOTAL
# shellcheck source=scripts/install/lib.sh
. "$ROOT/scripts/install/lib.sh"
# shellcheck source=scripts/install/ui.sh
. "$ROOT/scripts/install/ui.sh"
# shellcheck source=scripts/install/precheck.sh
. "$ROOT/scripts/install/precheck.sh"
# shellcheck source=scripts/install/guided.sh
. "$ROOT/scripts/install/guided.sh"
# shellcheck source=scripts/install/agent-tools.sh
. "$ROOT/scripts/install/agent-tools.sh"

CORE_HOME=/var/lib/ainkrad/core ETC=/etc/ainkrad BIN=/usr/local/bin UNITS=/etc/systemd/system
STAGING_DIR=https://acme-staging-v02.api.letsencrypt.org/directory
NO_LOCAL_RUNNER=0 RUNNER_STATE=/var/lib/ainkrad-runner/core
DEMO='' HARDEN_REQ='' HARDEN_WARN='' HARDEN_STATE='' FW_CHOICE=yes MODE=install GUIDED=0 CONFIG='' DRY=0 PURGE=0 CHECK_BACKUP=no CLI_BINARY='' STAGE=''

# say: a line that stays on the screen (in the guided install above the live progress line, so the two live lines stay at the bottom)
say() { if [ "$GUIDED" = 1 ]; then ui_emit "$*"; else printf '%s\n' "$*"; fi; }
# info TEXT: a detail line; in the guided install it is the live line (replaced by the next one), else a plain indented line
info() { if [ "$GUIDED" = 1 ]; then ui_status "$(printf '%s' "$*" | sed 's/^ *//')"; else say "  $*"; fi; }
step() { if [ "$GUIDED" = 1 ]; then guided_step "$*"; else printf '\n== %s\n' "$*"; fi; }
die() {
  if [ "$GUIDED" = 1 ] && [ "$UI_N" != 0 ]; then
    UI_RERUN=${AINKRAD_RERUN:-"sudo $0"}; ui_stopped "$*" "fix the cause, then run the command below; it is safe to run again (it keeps what is already done)"
  fi
  printf 'install: %s\n' "$*" >&2; exit 1
}
warn() { if [ "$GUIDED" = 1 ]; then ui_warn "$*"; else printf 'install: WARNING: %s\n' "$*" >&2; fi; }
# In the guided install a command runs in the background with its output in the log and a spinner naming it; RUN_PLAIN=1 keeps
# the old direct output (hardening prints a report).
run_label() {
  case $1 in
    systemctl) case $2 in
      daemon-reload) echo "Telling systemd about the new service files" ;; enable) echo "Enabling the services at boot" ;;
      restart | start) echo "Starting ${3:-the service}" ;; *) echo "systemctl $2 ${3:-}" ;; esac ;;
    useradd) echo "Creating the service account" ;;
    install) case $* in *ainkradctl*) echo "Installing the ainkradctl command" ;; *backup*) echo "Installing the backup service and timer" ;; *ainkrad-runner*) echo "Installing the runner" ;; *) echo "Installing files" ;; esac ;;
    rm) echo "Removing leftovers of optional modules" ;;
    runuser) case $* in *" setting set "*) echo "Turning on the encrypted secrets store" ;; *" init "*) echo "Creating the Core's home, keys and database" ;; *) echo "Running as the service user" ;; esac ;;
    *) echo "Running $1" ;;
  esac
}
run() {
  if [ "$GUIDED" = 1 ] && [ "$DRY" = 0 ] && [ "${RUN_PLAIN:-0}" != 1 ]; then
    ui_run "$(run_label "$@")" "$@" || die "$(run_label "$@") failed"
  else trace "$@"; [ "$DRY" = 1 ] || "$@"; fi
}
# write_file PATH MODE OWNER:GROUP CONTENT [SHOWN]: atomically, via a temp file beside it; SHOWN replaces
# CONTENT in the dry-run listing (secrets masked). printf is a builtin: CONTENT never reaches an argv.
write_file() {
  local path=$1 mode=$2 owner=$3 content=$4 shown=${5:-$4} tmp
  trace "write $path ($owner $mode)"
  if [ "$DRY" = 1 ]; then printf '%s\n' "$shown" | sed 's/^/    /'; return; fi
  tmp=$(mktemp "$(dirname "$path")/.$(basename "$path").XXXXXX")
  printf '%s\n' "$content" >"$tmp"
  chown "$owner" "$tmp" && chmod "$mode" "$tmp" && mv -f "$tmp" "$path"
}
env_get() { [ -r "$ETC/core.env" ] && sed -n "s/^$1=//p" "$ETC/core.env" | tail -n1 || true; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
# tty_foreground: 0 when this process can read the terminal without being stopped by SIGTTIN, i.e. it is in the terminal's
# foreground process group. (Started through `curl | sudo sh` it is not: sudo's pty does not hand the terminal over when its own
# stdin is a pipe, and the first read would stop the installer silently.) Unknown = allowed; no terminal = reading fails by itself.
tty_foreground() {
  local pg tp
  pg=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ') tp=$(ps -o tpgid= -p $$ 2>/dev/null | tr -d ' ')
  case $pg$tp in '' | *[!0-9]*) return 0 ;; esac
  [ "$tp" = 0 ] || [ "$pg" = "$tp" ]
}
need_terminal() { # before every read from /dev/tty: never leave the user at a silent prompt
  tty_foreground || die "this installer does not have the terminal (it was probably started with 'curl ... | sudo sh'): a question here would hang. Run it as: sudo sh -c \"\$(curl -fsSL https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh)\"  (or, from a checkout, sudo scripts/install.sh): both keep the terminal attached."
}
yes_no() { local a; need_terminal; read -r -p "$1 [y/N] " a </dev/tty; case $a in y | Y | yes) true ;; *) false ;; esac; }

# ask KEY "one-line explanation" [secret]: loops until the validator accepts; keeps A_KEY (or the default).
# ui_read PROMPT VAR [secret]: read one answer from the terminal (tests replace this)
ui_read() { need_terminal; if [ -n "${3:-}" ]; then read -r -s -p "$1" "$2" </dev/tty; echo; else read -r -p "$1" "$2" </dev/tty; fi; }
# ask KEY "plain label" [secret]: every question is a card (Question n of N, label, example, default), then it waits.
# loops until the validator accepts; keeps A_KEY (or the default).
ask() {
  local key=$1 why=$2 secret=${3:-} cur def v rc shown
  eval "cur=\${A_$key:-}"; def=${cur:-$(default_of "$key")}
  UI_Q_N=$((${UI_Q_N:-0} + 1))
  ui_card "$UI_Q_N" "${UI_Q_TOTAL:-0}" "$why" "$(ui_example "$key")" "$([ -n "$secret" ] || printf '%s' "$def")"
  while :; do
    if [ "$GUIDED" = 1 ]; then # a plain question: no variable name, a pointer for the prompt
      if [ -n "$secret" ]; then ui_read " $(ui_prompt)${cur:+ [keep current] }" v secret
      else ui_read " $(ui_prompt)${def:+[$def] }" v; fi
    elif [ -n "$secret" ]; then ui_read " > $key${cur:+ [keep current]}: " v secret
    else ui_read " > $key${def:+ [$def]}: " v; fi
    ui_after_read
    v=${v:-$def}
    case $key in BINARY_DIR) [ "$v" = build ] && { A_BUILD=yes; return; } ;; esac
    if [ -z "$v" ]; then case $key in PUBLIC_IP | ALLOW_ORIGINS | SSH_FROM | BACKUP_PREFIX | RUNNER_PAIR_CODE) printf -v "A_$key" ''; return ;; esac; fi
    rc=0; "$(validator_of "$key")" "$v" || rc=$?
    if [ "$rc" = 0 ]; then
      printf -v "A_$key" '%s' "$v"
      shown=$v; [ -z "$secret" ] || shown='(hidden)'
      if [ "$GUIDED" = 1 ]; then ui_after_answer "$key" "$v"; else ui_ok "$key = $shown"; fi
      return
    fi
    if [ "$rc" = 2 ] && [ "$key" = BACKUP_RECIPIENT ]; then
      say "  That is an age SECRET key (AGE-SECRET-KEY-...). It must never be on this host: paste the public"
      say "  key (age1...) printed next to it. If the secret was exposed here, make a new identity."
    else say "  $(ui_invalid "$key")"; fi
  done
}

wizard() {
  [ -t 0 ] || die "no terminal: use --config <answers file> for an unattended install"
  say "Ainkrad Core installer. Every answer is written to /etc/ainkrad on this host only; Ctrl-C aborts safely."
  ask BINARY_DIR "Binaries: a directory with ainkrad-core-server (and optionally ainkradctl, ainkrad-runner), or 'build' to compile this checkout with cargo."
  ask HOSTNAME "The public DNS name of this Core (its A/AAAA record must point at this host)."
  ask PUBLIC_IP "This host's public IPv4, if you know it (empty: looked up; behind NAT the interface address differs)."
  ask ACME_CONTACT "Email for the Let's Encrypt account (expiry notices)."
  ask ACME_ENV "staging (test certificate, not trusted by browsers; use it first) or production."
  ask ACME_CHALLENGE "tls-alpn-01 (proves the name on :443 only) or http-01 (needs :80 open too)."
  ask PASSKEYS "Passkeys for the web client (yes/no)."
  [ "$A_PASSKEYS" = no ] || ask ALLOW_ORIGINS "Extra browser origins allowed (comma-separated https:// origins; empty for none)."
  ask BACKUP "Backups: bucket (S3-compatible, credentials asked now), keep (an existing /etc/ainkrad/backup.env), or local (snapshots on this host only)."
  if [ "$A_BACKUP" = bucket ]; then
    say "  The bucket is addressed path-style (https://endpoint/<bucket>/<key>); give it create-only rights if you can."
    ask BACKUP_ENDPOINT "S3 endpoint URL (https://...)."
    ask BACKUP_REGION "The bucket's region (as the signature needs it)."
    ask BACKUP_BUCKET "Bucket name."
    ask BACKUP_PREFIX "Object prefix inside the bucket (ends with /)."
    ask BACKUP_ACCESS_KEY "Access key id of the backup credential."
    ask BACKUP_SECRET_KEY "Secret key (not echoed, never logged, written only to backup.env 0640)." secret
  fi
  ask BACKUP_SCHEDULE "When backups run: a systemd OnCalendar expression (daily, hourly, *-*-* 03:00:00)."
  say "
The backup encryption key: make it OFFLINE, on a machine other than this host:
    age-keygen -o core-backup.key        (or: ainkrad-core-server backup-keygen)
  It prints 'Public key: age1...'. Paste only that here. Keep core-backup.key offline (a password manager or
  paper): without it no backup can be restored, and with it anyone can read them."
  ask BACKUP_RECIPIENT "The age recipient (public key, age1...)."
  ask ENABLE_CITADEL "Enable the Citadel module? (default no) Needs the composed binary ainkrad-core-citadel beside the others; the unit then starts it with --enable-module citadel, and the module's data and migrations are handled by that binary. Off: nothing of Citadel is installed or mounted."
  ask ENABLE_SEMANTIC "Fetch the local sorting model for the Brain import (default no)? About 490 MB, downloaded once from a pinned Hugging Face revision and checked against pinned SHA-256 sums; it runs on this host only. Off: Review sorts by rules alone."
  ask RUNNER "Also install a runner on this host (yes/no)? exec.run stays OFF unless you add --enable-exec to RUNNER_ARGS in /etc/ainkrad-runner/runner.env."
  if [ "$A_RUNNER" = yes ]; then
    ask RUNNER_PTY "Offer terminals on that runner (yes/no)? A client with the terminal scope and a live step-up gets a shell as the unprivileged ainkrad-runner user, inside the unit's sandbox."
    ask RUNNER_PAIR_CODE "A pairing code (ABCDE-FGHJK) from 'ainkradctl device add <name> --kind runner' on an approved device, to pair and start it now; empty: pair later."
  fi
  ask HARDEN "Run scripts/host/harden.sh: firewall to 22/80/443 only, key-only SSH, no core dumps or swap, unattended security updates (yes/no)."
  [ "$A_HARDEN" = no ] || ask SSH_FROM "Allow new SSH only from these IPv4 CIDRs (comma-separated; empty = from anywhere). IPv6 SSH is not filtered by harden.sh."
  ask BOOTSTRAP "Pair your first device now (needs you at your machine within 5 minutes) or later (instructions printed)."
  ask SELFTEST_BACKUP "Test backup at the end: no, local (on this host), or bucket (one small object, which the bucket keeps until its expiry)."
}

review() {
  step "Review"
  local k v
  for k in $KEYS; do
    eval "v=\${A_$k:-}"
    case $k in BACKUP_SECRET_KEY | BACKUP_ACCESS_KEY) [ -z "$v" ] || v=$(mask "$v") ;; esac
    case $k in BACKUP_ENDPOINT | BACKUP_REGION | BACKUP_BUCKET | BACKUP_PREFIX | BACKUP_ACCESS_KEY | BACKUP_SECRET_KEY)
      [ "$A_BACKUP" = bucket ] || continue ;; RUNNER_PTY | RUNNER_PAIR_CODE) [ "$A_RUNNER" = yes ] || continue ;; esac
    printf '  %-18s %s\n' "$k" "${v:-<empty>}"
  done
}

preflight() {
  if [ "$(uname -s)" != Linux ] || [ ! -d /run/systemd/system ]; then
    local msg
    msg="the Core installs on Linux with systemd only (this is $(uname -s)). On macOS only a runner is supported, best effort: deploy/launchd/install.sh."
    [ "$DRY" = 1 ] && warn "$msg (dry run continues)" || die "$msg"
  fi
  [ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "run as root (sudo), or with --dry-run"
}

checks() { # ports and the host firewall first (before anything is installed), then DNS -> this host's public IP; any problem stops
  step "Checks"
  local bad='' addrs pub a ports=443
  [ "$A_ACME_CHALLENGE" = http-01 ] && ports="443 80"
  if ! pc_checks "$ports"; then
    if [ "$DRY" = 1 ]; then warn "$PC_WHAT (dry run continues)"; else die "$PC_WHAT. What to do: $PC_TODO"; fi
  elif [ "$DRY" = 0 ] && ! pc_probe "$ports"; then # from outside, through Ainkrad's sign-in service (N6)
    die "$PC_WHAT. What to do: $PC_TODO"
  fi
  if ! command -v getent >/dev/null; then warn "no getent here: DNS not checked"; return 0; fi
  addrs=$(getent ahosts "$A_HOSTNAME" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true) # pipefail: an unresolved name must reach the message below, not kill the script
  pub=${A_PUBLIC_IP:-$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsS4 --max-time 5 https://checkip.amazonaws.com 2>/dev/null || true)}
  pub=$(clean_ip "$pub")
  info "DNS $A_HOSTNAME -> ${addrs:-nothing}; this host's public IPv4: ${pub:-unknown}"
  if [ -z "$addrs" ]; then bad="$A_HOSTNAME does not resolve: add an A record for this host"
  elif [ -n "$pub" ] && ! printf ' %s ' "$addrs" | grep -q " $pub "; then bad="$A_HOSTNAME does not point at $pub (this machine): the certificate cannot be issued until it does"; fi
  for a in $addrs; do
    case $a in *:*) ip -6 addr 2>/dev/null | grep -q " $a/" || bad="${bad:+$bad; }AAAA $a is not on this host: remove it or the certificate may be validated against the wrong machine" ;; esac
  done
  [ -z "$bad" ] && return 0
  [ "$DRY" = 1 ] && { warn "$bad (dry run continues)"; return 0; }
  die "$bad"
}

stage_binaries() {
  step "Binaries"
  local src n citadel_src=''
  if [ "${A_BUILD:-no}" = yes ]; then
    command -v cargo >/dev/null || die "BUILD=yes needs cargo on this host"
    run nice -n 19 cargo build --release --manifest-path "$ROOT/Cargo.toml" -p ainkrad-ctl -p ainkrad-runner -p ainkrad-ptyhost
    # ainkrad-core-server is the Brain-carrying build (its own cargo workspace), like a release's.
    run nice -n 19 cargo build --release --manifest-path "$ROOT/modules/brain/Cargo.toml" -p ainkrad-core-brain
    src=$ROOT/target/release
    [ "$DRY" = 1 ] || cp "$ROOT/modules/brain/target/release/ainkrad-core-brain" "$src/ainkrad-core-server"
    if [ "$A_ENABLE_CITADEL" = yes ]; then # the composed binary is its own cargo workspace
      run nice -n 19 cargo build --release --manifest-path "$ROOT/modules/citadel/Cargo.toml" -p ainkrad-core-citadel
      citadel_src=$ROOT/modules/citadel/target/release
    fi
  else src=$A_BINARY_DIR; fi
  STAGE=$(mktemp -d)
  # shellcheck disable=SC2016 # the string is eval'd at exit, when $STAGE is known
  if [ "$GUIDED" = 1 ]; then ui_clean_add 'rm -rf "$STAGE"'; else trap 'rm -rf "$STAGE"' EXIT; fi
  for n in ainkrad-core-server ainkradctl ainkrad-runner ainkrad-ptyhost; do
    if [ -f "$src/$n" ]; then cp "$src/$n" "$STAGE/$n"; chmod 0755 "$STAGE/$n"; info "$n sha256 $(sha "$STAGE/$n")"
    elif [ "$n" = ainkrad-core-server ] && [ "$DRY" = 0 ]; then die "no $n in $src"
    else warn "$n: not in $src (skipped; every signed release ships it, so a release installed with scripts/release/install.sh has it)"; fi
  done
  if [ "$A_ENABLE_CITADEL" = yes ]; then
    src=${citadel_src:-$src}
    if [ -f "$src/ainkrad-core-citadel" ]; then
      cp "$src/ainkrad-core-citadel" "$STAGE/ainkrad-core-citadel"; chmod 0755 "$STAGE/ainkrad-core-citadel"
      say "  ainkrad-core-citadel sha256 $(sha "$STAGE/ainkrad-core-citadel")"
    elif [ "$DRY" = 0 ]; then die "ENABLE_CITADEL=yes but no ainkrad-core-citadel in $src"
    else say "  ainkrad-core-citadel: not in $src (skipped)"; fi
    [ "$DRY" = 1 ] || "$STAGE/ainkrad-core-citadel" --help | grep -q -- '--enable-module' || die "$src/ainkrad-core-citadel does not run here or lacks --enable-module"
  fi
  [ "$DRY" = 1 ] || "$STAGE/ainkrad-core-server" --help | grep -q -- '--acme-directory' || die "$src/ainkrad-core-server does not run here (wrong architecture?)"
  if [ "$A_PASSKEYS" = yes ] && [ "$DRY" = 0 ] && ! "$STAGE/ainkrad-core-server" --help | grep -q -- '--passkeys'; then
    die "this ainkrad-core-server predates --passkeys: use a newer build or PASSKEYS=no"
  fi
}

apply_harden_req() { [ -z "$HARDEN_REQ" ] || A_HARDEN=$HARDEN_REQ; }

harden() {
  if [ "$A_HARDEN" != yes ]; then step "Host hardening skipped"; [ "$GUIDED" = 1 ] || say "  Host hardening skipped (opt-in): SSH config and firewall untouched. Use --harden to apply it (experimental)."; return 0; fi
  step "Host hardening (scripts/host/harden.sh)"
  grep -E '^# [0-9]\.' "$ROOT/scripts/host/harden.sh" | sed 's/^# /  /'
  if [ -n "$A_SSH_FROM" ]; then
    local peers p
    peers=$(AINKRAD_HARDEN_SOURCE_ONLY=1 bash -c '. "$1"; ssh_peers' _ "$ROOT/scripts/host/harden.sh" 2>/dev/null || true) # on every sshd port
    [ -n "$peers$DRY" ] || die "SSH_FROM: cannot see your SSH session's address; refusing to restrict SSH blind"
    for p in $peers; do ip_in_cidrs "$p" "$A_SSH_FROM" || die "SSH_FROM $A_SSH_FROM would lock out the open SSH session from $p"; done
    say "  SSH will be admitted only from $A_SSH_FROM (current sessions: ${peers:-none seen}). Your cloud firewall may need the same."
  fi
  firewall_decide # what will stop being reachable, BEFORE any consent below
  [ -n "$CONFIG" ] || [ "$DRY" = 1 ] || [ "$GUIDED" = 1 ] || yes_no "Apply it now?" || { say "  skipped"; return 0; }
  HARDEN_WARN=$STAGE/harden.warn HARDEN_STATE=$STAGE/harden.state
  RUN_PLAIN=1 run env AINKRAD_SSH_FROM="$A_SSH_FROM" AINKRAD_FIREWALL="$FW_CHOICE" AINKRAD_NOTICE_SHOWN=1 \
    AINKRAD_HARDEN_WARN="$HARDEN_WARN" AINKRAD_HARDEN_STATE="$HARDEN_STATE" bash "$ROOT/scripts/host/harden.sh"
}

install_core() {
  step "Core: user, binary, unit, home"
  local out prev_env tls=$CORE_HOME/tls dry=() sem=()
  [ "$A_ENABLE_SEMANTIC" = yes ] && sem=(--semantic-model)
  [ "$DRY" = 1 ] && dry=(--dry-run)
  if [ "$GUIDED$DRY" = 10 ]; then
    out=''
    ui_run "Creating the service account, the Core's home (keys, database) and its service" bash "$ROOT/deploy/install-core-linux.sh" --binary "$STAGE/ainkrad-core-server" ${sem[@]+"${sem[@]}"} ||
      die "creating the Core's home failed"
  else
    out=$(bash "$ROOT/deploy/install-core-linux.sh" --binary "$STAGE/ainkrad-core-server" ${sem[@]+"${sem[@]}"} ${dry[@]+"${dry[@]}"} | tee -a /dev/stderr) # -a: on Linux a plain tee reopens a redirected stderr file and truncates it
  fi
  # The signer's fingerprint, base64url(SHA-256(SPKI)) as `init` prints it, from the key itself (so a re-run has it).
  SIGNER=''
  [ "$DRY" = 1 ] || SIGNER=$(openssl pkey -inform DER -in "$CORE_HOME/keys/backup-signing.p8" -pubout -outform DER |
    openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
  printf '%s\n' "$out" | grep -qxF "$SIGNER" || [ "$DRY" = 1 ] || [ "$GUIDED" = 1 ] || say "  (home kept; signer fingerprint derived from its key)"
  # The Core keeps one ACME account and certificate in tls/ whatever the directory: a switch between staging
  # and production must start a fresh tls/ (the old one is kept beside it).
  prev_env=$(env_get AINKRAD_ACME_ENV)
  if [ -n "$prev_env" ] && [ "$prev_env" != "$A_ACME_ENV" ] && { [ "$DRY" = 1 ] || [ -d "$tls" ]; }; then
    run mv "$tls" "$tls.$prev_env.$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  local args=''
  [ "$A_ACME_ENV" = staging ] && args="--acme-directory $STAGING_DIR"
  [ "$A_ACME_CHALLENGE" = http-01 ] && args="$args --acme-http01"
  [ "$A_PASSKEYS" = yes ] && args="$args --passkeys${A_ALLOW_ORIGINS:+ --allow-origin $A_ALLOW_ORIGINS}"
  write_file "$ETC/core.env" 0640 root:ainkrad "# Written by scripts/install.sh $(date -u +%FT%TZ). Not secret; the bucket credentials are in backup.env.
AINKRAD_LISTEN=public
AINKRAD_HOSTNAME=$(lower "$A_HOSTNAME")
AINKRAD_ACME_CONTACT=$A_ACME_CONTACT
AINKRAD_ACME_ENV=$A_ACME_ENV
AINKRAD_LOG_FORMAT=json
AINKRAD_SERVE_ARGS=${args# }
AINKRAD_BACKUP_RECIPIENT=$A_BACKUP_RECIPIENT
AINKRAD_BACKUP_SIGNER=$SIGNER"
}

# The Citadel module (opt-in): the composed binary beside the plain one and a drop-in that makes the Core unit run
# it with --enable-module citadel. Not chosen: the binary and the drop-in are removed, the plain unit runs as before.
install_citadel() {
  local d=$UNITS/ainkrad-core.service.d
  if [ "$A_ENABLE_CITADEL" != yes ]; then
    step "Citadel module: off (default)"
    run rm -rf "$d/citadel.conf" "$BIN/ainkrad-core-citadel"
    return 0
  fi
  step "Citadel module: on"
  [ -f "$STAGE/ainkrad-core-citadel" ] || [ "$DRY" = 1 ] || die "no ainkrad-core-citadel staged"
  run install -m 0755 "$STAGE/ainkrad-core-citadel" "$BIN/ainkrad-core-citadel"
  run install -d -m 0755 "$d"
  write_file "$d/citadel.conf" 0644 root:root "[Service]
ExecStart=
ExecStart=$BIN/ainkrad-core-citadel serve --config $CORE_HOME/config.toml --enable-module citadel \$AINKRAD_SERVE_ARGS"
}

install_backup() {
  step "Backups ($A_BACKUP, $A_BACKUP_SCHEDULE)"
  case $A_BACKUP in
    bucket)
      local body="AINKRAD_BACKUP_ENDPOINT=$A_BACKUP_ENDPOINT
AINKRAD_BACKUP_BUCKET=$A_BACKUP_BUCKET
AINKRAD_BACKUP_REGION=$A_BACKUP_REGION
AINKRAD_BACKUP_PREFIX=${A_BACKUP_PREFIX:-core/}
AINKRAD_BACKUP_ACCESS_KEY=$A_BACKUP_ACCESS_KEY"
      write_file "$ETC/backup.env" 0640 root:ainkrad "$body
AINKRAD_BACKUP_SECRET_KEY=$A_BACKUP_SECRET_KEY" "$(printf '%s\n' "$body" | sed "s|^AINKRAD_BACKUP_ACCESS_KEY=.*|AINKRAD_BACKUP_ACCESS_KEY=$(mask "$A_BACKUP_ACCESS_KEY")|")
AINKRAD_BACKUP_SECRET_KEY=$(mask "$A_BACKUP_SECRET_KEY")" ;;
    keep) [ "$DRY" = 1 ] || [ -s "$ETC/backup.env" ] || die "BACKUP=keep but there is no $ETC/backup.env"
      say "  $ETC/backup.env kept as it is (not read, not printed)" ;;
    local) info "no bucket: encrypted snapshots stay in $CORE_HOME/backups only" ;;
  esac
  [ "$DRY" = 1 ] || ! command -v systemd-analyze >/dev/null || systemd-analyze calendar "$A_BACKUP_SCHEDULE" >/dev/null ||
    die "BACKUP_SCHEDULE '$A_BACKUP_SCHEDULE' is not a systemd calendar expression"
  run install -m 0644 "$ROOT/deploy/systemd/ainkrad-backup.service" "$UNITS/ainkrad-backup.service"
  run install -m 0644 "$ROOT/deploy/systemd/ainkrad-backup.timer" "$UNITS/ainkrad-backup.timer"
  run install -d -m 0755 "$UNITS/ainkrad-backup.timer.d" "$UNITS/ainkrad-backup.service.d"
  write_file "$UNITS/ainkrad-backup.timer.d/schedule.conf" 0644 root:root "[Timer]
OnCalendar=
OnCalendar=$A_BACKUP_SCHEDULE"
  if [ "$A_BACKUP" = local ]; then
    write_file "$UNITS/ainkrad-backup.service.d/local.conf" 0644 root:root "[Service]
EnvironmentFile=
EnvironmentFile=$ETC/core.env
ExecStart=
ExecStart=$BIN/ainkrad-core-server backup --config $CORE_HOME/config.toml --local-only"
  else run rm -f "$UNITS/ainkrad-backup.service.d/local.conf"; fi
}

start_core() {
  step "Start"
  run systemctl daemon-reload
  local tm=ainkrad-backup.timer
  [ -n "$A_BACKUP_RECIPIENT" ] || tm='' # no age recipient (guided, no terminal): the timer would only fail every day
  run systemctl enable ainkrad-core.service $tm
  run systemctl restart ainkrad-core.service
  [ -z "$tm" ] || run systemctl restart ainkrad-backup.timer
  [ "$DRY" = 1 ] && return 0
  if [ "$GUIDED" = 1 ]; then
    cert_wait || { ui_warn "The Core's own log says:"; ui_emit "$(journalctl -u ainkrad-core -n 12 --no-pager 2>&1 | ui_clean_lines | cut -c1-"$((UI_W - 6))" | sed 's/^/     /')"; die "the Core did not become healthy within 4 minutes: check that $A_HOSTNAME points at this machine and that your cloud firewall allows inbound TCP 443 (the Core log is above)"; }
    ui_ok "The certificate was issued and the Core answers over HTTPS"
    return 0
  fi
  say "  waiting for https://$A_HOSTNAME/healthz (the first certificate can take a minute)..."
  local end=$((SECONDS + 240))
  until health >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$end" ] || { journalctl -u ainkrad-core -n 20 --no-pager >&2; die "the Core did not become healthy: check that $A_HOSTNAME points at this machine and that your cloud firewall allows inbound 443 (the log is above)"; }
    sleep 3
  done
  say "  healthy"
}

health() { # healthz on this host, by name (no hairpin NAT); a staging certificate is not verifiable
  local k=(); [ "$A_ACME_ENV" = staging ] && k=(-k)
  curl -fsS --max-time 5 ${k[@]+"${k[@]}"} --resolve "$A_HOSTNAME:443:127.0.0.1" "https://$A_HOSTNAME/healthz"
}

# Enrols this Core's own runner without a code (the Core makes the device itself, scope runner only) and puts its key and
# enrolment where the unprivileged runner user reads them. Runs as root; the Core command runs as the database's owner.
enrol_local_runner() {
  local out=$CORE_HOME/runner-enrol
  [ ! -e "$RUNNER_STATE/enrolment.json" ] || return 0
  if [ ! -s "$out/device.p8" ] || [ ! -s "$out/enrolment.json" ]; then
    rm -rf "$out"
    runuser -u ainkrad -- "$BIN/ainkrad-core-server" runner-enroll-local "$CORE_HOME/core.db" "$out" "https://$A_HOSTNAME" >/dev/null || return 1
  fi
  install -d -m 0700 -o ainkrad-runner -g ainkrad-runner "$RUNNER_STATE" &&
    install -m 0600 -o ainkrad-runner -g ainkrad-runner "$out/device.p8" "$RUNNER_STATE/device.p8" &&
    install -m 0600 -o ainkrad-runner -g ainkrad-runner "$out/enrolment.json" "$RUNNER_STATE/enrolment.json" &&
    rm -rf "$out"
}
runner_online() { # the Core has seen this runner connect (its device was used); up to 60 s
  local i
  for i in $(seq 30); do
    runuser -u ainkrad -- "$BIN/ainkrad-core-server" device list "$CORE_HOME/core.db" 2>/dev/null |
      awk -F'\t' '$2 == "runner" && $4 == "active" && $7 != "last used never" { f = 1 } END { exit !f }' && return 0
    sleep 2
  done
  return 1
}
# N8: the Core's own runner, on by default: terminals and agents, as the unprivileged ainkrad-runner user in its sandbox.
local_runner() {
  local a=(--binary "$STAGE/ainkrad-runner" --ptyhost "$STAGE/ainkrad-ptyhost" --pty --agents)
  if [ "$A_ACME_ENV" = staging ]; then
    warn "the Core serves a staging certificate that a runner does not trust, so the built-in runner is not set up. Re-run with a production certificate."
    return 0
  fi
  if [ "$DRY" = 1 ]; then
    trace "install Node $NODE_VERSION and claude-code@$CLAUDE_VERSION (DISABLE_AUTOUPDATER=1 in /etc/claude-code/managed-settings.json)"
    trace "ainkrad-core-server runner-enroll-local $CORE_HOME/core.db <dir> https://$A_HOSTNAME"
    bash "$ROOT/deploy/install-linux.sh" "${a[@]}" --dry-run; return 0
  fi
  if ! ui_run "Installing Node $NODE_VERSION and Claude Code $CLAUDE_VERSION for agents" install_agent_tools; then
    warn "the agent tools did not install (see above); the runner is set up with terminals only"; a=(--binary "$STAGE/ainkrad-runner" --ptyhost "$STAGE/ainkrad-ptyhost" --pty)
  fi
  ui_run "Installing the runner service (unprivileged user, sandboxed)" bash "$ROOT/deploy/install-linux.sh" "${a[@]}" || { warn "the runner did not install; see the log"; return 0; }
  if ! ui_run "Enrolling this Core's own runner (no code needed)" enrol_local_runner; then
    warn "the runner could not be enrolled (an older ainkrad-core-server?). Pair it by hand: ainkradctl device add <name> --kind runner, then deploy/install-linux.sh --pair"; return 0
  fi
  ui_run "Starting the runner" bash "$ROOT/deploy/install-linux.sh" "${a[@]}" --start || { warn "the runner did not start; see the log"; return 0; }
  if UI_QUIET=1 ui_run "Waiting for the runner to show online" runner_online; then ui_keep "The built-in runner is online (terminals and agents on)"
  else warn "the runner started but the Core has not seen it connect yet: check 'journalctl -u ainkrad-runner -n 30'. It must be able to reach https://$A_HOSTNAME from this machine."; fi
}

extras() {
  if [ -f "$STAGE/ainkradctl" ]; then step "ainkradctl"; run install -m 0755 "$STAGE/ainkradctl" "$BIN/ainkradctl"; fi
  [ "$A_RUNNER" = yes ] || { [ "$GUIDED" != 1 ] || ui_note "No built-in runner (--no-local-runner): the app shows No runner until you add one. Nothing runs on this machine for agents or terminals."; return 0; }
  step "Runner on this host (terminals $([ "$A_RUNNER_PTY" = yes ] && echo ON || echo off); exec.run OFF)"
  [ -f "$STAGE/ainkrad-runner" ] || { warn "no ainkrad-runner binary: runner skipped"; return 0; }
  if [ "$GUIDED" = 1 ] && [ -z "${A_RUNNER_PAIR_CODE:-}" ]; then
    [ -f "$STAGE/ainkrad-ptyhost" ] || { warn "no ainkrad-ptyhost binary: the built-in runner is skipped"; return 0; }
    local_runner; return 0
  fi
  local a=(--binary "$STAGE/ainkrad-runner") code=${A_RUNNER_PAIR_CODE:-}
  [ "$DRY" = 1 ] && a+=(--dry-run)
  if [ "$A_RUNNER_PTY" = yes ]; then
    [ -f "$STAGE/ainkrad-ptyhost" ] || die "RUNNER_PTY=yes but no ainkrad-ptyhost binary beside the others"
    a+=(--pty)
  fi
  [ -f "$STAGE/ainkrad-ptyhost" ] && a+=(--ptyhost "$STAGE/ainkrad-ptyhost")
  if [ -n "$code" ]; then
    if [ "$A_ACME_ENV" = staging ]; then
      warn "the Core serves a staging certificate the runner does not trust: pair by hand with --ca (below)"; code=''
    else a+=(--pair "https://$A_HOSTNAME"); fi
  fi
  AINKRAD_PAIR_CODE=$code bash "$ROOT/deploy/install-linux.sh" "${a[@]}" || { warn "runner install/pairing did not complete; pair it by hand (below)"; code=''; }
  [ -n "$code" ] || say "  Pair it once your first device is paired: on that device \`ainkradctl device add $(hostname -s 2>/dev/null || echo runner) --kind runner\`, then here:
    sudo $ROOT/deploy/install-linux.sh --binary $BIN/ainkrad-runner$([ "$A_RUNNER_PTY" = yes ] && echo ' --pty') --pair https://$A_HOSTNAME --code -
  compare the SAS it prints with the approver's, approve it; the runner then starts. (--ca <pem> for a staging Core.)"
}

runner_selftest() { # runner checks, when its unit is installed; t() comes from selftest
  [ -e "$UNITS/ainkrad-runner.service" ] || return 0
  local args; args=$(sed -n 's/^RUNNER_ARGS=//p' /etc/ainkrad-runner/runner.env 2>/dev/null | tail -n1)
  [ "$(systemctl show -p KillMode --value ainkrad-runner 2>/dev/null)" = process ] &&
    t PASS "runner unit: KillMode=process (terminal hosts survive a runner restart)" || t FAIL "runner unit: KillMode is not process (a restart would kill every terminal)"
  case " $args " in
    *" --enable-pty "*)
      [ -x "$BIN/ainkrad-ptyhost" ] && t PASS "runner terminals ON, $BIN/ainkrad-ptyhost present" || t FAIL "runner terminals ON but $BIN/ainkrad-ptyhost is missing" ;;
    *) say "        runner terminals: off" ;;
  esac
  case " $args " in *" --enable-exec "*) say "        NOTE: runner exec.run is ON (the Core can run any program as ainkrad-runner)" ;; *) say "        runner exec.run: off" ;; esac
  if [ -e /var/lib/ainkrad-runner/core/enrolment.json ]; then
    [ "$(systemctl is-active ainkrad-runner 2>/dev/null)" = active ] && t PASS "ainkrad-runner.service active (paired)" || t FAIL "paired but ainkrad-runner.service is not active"
  else say "        runner not paired yet: see the pairing instructions of the install"; fi
}

# Whether the Citadel module is mounted (the unit's drop-in AND the running process's flags agree), and that its
# read route refuses an unsigned request with 401. A signed 403 forbidden_scope (a device without the scope) needs a
# paired device: it is proven by the composed binary's own serve test, not here.
citadel_selftest() {
  local pid cmd code k=() want=no
  pid=$(systemctl show -p MainPID --value ainkrad-core 2>/dev/null || true)
  cmd=$(tr '\0' ' ' <"/proc/${pid:-0}/cmdline" 2>/dev/null || true)
  [ -e "$UNITS/ainkrad-core.service.d/citadel.conf" ] && want=yes
  case $cmd in
    *"--enable-module citadel"*) [ "$want" = yes ] && t PASS "citadel module: mounted (ainkrad-core-citadel --enable-module citadel)" ||
      t FAIL "citadel module mounted but not by the installer's drop-in" ;;
    *) [ "$want" = no ] && say "        citadel module: not mounted (default)" ||
      t FAIL "citadel module chosen but the running Core was not started with --enable-module citadel" ;;
  esac
  [ "${A_ACME_ENV:-}" = staging ] && k=(-k)
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 ${k[@]+"${k[@]}"} --resolve "$A_HOSTNAME:443:127.0.0.1" \
    "https://$A_HOSTNAME/modules/citadel/v1/companies" 2>/dev/null || true)
  [ "$code" = 401 ] && t PASS "citadel read route, unsigned: 401 (mounted or not, nothing is served without a signed device)" ||
    t FAIL "citadel read route, unsigned: got ${code:-no answer}, want 401"
}

# The Brain is carried by the shipped ainkrad-core-server and mounted by default. Unsigned, the gate answers 401 for any
# /modules path (mounted or not), so the carrying is proven by a Brain-only route string in the installed binary, and the
# 401 shows the Core is up and gated. The composed binary's own serve test proves the mount.
brain_selftest() {
  local code k=()
  grep -qa '/rooms/{room}/claims' "$BIN/ainkrad-core-server" 2>/dev/null &&
    t PASS "brain module: carried by ainkrad-core-server (mounted by default)" ||
    t FAIL "brain module: $BIN/ainkrad-core-server does not carry the Brain (a plain build; install the release's)"
  [ "${A_ACME_ENV:-}" = staging ] && k=(-k)
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 ${k[@]+"${k[@]}"} --resolve "$A_HOSTNAME:443:127.0.0.1" \
    "https://$A_HOSTNAME/modules/brain/v1/status" 2>/dev/null || true)
  [ "$code" = 401 ] && t PASS "brain read route, unsigned: 401" || t FAIL "brain read route, unsigned: got ${code:-no answer}, want 401"
}

selftest() { # PASS/FAIL lines; returns 1 on any FAIL
  step "Self-test"
  local fail=0 out cert
  t() { # PASS lines are the live line in the guided install (FAIL stays on the screen)
    [ "$1" = PASS ] || fail=1
    if [ "$GUIDED" != 1 ]; then printf '  %-5s %s\n' "$1" "$2"; elif [ "$1" = PASS ]; then ui_status "$2"; else ui_warn "$1 $2"; fi
  }
  [ "$(systemctl is-active ainkrad-core 2>/dev/null)" = active ] && t PASS "ainkrad-core.service active" || t FAIL "ainkrad-core.service not active"
  out=$(health 2>&1) && t PASS "healthz over TLS: $(printf '%s' "$out" | head -c 160)" || t FAIL "healthz: $out"
  cert=$(openssl s_client -connect 127.0.0.1:443 -servername "$A_HOSTNAME" </dev/null 2>/dev/null | openssl x509 -noout -issuer -enddate 2>/dev/null | tr '\n' ' ')
  [ -n "$cert" ] && [ -s "$CORE_HOME/tls/cert.pem" ] && t PASS "certificate in $CORE_HOME/tls: $cert" || t FAIL "no certificate served"
  case $cert in *STAGING*) say "        (staging: not trusted by browsers; switch with ACME_ENV=production)" ;; esac
  if [ -z "$(env_get AINKRAD_BACKUP_RECIPIENT)" ]; then say "        backups: off (no age recipient set)"
  elif systemctl is-enabled ainkrad-backup.timer >/dev/null 2>&1; then t PASS "backup timer: $(systemctl show -p NextElapseUSecRealtime --value ainkrad-backup.timer)"
  else t FAIL "ainkrad-backup.timer not enabled"; fi
  runner_selftest
  citadel_selftest
  brain_selftest
  case ${1:-no} in
    local)
      out=$(runuser -u ainkrad -- bash -c "set -a; . $ETC/core.env; set +a; exec $BIN/ainkrad-core-server backup --config $CORE_HOME/config.toml --local-only" 2>&1) &&
        t PASS "local backup: $(printf '%s' "$out" | tail -n1)" || t FAIL "local backup: $(printf '%s' "$out" | tail -n2 | tr '\n' ' ')" ;;
    bucket)
      say "        one small object (a fresh home is tens of KB); the backup key cannot delete it: it expires by the bucket's lifecycle rule"
      local since; since=$(date '+%Y-%m-%d %H:%M:%S')
      if systemctl start ainkrad-backup.service; then
        t PASS "bucket backup: $(journalctl -u ainkrad-backup --since "$since" --no-pager -o cat | grep -o 'uploaded as .*' | tail -n1)"
      else t FAIL "bucket backup: $(journalctl -u ainkrad-backup --since "$since" --no-pager -o cat | tail -n2 | tr '\n' ' ')"; fi
      say "        listing the bucket needs an S3 client with list rights; the key above is the object the Core PUT" ;;
  esac
  return "$fail"
}

bootstrap() {
  step "First device"
  say "  On this host (it prints code and core_fp, then waits up to 5 minutes):
    sudo -u ainkrad $BIN/ainkrad-core-server bootstrap $CORE_HOME/core.db <device name>
  On your machine, from a checkout of this repo, with ainkradctl:
    scripts/install/admin-relay.sh <you>@<this host> /tmp/ainkrad-admin.sock -- -i <your ssh key>
    ainkradctl --socket /tmp/ainkrad-admin.sock --host $A_HOSTNAME pair <code> --core-fp <core_fp>
  Compare the SAS both sides print, type y here; then: ainkradctl --url https://$A_HOSTNAME$([ "$A_ACME_ENV" = staging ] && echo ' --ca <Let'"'"'s Encrypt staging roots.pem>') health"
  [ "$A_BOOTSTRAP" = now ] && [ "$DRY" = 0 ] || return 0
  [ -t 0 ] || { warn "BOOTSTRAP=now needs a terminal: run the command above yourself"; return 0; }
  runuser -u ainkrad -- "$BIN/ainkrad-core-server" bootstrap "$CORE_HOME/core.db" "${SUDO_USER:-owner}" || warn "bootstrap did not complete; run it again as above"
}

summary() {
  step "Summary"
  say "  Exposed: TCP 443 (TLS 1.3, Let's Encrypt $A_ACME_ENV, $A_ACME_CHALLENGE)$([ "$A_ACME_CHALLENGE" = http-01 ] && echo ', TCP 80 (ACME HTTP-01)'); SSH :22${A_SSH_FROM:+ from $A_SSH_FROM only (IPv4; IPv6 SSH is not filtered by harden.sh)}.
  Not exposed: the admin socket ($CORE_HOME/admin.sock, the service user only)$([ "$A_RUNNER" = yes ] && echo '; the runner dials out, it listens on nothing').
  Backup signer fingerprint (restore needs it as --signer; record it OFFLINE with the age identity):
    ${SIGNER:-<shown here after a real run>}
  Still yours to do:
    - DNS: A (and AAAA only if this host has that IPv6) for $A_HOSTNAME; a CAA record: 0 issue \"letsencrypt.org\".
    - Your cloud firewall / security list: inbound 443$([ "$A_ACME_CHALLENGE" = http-01 ] && echo ' and 80'), and 22 only from where you administer.
    - $([ "$A_HARDEN" = yes ] && echo "Hardening applied${A_SSH_FROM:+; SSH admitted only from $A_SSH_FROM}" || echo 'Host hardening and SSH restriction: scripts/host/harden.sh (re-run this with HARDEN=yes)').
    - $([ "$A_ACME_ENV" = staging ] && echo 'This is a STAGING certificate: re-run with ACME_ENV=production when the checks pass.' || echo 'Production certificate: renewals are automatic.')
    - Delete any answers file that holds BACKUP_SECRET_KEY."
}

uninstall() {
  [ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "run as root (sudo), or with --dry-run"
  step "Uninstall"
  local u name
  for u in ainkrad-backup.timer ainkrad-backup.service ainkrad-runner-tools.socket ainkrad-runner.service ainkrad-core.service; do
    run systemctl disable --now "$u" 2>/dev/null || true
  done
  # KillMode=process: stopping the runner leaves its terminal hosts running on purpose; removing it ends them.
  run systemctl kill --kill-whom=all ainkrad-runner.service 2>/dev/null || true
  run rm -rf "$UNITS/ainkrad-core.service" "$UNITS/ainkrad-runner.service" "$UNITS/ainkrad-backup.service" \
    "$UNITS/ainkrad-backup.timer" "$UNITS/ainkrad-backup.timer.d" "$UNITS/ainkrad-backup.service.d" "$UNITS/ainkrad-core.service.d" "$UNITS/ainkrad-runner.service.d" "$UNITS/ainkrad-runner-tools.socket" "$UNITS/ainkrad-runner-tools@.service"
  run systemctl daemon-reload
  run systemctl reset-failed 2>/dev/null || true
  run rm -f "$BIN/ainkrad-core-server" "$BIN/ainkradctl" "$BIN/ainkrad-runner" "$BIN/ainkrad-ptyhost" "$BIN/ainkrad-core-citadel"
  if [ "$PURGE" = 1 ]; then
    name=$(env_get AINKRAD_HOSTNAME); name=${name:-purge}
    say "  --purge deletes $CORE_HOME (database, keys, certificates), the runner's state and $ETC/core.env. Type '$name' to confirm:"
    local typed=${AINKRAD_PURGE_CONFIRM:-}
    [ -n "$typed" ] || { [ -t 0 ] && need_terminal && read -r typed </dev/tty; } || true
    if [ "$typed" = "$name" ]; then
      run rm -rf "$CORE_HOME" /var/lib/ainkrad-runner /var/lib/ainkrad-runner-work /var/lib/akrw /etc/ainkrad-runner "$ETC/core.env"
    else say "  not confirmed: data kept"; fi
  fi
  say "  Kept: $ETC/backup.env (the bucket key: remove it yourself when retiring the host), the bucket and every
  object in it, the ainkrad / ainkrad-runner users, the firewall.$([ "$PURGE" = 1 ] || echo " Data kept in $CORE_HOME (--purge removes it).")"
  run rm -rf "$INSTALLER_SAVED"
  [ "$DRY" = 1 ] || { say "  TCP listeners now:"; ss -Hltn | awk '{print "    " $4}'; }
}

main() {
  while [ $# -gt 0 ]; do
    case $1 in
      --config) CONFIG=${2:?}; shift 2 ;;
      --binary) CLI_BINARY=${2:?}; shift 2 ;;
      --dry-run) DRY=1; shift ;;
      --demo) DEMO=1; shift ;;
      --harden) HARDEN_REQ=yes; shift ;;
      --no-local-runner) NO_LOCAL_RUNNER=1; shift ;;
      --guided) GUIDED=1; shift ;;
      --wizard) GUIDED=-1; shift ;;
      --uninstall) MODE=uninstall; shift ;;
      --purge) PURGE=1; shift ;;
      --check) MODE=check; shift ;;
      --backup) CHECK_BACKUP=${2:?}; valid_selftest "$CHECK_BACKUP" || die "--backup local|bucket"; shift 2 ;;
      -h | --help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
      *) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
  done
  case ${AINKRAD_HARDEN:-} in '' | yes | no) [ -n "$HARDEN_REQ" ] || HARDEN_REQ=${AINKRAD_HARDEN:-} ;; # the --harden flag wins over the variable
 *) die "AINKRAD_HARDEN must be yes or no (got '$AINKRAD_HARDEN')" ;; esac
  if [ -n "$DEMO" ]; then
    # shellcheck source=scripts/install/demo.sh
    . "$ROOT/scripts/install/demo.sh"; demo_main; return 3
  fi
  case $MODE in
    uninstall) uninstall; return ;;
    check)
      [ "$(id -u)" = 0 ] || die "run as root"
      A_HOSTNAME=$(env_get AINKRAD_HOSTNAME) A_ACME_ENV=$(env_get AINKRAD_ACME_ENV)
      [ -n "$A_HOSTNAME" ] || die "no install found ($ETC/core.env)"
      selftest "$CHECK_BACKUP"; return ;;
  esac
  preflight
  # No answers file and no --wizard: the guided install is the default.
  if [ -n "$CONFIG" ] || [ "$GUIDED" = -1 ]; then GUIDED=0; else GUIDED=1; fi
  if [ "$GUIDED" = 1 ]; then
    ui_init; ui_box_init; ui_traps; ui_tty_init
    if [ "${AINKRAD_FROM_GET:-}" = 1 ]; then UI_STATE="The Core programs are in /usr/local/bin; nothing else is set up yet."; fi
    guided_banner; guided_answers; apply_harden_req
    check_answers || die "an answer is not valid (see the line just above this card); fix it and run again"
  elif [ -n "$CONFIG" ]; then
    parse_answers "$CONFIG" || die "fix the answers file above"
    [ -z "$CLI_BINARY" ] || A_BINARY_DIR=$CLI_BINARY
    local missing; missing=$(missing_keys)
    [ -z "$missing" ] || die "missing in $CONFIG: $(echo "$missing" | tr '\n' ',' | sed 's/,$//; s/,/, /g')"
    apply_harden_req; check_answers || die "fix the answers above"
  else
    [ -z "$CLI_BINARY" ] || A_BINARY_DIR=$CLI_BINARY
    wizard; apply_harden_req; check_answers || die "invalid answers"
  fi
  A_HOSTNAME=$(lower "$A_HOSTNAME")
  if [ "$NO_LOCAL_RUNNER" = 1 ]; then A_RUNNER=no A_RUNNER_PTY=no A_RUNNER_PAIR_CODE=''; fi
  if [ "$GUIDED" = 1 ]; then guided_backup_key; else review; fi
  [ -n "$CONFIG" ] || [ "$DRY" = 1 ] || [ "$GUIDED" = 1 ] || yes_no "Install with these answers?" || die "aborted, nothing changed"
  [ "$DRY" = 0 ] || say "(dry run: the commands below are printed, not run)"
  UI_STATE="The Core programs are in /usr/local/bin; nothing else is set up yet."
  checks
  stage_binaries
  harden
  [ "$GUIDED$DRY" != 10 ] || [ "${AINKRAD_FROM_GET:-}" != 1 ] || save_installer
  UI_STATE="Setting up: the service account, the Core's home or its unit may exist. Running the installer again is safe; $(removal_hint)"
  install_core
  install_citadel
  install_backup
  start_core
  real_credentials
  extras
  [ "$DRY" = 1 ] || selftest "$A_SELFTEST_BACKUP" || warn "self-test failed: see above"
  if [ "$GUIDED" = 1 ]; then
    local rc=0
    step "First device"
    ui_live_end
    guided_invite || rc=$?
    guided_summary "$rc"
    [ "$rc" != 0 ] || [ -z "$INVITE" ] || guided_show_invite
    guided_next_steps "$rc"
    [ "$rc" != 2 ] || rc=0 # no terminal: deliberately no invite, the command to run is printed; the install itself succeeded
    return "$rc"
  fi
  bootstrap
  summary
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
