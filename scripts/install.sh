#!/usr/bin/env bash
# Guided installer for the Ainkrad Core on a Linux + systemd host (E1-16.x). Nothing about your environment lives
# in the repo: the wizard asks for it (or reads an answers file) and writes /etc/ainkrad/core.env (settings) and
# /etc/ainkrad/backup.env (bucket credentials, root:ainkrad 0640). Idempotent: re-run it to change an answer.
#   sudo scripts/install.sh                      interactive wizard
#   sudo scripts/install.sh --config <answers>   unattended (see deploy/install.answers.example)
#   scripts/install.sh --config <answers> --dry-run   print every action, change nothing (no root needed)
#   sudo scripts/install.sh --check [--backup local|bucket]   self-test an existing install
#   sudo scripts/install.sh --uninstall [--purge]   stop, disable, remove units and binaries; --purge also deletes
#        the Core's data after you type its host name. Never touches backup.env or the bucket.
# Options: --binary <dir> (ainkrad-core-server [, ainkradctl, ainkrad-runner, ainkrad-ptyhost]) overrides BINARY_DIR.
# A runner on this host (RUNNER=yes) is installed with its own hardened unit; RUNNER_PTY=yes offers terminals (a
# shell as the unprivileged runner user, inside the unit's sandbox), RUNNER_PAIR_CODE pairs and starts it.
# A runner on another Linux host: deploy/install-linux.sh. On a Mac: deploy/launchd/install.sh (or the package).
# SC2015: `test && pass || fail` is meant (pass never fails).
# shellcheck disable=SC2015
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=scripts/install/lib.sh
. "$ROOT/scripts/install/lib.sh"

CORE_HOME=/var/lib/ainkrad/core ETC=/etc/ainkrad BIN=/usr/local/bin UNITS=/etc/systemd/system
STAGING_DIR=https://acme-staging-v02.api.letsencrypt.org/directory
MODE=install CONFIG='' DRY=0 PURGE=0 CHECK_BACKUP=no CLI_BINARY='' STAGE=''

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }
warn() { printf 'install: WARNING: %s\n' "$*" >&2; }
run() { printf '+ %s\n' "$*"; [ "$DRY" = 1 ] || "$@"; }
# write_file PATH MODE OWNER:GROUP CONTENT [SHOWN]: atomically, via a temp file beside it; SHOWN replaces
# CONTENT in the dry-run listing (secrets masked). printf is a builtin: CONTENT never reaches an argv.
write_file() {
  local path=$1 mode=$2 owner=$3 content=$4 shown=${5:-$4} tmp
  printf '+ write %s (%s %s)\n' "$path" "$owner" "$mode"
  if [ "$DRY" = 1 ]; then printf '%s\n' "$shown" | sed 's/^/    /'; return; fi
  tmp=$(mktemp "$(dirname "$path")/.$(basename "$path").XXXXXX")
  printf '%s\n' "$content" >"$tmp"
  chown "$owner" "$tmp" && chmod "$mode" "$tmp" && mv -f "$tmp" "$path"
}
env_get() { [ -r "$ETC/core.env" ] && sed -n "s/^$1=//p" "$ETC/core.env" | tail -n1 || true; }
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
yes_no() { local a; read -r -p "$1 [y/N] " a </dev/tty; case $a in y | Y | yes) true ;; *) false ;; esac; }

# ask KEY "one-line explanation" [secret]: loops until the validator accepts; keeps A_KEY (or the default).
ask() {
  local key=$1 why=$2 secret=${3:-} cur def v rc
  eval "cur=\${A_$key:-}"; def=${cur:-$(default_of "$key")}
  printf '\n%s\n' "$why"
  while :; do
    if [ -n "$secret" ]; then
      read -r -s -p "$key${cur:+ [keep current]}: " v </dev/tty; echo
    else read -r -p "$key${def:+ [$def]}: " v </dev/tty; fi
    v=${v:-$def}
    case $key in BINARY_DIR) [ "$v" = build ] && { A_BUILD=yes; return; } ;; esac
    if [ -z "$v" ]; then case $key in PUBLIC_IP | ALLOW_ORIGINS | SSH_FROM | BACKUP_PREFIX | RUNNER_PAIR_CODE) printf -v "A_$key" ''; return ;; esac; fi
    rc=0; "$(validator_of "$key")" "$v" || rc=$?
    [ "$rc" = 0 ] && { printf -v "A_$key" '%s' "$v"; return; }
    if [ "$rc" = 2 ] && [ "$key" = BACKUP_RECIPIENT ]; then
      say "  That is an age SECRET key (AGE-SECRET-KEY-...). It must never be on this host: paste the public"
      say "  key (age1...) printed next to it. If the secret was exposed here, make a new identity."
    else say "  Not valid, try again."; fi
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

checks() { # DNS -> this host's public IP; :443 (and :80) free
  step "Checks"
  local problems=0 addrs pub p who
  if ! command -v getent >/dev/null; then warn "no getent here: DNS not checked"; return 0; fi
  addrs=$(getent ahosts "$A_HOSTNAME" | awk '{print $1}' | sort -u | tr '\n' ' ')
  pub=${A_PUBLIC_IP:-$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsS4 --max-time 5 https://checkip.amazonaws.com 2>/dev/null || true)}
  pub=$(printf '%s' "$pub" | tr -d '[:space:]')
  say "  DNS $A_HOSTNAME -> ${addrs:-nothing}; this host's public IPv4: ${pub:-unknown}"
  if [ -z "$addrs" ]; then warn "$A_HOSTNAME does not resolve: add an A record for this host"; problems=1
  elif [ -n "$pub" ] && ! printf ' %s ' "$addrs" | grep -q " $pub "; then
    warn "$A_HOSTNAME does not point at $pub: ACME will fail until it does"; problems=1
  fi
  for a in $addrs; do
    case $a in *:*) ip -6 addr 2>/dev/null | grep -q " $a/" || { warn "AAAA $a is not on this host: remove it or ACME may validate the wrong machine"; problems=1; } ;; esac
  done
  for p in 443 $([ "$A_ACME_CHALLENGE" = http-01 ] && echo 80); do
    who=$(ss -Hltnp "sport = :$p" 2>/dev/null || true)
    if [ -n "$who" ] && ! printf '%s' "$who" | grep -q ainkrad-core; then
      warn ":$p is in use: $(printf '%s' "$who" | head -n1)"; problems=1
    else say "  :$p free (or already the Core's)"; fi
  done
  say "  Reachability of :443/:80 from the internet cannot be tested from here: ACME issuance below proves it."
  [ "$problems" = 0 ] && return 0
  [ "$DRY" = 1 ] && { warn "checks failed (dry run continues)"; return 0; }
  [ -z "$CONFIG" ] && yes_no "Continue anyway?" && return 0
  die "checks failed"
}

stage_binaries() {
  step "Binaries"
  local src n citadel_src=''
  if [ "${A_BUILD:-no}" = yes ]; then
    command -v cargo >/dev/null || die "BUILD=yes needs cargo on this host"
    run nice -n 19 cargo build --release --manifest-path "$ROOT/Cargo.toml" -p ainkrad-core-server -p ainkrad-ctl -p ainkrad-runner -p ainkrad-ptyhost
    src=$ROOT/target/release
    if [ "$A_ENABLE_CITADEL" = yes ]; then # the composed binary is its own cargo workspace
      run nice -n 19 cargo build --release --manifest-path "$ROOT/modules/citadel/Cargo.toml" -p ainkrad-core-citadel
      citadel_src=$ROOT/modules/citadel/target/release
    fi
  else src=$A_BINARY_DIR; fi
  STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
  for n in ainkrad-core-server ainkradctl ainkrad-runner ainkrad-ptyhost; do
    if [ -f "$src/$n" ]; then cp "$src/$n" "$STAGE/$n"; chmod 0755 "$STAGE/$n"; say "  $n sha256 $(sha "$STAGE/$n")"
    elif [ "$n" = ainkrad-core-server ] && [ "$DRY" = 0 ]; then die "no $n in $src"
    else say "  $n: not in $src${n:+ (skipped)}"; fi
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

harden() {
  [ "$A_HARDEN" = yes ] || return 0
  step "Host hardening (scripts/host/harden.sh)"
  grep -E '^# [0-9]\.' "$ROOT/scripts/host/harden.sh" | sed 's/^# /  /'
  if [ -n "$A_SSH_FROM" ]; then
    local peers p
    peers=$(ss -Htn state established '( sport = :22 )' 2>/dev/null | awk '{print $4}' | sed -E 's/^\[?(.*)\]?:[0-9]+$/\1/; s/^::ffff://; s/\]$//' | sort -u || true)
    [ -n "$peers$DRY" ] || die "SSH_FROM: cannot see your SSH session's address; refusing to restrict SSH blind"
    for p in $peers; do ip_in_cidrs "$p" "$A_SSH_FROM" || die "SSH_FROM $A_SSH_FROM would lock out the open SSH session from $p"; done
    say "  SSH will be admitted only from $A_SSH_FROM (current sessions: ${peers:-none seen}). Your cloud firewall may need the same."
  fi
  [ -n "$CONFIG" ] || [ "$DRY" = 1 ] || yes_no "Apply it now?" || { say "  skipped"; return 0; }
  run env AINKRAD_SSH_FROM="$A_SSH_FROM" bash "$ROOT/scripts/host/harden.sh"
}

install_core() {
  step "Core: user, binary, unit, home"
  local out prev_env tls=$CORE_HOME/tls dry=()
  [ "$DRY" = 1 ] && dry=(--dry-run)
  out=$(bash "$ROOT/deploy/install-core-linux.sh" --binary "$STAGE/ainkrad-core-server" ${dry[@]+"${dry[@]}"} | tee /dev/stderr)
  # The signer's fingerprint, base64url(SHA-256(SPKI)) as `init` prints it, from the key itself (so a re-run has it).
  SIGNER=''
  [ "$DRY" = 1 ] || SIGNER=$(openssl pkey -inform DER -in "$CORE_HOME/keys/backup-signing.p8" -pubout -outform DER |
    openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
  printf '%s\n' "$out" | grep -qxF "$SIGNER" || [ "$DRY" = 1 ] || say "  (home kept; signer fingerprint derived from its key)"
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
    local) say "  no bucket: encrypted snapshots stay in $CORE_HOME/backups only" ;;
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
  run systemctl enable ainkrad-core.service ainkrad-backup.timer
  run systemctl restart ainkrad-core.service
  run systemctl restart ainkrad-backup.timer
  [ "$DRY" = 1 ] && return 0
  say "  waiting for https://$A_HOSTNAME/healthz (the first certificate can take a minute)..."
  local end=$((SECONDS + 240))
  until health >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$end" ] || { journalctl -u ainkrad-core -n 20 --no-pager >&2; die "the Core did not become healthy"; }
    sleep 3
  done
  say "  healthy"
}

health() { # healthz on this host, by name (no hairpin NAT); a staging certificate is not verifiable
  local k=(); [ "$A_ACME_ENV" = staging ] && k=(-k)
  curl -fsS --max-time 5 ${k[@]+"${k[@]}"} --resolve "$A_HOSTNAME:443:127.0.0.1" "https://$A_HOSTNAME/healthz"
}

extras() {
  if [ -f "$STAGE/ainkradctl" ]; then step "ainkradctl"; run install -m 0755 "$STAGE/ainkradctl" "$BIN/ainkradctl"; fi
  [ "$A_RUNNER" = yes ] || return 0
  step "Runner on this host (terminals $([ "$A_RUNNER_PTY" = yes ] && echo ON || echo off); exec.run OFF)"
  [ -f "$STAGE/ainkrad-runner" ] || { warn "no ainkrad-runner binary: runner skipped"; return 0; }
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
    else a+=(--pair "https://$A_HOSTNAME" --code "$code"); fi
  fi
  bash "$ROOT/deploy/install-linux.sh" "${a[@]}" || { warn "runner install/pairing did not complete; pair it by hand (below)"; code=''; }
  [ -n "$code" ] || say "  Pair it once your first device is paired: on that device \`ainkradctl device add $(hostname -s 2>/dev/null || echo runner) --kind runner\`, then here:
    sudo $ROOT/deploy/install-linux.sh --binary $BIN/ainkrad-runner$([ "$A_RUNNER_PTY" = yes ] && echo ' --pty') --pair https://$A_HOSTNAME --code <CODE>
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

selftest() { # PASS/FAIL lines; returns 1 on any FAIL
  step "Self-test"
  local fail=0 out cert
  t() { printf '  %-5s %s\n' "$1" "$2"; [ "$1" = PASS ] || fail=1; }
  [ "$(systemctl is-active ainkrad-core 2>/dev/null)" = active ] && t PASS "ainkrad-core.service active" || t FAIL "ainkrad-core.service not active"
  out=$(health 2>&1) && t PASS "healthz over TLS: $(printf '%s' "$out" | head -c 160)" || t FAIL "healthz: $out"
  cert=$(openssl s_client -connect 127.0.0.1:443 -servername "$A_HOSTNAME" </dev/null 2>/dev/null | openssl x509 -noout -issuer -enddate 2>/dev/null | tr '\n' ' ')
  [ -n "$cert" ] && [ -s "$CORE_HOME/tls/cert.pem" ] && t PASS "certificate in $CORE_HOME/tls: $cert" || t FAIL "no certificate served"
  case $cert in *STAGING*) say "        (staging: not trusted by browsers; switch with ACME_ENV=production)" ;; esac
  systemctl is-enabled ainkrad-backup.timer >/dev/null 2>&1 && t PASS "backup timer: $(systemctl show -p NextElapseUSecRealtime --value ainkrad-backup.timer)" || t FAIL "ainkrad-backup.timer not enabled"
  runner_selftest
  citadel_selftest
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
  for u in ainkrad-backup.timer ainkrad-backup.service ainkrad-runner.service ainkrad-core.service; do
    run systemctl disable --now "$u" 2>/dev/null || true
  done
  # KillMode=process: stopping the runner leaves its terminal hosts running on purpose; removing it ends them.
  run systemctl kill --kill-whom=all ainkrad-runner.service 2>/dev/null || true
  run rm -rf "$UNITS/ainkrad-core.service" "$UNITS/ainkrad-runner.service" "$UNITS/ainkrad-backup.service" \
    "$UNITS/ainkrad-backup.timer" "$UNITS/ainkrad-backup.timer.d" "$UNITS/ainkrad-backup.service.d" "$UNITS/ainkrad-core.service.d"
  run systemctl daemon-reload
  run systemctl reset-failed 2>/dev/null || true
  run rm -f "$BIN/ainkrad-core-server" "$BIN/ainkradctl" "$BIN/ainkrad-runner" "$BIN/ainkrad-ptyhost" "$BIN/ainkrad-core-citadel"
  if [ "$PURGE" = 1 ]; then
    name=$(env_get AINKRAD_HOSTNAME); name=${name:-purge}
    say "  --purge deletes $CORE_HOME (database, keys, certificates), the runner's state and $ETC/core.env. Type '$name' to confirm:"
    local typed=${AINKRAD_PURGE_CONFIRM:-}
    [ -n "$typed" ] || { [ -t 0 ] && read -r typed </dev/tty; } || true
    if [ "$typed" = "$name" ]; then
      run rm -rf "$CORE_HOME" /var/lib/ainkrad-runner /var/lib/ainkrad-runner-work /etc/ainkrad-runner "$ETC/core.env"
    else say "  not confirmed: data kept"; fi
  fi
  say "  Kept: $ETC/backup.env (the bucket key: remove it yourself when retiring the host), the bucket and every
  object in it, the ainkrad / ainkrad-runner users, the firewall.$([ "$PURGE" = 1 ] || echo " Data kept in $CORE_HOME (--purge removes it).")"
  [ "$DRY" = 1 ] || { say "  TCP listeners now:"; ss -Hltn | awk '{print "    " $4}'; }
}

main() {
  while [ $# -gt 0 ]; do
    case $1 in
      --config) CONFIG=${2:?}; shift 2 ;;
      --binary) CLI_BINARY=${2:?}; shift 2 ;;
      --dry-run) DRY=1; shift ;;
      --uninstall) MODE=uninstall; shift ;;
      --purge) PURGE=1; shift ;;
      --check) MODE=check; shift ;;
      --backup) CHECK_BACKUP=${2:?}; valid_selftest "$CHECK_BACKUP" || die "--backup local|bucket"; shift 2 ;;
      -h | --help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
      *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
    esac
  done
  case $MODE in
    uninstall) uninstall; return ;;
    check)
      [ "$(id -u)" = 0 ] || die "run as root"
      A_HOSTNAME=$(env_get AINKRAD_HOSTNAME) A_ACME_ENV=$(env_get AINKRAD_ACME_ENV)
      [ -n "$A_HOSTNAME" ] || die "no install found ($ETC/core.env)"
      selftest "$CHECK_BACKUP"; return ;;
  esac
  preflight
  if [ -n "$CONFIG" ]; then
    parse_answers "$CONFIG" || die "fix the answers file above"
    [ -z "$CLI_BINARY" ] || A_BINARY_DIR=$CLI_BINARY
    local missing; missing=$(missing_keys)
    [ -z "$missing" ] || die "missing in $CONFIG: $(echo "$missing" | tr '\n' ',' | sed 's/,$//; s/,/, /g')"
    check_answers || die "fix the answers above"
  else
    [ -z "$CLI_BINARY" ] || A_BINARY_DIR=$CLI_BINARY
    wizard; check_answers || die "invalid answers"
  fi
  A_HOSTNAME=$(lower "$A_HOSTNAME")
  review
  [ -n "$CONFIG" ] || [ "$DRY" = 1 ] || yes_no "Install with these answers?" || die "aborted, nothing changed"
  [ "$DRY" = 0 ] || say "(dry run: the commands below are printed, not run)"
  checks
  stage_binaries
  harden
  install_core
  install_citadel
  install_backup
  start_core
  extras
  [ "$DRY" = 1 ] || selftest "$A_SELFTEST_BACKUP" || warn "self-test failed: see above"
  bootstrap
  summary
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
