# shellcheck shell=bash
# scripts/install.sh --demo (the flag only; an environment variable does nothing): the whole screen flow with fake delays and NO change to this machine,
# for tests and for showing the installer. AINKRAD_DEMO_SPEED scales the delays (default 1 = about 40 s; 0.05 for tests);
# AINKRAD_DEMO_CLOCK runs the on-screen clock faster during the certificate wait so the 60 s / 120 s certificate hints appear (default 12).
# shellcheck disable=SC2034

demo_nap() { ui_sleep "$(awk -v s="$1" -v k="${AINKRAD_DEMO_SPEED:-1}" 'BEGIN { printf "%.2f", s * k }')"; }
demo_job() { ui_run "$1" demo_nap "$2"; }
demo_apt() { local p; for p in ca-certificates curl minisign bubblewrap qrencode; do echo "Setting up $p ..."; demo_nap 0.7; done; }
demo_download() { local i; for i in 1 2 3 4 5 6; do head -c 600000 /dev/zero >>"$UI_DL"; demo_nap 0.4; done; }
demo_typed() { # KEY LABEL ANSWER: the card, then the "typed" answer
  UI_Q_N=$((UI_Q_N + 1))
  ui_card "$UI_Q_N" 2 "$2" "$(ui_example "$1")" none
  demo_nap 1; printf ' > %s: %s\n' "$1" "$3"; ui_ok "$1 = $3"
}
demo_main() {
  GUIDED=1 DRY=1 A_HARDEN=no A_HOSTNAME=core.example.com A_ACME_ENV=production A_BACKUP_RECIPIENT=demo
  ui_init; ui_box_init; ui_traps
  UI_DEMO=1 # after ui_init: never taken from the environment
  UI_BASE=0 UI_TOTAL=8
  DEMO_BASE=$(date +%s) DEMO_REAL0=$DEMO_BASE DEMO_K=1
  ui_now() { echo $((DEMO_BASE + ($(date +%s) - DEMO_REAL0) * DEMO_K)); }
  UI_T0=$(ui_now); UI_RERUN='sudo scripts/install.sh --demo'
  ui_note "DEMO: nothing is installed or changed on this machine; the delays and results are made up."
  ui_roadmap
  ui_step 1 "$(ui_rname 1)" "Needs Linux with systemd, root, and Debian or Ubuntu (apt)."
  demo_job "Looking at this machine" 1
  ui_ok "This is Linux x86_64 with systemd and apt, and you are root: supported"
  ui_step 2 "$(ui_rname 2)" "curl, minisign (checks the release signature), bubblewrap (agent sandbox), qrencode (QR code)."
  ui_run "Installing the prerequisite packages with apt (nothing is ever removed)" demo_apt
  ui_step 3 "$(ui_rname 3)" "The signature over SHA256SUMS must match the pinned key; every file must match the signed sums."
  ui_logopen; UI_DL=$UI_LOGDIR/ainkrad-core-server-0.0.0-linux-x86_64 UI_TEXTFN=ui_dl_text; ui_run "Downloading ainkrad-core-server-0.0.0-linux-x86_64" demo_download
  demo_job "Checking the release signature against the pinned key" 1
  ui_ok "The signature is valid (ainkrad-core 0.0.0)"
  ui_ok "All 5 downloaded files match the signed checksums"
  ui_step 4 "$(ui_rname 4)" "The four programs go to /usr/local/bin as one set (all or none)."
  demo_job "Installing the four programs to /usr/local/bin" 1.5
  ui_step 5 "$(ui_rname 5)" "Only the public DNS name and an email are needed; everything else has a sensible default."
  UI_Q_N=0
  ui_note "The Core is served over HTTPS with a free Let's Encrypt certificate, so it needs a public DNS name that points at this machine."
  demo_typed HOSTNAME "Public DNS name of this Core" "$A_HOSTNAME"
  demo_job "Looking up this machine's public address (a request to api.ipify.org)" 1
  demo_job "Checking that $A_HOSTNAME points at 203.0.113.7" 1
  ui_ok "$A_HOSTNAME points at 203.0.113.7: this machine. Good."
  demo_typed ACME_CONTACT "Email for the Let's Encrypt account (expiry notices only)" "you@example.com"
  ui_note "Certificate: production Let's Encrypt (trusted by browsers). AINKRAD_ACME_ENV=staging asks for a test certificate instead."
  ui_step 6 "$(ui_rname 6)" "Creates the service account, the Core's keys and database, its systemd service and daily backups."
  ui_note "> Checking DNS and the ports"; demo_job "Checking that ports 80 and 443 are free" 1
  ui_note "> Host hardening: skipped (opt-in). SSH config and firewall are untouched"
  ui_note "> Creating the service account, the Core's home with its keys and database"; demo_job "Creating the service account, the Core's home (keys, database) and its service" 2
  ui_note "> Setting up daily encrypted backups on this machine"; demo_job "Installing the backup timer" 1
  ui_step 7 "$(ui_rname 7)" "Starts the Core, waits for its first HTTPS certificate and checks that it works."
  demo_job "Starting ainkrad-core.service" 1
  # the certificate wait runs on a faster on-screen clock so the 60 s and 120 s hints can be seen in a short demo
  local pre; pre=$(ui_now); DEMO_BASE=$pre DEMO_REAL0=$(date +%s) DEMO_K=${AINKRAD_DEMO_CLOCK:-12}
  ui_note "Usually 20-60 s; it needs port 443 reachable and the DNS record pointing here."
  UI_HINT=0; ( demo_nap 12 ) & local pid=$!
  ui_wait "$pid" "Requesting the certificate" "" ui_cert_text; wait "$pid" || true
  DEMO_BASE=$((pre + $(date +%s) - DEMO_REAL0)) DEMO_REAL0=$(date +%s) DEMO_K=1
  ui_ok "The certificate was issued and the Core answers over HTTPS"
  demo_job "Turning on the encrypted secrets store" 1
  ui_note "> Installing the runner (unprivileged user; terminals on, exec.run off; not started until paired)"; demo_job "Installing the runner" 1
  ui_step 8 "$(ui_rname 8)" "A one-time link and code that make the Mac app the owner of this Core."
  demo_job "Asking the Core for your one-time connect link" 1
  INVITE='ainkrad://connect?host=core.example.com&fp=DEMO-FINGERPRINT&secret=DEMO-NOT-A-REAL-SECRET'
  if tty_ok; then guided_show_invite; else ui_note "(demo: the link card is shown on a terminal only, never on stdout)"; fi
  guided_summary 0
  guided_next_steps 0
  ui_note "DEMO finished: nothing was installed or changed, and this run exits 3 so it can never pass for an install."
}
