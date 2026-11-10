#!/bin/sh
# Ainkrad Core: one command to set up a Core on a Linux machine (Debian or Ubuntu, x86_64 or arm64).
#
#   curl -fsSL https://github.com/AinkradHQ/AinkradCore/releases/latest/download/get.sh | sudo sh
#
# Optional, to skip the two questions (the Mac app can put them in the command):
#   ... | sudo AINKRAD_HOSTNAME=core.example.com AINKRAD_ACME_EMAIL=you@example.com sh
#
# What it does, in order: checks the machine, installs what the Core needs (curl, minisign, bubblewrap, a firewall,
# qrencode) with apt, downloads the signed release, VERIFIES the minisign signature over SHA256SUMS against the
# release key pinned below (any mismatch stops everything; nothing of the release is installed), checks every file
# against the signed sums, installs the Core and runs the guided installer.
# The one-time connect link and the backup key are shown on the terminal only (/dev/tty), never on stdout, so a
# captured stdout (cloud-init, CI, `> log`, tee) does not keep them. With no terminal they are not created at all
# and the command to run later is printed. They are not in a log or a file of ours; a terminal's own scrollback or
# recording still keeps what it displays (tmux, `script`, `ssh -t host ... > log`).
#
# Verify first, then run (get.sh is itself in the signed SHA256SUMS; the pinned key below is the same as
# scripts/release/ainkrad-release.pub, key id FB3618BCFCA5393E):
#   B=https://github.com/AinkradHQ/AinkradCore/releases/latest/download
#   curl -fsSLO $B/get.sh -O $B/SHA256SUMS -O $B/SHA256SUMS.minisig
#   minisign -Vm SHA256SUMS -P RWQ+OaX8vBg2+zmrma/A8QI/+cL5wvvHoanVJv0v4xHp04w6zIgS/pDA
#   grep ' get.sh$' SHA256SUMS | sha256sum -c -
#   sudo sh get.sh
#
# AINKRAD_RELEASE_URL=<https url or directory> reads another release (the pinned key still applies).
# AINKRAD_GET_VERIFY_ONLY=1 stops after the signature and checksum checks, installing nothing (used by the tests).
# Version floor: a signed release older than MIN_VERSION (the version this get.sh was built from) is refused, so a newer
# get.sh cannot be pointed at an older signed release. That does NOT stop a replay of an OLD get.sh together with its own
# old signed sums: the floor lives in the file being run. The command the Mac app shows therefore carries
#   ... | sudo AINKRAD_MIN_VERSION=<current version> sh
# and the HIGHER of the two floors applies. The verify-first path below has the same limit: check the version yourself.
#
# The whole script is one function called on the LAST line, so a download cut short runs nothing.

MIN_VERSION=0.0.0 # stamped by scripts/release/dry.sh with the release version this file ships in

main() {
  set -eu
  BASE=${AINKRAD_RELEASE_URL:-https://github.com/AinkradHQ/AinkradCore/releases/latest/download}
  # The pinned release key (same as scripts/release/ainkrad-release.pub). Compare the key id with the project's.
  KEY_ID=FB3618BCFCA5393E
  KEY_FILE='untrusted comment: minisign public key FB3618BCFCA5393E
RWQ+OaX8vBg2+zmrma/A8QI/+cL5wvvHoanVJv0v4xHp04w6zIgS/pDA'

  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then B=$(printf '\033[1m') D=$(printf '\033[2m') R=$(printf '\033[0m') RD=$(printf '\033[31m') GR=$(printf '\033[32m'); else B='' D='' R='' RD='' GR=''; fi
  n=0 NOTE="Nothing from the release was installed."
  say() { printf '%s\n' "$*"; }
  step() { n=$((n + 1)); printf '\n %s[%s/4] %s%s\n   %s%s%s\n' "$B" "$n" "$1" "$R" "$D" "$2" "$R"; }
  ok() { printf '   %s+%s %s\n' "$GR" "$R" "$*"; }
  die() { printf '\n %sStopped:%s %s\n %s\n' "$RD" "$R" "$*" "$NOTE" >&2; exit 1; }
  W=''
  trap '[ -z "$W" ] || rm -rf "$W"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  printf '\n%s Ainkrad Core%s\n %sOne command, one guided install.%s\n' "$B" "$R" "$D" "$R"

  case "$(uname -m)" in
    x86_64 | amd64) TARGET=linux-x86_64 ;;
    aarch64 | arm64) TARGET=linux-arm64 ;;
    *) die "no build for $(uname -m) (x86_64 and arm64 only)" ;;
  esac
  if [ "${AINKRAD_GET_VERIFY_ONLY:-}" != 1 ]; then
    step "Checking this machine" "Needs Linux with systemd, root, and Debian or Ubuntu (apt)."
    [ "$(uname -s)" = Linux ] || die "this is $(uname -s); Core installs on Linux only"
    [ "$(id -u)" = 0 ] || die "run it as root: ... | sudo sh"
    [ -d /run/systemd/system ] || die "systemd is not running here (a container without systemd?)"
    command -v apt-get >/dev/null || die "apt-get not found: only Debian and Ubuntu are supported by this installer"
    ok "Linux $(uname -m), $TARGET"

    step "Installing prerequisites" "curl, minisign (checks the release signature), bubblewrap (agent sandbox), iptables (firewall), qrencode (QR code)."
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
    # iptables-persistent keeps the firewall across reboots, but it clashes with ufw: with ufw present, ufw is used and
    # nothing is installed that could remove it. APT::Get::Remove=false makes apt refuse any removal instead of doing it.
    persist=iptables-persistent
    if dpkg -s ufw >/dev/null 2>&1; then persist=''; fi
    # shellcheck disable=SC2086 # $persist is empty or one package name
    apt_out=$(apt-get update -qq 2>&1 &&
      apt-get install -y -qq -o APT::Get::Remove=false --no-install-recommends ca-certificates curl minisign bubblewrap iptables $persist qrencode openssl iproute2 2>&1) ||
      { printf '%s\n' "$apt_out" >&2; die "could not install the prerequisites with apt-get (output above; apt never removes a package here)"; }
    command -v minisign >/dev/null || die "minisign is not available on this distribution; it is required to verify the release"
    ok "installed"
  fi

  W=$(mktemp -d)
  printf '%s\n' "$KEY_FILE" >"$W/release.pub"
  fetch() { # fetch NAME: from the release (https url or a directory) into $W
    case $BASE in
      https://*) curl -fsSL --proto '=https' --tlsv1.3 -o "$W/$1" "$BASE/$1" || die "cannot download $BASE/$1" ;;
      http://*) die "plain http is refused" ;;
      *) cp "$BASE/$1" "$W/$1" 2>/dev/null || die "no $1 in $BASE" ;;
    esac
  }
  sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

  step "Downloading and verifying the release" "The signature over SHA256SUMS must match the pinned key $KEY_ID; every file must match the signed sums."
  fetch SHA256SUMS
  fetch SHA256SUMS.minisig
  minisign -Vq -p "$W/release.pub" -x "$W/SHA256SUMS.minisig" -m "$W/SHA256SUMS" ||
    die "the signature does not verify against the pinned release key $KEY_ID. Do not run anything from this download."
  comment=$(sed -n 's/^trusted comment: //p' "$W/SHA256SUMS.minisig")
  ok "signature OK ($comment)"
  ver=${comment#ainkrad-core }
  case $ver in '' | "$comment" | *[!0-9.]*) die "the signed release has no version in its trusted comment ('$comment')" ;; esac
  case ${AINKRAD_MIN_VERSION:-0} in '' | *[!0-9.]*) die "AINKRAD_MIN_VERSION must look like 1.2.3" ;; esac
  floor=$(printf '%s\n%s\n' "$MIN_VERSION" "${AINKRAD_MIN_VERSION:-0}" | sort -V | tail -n1)
  if [ "$floor" = "$MIN_VERSION" ]; then ok "version floor $floor (from this get.sh's build)"; else ok "version floor $floor (from AINKRAD_MIN_VERSION)"; fi
  [ -n "${AINKRAD_MIN_VERSION:-}" ] || say "   (AINKRAD_MIN_VERSION is not set: the command shown by the Mac app is meant to carry it)"
  [ "$(printf '%s\n%s\n' "$floor" "$ver" | sort -V | head -n1)" = "$floor" ] ||
    die "the signed release is $ver, older than $floor (the build's floor or AINKRAD_MIN_VERSION): refused (no downgrade)"
  files=$(awk -v t="-$TARGET" 'substr($2, length($2) - length(t) + 1) == t || $2 ~ /^ainkrad-core-installer-.*\.tar\.gz$/ { print $2 }' "$W/SHA256SUMS")
  [ "$(echo "$files" | grep -c '^ainkrad-core-installer-')" = 1 ] || die "the signed release must have exactly one installer bundle"
  echo "$files" | grep -q "^ainkrad-core-server-.*-$TARGET\$" || die "the signed release has no Core build for $TARGET"
  for f in $files; do
    fetch "$f"
    want=$(awk -v f="$f" '$2 == f { print $1 }' "$W/SHA256SUMS")
    [ -n "$want" ] && [ "$(sha "$W/$f")" = "$want" ] || die "$f does not match its signed checksum"
  done
  ok "$(echo "$files" | wc -l | tr -d ' ') files match the signed checksums"
  if [ "${AINKRAD_GET_VERIFY_ONLY:-}" = 1 ]; then say "verify-only: release $ver verified, nothing installed"; return 0; fi
  tar -xzf "$W"/ainkrad-core-installer-*.tar.gz -C "$W" || die "the installer bundle is not a tar.gz"
  INST=$(echo "$W"/ainkrad-core-installer-*/)

  step "Installing the Core programs" "ainkrad-core-server, ainkrad-runner, ainkradctl and ainkrad-ptyhost go to /usr/local/bin as one set (all or none)."
  # release/install.sh verifies again, with the key pinned here (never the bundle's own copy), then installs atomically.
  bash "$INST/scripts/release/install.sh" --from "$W" --pubkey "$W/release.pub" --prefix /usr/local --target "$TARGET" >/dev/null ||
    die "installing the programs failed (the previous set, if any, was restored)"
  NOTE="The Core programs are in /usr/local/bin; the guided installer did not finish. Fix the cause and run the same command again."
  ok "installed in /usr/local/bin"

  say "
 Starting the guided installer..."
  # Only the child gets the terminal (stdin was the pipe: curl ... | sh); this shell keeps reading nothing from it.
  rc=0
  if ( : </dev/tty ) 2>/dev/null; then bash "$INST/scripts/install.sh" --binary /usr/local/bin </dev/tty || rc=$?
  else bash "$INST/scripts/install.sh" --binary /usr/local/bin </dev/null || rc=$?; fi
  exit "$rc" # not exec: the trap must still remove the download directory
}

{ main "$@"; }
