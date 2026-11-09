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
# release key pinned below (any mismatch stops everything, nothing is installed), checks every file against the
# signed sums, installs the Core and runs the guided installer. The last thing it prints is the link and one-time
# code for the Mac app. That secret goes to the terminal only: no log, no file.
# AINKRAD_RELEASE_URL=<https url or directory> reads another release (the pinned key still applies).
set -eu

BASE=${AINKRAD_RELEASE_URL:-https://github.com/AinkradHQ/AinkradCore/releases/latest/download}
# The pinned release key (same as scripts/release/ainkrad-release.pub). Compare the key id with the project's.
KEY_ID=FB3618BCFCA5393E
KEY_FILE='untrusted comment: minisign public key FB3618BCFCA5393E
RWQ+OaX8vBg2+zmrma/A8QI/+cL5wvvHoanVJv0v4xHp04w6zIgS/pDA'

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then B=$(printf '\033[1m') D=$(printf '\033[2m') R=$(printf '\033[0m') RD=$(printf '\033[31m') GR=$(printf '\033[32m'); else B='' D='' R='' RD='' GR=''; fi
n=0
say() { printf '%s\n' "$*"; }
step() { n=$((n + 1)); printf '\n %s[%s/4] %s%s\n   %s%s%s\n' "$B" "$n" "$1" "$R" "$D" "$2" "$R"; }
ok() { printf '   %s+%s %s\n' "$GR" "$R" "$*"; }
die() { printf '\n %sStopped:%s %s\n Nothing was installed or changed beyond the packages named above.\n' "$RD" "$R" "$*" >&2; exit 1; }

printf '\n%s Ainkrad Core%s\n %sOne command, one guided install.%s\n' "$B" "$R" "$D" "$R"

step "Checking this machine" "Needs Linux with systemd, root, and Debian or Ubuntu (apt)."
[ "$(uname -s)" = Linux ] || die "this is $(uname -s); Core installs on Linux only"
[ "$(id -u)" = 0 ] || die "run it as root: ... | sudo sh"
[ -d /run/systemd/system ] || die "systemd is not running here (a container without systemd?)"
command -v apt-get >/dev/null || die "apt-get not found: only Debian and Ubuntu are supported by this installer"
case "$(uname -m)" in
  x86_64 | amd64) TARGET=linux-x86_64 ;;
  aarch64 | arm64) TARGET=linux-arm64 ;;
  *) die "no build for $(uname -m) (x86_64 and arm64 only)" ;;
esac
ok "Linux $(uname -m), $TARGET"

step "Installing prerequisites" "curl, minisign (checks the release signature), bubblewrap (agent sandbox), iptables (firewall), qrencode (QR code)."
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
apt_out=$(apt-get update -qq 2>&1 &&
  apt-get install -y -qq --no-install-recommends ca-certificates curl minisign bubblewrap iptables iptables-persistent qrencode openssl iproute2 2>&1) ||
  { printf '%s\n' "$apt_out" >&2; die "could not install the prerequisites with apt-get (output above)"; }
command -v minisign >/dev/null || die "minisign is not available on this distribution; it is required to verify the release"
ok "installed"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT INT TERM
printf '%s\n' "$KEY_FILE" >"$W/release.pub"
fetch() { # fetch NAME: from the release (https url or a directory) into $W
  case $BASE in
    https://*) curl -fsSL --proto '=https' --tlsv1.2 -o "$W/$1" "$BASE/$1" || die "cannot download $BASE/$1" ;;
    http://*) die "plain http is refused" ;;
    *) cp "$BASE/$1" "$W/$1" 2>/dev/null || die "no $1 in $BASE" ;;
  esac
}
sha() { sha256sum "$1" | cut -d' ' -f1; }

step "Downloading and verifying the release" "The signature over SHA256SUMS must match the pinned key $KEY_ID; every file must match the signed sums."
fetch SHA256SUMS
fetch SHA256SUMS.minisig
minisign -Vq -p "$W/release.pub" -x "$W/SHA256SUMS.minisig" -m "$W/SHA256SUMS" ||
  die "the signature does not verify against the pinned release key $KEY_ID. Do not run anything from this download."
ok "signature OK ($(sed -n 's/^trusted comment: //p' "$W/SHA256SUMS.minisig"))"
files=$(awk -v t="-$TARGET" 'substr($2, length($2) - length(t) + 1) == t || $2 ~ /^ainkrad-core-installer-.*\.tar\.gz$/ { print $2 }' "$W/SHA256SUMS")
echo "$files" | grep -q '^ainkrad-core-installer-' || die "the signed release has no installer bundle"
echo "$files" | grep -q "^ainkrad-core-server-.*-$TARGET\$" || die "the signed release has no Core build for $TARGET"
for f in $files; do
  fetch "$f"
  want=$(awk -v f="$f" '$2 == f { print $1 }' "$W/SHA256SUMS")
  [ "$(sha "$W/$f")" = "$want" ] || die "$f does not match its signed checksum"
done
ok "$(echo "$files" | wc -l | tr -d ' ') files match the signed checksums"
tar -xzf "$W"/ainkrad-core-installer-*.tar.gz -C "$W" || die "the installer bundle is not a tar.gz"
INST=$(echo "$W"/ainkrad-core-installer-*/)

step "Installing the Core programs" "ainkrad-core-server, ainkrad-runner, ainkradctl and ainkrad-ptyhost go to /usr/local/bin as one set (all or none)."
# release/install.sh verifies again, with the key pinned here (never the bundle's own copy), then installs atomically.
bash "$INST/scripts/release/install.sh" --from "$W" --pubkey "$W/release.pub" --prefix /usr/local --target "$TARGET" >/dev/null ||
  die "installing the programs failed"
ok "installed in /usr/local/bin"

say "
 Starting the guided installer..."
# Hand the terminal back to the user even though stdin was the pipe (curl ... | sh).
if [ -r /dev/tty ] && ( : </dev/tty ) 2>/dev/null; then exec </dev/tty; fi
rc=0
bash "$INST/scripts/install.sh" --binary /usr/local/bin || rc=$?
exit "$rc" # not exec: the trap must still remove the download directory
