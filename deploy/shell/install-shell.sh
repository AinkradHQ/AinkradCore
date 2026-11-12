#!/usr/bin/env bash
# Installs the Ainkrad shell profile (N20): the read-only zsh configuration every runner terminal starts with
# (ZDOTDIR), pinned oh-my-zsh, powerlevel10k and plugins, the prompt of the owner's Mac. Linux; run as root.
#   install-shell.sh --dest /usr/local/share/ainkrad/shell [--from DIR] [--dry-run]
# --from DIR  read the pinned archives from DIR (named <commit>.tar.gz, gitstatusd-linux-<cpu>.tar.gz) instead of GitHub
#             (tests and offline installs); the SHA-256 checks are the same.
# The profile is built beside DEST and moved into place, so a failed run leaves the old one. Every download is checked
# against deploy/shell/pins.sh before anything is unpacked; a mismatch stops with nothing changed.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
dest='' from='' dry=0
while [ $# -gt 0 ]; do
  case $1 in
    --dest) dest=${2:?}; shift 2 ;;
    --from) from=${2:?}; shift 2 ;;
    --dry-run) dry=1; shift ;;
    *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
  esac
done
case $dest in /?*) ;; *) echo "install-shell: --dest is an absolute path" >&2; exit 2 ;; esac
# shellcheck source=deploy/shell/pins.sh
. "$HERE/pins.sh"
cpu=$(uname -m); case $cpu in arm64) cpu=aarch64 ;; amd64) cpu=x86_64 ;; esac
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

# The archives: NAME REPO COMMIT SHA256 TARGET (under the profile).
parts() {
  printf '%s\n' \
    "ohmyzsh $OMZ_REPO $OMZ_COMMIT $OMZ_SHA256 ohmyzsh" \
    "powerlevel10k $P10K_REPO $P10K_COMMIT $P10K_SHA256 custom/themes/powerlevel10k" \
    "zsh-autosuggestions $AUTOSUGGESTIONS_REPO $AUTOSUGGESTIONS_COMMIT $AUTOSUGGESTIONS_SHA256 custom/plugins/zsh-autosuggestions" \
    "zsh-syntax-highlighting $SYNTAX_HIGHLIGHTING_REPO $SYNTAX_HIGHLIGHTING_COMMIT $SYNTAX_HIGHLIGHTING_SHA256 custom/plugins/zsh-syntax-highlighting"
}
if [ "$dry" = 1 ]; then
  parts | while read -r name repo commit sum target; do
    echo "+ fetch https://github.com/$repo/archive/$commit.tar.gz, sha256 $sum, unpack to $dest/$target"
  done
  echo "+ fetch gitstatusd-linux-$cpu $GITSTATUSD_VERSION (powerlevel10k's git daemon), check its sha256, put it in $dest/custom/themes/powerlevel10k/gitstatus/usrbin"
  echo "+ install $HERE/zshrc as $dest/.zshrc and $HERE/p10k.zsh as $dest/.p10k.zsh, read-only, owned by root"
  exit 0
fi
[ "$(id -u)" = 0 ] || [ "${AINKRAD_SHELL_NOT_ROOT:-}" = 1 ] || { echo "install-shell: run as root" >&2; exit 1; }

mkdir -p "$(dirname "$dest")"
w=$(mktemp -d "$(dirname "$dest")/.ainkrad-shell.XXXXXX")
trap 'rm -rf "$w"' EXIT
fetch() { # fetch URL FILE SUM FROMNAME: the archive, checked
  if [ -n "$from" ]; then cp "$from/$4" "$2"; else curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; fi
  [ "$(sha "$2")" = "$3" ] || { echo "install-shell: $4 does not match its pinned SHA-256; nothing was installed" >&2; exit 1; }
}
parts | while read -r name repo commit sum target; do
  fetch "https://github.com/$repo/archive/$commit.tar.gz" "$w/$name.tgz" "$sum" "$commit.tar.gz"
  mkdir -p "$w/p/$target"
  tar -xzf "$w/$name.tgz" -C "$w/p/$target" --strip-components 1
done
gs=GITSTATUSD_SHA256_$cpu
if [ -n "${!gs:-}" ]; then
  fetch "https://github.com/romkatv/gitstatus/releases/download/$GITSTATUSD_VERSION/gitstatusd-linux-$cpu.tar.gz" "$w/gs.tgz" "${!gs}" "gitstatusd-linux-$cpu.tar.gz"
  mkdir -p "$w/p/custom/themes/powerlevel10k/gitstatus/usrbin"
  tar -xzf "$w/gs.tgz" -C "$w/p/custom/themes/powerlevel10k/gitstatus/usrbin"
else
  echo "install-shell: no pinned gitstatusd for $cpu: the prompt shows no git status" >&2
fi
install -m 0644 "$HERE/zshrc" "$w/p/.zshrc"
install -m 0644 "$HERE/p10k.zsh" "$w/p/.p10k.zsh"
chmod -R go-w,a+rX "$w/p"
if [ "$(id -u)" = 0 ]; then chown -R root:root "$w/p"; fi
rm -rf "$dest.old"; [ ! -e "$dest" ] || mv "$dest" "$dest.old"
mv "$w/p" "$dest"
rm -rf "$dest.old"
echo "the Ainkrad shell is in $dest (oh-my-zsh ${OMZ_COMMIT%"${OMZ_COMMIT#????????}"}, powerlevel10k ${P10K_COMMIT%"${P10K_COMMIT#????????}"})"
