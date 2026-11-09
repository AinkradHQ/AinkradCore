#!/usr/bin/env bash
# E2-15.1: the Mac runner package, notarisation-READY. scripts/release/mac-package.sh <version> [options]
#   --bin-dir DIR   ainkrad-runner and ainkrad-ptyhost to package (default: build them, `dist` profile, here)
#   --out DIR       where the package goes (default: dist/mac-runner)
#   --sign          Developer ID + hardened runtime + Apple timestamp. Needs the env vars below.
#   --notarize      submit the zip to Apple and wait. Needs --sign, NOTARY_PROFILE and the approval variable.
# Without --sign the binaries are signed ad hoc ("-"): a package for a dry run, named ...-adhoc, that Gatekeeper
# will refuse. Nothing is submitted, tagged or published by this script unless --notarize is given.
# The signing identity and the team are NEVER in the repo, only in the environment of whoever releases:
#   MACOS_SIGN_ID           the full identity name, "Developer ID Application: <name> (<TEAM ID>)"
#   MACOS_TEAM_ID           its Apple team id; must match the identity and the signed binaries
#   NOTARY_PROFILE          a `xcrun notarytool store-credentials` keychain profile (credentials stay in the keychain)
#   AINKRAD_RELEASE_APPROVED=yes   set it only when the owner has approved this release (notarisation is gated)
# The package (ainkrad-runner-<version>-macos-<arch>[-adhoc].zip, made with ditto):
#   <name>/bin/{ainkrad-runner,ainkrad-ptyhost}  <name>/install.sh  <name>/io.ainkrad.runner.plist  <name>/SHA256SUMS
# The user unzips it, runs ./install.sh install [--pty], then ./install.sh pair <core url> --code <CODE>.
# A bare Mach-O cannot be stapled: Gatekeeper looks the notarisation ticket up online on first run.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
die() { echo "mac-package: $*" >&2; exit 1; }

ver=${1:-}; [ -n "$ver" ] || { sed -n '2,3p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
shift
bindir='' out=$ROOT/dist/mac-runner sign=0 notarize=0
while [ $# -gt 0 ]; do
  case $1 in
    --bin-dir) bindir=${2:?}; shift 2 ;;
    --out) out=${2:?}; shift 2 ;;
    --sign) sign=1; shift ;;
    --notarize) notarize=1; shift ;;
    *) die "unknown option $1" ;;
  esac
done
case $ver in *[!0-9A-Za-z.+-]* | '') die "bad version '$ver'" ;; esac
[ "$(uname -s)" = Darwin ] || die "this packages on a Mac (codesign, ditto)"

id=- ts=--timestamp=none suffix=-adhoc
if [ "$sign" = 1 ]; then
  : "${MACOS_SIGN_ID:?MACOS_SIGN_ID is not set (the Developer ID identity name)}"
  : "${MACOS_TEAM_ID:?MACOS_TEAM_ID is not set}"
  case $MACOS_SIGN_ID in *"($MACOS_TEAM_ID)") ;; *) die "MACOS_SIGN_ID does not end in ($MACOS_TEAM_ID): wrong identity or team" ;; esac
  security find-identity -v -p codesigning | grep -qF "$MACOS_SIGN_ID" || die "that identity is not in the keychain"
  id=$MACOS_SIGN_ID ts=--timestamp suffix=''
fi
if [ "$notarize" = 1 ]; then
  [ "$sign" = 1 ] || die "--notarize needs --sign"
  : "${NOTARY_PROFILE:?NOTARY_PROFILE is not set (a notarytool keychain profile)}"
  [ "${AINKRAD_RELEASE_APPROVED:-}" = yes ] || die "notarisation is gated: set AINKRAD_RELEASE_APPROVED=yes once the release is approved"
fi

if [ -z "$bindir" ]; then
  (cd "$ROOT" && cargo build --profile dist --locked -p ainkrad-runner -p ainkrad-ptyhost)
  bindir=$ROOT/target/dist
fi
for b in ainkrad-runner ainkrad-ptyhost; do [ -f "$bindir/$b" ] || die "no $b in $bindir"; done

arch=$(uname -m)
name=ainkrad-runner-$ver-macos-$arch$suffix
stage=$out/$name
rm -rf "$stage" "$out/$name.zip"
mkdir -p "$stage/bin"
for b in ainkrad-runner ainkrad-ptyhost; do install -m 0755 "$bindir/$b" "$stage/bin/$b"; done
install -m 0755 "$ROOT/deploy/launchd/install.sh" "$stage/install.sh"
install -m 0644 "$ROOT/deploy/launchd/io.ainkrad.runner.plist" "$stage/io.ainkrad.runner.plist"

# Sign, then check each binary: the signature, no non-system library, and that it still starts (a signature can verify
# and dyld still refuse the binary; only running it shows that).
for b in ainkrad-runner ainkrad-ptyhost; do
  f=$stage/bin/$b
  codesign --force --options runtime "$ts" -s "$id" -i "io.ainkrad.$b" "$f"
  codesign --verify --strict --verbose=2 "$f"
  if [ "$sign" = 1 ]; then
    codesign -dv "$f" 2>&1 | grep -qx "TeamIdentifier=$MACOS_TEAM_ID" || die "$b is not signed by team $MACOS_TEAM_ID"
  fi
  if otool -L "$f" | tail -n +2 | awk '{print $1}' | grep -vE '^(/usr/lib/|/System/Library/)'; then die "$b links a non-system library (above)"; fi
  code=0; "$f" --help >/dev/null 2>&1 || code=$?
  [ "$code" -lt 128 ] || die "the signed $b does not start (exit $code)"
done
sums=$(cd "$stage" && find . -type f | LC_ALL=C sort | xargs shasum -a 256)
printf '%s\n' "$sums" >"$stage/SHA256SUMS"
ditto -c -k --keepParent "$stage" "$out/$name.zip"
echo "packaged $out/$name.zip ($([ "$sign" = 1 ] && echo "signed, team $MACOS_TEAM_ID" || echo 'AD HOC: not for distribution'))"

if [ "$notarize" = 1 ]; then
  xcrun notarytool submit "$out/$name.zip" --keychain-profile "$NOTARY_PROFILE" --wait
  echo "notarised. Inspect with: xcrun notarytool log <submission-id> --keychain-profile \$NOTARY_PROFILE"
else
  cat <<NOTE
NOT RUN: notarisation. After the release is approved:
  MACOS_SIGN_ID=... MACOS_TEAM_ID=... NOTARY_PROFILE=... AINKRAD_RELEASE_APPROVED=yes \\
    scripts/release/mac-package.sh $ver --bin-dir $bindir --sign --notarize
NOTE
fi
