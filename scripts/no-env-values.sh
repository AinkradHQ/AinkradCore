#!/usr/bin/env bash
# No environment-specific values in this public repo (E1-16.x): hosts, IPs, bucket namespaces and emails are
# supplied at install time (scripts/install.sh), never committed. Fails, listing file:line, on
#   - a public-looking IPv4 literal (allowed: loopback, 0.0.0.0, RFC 1918, RFC 5737 documentation ranges,
#     link-local, masks, and dotted version strings),
#   - an OCI object-storage or Oracle Cloud hostname (allowed under a reserved TLD: .example/.test/.invalid),
#   - an OCI namespace given literally (--namespace-name, namespace=, *_NS=),
#   - a real-looking email (allowed: example.com/.org/.net, reserved TLDs, .lan/.local, git/token@github.com),
#   - any fixed string listed, one per line, in $NO_ENV_DENYLIST (default ~/.config/ainkrad/env-denylist when it
#     exists): put your real host, IP and bucket there, OUTSIDE the repo, so they are caught by name too.
#   scripts/no-env-values.sh [FILE...]   (default: every tracked file but Cargo.lock)
#   scripts/no-env-values.sh --selftest  (plants each kind of value in a temp file and expects a failure)
set -euo pipefail
cd "$(dirname "$0")/.."

scan() { # FILE... -> offending lines on stdout, exit 1 if any
  local deny=${NO_ENV_DENYLIST:-${XDG_CONFIG_HOME:-$HOME/.config}/ainkrad/env-denylist}
  [ -r "$deny" ] || deny=''
  DENY=$deny perl -ne '
    BEGIN {
      @deny = ();
      if ($ENV{DENY} ne "" && open(my $d, "<", $ENV{DENY})) { while (<$d>) { chomp; s/^\s+|\s+$//g; push @deny, lc if length && !/^#/ } }
    }
    if ($. == 1) { $skip = -B $ARGV; }
    if ($skip) { close ARGV if eof; next; }
    my @why;
    my $l = $_;
    unless ($l =~ /version/i) {
      while ($l =~ /(?<![\w.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\w]|\.\d)/g) {
        my @o = ($1, $2, $3, $4); my $ip = join(".", @o);
        next if grep { $_ > 255 } @o;
        next if substr($l, 0, $-[0]) =~ /\bv\(\s*"$/;               # v("1.2.3.4"): a version
        next if $o[0] == 127 || $o[0] == 10 || $o[0] == 0 || $o[0] == 255;
        next if $o[0] == 172 && $o[1] >= 16 && $o[1] <= 31;
        next if $o[0] == 192 && $o[1] == 168;
        next if $o[0] == 169 && $o[1] == 254;
        next if "$o[0].$o[1].$o[2]" =~ /^(192\.0\.2|198\.51\.100|203\.0\.113)$/;
        push @why, "public IPv4 $ip";
      }
    }
    while ($l =~ /([\w.-]*\.(?:compat\.objectstorage|oraclecloud\.com)\b[\w.-]*)/gi) {
      my $h = $1; next if $h =~ /\.(example|test|invalid|localhost)$/i; push @why, "OCI host $h";
    }
    if ($l =~ /(?:--namespace(?:-name)?\s+["\x27]?|\b[Nn]amespace(?:_name)?\s*[:=]\s*["\x27]|_NS\s*=\s*["\x27]?)([a-z0-9]{6,})\b/) {
      push @why, "OCI namespace $1";
    }
    while ($l =~ /[\w.%+-]+@([\w-]+(?:\.[\w-]+)*\.([A-Za-z]{2,}))\b/g) {
      my ($dom, $tld) = (lc $1, lc $2);
      next if $dom =~ /(^|\.)example\.(com|org|net)$/ || $tld =~ /^(example|test|invalid|localhost|local|lan)$/;
      next if $dom eq "github.com";
      push @why, "email at $dom";
    }
    for my $d (@deny) { push @why, "denylisted value" if index(lc $l, $d) >= 0; }
    if (@why) { chomp $l; printf "%s:%d: %s: %s\n", $ARGV, $., join("; ", @why), $l; $bad = 1; }
    close ARGV if eof;
    END { exit($bad ? 1 : 0) }
  ' "$@"
}

if [ "${1:-}" = --selftest ]; then
  t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
  # Each bad value is assembled here, so this file holds none of them literally.
  at=@ dot=. ns=$(printf 'abcd%s' efgh1234)
  bad=(
    "addr = \"$(printf '%s.%s.%s.%s' 9 9 9 9)\""
    "endpoint https://ns1${dot}compat${dot}objectstorage${dot}xx-city-1${dot}oraclecloud${dot}com"
    "console at cloud${dot}oraclecloud${dot}com"
    "oci os object list --namespace-name $ns"
    "E1_OCI_NS=$ns"
    "contact = \"someone${at}realmail${dot}com\""
  )
  n=0
  for line in "${bad[@]}"; do
    printf 'ok line\n%s\n' "$line" >"$t/bad"
    if scan "$t/bad" >/dev/null; then echo "selftest FAIL: not caught: $line" >&2; exit 1; fi
    n=$((n + 1))
  done
  printf 'secret-host%sinternal\n' "$dot" >"$t/deny"
  printf 'host = "secret-host%sinternal"\n' "$dot" >"$t/bad"
  if NO_ENV_DENYLIST="$t/deny" scan "$t/bad" >/dev/null; then echo "selftest FAIL: denylist not applied" >&2; exit 1; fi
  cat >"$t/good" <<'OK'
bind 127.0.0.1:7700 and 0.0.0.0, peers 10.0.0.1 172.16.0.1 192.168.1.1 192.0.2.4 198.51.100.7 203.0.113.9
assert_eq!(v("1.2.3.4"), v("1.2.3")); VisualStudioVersion = 12.0.0.0; netmask 255.255.255.0
endpoint https://ns.compat.objectstorage.example; --namespace-name "$NS"; namespace = <namespace>
ops@example.com me@mail.example.org bot@citadel.lan test@citadel.invalid git@github.com:o/r.git https://tok@github.com/o/r.git
OK
  scan "$t/good" || { echo "selftest FAIL: allowed values were refused" >&2; exit 1; }
  echo "no-env-values selftest: $((n + 1)) planted kinds caught, allowed values pass"
  exit 0
fi

if [ $# -gt 0 ]; then files=("$@"); else
  files=()
  while IFS= read -r -d '' f; do
    case $f in Cargo.lock | */Cargo.lock) continue ;; esac
    [ -f "$f" ] && files+=("$f")
  done < <(git ls-files -z)
fi
if out=$(scan "${files[@]}"); then
  echo "no-env-values: ${#files[@]} files clean"
else
  printf '%s\n' "$out" >&2
  echo "no-env-values: environment-specific values above; use example.com, RFC 5737 IPs or <placeholder>" >&2
  exit 1
fi
