#!/usr/bin/env bash
# Tests for scripts/install.sh without root (macOS or Linux): the validators, the answers parser, and a full
# --dry-run from an answers file (nothing written, the secret never printed). `make install-test`.
# SC2015: `check && pass || fail` is meant; SC2016: the planted $( ) must stay literal; SC2012: a count only.
# shellcheck disable=SC2015,SC2016,SC2012
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=scripts/install/lib.sh
. "$HERE/lib.sh"
pass=0 fail=0
ok() { if "$@"; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: expected ok: $*" >&2; fi; }
no() { if "$@"; then fail=$((fail + 1)); echo "FAIL: expected refused: $*" >&2; else pass=$((pass + 1)); fi; }
rc() { local want=$1 got=0; shift; "$@" || got=$?; if [ "$got" = "$want" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL: $* -> $got, want $want" >&2; fi; }

# A syntactically valid recipient, assembled (bech32 alphabet only), and a secret-key-shaped string.
R=age1$(printf 'q%.0s' $(seq 58))
S=AGE-SECRET-KEY-1$(printf 'Q%.0s' $(seq 58))

ok valid_hostname core.example.com; ok valid_hostname A.Example.COM; ok valid_hostname x-1.example.org
no valid_hostname localhost; no valid_hostname -bad.example.com; no valid_hostname bad-.example.com
no valid_hostname 192.0.2.1; no valid_hostname 'a b.example.com'; no valid_hostname ''; no valid_hostname example.123
no valid_hostname "$(printf 'a%.0s' $(seq 64)).example.com"
ok valid_https_url https://s3.example.com; ok valid_https_url https://s3.example.com:8443/path; ok valid_https_url https://192.0.2.10
no valid_https_url http://s3.example.com; no valid_https_url 'https://user@s3.example.com'; no valid_https_url https://
no valid_https_url 'https://s3.example.com/?x=1'; no valid_https_url 'https://s3 .example.com'; no valid_https_url https://s3.example.com:99999
ok valid_port 1; ok valid_port 443; ok valid_port 65535; no valid_port 0; no valid_port 65536; no valid_port 080; no valid_port 4a; no valid_port ''
ok valid_email ops@example.com; ok valid_email first.last+tag@mail.example.org
no valid_email ops; no valid_email ops@localhost; no valid_email 'o ps@example.com'; no valid_email @example.com
ok valid_bucket core-backups; ok valid_bucket my.bucket_01; no valid_bucket ab; no valid_bucket -bucket; no valid_bucket 'bad bucket'
no valid_bucket 192.0.2.1; no valid_bucket "$(printf 'b%.0s' $(seq 64))"
ok valid_region us-east-1; ok valid_region xx-city-1; no valid_region 'a b'; no valid_region ''
ok valid_prefix core/; ok valid_prefix a/b/; ok valid_prefix ''; no valid_prefix /core/; no valid_prefix core; no valid_prefix 'a b/'
rc 0 age_recipient "$R"
rc 2 age_recipient "$S"
rc 2 age_recipient "$(printf '%s' "$S" | tr '[:upper:]' '[:lower:]')"
rc 2 age_recipient "# secret: $S"
rc 1 age_recipient "${R}q"; rc 1 age_recipient age1short; rc 1 age_recipient "age1$(printf 'b%.0s' $(seq 58))"; rc 1 age_recipient ''
ok valid_origins ''; ok valid_origins https://app.example.com; ok valid_origins https://a.example.com,https://b.example.com:8443
no valid_origins http://app.example.com; no valid_origins https://app.example.com/path; no valid_origins 'https://a.example.com, https://b.example.com'
ok valid_cidrs 198.51.100.0/24; ok valid_cidrs 198.51.100.0/24,2001:db8::/32; ok valid_cidrs ''
no valid_cidrs 198.51.100.7; no valid_cidrs 300.1.1.0/24; no valid_cidrs 198.51.100.0/33
ok ip_in_cidrs 198.51.100.7 203.0.113.0/24,198.51.100.0/24; no ip_in_cidrs 192.0.2.1 198.51.100.0/24
ok valid_schedule daily; ok valid_schedule '*-*-* 03:00:00'; no valid_schedule 'daily; rm -rf /'; no valid_schedule "$(printf 'x\ny')"
[ "$(mask abcdefghijkl)" = 'ab****kl' ] && pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL: mask" >&2; }
[ "$(mask short)" = '********' ] && pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL: mask short" >&2; }

t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
mkdir "$t/bin"; for n in ainkrad-core-server ainkradctl ainkrad-runner; do printf '#!/bin/sh\n' >"$t/bin/$n"; done
SECRET=planted$(date +%s)secretvalue
answers() {
  cat <<EOF
# test answers
BINARY_DIR=$t/bin
HOSTNAME=Core.Example.com
ACME_CONTACT=ops@example.com
ACME_CHALLENGE=http-01
PASSKEYS=yes
ALLOW_ORIGINS=https://app.example.com
BACKUP=bucket
BACKUP_ENDPOINT=https://s3.example.com
BACKUP_REGION=xx-city-1
BACKUP_BUCKET=core-backups
BACKUP_ACCESS_KEY=AKIDEXAMPLE0001
BACKUP_SECRET_KEY="$SECRET"
BACKUP_RECIPIENT=$R
EOF
}

# The parser: missing keys are listed, unknown keys and code are refused, nothing is executed.
printf 'HOSTNAME=core.example.com\nBACKUP=bucket\n' >"$t/partial"
( parse_answers "$t/partial" && m=$(missing_keys | tr '\n' ' ') &&
  for k in ACME_CONTACT BACKUP_RECIPIENT BINARY_DIR BACKUP_ENDPOINT BACKUP_SECRET_KEY; do case $m in *$k*) ;; *) exit 1 ;; esac; done ) &&
  pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL: missing keys not listed" >&2; }
printf 'HOSTNAME=$(touch %s/pwned)\nNOPE=1\n' "$t" >"$t/evil"
( parse_answers "$t/evil" 2>/dev/null ) && { fail=$((fail + 1)); echo "FAIL: unknown key accepted" >&2; } || pass=$((pass + 1))
[ ! -e "$t/pwned" ] && pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL: answers file was executed" >&2; }
{ answers; printf 'BACKUP_RECIPIENT=%s\n' "$S"; } >"$t/secretkey"
( parse_answers "$t/secretkey" && check_answers ) 2>"$t/err" && { fail=$((fail + 1)); echo "FAIL: secret age key accepted" >&2; } || pass=$((pass + 1))
grep -q 'age SECRET key' "$t/err" && ! grep -q "$S" "$t/err" && pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL: secret key message" >&2; }

# The dry run: every step printed, the secret masked, nothing written.
answers >"$t/answers"
before=$(ls -la /etc 2>/dev/null | wc -l)
if bash "$HERE/../install.sh" --config "$t/answers" --dry-run >"$t/out" 2>&1; then pass=$((pass + 1)); else
  fail=$((fail + 1)); echo "FAIL: dry run exited non-zero:" >&2; tail -n 20 "$t/out" >&2; fi
for want in 'write /etc/ainkrad/core.env' 'AINKRAD_HOSTNAME=core.example.com' 'acme-staging-v02' '--acme-http01' \
  '--passkeys --allow-origin https://app.example.com' 'write /etc/ainkrad/backup.env' 'AINKRAD_BACKUP_SECRET_KEY=pl****ue' \
  'ainkrad-backup.timer' 'OnCalendar=daily' 'systemctl restart ainkrad-core.service' 'bootstrap /var/lib/ainkrad/core/core.db' \
  'Still yours to do'; do
  grep -qF -- "$want" "$t/out" && pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL: dry run lacks: $want" >&2; }
done
grep -qF "$SECRET" "$t/out" && { fail=$((fail + 1)); echo "FAIL: the secret key was printed" >&2; } || pass=$((pass + 1))
[ "$(ls -la /etc 2>/dev/null | wc -l)" = "$before" ] && pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL: /etc changed" >&2; }
# Unattended with keys missing: refused, naming them.
sed '/^BACKUP_RECIPIENT=/d; /^ACME_CONTACT=/d' "$t/answers" >"$t/short"
if bash "$HERE/../install.sh" --config "$t/short" --dry-run >"$t/out2" 2>&1; then fail=$((fail + 1)); echo "FAIL: missing keys accepted" >&2
else grep -q 'missing in .*ACME_CONTACT, BACKUP_RECIPIENT' "$t/out2" && pass=$((pass + 1)) || { fail=$((fail + 1)); echo "FAIL: missing keys message: $(tail -n1 "$t/out2")" >&2; }; fi
# --uninstall --dry-run never names backup.env for removal.
bash "$HERE/../install.sh" --uninstall --purge --dry-run </dev/null >"$t/out3" 2>&1 || true
grep '^+ ' "$t/out3" | grep -q backup.env && { fail=$((fail + 1)); echo "FAIL: uninstall touches backup.env" >&2; } || pass=$((pass + 1))

echo "install tests: $pass passed, $fail failed"
[ "$fail" = 0 ]
