#!/usr/bin/env bash
# Proves the gate (E1-05.4): each mutation of the committed contract must fail or pass as listed.
# Needs Docker (oasdiff), so it is `make schema-compat-selftest`, not part of `make test`.
set -euo pipefail
cd "$(dirname "$0")/.."
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
fails=0
# case <name> <expect: fail|pass> <file> <jq filter>
case_() {
  rm -rf "$t/new"; cp -R api "$t/new"
  jq "$4" "api/$3" > "$t/new/$3"
  if scripts/schema-compat.sh --base api "$t/new" >"$t/out" 2>&1; then got=pass; else got=fail; fi
  reason=""; [ "$got" = fail ] && reason=" - $(grep -m1 -E '^error|^schema-compat: [a-z.]+json' "$t/out" | cut -c1-100 || true)"
  if [ "$got" = "$2" ]; then echo "ok   $1 ($got)${reason}"; else echo "FAIL $1: expected $2, got $got"; cat "$t/out"; fails=1; fi
}
O=openapi.json; E=events.schema.json; R=runner.schema.json
case_ "unchanged contract"                 pass $O '.'
case_ "optional field added (openapi)"     pass $O '.components.schemas.Device.properties.nickname={"type":"string"}'
case_ "optional field added (events)"      pass $E '.oneOf[0].properties.source={"type":"string"}'
case_ "field removed (openapi)"            fail $O 'del(.components.schemas.Device.properties.name)'
case_ "field made required (openapi)"      fail $O '.components.schemas.Device.required+=["revoked_at"]'
case_ "new required field (openapi)"       fail $O '.components.schemas.Device.properties.nickname={"type":"string"}|.components.schemas.Device.required+=["nickname"]'
case_ "path removed (openapi)"             fail $O 'del(.paths["/api/v1/me"])'
case_ "operation removed (openapi)"        fail $O 'del(.paths["/api/v1/devices"].get)'
case_ "type narrowed (openapi)"            fail $O '.components.schemas.Device.properties.id.type="string"'
case_ "field removed (events)"             fail $E 'del(.oneOf[0].properties.kind)'
case_ "new required field (events)"       fail $E '.oneOf[0].properties.source={"type":"string"}|.oneOf[0].required+=["source"]'
case_ "type narrowed (events)"             fail $E '.oneOf[0].properties.seq.type="string"'
case_ "enum value removed (runner)"       fail $R '.["$defs"].PermissionMode.oneOf |= .[1:]'
case_ "message variant removed (runner)"  fail $R '.oneOf[0].oneOf |= .[1:]'
case_ "new required field (runner)"      fail $R '.["$defs"].Policy.properties.extra={"type":"string"}|.["$defs"].Policy.required+=["extra"]'
exit "$fails"
