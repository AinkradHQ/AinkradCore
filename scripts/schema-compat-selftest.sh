#!/usr/bin/env bash
# Proves the gate (E1-05.4): each mutation of the committed contract must fail or pass as listed.
# Needs Docker (oasdiff), so it is `make schema-compat-selftest`, not part of `make test`.
set -euo pipefail
cd "$(dirname "$0")/.."
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
fails=0
# A tiny module contract, so the cases need no real module: modules/fake/api/openapi.json (C-21).
fake='{"openapi":"3.1.0","info":{"title":"fake","version":"1"},"paths":{"/x":{"get":{"operationId":"getX","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Thing"}}}}}}}},"components":{"schemas":{"Thing":{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}}}}'
# The baseline root: the committed contract files plus the fake module's.
mkdir -p "$t/base/modules/citadel/api" "$t/base/modules/fake/api"
cp -R api "$t/base/api"; cp modules/citadel/api/openapi.core.json "$t/base/modules/citadel/api/"
echo "$fake" > "$t/base/modules/fake/api/openapi.json"
# run <name> <expect: fail|pass>: schema-compat.sh on base vs new
run_() {
  if scripts/schema-compat.sh --base "$t/base" "$t/new" >"$t/out" 2>&1; then got=pass; else got=fail; fi
  reason=""; [ "$got" = fail ] && reason=" - $(grep -m1 -E '^error|^schema-compat: [a-z./]+json' "$t/out" | cut -c1-100 || true)"
  if [ "$got" = "$2" ]; then echo "ok   $1 ($got)${reason}"; else echo "FAIL $1: expected $2, got $got"; cat "$t/out"; fails=1; fi
}
# case <name> <expect> <file relative to the root> <jq filter>: the new root has the file mutated
case_() { rm -rf "$t/new"; cp -R "$t/base" "$t/new"; jq "$4" "$t/base/$3" > "$t/new/$3"; run_ "$1" "$2"; }
O=api/openapi.json; E=api/events.schema.json; R=api/runner.schema.json; M=modules/fake/api/openapi.json; C=modules/citadel/api/openapi.core.json
case_ "unchanged contract"                 pass $O '.'
case_ "optional field added (openapi)"     pass $O '.components.schemas.Device.properties.nickname={"type":"string"}'
case_ "optional field added (events)"      pass $E '.oneOf[0].properties.source={"type":"string"}'
case_ "field removed (openapi)"            fail $O 'del(.components.schemas.Device.properties.name)'
case_ "field made required (openapi)"      fail $O '.components.schemas.Device.required+=["revoked_at"]'
case_ "new required field (openapi)"       fail $O '.components.schemas.Device.properties.nickname={"type":"string"}|.components.schemas.Device.required+=["nickname"]'
case_ "path removed (openapi)"             fail $O 'del(.paths["/api/v1/me"])'
case_ "operation removed (openapi)"        fail $O 'del(.paths["/api/v1/devices"].get)'
case_ "type narrowed (openapi)"            fail $O '.components.schemas.Named.properties.name.type="integer"'
case_ "field removed (events)"             fail $E 'del(.oneOf[0].properties.kind)'
case_ "new required field (events)"       fail $E '.oneOf[0].properties.source={"type":"string"}|.oneOf[0].required+=["source"]'
case_ "type narrowed (events)"             fail $E '.oneOf[0].properties.seq.type="string"'
case_ "enum value removed (runner)"       fail $R '.["$defs"].PermissionMode.oneOf |= .[1:]'
case_ "message variant removed (runner)"  fail $R '.oneOf[0].oneOf |= .[1:]'
case_ "new required field (runner)"      fail $R '.["$defs"].Policy.properties.extra={"type":"string"}|.["$defs"].Policy.required+=["extra"]'
# C-21: a module contract is gated through scripts/contracts.list, with no per-module edit.
case_ "module: unchanged"                   pass $M '.'
case_ "module: optional field added"        pass $M '.components.schemas.Thing.properties.b={"type":"string"}'
case_ "module: field removed"               fail $M 'del(.components.schemas.Thing.properties.a)'
case_ "module: new required field"          fail $M '.components.schemas.Thing.properties.b={"type":"string"}|.components.schemas.Thing.required+=["b"]'
case_ "module: path removed"                fail $M 'del(.paths["/x"])'
case_ "module: type narrowed"               fail $M '.components.schemas.Thing.properties.a.type="integer"'
case_ "citadel core contract: field removed" fail $C 'del(.components.schemas.Device.properties.name)'
rm -rf "$t/new"; cp -R "$t/base" "$t/new"; rm "$t/new/$M"; run_ "module: contract file removed" fail
rm -rf "$t/new"; cp -R "$t/base" "$t/new"; mkdir -p "$t/new/modules/other/api"; echo "$fake" > "$t/new/modules/other/api/openapi.json"
run_ "module: new contract, no baseline" pass
# the same gate on the next run: the new file is now the baseline
cp -R "$t/new/modules/other" "$t/base/modules/"; jq 'del(.components.schemas.Thing.properties.a)' "$t/new/modules/other/api/openapi.json" > "$t/x"; mv "$t/x" "$t/new/modules/other/api/openapi.json"
run_ "module: new contract, then compared" fail

# api-minor-check.sh: a throwaway git repo; only files marked `api-minor` need a bump.
g="$t/git"; mkdir -p "$g/scripts" "$g/crates/server/src/api/v1"
cp scripts/api-minor-check.sh scripts/contracts.sh scripts/contracts.list "$g/scripts/"; cp -R "$t/base/api" "$t/base/modules" "$g/"
echo 'pub const API_MINOR: u32 = 5;' > "$g/crates/server/src/api/v1/types.rs"
git -C "$g" init -q && git -C "$g" add -A && git -C "$g" -c user.name=t -c user.email=t@t commit -qm base
minor_() { # <name> <expect> <file> <jq filter> <API_MINOR>
  git -C "$g" checkout -q -- . && git -C "$g" clean -fdq
  jq "$4" "$g/$3" > "$t/x" && mv "$t/x" "$g/$3"
  echo "pub const API_MINOR: u32 = $5;" > "$g/crates/server/src/api/v1/types.rs"
  if BASE_REF=HEAD "$g/scripts/api-minor-check.sh" >"$t/out" 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$2" ]; then echo "ok   api-minor: $1 ($got)"; else echo "FAIL api-minor: $1: expected $2, got $got"; cat "$t/out"; fails=1; fi
}
ADD='.info.title="x"'
minor_ "platform file changed, no bump"      fail $O "$ADD" 5
minor_ "platform file changed, bumped"       pass $O "$ADD" 6
minor_ "citadel core changed, no bump"       fail $C "$ADD" 5
minor_ "module contract changed, no bump"    pass $M "$ADD" 5
minor_ "nothing changed"                     pass $M '.' 5
exit "$fails"
