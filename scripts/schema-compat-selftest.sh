#!/usr/bin/env bash
# Proves the gate (E1-05.4): each mutation of the committed contract must fail or pass as listed.
# Needs Docker (oasdiff), so it is `make schema-compat-selftest`, not part of `make test`.
set -euo pipefail
cd "$(dirname "$0")/.."
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
fails=0; again=()
# A tiny module contract, so the cases need no real module: modules/fake/api/openapi.json (C-21).
fake='{"openapi":"3.1.0","info":{"title":"fake","version":"1"},"paths":{"/x":{"get":{"operationId":"getX","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Thing"}}}}}}}},"components":{"schemas":{"Thing":{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}}}}'
# The baseline root: the committed contract files plus the fake module's.
mkdir -p "$t/base/modules/citadel/api" "$t/base/modules/fake/api"
cp -R api "$t/base/api"; cp modules/citadel/api/openapi.core.json "$t/base/modules/citadel/api/"; mkdir -p "$t/base/scripts"; cp scripts/contracts.list "$t/base/scripts/"
echo "$fake" > "$t/base/modules/fake/api/openapi.json"
# run_ <name> <expect: fail|pass> [reason regex the output must match on a fail]: schema-compat.sh on base vs new
run_() { again=(scripts/schema-compat.sh --base "$t/base" "$t/new"); try_ "${again[@]}"; check_ "$1" "$2" "${3:-}"; }
# try_ <cmd...>: sets got; Docker Desktop's file sharing can serve a just-written file half-read, so a
# run that does not meet the expectation is repeated once before it counts (expectation read from caller).
try_() { if "$@" >"$t/out" 2>&1; then got=pass; else got=fail; fi; }
check_() {
  reason=""; [ "$got" = fail ] && reason=" - $(grep -m1 -E '^error|^schema-compat: [a-z./]+json' "$t/out" | cut -c1-100 || true)"
  if ! { [ "$got" = "$2" ] && { [ "$2" = pass ] || [ -z "$3" ] || grep -Eq "$3" "$t/out"; }; } && [ -n "${again:-}" ]; then
    sleep 3; try_ "${again[@]}"; again=()
  fi
  if [ "$got" = "$2" ] && { [ "$2" = pass ] || [ -z "$3" ] || grep -Eq "$3" "$t/out"; }; then echo "ok   $1 ($got)${reason}"
  else echo "FAIL $1: expected $2 ${3:+matching /$3/}, got $got"; cat "$t/out"; fails=1; fi
}
# case_ <name> <expect> <file relative to the root> <jq filter> [reason]: the new root has the file mutated
case_() { rm -rf "$t/new"; cp -R "$t/base" "$t/new"; jq "$4" "$t/base/$3" > "$t/new/$3"; run_ "$1" "$2" "${5:-}"; }
fresh_() { rm -rf "$t/new"; cp -R "$t/base" "$t/new"; }
O=api/openapi.json; E=api/events.schema.json; R=api/runner.schema.json; M=modules/fake/api/openapi.json; C=modules/citadel/api/openapi.core.json
case_ "unchanged contract"                 pass $O '.'
case_ "optional field added (openapi)"     pass $O '.components.schemas.Device.properties.nickname={"type":"string"}'
case_ "optional field added (events)"      pass $E '.oneOf[0].properties.source={"type":"string"}'
case_ "field removed (openapi)"            fail $O 'del(.components.schemas.Device.properties.name)' 'response-required-property-removed'
case_ "field made required (openapi)"      fail $O '.components.schemas.Device.required+=["revoked_at"]' 'revoked_at. is required now'
case_ "new required field (openapi)"       fail $O '.components.schemas.Device.properties.nickname={"type":"string"}|.components.schemas.Device.required+=["nickname"]' 'nickname. is required now'
case_ "path removed (openapi)"             fail $O 'del(.paths["/api/v1/me"])' 'api-path-removed-without-deprecation'
case_ "operation removed (openapi)"        fail $O 'del(.paths["/api/v1/devices"].get)' 'api-removed-without-deprecation'
case_ "type narrowed (openapi)"            fail $O '.components.schemas.Named.properties.name.type="integer"' 'response-property-type-changed'
case_ "field removed (events)"             fail $E 'del(.oneOf[0].properties.kind)' 'removed /oneOf'
case_ "new required field (events)"       fail $E '.oneOf[0].properties.source={"type":"string"}|.oneOf[0].required+=["source"]' 'source. is required now'
case_ "type narrowed (events)"             fail $E '.oneOf[0].properties.seq.type="string"' 'type narrowed'
case_ "enum value removed (runner)"       fail $R '.["$defs"].PermissionMode.oneOf |= .[1:]' 'variant ask removed'
case_ "message variant removed (runner)"  fail $R '.oneOf[0].oneOf |= .[1:]' 'variant hello removed'
case_ "new required field (runner)"      fail $R '.["$defs"].Policy.properties.extra={"type":"string"}|.["$defs"].Policy.required+=["extra"]' 'extra. is required now'
# C-21: a module contract is gated through scripts/contracts.list, with no per-module edit.
case_ "module: unchanged"                   pass $M '.'
case_ "module: optional field added"        pass $M '.components.schemas.Thing.properties.b={"type":"string"}'
case_ "module: field removed"               fail $M 'del(.components.schemas.Thing.properties.a)' 'response-required-property-removed'
case_ "module: new required field"          fail $M '.components.schemas.Thing.properties.b={"type":"string"}|.components.schemas.Thing.required+=["b"]' 'b. is required now'
case_ "module: path removed"                fail $M 'del(.paths["/x"])' 'api-path-removed-without-deprecation'
case_ "module: type narrowed"               fail $M '.components.schemas.Thing.properties.a.type="integer"' 'response-property-type-changed'
case_ "citadel core contract: field removed" fail $C 'del(.components.schemas.Device.properties.name)' 'response-required-property-removed'
rm -rf "$t/new"; cp -R "$t/base" "$t/new"; rm "$t/new/$M"; run_ "module: contract file removed" fail "contract file removed"
rm -rf "$t/new"; cp -R "$t/base" "$t/new"; mkdir -p "$t/new/modules/other/api"; echo "$fake" > "$t/new/modules/other/api/openapi.json"
run_ "module: new contract, no baseline" pass
# the same gate on the next run: the new file is now the baseline
cp -R "$t/new/modules/other" "$t/base/modules/"; jq 'del(.components.schemas.Thing.properties.a)' "$t/new/modules/other/api/openapi.json" > "$t/x"; mv "$t/x" "$t/new/modules/other/api/openapi.json"
run_ "module: new contract, then compared" fail "response-required-property-removed"

# oasdiff only: schema_compat.py ignores parameter lists, so this fails only if oasdiff really runs
case_ "new required query parameter (oasdiff only)" fail $O '.paths["/api/v1/devices"].get.parameters+=[{"name":"zz","in":"query","required":true,"schema":{"type":"string"}}]' 'new-required-request-parameter'

# the registry is the only source of file names (review of C-21)
thing='{"type":"object","properties":{"a":{"type":"string"}}}'
mkdir -p "$t/base/crates/x"; echo "$thing" > "$t/base/crates/x/contract.json"; echo 'crates/x/contract.json' >> "$t/base/scripts/contracts.list"
case_ "registry entry outside modules/: unchanged"        pass crates/x/contract.json '.'
case_ "registry entry outside modules/: breaking change"  fail crates/x/contract.json 'del(.properties.a)' 'removed /properties/a'
rm -rf "$t/base/crates"; cp scripts/contracts.list "$t/base/scripts/"
# a change cannot un-gate its own contract: the baseline is read with the baseline's registry
fresh_; echo '!modules/fake/api/*.json' >> "$t/new/scripts/contracts.list"
jq 'del(.components.schemas.Thing.properties.a)' "$t/base/$M" > "$t/new/$M"
run_ "registry drops a contract and breaks it" fail "dropped from the contract registry"
echo "$M: dropped from the contract registry" >> "$t/new/api/compat-allow.txt"
run_ "registry drop carried by an allow line" pass
# off-convention contract files are never silently ungated
for f in modules/fake/api/second.JSON modules/fake/api/v1/openapi.json modules/fake/api/openapi.yaml; do
  fresh_; mkdir -p "$(dirname "$t/new/$f")"; echo "$fake" > "$t/new/$f"; run_ "off-convention file $f" fail "off-convention"
done
# non-ASCII and symlinked paths
mkdir -p "$t/base/modules/módulo/api"; echo "$fake" > "$t/base/modules/módulo/api/openapi.json"
case_ "non-ASCII module dir: breaking change" fail "modules/módulo/api/openapi.json" 'del(.components.schemas.Thing.properties.a)' 'response-required-property-removed'
rm -rf "$t/base/modules/módulo"
fresh_; rm -rf "$t/new/modules/fake/api"; ln -s "$t/base/modules/fake/api" "$t/new/modules/fake/api"
run_ "symlinked api dir" fail "symlinked contract path"

# api-minor-check.sh: a throwaway git repo; only files marked `api-minor` need a bump.
g="$t/git"; mkdir -p "$g/scripts" "$g/crates/server/src/api/v1"
cp scripts/api-minor-check.sh scripts/schema-compat.sh scripts/schema_compat.py scripts/contracts.sh scripts/contracts.list "$g/scripts/"; cp -R "$t/base/api" "$t/base/modules" "$g/"
mkdir -p "$g/modules/módulo/api"; echo "$fake" > "$g/modules/módulo/api/openapi.json"
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

# schema-compat.sh in git mode (BASE_REF): paths come from git ls-tree -z, not C-quoted
gitrun_() { # <name> <expect> <reason>
  again=(env BASE_REF=HEAD "$g/scripts/schema-compat.sh"); try_ "${again[@]}"
  check_ "$1" "$2" "${3:-}"
}
gclean_() { git -C "$g" checkout -q -- . && git -C "$g" clean -fdq; }
gclean_; gitrun_ "git mode: unchanged" pass
gclean_; jq 'del(.components.schemas.Thing.properties.a)' "$g/modules/módulo/api/openapi.json" > "$t/x" && mv "$t/x" "$g/modules/módulo/api/openapi.json"
gitrun_ "git mode: non-ASCII module dir, breaking change" fail "response-required-property-removed"
gclean_; mkdir -p "$g/modules/lnk" && ln -s ../fake/api "$g/modules/lnk/api" && git -C "$g" add -A && git -C "$g" -c user.name=t -c user.email=t@t commit -qm link
rm -rf "$g/modules/lnk"; gitrun_ "git mode: symlinked api dir in the baseline" fail "symlinked contract path"
exit "$fails"
