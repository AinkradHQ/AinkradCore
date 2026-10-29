#!/usr/bin/env bash
# Kotlin, C# and TypeScript clients from api/openapi.json (E1-05.3): generate + compile-smoke only;
# the clients themselves are built in E4-E7. Everything runs in pinned official images, so the host
# needs only Docker. Swift is scripts/contract-swift.sh.
#
# Generators (spike result, OpenAPI 3.1 input, offline from api/openapi.json):
#   Kotlin  openapi-generator 7.15.0  `-g kotlin --library jvm-ktor` (kotlinx.serialization)
#           compiled by Gradle 8.14 on JDK 21 (`gradle compileKotlin`)
#   C#      openapi-generator 7.15.0  `-g csharp --library httpclient`
#           compiled by the .NET SDK 9.0 (`dotnet build`). Kiota and NSwag were not picked: both need
#           a second toolchain image for no gain here; the same pinned image serves Kotlin and C#.
#   TS      openapi-typescript 7.10.1 (types only, `schema.d.ts`), type-checked by TypeScript 5.9.3
#           (`tsc --noEmit`) on Node 22
# Image digests below are the pin; bump a version and its digest together.
#
#   scripts/contract-clients.sh gen   [<clients-dir>]   regenerate clients/{kotlin,csharp,ts}/generated
#   scripts/contract-clients.sh smoke [<clients-dir>]   compile each in a clean container
set -euo pipefail
cd "$(dirname "$0")/.."
cmd="${1:?gen|smoke}"; clients="$(cd "${2:-clients}" && pwd)"
OPENAPI_GEN=openapitools/openapi-generator-cli@sha256:509f01c3c7eee9d1ad286506a7b6aa4624a95b410be9a238a306d209e900621f
GRADLE=gradle@sha256:b3453e88792ea90b526f5d04fa2961bba183ae57ded4ad3437a49fb4e8381c06
DOTNET=mcr.microsoft.com/dotnet/sdk@sha256:7e3a4bd66701a451823db2028154ae16ff191bc452596ba618ef4d0c58f9cd01
NODE=node@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da
OPENAPI_TS=7.10.1
TSC=5.9.3
spec="$(pwd)/api/openapi.json"
me="$(id -u):$(id -g)"
# Not part of a client: CI/VCS boilerplate, the Gradle wrapper jar, the generator's own timestamps.
junk="git_push.sh appveyor.yml .travis.yml .gitignore .gitattributes .openapi-generator-ignore gradle gradlew gradlew.bat README.md docs api"

openapi_gen() { # <lang> <out> <generator args...>
  local out="$2"; rm -rf "$out/generated"; mkdir -p "$out/generated"
  docker run --rm --user "$me" -v "$spec:/spec/openapi.json:ro" -v "$out/generated:/out" "$OPENAPI_GEN" \
    generate -i /spec/openapi.json -o /out --skip-validate-spec \
    --global-property=apiTests=false,modelTests=false,apiDocs=false,modelDocs=false "${@:3}" >/dev/null 2>&1 \
    || { echo "contract-clients: $1 generation failed" >&2; exit 1; }
  for j in $junk; do rm -rf "${out:?}/generated/$j"; done
}

gen() {
  openapi_gen kotlin "$clients/kotlin" -g kotlin --library jvm-ktor \
    --additional-properties=serializationLibrary=kotlinx_serialization,packageName=ainkrad.client,groupId=ainkrad,artifactId=ainkrad-client
  openapi_gen csharp "$clients/csharp" -g csharp --library httpclient \
    --additional-properties=packageName=Ainkrad.Client,packageGuid={7B1D9F0E-3C2A-4E55-9A4B-A1C2D3E4F5A6}
  rm -rf "$clients/ts/generated"; mkdir -p "$clients/ts/generated"
  docker run --rm --user "$me" -e HOME=/tmp -v "$spec:/spec/openapi.json:ro" -v "$clients/ts/generated:/out" "$NODE" \
    npx --yes "openapi-typescript@$OPENAPI_TS" /spec/openapi.json -o /out/schema.d.ts >/dev/null 2>&1 \
    || { echo "contract-clients: ts generation failed" >&2; exit 1; }
  echo "contract-clients: generated kotlin, csharp, ts into $clients"
}

# Runs in a copy inside the container, so the checkout never gets build output or root-owned files.
smoke() { # <label> <image> <dir under clients/> <shell command run in /work>
  echo "contract-clients: compiling $1"
  docker run --rm -v "$clients/$3:/src:ro" "$2" sh -c "cp -R /src /work && cd /work && $4" >/dev/null \
    || { echo "contract-clients: $1 did not compile" >&2; exit 1; }
}

case "$cmd" in
  gen) gen ;;
  smoke)
    smoke kotlin "$GRADLE" kotlin/generated "gradle --no-daemon -q compileKotlin"
    smoke csharp "$DOTNET" csharp/generated "dotnet build -c Release -nologo -v q"
    smoke ts "$NODE" ts "npx --yes -p typescript@$TSC tsc --noEmit -p ."
    echo "contract-clients: kotlin, csharp, ts compile" ;;
  *) echo "usage: $0 gen|smoke [clients-dir]" >&2; exit 2 ;;
esac
