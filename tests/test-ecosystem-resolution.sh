#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-ecosystem-resolution.sh: No-Docker checks for how npm, Ruby, PHP and .NET
# sources are read.
#
#   - the npm helper names the one dependency npm could not fetch (git URL,
#     404, no matching version) and removes only that one from package.json.
#   - the Gemfile reader reads `group :x, optional: true`, and the dev filter
#     marks those gems scope optional.
#   - the syft exclude list leaves out a package-lock.json under vendor/.
#   - normalize-sbom.sh drops versionless .NET base assemblies only.
#   - assess-completeness.sh reports npm-excluded:NAME as resolution-failed.
#
# Fixtures: tests/fixtures/journey/{npm-git-dep,ruby-optional-group,php-vendor-lock,dotnet-packages-config,go-mod}.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures/journey"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }
check() {  # <label> <got> <want>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "got [$2], expected [$3]"; fi
}

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq is not installed"; exit 0; }
command -v node >/dev/null 2>&1 || { echo "SKIP: node is not installed"; exit 0; }

# Heredoc bodies of build-prep.sh, run as they are.
extract() {  # <marker> <out>
    sed -n "/<<'$1'/,/^$1\$/p" "$LIB/build-prep.sh" | sed '1d;$d' > "$2"
}

echo "== npm: one unresolvable dependency =="
extract NPMDROP_JS "$WORK/npmdrop.js"
drop() {  # <name> <spec> <stderr text>
    printf '{"dependencies":{"express":"4","%s":"%s"}}\n' "$1" "$2" > "$WORK/package.json"
    printf '%s\n' "$3" > "$WORK/err"
    node "$WORK/npmdrop.js" "$WORK/package.json" "$WORK/err" | tr '\n' ' '
}
check "git URL named in npm's error" \
    "$(drop private-lib 'git+https://git.invalid.example/team/private-lib.git#v1.2.0' "npm error code 128
npm error command git --no-replace-objects ls-remote https://git.invalid.example/team/private-lib.git")" "private-lib "
check "express stays" "$(jq -c '.dependencies | keys' "$WORK/package.json")" '["express"]'
check "EALLOWGIT drops the git dependency" \
    "$(drop private-lib 'github:acme/private-lib' 'npm error code EALLOWGIT')" "private-lib "
check "E404 for a scoped package" \
    "$(drop @acme/ghost '^1.0.0' 'npm error 404 Not Found - GET https://registry.npmjs.org/@acme%2fghost - Not found')" "@acme/ghost "
check "ETARGET" \
    "$(drop nover '^99.0.0' 'npm error notarget No matching version found for nover@^99.0.0.')" "nover "
check "an unrelated error drops nothing" \
    "$(drop other '1.0.0' 'npm error code ERESOLVE')" ""
check "...and leaves package.json alone" "$(jq -c '.dependencies | keys' "$WORK/package.json")" '["express","other"]'

echo "== Ruby: optional group =="
extract GEMDEV_JS "$WORK/gemdev.js"
extract DEVFILTER_JS "$WORK/devfilter.js"
( cd "$FIX/ruby-optional-group" && node "$WORK/gemdev.js" Gemfile Gemfile.lock ) > "$WORK/gems.txt" 2>/dev/null
check "dev/test gems and the optional-group gem are read" "$(tr '\n' ' ' < "$WORK/gems.txt")" "capybara pry rspec-rails optional:avo "
cat > "$WORK/bom.json" <<'E'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"a","bom-ref":"a"}},
 "components":[{"type":"library","name":"avo","purl":"pkg:gem/avo@2.0.0","bom-ref":"avo"},{"type":"library","name":"rails","purl":"pkg:gem/rails@7.1.0","bom-ref":"rails"},{"type":"library","name":"rspec-rails","purl":"pkg:gem/rspec-rails@6.0.0","bom-ref":"rspec"}],
 "dependencies":[{"ref":"a","dependsOn":["avo","rails","rspec"]}]}
E
node "$WORK/devfilter.js" "$WORK/bom.json" 0 "$WORK/gems.txt" "" >/dev/null 2>&1
check "avo is kept with scope optional, rspec-rails is dropped" \
    "$(jq -c '[.components[] | {n: .name, s: .scope}]' "$WORK/bom.json")" '[{"n":"avo","s":"optional"},{"n":"rails","s":null}]'

echo "== PHP: vendored package-lock.json =="
# shellcheck source=docker/lib/source-detect.sh
. "$LIB/source-detect.sh"
case "$(non_shipped_syft_args)" in
    *"--exclude ./**/vendor/**/package-lock.json"*) pass "syft exclude list names vendor/**/package-lock.json" ;;
    *) fail "syft exclude list names vendor/**/package-lock.json" ;;
esac
if command -v syft >/dev/null 2>&1; then
    read -ra _x <<< "$(non_shipped_syft_args)"
    check "syft finds no npm component in the PHP fixture" \
        "$(syft "dir:$FIX/php-vendor-lock" "${_x[@]}" -o cyclonedx-json 2>/dev/null | jq '[.components[]? | select((.purl // "") | startswith("pkg:npm/"))] | length')" 0
else
    echo "  SKIP: syft is not installed"
fi

echo "== .NET: base assemblies =="
cat > "$WORK/n.json" <<'E'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"component":{"type":"application","name":"app","bom-ref":"app"}},
 "components":[
  {"type":"library","name":"System","purl":"pkg:nuget/System","bom-ref":"pkg:nuget/System"},
  {"type":"library","name":"System.Core","purl":"pkg:nuget/System.Core","bom-ref":"pkg:nuget/System.Core"},
  {"type":"library","name":"System.Net.Http","version":"4.3.4","purl":"pkg:nuget/System.Net.Http@4.3.4","bom-ref":"pkg:nuget/System.Net.Http@4.3.4"},
  {"type":"library","name":"Newtonsoft.Json","version":"13.0.3","purl":"pkg:nuget/Newtonsoft.Json@13.0.3","bom-ref":"pkg:nuget/Newtonsoft.Json@13.0.3"}],
 "dependencies":[{"ref":"app","dependsOn":["pkg:nuget/System","pkg:nuget/Newtonsoft.Json@13.0.3"]},{"ref":"pkg:nuget/System"}]}
E
bash "$LIB/normalize-sbom.sh" "$WORK/n.json" >/dev/null 2>&1
check "versionless System and System.Core go, versioned packages stay" \
    "$(jq -c '[.components[].purl]' "$WORK/n.json")" '["pkg:nuget/Newtonsoft.Json@13.0.3","pkg:nuget/System.Net.Http@4.3.4"]'
check "the dependency edges to them go too" \
    "$(jq -c '.dependencies' "$WORK/n.json")" '[{"dependsOn":["pkg:nuget/Newtonsoft.Json@13.0.3"],"ref":"app"}]'

echo "== completeness: npm-excluded =="
cat > "$WORK/c.json" <<'E'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"component":{"type":"application","name":"app","bom-ref":"app"},
   "properties":[{"name":"bomlens:pipeline-step-failed","value":"npm-excluded:private-lib"}]},
 "components":[{"type":"library","name":"express","version":"4.19.2","purl":"pkg:npm/express@4.19.2","bom-ref":"e"}]}
E
bash "$LIB/assess-completeness.sh" "$WORK/c.json" "$WORK/c" >/dev/null 2>&1
check "resolution-failed names the dependency left out" \
    "$(jq -r '[.. | objects | select(.code? == "resolution-failed") | .detail] | first // ""' "$WORK/c_completeness.json")" "npm-excluded:private-lib"

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
