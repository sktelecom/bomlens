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
check "EALLOWGIT drops the git dependency whose source the message names" \
    "$(drop private-lib 'github:acme/private-lib' 'npm error code EALLOWGIT
npm error Fetching git+ssh://git@github.com/acme/private-lib.git is not allowed')" "private-lib "
check "EALLOWGIT without a named source drops nothing" \
    "$(drop private-lib 'github:acme/private-lib' 'npm error code EALLOWGIT')" ""
printf '{"dependencies":{"cfg":"acme/config#v2","bad":"git+https://git.corp/team/bad.git"}}\n' > "$WORK/package.json"
printf '%s\n' "npm error command git ls-remote https://git.corp/team/bad.git" "npm error fatal: could not read Username for https://git.corp: config" > "$WORK/err"
check "a short repository name elsewhere in the message does not drop another dependency" \
    "$(node "$WORK/npmdrop.js" "$WORK/package.json" "$WORK/err" | tr '\n' ' ')" "bad "
check "a development-only dependency is reported as such" \
    "$(printf '{"devDependencies":{"ghost":"^1.0.0"}}\n' > "$WORK/package.json"; printf '%s\n' 'npm error 404 Not Found - GET https://registry.npmjs.org/ghost - Not found' > "$WORK/err"; node "$WORK/npmdrop.js" "$WORK/package.json" "$WORK/err" | tr '\t' '~' | tr '\n' ' ')" "ghost~dev "
check "E404 for a scoped package" \
    "$(drop @acme/ghost '^1.0.0' 'npm error 404 Not Found - GET https://registry.npmjs.org/@acme%2fghost - Not found')" "@acme/ghost "
check "ETARGET" \
    "$(drop nover '^99.0.0' 'npm error notarget No matching version found for nover@^99.0.0.')" "nover "
check "an unrelated error drops nothing" \
    "$(drop other '1.0.0' 'npm error code ERESOLVE')" ""
check "...and leaves package.json alone" "$(jq -c '.dependencies | keys' "$WORK/package.json")" '["express","other"]'

echo "== npm: the retry block, with a stub npm =="
# The block of build-prep.sh that resolves the production set, run on its own
# against a stub npm that cannot fetch private-lib.
sed -n '/^NODE_PROD_SET=""$/,/^# --- build the cdxgen argument list/p' "$LIB/build-prep.sh" | sed '$d' > "$WORK/npmblock.sh"
mkdir -p "$WORK/bin"
cat > "$WORK/bin/npm" <<'E'
#!/bin/sh
if grep -q private-lib package.json; then
  echo "npm error code 128" >&2
  echo "npm error command git --no-replace-objects ls-remote https://git.invalid.example/team/private-lib.git" >&2
  exit 128
fi
echo '{"name":"x","lockfileVersion":3,"packages":{"":{},"node_modules/express":{"version":"4.19.2"},"node_modules/lodash":{"version":"4.17.21"}}}' > package-lock.json
E
chmod +x "$WORK/bin/npm"
cat > "$WORK/npmprelude.sh" <<'E'
log() { echo "[build-prep] $*"; }
opted_out() { case "$1" in 1|true) return 0 ;; esac; return 1; }
run_supervised_timeout() { shift; "$@"; }
PREP_FAILED=""; PREP_APPLIED=""; PREP_TIMEOUT_DEFAULT=900
prep_step() { _l="$1"; shift 2; PREP_APPLIED="$PREP_APPLIED $_l"; "$@"; _r=$?; [ "$_r" -eq 0 ] || PREP_FAILED="${PREP_FAILED:+$PREP_FAILED }$_l"; return "$_r"; }
mark_prep_failed() { PREP_FAILED="${PREP_FAILED:+$PREP_FAILED }$1"; }
unmark_prep_failed() { _n=""; for _x in $PREP_FAILED; do [ "$_x" = "$1" ] || _n="${_n:+$_n }$_x"; done; PREP_FAILED="$_n"; }
E
run_npm_block() {  # <dir>
    ( cd "$1" && PATH="$WORK/bin:$PATH" bash -c '. "$1"; . "$2"; echo "FAILED=[$PREP_FAILED]"; echo "SET=$(cat "$NODE_PROD_SET" 2>/dev/null | tr "\n" " ")"' _ "$WORK/npmprelude.sh" "$WORK/npmblock.sh" 2>/dev/null )
}
rm -rf "$WORK/n1"; cp -R "$FIX/npm-git-dep" "$WORK/n1"
out=$(run_npm_block "$WORK/n1")
check "no lock file: the dependency is left out and named as a failed step" \
    "$(echo "$out" | grep '^FAILED=')" "FAILED=[npm-excluded:private-lib]"
check "...the resolved lock file is handed to cdxgen" "$([ -f "$WORK/n1/package-lock.json" ] && echo placed)" placed
check "...package.json is untouched" "$(jq -c '.dependencies | keys' "$WORK/n1/package.json")" '["express","lodash","private-lib","uuid"]'
rm -rf "$WORK/n2"; cp -R "$FIX/npm-git-dep" "$WORK/n2"; : > "$WORK/n2/yarn.lock"
out=$(run_npm_block "$WORK/n2")
check "a yarn.lock project is left alone: no lock file placed" "$([ -f "$WORK/n2/package-lock.json" ] && echo placed || echo none)" none
check "...and nothing is recorded as excluded" "$(echo "$out" | grep '^FAILED=')" "FAILED=[npm-production-set]"

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
cat > "$WORK/n2.json" <<'E'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"s"}},
 "components":[{"type":"library","name":"System","purl":"pkg:nuget/System","bom-ref":"pkg:nuget/System"}]}
E
MODE=ANALYZE bash "$LIB/normalize-sbom.sh" "$WORK/n2.json" >/dev/null 2>&1
check "a supplier SBOM under analysis keeps its versionless entry" "$(jq '.components | length' "$WORK/n2.json")" 1
cat > "$WORK/n3.json" <<'E'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"s"}},
 "components":[{"type":"library","name":"System.Net.Http","purl":"pkg:nuget/System.Net.Http","bom-ref":"x"},
               {"type":"library","name":"System","purl":"pkg:nuget/System@","bom-ref":"y"}]}
E
bash "$LIB/normalize-sbom.sh" "$WORK/n3.json" >/dev/null 2>&1
check "a real NuGet package name stays; the empty-version form of a base assembly goes" "$(jq -r '[.components[].name] | join(" ")' "$WORK/n3.json")" "System.Net.Http"
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

echo "== Gradle version catalog: table order, two files, ranges, comments =="
mkdir -p "$WORK/cat/gradle"
printf '[versions]\nkotlin = "1.9.0"\n' > "$WORK/cat/gradle/a.versions.toml"
cat > "$WORK/cat/gradle/libs.versions.toml" <<'E'
[libraries] # the libs
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
k2 = { module = "org.jetbrains.kotlin:kotlin-reflect", version.ref = "kotlin" }
range = { module = "g:range", version = { strictly = "[1.0, 2.0[", prefer = "1.5" } }
onlyrange = { module = "g:onlyrange", version = { strictly = "[1.0, 2.0[" } }
dyn = { module = "g:dyn", version = "1.+" }
lit = 'g:lit:1.0'
"quoted.key" = { module = "g:qk", version.ref = "okhttp" }

[versions]
okhttp = "4.12.0"
kotlin = "2.0.0"
E
bash "$LIB/gradle-version-catalog.sh" "$WORK/cat" "$WORK/cat/out.json" 1.0 >/dev/null 2>&1
check "libraries before [versions], files kept apart, ranges skipped, comments and quotes read" \
    "$(jq -r '[.components[].purl] | sort | join(" ")' "$WORK/cat/out.json")" \
    "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0 pkg:maven/g/lit@1.0 pkg:maven/g/qk@4.12.0 pkg:maven/g/range@1.5 pkg:maven/org.jetbrains.kotlin/kotlin-reflect@2.0.0"

echo "== Android wrapper check and a custom SDK image =="
check "the default image: an old wrapper is flagged" \
    "$(ANDROID_IMAGE_PREFIX=bomlens-android-sdk bash -c '. "$1"; android_wrapper_jdk_check "$2" quiet; echo "$ANDROID_WRAPPER_JDK_BAD"' _ "$LIB/source-detect.sh" "$FIX/android-old-wrapper")" "6.5.0"
check "a custom image prefix: nothing is flagged" \
    "$(ANDROID_IMAGE_PREFIX=my-android-sdk bash -c '. "$1"; android_wrapper_jdk_check "$2" quiet; echo "$ANDROID_WRAPPER_JDK_BAD"' _ "$LIB/source-detect.sh" "$FIX/android-old-wrapper")" ""

echo "== compositions with an excluded npm dependency =="
sed -n '/^mark_compositions_aggregate() {$/,/^}$/p' "$ROOT_DIR/docker/entrypoint.sh" > "$WORK/comp-fn.sh"
cat > "$WORK/comp.json" <<'E'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"component":{"type":"application","name":"app","bom-ref":"app"},
   "properties":[{"name":"bomlens:prep-step-applied","value":"npm-production-set"},
                 {"name":"bomlens:pipeline-step-failed","value":"npm-excluded:private-lib"}]},
 "components":[{"type":"library","name":"a","bom-ref":"a"},{"type":"library","name":"b","bom-ref":"b"}],
 "dependencies":[{"ref":"app","dependsOn":["a","b"]}]}
E
check "aggregate is incomplete, not complete" \
    "$(bash -c '. "$1"; SCAN_MODE=SOURCE; mark_compositions_aggregate "$2"; jq -r ".compositions[0].aggregate" "$2"' _ "$WORK/comp-fn.sh" "$WORK/comp.json" 2>/dev/null)" "incomplete"

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
