#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-java-build-tool.sh: No-Docker checks for two Java source-scan details.
#
#   - build tool choice (BOMLENS_BUILD_TOOL) for a folder holding both pom.xml
#     and build.gradle: the block in build-prep.sh, the SBOM property it writes,
#     and the --build-tool option of scan-sbom.sh.
#   - license exceptions: "X OR <exception id>" and "... with <exception name>"
#     become "X WITH <exception id>" in normalize-sbom.sh, and are not classified
#     as strong copyleft or as a conflict.
#
# Fixtures: tests/fixtures/journey/java-both-tools, java-license-exceptions.
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

echo "== build tool choice in build-prep.sh =="
# The block that decides, run on its own in a copy of the fixture.
sed -n '/^BUILD_TOOL_CHOSEN=""; BUILD_TOOL_WHY/,/^fi$/p' "$LIB/build-prep.sh" > "$WORK/choice.sh"
if [ -s "$WORK/choice.sh" ]; then pass "the choice block is in build-prep.sh"; else fail "the choice block is in build-prep.sh"; fi
choose() {  # <dir> <BOMLENS_BUILD_TOOL value or ->
    ( cd "$1" || exit 1
      if [ "$2" = "-" ]; then unset BOMLENS_BUILD_TOOL; else export BOMLENS_BUILD_TOOL="$2"; fi
      # shellcheck disable=SC1090,SC1091
      . "$WORK/choice.sh" >/dev/null 2>&1
      echo "$BUILD_TOOL_CHOSEN|$BUILD_TOOL_EXCLUDE" )
}
cp -R "$FIX/java-both-tools" "$WORK/both"
check "unset: Gradle stays the default" "$(choose "$WORK/both" -)" "gradle|"
check "auto: Gradle stays the default" "$(choose "$WORK/both" auto)" "gradle|"
check "maven: the Gradle files are left out" "$(choose "$WORK/both" maven)" 'maven|**/build.gradle **/build.gradle.kts **/settings.gradle **/settings.gradle.kts'
check "gradle: pom.xml is left out" "$(choose "$WORK/both" gradle)" 'gradle|**/pom.xml'
check "an unknown value falls back to auto" "$(choose "$WORK/both" bogus)" "gradle|"
mkdir "$WORK/mvn" "$WORK/gr" "$WORK/kts"
cp "$FIX/java-both-tools/pom.xml" "$WORK/mvn/"
cp "$FIX/java-both-tools/build.gradle" "$WORK/gr/"
cp "$FIX/java-both-tools/pom.xml" "$WORK/kts/"
: > "$WORK/kts/build.gradle.kts"
check "pom.xml only: no choice is made" "$(choose "$WORK/mvn" maven)" "|"
check "build.gradle only: no choice is made" "$(choose "$WORK/gr" maven)" "|"
check "pom.xml with build.gradle.kts counts as both" "$(choose "$WORK/kts" maven | cut -d'|' -f1)" "maven"

echo "== build-prep.sh reads the choice where it matters =="
if grep -q 'BOMLENS_BUILD_TOOL' "$LIB/source-detect.sh"; then pass "BOMLENS_BUILD_TOOL is passed to the container by name"; else fail "BOMLENS_BUILD_TOOL is passed to the container by name"; fi
check "Maven runs for a chosen maven" "$(grep -c '\[ "\$BUILD_TOOL_CHOSEN" = maven \]' "$LIB/build-prep.sh")" "1"
check "Gradle steps are skipped for a chosen maven" "$(grep -c '\[ "\$BUILD_TOOL_CHOSEN" != maven \]' "$LIB/build-prep.sh")" "4"

echo "== bomlens:build-tool-choice on the SBOM =="
sed -n "/<<'BT_JS'/,/^BT_JS\$/p" "$LIB/build-prep.sh" | sed '1d;$d' > "$WORK/bt.js"
echo '{"bomFormat":"CycloneDX","metadata":{"properties":[{"name":"a","value":"b"}]},"components":[]}' > "$WORK/bom.json"
node "$WORK/bt.js" "$WORK/bom.json" maven "requested with --build-tool maven"
check "tool recorded" "$(jq -r '.metadata.properties[] | select(.name=="bomlens:build-tool-choice") | .value' "$WORK/bom.json")" "maven"
check "reason recorded" "$(jq -r '.metadata.properties[] | select(.name=="bomlens:build-tool-choice-why") | .value' "$WORK/bom.json")" "requested with --build-tool maven"
check "other properties kept" "$(jq -r '.metadata.properties[] | select(.name=="a") | .value' "$WORK/bom.json")" "b"
node "$WORK/bt.js" "$WORK/bom.json" gradle "x"
check "a second write replaces, not adds" "$(jq '[.metadata.properties[] | select(.name=="bomlens:build-tool-choice")] | length' "$WORK/bom.json")" "1"

echo "== scan-sbom.sh --build-tool =="
out=$(bash "$ROOT_DIR/scripts/scan-sbom.sh" --build-tool bogus 2>&1); rc=$?
check "an unknown tool exits 1" "$rc" "1"
case "$out" in *"--build-tool takes auto, maven or gradle"*) pass "the message names the values" ;; *) fail "the message names the values" "$out" ;; esac
case "$(bash "$ROOT_DIR/scripts/scan-sbom.sh" --help 2>&1)" in *"--build-tool <tool>"*) pass "--help lists --build-tool" ;; *) fail "--help lists --build-tool" ;; esac

echo "== license exceptions =="
cp "$FIX/java-license-exceptions/sbom-exceptions.cdx.json" "$WORK/lic.json"
bash "$LIB/normalize-sbom.sh" "$WORK/lic.json" >/dev/null 2>&1
lic() { jq -c --arg n "$1" '.components[] | select(.name==$n) | .licenses' "$WORK/lic.json"; }
check "jakarta.annotation-api: exception joined with WITH" "$(lic jakarta.annotation-api)" '[{"expression":"GPL-2.0-or-later WITH Classpath-exception-2.0"}]'
check "jakarta.transaction-api: EPL choice kept as OR" "$(lic jakarta.transaction-api)" '[{"expression":"EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0"}]'
check "mysql-connector-j: Universal FOSS Exception" "$(lic mysql-connector-j)" '[{"expression":"GPL-2.0-only WITH Universal-FOSS-exception-1.0"}]'
check "GPL with the Classpath Exception named in words" "$(lic gpl-cp)" '[{"expression":"GPL-2.0-only WITH Classpath-exception-2.0"}]'
check "a mix with CDDL is left as it was" "$(lic javax.annotation-api | jq -r '.[0].license.name')" "CDDL + GPLv2 with classpath exception"
cp "$WORK/lic.json" "$WORK/lic2.json"
bash "$LIB/normalize-sbom.sh" "$WORK/lic2.json" >/dev/null 2>&1
check "a second normalize pass changes nothing" "$(jq -c '[.components[].licenses]' "$WORK/lic2.json")" "$(jq -c '[.components[].licenses]' "$WORK/lic.json")"
check "MIT OR Apache-2.0 is untouched" "$(lic plain)" '[{"expression":"MIT OR Apache-2.0"}]'
check "plain GPL-2.0-only is untouched" "$(lic gpl-plain)" '[{"license":{"id":"GPL-2.0-only"}}]'
c=$(jq -r "$(cat "$LIB/license-flags.jq")
.components[] | [.name, ([.licenses[] | (.license.id // .license.name // .expression)] | map(license_class(.)) | .[0])] | @tsv" "$WORK/lic.json" 2>&1)
cls() { echo "$c" | awk -F'\t' -v n="$1" '$1==n{print $2}'; }
check "jakarta.annotation-api is weak copyleft" "$(cls jakarta.annotation-api)" "weak-copyleft"
check "jakarta.transaction-api is weak copyleft" "$(cls jakarta.transaction-api)" "weak-copyleft"
check "mysql-connector-j is weak copyleft" "$(cls mysql-connector-j)" "weak-copyleft"
check "plain GPL-2.0-only stays strong copyleft" "$(cls gpl-plain)" "strong-copyleft"
v=$(jq -r --slurpfile compat "$LIB/license-compat.json" "$(cat "$LIB/license-flags.jq")
.components[] | select(.name==\"mysql-connector-j\") | component_license_conflict(\"Apache-2.0\"; \$compat[0]) | .verdict" "$WORK/lic.json" 2>&1)
case "$v" in incompatible|*error*) fail "mysql-connector-j is not an incompatible verdict against Apache-2.0" "$v" ;; *) pass "mysql-connector-j is not an incompatible verdict against Apache-2.0 ($v)" ;; esac

echo
echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
