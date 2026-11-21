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
#   - Maven multi-module build: a sibling module named in the jar fetch's
#     errors is not a failed step, a dependency no repository has still is,
#     and a module scanned without its parent POM gets the
#     maven-parent-outside-scan hint, which the completeness result turns into
#     its fix.
#
# Fixtures: tests/fixtures/journey/java-both-tools, java-license-exceptions,
# maven-multi-module.
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
check "Gradle steps are skipped for a chosen maven" "$(grep -c '\[ "\$BUILD_TOOL_CHOSEN" != maven \]' "$LIB/build-prep.sh")" "5"

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

echo "== Maven multi-module build: the jar fetch's errors =="
# The jar fetch block of build-prep.sh, run with a stand-in mvn that prints
# the [ERROR] lines given in MM_ERR (as --fail-never leaves them, exit 0).
mm_block=$(sed -n '/^# Maven component hashes/,/^fi$/p' "$LIB/build-prep.sh")
mm_fns=$(sed -n '/^xml_without_comments() {/,/^}/p' "$LIB/build-prep.sh")
if [ -z "$mm_block" ] || [ -z "$mm_fns" ]; then
    fail "could not extract the Maven block of build-prep.sh"
else
    mkdir -p "$WORK/mm-bin" "$WORK/mm-home"
    cat > "$WORK/mm-bin/mvn" <<'STUB'
#!/bin/sh
[ -z "$MM_ERR" ] || printf '%s\n' "$MM_ERR"
exit 0
STUB
    chmod +x "$WORK/mm-bin/mvn"
    mm_prelude='log() { echo "[build-prep] $*"; }
mark_prep_failed() { echo "MARK-FAILED $1"; }
prep_cause() { echo "CAUSE $1: $2"; }
prep_hint() { echo "HINT $1"; }
run_supervised_timeout() { shift; "$@"; }
PREP_TIMEOUT_DEFAULT=5'
    mm_run() {  # <dir> <errors>
        ( cd "$1" && PATH="$WORK/mm-bin:$PATH" HOME="$WORK/mm-home" MM_ERR="$2" MAVEN_OPTS="" \
            MAVEN_SETTINGS_ARGS="" bash -c "$mm_prelude
$mm_fns
$mm_block" 2>&1 )
    }
    cp -R "$FIX/maven-multi-module" "$WORK/mm"
    # Maven 3.10 lists each unresolved dependency on its own line.
    sib='[ERROR] Failed to execute goal on project web: Could not resolve dependencies for project example.mm:web:jar:1.0.0
[ERROR] dependency: example.mm:core:jar:1.0.0 (compile)
[ERROR] 	prefixes: Path example/mm/core/1.0.0/core-1.0.0.jar NOT allowed from central
[ERROR] -> [Help 1]'
    o=$(mm_run "$WORK/mm" "$sib")
    case "$o" in *MARK-FAILED*) fail "a sibling module is not a failed step" "$o" ;; *) pass "a sibling module of the build (core) is not a failed step" ;; esac
    case "$o" in *"modules of this build (core) are not built"*) pass "the log names the sibling module" ;; *) fail "the log names the sibling module" "$o" ;; esac
    o=$(mm_run "$WORK/mm" '[ERROR] Failed to execute goal on project web: Could not resolve dependencies for project example.mm:web:jar:1.0.0: The following artifacts could not be resolved: example.mm:core:jar:1.0.0 (absent): Could not find artifact example.mm:core:jar:1.0.0 in central (https://repo.maven.apache.org/maven2) -> [Help 1]')
    case "$o" in *MARK-FAILED*) fail "Maven 3.9 one-line form: a sibling module is not a failed step" "$o" ;; *) pass "Maven 3.9 one-line form: a sibling module is not a failed step" ;; esac
    o=$(mm_run "$WORK/mm" "$sib
[ERROR] dependency: com.example.nope:nope:jar:9.9.9 (compile)
[ERROR] 	Could not find artifact com.example.nope:nope:jar:9.9.9 in central (https://repo.maven.apache.org/maven2)")
    case "$o" in *"MARK-FAILED maven-dependency-resolve"*) pass "a dependency no repository has, beside a sibling module, is still a failed step" ;; *) fail "a missing dependency beside a sibling module is still a failed step" "$o" ;; esac
    case "$o" in *"CAUSE maven-dependency-resolve: Maven could not resolve com.example.nope:nope:jar:9.9.9"*) pass "the cause names the missing dependency, not the sibling" ;; *) fail "the cause names the missing dependency" "$o" ;; esac
    o=$(mm_run "$WORK/mm" '[ERROR] Failed to execute goal on project web: Could not resolve dependencies for project example.mm:web:jar:1.0.0
[ERROR] dependency: example.mm:core:jar:0.9.0 (compile)')
    case "$o" in *"MARK-FAILED maven-dependency-resolve"*) pass "a sibling at another version than the build's is not excused" ;; *) fail "a sibling at another version than the build's is not excused" "$o" ;; esac
    # A module whose version comes from a property matches any version.
    cp -R "$FIX/maven-multi-module" "$WORK/mm-rev"
    sed -i.bak 's|<artifactId>core</artifactId>|<artifactId>core</artifactId><version>${revision}</version>|' "$WORK/mm-rev/core/pom.xml"
    o=$(mm_run "$WORK/mm-rev" "$sib")
    case "$o" in *MARK-FAILED*) fail "a module with a \${revision} version is a module of the build" "$o" ;; *) pass "a module with a \${revision} version is a module of the build" ;; esac
    # A module scanned alone: its parent POM is one folder up, outside the scan.
    mkdir -p "$WORK/web-only"; cp "$FIX/maven-multi-module/web/pom.xml" "$WORK/web-only/"
    par='[ERROR] [ERROR] Some problems were encountered while processing the POMs:
[ERROR] The build could not read 1 project -> [Help 1]
[ERROR]   The project example.mm:web:1.0.0 (/app/pom.xml) has 1 error
[ERROR]     Non-resolvable parent POM for example.mm:web:1.0.0: The following artifacts could not be resolved: example.mm:parent:pom:1.0.0 (absent): Could not find artifact example.mm:parent:pom:1.0.0 and '"'"'parent.relativePath'"'"' points at wrong local POM @ line 4, column 11 -> [Help 2]'
    o=$(mm_run "$WORK/web-only" "$par")
    case "$o" in *"MARK-FAILED maven-dependency-tree"*) pass "a parent POM outside the folder: the dependency tree is the failed step" ;; *) fail "a parent POM outside the folder: the dependency tree is the failed step" "$o" ;; esac
    case "$o" in *"MARK-FAILED maven-dependency-jars"*) fail "a parent POM outside the folder is not recorded as a jar fetch failure" "$o" ;; *) pass "a parent POM outside the folder is not recorded as a jar fetch failure" ;; esac
    case "$o" in *"HINT maven-parent-outside-scan"*) pass "the hint names the parent POM outside the folder" ;; *) fail "the hint names the parent POM outside the folder" "$o" ;; esac
    case "$o" in *"parent POM example.mm:parent:1.0.0 at ../pom.xml, outside the scanned folder"*"Scan the top-level folder"*) pass "the log says where the parent is and what to scan" ;; *) fail "the log says where the parent is and what to scan" "$o" ;; esac
    # A parent from a repository (empty relativePath) that is missing is an
    # ordinary download failure, without the hint.
    mkdir -p "$WORK/repo-parent"
    sed 's|<version>1.0.0</version></parent>|<version>1.0.0</version><relativePath/></parent>|' "$FIX/maven-multi-module/web/pom.xml" > "$WORK/repo-parent/pom.xml"
    o=$(mm_run "$WORK/repo-parent" "$par")
    case "$o" in *"HINT maven-parent-outside-scan"*) fail "a repository parent gets no outside-folder hint" "$o" ;; *) pass "a repository parent (empty relativePath) gets no outside-folder hint" ;; esac
fi

echo "== completeness: a cause and a hint on a failed Maven step =="
cat > "$WORK/hint.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"properties":[
 {"name":"bomlens:pipeline-step-failed","value":"maven-dependency-tree"},
 {"name":"bomlens:pipeline-step-cause","value":"maven-dependency-tree: Non-resolvable parent POM example.mm:parent:1.0.0 (../pom.xml is outside the scanned folder)"},
 {"name":"bomlens:resolution-hint","value":"maven-parent-outside-scan"}]},
 "components":[{"type":"library","name":"spring-web","purl":"pkg:maven/org.springframework/spring-web@5.3.20"}]}
EOF
check "the grade stays partial" "$(bash "$LIB/assess-completeness.sh" "$WORK/hint.json" "$WORK/hint")" "partial"
case "$(jq -r '.reasons[0].fix.en' "$WORK/hint_completeness.json")" in
    *"Non-resolvable parent POM"*"Scan the top-level folder of the build"*) pass "the fix names the cause and says to scan the top-level folder" ;;
    *) fail "the fix names the cause and says to scan the top-level folder" "$(jq -r '.reasons[0].fix.en' "$WORK/hint_completeness.json")" ;;
esac
case "$(jq -r '.reasons[0].message.ko' "$WORK/hint_completeness.json")" in
    *"부모 POM이 폴더 밖에"*) pass "the Korean message names the parent POM" ;;
    *) fail "the Korean message names the parent POM" "$(jq -r '.reasons[0].message.ko' "$WORK/hint_completeness.json")" ;;
esac

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
