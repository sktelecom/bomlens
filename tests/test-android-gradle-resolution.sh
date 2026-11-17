#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-android-gradle-resolution.sh: No-Docker checks for how an Android Gradle
# project is read before and around the build.
#
#   - android_api finds the highest compileSdk across the build files,
#     build-logic/ and buildSrc/ sources and the version catalog.
#   - gradle-version-catalog.sh lists the libraries a version catalog declares.
#   - android_wrapper_jdk_check warns about a Gradle wrapper that cannot run on
#     the SDK image's Java 21.
#   - stage1_fail_reason reads "Gradle build daemon disappeared" as oom.
#   - build-prep.sh leaves --no-configuration-cache out of a build with
#     Isolated Projects, and runs again without it on Gradle's refusal.
#
# Fixtures: tests/fixtures/journey/android-catalog, android-old-wrapper.
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

# shellcheck source=docker/lib/source-detect.sh
. "$LIB/source-detect.sh"

echo "== android_api =="
check "compileSdk = 37 in build-logic, the catalog key and a variable in app/ give 37" \
    "$(android_api "$FIX/android-catalog")" 37

d="$WORK/plain"; mkdir -p "$d/app"
check "no compileSdk anywhere gives the default ($ANDROID_API_DEFAULT)" "$(android_api "$d")" "$ANDROID_API_DEFAULT"
printf 'android { compileSdk = 33 }\n' > "$d/app/build.gradle.kts"
check "compileSdk = 33 in app/build.gradle.kts" "$(android_api "$d")" 33
printf 'android { compileSdkVersion 34 }\n' > "$d/build.gradle"
check "the largest of root 34 and app 33 wins" "$(android_api "$d")" 34
mkdir -p "$d/buildSrc/src/main/kotlin"
printf 'android { compileSdk { version = release(36) } }\n' > "$d/buildSrc/src/main/kotlin/Conv.kt"
check "release(36) in buildSrc raises it to 36" "$(android_api "$d")" 36
mkdir -p "$d/gradle"
printf '[versions]\nandroid_compile_sdk = 35\n' > "$d/gradle/libs.versions.toml"
check "a catalog key below the others does not lower it" "$(android_api "$d")" 36
printf '[versions]\nandroid-compileSdk = "38"\nminSdk = "21"\n' > "$d/gradle/libs.versions.toml"
check "a quoted catalog value of 38 raises it; minSdk is not read" "$(android_api "$d")" 38
d2="$WORK/build-dir"; mkdir -p "$d2/build-logic/build/generated"
printf 'compileSdk = 99\n' > "$d2/build-logic/build/generated/X.kt"
check "a build output folder inside build-logic is not read" "$(android_api "$d2")" "$ANDROID_API_DEFAULT"
# A scan under set -e must not stop on a tree with nothing to read.
if ( set -eo pipefail; android_api "$WORK/plain-none" >/dev/null ); then
    pass "a missing folder does not fail under set -e"
else
    fail "android_api failed under set -e on a missing folder"
fi

echo "== gradle-version-catalog.sh =="
out="$WORK/catalog.json"
bash "$LIB/gradle-version-catalog.sh" "$FIX/android-catalog" "$out" 1.0 2>"$WORK/catalog.err"
check "exit code 0 for a catalog" "$?" 0
check "the seven libraries with a version are listed (one without a version skipped)" \
    "$(jq '.components | length' "$out")" 7
check "module form with version.ref: okhttp 4.12.0" \
    "$(jq -r '[.components[] | select(.name == "okhttp") | .purl] | first' "$out")" "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0"
check "group and name form with version.ref" \
    "$(jq -r '[.components[] | select(.name == "core-ktx") | .purl] | first' "$out")" "pkg:maven/androidx.core/core-ktx@1.13.1"
check "string form group:artifact:version" \
    "$(jq -r '[.components[] | select(.name == "gson") | .purl] | first' "$out")" "pkg:maven/com.google.code.gson/gson@2.10.1"
check "version = { strictly = ... }" \
    "$(jq -r '[.components[] | select(.name == "timber") | .version] | first' "$out")" "5.0.1"
check "a library with no version is not listed" \
    "$(jq '[.components[] | select(.name == "managed-by-bom")] | length' "$out")" 0
check "every component carries bomlens:source=version-catalog" \
    "$(jq '[.components[] | select((.properties // []) | any(.name == "bomlens:source" and .value == "version-catalog") | not)] | length' "$out")" 0
check "the document is CycloneDX" "$(jq -r '.bomFormat' "$out")" CycloneDX
mkdir -p "$WORK/empty"
bash "$LIB/gradle-version-catalog.sh" "$WORK/empty" "$WORK/none.json" 1.0 2>/dev/null
check "no catalog: exit code 3" "$?" 3
bash "$LIB/gradle-version-catalog.sh" "$WORK/no-such-dir" "$WORK/none.json" 1.0 2>/dev/null
check "no such folder: exit code 1" "$?" 1

echo "== android_wrapper_jdk_check =="
msg="$(android_wrapper_jdk_check "$FIX/android-old-wrapper")"
android_wrapper_jdk_check "$FIX/android-old-wrapper" quiet
check "Gradle 6.5 is recorded as not running on Java 21" "$ANDROID_WRAPPER_JDK_BAD" "6.5.0"
case "$msg" in *"does not run on the Java 21"*"gradle-wrapper.properties"*"BASE_JDK_IMAGE"*) pass "the warning names the cause and both fixes" ;; *) fail "warning text" "$msg" ;; esac
case "$msg" in *"Java 21에서 실행되지 않습니다"*"BASE_JDK_IMAGE"*) pass "the Korean pair is printed" ;; *) fail "Korean warning text" "$msg" ;; esac
msg="$(android_wrapper_jdk_check "$FIX/android-old-wrapper" quiet)"
check "quiet mode prints nothing" "$msg" ""
android_wrapper_jdk_check "$FIX/android-old-wrapper" quiet
check "quiet mode still sets the versions" "$ANDROID_WRAPPER_JDK_BAD" "6.5.0"
w="$WORK/new-wrapper"; mkdir -p "$w/gradle/wrapper"
printf '#!/bin/sh\n' > "$w/gradlew"; : > "$w/build.gradle"
printf 'distributionUrl=https\\://services.gradle.org/distributions/gradle-8.5-bin.zip\n' > "$w/gradle/wrapper/gradle-wrapper.properties"
msg="$(android_wrapper_jdk_check "$w")"
android_wrapper_jdk_check "$w" quiet
check "Gradle 8.5 runs on Java 21: no warning, nothing recorded" "$msg|$ANDROID_WRAPPER_JDK_BAD" "|"
check "a folder with no wrapper: nothing recorded" "$(android_wrapper_jdk_check "$WORK/plain" quiet; echo "$ANDROID_WRAPPER_JDK_BAD")" ""

echo "== stage1_fail_reason =="
printf 'FAILURE: Build failed with an exception.\nGradle build daemon disappeared unexpectedly (it may have been killed or may have crashed)\n' > "$WORK/daemon.log"
check "a vanished Gradle daemon is oom" "$(stage1_fail_reason false "$WORK/daemon.log" 1)" oom
printf 'cdxgen: some internal error\n' > "$WORK/other.log"
check "another failure stays cdxgen-crash" "$(stage1_fail_reason false "$WORK/other.log" 1)" cdxgen-crash

echo "== build-prep.sh: Isolated Projects =="
PREP="$ROOT_DIR/docker/lib/build-prep.sh"
block=$(sed -n '/^# Gradle (java-gradle \/ Android)/,/^# A root Gradle build that did not reach/p' "$PREP" | sed '$d')
fns=$(sed -n '/^mark_prep_failed() {/,/^}/p; /^unmark_prep_failed() {/,/^}/p; /^prep_step() {/,/^}/p; /^wrapper_shell() {/,/^}/p' "$PREP")
if [ -z "$block" ] || [ -z "$fns" ]; then
    fail "could not extract the Gradle block of build-prep.sh"
else
    bin="$WORK/bin"; mkdir -p "$bin" "$WORK/home"
    printf '#!/bin/sh\nexit 0\n' > "$bin/gradle"; chmod +x "$bin/gradle"
    cat > "$WORK/gradlew" <<'STUB'
#!/bin/sh
# A stand-in Gradle: with Isolated Projects it refuses --no-configuration-cache.
case " $* " in *" --version "*) exit 0 ;; esac
echo "$*" >> "$STUB_CALLS"
for a in "$@"; do
    case "$a" in
        --no-configuration-cache)
            echo "FAILURE: Configuration Cache cannot be disabled when Isolated Projects is enabled." >&2
            exit 1 ;;
        -Dbomlens.gradle.out=*) out="${a#-Dbomlens.gradle.out=}" ;;
        bomlensRuntime) mkdir -p "$out"; printf 'P\t:\nH\t:\nZ\t1\nR\t:\torg.example:lib:1.0\n' > "$out/p.txt"; exit 0 ;;
    esac
done
exit 0
STUB
    chmod +x "$WORK/gradlew"
    prelude='log() { echo "[build-prep] $*"; }
opted_out() { case "$1" in 1|true) return 0 ;; esac; return 1; }
gradle_settings_copy() { :; }
run_supervised_timeout() { shift; "$@"; }
PREP_FAILED=""; PREP_APPLIED=""; PREP_TIMEOUT_GRADLE=5'
    report='echo "FAILED:$PREP_FAILED"
echo "SET:$( [ -n "$GRADLE_RUNTIME_SET" ] && [ -f "$GRADLE_RUNTIME_SET" ] && tr "\n" " " < "$GRADLE_RUNTIME_SET")"'
    run_prep() {  # <gradle.properties text, or empty for none>
        local p="$WORK/proj"
        rm -rf "$p"; mkdir -p "$p"; : > "$p/build.gradle"; cp "$WORK/gradlew" "$p/gradlew"
        if [ -n "$1" ]; then printf '%s\n' "$1" > "$p/gradle.properties"; fi
        : > "$WORK/calls"
        ( cd "$p" && env -u GRADLE_USER_HOME -u ANDROID_HOME -u GRADLE_INCLUDED_BUILDS -u BOMLENS_GRADLE_FULL_GRAPH \
            PATH="$bin:$PATH" HOME="$WORK/home" STUB_CALLS="$WORK/calls" \
            sh -c "$prelude
$fns
$block
$report" ) 2>&1
    }
    o=$(run_prep 'org.gradle.unsafe.isolated-projects=true')
    check "isolated-projects in gradle.properties: one run, without --no-configuration-cache" \
        "$(wc -l < "$WORK/calls" | tr -d ' ')|$(grep -c -- '--no-configuration-cache' "$WORK/calls" | tr -d ' ')" "1|0"
    check "isolated-projects in gradle.properties: the step is not left failed" "$(printf '%s\n' "$o" | sed -n 's/^FAILED://p')" ""
    run_prep 'org.gradle.isolated-projects = true' >/dev/null
    check "the other property name is read too" "$(grep -c -- '--no-configuration-cache' "$WORK/calls" | tr -d ' ')" 0
    run_prep 'org.gradle.isolated-projects=false' >/dev/null
    case "$(head -n 1 "$WORK/calls")" in *--no-configuration-cache*) pass "isolated-projects=false keeps the option on the first run" ;; *) fail "a false value must not turn the option off" "$(cat "$WORK/calls")" ;; esac
    o=$(run_prep '')
    check "no property: the first run has --no-configuration-cache and Gradle's refusal triggers a second run without it" \
        "$(wc -l < "$WORK/calls" | tr -d ' ')|$(grep -c -- '--no-configuration-cache' "$WORK/calls" | tr -d ' ')" "2|1"
    check "the second run succeeded: the step is not left failed" "$(printf '%s\n' "$o" | sed -n 's/^FAILED://p')" ""
    case "$o" in *"running again without --no-configuration-cache"*) pass "the log says why it ran again" ;; *) fail "no log line for the second run" "$o" ;; esac
fi

echo
echo "Result: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
