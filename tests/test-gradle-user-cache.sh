#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-gradle-user-cache.sh: No-Docker checks for the user's Gradle cache in a
# source scan, and for Gradle dependency entries that did not resolve.
#
#   - gradle_user_cache_dirs (scripts/scan-sbom.sh) lists the Gradle cache and
#     wrapper folders to mount: GRADLE_USER_HOME, a missing folder, the opt-out.
#   - The gradle user cache section of docker/lib/build-prep.sh sets
#     GRADLE_RO_DEP_CACHE, and adds --offline only when no repository the build
#     names answers (a local HTTP server and a closed port stand in for them).
#   - Offline, a wrapper's Gradle is copied from the user's wrapper folder, or
#     the image's Gradle runs instead.
#   - bomlens:gradle-user-cache is written on the SBOM.
#   - A Gradle report or runtime classpath read with unresolved (FAILED)
#     entries records gradle-dependencies as failed.
#
# Fixtures: tests/fixtures/gradle-user-cache (dependencies-offline.txt is the
# output of `gradle dependencies` from Gradle 8.14.5 with no network and an
# empty cache; it exited 0).
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREP="$ROOT_DIR/docker/lib/build-prep.sh"
FIX="$ROOT_DIR/tests/fixtures/gradle-user-cache"
WORK="$(mktemp -d)"
HTTP_PID=""
trap '[ -z "$HTTP_PID" ] || kill "$HTTP_PID" 2>/dev/null; chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }
check() {  # <label> <got> <want>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "got [$2], expected [$3]"; fi
}

echo "== gradle_user_cache_dirs (scan-sbom.sh) =="
_fn="$WORK/dirs.sh"
sed -n '/^gradle_user_cache_dirs() {/,/^}/p' "$ROOT_DIR/scripts/scan-sbom.sh" > "$_fn"
if [ -s "$_fn" ]; then
    h="$WORK/home"; mkdir -p "$h/.gradle/caches/modules-2" "$h/.gradle/wrapper/dists"
    check "HOME/.gradle: the cache and the wrapper folder" \
        "$(env -u GRADLE_USER_HOME -u BOMLENS_GRADLE_USER_CACHE HOME="$h" bash -c '. "$1"; gradle_user_cache_dirs' _ "$_fn" | tr '\n' ' ')" \
        "$h/.gradle/caches|/bomlens-user-cache/gradle $h/.gradle/wrapper/dists|/bomlens-user-cache/gradle-wrapper "
    g="$WORK/gh"; mkdir -p "$g/caches/modules-2"
    check "GRADLE_USER_HOME wins over ~/.gradle; no wrapper folder there, none listed" \
        "$(env -u BOMLENS_GRADLE_USER_CACHE HOME="$h" GRADLE_USER_HOME="$g" bash -c '. "$1"; gradle_user_cache_dirs' _ "$_fn" | tr '\n' ' ')" \
        "$g/caches|/bomlens-user-cache/gradle "
    mkdir -p "$WORK/nocache/.gradle/caches"
    check "a caches folder without modules-2 is not mounted" \
        "$(env -u GRADLE_USER_HOME HOME="$WORK/nocache" bash -c '. "$1"; gradle_user_cache_dirs' _ "$_fn")" ""
    check "no ~/.gradle: nothing, exit 0" \
        "$(env -u GRADLE_USER_HOME HOME="$WORK/none" bash -c 'set -e; . "$1"; gradle_user_cache_dirs; echo rc=$?' _ "$_fn")" "rc=0"
    check "BOMLENS_GRADLE_USER_CACHE=false: nothing" \
        "$(env -u GRADLE_USER_HOME HOME="$h" BOMLENS_GRADLE_USER_CACHE=false bash -c '. "$1"; gradle_user_cache_dirs' _ "$_fn")" ""
else
    fail "could not extract gradle_user_cache_dirs from scan-sbom.sh"
fi

echo "== build-prep.sh: the gradle user cache section =="
_sec="$WORK/section.sh"
{
    printf '%s\n' 'log() { echo "[build-prep] $*"; }'
    printf '%s\n' 'BUILD_TOOL_CHOSEN=""'
    sed -n '/^# --- gradle user cache ---$/,/^# --- end gradle user cache ---$/p' "$PREP"
    # shellcheck disable=SC2016
    printf '%s\n' 'echo "RO:${GRADLE_RO_DEP_CACHE:-}"; echo "STATE:$GRADLE_USER_CACHE_STATE"; echo "OFFLINE:$GRADLE_OFFLINE_ARG"; echo "ARGS:${GRADLE_ARGS:-}"'
} > "$_sec"
grep -q '^gradle_repository_probe() {' "$_sec" || fail "could not extract the gradle user cache section from build-prep.sh"
line() { printf '%s\n' "$1" | sed -n "s/^$2://p"; }
UC="$WORK/uc"; mkdir -p "$UC/gradle/modules-2"
run_section() {  # <project dir> [VAR=value ...]
    local p="$1"; shift
    ( cd "$p" && env -u GRADLE_RO_DEP_CACHE -u GRADLE_ARGS -u BOMLENS_GRADLE_USER_CACHE \
        PREP_USER_CACHE_ROOT="$UC" SETTINGS_ROOT="$WORK/no-settings" "$@" sh "$_sec" ) 2>&1
}
if command -v node >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    # A local server for a repository that answers, a closed port for one that does not.
    mkdir -p "$WORK/www"
    _port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
    _closed=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
    ( cd "$WORK/www" && exec python3 -m http.server "$_port" --bind 127.0.0.1 ) >/dev/null 2>&1 &
    HTTP_PID=$!
    _n=0; until curl -s -o /dev/null "http://127.0.0.1:$_port/" 2>/dev/null || [ "$_n" -ge 50 ]; do sleep 0.1; _n=$((_n + 1)); done

    on="$WORK/p-online"; mkdir -p "$on"
    printf "repositories { maven { url 'http://127.0.0.1:%s/m2/' } }\n" "$_port" > "$on/build.gradle"
    o=$(run_section "$on")
    check "a repository answers: GRADLE_RO_DEP_CACHE is the mount" "$(line "$o" RO)" "$UC/gradle"
    check "a repository answers: recorded online" "$(line "$o" STATE)" "online"
    check "a repository answers: no --offline, GRADLE_ARGS untouched" "$(line "$o" OFFLINE)|$(line "$o" ARGS)" "|"
    o=$(run_section "$on" GRADLE_ARGS=--info)
    check "a repository answers: a caller's GRADLE_ARGS kept as it is" "$(line "$o" ARGS)" "--info"

    off="$WORK/p-offline"; mkdir -p "$off"
    cat > "$off/build.gradle.kts" <<EOF
repositories {
    // maven("http://127.0.0.1:$_port/commented-out/")
    maven("http://127.0.0.1:$_closed/a/")
    maven { url = uri("http://127.0.0.1:$_closed/b/") }
}
EOF
    o=$(run_section "$off" GRADLE_ARGS=--info)
    check "no repository answers (a commented one is not read): recorded offline" "$(line "$o" STATE)" "offline"
    check "no repository answers: --offline for build-prep's runs and in GRADLE_ARGS for cdxgen" \
        "$(line "$o" OFFLINE)|$(line "$o" ARGS)" "--offline|--info --offline"
    if printf '%s\n' "$o" | grep -q "no repository the build names answered: 127.0.0.1:$_closed"; then
        pass "the log names the repository that did not answer"
    else
        fail "the probe's cause is not logged" "$o"
    fi

    both="$WORK/p-both"; mkdir -p "$both"
    printf "repositories {\n  maven { url \"http://127.0.0.1:%s/\" }\n  maven { url 'http://127.0.0.1:%s/' }\n}\n" "$_closed" "$_port" > "$both/build.gradle"
    o=$(run_section "$both")
    check "one of two repositories answers: online" "$(line "$o" STATE)" "online"

    o=$(run_section "$off" BOMLENS_GRADLE_USER_CACHE=false)
    check "BOMLENS_GRADLE_USER_CACHE=false: the mount is not read" "$(line "$o" RO)|$(line "$o" STATE)|$(line "$o" OFFLINE)" "||"
    o=$(run_section "$off" GRADLE_RO_DEP_CACHE=/elsewhere)
    check "a GRADLE_RO_DEP_CACHE the caller set is kept, and nothing is probed" "$(line "$o" RO)|$(line "$o" STATE)" "/elsewhere|"
    o=$(run_section "$off" PREP_USER_CACHE_ROOT="$WORK/no-mount")
    check "no mount (no modules-2): nothing set" "$(line "$o" RO)|$(line "$o" STATE)" "|"
    np="$WORK/p-none"; mkdir -p "$np"; : > "$np/package.json"
    o=$(run_section "$np")
    check "not a Gradle build: nothing set" "$(line "$o" RO)|$(line "$o" STATE)" "|"
    # BUILD_TOOL_CHOSEN is set in the section's prelude; a Maven choice is
    # checked by editing that line.
    sed 's/^BUILD_TOOL_CHOSEN=""$/BUILD_TOOL_CHOSEN=maven/' "$_sec" > "$WORK/section-maven.sh"
    o=$( cd "$off" && env -u GRADLE_RO_DEP_CACHE PREP_USER_CACHE_ROOT="$UC" sh "$WORK/section-maven.sh" 2>&1 )
    check "pom.xml chosen over build.gradle: nothing set" "$(line "$o" RO)" ""

    echo "== build-prep.sh: the wrapper's Gradle offline =="
    _wr="$WORK/wrapper.sh"
    {
        printf '%s\n' 'log() { echo "[build-prep] $*"; }'
        sed -n '/^gradle_wrapper_offline() {/,/^}/p' "$PREP"
        printf '%s\n' 'GRADLE_USER_WRAPPER_DIR="$1"; GRADLEW=./gradlew; GRADLEW_SH=""; gradle_wrapper_offline'
        # shellcheck disable=SC2016
        printf '%s\n' 'echo "GRADLEW:$GRADLEW"; echo "PINNED:${CDXGEN_JVM_TOOL_PINNED:-}"'
    } > "$_wr"
    wp="$WORK/p-wrapper"; mkdir -p "$wp/gradle/wrapper"; : > "$wp/gradlew"
    printf 'distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\ndistributionUrl=https\\://services.gradle.org/distributions/gradle-8.9-bin.zip\n' \
        > "$wp/gradle/wrapper/gradle-wrapper.properties"
    # The folder name Gradle's wrapper uses for this URL (measured with Gradle 8.9).
    _hash=90cnw93cvbtalezasaz0blq0a
    ud="$WORK/user-dists"; mkdir -p "$ud/gradle-8.9-bin/$_hash/gradle-8.9/lib" "$ud/gradle-8.9-bin/$_hash/gradle-8.9/bin"
    : > "$ud/gradle-8.9-bin/$_hash/gradle-8.9-bin.zip.ok"; : > "$ud/gradle-8.9-bin/$_hash/gradle-8.9/bin/gradle"
    chmod -R a-w "$ud"
    gh="$WORK/wgh"
    o=$( cd "$wp" && GRADLE_USER_HOME="$gh" sh "$_wr" "$ud" 2>&1 )
    if [ -f "$gh/wrapper/dists/gradle-8.9-bin/$_hash/gradle-8.9-bin.zip.ok" ] && [ -f "$gh/wrapper/dists/gradle-8.9-bin/$_hash/gradle-8.9/bin/gradle" ] \
        && [ -w "$gh/wrapper/dists/gradle-8.9-bin/$_hash" ] && [ "$(line "$o" GRADLEW)" = ./gradlew ]; then
        pass "the user's read-only distribution is copied into the scan's Gradle home under the wrapper's folder name; the wrapper runs"
    else
        fail "wrapper distribution not copied" "$o $(find "$gh" -maxdepth 5 2>/dev/null | head -10)"
    fi
    o=$( cd "$wp" && GRADLE_USER_HOME="$gh" sh "$_wr" "$ud" 2>&1 )
    if printf '%s\n' "$o" | grep -q "in BomLens's Gradle cache" && [ "$(line "$o" GRADLEW)" = ./gradlew ]; then
        pass "a distribution the scan's Gradle home already has is used as it is"
    else
        fail "second run" "$o"
    fi
    _fake_bin="$WORK/fake-bin"; mkdir -p "$_fake_bin"; printf '#!/bin/sh\nexit 0\n' > "$_fake_bin/gradle"; chmod +x "$_fake_bin/gradle"
    o=$( cd "$wp" && PATH="$_fake_bin:$PATH" GRADLE_USER_HOME="$WORK/wgh2" sh "$_wr" "$WORK/no-dists" 2>&1 )
    check "no distribution anywhere: the image's Gradle runs, cdxgen told to skip the wrapper" \
        "$(line "$o" GRADLEW)|$(line "$o" PINNED)" "gradle|true"
    chmod -R u+w "$ud"
else
    echo "  SKIP: node or python3 is not installed"
fi

echo "== build-prep.sh: bomlens:gradle-user-cache on the SBOM =="
_guc="$WORK/guc.js"
sed -n "/<<'GUC_JS'/,/^GUC_JS\$/p" "$PREP" | sed '1d;$d' > "$_guc"
if command -v node >/dev/null 2>&1 && [ -s "$_guc" ]; then
    printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"properties":[{"name":"bomlens:gradle-user-cache","value":"old"}]},"components":[]}' > "$WORK/bom.json"
    node "$_guc" "$WORK/bom.json" offline
    check "the state is recorded once, replacing an earlier value" \
        "$(jq -c '[.metadata.properties[] | select(.name=="bomlens:gradle-user-cache") | .value]' "$WORK/bom.json")" '["offline"]'
else
    fail "could not extract the bomlens:gradle-user-cache writer, or node is missing"
fi

echo "== build-prep.sh: unresolved Gradle entries =="
_fns="$WORK/fns.sh"
{
    printf '%s\n' 'log() { echo "[build-prep] $*"; }'
    sed -n '/^mark_prep_failed() {/,/^}/p; /^gradle_report_failed() {/,/^}/p; /^gradle_unresolved() {/,/^}/p' "$PREP"
} > "$_fns"
check "the FAILED entries of a real offline report, each once" \
    "$(bash -c '. "$1"; gradle_report_failed "$2"' _ "$_fns" "$FIX/dependencies-offline.txt" | tr '\n' ' ')" \
    "ch.qos.logback:logback-classic:1.4.14 com.fasterxml.jackson.core:jackson-databind:2.16.0 com.google.guava:guava:32.1.3-jre org.junit.jupiter:junit-jupiter:5.10.1 org.slf4j:slf4j-api:2.0.9 "
o=$(bash -c '. "$1"; PREP_FAILED=""; gradle_report_failed "$2" > "$3"; gradle_unresolved gradle-dependencies "$3"; echo "FAILED:$PREP_FAILED"' _ "$_fns" "$FIX/dependencies-offline.txt" "$WORK/u.txt" 2>&1)
check "a report with FAILED entries records gradle-dependencies as failed" "$(line "$o" FAILED)" "gradle-dependencies"
if printf '%s\n' "$o" | grep -q 'gradle-dependencies: \[WARN\] Gradle could not resolve 5 dependency entries (ch.qos.logback:logback-classic:1.4.14, com.fasterxml.jackson.core:jackson-databind:2.16.0, com.google.guava:guava:32.1.3-jre, ...)'; then
    pass "the log names how many entries were unresolved and the first three"
else
    fail "unresolved log line" "$o"
fi
printf 'dependencies\n+--- a:b:1\n' > "$WORK/ok.txt"
o=$(bash -c '. "$1"; PREP_FAILED=""; gradle_report_failed "$2" > "$3"; gradle_unresolved gradle-dependencies "$3"; echo "FAILED:$PREP_FAILED"' _ "$_fns" "$WORK/ok.txt" "$WORK/u2.txt" 2>&1)
check "a report with no FAILED entry records nothing" "$(line "$o" FAILED)" ""

# The runtime classpath read (the init script's files) with U lines, through the
# real Gradle block, as tests/test-postprocess.sh drives it.
if command -v node >/dev/null 2>&1; then
    _blk=$(sed -n '/^# Gradle (java-gradle \/ Android)/,/^# A root Gradle build that did not reach/p' "$PREP" | sed '$d')
    _hlp=$(sed -n '/^mark_prep_failed() {/,/^}/p; /^unmark_prep_failed() {/,/^}/p; /^prep_step() {/,/^}/p; /^wrapper_shell() {/,/^}/p; /^gradle_wrapper_offline() {/,/^}/p' "$PREP")
    gb="$WORK/gbin"; mkdir -p "$gb"; printf '#!/bin/sh\nexit 0\n' > "$gb/gradle"; chmod +x "$gb/gradle"
    gp="$WORK/gproj"; mkdir -p "$gp"; : > "$gp/build.gradle"
    cat > "$gp/gradlew" <<'STUB'
#!/bin/sh
case " $* " in *" --version "*) exit 0 ;; esac
echo "$*" >> "$GW_CALLS"
for a in "$@"; do
    case "$a" in
        -Dbomlens.gradle.out=*) cp "$GW_REPORT"/* "${a#-Dbomlens.gradle.out=}"/; exit 0 ;;
        dependencies) cat "$GW_TEXT"; exit 0 ;;
    esac
done
exit 1
STUB
    chmod +x "$gp/gradlew"
    run_block() {
        : > "$WORK/gcalls"
        ( cd "$gp" && env -u GRADLE_USER_HOME -u ANDROID_HOME -u GRADLE_INCLUDED_BUILDS -u BOMLENS_GRADLE_FULL_GRAPH \
            PATH="$gb:$PATH" HOME="$WORK/ghome" GW_CALLS="$WORK/gcalls" GW_TEXT="$FIX/dependencies-offline.txt" "$@" \
            sh -c 'log() { echo "[build-prep] $*"; }
opted_out() { case "$1" in 1|true) return 0 ;; esac; return 1; }
gradle_settings_copy() { :; }
run_supervised_timeout() { shift; "$@"; }
PREP_FAILED=""; PREP_APPLIED=""; PREP_TIMEOUT_GRADLE=5
'"$_hlp"'
'"$_blk"'
echo "FAILED:$PREP_FAILED"
echo "SET:$( [ -n "$GRADLE_RUNTIME_SET" ] && tr "\n" " " < "$GRADLE_RUNTIME_SET")"' ) 2>&1
    }
    o=$(run_block GW_REPORT="$FIX/unresolved")
    check "runtime classpath read with unresolved (U) entries: gradle-dependencies recorded as failed" "$(line "$o" FAILED)" "gradle-dependencies"
    check "the direct dependencies asked for are still in the set" "$(line "$o" SET)" "com.google.guava:guava:32.1.3-jre org.slf4j:slf4j-api:2.0.9 "
    if printf '%s\n' "$o" | grep -q 'Gradle could not resolve 2 dependency entries'; then
        pass "the runtime classpath read names the 2 unresolved entries"
    else
        fail "unresolved count not logged" "$o"
    fi
    o=$(run_block GW_REPORT="$ROOT_DIR/tests/fixtures/gradle-runtime/single")
    check "no U line: not failed" "$(line "$o" FAILED)" ""
    o=$(run_block GW_REPORT="$FIX/unresolved" BOMLENS_GRADLE_FULL_GRAPH=1)
    check "BOMLENS_GRADLE_FULL_GRAPH=1, the plain dependencies report has FAILED entries: recorded as failed" "$(line "$o" FAILED)" "gradle-dependencies"
    if grep -qx -- '--no-daemon dependencies' "$WORK/gcalls"; then
        pass "online, the plain dependencies run gets no --offline"
    else
        fail "plain dependencies call" "$(cat "$WORK/gcalls")"
    fi
    o=$(run_block GW_REPORT="$FIX/unresolved" BOMLENS_GRADLE_FULL_GRAPH=1 GRADLE_OFFLINE_ARG=--offline)
    if grep -qx -- '--no-daemon --offline dependencies' "$WORK/gcalls"; then
        pass "offline, build-prep's own Gradle run gets --offline"
    else
        fail "offline dependencies call" "$(cat "$WORK/gcalls")"
    fi
else
    echo "  SKIP: node is not installed"
fi

echo ""
echo "Passed: $PASS  Failed: $FAIL"
[ "$FAIL" -eq 0 ]
