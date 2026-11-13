#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-gradle-runtime.sh - the java-gradle runtime classpath step of
# docker/lib/build-prep.sh against a real Gradle.
#
# build-prep adds an init script to a Gradle run that resolves every project's
# runtimeClasspath and writes the coordinates to files. The unit tests in
# test-postprocess.sh drive the shell around it with a stand-in gradlew, so
# they cannot tell whether the init script works. This one runs the real
# gradle_runtime_classpath function, init script included, on a small
# multi-project build with several Gradle versions, each with the configuration
# cache switched on in gradle.properties (and parallel execution on) and
# switched off, and checks that every run gives the same set, the runtime
# classpath, and that a build with an included build is recognised.
# (With the configuration cache on, Gradle 8 and 9 run the projects'
# dependencies tasks in parallel and mix their console output, which is why
# nothing is read from the console.)
#
# It needs Docker and a route to Docker Hub (the official gradle images, one per
# Gradle version) and to Maven Central, so it self-skips without them.
#
# Usage: ./tests/test-gradle-runtime.sh
# Env:
#   GRADLE_RUNTIME_CASES   space-separated <gradle version>:<jdk> pairs, each
#                          the image gradle:<version>-jdk<jdk>
#                          (default: "6.9.4:11 7.6.6:11 8.14.3:21 9.0.0:21 9.8.2:21"; a version older than 6.6 is
#                          expected to be refused and fall back, but its
#                          image is amd64 only)
#   VERBOSE=true           print the step's log on failure
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
PREP="$REPO/docker/lib/build-prep.sh"
CASES="${GRADLE_RUNTIME_CASES:-6.9.4:11 7.6.6:11 8.14.3:21 9.0.0:21 9.8.2:21}"
VERBOSE="${VERBOSE:-false}"
# Under the repo so Docker file sharing mounts it (mktemp -d is /var/folders on macOS).
WORK="$SCRIPT_DIR/test-workspace/gradle-runtime"
c0="${CASES%% *}"
RECLAIM_IMAGE="gradle:${c0%%:*}-jdk${c0##*:}"

# The builds run in containers as the invoking user, so what they write is theirs.
# This hands back anything an earlier run (an older version of this script, or a
# container that ran as root) left owned by root, which a runner whose daemon runs
# as root would otherwise keep: its next rm -rf of $WORK and git clean would fail.
# It needs no sudo: a short root container does the chown.
reclaim() {
    [ -d "$WORK" ] || return 0
    command -v docker >/dev/null 2>&1 || return 0
    [ -n "$(find "$WORK" ! -user "$(id -u)" -print -quit 2>/dev/null)" ] || return 0
    docker run --rm -u 0:0 -v "$WORK":/w --entrypoint chown "$RECLAIM_IMAGE" \
        -R "$(id -u):$(id -g)" /w >/dev/null 2>&1 || true
}
trap reclaim EXIT
reclaim
rm -rf "$WORK"; mkdir -p "$WORK/gcache"

c_green='\033[0;32m'; c_red='\033[0;31m'; c_yellow='\033[0;33m'; c_reset='\033[0m'
PASS=0; FAIL=0
pass() { echo -e "  ${c_green}PASS${c_reset} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${c_red}FAIL${c_reset} $1"; FAIL=$((FAIL+1)); [ -n "${2:-}" ] && echo "        ↳ $2"; return 0; }
skip() { echo -e "  ${c_yellow}SKIP${c_reset} $1"; exit 0; }

echo "▶ java-gradle runtime classpath against real Gradle ($CASES)"
command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || skip "docker unavailable"
curl -fsSI --max-time 15 https://repo1.maven.org/maven2/ >/dev/null 2>&1 || skip "Maven Central unreachable"

# The step's own code: the helpers it calls and the function.
FUNCS="$WORK/funcs.sh"
{
    printf '%s\n' 'log() { echo "[build-prep] $*"; }'
    printf '%s\n' 'PREP_FAILED=""; PREP_APPLIED=""; PREP_TIMEOUT_GRADLE=1500'
    # The real prep_step, which also writes the java-toolchain-missing marker the
    # CLI reads to rerun stage 1; only the time limit is left out.
    printf '%s\n' 'run_supervised_timeout() { shift; "$@"; }'
    sed -n '/^prep_step() {/,/^}/p' "$PREP"
    sed -n '/^mark_prep_failed() {/,/^}/p; /^unmark_prep_failed() {/,/^}/p' "$PREP"
    # The init script's heredoc has lines starting with "}", so the function's
    # end is found by its last statement.
    sed -n '/^gradle_runtime_classpath() {/,/^    rm -rf "\$_gr_dir"$/p' "$PREP"
    printf '%s\n' '}'
    # shellcheck disable=SC2016
    printf '%s\n' 'GRADLEW=gradle; GRADLE_RUNTIME_SET=""'
    printf '%s\n' 'gradle_runtime_classpath'
    # shellcheck disable=SC2016
    printf '%s\n' '[ -z "$GRADLE_RUNTIME_SET" ] || { echo "SET-BEGIN"; cat "$GRADLE_RUNTIME_SET"; echo "SET-END"; }'
} > "$WORK/funcs.sh"
grep -q '^gradle_runtime_classpath() {' "$FUNCS" || { fail "could not extract gradle_runtime_classpath from build-prep.sh"; exit 1; }

# A multi-project build: app depends on lib and guava 33.0.0 (whose module
# metadata gives j2objc-annotations to compile only), and has a test-only and
# a compile-only dependency; lib has an api and a compile-only dependency; kmp
# has no runtimeClasspath, only configurations of its own, some of them test or
# build tool ones (left out) and two a project may ship (kept).
# From Gradle 7 on, guava 33.0.0 is added, whose Gradle module metadata gives
# j2objc-annotations to the compile classpath only (Gradle 6 cannot read it).
make_build() {  # <dir> <composite: yes|no|tc|kmptc|kmpsoft> <guava: yes|no>
    local d="$1" comp="$2" guava="$3"
    case "$comp" in kmptc|kmpsoft)
        # One project with no runtimeClasspath, only a configuration of its own that
        # cannot be resolved: for a toolchain no JDK matches, or for another reason.
        local msg="boom"
        [ "$comp" != kmptc ] || msg="No matching toolchains found for requested specification: {languageVersion=13, vendor=any, implementation=vendor-specific}"
        mkdir -p "$d"
        printf "rootProject.name = 'kmp1'\n" > "$d/settings.gradle"
        cat > "$d/build.gradle" <<EOF
repositories { mavenCentral() }
configurations.create('jvmRuntimeClasspath') {
    canBeConsumed = false
    canBeResolved = true
    incoming.beforeResolve { throw new GradleException("$msg") }
}
dependencies.add('jvmRuntimeClasspath', 'commons-codec:commons-codec:1.16.0')
EOF
        return 0 ;;
    esac
    mkdir -p "$d/app" "$d/lib" "$d/kmp" "$d/plat"
    printf "rootProject.name = 'demo'\ninclude 'app', 'lib', 'kmp', 'plat'\n" > "$d/settings.gradle"
    if [ "$comp" = yes ]; then
        mkdir -p "$d/other"
        printf "rootProject.name = 'other'\n" > "$d/other/settings.gradle"
        printf "plugins { id 'java' }\n" > "$d/other/build.gradle"
        printf "includeBuild 'other'\n" >> "$d/settings.gradle"
    fi
    : > "$d/build.gradle"
    local extra=""
    [ "$guava" != yes ] || extra="    implementation 'com.google.guava:guava:33.0.0-jre'"
    cat > "$d/app/build.gradle" <<EOF
plugins { id 'java' }
repositories { mavenCentral() }
dependencies {
    implementation project(':lib')
    implementation 'org.apache.commons:commons-text:1.11.0'
$extra
    testImplementation 'junit:junit:4.13.2'
    testImplementation 'org.mockito:mockito-core:5.11.0'
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher:1.10.2'
    compileOnly 'org.projectlombok:lombok:1.18.30'
    annotationProcessor 'org.projectlombok:lombok:1.18.30'
}
EOF
    # Only constraints: a project with nothing to ship that must not turn the filter off.
    cat > "$d/plat/build.gradle" <<'EOF'
plugins { id 'java-platform' }
dependencies { constraints { api 'org.slf4j:slf4j-api:2.0.9' } }
EOF
    cat > "$d/kmp/build.gradle" <<'EOF'
repositories { mavenCentral() }
def cfg = { String n, String dep ->
    configurations.create(n) { canBeConsumed = false; canBeResolved = true }
    dependencies.add(n, dep)
}
cfg('jvmRuntimeClasspath', 'commons-codec:commons-codec:1.16.0')
cfg('fooTestament', 'commons-io:commons-io:2.15.1')
cfg('jvmTestRuntimeClasspath', 'junit:junit:4.13.2')
cfg('kotlinCompilerClasspath', 'org.apache.commons:commons-text:1.11.0')
cfg('dokkaGfmPlugin', 'commons-collections:commons-collections:3.2.2')
cfg('_internal-unified-test-platform-core', 'joda-time:joda-time:2.12.5')
cfg('jacocoAgent', 'org.jacoco:org.jacoco.agent:0.8.11')
EOF
    cat > "$d/lib/build.gradle" <<'EOF'
plugins { id 'java-library' }
repositories { mavenCentral() }
dependencies {
    api 'org.slf4j:slf4j-api:2.0.9'
    compileOnly 'org.apache.commons:commons-lang3:3.14.0'
}
EOF
    if [ "$comp" = tc ]; then
        # A JDK that is not in the image, with detection and download off: the
        # runtimeClasspath cannot be resolved.
        printf "java { toolchain { languageVersion = JavaLanguageVersion.of(13) } }\n" >> "$d/lib/build.gradle"
    fi
}

EXPECTED_RAW="commons-codec:commons-codec:1.16.0
commons-io:commons-io:2.15.1
org.apache.commons:commons-lang3:3.13.0
org.apache.commons:commons-text:1.11.0
org.slf4j:slf4j-api:2.0.9"
GUAVA_RAW="com.google.code.findbugs:jsr305:3.0.2
com.google.errorprone:error_prone_annotations:2.23.0
com.google.guava:failureaccess:1.0.2
com.google.guava:guava:33.0.0-jre
com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava
org.checkerframework:checker-qual:3.41.0"
old_gradle() { case "$1" in 6.[0-5]|6.[0-5].*|[0-5].*) return 0 ;; esac; return 1; }
expected_for() {  # <gradle version>
    if [ "${1%%.*}" -ge 7 ]; then printf '%s\n%s\n' "$EXPECTED_RAW" "$GUAVA_RAW" | LC_ALL=C sort
    else printf '%s\n' "$EXPECTED_RAW" | LC_ALL=C sort; fi
}

# run <gradle version> <jdk> <cc on|off> <composite yes|no> -> log in $WORK/<tag>.log
run_step() {
    local v="$1" jdk="$2" cc="$3" comp="$4" tag="$1-$3-$4"
    local d="$WORK/$tag"
    local guava=no; [ "${v%%.*}" -lt 7 ] || guava=yes
    rm -rf "$d"; make_build "$d" "$comp" "$guava"
    if [ "$cc" = on ]; then
        printf 'org.gradle.configuration-cache=true\norg.gradle.unsafe.configuration-cache=true\norg.gradle.parallel=true\n' > "$d/gradle.properties"
    fi
    if [ "$comp" = tc ] || [ "$comp" = kmptc ]; then
        printf 'org.gradle.java.installations.auto-download=false\norg.gradle.java.installations.auto-detect=false\n' >> "$d/gradle.properties"
    fi
    docker run --rm -u "$(id -u):$(id -g)" -v "$d":/app -v "$WORK/gcache":/gh -v "$WORK/funcs.sh":/funcs.sh:ro \
        -e HOME=/tmp/h -e GRADLE_USER_HOME=/gh -w /app "gradle:${v}-jdk${jdk}" sh /funcs.sh > "$WORK/$tag.log" 2>&1
    echo "$WORK/$tag.log"
}
set_of() { sed -n '/^SET-BEGIN$/,/^SET-END$/p' "$1" | sed '1d;$d' | LC_ALL=C sort; }

for c in $CASES; do
    v="${c%%:*}"; jdk="${c##*:}"
    for cc in on off; do
        log="$(run_step "$v" "$jdk" "$cc" no)"
        got="$(set_of "$log")"
        if old_gradle "$v"; then
            # --no-configuration-cache is unknown before 6.6: no filter, and the root warm-up runs.
            if [ -z "$got" ] && grep -q 'resolving the root project only (full graph)' "$log"; then
                pass "Gradle $v, configuration cache $cc: older than 6.6, the run is refused and the root warm-up runs (full graph kept)"
            else
                fail "Gradle $v, configuration cache $cc: older than 6.6" "$(tail -4 "$log" | tr '\n' ' ')"
            fi
        elif [ "$got" = "$(expected_for "$v")" ]; then
            pass "Gradle $v, configuration cache $cc: the runtime classpath, none compile-only, test-only or from a build tool configuration"
        else
            fail "Gradle $v, configuration cache $cc: the runtime classpath" "got: $(printf '%s' "$got" | tr '\n' ' ')"
            [ "$VERBOSE" = true ] && sed -n '1,40p' "$log"
        fi
    done
done

# An included build: cdxgen reads its dependencies too, so the step keeps the full graph.
for c in $CASES; do v="${c%%:*}"; old_gradle "$v" || break; done; jdk="${c##*:}"
log="$(run_step "$v" "$jdk" off yes)"
if grep -q 'the build includes the build other; using full graph' "$log" && [ -z "$(set_of "$log")" ]; then
    pass "Gradle $v: an included build is recognised and the full graph kept"
else
    fail "Gradle $v: included build" "$(tail -5 "$log" | tr '\n' ' ')"
fi

# A toolchain no JDK matches: the run fails, so the step is recorded as failed, the
# message names the JDK (the marker the CLI reads to rerun stage 1 in an image
# that has it), and the root warm-up, which would fail the same way, is skipped.
# The toolchain's JDK version attribute reaches dependency resolution from Gradle 7 on
# (Gradle 6 resolves such a build), so the first case of 8 or later runs it.
tcv=""; tcjdk=""
for c in $CASES; do
    if [ "${c%%.*}" -ge 8 ] 2>/dev/null; then tcv="${c%%:*}"; tcjdk="${c##*:}"; break; fi
done
[ -n "$tcv" ] || { tcv="$v"; tcjdk="$jdk"; }
v="$tcv"; jdk="$tcjdk"
log="$(run_step "$v" "$jdk" off tc)"
if [ -z "$(set_of "$log")" ] \
   && grep -q 'java-toolchain-missing=13' "$log" \
   && grep -q 'would fail the same way' "$log" \
   && ! grep -q 'resolving the root project only' "$log"; then
    pass "Gradle $v: a toolchain no JDK matches fails the run, is named as java-toolchain-missing=13, and no second run is made"
else
    fail "Gradle $v: toolchain that no JDK matches" "$(grep -E 'build-prep\]|bomlens:' "$log" | head -6 | tr '\n' ' ')"
    [ "$VERBOSE" = true ] && sed -n '1,40p' "$log"
fi

# The same for a project with no runtimeClasspath (a Kotlin Multiplatform root): a
# toolchain failure fails the run too, any other unresolved configuration only
# keeps the full graph.
log="$(run_step "$v" "$jdk" off kmptc)"
if [ -z "$(set_of "$log")" ] \
   && grep -q 'java-toolchain-missing=13' "$log" \
   && grep -q 'would fail the same way' "$log"; then
    pass "Gradle $v: a project without runtimeClasspath that fails for want of a toolchain JDK fails the run and is named as java-toolchain-missing=13"
else
    fail "Gradle $v: toolchain failure in a project without runtimeClasspath" "$(grep -E 'build-prep\]' "$log" | head -6 | tr '\n' ' ')"
    [ "$VERBOSE" = true ] && sed -n '1,40p' "$log"
fi
log="$(run_step "$v" "$jdk" off kmpsoft)"
if [ -z "$(set_of "$log")" ] \
   && ! grep -q 'java-toolchain-missing' "$log" \
   && ! grep -q 'gradle-dependencies: failed' "$log" \
   && grep -q 'could not resolve jvmRuntimeClasspath of project :.*using full graph' "$log"; then
    pass "Gradle $v: another reason for an unresolved configuration only keeps the full graph, with the reason on stderr"
else
    fail "Gradle $v: soft failure in a project without runtimeClasspath" "$(grep -E 'build-prep\]|bomlens' "$log" | head -6 | tr '\n' ' ')"
    [ "$VERBOSE" = true ] && sed -n '1,40p' "$log"
fi

echo ""
echo "Gradle runtime classpath: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
