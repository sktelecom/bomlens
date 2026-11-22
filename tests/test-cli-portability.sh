#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-cli-portability.sh - No-Docker tests for the CLI on macOS's default bash 3.2
# and for what a failed run leaves behind: bash 3.2 syntax guards, the folders a
# failed run removes, two scans of one result or one source folder at once
# (the second waits, the folder is left as it was), the progress line of a long image scan, the container's
# [ERROR]/[WARN] lines on stderr, a Gradle root whose folder name starts with a
# dot, the Xcode-held Package.resolved, check-setup's own-UI port, the scan
# container's output on a terminal and the scan log, and --ui from a BomLens clone.
# A fake `docker` on PATH answers the few calls these paths make.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/scan-sbom.sh"
PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [ -z "${LISTEN_PID:-}" ] || kill "$LISTEN_PID" 2>/dev/null' EXIT
mkdir -p "$WORK/bin" "$WORK/cwd"

extract_fn() { # <file> <function>
    awk -v fn="$2" '
        $0 ~ "^" fn "\\(\\) \\{" { inside = 1 }
        inside { print }
        inside && $0 == "}" { exit }
    ' "$1"
}

# --- 1) bash 3.2: patterns it cannot parse or run, in the scripts a user runs
echo "== bash 3.2 guards"
USER_SCRIPTS="$ROOT_DIR/scripts/scan-sbom.sh $ROOT_DIR/scripts/check-setup.sh $ROOT_DIR/scripts/verify-release.sh"
# bash -n does not parse a command substitution until it runs, so a $(case ...)
# inside a quoted string passes -n and fails at run time on 3.2. Look for it.
if grep -nE '\$\([[:space:]]*case[[:space:]]' $USER_SCRIPTS >"$WORK/g1" 2>/dev/null \
   || awk 'prev ~ /\$\([[:space:]]*$/ && $0 ~ /^[[:space:]]*case[[:space:]]/ { print FILENAME ":" FNR } { prev = $0 }' $USER_SCRIPTS | grep -q .; then
    fail "a case inside \$( ) (bash 3.2 cannot parse it in a quoted string)" "$(head -n 3 "$WORK/g1")"
else
    pass "no case inside \$( ) in the user-run scripts"
fi
if grep -nE '\$\{[A-Za-z_0-9]+(,,|\^\^)\}|declare -A|local -A|&>>|\bmapfile\b|\breadarray\b|\[\[ -v |\$\{[A-Za-z_]+@[UuLlQ]\}|\bwait -n\b|local -n |coproc ' $USER_SCRIPTS >"$WORK/g2" 2>/dev/null; then
    fail "a bash 4+ construct in a user-run script" "$(head -n 3 "$WORK/g2")"
else
    pass "no bash 4+ construct in the user-run scripts"
fi
OLD_BASH=""
if [ -x /bin/bash ] && /bin/bash -c '[ "${BASH_VERSINFO[0]}" -le 3 ]' 2>/dev/null; then OLD_BASH=/bin/bash; fi
if [ -n "$OLD_BASH" ]; then
    for f in $USER_SCRIPTS; do
        if "$OLD_BASH" -n "$f" 2>"$WORK/n"; then pass "bash 3.2 parses $(basename "$f")"; else fail "bash 3.2 parse of $(basename "$f")" "$(head -n 2 "$WORK/n")"; fi
    done
    {
        printf 'log_error() { printf "[ERROR] %%s\\n" "$*" >&2; }\n'
        extract_fn "$SCRIPT" docker_run_failure_code
        echo 'for c in 125 126 127; do docker_run_failure_code "$c" "the scan container"; done'
    } > "$WORK/dr.sh"
    out="$("$OLD_BASH" "$WORK/dr.sh" 2>&1)"
    if printf '%s\n' "$out" | grep -q 'engine refused to start' && printf '%s\n' "$out" | grep -q 'not found in the image' \
       && ! printf '%s' "$out" | grep -qi 'syntax error'; then
        pass "docker_run_failure_code runs on bash 3.2 and names each cause"
    else
        fail "docker_run_failure_code on bash 3.2" "$out"
    fi
else
    echo "  SKIP: no bash 3.x at /bin/bash here; only the pattern guards ran"
fi

# --- 2) the container's [ERROR] and [WARN] lines go to stderr
echo "== container messages on stderr"
if grep -nE 'echo "\[(ERROR|WARN)\]' "$ROOT_DIR/docker/entrypoint.sh" | grep -v '>&2' >"$WORK/g3"; then
    fail "an entrypoint [ERROR]/[WARN] line is not on stderr" "$(head -n 2 "$WORK/g3")"
else
    pass "every [ERROR]/[WARN] echo in entrypoint.sh goes to stderr"
fi

# --- 3) what a failed run leaves behind
echo "== a failed run leaves no empty result folder"
cat > "$WORK/bin/docker" <<'MOCK'
#!/bin/bash
case "$1" in
    info|image|ps|rm|inspect) exit 0 ;;
    pull) exit "${FAKE_PULL_RC:-0}" ;;
    run)
        # The scan container leaves its manifest in the mounted run folder.
        prev=""
        for a in "$@"; do
            case "$prev$a" in
                -v*) : ;;
            esac
            case "$a" in
                *:/host-output|*:/host-output:*)
                    d="${a%%:/host-output*}"; d="${d%\"}"; d="${d#\"}"
                    [ -z "${FAKE_RESULT_FILE:-}" ] || printf '{}' > "$d/bomlens-result.json" ;;
            esac
            prev="$a"
        done
        [ -z "${FAKE_RUN_SLEEP:-}" ] || sleep "$FAKE_RUN_SLEEP"
        exit "${FAKE_RUN_RC:-0}" ;;
    *) exit 0 ;;
esac
MOCK
chmod +x "$WORK/bin/docker"
run_cli() {
    ( cd "$WORK/cwd" && PATH="$WORK/bin:$PATH" HOME="$WORK/home" "$@" >"$WORK/out" 2>"$WORK/err" )
    RC=$?
}
rm -rf "$WORK/o1"
FAKE_RESULT_FILE=1 FAKE_RUN_RC=1 SBOM_PULL=never run_cli bash "$SCRIPT" --project p --version 1 --target alpine:3.20 --generate-only -o "$WORK/o1"
if [ "$RC" != 0 ] && [ ! -e "$WORK/o1" ]; then
    pass "a failed image scan removes the new -o folder and the run folder holding only the manifest"
else
    fail "failed image scan leftovers" "rc=$RC $(find "$WORK/o1" 2>/dev/null | head -n 5)"
fi
rm -rf "$WORK/o2"; mkdir -p "$WORK/o2"
FAKE_RESULT_FILE=1 FAKE_RUN_RC=1 SBOM_PULL=never run_cli bash "$SCRIPT" --project p --version 1 --target alpine:3.20 --generate-only -o "$WORK/o2"
if [ -d "$WORK/o2" ] && [ ! -e "$WORK/o2/p_1" ]; then
    pass "an -o folder that existed before the run stays; its run folder goes"
else
    fail "existing -o folder" "$(find "$WORK/o2" | head -n 5)"
fi
rm -rf "$WORK/o3"
FAKE_PULL_RC=1 SBOM_PULL=always run_cli bash "$SCRIPT" --project p --version 1 --target alpine:3.20 --generate-only -o "$WORK/o3"
if [ "$RC" = 1 ] && grep -q '^\[ERROR\] Failed to pull' "$WORK/err" && [ ! -e "$WORK/o3" ]; then
    pass "a failed pull exits 1 with the cause and leaves no folder"
else
    fail "failed pull" "rc=$RC err=$(head -c 200 "$WORK/err") $(find "$WORK/o3" 2>/dev/null | head -n 3)"
fi
# The SBOM stage 1 wrote is parked under the unprocessed name, not left as a result.
(
    # shellcheck disable=SC1090
    log_warn() { :; }
    eval "$(extract_fn "$SCRIPT" park_unprocessed_sbom)"
    mkdir -p "$WORK/r"; echo '{}' > "$WORK/r/p_1_bom.json"
    OUTPUT_HOST_DIR="$WORK/r" OUTPUT_FILE="p_1_bom.json" park_unprocessed_sbom
    [ ! -e "$WORK/r/p_1_bom.json" ] && [ -f "$WORK/r/p_1_bom.unprocessed.json" ]
) && pass "an SBOM left by stage 1 is renamed to _bom.unprocessed.json" || fail "park_unprocessed_sbom"

# --- 3b) two scans of the same project and version into one folder
echo "== a second scan of the same name waits its turn"
rm -rf "$WORK/o4"; mkdir -p "$WORK/o4"
( cd "$WORK/cwd" && PATH="$WORK/bin:$PATH" HOME="$WORK/home" FAKE_RUN_SLEEP=4 SBOM_PULL=never \
    bash "$SCRIPT" --project same --version 1 --target alpine:3.20 --generate-only -o "$WORK/o4" >"$WORK/first.out" 2>&1 ) &
FIRST_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -d "$WORK/o4/same_1/.bomlens-scan-same_1.lock" ] && break
    sleep 0.2
done
SBOM_PULL=never run_cli bash "$SCRIPT" --project same --version 1 --target alpine:3.20 --generate-only -o "$WORK/o4"
if [ "$RC" = 1 ] && grep -q 'already running into this folder' "$WORK/err" && ! grep -q 'file sharing' "$WORK/err"; then
    pass "a second scan of the same name into the same folder stops at once and says the first is still running"
else
    fail "same-name concurrent scan" "rc=$RC err=$(head -c 300 "$WORK/err")"
fi
SBOM_PULL=never run_cli bash "$SCRIPT" --project other --version 1 --target alpine:3.20 --generate-only -o "$WORK/o4"
if ! grep -q 'already running' "$WORK/err"; then
    pass "a scan of another name into the same folder is not held back"
else
    fail "other-name concurrent scan" "rc=$RC err=$(head -c 300 "$WORK/err")"
fi
wait "$FIRST_PID" || true
if ! grep -q 'already running' "$WORK/first.out" && [ ! -e "$WORK/o4/same_1/.bomlens-scan-same_1.lock" ]; then
    pass "the first scan runs to its end and frees its lock"
else
    fail "first scan after a refused second" "rc=$FIRST_RC $(tail -n 3 "$WORK/first.out")"
fi
# A lock left by a scan that was killed outright (its process is gone) is taken over.
mkdir -p "$WORK/o4/same_1/.bomlens-scan-same_1.lock"
( exit 0 ) & DEAD_PID=$!; wait "$DEAD_PID"
echo "$DEAD_PID" > "$WORK/o4/same_1/.bomlens-scan-same_1.lock/pid"
SBOM_PULL=never run_cli bash "$SCRIPT" --project same --version 1 --target alpine:3.20 --generate-only -o "$WORK/o4"
if ! grep -q 'already running' "$WORK/err" && [ ! -e "$WORK/o4/same_1/.bomlens-scan-same_1.lock" ]; then
    pass "a lock whose scan is gone is taken over and freed"
else
    fail "stale lock" "rc=$RC err=$(head -c 300 "$WORK/err")"
fi
# The rerun after an exec of itself (--detection build keeps the process id)
# takes its own result lock back instead of refusing to start.
out="$( (
    SCAN_LOCK_DIR="$WORK/own-result.lock"; SCAN_LOCK_HELD=0
    eval "$(extract_fn "$SCRIPT" take_scan_lock)"
    mkdir -p "$SCAN_LOCK_DIR"; echo "$$" > "$SCAN_LOCK_DIR/pid"
    take_scan_lock && [ "$SCAN_LOCK_HELD" = 1 ] && echo took
) 2>&1 )"
if [ "$out" = took ]; then pass "a result lock this same process wrote before an exec is taken back"; else fail "own result lock" "$out"; fi

# --- 3c) two scans of one source folder with different versions
# This stand-in runs build-prep.sh's real source-tree guard (guard_snapshot,
# guard_restore) on the mounted folder in stage 1 and models `cargo
# generate-lockfile` (writes a Cargo.lock when there is none); stage 2 grades
# the folder as it finds it (complete with a Cargo.lock, partial without).
echo "== a second scan of the same source folder waits for the first"
mkdir -p "$WORK/gbin" "$WORK/gstub"
cat > "$WORK/gbin/docker" <<'MOCK'
#!/bin/bash
S="${STUB_STATE:?}"
mkdir -p "$S/running"
case "$1" in
    wait) cat "$S/rc.$2" 2>/dev/null || echo 0; exit 0 ;;
    ps)
        for a in "$@"; do
            case "$a" in
                name=^*) n="${a#name=^}"; n="${n%\$}"; [ -f "$S/running/$n" ] && echo "$n" ;;
                id=*) [ -f "$S/running/${a#id=}" ] && echo "${a#id=}" ;;
            esac
        done
        exit 0 ;;
    run)
        shift; name=""; app=""; state=""; out=""; src=""; hout=""; gid=""; ronly=""; prev=""; bom=""
        for a in "$@"; do
            a="${a%\"}"; a="${a#\"}"
            [ "$prev" != "--name" ] || name="$a"
            case "$a" in
                *:/app) app="${a%:/app}" ;;
                *:/bomlens-state) state="${a%:/bomlens-state}" ;;
                *:/out) out="${a%:/out}" ;;
                *:/src) src="${a%:/src}" ;;
                *:/host-output) hout="${a%:/host-output}" ;;
                BOMLENS_GUARD_ID=*) gid="${a#BOMLENS_GUARD_ID=}" ;;
                BOMLENS_GUARD_RESTORE_ONLY=1) ronly=1 ;;
                /out/*_bom.json) bom="${a##*/}" ;;
            esac
            prev="$a"
        done
        if [ -n "$app" ]; then
            [ -z "$name" ] || : > "$S/running/$name"
            drv="$S/drv.$$.sh"
            {
                echo 'log() { echo "[build-prep] $*"; }'
                echo 'opted_out() { case "$1" in 1|true) return 0 ;; esac; return 1; }'
                for fn in guard_paths guard_snapshot guard_git_tracked guard_restore; do
                    awk -v fn="$fn" '$0 ~ "^" fn "\\(\\) +\\{" { i = 1 } i { print } i && $0 == "}" { exit }' "${STUB_BUILD_PREP:?}"
                done
            } > "$drv"
            (
                . "$drv"
                GUARD_DIR=""; GUARD_NOEXEC=""; GUARD_NAMES_VERSION=5
                GUARD_STATE_ROOT="${state:-/nonexistent}"; BOMLENS_GUARD_ID="$gid"; SRC="$app"; OUT=/out/x
                cd "$app" || exit 1
                if [ -n "$ronly" ]; then
                    GUARD_DIR="$GUARD_STATE_ROOT/$BOMLENS_GUARD_ID"
                    [ ! -f "$GUARD_DIR/names.version" ] || guard_restore
                    exit 0
                fi
                guard_snapshot
                [ -f Cargo.lock ] || head -c 3138 /dev/zero | tr '\0' x > Cargo.lock
                sleep "${STUB_STAGE1_SECS:-3}"
                [ -z "$bom" ] || printf '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "$out/$bom"
                guard_restore
            ) >> "$S/stage1.log" 2>&1
            rm -f "$drv" "$S/running/$name"
            [ -z "$name" ] || echo 0 > "$S/rc.$name"
            exit 0
        fi
        if [ -n "$src" ] && [ -n "$hout" ]; then
            if [ -f "$src/Cargo.lock" ]; then echo complete > "$hout/grade.txt"; else echo partial > "$hout/grade.txt"; fi
        fi
        exit 0 ;;
    *) exit 0 ;;
esac
MOCK
chmod +x "$WORK/gbin/docker"
mkdir -p "$WORK/rt" "$WORK/gout" "$WORK/ghome"
printf '[package]\nname = "rtrep"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1"\n' > "$WORK/rt/Cargo.toml"
# Where scan-sbom.sh keeps the guard state: LOCALAPPDATA under Git Bash,
# XDG_STATE_HOME elsewhere.
GSTATE_HOME="$WORK/ghome/state"
GSTATE_LAD="$GSTATE_HOME"
command -v cygpath >/dev/null 2>&1 && GSTATE_LAD="$(cygpath -w "$GSTATE_HOME" 2>/dev/null || printf '%s' "$GSTATE_HOME")"
GUARD_ROOT="$GSTATE_HOME/bomlens/guard"
gscan() { # <version> <stdout file>
    ( cd "$WORK/rt" && PATH="$WORK/gbin:$PATH" HOME="$WORK/ghome" XDG_STATE_HOME="$GSTATE_HOME" LOCALAPPDATA="$GSTATE_LAD" \
        STUB_STATE="$WORK/gstub" STUB_BUILD_PREP="$ROOT_DIR/docker/lib/build-prep.sh" SBOM_PULL=never \
        bash "$SCRIPT" --project rtrep --version "$1" --generate-only -o "$WORK/gout" ) >"$2" 2>&1
}
gscan 1 "$WORK/g1.out" & G1=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
    [ -f "$WORK/rt/Cargo.lock" ] && break
    sleep 0.2
done
gscan 2 "$WORK/g2.out" & G2=$!
wait "$G1"; G1_RC=$?
wait "$G2"; G2_RC=$?
if [ "$G1_RC" = 0 ] && [ "$G2_RC" = 0 ] && grep -q '^\[INFO\] Another scan of this folder is running' "$WORK/g2.out" \
   && ! grep -q 'still be running' "$WORK/g1.out" "$WORK/g2.out"; then
    pass "a second scan of the same folder with another version says it waits, then runs"
else
    fail "same-folder second scan" "rc=$G1_RC/$G2_RC $(grep -h 'INFO\|WARN\|ERROR' "$WORK/g1.out" "$WORK/g2.out" | head -n 6)"
fi
if [ ! -e "$WORK/rt/Cargo.lock" ] && [ "$(ls -A "$WORK/rt")" = "Cargo.toml" ]; then
    pass "no lock file or other build file is left in the scanned folder"
else
    fail "files left in the scanned folder" "$(ls -la "$WORK/rt")"
fi
if [ "$(cat "$WORK/gout/rtrep_1/grade.txt" 2>/dev/null)" = partial ] && [ "$(cat "$WORK/gout/rtrep_2/grade.txt" 2>/dev/null)" = partial ]; then
    pass "each scan is graded on the folder as it is (no lock file there)"
else
    fail "grades" "1=$(cat "$WORK/gout/rtrep_1/grade.txt" 2>&1) 2=$(cat "$WORK/gout/rtrep_2/grade.txt" 2>&1)"
fi
if [ -z "$(find "$GUARD_ROOT" -maxdepth 1 -name '*.lock' 2>/dev/null)" ]; then
    pass "both scans free the folder's lock"
else
    fail "folder lock left behind" "$(find "$GUARD_ROOT" -maxdepth 2 2>/dev/null)"
fi
# A folder lock whose scan is gone, from this machine or from a web UI
# container that no longer runs, is taken over without waiting.
if command -v shasum >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1; then
    rt_real="$(cd "$WORK/rt" && pwd -P)"
    if command -v sha256sum >/dev/null 2>&1; then gkey="$(printf '%s' "$rt_real" | sha256sum | awk '{print $1}')"
    else gkey="$(printf '%s' "$rt_real" | shasum -a 256 | awk '{print $1}')"; fi
    # The folder lock is keyed on the host path in one form (source_lock_key):
    # C:/users/... under Git Bash, the path as it is elsewhere.
    rt_lock_path="$rt_real"
    command -v cygpath >/dev/null 2>&1 && rt_lock_path="$(cygpath -m "$rt_real" | tr '[:upper:]' '[:lower:]')"
    if command -v sha256sum >/dev/null 2>&1; then lkey="$(printf '%s' "$rt_lock_path" | sha256sum | awk '{print $1}')"
    else lkey="$(printf '%s' "$rt_lock_path" | shasum -a 256 | awk '{print $1}')"; fi
    ( exit 0 ) & DEAD_PID=$!; wait "$DEAD_PID"
    mkdir -p "$GUARD_ROOT/$lkey.lock"
    echo "$DEAD_PID" > "$GUARD_ROOT/$lkey.lock/pid"; echo cli > "$GUARD_ROOT/$lkey.lock/origin"
    STUB_STAGE1_SECS=0 gscan 3 "$WORK/g3.out"; G3_RC=$?
    mkdir -p "$GUARD_ROOT/$lkey.lock"
    echo 7 > "$GUARD_ROOT/$lkey.lock/pid"; echo "container 0123abcd" > "$GUARD_ROOT/$lkey.lock/origin"
    STUB_STAGE1_SECS=0 gscan 4 "$WORK/g4.out"; G4_RC=$?
    if [ "$G3_RC" = 0 ] && [ "$G4_RC" = 0 ] && ! grep -q 'Another scan of this folder' "$WORK/g3.out" "$WORK/g4.out" \
       && [ ! -e "$GUARD_ROOT/$lkey.lock" ]; then
        pass "a folder lock whose scan is gone is taken over and freed"
    else
        fail "stale folder lock" "rc=$G3_RC/$G4_RC $(grep -h 'INFO\|ERROR' "$WORK/g3.out" "$WORK/g4.out" | head -n 4)"
    fi
    # A scan container an earlier, stopped scan left running: waited for, and
    # named with the command that ends it, instead of a warning.
    mkdir -p "$GUARD_ROOT/$gkey"
    echo bomlens-scan-orphan > "$GUARD_ROOT/$gkey/owner"; echo "$rt_real" > "$GUARD_ROOT/$gkey/path"
    echo img > "$GUARD_ROOT/$gkey/image"
    mkdir -p "$WORK/gstub/running"; : > "$WORK/gstub/running/bomlens-scan-orphan"
    ( sleep 3; rm -f "$WORK/gstub/running/bomlens-scan-orphan"; rm -rf "${GUARD_ROOT:?}/$gkey" ) &
    STUB_STAGE1_SECS=0 gscan 5 "$WORK/g5.out"; G5_RC=$?
    if [ "$G5_RC" = 0 ] && grep -q 'This scan waits for it to end. To end a leftover one now: docker stop bomlens-scan-orphan' "$WORK/g5.out" \
       && ! grep -q 'still be running' "$WORK/g5.out" && [ ! -e "$WORK/rt/Cargo.lock" ]; then
        pass "a scan container left running in the folder is waited for and named with how to end it"
    else
        fail "left-running scan container" "rc=$G5_RC $(grep -h 'INFO\|WARN' "$WORK/g5.out" | head -n 4)"
    fi
    # The rerun after an exec of itself (same process id) takes its own lock back.
    out="$( (
        # Read by the functions the evals below define.
        # shellcheck disable=SC2034
        GUARD_STATE_DIR="$GUARD_ROOT"
        # shellcheck disable=SC2034
        CLEANUP_DIRS=()
        # shellcheck disable=SC2034
        SCAN_INPUT_DIR="$WORK/rt"
        # shellcheck disable=SC2034
        DOCKER_ENV=()
        hostpath() { cygpath -m -- "$1" 2>/dev/null || printf '%s' "$1"; }
        eval "$(extract_fn "$SCRIPT" guard_hash)"
        eval "$(extract_fn "$SCRIPT" source_lock_key)"
        eval "$(extract_fn "$SCRIPT" source_lock_holder_gone)"
        eval "$(extract_fn "$SCRIPT" take_source_lock)"
        mkdir -p "$GUARD_ROOT/$lkey.lock"; echo "$$" > "$GUARD_ROOT/$lkey.lock/pid"
        take_source_lock && [ "$SOURCE_LOCK_HELD" = 1 ] && echo took
    ) 2>&1 )"
    rm -rf "$GUARD_ROOT/$lkey.lock"
    if [ "$out" = took ]; then pass "a folder lock this same process wrote before an exec is taken back"; else fail "own folder lock" "$out"; fi
    # A web UI container that still runs: its lock is gone only when the scan
    # process inside it has ended (docker exec answers 1).
    out="$( (
        # shellcheck disable=SC2034
        DOCKER_ENV=()
        docker() {
            case "$1" in
                ps) echo 0123abcd0123 ;;
                exec) [ "$7" = 41 ] && return 0; [ "$7" = 42 ] && return 1; return 126 ;;
            esac
        }
        eval "$(extract_fn "$SCRIPT" source_lock_holder_gone)"
        a=running; source_lock_holder_gone 41 "container 0123abcd0123" && a=gone
        b=running; source_lock_holder_gone 42 "container 0123abcd0123" && b=gone
        c=running; source_lock_holder_gone 43 "container 0123abcd0123" && c=gone
        echo "$a $b $c"
    ) 2>&1 )"
    if [ "$out" = "running gone running" ]; then
        pass "a running web UI container's lock is taken over only when its scan process has ended"
    else
        fail "web UI container lock" "$out"
    fi
else
    echo "  SKIP: no sha256sum or shasum here; the stale folder lock cases did not run"
fi

# --- 4) the progress line while an image is read
echo "== progress line"
(
    # shellcheck disable=SC1090
    eval "$(extract_fn "$SCRIPT" start_progress_ticker)"
    eval "$(extract_fn "$SCRIPT" stop_progress_ticker)"
    PROGRESS_TICKER_PID=""
    export BOMLENS_PROGRESS_SECS=1
    start_progress_ticker "image scan test" > "$WORK/tick"
    sleep 3
    stop_progress_ticker
    kill -0 "$PROGRESS_TICKER_PID" 2>/dev/null && exit 1
    exit 0
) && pass "the ticker can be started and stopped" || fail "ticker stop"
sleep 1
if [ "$(grep -c '^\[INFO\] Still running: image scan test' "$WORK/tick")" -ge 1 ]; then pass "a still-running line is printed while the container runs"; else fail "ticker line" "$(cat "$WORK/tick")"; fi
n1="$(wc -l < "$WORK/tick")"; sleep 2; n2="$(wc -l < "$WORK/tick")"
if [ "$n1" = "$n2" ]; then pass "no line after the ticker stopped"; else fail "ticker kept running"; fi

# --- 5) a Gradle root named with a leading dot
echo "== Gradle root folder name"
{
    printf 'log() { echo "[build-prep] $*"; }\n'
    extract_fn "$ROOT_DIR/docker/lib/build-prep.sh" gradle_dot_root_settings
} > "$WORK/gd.sh"
mkdir -p "$WORK/.srccopy-ab12cd34" "$WORK/plainproj" "$WORK/.hidden-own"
echo "plugins { id 'java' }" > "$WORK/.srccopy-ab12cd34/build.gradle"
echo "plugins { id 'java' }" > "$WORK/plainproj/build.gradle"
echo "plugins { id 'java' }" > "$WORK/.hidden-own/build.gradle"; echo "rootProject.name = 'mine'" > "$WORK/.hidden-own/settings.gradle"
for d in .srccopy-ab12cd34 plainproj .hidden-own; do sh -c ". '$WORK/gd.sh'; gradle_dot_root_settings '$WORK/$d'" >/dev/null 2>&1; done
if grep -q "^rootProject.name = 'srccopy-ab12cd34'$" "$WORK/.srccopy-ab12cd34/settings.gradle" 2>/dev/null; then
    pass "a dot-named copy without settings.gradle gets a valid project name"
else
    fail "dot-named root" "$(cat "$WORK/.srccopy-ab12cd34/settings.gradle" 2>&1)"
fi
if [ ! -e "$WORK/plainproj/settings.gradle" ]; then pass "a normally named folder is left alone"; else fail "plain folder touched"; fi
if [ "$(cat "$WORK/.hidden-own/settings.gradle")" = "rootProject.name = 'mine'" ]; then pass "an existing settings.gradle is kept"; else fail "own settings overwritten"; fi

# --- 6) Package.resolved inside the Xcode project is the lock file
echo "== Xcode-held Package.resolved"
mkdir -p "$WORK/ios1/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm" "$WORK/ios2"
for d in ios1 ios2; do printf '// swift-tools-version:5.5\nlet package = Package(dependencies: [.package(url: "https://x/y", from: "1.0.0")])\n' > "$WORK/$d/Package.swift"; done
echo '{"pins":[],"version":2}' > "$WORK/ios1/App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"
for d in ios1 ios2; do
    echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "$WORK/$d.json"
    bash "$ROOT_DIR/docker/lib/detect-lockfile-state.sh" "$WORK/$d" "$WORK/$d.json" >/dev/null 2>&1
done
if jq -e 'any(.metadata.properties[]?; .name == "bomlens:lockfile-missing")' "$WORK/ios1.json" >/dev/null 2>&1; then fail "xcodeproj Package.resolved still reported missing"; else pass "Package.resolved in the .xcodeproj counts as the lock file"; fi
if jq -e 'any(.metadata.properties[]?; .name == "bomlens:lockfile-missing")' "$WORK/ios2.json" >/dev/null 2>&1; then pass "no Package.resolved anywhere is still reported"; else fail "missing lock file not reported"; fi
mkdir -p "$WORK/ios3/A.xcworkspace/xcshareddata/swiftpm"
cp "$WORK/ios2/Package.swift" "$WORK/ios3/"; echo 'not json' > "$WORK/ios3/A.xcworkspace/xcshareddata/swiftpm/Package.resolved"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "$WORK/ios3.json"
bash "$ROOT_DIR/docker/lib/detect-lockfile-state.sh" "$WORK/ios3" "$WORK/ios3.json" >/dev/null 2>&1
if jq -e 'any(.metadata.properties[]?; .name == "bomlens:lockfile-corrupt")' "$WORK/ios3.json" >/dev/null 2>&1 \
   && ! jq -e 'any(.metadata.properties[]?; .name == "bomlens:lockfile-missing")' "$WORK/ios3.json" >/dev/null 2>&1; then
    pass "a damaged workspace Package.resolved is reported as damaged, not missing"
else
    fail "workspace lock file"
fi

# --- 7) check-setup names BomLens's own running UI
echo "== check-setup own UI port"
if command -v python3 >/dev/null 2>&1 && { command -v lsof >/dev/null 2>&1 || command -v ss >/dev/null 2>&1 || command -v netstat >/dev/null 2>&1; }; then
    PORT="$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
    python3 -I -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT)); s.listen(5); time.sleep(60)" &
    LISTEN_PID=$!
    sleep 1
    mkdir -p "$WORK/cs"
    cat > "$WORK/cs/docker" <<'MOCK'
#!/bin/bash
case "$1" in
    ps) if [ -n "${FAKE_OWN_UI:-}" ]; then echo "ghcr.io/sktelecom/bomlens:1.15.0"; fi; exit 0 ;;
    info|image) exit 0 ;;
    *) exit 0 ;;
esac
MOCK
    chmod +x "$WORK/cs/docker"
    out="$(cd "$WORK/cwd" && PATH="$WORK/cs:$PATH" UI_PORT="$PORT" SBOM_LANG=en FAKE_OWN_UI=1 bash "$ROOT_DIR/scripts/check-setup.sh" 2>&1)"
    if printf '%s\n' "$out" | grep -q "used by BomLens's own web UI" && ! printf '%s\n' "$out" | grep -q 'already in use'; then
        pass "BomLens's own UI on the port is named, not reported as an error"
    else
        fail "own UI port" "$(printf '%s\n' "$out" | grep -i port)"
    fi
    out="$(cd "$WORK/cwd" && PATH="$WORK/cs:$PATH" UI_PORT="$PORT" SBOM_LANG=en bash "$ROOT_DIR/scripts/check-setup.sh" 2>&1)"
    if printf '%s\n' "$out" | grep -q 'already in use'; then pass "another program on the port is still an error"; else fail "foreign port user" "$(printf '%s\n' "$out" | grep -i port)"; fi
    kill "$LISTEN_PID" 2>/dev/null; LISTEN_PID=""
else
    echo "  SKIP: python3 or a port tool is missing"
fi

# --- 8) the component counts say what each number counts
echo "== component count basis"
if command -v jq >/dev/null 2>&1; then
    cat > "$WORK/img.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"component":{"type":"container","name":"alpine"}},
 "components":[
  {"type":"library","name":"musl","version":"1","purl":"pkg:apk/alpine/musl@1"},
  {"type":"library","name":"busybox","version":"1","purl":"pkg:apk/alpine/busybox@1"},
  {"type":"operating-system","name":"alpine","version":"3.19"},
  {"type":"file","name":"/etc/os-release"}]}
JSON
    bash "$ROOT_DIR/docker/lib/generate-notice.sh" "$WORK/img.json" "$WORK/img" imgp >"$WORK/notice.log" 2>&1
    if grep -q '^Counted: 0 libraries, 2 OS packages, 1 operating system, 1 files' "$WORK/img_NOTICE.txt" \
       && grep -q '4 components: 0 libraries, 2 OS packages, 1 operating system, 1 files' "$WORK/notice.log"; then
        pass "the notice and its log line split the operating system entry from the OS packages"
    else
        fail "notice count basis" "$(grep -i 'counted' "$WORK/img_NOTICE.txt"; cat "$WORK/notice.log")"
    fi
    bash "$ROOT_DIR/docker/lib/validate-sbom.sh" "$WORK/img.json" "$WORK/img" supplier >/dev/null 2>&1
    if grep -q "^components	2$" "$WORK/img_summary.result" 2>/dev/null \
       && grep -q "^basis	0 libraries, 2 OS packages, 1 operating system, 1 files; 4 entries in all, 2 of them identified components" "$WORK/img_summary.result"; then
        pass "the summary states how its identified count relates to the entries in the SBOM"
    else
        fail "summary basis" "$(cat "$WORK/img_summary.result" 2>&1)"
    fi
fi

# --- 9) the scan container's processing lines on a terminal, and the scan log
echo "== container output and the scan log"
mkdir -p "$WORK/qbin"
cat > "$WORK/qbin/docker" <<'MOCK'
#!/bin/bash
case "$1" in
    run)
        for a in "$@"; do
            case "$a" in
                *:/host-output|*:/host-output:*)
                    d="${a%%:/host-output*}"; d="${d%\"}"; d="${d#\"}"
                    printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}' > "$d/q_1_bom.json" ;;
            esac
        done
        echo "[1/2] Scanning the image"
        echo "[cpe] set a cpe:2.3 on 0 component(s)"
        echo "[notice] PDF skipped: no PDF renderer in image"
        echo "    a continuation of the notice line"
        echo "[validate] CycloneDX -> result=pass (mandatory fails=0)"
        echo "[INFO] source-snapshot: captured 4 file(s)"
        echo "[security] the advisory lookup failed: timeout"
        echo "[WARN] a warning from the container" >&2
        echo "an unknown line" ;;
    *) exit 0 ;;
esac
MOCK
for opener in open xdg-open; do printf '#!/bin/sh\nexit 0\n' > "$WORK/qbin/$opener"; chmod +x "$WORK/qbin/$opener"; done
chmod +x "$WORK/qbin/docker"
run_q() {
    ( cd "$WORK/cwd" && PATH="$WORK/qbin:$PATH" HOME="$WORK/home" SBOM_PULL=never "$@" >"$WORK/out" 2>"$WORK/err" )
    RC=$?
}
QARGS="--project q --version 1 --target alpine:3.20 --generate-only --notice"
rm -rf "$WORK/q1"
# shellcheck disable=SC2086
_BOMLENS_FORCE_TTY=1 VERBOSE=false run_q bash "$SCRIPT" $QARGS -o "$WORK/q1"
if [ "$RC" = 0 ] && grep -q '^\[1/2\] Scanning the image' "$WORK/out" && grep -q '^an unknown line' "$WORK/out" \
   && ! grep -qE '^\[(cpe|notice|validate)\]|source-snapshot|a continuation' "$WORK/out"; then
    pass "on a terminal the processing lines are hidden; stage lines and unknown lines stay"
else
    fail "quiet terminal output" "rc=$RC $(head -c 400 "$WORK/out")"
fi
if grep -q '^\[WARN\] a warning from the container' "$WORK/err" && grep -q 'the advisory lookup failed' "$WORK/out"; then
    pass "a [WARN] line and a line naming a failure are shown on a terminal"
else
    fail "warnings on a terminal" "out=$(head -c 300 "$WORK/out") err=$(head -c 300 "$WORK/err")"
fi
if grep -q '^\[cpe\] set a cpe' "$WORK/q1/q_1/q_1_scan.log" 2>/dev/null && grep -q '^\[WARN\] a warning' "$WORK/q1/q_1/q_1_scan.log" \
   && grep -q 'q_1_scan.log' "$WORK/out"; then
    pass "every container line is kept in <prefix>_scan.log and the summary names it"
else
    fail "scan log" "$(ls "$WORK/q1/q_1" 2>&1)"
fi
# The notice is requested and not produced: the summary's pointer to the details.
if grep -q 'check q_1_scan.log for its warning' "$WORK/err"; then
    pass "on a terminal the summary points to the scan log for details"
else
    fail "quiet log pointer" "$(grep -i 'degraded' "$WORK/err")"
fi
rm -rf "$WORK/q2"
# shellcheck disable=SC2086
_BOMLENS_FORCE_TTY=1 VERBOSE=true run_q bash "$SCRIPT" $QARGS -o "$WORK/q2"
if grep -q '^\[cpe\] set a cpe' "$WORK/out" && grep -q '^\[notice\] PDF skipped' "$WORK/out"; then
    pass "VERBOSE=true shows every processing line on a terminal"
else
    fail "VERBOSE=true" "$(head -c 400 "$WORK/out")"
fi
rm -rf "$WORK/q3"
# shellcheck disable=SC2086
_BOMLENS_FORCE_TTY=1 VERBOSE=false run_q bash "$SCRIPT" $QARGS --verbose -o "$WORK/q3"
if grep -q '^\[cpe\] set a cpe' "$WORK/out"; then pass "--verbose shows every processing line"; else fail "--verbose" "$(head -c 400 "$WORK/out")"; fi
rm -rf "$WORK/q4"
# shellcheck disable=SC2086
VERBOSE=false run_q bash "$SCRIPT" $QARGS -o "$WORK/q4"
if grep -q '^\[cpe\] set a cpe' "$WORK/out" && grep -q '^\[WARN\] a warning' "$WORK/err" && ! grep -q '^\[WARN\]' "$WORK/out"; then
    pass "output to a file is not shortened, and the container's stderr stays on stderr"
else
    fail "output to a file" "out=$(head -c 300 "$WORK/out") err=$(head -c 300 "$WORK/err")"
fi
if grep -q 'check the log above for its warning' "$WORK/err"; then pass "output to a file keeps 'the log above'"; else fail "log pointer in a file" "$(grep -i 'degraded' "$WORK/err")"; fi
# A source scan's post-processing container numbers its own steps; on a
# terminal only the CLI's stages are shown then, and a single-container scan's
# own stages stay.
(
    eval "$(extract_fn "$SCRIPT" container_line_names_problem)"
    eval "$(extract_fn "$SCRIPT" container_line_is_detail)"
    # shellcheck disable=SC2034  # read by the lifted container_line_is_detail
    HIDE_CONTAINER_STAGES=1
    container_line_is_detail out "[1/2] static: source dir /src (lock file, no build)" || exit 1
    # shellcheck disable=SC2034
    HIDE_CONTAINER_STAGES=0
    container_line_is_detail out "[1/2] syft: Docker image alpine:3.20" && exit 1
    exit 0
) && pass "the post-processing container's own [N/M] lines are hidden, a single-container scan's are not" \
  || fail "container stage lines"
# --ui started from a BomLens clone says the folder it would scan is BomLens itself.
mkdir -p "$WORK/repo/scripts" "$WORK/repo/docker/web"
: > "$WORK/repo/scripts/scan-sbom.sh"; : > "$WORK/repo/docker/web/server.py"
( cd "$WORK/repo" && PATH="$WORK/qbin:$PATH" HOME="$WORK/home" SBOM_PULL=never UI_PORT=18397 \
    bash "$SCRIPT" --ui -o "$WORK/uiout" >"$WORK/out" 2>"$WORK/err" ); RC=$?
if grep -q 'The current folder is the BomLens repository' "$WORK/out" && grep -q '현재 폴더는 BomLens 저장소입니다' "$WORK/out" && [ "$RC" = 0 ]; then
    pass "--ui from the BomLens repository says so in English and Korean, and starts"
else
    fail "--ui repository notice" "rc=$RC $(head -c 300 "$WORK/out") $(head -c 300 "$WORK/err")"
fi
( cd "$WORK/cwd" && PATH="$WORK/qbin:$PATH" HOME="$WORK/home" SBOM_PULL=never UI_PORT=18397 \
    bash "$SCRIPT" --ui -o "$WORK/uiout" >"$WORK/out" 2>"$WORK/err" )
if ! grep -q 'BomLens repository' "$WORK/out"; then pass "--ui from another folder does not"; else fail "--ui notice elsewhere"; fi

echo ""
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
