#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-cli-conventions.sh - No-Docker tests for the CLI's exit codes and output
# streams: a missing path-shaped --target, the upload skip, Docker's own run
# failures, the stderr split, a busy UI port, and the Windows path length check.
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

# A docker that is up, has every image, and fails `run` with $FAKE_RUN_RC.
cat > "$WORK/bin/docker" <<'MOCK'
#!/bin/bash
case "$1" in
    info) exit 0 ;;
    image) exit 0 ;;
    ps) exit 0 ;;
    run) exit "${FAKE_RUN_RC:-0}" ;;
    *) exit 0 ;;
esac
MOCK
chmod +x "$WORK/bin/docker"

# run_cli <args...>: stdout to $WORK/out, stderr to $WORK/err, status in $RC.
run_cli() {
    ( cd "$WORK/cwd" && PATH="$WORK/bin:$PATH" SBOM_PULL=never HOME="$WORK/home" \
        bash "$SCRIPT" "$@" >"$WORK/out" 2>"$WORK/err" )
    RC=$?
}

# --- decision 2: a path-shaped --target that does not exist
# shellcheck disable=SC2088  # the tilde is meant literally: the script must see it unexpanded
for t in ./nope ../nope /nope/at/all '~/nope' 'C:/nope'; do
    run_cli --project p --version 1 --target "$t" --generate-only
    if [ "$RC" = 1 ] && grep -q '^\[ERROR\] --target' "$WORK/err"; then
        pass "missing path-shaped --target '$t' exits 1"
    else
        fail "missing path-shaped --target '$t'" "rc=$RC err=$(head -c 200 "$WORK/err")"
    fi
done
run_cli --project p --version 1 --target missing.tar --generate-only
if grep -q '^\[WARN\] --target .missing.tar. is not a file or folder' "$WORK/err"; then
    pass "a name that only ends like an archive still warns and is read as an image"
else
    fail "suffix-only target keeps the warning" "rc=$RC err=$(head -c 200 "$WORK/err")"
fi

# --- decision 5: the script's own [WARN] and [ERROR] are on stderr
run_cli --no-such-option
if [ "$RC" = 1 ] && grep -q '^\[ERROR\] Unknown option' "$WORK/err" && ! grep -q '\[ERROR\]' "$WORK/out"; then
    pass "[ERROR] goes to stderr, none on stdout"
else
    fail "[ERROR] stream" "rc=$RC out=$(head -c 200 "$WORK/out")"
fi
if grep -q '^\[WARN\]' "$WORK/out"; then fail "[WARN] stayed on stdout"; else pass "[WARN] is not on stdout"; fi

# --- decision 3 and 4: no upload server -> skipped; Docker's own failure -> 1
for rc in 125 126 127; do
    FAKE_RUN_RC=$rc run_cli --project p --version 1 --target alpine:3.20
    if [ "$RC" = 1 ] && grep -q "docker exit code $rc" "$WORK/err"; then
        pass "docker run exit $rc leaves the script as 1 with the cause"
    else
        fail "docker run exit $rc" "rc=$RC err=$(tail -n 3 "$WORK/err" | head -c 300)"
    fi
done
FAKE_RUN_RC=4 run_cli --project p --version 1 --target alpine:3.20
if [ "$RC" = 4 ]; then pass "a scan container's own exit code is kept (4)"; else fail "container exit code kept" "rc=$RC"; fi
if grep -q 'No upload server is set' "$WORK/out"; then
    pass "no API key and no server: the upload is skipped with one line"
else
    fail "upload skip line" "out=$(head -c 300 "$WORK/out")"
fi
FAKE_RUN_RC=125 API_URL=http://dt.example run_cli --project p --version 1 --target alpine:3.20
if grep -q 'No upload server is set' "$WORK/out"; then
    fail "an explicit API_URL must keep the upload"
else
    pass "an explicit API_URL keeps the upload"
fi
run_cli --project p --version 1 --target alpine:3.20 --generate-only
if grep -q 'No upload server is set' "$WORK/out"; then fail "--generate-only prints the skip line"; else pass "--generate-only prints no skip line"; fi

# --- the busy UI port
if command -v python3 >/dev/null 2>&1; then
    PORT="$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
    python3 -I -c "
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT)); s.listen(5); time.sleep(60)" &
    LISTEN_PID=$!
    sleep 1
    UI_PORT="$PORT" run_cli --ui
    if [ "$RC" = 1 ] && grep -q "Port $PORT is already in use" "$WORK/err" \
       && grep -q "UI_PORT=$((PORT + 1)) ./scripts/scan-sbom.sh --ui" "$WORK/err" \
       && ! grep -q 'http://localhost' "$WORK/out"; then
        pass "a busy UI port stops before the address is printed, with the way out"
    else
        fail "busy UI port" "rc=$RC err=$(head -c 300 "$WORK/err") out=$(head -c 200 "$WORK/out")"
    fi
    kill "$LISTEN_PID" 2>/dev/null; LISTEN_PID=""
fi
UI_PORT=80x run_cli --ui
if [ "$RC" = 1 ] && grep -q 'UI_PORT must be a port number' "$WORK/err"; then pass "a non-numeric UI_PORT is refused"; else fail "UI_PORT validation" "rc=$RC"; fi

# --- lifted helpers
extract_fn() {
    awk -v fn="$1" '
        $0 ~ "^" fn "\\(\\) \\{" { inside = 1 }
        inside { print }
        inside && $0 == "}" { exit }
    ' "$SCRIPT"
}
for fn in log_warn log_error wait_with_progress docker_run_failure_code engine_stopped_during_scan remove_earlier_result windows_path_too_long; do
    body="$(extract_fn "$fn")"
    if [ -z "$body" ]; then echo "[ERROR] could not lift $fn out of scan-sbom.sh (was it renamed?)"; exit 1; fi
    eval "$body"
done

printf 'unexpected EOF\ndocker: error during connect: x\n' > "$WORK/log1"
printf 'npm ERR! network timeout\n' > "$WORK/log2"
if engine_stopped_during_scan 1 "$WORK/log1" 2>/dev/null; then pass "an engine error in the log is read as an engine stop"; else fail "engine stop from log"; fi
if engine_stopped_during_scan 1 "$WORK/log2" 2>/dev/null; then fail "an ordinary cdxgen failure read as an engine stop"; else pass "an ordinary cdxgen failure is not an engine stop"; fi

mkdir -p "$WORK/res"; : > "$WORK/res/old.json"
if ( remove_earlier_result "$WORK/res/old.json" ) 2>/dev/null && [ ! -e "$WORK/res/old.json" ]; then
    pass "remove_earlier_result removes the file"
else
    fail "remove_earlier_result removes"
fi
if [ "$(id -u)" != 0 ]; then
    : > "$WORK/res/busy.json"; chmod a-w "$WORK/res"
    out="$( ( remove_earlier_result "$WORK/res/busy.json" ) 2>&1 )"; rc=$?
    chmod u+w "$WORK/res"
    if [ "$rc" = 1 ] && printf '%s' "$out" | grep -q "busy.json" && printf '%s' "$out" | grep -q 'Close it and run again'; then
        pass "a file that cannot be removed names the file, the reason and the fix"
    else
        fail "remove_earlier_result failure message" "rc=$rc out=$out"
    fi
fi

sleep 3 & _bg=$!
out="$(BOMLENS_PROGRESS_SECS=1 wait_with_progress "$_bg" "stage 1 test" 2>&1)"
wait "$_bg" 2>/dev/null
if [ "$(printf '%s\n' "$out" | grep -c '^\[INFO\] Still running: stage 1 test')" -ge 1 ]; then
    pass "a long wait prints one progress line per period"
else
    fail "progress line" "out=$out"
fi

SBOM_OUTPUT_FLAT=1 run_cli --project p --version 1 --target alpine:3.20 --timestamp --generate-only
if grep -q '^\[WARN\] --timestamp only names the run subfolder' "$WORK/err"; then
    pass "--timestamp with SBOM_OUTPUT_FLAT=1 warns that it has no effect"
else
    fail "timestamp with flat output" "err=$(head -c 300 "$WORK/err")"
fi

DOCKER_MSYS=""
if windows_path_too_long "$(printf 'a%.0s' $(seq 1 300))" "x"; then fail "path check off Windows"; else pass "the path length check does nothing off Windows"; fi
# shellcheck disable=SC2034  # read by the lifted windows_path_too_long
DOCKER_MSYS="x"; hostpath() { printf '%s' "$1"; }
long="$(printf 'a%.0s' $(seq 1 300))"
if out="$(windows_path_too_long "$long" "The --target path" 2>&1)" && printf '%s' "$out" | grep -q 'not a Docker engine problem'; then
    pass "a path of 260 characters or more is named, apart from an engine failure"
else
    fail "long path message"
fi
if windows_path_too_long "short" "x" 2>/dev/null; then fail "a short path flagged"; else pass "a short path is not flagged"; fi

echo ""
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
