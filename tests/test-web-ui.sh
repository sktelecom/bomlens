#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-web-ui.sh — No-Docker contract tests for the web UI server (docker/web/server.py).
#
# Runs the stdlib HTTP server standalone (SBOM_OUTPUT_DIR points at a temp dir) and
# exercises the endpoints the browser depends on — most importantly the file-upload
# round-trip (POST /upload), which the rest of the test suite never covered and
# where a regression surfaces as the UI's "upload failed: Failed to fetch". No
# Docker, no network: pure python3 + curl, so it runs in CI.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$ROOT_DIR/docker/web/server.py"
PORT="${WEB_UI_TEST_PORT:-18099}"
BASE="http://127.0.0.1:${PORT}"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); }

command -v python3 >/dev/null 2>&1 || { echo "[ERROR] python3 required"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "[ERROR] curl required"; exit 1; }

WORK="$(mktemp -d)"
OUT="$WORK/out"; mkdir -p "$OUT"
SRV_PID=""
cleanup() { [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== starting server.py standalone (SBOM_OUTPUT_DIR=$OUT, port $PORT) =="
SBOM_OUTPUT_DIR="$OUT" UI_PORT="$PORT" SBOM_UI_HOST_DIR="$WORK" \
    python3 "$SERVER" > "$WORK/server.log" 2>&1 &
SRV_PID=$!
disown "$SRV_PID" 2>/dev/null || true  # silence the job-control "Terminated" notice on cleanup

# Readiness via an API endpoint, not the SPA: the built dist lives at
# docker/web/frontend/dist in the source tree (the container copies it next to
# server.py), so static serving is only wired up in the image. This test covers
# the API/upload contract.
ready=0
for _ in $(seq 1 30); do
    if curl -fsS "$BASE/capabilities" >/dev/null 2>&1; then ready=1; break; fi
    kill -0 "$SRV_PID" 2>/dev/null || { echo "[ERROR] server exited early:"; cat "$WORK/server.log"; exit 1; }
    sleep 0.3
done
[ "$ready" = 1 ] && pass "server is up and answering the API" || { fail "server did not become ready" "$(tail -5 "$WORK/server.log")"; exit 1; }

echo "== capabilities + results contract =="
caps=$(curl -fsS "$BASE/capabilities" 2>/dev/null)
if echo "$caps" | python3 -c "import sys,json;d=json.load(sys.stdin);assert all(k in d for k in('firmware','docker','scanoss'))" 2>/dev/null; then
    pass "/capabilities reports firmware, docker, scanoss flags"
else
    fail "/capabilities missing expected keys" "$caps"
fi
if curl -fsS "$BASE/results" 2>/dev/null | python3 -c "import sys,json;assert isinstance(json.load(sys.stdin),list)" 2>/dev/null; then
    pass "/results returns a JSON array"
else
    fail "/results is not a JSON array"
fi

echo "== path traversal is blocked =="
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/file?name=../../etc/passwd")
[ "$code" = "404" ] && pass "/file blocks path traversal (404)" || fail "/file traversal returned $code (expected 404)"

echo "== upload round-trip (the regression that shows as 'Failed to fetch') =="
echo "hello" > "$WORK/payload.txt"
( cd "$WORK" && zip -q sample.zip payload.txt )
resp=$(curl -fsS -F "kind=zip" -F "file=@$WORK/sample.zip" "$BASE/upload?kind=zip" 2>/dev/null)
token=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -n "$token" ]; then
    pass "POST /upload (zip) returns a token"
else
    fail "POST /upload did not return a token" "$resp"
fi
# The uploaded file must be saved under the token dir (traversal-safe token).
if [ -n "$token" ] && [ -n "$(find "$OUT/.uploads/$token" -name '*.zip' 2>/dev/null | head -1)" ]; then
    pass "uploaded file saved under .uploads/<token>/"
else
    fail "uploaded file not found under .uploads/<token>/" "token=$token"
fi
# Unknown kind / wrong extension / missing body are rejected, not 200.
c_kind=$(curl -s -o /dev/null -w '%{http_code}' -F "file=@$WORK/sample.zip" "$BASE/upload?kind=bogus")
[ "$c_kind" = "400" ] && pass "unknown upload kind rejected (400)" || fail "bogus kind returned $c_kind (expected 400)"
c_ext=$(curl -s -o /dev/null -w '%{http_code}' -F "kind=zip" -F "file=@$WORK/payload.txt" "$BASE/upload?kind=zip")
[ "$c_ext" = "415" ] && pass "wrong extension rejected (415)" || fail ".txt as zip returned $c_ext (expected 415)"

echo "== git-cred stash returns a credId =="
cid=$(curl -fsS -X POST -H "Content-Type: application/json" -d '{"token":"ghp_demo"}' "$BASE/git-cred" 2>/dev/null \
      | python3 -c "import sys,json;print(json.load(sys.stdin).get('credId',''))" 2>/dev/null)
[ -n "$cid" ] && pass "POST /git-cred returns a credId" || fail "/git-cred did not return a credId"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
