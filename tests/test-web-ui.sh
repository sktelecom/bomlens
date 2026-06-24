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

echo "== component Risk/Scope join (sbom_summary) =="
# Fixtures: flask is a direct dep; werkzeug/jinja2 are transitive. werkzeug has
# two CVEs (one CRITICAL) — the second's purl carries a qualifier to prove the
# join normalizes. openssl (flat SBOM, no graph) joins risk by name/version and
# has no scope. Malformed security must not crash the summary.
cat > "$OUT/demo_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX",
 "metadata":{"component":{"bom-ref":"root","name":"demo","version":"1.0"}},
 "components":[
   {"bom-ref":"pkg:pypi/flask@2.0","name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"},
   {"bom-ref":"pkg:pypi/werkzeug@2.0","name":"werkzeug","version":"2.0","type":"library","purl":"pkg:pypi/werkzeug@2.0"},
   {"bom-ref":"pkg:pypi/jinja2@3.0","name":"jinja2","version":"3.0","type":"library","purl":"pkg:pypi/jinja2@3.0"}
 ],
 "dependencies":[
   {"ref":"root","dependsOn":["pkg:pypi/flask@2.0"]},
   {"ref":"pkg:pypi/flask@2.0","dependsOn":["pkg:pypi/werkzeug@2.0","pkg:pypi/jinja2@3.0"]}
 ]}
JSON
cat > "$OUT/demo_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[
  {"VulnerabilityID":"CVE-1","Severity":"CRITICAL","PkgName":"werkzeug","InstalledVersion":"2.0","PkgIdentifier":{"PURL":"pkg:pypi/werkzeug@2.0"}},
  {"VulnerabilityID":"CVE-2","Severity":"LOW","PkgName":"werkzeug","InstalledVersion":"2.0","PkgIdentifier":{"PURL":"pkg:pypi/werkzeug@2.0?foo=bar"}}
]}]}
JSON
cat > "$OUT/flat_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","components":[{"name":"openssl","version":"3.0","type":"library","purl":"pkg:generic/openssl@3.0"}]}
JSON
cat > "$OUT/flat_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-X","Severity":"HIGH","PkgName":"openssl","InstalledVersion":"3.0"}]}]}
JSON
cat > "$OUT/bad_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","components":[{"name":"a","version":"1","type":"library"}]}
JSON
printf 'not json{' > "$OUT/bad_1.0_security.json"
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
demo = {r["name"]: r for r in server.sbom_summary("demo", "1.0")["componentList"]}
assert demo["flask"]["scope"] == "direct", demo["flask"]
assert demo["werkzeug"]["scope"] == "transitive", demo["werkzeug"]
assert demo["jinja2"]["scope"] == "transitive", demo["jinja2"]
assert demo["werkzeug"]["maxSeverity"] == "CRITICAL", demo["werkzeug"]
assert demo["werkzeug"]["vulnCount"] == 2, demo["werkzeug"]
assert "maxSeverity" not in demo["flask"], demo["flask"]
flat = {r["name"]: r for r in server.sbom_summary("flat", "1.0")["componentList"]}
assert "scope" not in flat["openssl"], flat["openssl"]
assert flat["openssl"]["maxSeverity"] == "HIGH", flat["openssl"]
assert flat["openssl"]["vulnCount"] == 1, flat["openssl"]
bad = {r["name"]: r for r in server.sbom_summary("bad", "1.0")["componentList"]}
assert "maxSeverity" not in bad["a"], bad["a"]
PY
then
    pass "Risk/Scope join (direct/transitive, purl + name/version, no-graph, malformed)"
else
    fail "Risk/Scope join produced wrong values (see assertion above)"
fi
rm -f "$OUT"/demo_1.0_* "$OUT"/flat_1.0_* "$OUT"/bad_1.0_*

echo "== conformance checks exposure (G7 split) =="
# Generate a real conformance report for the AI fixture, then check that
# conformance_summary surfaces the per-check array with the G7 (g7-*) checks.
if command -v jq >/dev/null 2>&1; then
    PROJECT=conf GEN_AT=2026-01-01 bash "$ROOT_DIR/docker/lib/validate-sbom.sh" \
        "$ROOT_DIR/tests/fixtures/aibom-owasp-1_7.json" "$OUT/conf_1.0" >/dev/null 2>&1
    if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
c = server.conformance_summary("conf", "1.0")
assert c is not None, "no conformance summary"
checks = c.get("checks") or []
assert len(checks) > 0, "checks not exposed"
g7 = [x for x in checks if x["id"].startswith("g7-")]
base = [x for x in checks if not x["id"].startswith("g7-")]
assert len(g7) == 6, ("expected 6 G7 checks", len(g7))
assert len(base) >= 1, "no base checks"
assert all(x["required"] is False for x in g7), "G7 checks must be advisory"
assert all(set(x) >= {"id", "label", "required", "status", "detail"} for x in checks)
PY
    then
        pass "conformance_summary exposes checks with the 6 G7 elements"
    else
        fail "conformance checks exposure / G7 split is wrong"
    fi
    rm -f "$OUT"/conf_1.0_*
else
    echo "  SKIP: jq not available for conformance generation"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
