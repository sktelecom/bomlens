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
if echo "$caps" | python3 -c "import sys,json;d=json.load(sys.stdin);assert all(k in d for k in('firmware','docker','scanoss','aibom','firmwareSibling','aibomSibling'))" 2>/dev/null; then
    pass "/capabilities reports firmware, docker, scanoss, aibom (+ sibling) flags"
else
    fail "/capabilities missing expected keys" "$caps"
fi
if curl -fsS "$BASE/results" 2>/dev/null | python3 -c "import sys,json;assert isinstance(json.load(sys.stdin),list)" 2>/dev/null; then
    pass "/results returns a JSON array"
else
    fail "/results is not a JSON array"
fi

echo "== sibling docker-run dispatch is allowlist-guarded =="
# Firmware/AI scans hand the job to a dedicated image via a sibling `docker run`.
# Every user-influenced value (image ref, MODE, MODEL_ID, project/version env)
# must pass an allowlist/sanitizer before it reaches the command line, so a
# crafted request can never smuggle a docker-run flag or shell metacharacter.
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

# Image ref allowlist: no leading '-', no whitespace, no flag smuggling.
assert server._valid_image_ref("ghcr.io/sktelecom/bomlens-aibom:1.5.0")
assert not server._valid_image_ref("-v/etc:/etc")
assert not server._valid_image_ref("img with space")
assert not server._valid_image_ref("")

# Model id allowlist (HuggingFace owner/name); reject traversal/flags.
assert server._valid_model_id("openai/clip-vit-base")
assert server._valid_model_id("bert-base-uncased")
assert not server._valid_model_id("../etc/passwd")
assert not server._valid_model_id("--privileged")
assert not server._valid_model_id("a b")

# Free-text env values are stripped to a bounded, flag-safe token.
assert server._env_flag_value("ok-name_1.0") == "ok-name_1.0"
assert ";" not in server._env_flag_value("a;rm -rf /")
assert "$" not in server._env_flag_value("$(whoami)")
assert "`" not in server._env_flag_value("`id`")
assert len(server._env_flag_value("x" * 5000)) <= 256

# The sibling shares files via --volumes-from THIS container, not a host bind: the
# output dir and firmware upload are CONTAINER paths, gated by containment
# (_path_under) so a traversal-crafted path cannot escape OUTPUT_DIR / UPLOAD_DIR.
assert server._path_under(server.OUTPUT_DIR + "/run_1", server.OUTPUT_DIR)
assert server._path_under(server.OUTPUT_DIR, server.OUTPUT_DIR)                 # equal ok
assert server._path_under(server.UPLOAD_DIR + "/tok/fw.bin", server.UPLOAD_DIR)
assert not server._path_under("/etc/passwd", server.OUTPUT_DIR)                 # outside
assert not server._path_under(server.OUTPUT_DIR + "/../etc", server.OUTPUT_DIR) # traversal escapes
assert not server._path_under("/tmp/evil", server.UPLOAD_DIR)
# self id: reads /proc/self/mountinfo, falls back to $HOSTNAME; always a str.
assert isinstance(server._self_container_id(), str)

run_out = server.OUTPUT_DIR + "/run_1"
up_file = server.UPLOAD_DIR + "/tok/fw.bin"

# Deterministic self id so the sibling launch does not depend on the test host.
server._self_container_id = lambda: "selfcid000000"

# A hostile project name reaches docker run only as a sanitized -e value, and
# an out-of-allowlist mode is refused outright (returns -1 without launching).
captured = {}
def fake_stream(args, on_log, on_progress=None, cancel=None, container=None):
    captured["args"] = args
    captured["container"] = container
    return 0
server._stream_cmd = fake_stream
server._sibling_image_present = lambda image: True

rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip",
    extra_env={"PROJECT_NAME": "a;rm -rf /", "PROJECT_VERSION": "1.0"},
)
assert rc == 0, rc
args = captured["args"]
# The PROJECT_NAME value reaches docker run only as one sanitized -e element
# (shell metacharacters stripped); it can never split into a new flag.
pname = [a for a in args if a.startswith("PROJECT_NAME=")][0]
assert not any(c in pname for c in ";`$&|<>\n"), pname
assert "MODE=AIBOM" in args and "MODEL_ID=openai/clip" in args, args
assert "ghcr.io/sktelecom/bomlens-aibom:1.5.0" in args, args
# Shared via --volumes-from, NOT a host-path bind mount; the run dir is the workdir
# and HOST_OUTPUT_DIR (container paths).
assert "--volumes-from" in args and "selfcid000000" in args, args
assert not any(a.endswith(":/host-output") for a in args), args
assert ("HOST_OUTPUT_DIR=%s" % run_out) in args, args
assert args[args.index("-w") + 1] == run_out, args

# Cancel support: a valid container_name reaches docker run as a `--name`
# (so a cancelled scan can be stopped); an invalid one is dropped, not smuggled.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip", container_name="bomlens-sib-demo_1.0",
)
assert rc == 0 and "--name" in captured["args"], captured.get("args")
assert "bomlens-sib-demo_1.0" in captured["args"], captured["args"]
assert captured["container"] == "bomlens-sib-demo_1.0", captured["container"]
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip", container_name="evil; rm -rf /",
)
assert rc == 0 and "--name" not in captured["args"], captured["args"]
assert captured["container"] is None, captured["container"]

# A firmware upload is read in place (TARGET_FILE = its container path), with no
# extra bind mount — --volumes-from already exposes it under UPLOAD_DIR.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-firmware:1.5.0", "FIRMWARE", run_out,
    lambda ln: None, upload_file=up_file,
)
assert rc == 0, rc
assert ("TARGET_FILE=%s" % up_file) in captured["args"], captured["args"]
assert not any("/input/" in a for a in captured["args"]), captured["args"]

# Opt-in OSV (includeOsv): the firmware path sets the two control env vars and
# they are forwarded to the sibling as exactly two fixed -e literals. AIBOM and
# the default (off) firmware path must NOT carry them.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-firmware:1.5.0", "FIRMWARE", run_out,
    lambda ln: None, upload_file=up_file,
    extra_env={"CVE_BIN_TOOL_DISABLE_SOURCES": "GAD", "CVE_BIN_TOOL_MODE": "online"},
)
assert rc == 0, rc
assert "CVE_BIN_TOOL_DISABLE_SOURCES=GAD" in captured["args"], captured["args"]
assert "CVE_BIN_TOOL_MODE=online" in captured["args"], captured["args"]

# Default firmware (no opt-in) forwards neither var -> offline-bundle default.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-firmware:1.5.0", "FIRMWARE", run_out,
    lambda ln: None, upload_file=up_file,
)
assert rc == 0, rc
assert not any(a.startswith("CVE_BIN_TOOL_") for a in captured["args"]), captured["args"]

# AIBOM never carries the OSV control vars even if present in extra_env.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip",
    extra_env={"CVE_BIN_TOOL_DISABLE_SOURCES": "GAD", "CVE_BIN_TOOL_MODE": "online"},
)
assert rc == 0, rc
assert not any(a.startswith("CVE_BIN_TOOL_") for a in captured["args"]), captured["args"]

# A bogus mode is refused before any docker run is attempted.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "EVIL", run_out, lambda ln: None,
)
assert rc == -1 and "args" not in captured, (rc, captured)

# A bogus model id is refused too.
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="--privileged",
)
assert rc == -1 and "args" not in captured, (rc, captured)

# An output dir outside OUTPUT_DIR (traversal / absolute escape) is refused.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", "/etc",
    lambda ln: None, model_id="openai/clip",
)
assert rc == -1 and "args" not in captured, (rc, captured)

# A firmware upload outside UPLOAD_DIR is refused too.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-firmware:1.5.0", "FIRMWARE", run_out,
    lambda ln: None, upload_file="/etc/passwd",
)
assert rc == -1 and "args" not in captured, (rc, captured)

# Firmware CVE-DB progress markers become a `progress` channel call (clamped
# 0..100); everything else stays a plain log line. A missing progress handler
# falls back to log so older callers keep working.
logs = []; progs = []
server._emit_or_log("[firmware-cvedb-progress] 42%", logs.append, progs.append)
server._emit_or_log("[firmware-cvedb-progress] 250%", logs.append, progs.append)
server._emit_or_log("regular build line", logs.append, progs.append)
server._emit_or_log("[firmware-cvedb-progress] 10%", logs.append, None)
assert progs == [42, 100], progs
assert logs == ["regular build line", "[firmware-cvedb-progress] 10%"], logs
PY
then
    pass "sibling dispatch allowlists image/mode/model-id and sanitizes env (no flag/shell injection)"
else
    fail "sibling dispatch guard failed (see assertion above)"
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
demo = {r["name"]: r for r in server.sbom_summary("demo_1.0")["componentList"]}
assert demo["flask"]["scope"] == "direct", demo["flask"]
assert demo["werkzeug"]["scope"] == "transitive", demo["werkzeug"]
assert demo["jinja2"]["scope"] == "transitive", demo["jinja2"]
assert demo["werkzeug"]["maxSeverity"] == "CRITICAL", demo["werkzeug"]
assert demo["werkzeug"]["vulnCount"] == 2, demo["werkzeug"]
assert "maxSeverity" not in demo["flask"], demo["flask"]
flat = {r["name"]: r for r in server.sbom_summary("flat_1.0")["componentList"]}
assert "scope" not in flat["openssl"], flat["openssl"]
assert flat["openssl"]["maxSeverity"] == "HIGH", flat["openssl"]
assert flat["openssl"]["vulnCount"] == 1, flat["openssl"]
bad = {r["name"]: r for r in server.sbom_summary("bad_1.0")["componentList"]}
assert "maxSeverity" not in bad["a"], bad["a"]
PY
then
    pass "Risk/Scope join (direct/transitive, purl + name/version, no-graph, malformed)"
else
    fail "Risk/Scope join produced wrong values (see assertion above)"
fi
echo "== EOL flag surfaced + counted (sbom_summary) =="
# enrich-eol.sh writes bomlens:eol / bomlens:eol:date on mapped components.
# sbom_summary must surface them per-row (eol/eolDate) and aggregate: eolCount =
# every eol=true; atRiskCount = eol=true that ALSO has a vulnerability (the
# actionable set). boot has a CVE (at risk); ex is EOL but clean; dj is supported;
# lo is unmapped (no property, not counted).
cat > "$OUT/eolsum_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX",
 "components":[
   {"name":"boot","version":"3.2.0","type":"library","purl":"pkg:maven/org.springframework.boot/boot@3.2.0",
    "properties":[{"name":"bomlens:eol","value":"true"},{"name":"bomlens:eol:date","value":"2024-12-31"}]},
   {"name":"ex","version":"3.0","type":"library","purl":"pkg:npm/ex@3.0",
    "properties":[{"name":"bomlens:eol","value":"true"}]},
   {"name":"dj","version":"5.0","type":"library","purl":"pkg:pypi/dj@5.0",
    "properties":[{"name":"bomlens:eol","value":"false"},{"name":"bomlens:eol:date","value":"2099-01-01"}]},
   {"name":"lo","version":"4.0","type":"library","purl":"pkg:npm/lo@4.0"}
 ]}
JSON
cat > "$OUT/eolsum_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[
  {"VulnerabilityID":"CVE-9","Severity":"HIGH","PkgName":"boot","InstalledVersion":"3.2.0","PkgIdentifier":{"PURL":"pkg:maven/org.springframework.boot/boot@3.2.0"}}
]}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
s = server.sbom_summary("eolsum_1.0")
assert s["eolCount"] == 2, s              # boot + ex
assert s["atRiskCount"] == 1, s           # boot (EOL + CVE); ex is EOL but clean
rows = {r["name"]: r for r in s["componentList"]}
assert rows["boot"]["eol"] == "true", rows["boot"]
assert rows["boot"]["eolDate"] == "2024-12-31", rows["boot"]
assert rows["boot"]["vulnCount"] == 1, rows["boot"]
assert rows["ex"]["eol"] == "true", rows["ex"]
assert "eolDate" not in rows["ex"], rows["ex"]      # no date property -> absent
assert rows["dj"]["eol"] == "false", rows["dj"]
assert "eol" not in rows["lo"], rows["lo"]          # unmapped -> no eol field
PY
then
    pass "EOL surfaced per-row and aggregated (eolCount/atRiskCount, date, unmapped skip)"
else
    fail "EOL summary produced wrong values (see assertion above)"
fi
echo "== version currency surfaced + counted (sbom_summary) =="
# enrich-eol.sh writes bomlens:currency:* (offline, behind latest patch in cycle);
# enrich-staleness.py (opt-in) writes bomlens:staleness:* (deps.dev absolute). The
# summary surfaces both per-row (outdated/latestVersion/releasesBehind/lastReleased)
# and counts outdatedCount. deps.dev latest wins over the in-cycle patch.
cat > "$OUT/cur_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX",
 "components":[
   {"name":"boot","version":"3.2.0","type":"library","purl":"pkg:maven/x/boot@3.2.0",
    "properties":[{"name":"bomlens:currency:outdated","value":"true"},{"name":"bomlens:currency:latestPatch","value":"3.2.12"},
                  {"name":"bomlens:staleness:latest","value":"4.1.0"},{"name":"bomlens:staleness:releasesBehind","value":"82"},
                  {"name":"bomlens:staleness:lastReleased","value":"2026-06-10T00:00:00Z"}]},
   {"name":"fresh","version":"1.0","type":"library","purl":"pkg:npm/fresh@1.0",
    "properties":[{"name":"bomlens:currency:outdated","value":"false"},{"name":"bomlens:currency:latestPatch","value":"1.0"}]},
   {"name":"plain","version":"1.0","type":"library","purl":"pkg:npm/plain@1.0"}
 ]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
s = server.sbom_summary("cur_1.0")
assert s["outdatedCount"] == 1, s                       # boot outdated; fresh is current
rows = {r["name"]: r for r in s["componentList"]}
assert rows["boot"]["outdated"] == "true", rows["boot"]
assert rows["boot"]["latestVersion"] == "4.1.0", rows["boot"]   # deps.dev wins over in-cycle
assert rows["boot"]["releasesBehind"] == 82, rows["boot"]
assert rows["boot"]["lastReleased"] == "2026-06-10T00:00:00Z", rows["boot"]
assert rows["fresh"]["outdated"] == "false", rows["fresh"]
assert rows["fresh"]["latestVersion"] == "1.0", rows["fresh"]   # offline latestPatch when no deps.dev
assert "releasesBehind" not in rows["fresh"], rows["fresh"]     # offline tier has no behind count
assert "outdated" not in rows["plain"], rows["plain"]           # unmapped -> no currency
PY
then
    pass "currency surfaced per-row + outdatedCount (offline + deps.dev, deps.dev latest wins)"
else
    fail "currency summary produced wrong values (see assertion above)"
fi
echo "== EPSS / KEV enrichment join (security_summary) =="
# The raw _security.json has no EPSS/KEV; scan-security.sh writes them as a
# sidecar map. security_summary must join them onto the matching CVE rows.
cat > "$OUT/sec_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[
  {"VulnerabilityID":"CVE-1","Severity":"CRITICAL","PkgName":"openssl","InstalledVersion":"3.0"},
  {"VulnerabilityID":"CVE-2","Severity":"LOW","PkgName":"zlib","InstalledVersion":"1.2"}
]}]}
JSON
cat > "$OUT/sec_1.0_security_epss.json" <<'JSON'
{"CVE-1":{"epss":0.97,"kev":true},"CVE-2":{"epss":0.001,"kev":false}}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
vulns = {x["id"]: x for x in server.security_summary("sec_1.0")["vulnerabilities"]}
assert vulns["CVE-1"]["epss"] == 0.97, vulns["CVE-1"]
assert vulns["CVE-1"]["kev"] is True, vulns["CVE-1"]
assert vulns["CVE-2"]["epss"] == 0.001, vulns["CVE-2"]
assert "kev" not in vulns["CVE-2"], vulns["CVE-2"]   # kev false -> omitted
PY
then
    pass "EPSS/KEV joined onto vulnerabilities from the sidecar map"
else
    fail "EPSS/KEV join is wrong"
fi
rm -f "$OUT"/sec_1.0_*

echo "== scanError exposure (security_summary) =="
# scan-security.sh stamps ScanError when the engine run fails; the summary must
# surface it so the UI can tell "scan failed" from a clean 0-findings result,
# and must omit it on a normal report.
cat > "$OUT/serr_1.0_security.json" <<'JSON'
{"Results":[],"ScanError":{"Engine":"Trivy","Message":"CycloneDX decode error: invalid specification version"}}
JSON
cat > "$OUT/sok_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"LOW","PkgName":"libfoo","InstalledVersion":"1.0"}]}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
s = server.security_summary("serr_1.0")
assert s["TOTAL"] == 0, s
assert "invalid specification version" in s["scanError"], s
ok = server.security_summary("sok_1.0")
assert "scanError" not in ok, ok
PY
then
    pass "scanError surfaced on failure, absent on a clean report"
else
    fail "scanError exposure is wrong"
fi
rm -f "$OUT"/serr_1.0_* "$OUT"/sok_1.0_*

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
c = server.conformance_summary("conf_1.0")
assert c is not None, "no conformance summary"
checks = c.get("checks") or []
assert len(checks) > 0, "checks not exposed"
g7 = [x for x in checks if x["id"].startswith("g7-")]
base = [x for x in checks if not x["id"].startswith("g7-")]
# Registry-driven: the full G7 checklist (7 clusters), not just the 6 model checks.
assert len(g7) >= 40, ("expected the full G7 checklist", len(g7))
assert len(base) >= 1, "no base checks"
assert all(x["required"] is False for x in g7), "G7 checks must be advisory"
# The cluster + source fields must survive server normalization (else the UI can't
# group by cluster or badge the data source).
assert all(set(x) >= {"id", "label", "required", "status", "detail", "evidence",
                      "cluster", "source"} for x in checks)
assert len({x["cluster"] for x in g7}) >= 7, "G7 checks should span the 7 clusters"
assert {x["source"] for x in g7} >= {"auto", "na"}, "G7 source tags not passed through"
# Passing G7 elements carry their satisfying SBOM values as evidence.
lic = next(x for x in g7 if x["id"] == "g7-model-license")
assert lic["status"] == "pass" and any("Apache-2.0" in e for e in lic["evidence"]), (
    "g7-model-license evidence missing", lic)
assert lic["cluster"] == "models", ("g7-model-license cluster", lic)
PY
    then
        pass "conformance_summary exposes the full G7 checklist with cluster/source"
    else
        fail "conformance checks exposure / G7 split is wrong"
    fi
    rm -f "$OUT"/conf_1.0_*
else
    echo "  SKIP: jq not available for conformance generation"
fi

echo "== license review property (normalize -> sbom_summary) =="
# Normalize the AI-license fixture (adds bomlens:licenseReview), then check
# sbom_summary surfaces the behavioral-use / non-commercial class per component.
if command -v jq >/dev/null 2>&1; then
    cp "$ROOT_DIR/tests/fixtures/notice-ai-licenses.json" "$OUT/lic_1.0_bom.json"
    bash "$ROOT_DIR/docker/lib/normalize-sbom.sh" "$OUT/lic_1.0_bom.json" >/dev/null 2>&1
    if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
rows = {r["name"]: r for r in server.sbom_summary("lic_1.0")["componentList"]}
assert rows["some-llama-model"]["licenseReview"] == "behavioral-use", rows["some-llama-model"]
assert rows["some-nc-dataset"]["licenseReview"] == "non-commercial", rows["some-nc-dataset"]
assert "licenseReview" not in rows["ordinary-lib"], rows["ordinary-lib"]
PY
    then
        pass "licenseReview surfaced (behavioral-use / non-commercial; MIT unflagged)"
    else
        fail "licenseReview not surfaced correctly"
    fi
    rm -f "$OUT"/lic_1.0_*
fi

echo "== sbom-tool-degraded property (sbom_summary) =="
# When entrypoint records the syft fallback as bomlens:sbom-tool-degraded, the
# summary must surface it (drives the Overview banner); absent -> None.
cat > "$OUT/deg_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"deg","version":"1.0"},"properties":[{"name":"bomlens:sbom-tool-degraded","value":"disk-space"}]},"components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
cat > "$OUT/clean_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"clean","version":"1.0"}},"components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
assert server.sbom_summary("deg_1.0")["sbomToolDegraded"] == "disk-space"
assert server.sbom_summary("clean_1.0")["sbomToolDegraded"] is None
PY
then
    pass "sbomToolDegraded surfaced from metadata (None when absent)"
else
    fail "sbomToolDegraded not surfaced correctly"
fi
rm -f "$OUT"/deg_1.0_* "$OUT"/clean_1.0_*

echo "== direct/transitive scope with an empty root dependsOn (cdxgen quirk) =="
# Regression: cdxgen sometimes emits the root component with an EMPTY dependsOn
# and floats the real direct deps as nodes nothing depends on. sbom_summary must
# still count them as direct (was 0/N before the _scope_index fallback fix).
cat > "$OUT/dep_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX",
 "metadata":{"component":{"name":"dep","version":"1.0","type":"application","bom-ref":"root"}},
 "components":[
   {"name":"app","version":"1","type":"library","purl":"pkg:maven/x/app@1","bom-ref":"pkg:maven/x/app@1"},
   {"name":"lib","version":"1","type":"library","purl":"pkg:maven/x/lib@1","bom-ref":"pkg:maven/x/lib@1"}],
 "dependencies":[
   {"ref":"root","dependsOn":[]},
   {"ref":"pkg:maven/x/app@1","dependsOn":["pkg:maven/x/lib@1"]},
   {"ref":"pkg:maven/x/lib@1","dependsOn":[]}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
s = server.sbom_summary("dep_1.0")
assert s["directCount"] == 1, s            # app: nothing depends on it -> direct
assert s["transitiveCount"] == 1, s        # lib: pulled in by app -> transitive
rows = {r["name"]: r for r in s["componentList"]}
assert rows["app"]["scope"] == "direct", rows["app"]
assert rows["lib"]["scope"] == "transitive", rows["lib"]
PY
then
    pass "empty-root dependsOn falls back to orphan roots (direct counted, not 0)"
else
    fail "direct/transitive scope wrong for an empty-root graph"
fi
rm -f "$OUT"/dep_1.0_*

echo "== scan-config sidecar (re-scan settings) =="
# A scan saves how it was launched (source + non-secret toggles) as a dot-prefixed
# sidecar in its run folder, surfaced as `scanConfig` on the done event and on a
# re-opened scan. The sidecar must NOT leak tokens/credentials and must NOT appear
# in the artifact listing/downloads (dot-prefixed, not an ARTIFACT_SUFFIX).
mkdir -p "$OUT/cfg_2.0"
cat > "$OUT/cfg_2.0/cfg_2.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"cfg","version":"2.0","type":"application"}},
 "components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

run_out = server.run_dir("cfg_2.0")
assert run_out and os.path.isdir(run_out), run_out
cfg = {
    "source": "git-url",
    "target": "https://example.com/acme/widget.git",
    "project": "cfg",
    "version": "2.0",
    "notice": True,
    "security": True,
    "deepLicense": False,
    "identifyVendored": True,
    "includeOsv": False,
    "byteStable": True,
}
server.write_scanmeta(run_out, cfg)

# The sidecar lands under the run folder with the dot-prefixed name.
assert os.path.isfile(os.path.join(run_out, server.SCANMETA_NAME)), os.listdir(run_out)
assert server.SCANMETA_NAME.startswith("."), server.SCANMETA_NAME
# It is NOT an artifact suffix, so it can never enter list_results / downloads.
assert not server.SCANMETA_NAME.endswith(server.ARTIFACT_SUFFIXES), server.SCANMETA_NAME

# scanmeta() reads it back verbatim; the exact camelCase contract keys are present.
got = server.scanmeta("cfg_2.0")
assert got == cfg, got
expected_keys = {"source", "target", "project", "version", "notice", "security",
                 "deepLicense", "identifyVendored", "includeOsv", "byteStable"}
assert set(got) == expected_keys, set(got)
# No secret material is ever stored.
assert not any(k in got for k in ("token", "cred", "scanoss_cred", "gitToken",
                                  "SCANOSS_API_KEY")), got

# The sidecar is excluded from the artifact listing and the download bundle.
names = [r["name"] for r in server.list_results("cfg_2.0")]
assert server.SCANMETA_NAME not in names, names
assert "cfg_2.0_bom.json" in names, names

# scan_detail carries scanConfig for a re-opened scan.
detail = server.scan_detail("cfg_2.0")
assert detail["scanConfig"] == cfg, detail.get("scanConfig")

# A run with no sidecar (pre-feature scan) degrades gracefully to None.
assert server.scanmeta("flat_1.0") is None  # absent -> None
# Traversal ids are refused by the same run_dir barrier.
assert server.scanmeta("../etc") is None
PY
then
    pass "scanConfig sidecar round-trips (camelCase keys, no secrets, excluded from results)"
else
    fail "scan-config sidecar contract is wrong (see assertion above)"
fi
# /scan?id= surfaces scanConfig over the wire, and /results never lists the sidecar.
if curl -fsS "$BASE/scan?id=cfg_2.0" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
c = d.get('scanConfig')
assert c is not None and c['source'] == 'git-url', c
assert c['identifyVendored'] is True and c['deepLicense'] is False, c
assert c['byteStable'] is True, c
assert 'token' not in c and 'scanoss_cred' not in c, c
"; then
    pass "/scan?id= exposes scanConfig (no secrets)"
else
    fail "/scan?id= did not expose scanConfig"
fi
if curl -fsS "$BASE/results?id=cfg_2.0" 2>/dev/null | python3 -c "
import sys, json
names = [r['name'] for r in json.load(sys.stdin)]
assert '.scanmeta.json' not in names, names
assert 'cfg_2.0_bom.json' in names, names
"; then
    pass "/results omits the .scanmeta.json sidecar"
else
    fail "/results leaked the scan-config sidecar"
fi
curl -fsS -X POST "$BASE/scan-delete?id=cfg_2.0" >/dev/null 2>&1

echo "== recent scans (/scans + /scan) =="
# Reuse the demo fixtures left in OUT: list past scans, re-open one, block traversal.
cat > "$OUT/demo_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"demo","version":"1.0"}},
 "components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
cat > "$OUT/demo_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","Severity":"HIGH","PkgName":"flask","InstalledVersion":"2.0"}]}]}
JSON
scans=$(curl -fsS "$BASE/scans" 2>/dev/null)
if echo "$scans" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, list) and len(d) >= 1, d
s = next(x for x in d if x['id'] == 'demo_1.0')
assert s['project'] == 'demo' and s['version'] == '1.0', s
assert s['maxSeverity'] == 'HIGH', s
assert s['components'] == 1, s
"; then
    pass "/scans lists past scans with project/version/severity"
else
    fail "/scans summary is wrong" "$scans"
fi
if curl -fsS "$BASE/scan?id=demo_1.0" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['ok'] is True and d['sbom']['components'] == 1, d
assert d['security']['TOTAL'] == 1, d
"; then
    pass "/scan?id= re-opens a past scan"
else
    fail "/scan?id= did not return the scan detail"
fi
c_bad=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/scan?id=../../etc/passwd")
[ "$c_bad" = "400" ] && pass "/scan blocks traversal id (400)" || fail "/scan traversal id returned $c_bad (expected 400)"
c_missing=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/scan?id=nope_9.9")
[ "$c_missing" = "404" ] && pass "/scan unknown id returns 404" || fail "/scan unknown id returned $c_missing (expected 404)"

echo "== source-tree fallback (_files.json artifact + script shape) =="
# The structure-only source tree (_files.json) lets the UI show a source tree
# without the opt-in ScanCode scan. It must be a listed/downloadable artifact and
# re-open with the scan, so the frontend can fetch it (it prefers _scancode when
# both exist; here only _files is present).
cat > "$OUT/demo_1.0_files.json" <<'JSON'
{"files":[{"path":"src","type":"directory"},{"path":"src/main.py","type":"file"}]}
JSON
if curl -fsS "$BASE/results" 2>/dev/null | python3 -c "
import sys, json
names = [r['name'] for r in json.load(sys.stdin)]
assert 'demo_1.0_files.json' in names, names
"; then
    pass "/results lists the _files.json source tree"
else
    fail "/results did not list _files.json"
fi
if curl -fsS "$BASE/file?name=demo_1.0_files.json" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert any(f['type'] == 'file' for f in d['files']), d
"; then
    pass "/file serves the _files.json source tree"
else
    fail "/file did not serve _files.json"
fi
if curl -fsS "$BASE/scan?id=demo_1.0" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
names = [r['name'] for r in d['results']]
assert 'demo_1.0_files.json' in names, names
"; then
    pass "/scan?id= re-open includes the _files.json source tree"
else
    fail "/scan?id= re-open omitted _files.json"
fi
rm -f "$OUT/demo_1.0_files.json"

# The scanner script emits the ScanCode 'files[]' shape the frontend parser
# consumes, with noise dirs (.git/node_modules) pruned.
sft_dir="$WORK/sft-src"
mkdir -p "$sft_dir/app/sub" "$sft_dir/.git/objects" "$sft_dir/node_modules/dep"
: > "$sft_dir/app/main.py"
: > "$sft_dir/app/sub/util.go"
: > "$sft_dir/node_modules/dep/index.js"
: > "$sft_dir/.git/objects/blob"
if bash "$ROOT_DIR/docker/lib/source-file-tree.sh" "$sft_dir" "$WORK/sft.json" >/dev/null 2>&1 \
   && python3 -c "
import json
d = json.load(open('$WORK/sft.json'))
paths = {f['path'] for f in d['files']}
types = {f['type'] for f in d['files']}
assert 'app/main.py' in paths and 'app/sub/util.go' in paths, paths
assert 'app' in paths, paths
assert not any('node_modules' in p or '.git' in p for p in paths), paths
assert types <= {'file', 'directory'}, types
"; then
    pass "source-file-tree.sh emits a pruned ScanCode-shaped files[] tree"
else
    fail "source-file-tree.sh output is wrong" "$(cat "$WORK/sft.json" 2>/dev/null)"
fi

# D-6 regression: the EPSS sidecar (_security_epss.json) must be deleted with the
# rest of a flat scan's artifacts. It was absent from ARTIFACT_SUFFIXES, so
# /scan-delete walked past it and left the file orphaned to accumulate on disk.
cat > "$OUT/demo_1.0_security_epss.json" <<'JSON'
{"items":[{"cve":"CVE-2020-0001","epss":0.12,"percentile":0.5}]}
JSON

# /scan-delete removes a past scan's artifacts, and fails closed on a bad id.
# The delete builds an OUTPUT_DIR path from the id, so cover the traversal guard.
del_bad=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/scan-delete?id=../../etc/passwd")
[ "$del_bad" = "400" ] && pass "/scan-delete blocks traversal id (400)" || fail "/scan-delete traversal id returned $del_bad (expected 400)"
del_resp=$(curl -fsS -X POST "$BASE/scan-delete?id=demo_1.0" 2>/dev/null)
if echo "$del_resp" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['deleted'] == 'demo_1.0' and d['removed'] >= 1, d
"; then
    pass "/scan-delete removes the scan's artifacts"
else
    fail "/scan-delete did not delete the scan" "$del_resp"
fi
if [ ! -f "$OUT/demo_1.0_bom.json" ] && [ ! -f "$OUT/demo_1.0_security_epss.json" ]; then
    pass "/scan-delete left no artifact behind (incl. the EPSS sidecar)"
else
    fail "demo_1.0 artifacts still present after delete" "$(ls "$OUT"/demo_1.0_* 2>/dev/null)"
fi
del_gone=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/scan?id=demo_1.0")
[ "$del_gone" = "404" ] && pass "deleted scan is gone (404)" || fail "deleted scan returned $del_gone (expected 404)"
rm -f "$OUT"/demo_1.0_*

echo "== per-run subfolder layout (OUTPUT_DIR/<run_id>/) =="
# New disk layout: each scan's artifacts live in a per-run folder named by the
# run_id (default {prefix}, e.g. demo_1.0). Files inside stay named by the
# {prefix}. The summary helpers (sbom_summary/security_summary/...) take the
# run_id (folder name), glob the folder by suffix, and the /file, /download-all,
# /scan, /scans, /scan-delete endpoints all address a scan by its run_id.
mkdir -p "$OUT/demo_1.0"
cat > "$OUT/demo_1.0/demo_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX",
 "metadata":{"component":{"bom-ref":"root","name":"demo","version":"1.0","type":"application"}},
 "components":[
   {"bom-ref":"pkg:pypi/flask@2.0","name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"},
   {"bom-ref":"pkg:pypi/werkzeug@2.0","name":"werkzeug","version":"2.0","type":"library","purl":"pkg:pypi/werkzeug@2.0"}
 ],
 "dependencies":[
   {"ref":"root","dependsOn":["pkg:pypi/flask@2.0"]},
   {"ref":"pkg:pypi/flask@2.0","dependsOn":["pkg:pypi/werkzeug@2.0"]}
 ]}
JSON
cat > "$OUT/demo_1.0/demo_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[
  {"VulnerabilityID":"CVE-1","Severity":"CRITICAL","PkgName":"werkzeug","InstalledVersion":"2.0","PkgIdentifier":{"PURL":"pkg:pypi/werkzeug@2.0"}}
]}]}
JSON
cat > "$OUT/demo_1.0/demo_1.0_security_epss.json" <<'JSON'
{"CVE-1":{"epss":0.91,"kev":true}}
JSON
# A timestamped run: the folder name (demo_1.0_20260101-120000) differs from the
# file prefix (demo_1.0), proving the helpers resolve artifacts by suffix glob,
# not by deriving the filename from the folder name.
mkdir -p "$OUT/demo_1.0_20260101-120000"
cat > "$OUT/demo_1.0_20260101-120000/demo_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"demo","version":"1.0","type":"application"}},
 "components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
# Helpers take the run_id (folder name) and glob the folder by suffix.
demo = {r["name"]: r for r in server.sbom_summary("demo_1.0")["componentList"]}
assert demo["flask"]["scope"] == "direct", demo["flask"]
assert demo["werkzeug"]["scope"] == "transitive", demo["werkzeug"]
assert demo["werkzeug"]["maxSeverity"] == "CRITICAL", demo["werkzeug"]
v = {x["id"]: x for x in server.security_summary("demo_1.0")["vulnerabilities"]}
assert v["CVE-1"]["epss"] == 0.91 and v["CVE-1"]["kev"] is True, v["CVE-1"]
# run_file resolves the artifact INSIDE the run folder.
rf = server.run_file("demo_1.0", "_bom.json")
assert rf and rf.endswith("/demo_1.0/demo_1.0_bom.json"), rf
# Timestamped run: folder name != file prefix, resolved by suffix glob.
ts = server.sbom_summary("demo_1.0_20260101-120000")
assert ts and ts["components"] == 1, ts
tf = server.run_file("demo_1.0_20260101-120000", "_bom.json")
assert tf and tf.endswith("/demo_1.0_20260101-120000/demo_1.0_bom.json"), tf
# Path-traversal barriers: a run_id with separators/.. resolves to nothing, and
# a name that is not a bare basename is refused.
assert server.run_dir("../etc") is None
assert server.run_dir("a/b") is None
assert server.run_file("../etc", "_bom.json") is None
assert server.run_artifact_path("demo_1.0", "../x") is None
assert server.run_artifact_path("demo_1.0", "a/b") is None
PY
then
    pass "subfolder helpers resolve by run_id + suffix glob (incl. timestamped folder; traversal refused)"
else
    fail "subfolder layout helper resolution is wrong (see assertion above)"
fi
# /scans walks the subfolders and lists each by its folder name (run_id).
scans=$(curl -fsS "$BASE/scans" 2>/dev/null)
if echo "$scans" | python3 -c "
import sys, json
d = json.load(sys.stdin)
s = next(x for x in d if x['id'] == 'demo_1.0')
assert s['project'] == 'demo' and s['version'] == '1.0', s
assert s['maxSeverity'] == 'CRITICAL' and s['components'] == 2, s
t = next(x for x in d if x['id'] == 'demo_1.0_20260101-120000')
assert t['project'] == 'demo' and t['components'] == 1, t
"; then
    pass "/scans lists each run subfolder by its folder name (run_id)"
else
    fail "/scans did not list the run subfolders" "$scans"
fi
# /scan?id=<run_id> re-opens the scan from its folder.
if curl -fsS "$BASE/scan?id=demo_1.0" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['ok'] is True and d['id'] == 'demo_1.0', d
assert d['sbom']['components'] == 2 and d['security']['TOTAL'] == 1, d
names = [r['name'] for r in d['results']]
assert 'demo_1.0_security_epss.json' in names, names
"; then
    pass "/scan?id=<run_id> re-opens a subfolder scan with its artifacts"
else
    fail "/scan?id=<run_id> did not return the subfolder scan"
fi
# /file?id=<run_id>&name=<basename> serves an artifact from the run folder.
if curl -fsS "$BASE/file?id=demo_1.0&name=demo_1.0_security.json" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['Results'][0]['Vulnerabilities'][0]['VulnerabilityID'] == 'CVE-1', d
"; then
    pass "/file?id=&name= serves an artifact from the run folder"
else
    fail "/file?id=&name= did not serve the subfolder artifact"
fi
# Timestamped folder: /file by folder-name id + prefix-named file.
fc=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/file?id=demo_1.0_20260101-120000&name=demo_1.0_bom.json")
[ "$fc" = "200" ] && pass "/file resolves a prefix-named file in a timestamped folder" || fail "/file timestamped folder returned $fc (expected 200)"
# /download-all?id=<run_id> bundles only that run folder's artifacts.
curl -fsS "$BASE/download-all?id=demo_1.0" -o "$WORK/dl.zip" 2>/dev/null
if python3 -c "
import zipfile
names = set(zipfile.ZipFile('$WORK/dl.zip').namelist())
assert {'demo_1.0_bom.json','demo_1.0_security.json','demo_1.0_security_epss.json'} <= names, names
"; then
    pass "/download-all?id=<run_id> zips the run folder's artifacts"
else
    fail "/download-all?id=<run_id> bundle is wrong"
fi
# /file path-traversal: a name that is not a bare basename is 404 regardless of id.
fc_trav=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/file?id=demo_1.0&name=../../etc/passwd")
[ "$fc_trav" = "404" ] && pass "/file blocks a traversal name even with a valid id (404)" || fail "/file traversal name returned $fc_trav (expected 404)"
fc_id=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/file?id=../etc&name=demo_1.0_bom.json")
[ "$fc_id" = "404" ] && pass "/file with a traversal id does not escape (404)" || fail "/file traversal id returned $fc_id (expected 404)"

echo "== backward compatibility: legacy flat layout (OUTPUT_DIR/{prefix}_*) =="
# Pre-upgrade scans wrote artifacts flat in OUTPUT_DIR (no run folder). They must
# keep listing, re-opening, downloading, serving (with id omitted OR supplied),
# and deleting — the helpers fall back to the flat {prefix}_* layout.
cat > "$OUT/legacy_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"legacy","version":"1.0","type":"application"}},
 "components":[{"name":"openssl","version":"3.0","type":"library","purl":"pkg:generic/openssl@3.0"}]}
JSON
cat > "$OUT/legacy_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-L","Severity":"MEDIUM","PkgName":"openssl","InstalledVersion":"3.0"}]}]}
JSON
if curl -fsS "$BASE/scans" 2>/dev/null | python3 -c "
import sys, json
s = next(x for x in json.load(sys.stdin) if x['id'] == 'legacy_1.0')
assert s['project'] == 'legacy' and s['maxSeverity'] == 'MEDIUM' and s['components'] == 1, s
"; then
    pass "/scans lists a legacy flat scan by its {prefix} id"
else
    fail "/scans dropped the legacy flat scan"
fi
if curl -fsS "$BASE/scan?id=legacy_1.0" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['ok'] is True and d['sbom']['components'] == 1 and d['security']['TOTAL'] == 1, d
"; then
    pass "/scan?id= re-opens a legacy flat scan"
else
    fail "/scan?id= did not re-open the legacy flat scan"
fi
lc_noid=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/file?name=legacy_1.0_bom.json")
[ "$lc_noid" = "200" ] && pass "/file (id omitted) serves a legacy flat artifact" || fail "/file id-omitted legacy returned $lc_noid (expected 200)"
lc_id=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/file?id=legacy_1.0&name=legacy_1.0_bom.json")
[ "$lc_id" = "200" ] && pass "/file (id supplied, no folder) falls back to the legacy flat artifact" || fail "/file id-supplied legacy returned $lc_id (expected 200)"
curl -fsS "$BASE/download-all?id=legacy_1.0" -o "$WORK/dl-legacy.zip" 2>/dev/null
if python3 -c "
import zipfile
names = set(zipfile.ZipFile('$WORK/dl-legacy.zip').namelist())
assert 'legacy_1.0_bom.json' in names and 'legacy_1.0_security.json' in names, names
"; then
    pass "/download-all?id= bundles a legacy flat scan"
else
    fail "/download-all?id= legacy bundle is wrong"
fi

echo "== delete: subfolder removes the run folder, legacy removes flat {prefix}_* =="
del_sub=$(curl -fsS -X POST "$BASE/scan-delete?id=demo_1.0" 2>/dev/null)
if echo "$del_sub" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['deleted'] == 'demo_1.0' and d['removed'] >= 2, d
"; then
    pass "/scan-delete removes a subfolder scan's artifacts"
else
    fail "/scan-delete did not delete the subfolder scan" "$del_sub"
fi
[ ! -d "$OUT/demo_1.0" ] && pass "/scan-delete removed the whole run folder" || fail "run folder still present after delete"
del_gone=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/scan?id=demo_1.0")
[ "$del_gone" = "404" ] && pass "deleted subfolder scan is gone (404)" || fail "deleted subfolder scan returned $del_gone (expected 404)"
curl -fsS -X POST "$BASE/scan-delete?id=demo_1.0_20260101-120000" >/dev/null 2>&1
del_legacy=$(curl -fsS -X POST "$BASE/scan-delete?id=legacy_1.0" 2>/dev/null)
if echo "$del_legacy" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['deleted'] == 'legacy_1.0' and d['removed'] >= 1, d
"; then
    pass "/scan-delete removes a legacy flat scan's {prefix}_* artifacts"
else
    fail "/scan-delete did not delete the legacy flat scan" "$del_legacy"
fi
[ ! -f "$OUT/legacy_1.0_bom.json" ] && pass "/scan-delete left no legacy flat artifact behind" || fail "legacy flat artifacts still present after delete"

echo "== /scan-stream SSE contract (stub scanner via SBOM_RUN_SCAN) =="
# The SSE scan stream was previously exercised only by the container-based
# tests/test-web-e2e.sh, which is gated to push/dispatch CI — so the protocol
# the frontend depends on (log/progress/error events, one terminal `done`
# payload, cancel-on-disconnect) had no always-on coverage. A second server
# instance runs with SBOM_RUN_SCAN pointing at a stub scanner whose behavior
# each test selects through a control file, so every branch is reachable
# without Docker.
PORT2=$((PORT + 1))
BASE2="http://127.0.0.1:${PORT2}"
OUT2="$WORK/out2"; mkdir -p "$OUT2"
STUB_MODE_FILE="$WORK/stub-mode"
STUB_HEARTBEAT="$WORK/stub-heartbeat"
mkdir -p "$WORK/bin"
cat > "$WORK/bin/run-scan" <<'STUB'
#!/bin/bash
# Stub scanner for the SSE contract tests. Reads its behavior from the control
# file each run; writes the bom artifact into $PWD (the server sets cwd to the
# per-run output folder, exactly like the real run-scan).
mode="$(cat "$STUB_MODE_FILE" 2>/dev/null || echo ok)"
echo "[stub] scanning ${PROJECT_NAME} ${PROJECT_VERSION} (mode=$mode)"
# Record the upload-relevant env the server passed, so the contract test can
# assert the web upload params map to the run-scan environment.
{ echo "UPLOAD_ENABLED=${UPLOAD_ENABLED:-}"
  echo "UPLOAD_TARGET=${UPLOAD_TARGET:-}"
  echo "API_URL=${API_URL:-}"
  echo "API_KEY=${API_KEY:-}"
  echo "TRUSCA_PROJECT_ID=${TRUSCA_PROJECT_ID:-}"; } > "${STUB_ENV_FILE:-/dev/null}"
write_bom() {
    printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"a","version":"1"},{"type":"library","name":"b","version":"2"}]}' \
        > "${PROJECT_NAME}_${PROJECT_VERSION}_bom.json"
}
case "$mode" in
    ok) write_bom; echo "[stub] done" ;;
    progress) echo "[firmware-cvedb-progress] 42%"; write_bom ;;
    fail) echo "[stub] scanner exploded" >&2; exit 1 ;;
    hang)
        i=0
        while [ "$i" -lt 100 ]; do
            date +%s >> "$STUB_HEARTBEAT"
            echo "[stub] tick $i"
            sleep 0.2
            i=$((i + 1))
        done
        ;;
esac
STUB
chmod +x "$WORK/bin/run-scan"

SRV2_PID=""
cleanup2() { [ -n "$SRV2_PID" ] && kill "$SRV2_PID" 2>/dev/null; }
trap 'cleanup2; cleanup' EXIT
SBOM_OUTPUT_DIR="$OUT2" UI_PORT="$PORT2" SBOM_UI_HOST_DIR="$WORK" \
    SBOM_RUN_SCAN="$WORK/bin/run-scan" SBOM_DOCKER_SOCK="$WORK/no-such.sock" \
    STUB_MODE_FILE="$STUB_MODE_FILE" STUB_HEARTBEAT="$STUB_HEARTBEAT" \
    STUB_ENV_FILE="$WORK/stub-env" \
    python3 "$SERVER" > "$WORK/server2.log" 2>&1 &
SRV2_PID=$!
disown "$SRV2_PID" 2>/dev/null || true
ready2=0
for _ in $(seq 1 30); do
    if curl -fsS "$BASE2/capabilities" >/dev/null 2>&1; then ready2=1; break; fi
    kill -0 "$SRV2_PID" 2>/dev/null || { echo "[ERROR] SSE server exited early:"; cat "$WORK/server2.log"; exit 1; }
    sleep 0.3
done
[ "$ready2" = 1 ] && pass "stub-scanner server is up" || { fail "stub-scanner server did not become ready" "$(tail -5 "$WORK/server2.log")"; exit 1; }

# Fetch one SSE stream (headers + body) and normalize the events to a JSON
# array [{"event":..., "data":<parsed>}] for python3 assertions.
sse_events() { # $1=query-string  -> writes $WORK/sse-headers, prints events JSON
    curl -sN -D "$WORK/sse-headers" "$BASE2/scan-stream?$1" | python3 -c '
import sys, json
events, ev, data = [], None, []
for line in sys.stdin:
    line = line.rstrip("\n")
    if line.startswith("event: "):
        ev = line[len("event: "):]
    elif line.startswith("data: "):
        data.append(line[len("data: "):])
    elif line == "" and ev is not None:
        try:
            parsed = json.loads("\n".join(data)) if data else None
        except ValueError:
            parsed = "\n".join(data)
        events.append({"event": ev, "data": parsed})
        ev, data = None, []
print(json.dumps(events))
'
}

echo ok > "$STUB_MODE_FILE"
events=$(sse_events "project=demo&version=1.0&source=current-dir")
if grep -qi '^content-type: text/event-stream' "$WORK/sse-headers"; then
    pass "scan-stream responds with Content-Type: text/event-stream"
else
    fail "wrong content type" "$(grep -i '^content-type' "$WORK/sse-headers")"
fi
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
logs = [e for e in evs if e['event'] == 'log']
dones = [e for e in evs if e['event'] == 'done']
assert logs, 'no log events'
assert len(dones) == 1, 'expected exactly one done, got %d' % len(dones)
d = dones[0]['data']
assert d['ok'] is True, d
assert d['id'] == 'demo_1.0', d['id']
assert d['mode'] == 'SOURCE', d['mode']
assert any(r['name'] == 'demo_1.0_bom.json' for r in d['results']), d['results']
assert d['sbom'] and d['sbom'].get('components') == 2, d.get('sbom')
assert d['scanConfig']['source'] == 'current-dir', d['scanConfig']
assert evs[-1]['event'] == 'done', 'done is not the terminal event'
"; then
    pass "happy path: log events then a single terminal done (ok, id, results, sbom, scanConfig)"
else
    fail "happy-path SSE contract violated" "$events"
fi
[ -f "$OUT2/demo_1.0/.scanmeta.json" ] && pass "scan writes the .scanmeta.json sidecar into the run folder" || fail "missing .scanmeta.json sidecar"

echo progress > "$STUB_MODE_FILE"
events=$(sse_events "project=prog&version=1.0&source=current-dir")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
progs = [e for e in evs if e['event'] == 'progress']
assert len(progs) == 1, 'expected one progress event, got %d' % len(progs)
assert progs[0]['data'] == {'phase': 'cvedb', 'percent': 42}, progs[0]['data']
assert not any('firmware-cvedb-progress' in str(e['data']) for e in evs if e['event'] == 'log'), \
    'progress marker leaked into log events'
"; then
    pass "cvedb progress marker becomes a progress event (not duplicated as log)"
else
    fail "progress event contract violated" "$events"
fi

echo fail > "$STUB_MODE_FILE"
events=$(sse_events "project=bad&version=1.0&source=current-dir")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
dones = [e for e in evs if e['event'] == 'done']
assert len(dones) == 1 and dones[0]['data']['ok'] is False, evs
"; then
    pass "scanner exit 1 ends the stream with done ok:false"
else
    fail "failed scan did not report done ok:false" "$events"
fi

echo ok > "$STUB_MODE_FILE"
code=$(curl -s -o "$WORK/sse-400" -w '%{http_code}' "$BASE2/scan-stream?version=1.0")
if [ "$code" = "400" ] && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$WORK/sse-400" 2>/dev/null; then
    pass "missing project is rejected pre-stream with HTTP 400 JSON"
else
    fail "missing project returned $code (expected 400 JSON)"
fi

events=$(sse_events "project=nodocker&version=1.0&source=docker-image&target=alpine:latest")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
errs = [e for e in evs if e['event'] == 'error']
dones = [e for e in evs if e['event'] == 'done']
assert errs and 'Docker socket' in errs[0]['data'], evs
assert len(dones) == 1, evs
d = dones[0]['data']
assert d['ok'] is False and d['sbom'] is None and isinstance(d['results'], list), d
"; then
    pass "docker-image without a socket fails in-stream (error + done ok:false shape)"
else
    fail "socketless docker-image error contract violated" "$events"
fi

events=$(sse_events "project=weird&version=1.0&source=carrier-pigeon")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
assert any(e['event'] == 'error' and 'unknown input type' in e['data'] for e in evs), evs
assert [e for e in evs if e['event'] == 'done'][0]['data']['ok'] is False
"; then
    pass "unknown source is rejected in-stream"
else
    fail "unknown source contract violated" "$events"
fi

events=$(sse_events "project=gitfail&version=1.0&source=git-url&target=file:///nonexistent-repo-path")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
assert any(e['event'] == 'error' and 'git clone failed' in str(e['data']) for e in evs), evs
assert [e for e in evs if e['event'] == 'done'][0]['data']['ok'] is False
"; then
    pass "failed git clone reports error + done ok:false"
else
    fail "git clone failure contract violated" "$events"
fi

echo hang > "$STUB_MODE_FILE"
rm -f "$STUB_HEARTBEAT"
curl -sN --max-time 2 "$BASE2/scan-stream?project=cancel&version=1.0&source=current-dir" >/dev/null 2>&1 || true
sleep 3
hb1=$(wc -c < "$STUB_HEARTBEAT" 2>/dev/null || echo 0)
sleep 1.5
hb2=$(wc -c < "$STUB_HEARTBEAT" 2>/dev/null || echo 0)
if [ "$hb1" -gt 0 ] && [ "$hb1" = "$hb2" ]; then
    pass "client disconnect terminates the running scan (heartbeat stopped)"
else
    fail "scan kept running after client disconnect" "heartbeat $hb1 -> $hb2"
fi

echo ok > "$STUB_MODE_FILE"
events=$(sse_events "project=demo2&version=1.0&source=current-dir&timestamp=true")
ts_dirs=$(find "$OUT2" -maxdepth 1 -type d -name 'demo2_1.0_[0-9]*-[0-9]*' | wc -l | tr -d ' ')
if [ "$ts_dirs" = "1" ] && compgen -G "$OUT2"/demo2_1.0_[0-9]*/demo2_1.0_bom.json >/dev/null; then
    pass "timestamp=true: run folder gets the _YYYYMMDD-HHMMSS suffix, file names keep the plain prefix"
else
    fail "timestamped run layout violated" "$(ls "$OUT2")"
fi
if echo "$events" | python3 -c "
import sys, json, re
evs = json.load(sys.stdin)
d = [e for e in evs if e['event'] == 'done'][0]['data']
assert re.fullmatch(r'demo2_1\.0_\d{8}-\d{6}', d['id']), d['id']
"; then
    pass "done event id carries the timestamped run id"
else
    fail "done id is not the timestamped run id" "$events"
fi

echo "== upload: web upload params map to the run-scan env (token via single-use cred) =="
echo ok > "$STUB_MODE_FILE"
# No upload params -> the scan stays generate-only (UPLOAD_ENABLED not "true").
rm -f "$WORK/stub-env"
sse_events "project=noup&version=1.0&source=current-dir" >/dev/null
if [ "$(sed -n 's/^UPLOAD_ENABLED=//p' "$WORK/stub-env")" != "true" ]; then
    pass "no upload params -> scan stays generate-only"
else
    fail "scan enabled upload without any upload params" "$(cat "$WORK/stub-env")"
fi
# Stash the upload token the same single-use way the frontend does, then scan
# with TRUSCA upload params and assert the server mapped them into run-scan's env.
UPCID=$(curl -sS -X POST "$BASE2/git-cred" -H 'Content-Type: application/json' \
    -d '{"token":"secret-upload-tok"}' \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["credId"])')
rm -f "$WORK/stub-env"
sse_events "project=up&version=1.0&source=current-dir&upload_target=trusca&upload_url=https://trusca.example&trusca_project_id=proj-123&upload_cred=$UPCID" >/dev/null
if python3 - "$WORK/stub-env" <<'PY'
import sys
env = dict(l.rstrip("\n").split("=", 1) for l in open(sys.argv[1]) if "=" in l)
assert env.get("UPLOAD_ENABLED") == "true", env
assert env.get("UPLOAD_TARGET") == "trusca", env
assert env.get("API_URL") == "https://trusca.example", env
assert env.get("API_KEY") == "secret-upload-tok", env
assert env.get("TRUSCA_PROJECT_ID") == "proj-123", env
PY
then
    pass "TRUSCA upload params -> UPLOAD_ENABLED/UPLOAD_TARGET/API_URL/TRUSCA_PROJECT_ID + API_KEY from the single-use cred"
else
    fail "upload env mapping is wrong" "$(cat "$WORK/stub-env")"
fi
# The credId is single-use: a second scan reusing it must not carry the token.
rm -f "$WORK/stub-env"
sse_events "project=up2&version=1.0&source=current-dir&upload_target=trusca&upload_url=https://trusca.example&trusca_project_id=proj-123&upload_cred=$UPCID" >/dev/null
if [ -z "$(sed -n 's/^API_KEY=//p' "$WORK/stub-env")" ] \
   && [ "$(sed -n 's/^UPLOAD_ENABLED=//p' "$WORK/stub-env")" != "true" ]; then
    pass "upload credId is single-use (reuse carries no token, upload stays off)"
else
    fail "upload credId was reusable (token leaked to a second scan)" "$(cat "$WORK/stub-env")"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
