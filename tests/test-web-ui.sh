#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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
# An extra --mount scan target, as scan-sbom.sh --ui --mount would pass it:
# "<container path>|<host path>" (one per line). A bogus second entry must be
# dropped with a warning, not break startup.
SCANROOT="$WORK/scanroot"; mkdir -p "$SCANROOT/etc"
SBOM_OUTPUT_DIR="$OUT" UI_PORT="$PORT" SBOM_UI_HOST_DIR="$WORK" \
    SBOM_UI_SCAN_ROOTS="$SCANROOT|/host/mounted
/does-not-exist|/host/bogus" \
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
if echo "$caps" | python3 -c "import sys,json;d=json.load(sys.stdin);assert all(k in d for k in('firmware','docker','scanoss','aibom','firmwareSibling','aibomSibling','deepCve','deepCveSibling','version'))" 2>/dev/null; then
    pass "/capabilities reports firmware, docker, scanoss, aibom, deepCve (+ sibling) flags and the image version"
else
    fail "/capabilities missing expected keys" "$caps"
fi
if curl -fsS "$BASE/results" 2>/dev/null | python3 -c "import sys,json;assert isinstance(json.load(sys.stdin),list)" 2>/dev/null; then
    pass "/results returns a JSON array"
else
    fail "/results is not a JSON array"
fi
# Extra --mount scan targets are surfaced (path + host label); the entry whose
# container path does not exist is dropped.
if echo "$caps" | SCANROOT="$SCANROOT" python3 -c "
import sys, json, os
roots = json.load(sys.stdin).get('scanRoots')
assert roots == [{'path': os.environ['SCANROOT'], 'hostPath': '/host/mounted'}], roots
" 2>/dev/null; then
    pass "/capabilities lists the valid scan root and drops the bogus one"
else
    fail "/capabilities scanRoots wrong" "$caps"
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
def fake_stream(args, on_log, on_progress=None, cancel=None, container=None, env=None,
                on_deepcve_progress=None):
    captured["args"] = args
    captured["container"] = container
    captured["env"] = env
    return 0
server._stream_cmd = fake_stream
server._sibling_image_present = lambda image: True
# This section tests dispatch/allowlisting, not the background refresh (that has
# its own section below with a fake docker on PATH) — stub it to a no-op so an
# "already present" image never shells out to a real `docker pull` here.
server.refresh_sibling_image_quietly = lambda *a, **k: None

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
# The sibling runs the same entrypoint, which defaults UPLOAD_ENABLED to true and
# exits 1 without credentials — so without this the scan reports failure despite
# generating every artifact. With no upload configured the sibling must be told
# generate-only, and no credential may reach the argv.
assert "UPLOAD_ENABLED=false" in args, args
assert not any(a.startswith("API_KEY") for a in args), args
# With an upload configured, the destination is forwarded but the secret API key
# rides the subprocess env (name-only `-e API_KEY`), never the argv / `ps`.
captured.clear()
server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip",
    extra_env={"PROJECT_NAME": "p", "PROJECT_VERSION": "1.0", "UPLOAD_ENABLED": "true",
               "UPLOAD_TARGET": "dependency-track", "API_URL": "https://dt.example",
               "API_KEY": "s3cr3t-should-not-appear"},
)
uargs = captured["args"]
assert "UPLOAD_ENABLED=true" in uargs, uargs
assert "UPLOAD_TARGET=dependency-track" in uargs and "API_URL=https://dt.example" in uargs, uargs
assert "API_KEY" in uargs and not any(a.startswith("API_KEY=") for a in uargs), uargs
assert "s3cr3t-should-not-appear" not in " ".join(uargs), "upload secret leaked onto the argv"
assert (captured["env"] or {}).get("API_KEY") == "s3cr3t-should-not-appear", "subprocess env must carry the key for name-only -e"
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

# Deep CVE matching (maven NVD-CPE via grype) on an uploaded SBOM: ANALYZE runs
# as a sibling in the deep-cve image. The upload is read as ANALYZE_SBOM (not the
# firmware TARGET_FILE), and DEEP_CVE=true is forwarded so scan-security.sh runs
# the grype sidecar. deep_cve capability helpers exist for the frontend gate.
assert "ANALYZE" in server._SIBLING_MODES, server._SIBLING_MODES
assert callable(server.deep_cve_capable) and callable(server.deep_cve_usable)
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "ANALYZE", run_out,
    lambda ln: None, upload_file=up_file,
    extra_env={"DEEP_CVE": "true", "GENERATE_SECURITY": "true"},
)
assert rc == 0, rc
_a = captured["args"]
assert "MODE=ANALYZE" in _a, _a
assert ("ANALYZE_SBOM=%s" % up_file) in _a, _a
assert not any(x.startswith("TARGET_FILE=") for x in _a), _a
assert "DEEP_CVE=true" in _a, _a
assert "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0" in _a, _a
# DEEP_CVE is NOT forwarded when off (kept out of the argv entirely).
captured.clear()
server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "ANALYZE", run_out,
    lambda ln: None, upload_file=up_file, extra_env={"GENERATE_SECURITY": "true"},
)
assert not any(x == "DEEP_CVE=true" for x in captured["args"]), captured["args"]
assert not any("/input/" in a for a in captured["args"]), captured["args"]

# Deep CVE matching also runs as a sibling on the base-image scan modes (SOURCE,
# IMAGE, ROOTFS, BINARY) — not just an uploaded SBOM. Each carries exactly the
# one env var that mode needs (mirroring the ANALYZE/upload_file case above),
# plus DEEP_CVE=true, and nothing from another mode's input shape.
for m in ("SOURCE", "IMAGE", "ROOTFS", "BINARY"):
    assert m in server._SIBLING_MODES, server._SIBLING_MODES

src_root = server.SRC_DIR + "/myproject"
target_dir = server.SRC_DIR + "/rootfs"
target_image = "ghcr.io/library/nginx:1.25"

captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
    extra_env={"DEEP_CVE": "true", "GENERATE_SECURITY": "true"},
)
assert rc == 0, rc
_a = captured["args"]
assert "MODE=SOURCE" in _a, _a
assert ("SOURCE_ROOT=%s" % src_root) in _a, _a
assert "DEEP_CVE=true" in _a, _a
assert "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0" in _a, _a
assert not any(x.startswith("TARGET_FILE=") for x in _a), _a
assert not any(x.startswith("TARGET_DIR=") for x in _a), _a
assert not any(x.startswith("TARGET_IMAGE=") for x in _a), _a
assert not any(x.startswith("ANALYZE_SBOM=") for x in _a), _a

captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "IMAGE", run_out,
    lambda ln: None, target_image=target_image,
    extra_env={"DEEP_CVE": "true", "GENERATE_SECURITY": "true"},
)
assert rc == 0, rc
_a = captured["args"]
assert "MODE=IMAGE" in _a, _a
assert ("TARGET_IMAGE=%s" % target_image) in _a, _a
assert "DEEP_CVE=true" in _a, _a
assert not any(x.startswith("TARGET_FILE=") for x in _a), _a
assert not any(x.startswith("SOURCE_ROOT=") for x in _a), _a
assert not any(x.startswith("TARGET_DIR=") for x in _a), _a

captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "ROOTFS", run_out,
    lambda ln: None, target_dir=target_dir,
    extra_env={"DEEP_CVE": "true", "GENERATE_SECURITY": "true"},
)
assert rc == 0, rc
_a = captured["args"]
assert "MODE=ROOTFS" in _a, _a
assert ("TARGET_DIR=%s" % target_dir) in _a, _a
assert "DEEP_CVE=true" in _a, _a
assert not any(x.startswith("TARGET_FILE=") for x in _a), _a
assert not any(x.startswith("SOURCE_ROOT=") for x in _a), _a
assert not any(x.startswith("TARGET_IMAGE=") for x in _a), _a

captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "BINARY", run_out,
    lambda ln: None, upload_file=up_file,
    extra_env={"DEEP_CVE": "true", "GENERATE_SECURITY": "true"},
)
assert rc == 0, rc
_a = captured["args"]
assert "MODE=BINARY" in _a, _a
assert ("TARGET_FILE=%s" % up_file) in _a, _a
assert "DEEP_CVE=true" in _a, _a
assert not any(x.startswith("ANALYZE_SBOM=") for x in _a), _a

# DEEP_CVE off -> stays out of the argv on every one of these modes too (not
# just ANALYZE).
for m, kw in (("SOURCE", {"source_root": src_root}),
              ("IMAGE", {"target_image": target_image}),
              ("ROOTFS", {"target_dir": target_dir}),
              ("BINARY", {"upload_file": up_file})):
    captured.clear()
    rc = server.run_sibling_scan(
        "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", m, run_out,
        lambda ln: None, extra_env={"GENERATE_SECURITY": "true"}, **kw,
    )
    assert rc == 0, (m, rc)
    assert not any(x == "DEEP_CVE=true" for x in captured["args"]), (m, captured["args"])

# FIRMWARE/AIBOM never carry DEEP_CVE even if a caller sets it — those two use
# their own tools and never swap to the deep-cve image.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-firmware:1.5.0", "FIRMWARE", run_out,
    lambda ln: None, upload_file=up_file, extra_env={"DEEP_CVE": "true"},
)
assert rc == 0, rc
assert not any(x == "DEEP_CVE=true" for x in captured["args"]), captured["args"]
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip", extra_env={"DEEP_CVE": "true"},
)
assert rc == 0, rc
assert not any(x == "DEEP_CVE=true" for x in captured["args"]), captured["args"]

# A SOURCE scan also forwards SOURCE_ROOT_HOST unchanged when present, so the
# deep-cve sibling's own entrypoint sees the same "this tree is under a mount
# we own" signal an in-process SOURCE scan gets (its VALUE is unused there —
# see server.py — only non-emptiness matters); absent, nothing is forwarded.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
    extra_env={"DEEP_CVE": "true", "SOURCE_ROOT_HOST": "/Users/x/project"},
)
assert rc == 0, rc
assert "SOURCE_ROOT_HOST=/Users/x/project" in captured["args"], captured["args"]
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root, extra_env={"DEEP_CVE": "true"},
)
assert rc == 0, rc
assert not any(x.startswith("SOURCE_ROOT_HOST=") for x in captured["args"]), captured["args"]

# Vendored-OSS identification (SCANOSS) can ride the same SOURCE sibling: the
# flag is forwarded verbatim, and a credential goes by NAME ONLY, never as its
# value, mirroring API_KEY/HF_TOKEN.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
    extra_env={"DEEP_CVE": "true", "IDENTIFY_VENDORED": "true",
               "SCANOSS_API_KEY": "scanoss-secret-should-not-appear"},
)
assert rc == 0, rc
_a = captured["args"]
assert "IDENTIFY_VENDORED=true" in _a, _a
assert "SCANOSS_API_KEY" in _a and not any(x.startswith("SCANOSS_API_KEY=") for x in _a), _a
assert "scanoss-secret-should-not-appear" not in " ".join(_a), "SCANOSS key leaked onto the argv"
assert (captured["env"] or {}).get("SCANOSS_API_KEY") == "scanoss-secret-should-not-appear"
# IMAGE never carries the vendored-OSS flags (source-only).
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "IMAGE", run_out,
    lambda ln: None, target_image=target_image,
    extra_env={"DEEP_CVE": "true", "IDENTIFY_VENDORED": "true",
               "SCANOSS_API_KEY": "scanoss-secret-should-not-appear"},
)
assert rc == 0, rc
assert not any(x.startswith("IDENTIFY_VENDORED") for x in captured["args"]), captured["args"]
assert not any(x.startswith("SCANOSS_API_KEY") for x in captured["args"]), captured["args"]

# Path-safety regression: SOURCE_ROOT / TARGET_DIR outside every allowed scan
# root (SRC_DIR, UPLOAD_DIR, ALLOWED_SCAN_ROOTS) is refused before any docker
# run is attempted, exactly like the existing upload_file / out_dir guards.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root="/etc",
)
assert rc == -1 and "args" not in captured, (rc, captured)
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root="/etc/../etc/passwd",
)
assert rc == -1 and "args" not in captured, (rc, captured)
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "ROOTFS", run_out,
    lambda ln: None, target_dir="/etc",
)
assert rc == -1 and "args" not in captured, (rc, captured)
# An invalid image reference (leading '-', flag smuggling) is refused too.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "IMAGE", run_out,
    lambda ln: None, target_image="-v/etc:/etc",
)
assert rc == -1 and "args" not in captured, (rc, captured)

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

# AI usage scenario (usage= -> AI_USAGE_CONTEXT): forwarded to the AIBOM sibling
# only as one of the fixed allowlist literals; an out-of-allowlist value is
# dropped (never smuggled into the argv), and FIRMWARE never carries it.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip",
    extra_env={"AI_USAGE_CONTEXT": "redistribute"},
)
assert rc == 0, rc
assert "AI_USAGE_CONTEXT=redistribute" in captured["args"], captured["args"]
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip",
    extra_env={"AI_USAGE_CONTEXT": "commercial; rm -rf /"},
)
assert rc == 0, rc
assert not any(a.startswith("AI_USAGE_CONTEXT") for a in captured["args"]), captured["args"]
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-firmware:1.5.0", "FIRMWARE", run_out,
    lambda ln: None, upload_file=up_file,
    extra_env={"AI_USAGE_CONTEXT": "redistribute"},
)
assert rc == 0, rc
assert not any(a.startswith("AI_USAGE_CONTEXT") for a in captured["args"]), captured["args"]

# CONFORMANCE_PROFILE reaches the deep-cve sibling ANALYZE runs on when the base
# image lacks grype: a missed forward would silently re-grade a submission
# under review against the wrong thresholds. Forwarded only as one of the two
# recognized values, same allowlist rule as AI_USAGE_CONTEXT above.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "ANALYZE", run_out,
    lambda ln: None, upload_file=up_file,
    extra_env={"CONFORMANCE_PROFILE": "skt-submission"},
)
assert rc == 0, rc
assert "CONFORMANCE_PROFILE=skt-submission" in captured["args"], captured["args"]
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "ANALYZE", run_out,
    lambda ln: None, upload_file=up_file,
    extra_env={"CONFORMANCE_PROFILE": "bogus; rm -rf /"},
)
assert rc == 0, rc
assert not any(a.startswith("CONFORMANCE_PROFILE") for a in captured["args"]), captured["args"]

# PURL/LICENSE/HASH/FIELD_MIN_PCT: an operator's environment variable on this
# server's own container (docs/reference/docker-image.md), not a request field
# -- so _pct_env reads os.environ directly, and the test sets it there too
# (not via extra_env, which run_sibling_scan merges in as if it were a request
# field). A missed forward would silently re-grade a scan against the default
# thresholds instead of the operator's own, the same class of bug as
# CONFORMANCE_PROFILE above.
_PCT_VARS = ("PURL_MIN_PCT", "LICENSE_MIN_PCT", "HASH_MIN_PCT", "FIELD_MIN_PCT")
for _v in _PCT_VARS:
    os.environ[_v] = "77"
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "ANALYZE", run_out,
    lambda ln: None, upload_file=up_file,
)
assert rc == 0, rc
for _v in _PCT_VARS:
    assert ("%s=77" % _v) in captured["args"], (_v, captured["args"])
for _v in _PCT_VARS:
    del os.environ[_v]

# Unset -> not forwarded at all (validate-sbom.sh's own default applies).
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "ANALYZE", run_out,
    lambda ln: None, upload_file=up_file,
)
assert rc == 0, rc
assert not any(a.startswith(_PCT_VARS) for a in captured["args"]), captured["args"]

# A bad value (non-numeric, or numeric but out of 0-100) is dropped, not
# forwarded as-is -- validate-sbom.sh's `--argjson` would crash the whole
# conformance step on the non-numeric one.
for _bad in ("abc", "150", "-5", "12.5", ""):
    os.environ["PURL_MIN_PCT"] = _bad
    captured.clear()
    rc = server.run_sibling_scan(
        "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "ANALYZE", run_out,
        lambda ln: None, upload_file=up_file,
    )
    assert rc == 0, rc
    assert not any(a.startswith("PURL_MIN_PCT") for a in captured["args"]), (_bad, captured["args"])
    del os.environ["PURL_MIN_PCT"]

# DEEP_LICENSE and BYTE_STABLE: plain New scan checkboxes the request already
# sets on the in-process env dict (server's own env.update above), not an
# operator environment variable like the four PCT vars -- so the test drives
# them via extra_env, the same way CONFORMANCE_PROFILE above does. A missed
# forward would silently drop a checkbox the reader just turned on.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
    extra_env={"DEEP_LICENSE": "true", "BYTE_STABLE": "true"},
)
assert rc == 0, rc
assert "DEEP_LICENSE=true" in captured["args"], captured["args"]
assert "BYTE_STABLE=true" in captured["args"], captured["args"]

# Off (or simply not set) forwards the explicit "false", not silence -- a
# missing key must not fall back to _bool_env's default-true.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
)
assert rc == 0, rc
assert "DEEP_LICENSE=false" in captured["args"], captured["args"]
assert "BYTE_STABLE=false" in captured["args"], captured["args"]

# SECURITY_ENRICH/ENRICH_MALICIOUS: an operator's own container environment
# (docs/reference/cli.md, docs/reference/docker-image.md), not a request
# field -- same as the PCT vars, forwarded via extra_env the way
# run_sibling_scan's caller passes its own os.environ.copy()-based env
# through. Both default on and must reach the sibling explicitly off when the
# operator turned them off (e.g. air-gapped, no EPSS/KEV/malicious lookup);
# a missed forward would silently re-enable them only in the sibling.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
    extra_env={"SECURITY_ENRICH": "false", "ENRICH_MALICIOUS": "false"},
)
assert rc == 0, rc
assert "SECURITY_ENRICH=false" in captured["args"], captured["args"]
assert "ENRICH_MALICIOUS=false" in captured["args"], captured["args"]

# Unset (or any other value) forwards the explicit default "true" -- the
# missing-key case _bool_env is meant for, unlike DEEP_LICENSE/BYTE_STABLE.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
)
assert rc == 0, rc
assert "SECURITY_ENRICH=true" in captured["args"], captured["args"]
assert "ENRICH_MALICIOUS=true" in captured["args"], captured["args"]

# STALENESS_ENRICH: same operator-environment story, but opt-in (default off)
# like DEEP_LICENSE/BYTE_STABLE -- on must be explicit, and unset must forward
# the explicit "false", not silence.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
    extra_env={"STALENESS_ENRICH": "true"},
)
assert rc == 0, rc
assert "STALENESS_ENRICH=true" in captured["args"], captured["args"]
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
)
assert rc == 0, rc
assert "STALENESS_ENRICH=false" in captured["args"], captured["args"]

# SECURITY_NVD_VERIFY + NVD_API_KEY: opt-in, meaningful only alongside
# DEEP_CVE (gated the same way scan-security.sh gates scan-nvd-cpe.py). The
# key is a secret, forwarded by NAME ONLY like SCANOSS_API_KEY above -- never
# inlined as NVD_API_KEY=value.
NVD_SENTINEL = "nvd_sentinel_do_not_leak_7c2e"
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
    extra_env={"DEEP_CVE": "true", "SECURITY_NVD_VERIFY": "true", "NVD_API_KEY": NVD_SENTINEL},
)
assert rc == 0, rc
_a = captured["args"]
assert "SECURITY_NVD_VERIFY=true" in _a, _a
assert "NVD_API_KEY" in _a and not any(x.startswith("NVD_API_KEY=") for x in _a), _a
assert not any(NVD_SENTINEL in a for a in _a), "NVD_API_KEY value leaked into argv"
assert (captured["env"] or {}).get("NVD_API_KEY") == NVD_SENTINEL, "subprocess env must carry the key for name-only -e"

# SECURITY_NVD_VERIFY without DEEP_CVE -> not forwarded (the version filter it
# controls never runs outside a deep-cve scan).
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
    extra_env={"SECURITY_NVD_VERIFY": "true", "NVD_API_KEY": NVD_SENTINEL},
)
assert rc == 0, rc
assert not any(x.startswith("SECURITY_NVD_VERIFY") for x in captured["args"]), captured["args"]
assert not any(x == "NVD_API_KEY" for x in captured["args"]), captured["args"]

# SECURITY_NVD_VERIFY off (default) with DEEP_CVE on -> stays out of the argv,
# and no key is forwarded without it.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "SOURCE", run_out,
    lambda ln: None, source_root=src_root,
    extra_env={"DEEP_CVE": "true", "NVD_API_KEY": NVD_SENTINEL},
)
assert rc == 0, rc
assert not any(x.startswith("SECURITY_NVD_VERIFY") for x in captured["args"]), captured["args"]
assert not any(x == "NVD_API_KEY" for x in captured["args"]), captured["args"]

# HF_TOKEN: inherited from THIS container's environment (never posted to the UI)
# and forwarded by name only, so the secret stays out of the docker-run argv.
HF_SENTINEL = "hf_sentinel_do_not_leak_9f3a"
os.environ["HF_TOKEN"] = HF_SENTINEL
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip",
)
assert rc == 0, rc
assert "HF_TOKEN" in captured["args"], captured["args"]
assert captured["args"][captured["args"].index("HF_TOKEN") - 1] == "-e", captured["args"]
# The value itself must appear nowhere in argv (bare -e, not -e NAME=VALUE).
assert not any(HF_SENTINEL in a for a in captured["args"]), "HF_TOKEN value leaked into argv"

# Firmware never carries it: only the AI-model path talks to HuggingFace.
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-firmware:1.5.0", "FIRMWARE", run_out,
    lambda ln: None, upload_file=up_file,
)
assert rc == 0, rc
assert "HF_TOKEN" not in captured["args"], captured["args"]

# No token in the environment -> no flag at all (anonymous, public models only).
del os.environ["HF_TOKEN"]
captured.clear()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    lambda ln: None, model_id="openai/clip",
)
assert rc == 0, rc
assert "HF_TOKEN" not in captured["args"], captured["args"]

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

# Deep-cve NVD-verification progress markers get their own channel
# (on_deepcve_progress), separate from the firmware CVE-DB one above — a
# missing on_deepcve_progress falls back to log the same way.
logs = []; progs = []; deep_progs = []
server._emit_or_log("[deep-cve-progress] 7%", logs.append, progs.append, deep_progs.append)
server._emit_or_log("[deep-cve-progress] 150%", logs.append, progs.append, deep_progs.append)
server._emit_or_log("[firmware-cvedb-progress] 5%", logs.append, progs.append, deep_progs.append)
server._emit_or_log("regular build line", logs.append, progs.append, deep_progs.append)
server._emit_or_log("[deep-cve-progress] 20%", logs.append, progs.append, None)
assert deep_progs == [7, 100], deep_progs
assert progs == [5], progs
assert logs == ["regular build line", "[deep-cve-progress] 20%"], logs
PY
then
    pass "sibling dispatch allowlists image/mode/model-id and sanitizes env (no flag/shell injection)"
else
    fail "sibling dispatch guard failed (see assertion above)"
fi

echo "== scan-stream log/error cleanup: ANSI stripped, git failures classified =="
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

# A colored notice (cdxgen and friends) must reach on_log with the CSI
# sequences gone, not just the ESC byte: this codebase saw a real case where
# only the ESC byte was dropped upstream, leaving literal "[1;35m...[0m".
logs = []
server._emit_or_log("\x1b[1;35mNotice: something\x1b[0m", logs.append)
assert logs == ["Notice: something"], logs
server._emit_or_log("plain line, no color", logs.append)
assert logs[-1] == "plain line, no color", logs

# git failure classification: only the two patterns this codebase has actually
# confirmed (missing/private repo, network) get a key; anything else is None,
# and the caller then falls back to showing the raw text unclassified.
assert server._classify_git_failure(
    "fatal: could not read Username for 'https://github.com': terminal prompts disabled"
) == "run.errorGitNotFoundOrPrivate"
assert server._classify_git_failure(
    "remote: Repository not found."
) == "run.errorGitNotFoundOrPrivate"
assert server._classify_git_failure(
    "fatal: unable to access '...': Could not resolve host: github.com"
) == "run.errorGitNetwork"
assert server._classify_git_failure("fatal: some other git error entirely") is None
assert server._classify_git_failure("") is None
assert server._classify_git_failure(None) is None
PY
then
    pass "ANSI stripped from scan log lines, git failures classified into i18n keys"
else
    fail "scan-stream log/error cleanup failed (see assertion above)"
fi

echo "== safe_extract_zip rejects members that are unsafe once bind-mounted onto Windows =="
# safe_extract_zip already rejected zip-slip (absolute/../ paths). It did NOT
# reject a member name containing a character Windows forbids in a path
# (backslash, colon, ...) -- on Linux those are just odd-looking literal
# filename characters, not separators, so "..\\evil.txt" extracted harmlessly
# INSIDE the destination directory. Verified end to end in this session on a
# real Windows host with Docker Desktop file sharing: those characters get
# silently DROPPED once the tree reaches the Windows side, so two differently
# -named members can collide onto the same Windows filename -- and instead of
# a clean overwrite, the host-visible file ends up holding both members'
# content appended together, silently, with no error anywhere. Must now fail
# closed at extraction time instead.
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os, zipfile, tempfile
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

def build_zip(path, members):
    with zipfile.ZipFile(path, "w") as z:
        for name, content in members.items():
            zi = zipfile.ZipInfo(name)  # bypasses writestr's own os.sep-based rewrite
            z.writestr(zi, content)

with tempfile.TemporaryDirectory() as tmp:
    # Windows-illegal characters embedded in an otherwise-plausible member name.
    hostile = os.path.join(tmp, "hostile.zip")
    build_zip(hostile, {
        "normal.txt": "ok",
        "..\\..\\evil-backslash.txt": "x",
    })
    dest = os.path.join(tmp, "dest1"); os.makedirs(dest)
    try:
        server.safe_extract_zip(hostile, dest)
        raise AssertionError("expected ValueError for a backslash-containing member name")
    except ValueError as e:
        assert "not Windows-safe" in str(e), e

    colon = os.path.join(tmp, "colon.zip")
    build_zip(colon, {"a:b.txt": "x"})
    dest2 = os.path.join(tmp, "dest2"); os.makedirs(dest2)
    try:
        server.safe_extract_zip(colon, dest2)
        raise AssertionError("expected ValueError for a colon-containing member name")
    except ValueError as e:
        assert "not Windows-safe" in str(e), e

    # A normal archive must still extract without complaint (no regression).
    clean = os.path.join(tmp, "clean.zip")
    build_zip(clean, {"package.json": "{}", "src/index.js": "1"})
    dest3 = os.path.join(tmp, "dest3"); os.makedirs(dest3)
    server.safe_extract_zip(clean, dest3)  # raises on failure
    assert os.path.isfile(os.path.join(dest3, "package.json"))
    assert os.path.isfile(os.path.join(dest3, "src", "index.js"))
PY
then
    pass "safe_extract_zip rejects Windows-illegal member names, still extracts clean archives"
else
    fail "safe_extract_zip Windows-safety check failed (see assertion above)"
fi

echo "== a per-feature image can be pulled ahead of time, with progress =="

# Firmware/AI/deep-CVE each live in their own image, pulled on the feature's first
# use. That used to be a multi-minute stall in the middle of a scan with only raw
# `docker pull` lines to show. The tests below hold the contract the UI reads.
if python3 - "$SERVER" <<'PULLPY'
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("server", sys.argv[1])
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

# A request names a feature, never an image reference. The reference comes from
# the server's own environment, so no request can make the daemon pull something
# else. `scanner` is not a key: every published image carries syft, so the SPDX
# fallback never runs and UI for it could not be exercised.
keys = set(server._pullable_images())
assert keys == {"firmware", "aibom", "deep-cve"}, keys
assert server._pullable_images()["firmware"] == server.FIRMWARE_IMAGE

# Layer counting, read from a real non-TTY transcript. A non-TTY `docker pull`
# prints no byte totals and no percentage, so layer counts are the only honest
# unit; the total counts every layer id that appears, because docker omits
# "Pulling fs layer" for a layer it already has.
transcript = (pathlib.Path(sys.argv[1]).parents[2] / "tests" / "fixtures"
              / "docker-pull-nontty.txt").read_text().splitlines()
prog = server.PullProgress()
snaps = [x for x in (prog.feed(line) for line in transcript) if x is not None]
assert snaps, "no progress was reported for a real pull transcript"
final = prog.snapshot()
assert final["total"] > 0 and final["complete"] <= final["total"], final
# feed() reports only on a real change, so a caller can emit one event per change.
assert all(a != b for a, b in zip(snaps, snaps[1:])), snaps
# A line that is not a layer status is not progress; it stays a log line.
assert server.PullProgress().feed("Digest: sha256:abc") is None

# Failure reasons come back as keys the UI translates, and the specific signals
# win over the general ones (a proxy doing TLS interception shows up as x509).
assert server.classify_pull_failure("", "timeout") == "timeout"
assert server.classify_pull_failure("no space left on device") == "disk"
assert server.classify_pull_failure("dial tcp: lookup ghcr.io") == "dns"
assert server.classify_pull_failure("x509: certificate signed by unknown authority") == "proxy"
assert server.classify_pull_failure("pull access denied") == "auth"
assert server.classify_pull_failure("something else entirely") == "unknown"

# An invalid reference is refused before it reaches a command line.
logs = []
code, reason = server._pull_image("-v/etc:/etc", logs.append)
assert code == -1 and reason == "unknown", (code, reason)
assert any("invalid image reference" in x for x in logs), logs

# The pull runs through _stream_cmd, and a cancel callback reaches it — closing
# the stream must stop the download rather than run it to the end.
seen = {}
def fake_stream(args, on_log, on_progress=None, cancel=None, container=None, env=None):
    seen["args"] = args
    seen["cancel"] = cancel
    for line in ["17a39c0ba978: Pulling fs layer", "17a39c0ba978: Pull complete",
                 "Status: Downloaded newer image"]:
        on_log(line)
    return 0
server._stream_cmd = fake_stream
logs, progs = [], []
code, reason = server._pull_image("ghcr.io/x/y:1", logs.append, on_progress=progs.append,
                                  cancel=lambda: False)
assert code == 0 and reason is None, (code, reason)
assert seen["args"] == ["docker", "pull", "ghcr.io/x/y:1"], seen["args"]
assert seen["cancel"] is not None, "cancel was not forwarded to the pull"
assert progs and progs[-1]["total"] >= 1, progs
# Layer lines went to progress, not to the log; other lines stayed logs.
assert "Status: Downloaded newer image" in logs, logs
assert not any("Pull complete" in x for x in logs), logs
PULLPY
then
    pass "the pull reader counts layers, classifies failures and keeps the image set closed"
else
    fail "per-feature image pull contract failed (see assertion above)"
fi

# The two endpoints the UI calls. Both take a feature key; an unknown key is a
# 400 rather than a pull of something unexpected.
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/image-status?image=firmware")
if [ "$code" = "200" ]; then
    pass "/image-status answers for a known feature key"
else
    fail "/image-status did not answer for a known key" "got $code"
fi

body=$(curl -s "$BASE/image-status?image=firmware")
if printf '%s' "$body" | grep -q '"present"'; then
    pass "/image-status reports whether the image is already there"
else
    fail "/image-status has no present field" "$body"
fi

for ep in image-status pull-stream; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$ep?image=scanner")
    if [ "$code" = "400" ]; then
        pass "/$ep refuses a key that is not in the set"
    else
        fail "/$ep accepted an out-of-set key" "got $code"
    fi
    code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/$ep?image=ghcr.io/evil/x:1")
    if [ "$code" = "400" ]; then
        pass "/$ep refuses a raw image reference"
    else
        fail "/$ep accepted a raw image reference" "got $code"
    fi
done

echo "== path traversal is blocked =="
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/file?name=../../etc/passwd")
[ "$code" = "404" ] && pass "/file blocks path traversal (404)" || fail "/file traversal returned $code (expected 404)"

echo "== SPDX export is on demand (GET /spdx-export) =="
# SPDX is no longer a pre-scan toggle: the results screen converts the finished
# CycloneDX BOM when the user asks. Bad ids must be refused before any work, a
# scan with no BOM is a 404, and an already-converted scan is idempotent — that
# last one must hold even here, where there is no syft to convert with.
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/spdx-export?id=../etc")
[ "$code" = "400" ] && pass "/spdx-export rejects a traversal id (400)" || fail "/spdx-export bad id returned $code (expected 400)"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/spdx-export?id=no_such_scan")
[ "$code" = "404" ] && pass "/spdx-export 404s a scan with no CycloneDX BOM" || fail "/spdx-export missing scan returned $code (expected 404)"

mkdir -p "$OUT/spdxrun_1.0"
echo '{"bomFormat":"CycloneDX"}' > "$OUT/spdxrun_1.0/spdxrun_1.0_bom.json"
echo '{"spdxVersion":"SPDX-2.3"}' > "$OUT/spdxrun_1.0/spdxrun_1.0_bom.spdx.json"
spdx_body=$(curl -fsS "$BASE/spdx-export?id=spdxrun_1.0" 2>/dev/null)
if echo "$spdx_body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['name'] == 'spdxrun_1.0_bom.spdx.json', d
# The refreshed listing is what the UI swaps in, so the file must be in it.
assert any(f['name'].endswith('_bom.spdx.json') for f in d['results']), d
" 2>/dev/null; then
    pass "/spdx-export returns the existing SPDX without reconverting"
else
    fail "/spdx-export idempotent case failed" "$spdx_body"
fi

if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

# Both paths cross into an argv, so containment is re-checked even though the
# server derives them itself — a symlinked run folder must not export outside.
assert server.convert_bom_to_spdx("/etc/passwd", server.OUTPUT_DIR + "/x.spdx.json",
                                  False, lambda ln: None) == -1
assert server.convert_bom_to_spdx(server.OUTPUT_DIR + "/x_bom.json", "/tmp/evil.spdx.json",
                                  False, lambda ln: None) == -1

# With no syft here, the work goes to a sibling scanner container. Capture the
# argv: the converter script runs via --entrypoint bash with the two container
# paths (shared by --volumes-from, not a host bind), and --stable rides along
# when the original scan was byte-stable.
captured = {}
def fake_stream(args, on_log, **kw):
    captured["args"] = args
    return 0
server._stream_cmd = fake_stream
server._sibling_image_present = lambda image: True
server._self_container_id = lambda: "selfcid000000"
server.docker_cli_present = lambda: True
server.docker_capable = lambda: True
server.spdx_convert_capable = lambda: False
# Same no-op as the run_sibling_scan dispatch tests above: this section is not
# about the background refresh, so an "already present" scanner image must not
# shell out to a real `docker pull` here.
server.refresh_sibling_image_quietly = lambda *a, **k: None

bom = server.OUTPUT_DIR + "/run_1/run_1_bom.json"
spdx = server.OUTPUT_DIR + "/run_1/run_1_bom.spdx.json"
rc = server.convert_bom_to_spdx(bom, spdx, True, lambda ln: None)
args = captured["args"]
assert rc == 0, rc
assert args[:3] == ["docker", "run", "--rm"], args
assert "--volumes-from" in args and "selfcid000000" in args, args
assert "-v" not in args, args              # no host bind mount (breaks on Windows)
assert args[-4:] == ["/usr/local/lib/sbom/convert-to-spdx.sh", bom, spdx, "--stable"], args
assert "--entrypoint" in args and args[args.index("--entrypoint") + 1] == "bash", args

# Not byte-stable -> no --stable flag.
captured.clear()
server.convert_bom_to_spdx(bom, spdx, False, lambda ln: None)
assert "--stable" not in captured["args"], captured["args"]
PY
then
    pass "SPDX conversion guards paths and dispatches a sibling with a safe argv"
else
    fail "SPDX conversion guard failed (see assertion above)"
fi

echo "== rootfs scan-root boundary (safe_scan_dir with extra --mount roots) =="
if SBOM_OUTPUT_DIR="$OUT" SBOM_UI_SCAN_ROOTS="$SCANROOT|/host/mounted" \
   python3 - "$ROOT_DIR" "$SCANROOT" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

root = sys.argv[2]
real_root = os.path.realpath(root)

# The mounted root itself and subfolders inside it are allowed.
assert server.safe_scan_dir(root) == real_root
assert server.safe_scan_dir(root + "/etc") == os.path.join(real_root, "etc")

# Traversal, absolute outside paths and control characters are rejected.
assert server.safe_scan_dir(root + "/../outside") is None
assert server.safe_scan_dir("/etc") is None
assert server.safe_scan_dir("/scan-targets-evil") is None
assert server.safe_scan_dir(root + "/etc\n") is None
assert server.safe_scan_dir("") is None

# A symlink inside the mount pointing outside must not escape the boundary.
link = os.path.join(root, "escape")
if not os.path.lexists(link):
    os.symlink("/etc", link)
assert server.safe_scan_dir(link) is None

# Non-mounted input still resolves relative to /src (classic behavior): with
# no /src on this host it must come back None (rejected), never throw or fall
# through to some other root.
assert server.safe_scan_dir("relative/subdir") is None
assert server.safe_scan_dir("/absolute-under-src") is None
PY
then
    pass "safe_scan_dir allows inside-the-mount paths and blocks escapes"
else
    fail "safe_scan_dir extra-root boundary failed (see assertion above)"
fi

echo "== Yocto build directory detection (parity with scripts/scan-sbom.sh) =="
# The UI must read a Yocto build directory exactly as the CLI does, or the same
# folder would be analyzed one way from a terminal and another from the browser.
YFIX="$WORK/yocto-fixtures"
mkdir -p "$YFIX"
# The fixtures are registered as a scan root: the detection walks a folder the
# request named, so it re-checks that the folder is inside one before touching
# it, and refuses anything else.
if SBOM_OUTPUT_DIR="$OUT" SBOM_UI_SCAN_ROOTS="$YFIX|/host/yocto-fixtures" \
   python3 - "$ROOT_DIR" "$YFIX" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

root = sys.argv[2]
YOCTO3 = '{"@context":"https://spdx.org/rdf/3.0.1/x","@graph":[{"type":"Tool","name":"bitbake"}]}'
YOCTO2 = '{"spdxVersion": "SPDX-2.2", "creationInfo": {"creators": ["Tool: bitbake"]}, "packages": []}'
OTHER = '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}'

def write(rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    # Candidates come back resolved (the containment check resolves before it
    # walks), so compare against the resolved path — which document is chosen is
    # what has to match the CLI, not how the path is spelled.
    return os.path.realpath(path)

# bitbake's own markers stand alone, so a build that emitted no SBOM is still
# recognized (and gets told which setting to add) rather than scanned as a tree.
build = os.path.join(root, "build")
img = write("build/tmp/deploy/images/qemux86-64/core-image.rootfs.spdx.json", YOCTO3)
os.makedirs(os.path.join(build, "conf"), exist_ok=True)
write("build/conf/bblayers.conf", 'BBLAYERS = "x"')
assert server.is_yocto_build_dir(build)
assert server.yocto_pick_spdx(server.yocto_spdx_candidates(build)) == img
assert server.is_yocto_build_dir(os.path.join(root, "nosbom")) is False

nosbom = os.path.join(root, "nosbom", "conf")
os.makedirs(nosbom, exist_ok=True)
write("nosbom/conf/bblayers.conf", 'BBLAYERS = "x"')
assert server.is_yocto_build_dir(os.path.join(root, "nosbom"))
assert server.yocto_spdx_candidates(os.path.join(root, "nosbom")) == []

# TMPDIR carries the C library suffix outside poky: tmp-glibc, not tmp.
oe = os.path.join(root, "oecore")
oeimg = write("oecore/tmp-glibc/deploy/images/qemuarm/core-image-base.rootfs.spdx.json", YOCTO3)
assert server.is_yocto_build_dir(oe)
assert server.yocto_pick_spdx(server.yocto_spdx_candidates(oe)) == oeimg

# An ordinary directory, and folders whose only Yocto-looking trait is a common
# name, stay directory scans — being taken over would refuse a scan the user meant.
plain = os.path.join(root, "plain")
os.makedirs(os.path.join(plain, "etc"), exist_ok=True)
assert server.is_yocto_build_dir(plain) is False
write("assets/deploy/images/banners/note.txt", "not an sbom")
assert server.is_yocto_build_dir(os.path.join(root, "assets")) is False
write("release/release.spdx.json", OTHER)
write("release/app.manifest", "")
assert server.is_yocto_build_dir(os.path.join(root, "release")) is False

# SPDX 3.x wins over 2.x even when the 2.x document was written later, since only
# 3.x carries the installed set and the build's CVE verdicts.
mixed = os.path.join(root, "mixed")
new3 = write("mixed/tmp/deploy/images/m1/new.rootfs.spdx.json", YOCTO3)
old2 = write("mixed/tmp/deploy/images/m2/old.rootfs.spdx.json", YOCTO2)
os.utime(old2, (2 ** 31 - 1, 2 ** 31 - 1))
assert server.is_spdx2_doc(old2) and not server.is_spdx2_doc(new3)
assert server.yocto_pick_spdx(server.yocto_spdx_candidates(mixed)) == new3

# bitbake publishes a timestamped file plus an IMAGE_LINK_NAME symlink to it;
# both match, and they are one document, not a choice.
linked = os.path.join(root, "linked")
real = write("linked/tmp/deploy/images/m1/img-20260101.rootfs.spdx.json", YOCTO3)
os.symlink(os.path.basename(real), os.path.join(os.path.dirname(real), "img.rootfs.spdx.json"))
write("linked/conf/bblayers.conf", 'BBLAYERS = "x"')
assert len(server.yocto_spdx_candidates(linked)) == 1, server.yocto_spdx_candidates(linked)

# A real build directory carries a per-recipe SPDX document for every recipe
# under tmp/deploy/spdx/, plus an SDK's own documents. None describe the image,
# and the browser has to reach the same answer the CLI does.
big = os.path.join(root, "bigtree")
bigimg = write("bigtree/tmp/deploy/images/qemux86-64/core-image-minimal.rootfs.spdx.json", YOCTO3)
write("bigtree/conf/bblayers.conf", 'BBLAYERS = "x"')
for i in range(300):
    write("bigtree/tmp/deploy/spdx/qemux86-64/recipe-pkg%d.spdx.json" % i, YOCTO3)
write("bigtree/tmp/deploy/sdk/poky-glibc-x86_64-core-image-minimal.rootfs.spdx.json", YOCTO3)
assert server.is_yocto_build_dir(big)
cands = server.yocto_spdx_candidates(big)
assert cands == [bigimg], cands
assert server.yocto_pick_spdx(cands) == bigimg

# Outside every allowed scan root there is nothing to detect, whatever the
# folder looks like: the walk is only safe inside the boundary.
outside = os.path.join(os.path.dirname(root), "outside-build")
os.makedirs(os.path.join(outside, "conf"), exist_ok=True)
with open(os.path.join(outside, "conf", "bblayers.conf"), "w") as fh:
    fh.write('BBLAYERS = "x"')
assert server.scan_root_dir(outside) is None
assert server.is_yocto_build_dir(outside) is False
assert server.yocto_spdx_candidates(outside) == []
PY
then
    pass "Yocto detection matches the CLI rules (markers, tmp-glibc, SPDX 3.x, symlinks)"
else
    fail "Yocto detection parity failed (see assertion above)"
fi

echo "== nested_rootfs_hint: mirrors scan-sbom.sh's shape check for the web UI's deep source scan =="
if python3 - "$ROOT_DIR" <<'PY'
import os, sys, tempfile
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

with tempfile.TemporaryDirectory() as root:
    def mk(*parts):
        p = os.path.join(root, *parts)
        os.makedirs(p, exist_ok=True)
        return p

    # Same four fixtures, same names and shapes, as
    # tests/test-input-routing.sh's "nested_rootfs_hint" section,
    # kept in sync deliberately (see the comment on nested_rootfs_hint in
    # scripts/scan-sbom.sh and in this file's own nested_rootfs_hint).

    # A directory that is itself a rootfs (etc/ + 2 of bin/sbin/usr/lib/var)
    # gets no hint -- it has nothing to add there, this check exists only for
    # the SOURCE-branch diagnostic.
    flat = mk("flat")
    for sub in ("etc", "bin", "sbin", "usr", "lib"):
        mk("flat", sub)
    assert server.nested_rootfs_hint(flat) is None, "a rootfs itself should get no hint"

    # The common wrapped-delivery shape, named relative to the picked folder --
    # what the web UI's own diagnostic will show the user.
    delivery = mk("delivery")
    mk("delivery", "release-20260919", "rootfs", "etc")
    mk("delivery", "release-20260919", "rootfs", "bin")
    mk("delivery", "release-20260919", "rootfs", "usr")
    assert server.nested_rootfs_hint(delivery) == os.path.join("release-20260919", "rootfs"), \
        server.nested_rootfs_hint(delivery)

    onelevel = mk("onelevel")
    mk("onelevel", "rootfs", "etc")
    mk("onelevel", "rootfs", "bin")
    mk("onelevel", "rootfs", "var")
    assert server.nested_rootfs_hint(onelevel) == "rootfs", server.nested_rootfs_hint(onelevel)

    # No nested rootfs anywhere -- no hint, same as an ordinary source tree.
    nodeps = mk("nodeps")
    mk("nodeps", "src")
    assert server.nested_rootfs_hint(nodeps) is None
PY
then
    pass "nested_rootfs_hint matches the CLI's shape check (self/wrapped/one-level/none)"
else
    fail "nested_rootfs_hint parity with scan-sbom.sh failed (see assertion above)"
fi

# A deep source scan always copies and builds the whole picked scan root
# (picked["path"]), never the request-derived scan_dir a caller may have
# pointed at a subfolder of it -- copy_scan_target_tree already makes this
# choice explicitly (its own comment: request input must not reach the
# copytree sink). nested_rootfs_hint must look in the same place the scan
# actually covers, for the same reason and so the CLI/web-UI diagnostics
# agree on what "one or two levels below the scanned folder" means. A CodeQL
# alert on the earlier scan_dir-based call is closed by this source fix, not
# by dismissal -- this guards the fix by source text rather than re-running
# the request handler (no scan-target-src integration harness exists yet to
# drive it end to end).
if grep -qF 'hint = nested_rootfs_hint(picked["path"])' "$ROOT_DIR/docker/web/server.py"; then
    pass "the deep-scan nested-rootfs hint is looked up from the picked scan root, not the request path"
else
    fail "the deep-scan nested-rootfs hint call no longer uses picked[\"path\"] -- did it regress to the request-derived scan_dir?"
fi

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
# An XML SBOM is refused here rather than in the container: the pipeline reads
# JSON only, so accepting the file just spends a scan to fail. The answer has to
# name the format and the fix, not read as "unsupported file type".
printf '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>\n' > "$WORK/supplier.xml"
xml_body=$(curl -s -o "$WORK/xml-resp.json" -w '%{http_code}' -F "kind=sbom" -F "file=@$WORK/supplier.xml" "$BASE/upload?kind=sbom")
[ "$xml_body" = "415" ] && pass "XML SBOM upload rejected (415)" || fail ".xml as sbom returned $xml_body (expected 415)"
xml_err=$(python3 -c "import json;print(json.load(open('$WORK/xml-resp.json')).get('error',''))" 2>/dev/null)
case "$xml_err" in
    *"not supported yet"*) pass "the 415 names XML and tells the user to convert to JSON" ;;
    *) fail "XML upload error text unexpected" "got '$xml_err'" ;;
esac
# A JSON SBOM upload is unaffected by that guard.
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}\n' > "$WORK/supplier.json"
c_json=$(curl -s -o /dev/null -w '%{http_code}' -F "kind=sbom" -F "file=@$WORK/supplier.json" "$BASE/upload?kind=sbom")
[ "$c_json" = "200" ] && pass "JSON SBOM upload still accepted (200)" || fail ".json as sbom returned $c_json (expected 200)"

# Regression: the filename sanitizer used to be an ASCII-only allowlist
# (re.sub(r"[^A-Za-z0-9._-]", "_", ...)), so a Korean filename — the common
# case for this product's users, not an edge case — came back as a run of
# underscores. It must now only strip what is genuinely unsafe (Windows-
# illegal characters, since this upload can be bind-mounted back onto a
# Windows host) while preserving non-ASCII scripts.
ko_resp=$(curl -fsS -F "kind=zip" -F "file=@$WORK/sample.zip;filename=사내프로젝트.zip" "$BASE/upload?kind=zip" 2>/dev/null)
ko_fn=$(echo "$ko_resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('filename',''))" 2>/dev/null)
[ "$ko_fn" = "사내프로젝트.zip" ] && pass "Korean upload filename survives sanitization intact" \
    || fail "Korean upload filename was mangled" "got '$ko_fn' from $ko_resp"

# Windows-illegal characters must still be neutralized (this filename can end
# up as a real path on a Windows host via Docker Desktop's file sharing).
win_resp=$(curl -fsS -F "kind=zip" -F 'file=@'"$WORK"'/sample.zip;filename=a<b>c:d.zip' "$BASE/upload?kind=zip" 2>/dev/null)
win_fn=$(echo "$win_resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('filename',''))" 2>/dev/null)
if printf '%s' "$win_fn" | grep -qE '[<>:]'; then
    fail "Windows-illegal characters survived sanitization" "got '$win_fn' from $win_resp"
else
    pass "Windows-illegal characters (<>:) are still neutralized"
fi

# Most vendors ship a firmware download as a zip, and the CLI has always taken
# one. The upload form used to refuse the same file because the extension was
# missing from the firmware list, so a scan the CLI could run had no path
# through the UI at all.
cp "$WORK/sample.zip" "$WORK/vendor-firmware.zip"
c_fw=$(curl -s -o /dev/null -w '%{http_code}' -F "kind=firmware" \
       -F "file=@$WORK/vendor-firmware.zip" "$BASE/upload?kind=firmware")
[ "$c_fw" = "200" ] && pass "a zip is accepted as firmware, as the CLI accepts it" \
    || fail "a firmware zip returned $c_fw (expected 200)" \
            "the CLI scans vendor firmware shipped as .zip; the form must not refuse it"
# The list stays a list, though — an arbitrary extension is still refused.
c_fw_bad=$(curl -s -o /dev/null -w '%{http_code}' -F "kind=firmware" \
           -F "file=@$WORK/payload.txt" "$BASE/upload?kind=firmware")
[ "$c_fw_bad" = "415" ] && pass "a .txt is still refused as firmware (415)" \
    || fail ".txt as firmware returned $c_fw_bad (expected 415)"

# An AI model weight file, read by its own header (MODE=MODELFILE). The cap is
# in gigabytes because that is what a quantized model weighs, and .bin stays out
# of the list on purpose: it names both a checkpoint and a firmware image.
printf 'GGUF\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    > "$WORK/tiny.gguf"
c_ml=$(curl -s -o /dev/null -w '%{http_code}' -F "kind=model" \
       -F "file=@$WORK/tiny.gguf" "$BASE/upload?kind=model")
[ "$c_ml" = "200" ] && pass "a .gguf is accepted as a model upload" \
    || fail "a model upload returned $c_ml (expected 200)"
c_ml_bad=$(curl -s -o /dev/null -w '%{http_code}' -F "kind=model" \
           -F "file=@$WORK/payload.txt" "$BASE/upload?kind=model")
[ "$c_ml_bad" = "415" ] && pass "a .txt is refused as a model file (415)" \
    || fail ".txt as model returned $c_ml_bad (expected 415)"
if python3 - "$SERVER" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("server", sys.argv[1])
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)
# 8 GB: the common quantized sizes fit, and anything past it is a CLI job.
assert server.MAX_BYTES["model"] == 8 * 1024 * 1024 * 1024, server.MAX_BYTES["model"]
exts = server.UPLOAD_EXTS["model"]
for want in (".gguf", ".safetensors", ".pt", ".onnx", ".npz"):
    assert want in exts, (want, exts)
# .bin belongs to firmware; a checkpoint named .bin goes through the CLI.
assert ".bin" not in exts, exts
assert ".bin" in server.UPLOAD_EXTS["firmware"], server.UPLOAD_EXTS["firmware"]
PY
then
    pass "model upload cap is 8 GB and .bin stays with firmware"
else
    fail "model upload kind contract failed (see assertion above)"
fi

# A Yocto SPDX 2.2 build deploys one <image>.spdx.tar.zst and no document, so
# that archive is the only SBOM such a build can hand over. It has to be
# uploadable, while a bare zstd tarball stays out.
: > "$WORK/core-image-minimal.rootfs.spdx.tar.zst"
: > "$WORK/something.tar.zst"
zst_tok=$(curl -fsS -F "kind=sbom" -F "file=@$WORK/core-image-minimal.rootfs.spdx.tar.zst" \
    "$BASE/upload?kind=sbom" 2>/dev/null \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
[ -n "$zst_tok" ] && pass "a Yocto SPDX 2.x archive uploads as an SBOM" \
    || fail ".spdx.tar.zst was refused as an SBOM upload"
c_zst=$(curl -s -o /dev/null -w '%{http_code}' -F "kind=sbom" -F "file=@$WORK/something.tar.zst" "$BASE/upload?kind=sbom")
[ "$c_zst" = "415" ] && pass "a bare zstd tarball is still refused (415)" \
    || fail "something.tar.zst as sbom returned $c_zst (expected 415)"
# The extension has to survive the save, or the scanner cannot tell what it got.
[ -n "$zst_tok" ] && [ -n "$(find "$OUT/.uploads/$zst_tok" -name '*.spdx.tar.zst' 2>/dev/null | head -1)" ] \
    && pass "the archive keeps its extension where the scanner reads it" \
    || fail "uploaded archive lost its .spdx.tar.zst name"

echo "== upload size caps are enforced before the body is read =="
# The SBOM cap is sized from measurement, not taste: a Yocto core-image-minimal
# SPDX 3.0 document is 15.8 MB and parsing peaks around 4.8x the file size, so the
# cap has to clear real build-system output while still bounding memory. Guarding
# the declared Content-Length means an oversized upload costs nothing to refuse —
# assert that, rather than actually sending 100 MB.
sbom_cap=$(python3 - "$ROOT_DIR/docker/web/server.py" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'"sbom":\s*(\d+)\s*\*\s*1024\s*\*\s*1024', src)
print(m.group(1) if m else "0")
PY
)
[ "${sbom_cap:-0}" -ge 25 ] \
    && pass "sbom upload cap is at least 25 MB (declared: ${sbom_cap} MB)" \
    || fail "sbom cap is ${sbom_cap} MB — too small for build-system SBOMs"
# An over-cap declaration is refused with 413 without streaming a body, and the
# message names the limit so the user knows whether trimming the file would help.
over=$(( (sbom_cap + 1) * 1024 * 1024 ))
cap_resp=$(curl -s -o "$WORK/cap.out" -w '%{http_code}' -X POST \
    -H "Content-Type: multipart/form-data; boundary=zz" \
    -H "Content-Length: $over" \
    --max-time 10 "$BASE/upload?kind=sbom" 2>/dev/null || echo "000")
if [ "$cap_resp" = "413" ]; then
    pass "over-cap upload refused with 413 before the body is read"
    grep -q "limit" "$WORK/cap.out" 2>/dev/null \
        && pass "413 response names the limit" \
        || fail "413 body does not mention the limit: $(head -c 200 "$WORK/cap.out")"
else
    fail "over-cap upload returned $cap_resp (expected 413)"
fi

echo "== package upload: the accepted extensions are the measured ones =="
# A build artifact instead of source. The list is measured (see the archive
# table in the plan): java archives and OS packages are readable as a file, a
# wheel is readable once unpacked, and formats that yield nothing either way are
# not accepted at all — receiving one would produce an empty scan that reads as
# a broken feature.
: > "$WORK/lib.jar"
resp=$(curl -fsS -F "kind=package" -F "file=@$WORK/lib.jar" "$BASE/upload?kind=package" 2>/dev/null)
ptoken=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
if [ -n "$ptoken" ]; then
    pass "POST /upload (package, .jar) returns a token"
else
    fail "package upload did not return a token" "$resp"
fi
: > "$WORK/lib.gem"
c_gem=$(curl -s -o /dev/null -w '%{http_code}' -F "kind=package" -F "file=@$WORK/lib.gem" "$BASE/upload?kind=package")
[ "$c_gem" = "415" ] && pass ".gem rejected (415) — measured at zero components" \
                     || fail ".gem returned $c_gem (expected 415)"

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
echo "== malicious flag surfaced + counted (sbom_summary) =="
# enrich-malicious.sh writes bomlens:malicious plus the advisory id and snapshot
# date. sbom_summary must surface them per-row and count them separately from
# the vulnerability figures — a malicious package is removed, not patched, so
# folding it into maxSeverity would file it under the wrong action.
cat > "$OUT/malsum_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX",
 "components":[
   {"name":"evil","version":"1.0","type":"library","purl":"pkg:npm/evil@1.0",
    "properties":[{"name":"bomlens:malicious","value":"true"},
                  {"name":"bomlens:malicious:id","value":"MAL-2024-1"},
                  {"name":"bomlens:malicious:source","value":"osv.dev@2026-01-02"}]},
   {"name":"honest","version":"2.0","type":"library","purl":"pkg:npm/honest@2.0"}
 ]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
s = server.sbom_summary("malsum_1.0")
assert s["maliciousCount"] == 1, s
rows = {r["name"]: r for r in s["componentList"]}
assert rows["evil"]["malicious"] is True, rows["evil"]
assert rows["evil"]["maliciousId"] == "MAL-2024-1", rows["evil"]
assert rows["evil"]["maliciousSource"] == "osv.dev@2026-01-02", rows["evil"]
# Kept out of the severity figures on purpose.
assert "maxSeverity" not in rows["evil"], rows["evil"]
assert "malicious" not in rows["honest"], rows["honest"]
PY
then
    pass "malicious flag surfaced per-row (id, snapshot) and counted apart from severities"
else
    fail "malicious summary produced wrong values (see assertion above)"
fi
# No flagged component -> the count is absent, not zero. The snapshot may simply
# not have been bundled, and a zero would read as an all-clear nobody checked.
cat > "$OUT/malnone_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","components":[{"name":"a","version":"1","type":"library","purl":"pkg:npm/a@1"}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
s = server.sbom_summary("malnone_1.0")
assert "maliciousCount" not in s, s
PY
then
    pass "nothing flagged -> maliciousCount absent (never a reassuring zero)"
else
    fail "maliciousCount was present with nothing flagged"
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
echo "== kernel advisories are counted apart from the severity figures =="

# A rootfs carries one kernel, and an old one carries thousands of advisories
# (measured: 5,262 and 5,032 on two consumer routers). Nearly all are for
# subsystems that image never compiled in, and the SBOM cannot tell which. Mixed
# into the totals they make a device with two real criticals read like one with
# two thousand, so they are reported on their own line instead.
cat > "$OUT/kern_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[
  {"VulnerabilityID":"CVE-K1","Severity":"CRITICAL","PkgName":"linux_kernel","InstalledVersion":"2.6.19"},
  {"VulnerabilityID":"CVE-K2","Severity":"HIGH","PkgName":"kernel","InstalledVersion":"4.4.153"},
  {"VulnerabilityID":"CVE-K3","Severity":"HIGH","PkgName":"linux-kernel","InstalledVersion":"4.4.153"},
  {"VulnerabilityID":"CVE-R1","Severity":"CRITICAL","PkgName":"openssl","InstalledVersion":"1.0.2"},
  {"VulnerabilityID":"CVE-R2","Severity":"LOW","PkgName":"linux-pam","InstalledVersion":"1.3"}
]}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
sm = server.security_summary("kern_1.0")
# The three kernel rows are counted on their own and are out of the figures.
assert sm["kernelCount"] == 3, sm
assert sm["CRITICAL"] == 1 and sm["HIGH"] == 0 and sm["LOW"] == 1, sm
assert sm["TOTAL"] == 2, sm
ids = {v["id"] for v in sm["vulnerabilities"]}
assert ids == {"CVE-R1", "CVE-R2"}, ids
# A name that merely starts with "linux" is not the kernel — linux-pam is a real
# component with its own advisories and must stay in the table.
assert any(v["pkg"] == "linux-pam" for v in sm["vulnerabilities"]), sm["vulnerabilities"]
# No kernel rows means no extra field, so the shape does not change for the
# overwhelming majority of scans.
import json, pathlib
out = pathlib.Path(os.environ["SBOM_OUTPUT_DIR"])
(out / "nokern_1.0_security.json").write_text(json.dumps(
    {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-X", "Severity": "LOW", "PkgName": "zlib",
         "InstalledVersion": "1.2"}]}]}))
sm2 = server.security_summary("nokern_1.0")
assert "kernelCount" not in sm2, sm2
PY
then
    pass "kernel advisories are counted apart and other linux-* packages are not"
else
    fail "kernel advisory separation is wrong (see assertion above)"
fi
rm -f "$OUT"/kern_1.0_* "$OUT"/nokern_1.0_*

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

echo "== Status / NVD severity / publish date (security_summary) =="
# Status (fix availability), VendorSeverity.nvd (a second rating axis) and
# PublishedDate are only sometimes present on a finding; each must be joined
# onto the row when present and omitted entirely when not.
cat > "$OUT/sev_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[
  {"VulnerabilityID":"CVE-1","Severity":"CRITICAL","PkgName":"openssl","InstalledVersion":"3.0",
   "Status":"affected","VendorSeverity":{"nvd":3},"PublishedDate":"2024-01-02T00:00:00Z"},
  {"VulnerabilityID":"CVE-2","Severity":"LOW","PkgName":"zlib","InstalledVersion":"1.2"}
]}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
vulns = {x["id"]: x for x in server.security_summary("sev_1.0")["vulnerabilities"]}
assert vulns["CVE-1"]["status"] == "affected", vulns["CVE-1"]
assert vulns["CVE-1"]["nvdSeverity"] == "HIGH", vulns["CVE-1"]
assert vulns["CVE-1"]["publishedDate"] == "2024-01-02T00:00:00Z", vulns["CVE-1"]
for k in ("status", "nvdSeverity", "publishedDate"):
    assert k not in vulns["CVE-2"], (k, vulns["CVE-2"])
PY
then
    pass "status/nvdSeverity/publishedDate joined when present, omitted when not"
else
    fail "status/nvdSeverity/publishedDate handling is wrong"
fi
rm -f "$OUT"/sev_1.0_*

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

echo "== purl attached to vulnerability rows (security_summary) =="
# Two different components (different ecosystems) can share a name and
# installed version by coincidence. Without the purl on each row, a consumer
# joining/grouping by pkg+installed alone (groupByUpgrade on the frontend)
# would merge findings that belong to two unrelated components.
cat > "$OUT/purl_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[
  {"VulnerabilityID":"CVE-1","Severity":"HIGH","PkgName":"foo","InstalledVersion":"1.0",
   "PkgIdentifier":{"PURL":"pkg:npm/foo@1.0"}},
  {"VulnerabilityID":"CVE-2","Severity":"LOW","PkgName":"foo","InstalledVersion":"1.0",
   "PkgIdentifier":{"PURL":"pkg:golang/foo@1.0"}},
  {"VulnerabilityID":"CVE-3","Severity":"LOW","PkgName":"libfoo","InstalledVersion":"1.0"}
]}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
vulns = {x["id"]: x for x in server.security_summary("purl_1.0")["vulnerabilities"]}
assert vulns["CVE-1"]["purl"] == "pkg:npm/foo@1.0", vulns["CVE-1"]
assert vulns["CVE-2"]["purl"] == "pkg:golang/foo@1.0", vulns["CVE-2"]
assert vulns["CVE-1"]["purl"] != vulns["CVE-2"]["purl"], "different components must not share a purl"
assert "purl" not in vulns["CVE-3"], vulns["CVE-3"]  # no PkgIdentifier -> omitted, not guessed
PY
then
    pass "purl attached to each vulnerability row when Trivy resolved one"
else
    fail "purl attachment is wrong"
fi
rm -f "$OUT"/purl_1.0_*

echo "== untrusted SBOM shapes must not crash the summaries (ANALYZE mode) =="
# ANALYZE copies an uploaded SBOM verbatim; CycloneDX does not force components[]
# to be objects or properties/licenses/externalReferences to be arrays. A crafted
# SBOM must degrade (skip the malformed element) instead of crashing
# sbom_summary/list_scans and leaving the SSE 'done' event unsent (UI hangs) or
# permanently breaking the Recent-scans sidebar.
# (a) scalar entries mixed into components[].
cat > "$OUT/evil_scal_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX",
 "metadata":{"component":{"name":"evil-scal","version":"1.0","type":"application"}},
 "components":["x", 42, null,
   {"type":"library","name":"real","version":"1.0","purl":"pkg:pypi/real@1.0"}]}
JSON
# (b) dict components whose properties/licenses/externalReferences are scalars,
# and a metadata that is itself a scalar — every list/dict field must degrade.
cat > "$OUT/evil_field_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":"oops",
 "components":[
   {"name":"bad","properties":"x","licenses":"y","externalReferences":7,"type":"library"},
   {"name":"good","version":"2.0","type":"library","purl":"pkg:npm/good@2.0",
    "properties":[null,"scalar",{"name":"bomlens:eol","value":"true"}],
    "licenses":[{"license":{"id":"MIT"}}]}
 ]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

# (a) scalar components are skipped; the one real component is summarized, and
# the reported `components` count still reflects the full array length.
s = server.sbom_summary("evil_scal_1.0")
assert s is not None, "summary crashed on scalar components"
rows = {r["name"]: r for r in s["componentList"]}
assert list(rows) == ["real"], rows          # scalars dropped, real kept
assert rows["real"]["purl"] == "pkg:pypi/real@1.0", rows["real"]
assert s["components"] == 4, s                # full array length preserved

# (b) scalar properties/licenses/externalReferences and a scalar metadata all
# degrade to empty: the malformed component still yields a row, the well-formed
# one is fully summarized (eol property + MIT license), and eolCount counts it.
s2 = server.sbom_summary("evil_field_1.0")
assert s2 is not None, "summary crashed on scalar object fields"
rows2 = {r["name"]: r for r in s2["componentList"]}
assert set(rows2) == {"bad", "good"}, rows2
assert rows2["bad"]["licenses"] == [] and "eol" not in rows2["bad"], rows2["bad"]
assert rows2["good"]["licenses"] == ["MIT"], rows2["good"]
assert rows2["good"]["eol"] == "true", rows2["good"]
assert s2["eolCount"] == 1, s2

# scan_detail re-opens the poisoned scan without crashing (the done-event shape).
assert server.scan_detail("evil_scal_1.0")["ok"] is True

# (c) list_scans walks EVERY scan in OUTPUT_DIR, so one poisoned folder must not
# break the whole Recent list: it returns for both malformed scans.
ids = {x["id"]: x for x in server.list_scans()}
assert "evil_scal_1.0" in ids and "evil_field_1.0" in ids, ids
assert ids["evil_scal_1.0"]["components"] == 4, ids["evil_scal_1.0"]
assert ids["evil_field_1.0"]["project"] == "evil_field_1.0", ids["evil_field_1.0"]
PY
then
    pass "malformed components / scalar object fields degrade (no crash; valid components summarized)"
else
    fail "untrusted SBOM shapes crashed a summary (see assertion above)"
fi
rm -f "$OUT"/evil_scal_1.0_* "$OUT"/evil_field_1.0_*

rm -f "$OUT"/demo_1.0_* "$OUT"/flat_1.0_* "$OUT"/bad_1.0_*

echo "== the root component is not a dependency of itself =="
# An AI scan folds the root model INTO components[], unlike a software scan whose
# root lives only in metadata. The root also keys the dependency graph, so it was
# picked up as a transitive dependency of its own SBOM: three referenced datasets
# were reported as "3 direct · 1 transitive" and the model carried a scope badge.
cat > "$OUT/mlroot_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"component":{"bom-ref":"root-model","type":"machine-learning-model",
   "name":"root-model","version":"1.0"}},
 "components":[
   {"bom-ref":"root-model","type":"machine-learning-model","name":"root-model","version":"1.0"},
   {"bom-ref":"ds-a","type":"data","name":"ds-a","version":"1"},
   {"bom-ref":"ds-b","type":"data","name":"ds-b","version":"1"}],
 "dependencies":[{"ref":"root-model","dependsOn":["ds-a","ds-b"]},
   {"ref":"ds-a","dependsOn":[]},{"ref":"ds-b","dependsOn":[]}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
s = server.sbom_summary("mlroot_1.0")
assert s["directCount"] == 2, ("both datasets are direct", s)
assert s["transitiveCount"] == 0, ("the root is not a transitive dep of itself", s)
rows = {r["name"]: r for r in s["componentList"]}
assert rows["ds-a"]["scope"] == "direct", rows["ds-a"]
assert "scope" not in rows["root-model"] or not rows["root-model"]["scope"], (
    "the root component carries no scope", rows["root-model"])
PY
then
    pass "the root model is excluded from the dependency scope index"
else
    fail "the root model is excluded from the dependency scope index"
fi
rm -f "$OUT"/mlroot_1.0_*

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
# Regulatory crosswalk: validate-sbom.sh joins regulation-crosswalk.json onto the
# G7 checks. conformance_summary must pass through the per-check `regulations`
# array and the top-level `regulatoryCrosswalk` rollup (dropping either hides the
# documentation-preparation view from the UI).
xw = c.get("regulatoryCrosswalk")
assert isinstance(xw, dict), ("no regulatoryCrosswalk", type(xw))
assert xw.get("disclaimer"), "crosswalk disclaimer missing"
fws = xw.get("frameworks") or []
assert len(fws) >= 1, "no crosswalk frameworks"
assert {"id", "title", "source", "total", "present", "gap", "review", "failed",
        "elements"} <= set(fws[0]), fws[0]
# The four counts have to account for every mapped requirement. They did not:
# `failed` was absent and the only consumer worked it out as a remainder, then
# labelled that remainder "advisory" — so a failure was displayed as the mildest
# category there is.
for fw in fws:
    assert fw["present"] + fw["gap"] + fw["failed"] + fw["review"] == fw["total"], fw
el = fws[0]["elements"][0]
assert {"label", "status", "source", "refs"} <= set(el), el
# The per-check mapping is preserved as {framework, ref, basis}.
mapped = [x for x in g7 if x.get("regulations")]
assert len(mapped) >= 1, "no per-check regulations passed through"
reg = mapped[0]["regulations"][0]
assert {"framework", "ref", "basis"} <= set(reg), reg
# Base (non-G7) format checks carry crosswalk mappings too: the CRA/NTIA SBOM
# baselines apply to every SBOM, not just AI ones, so the plain CycloneDX checks
# pick up their references the same way a G7 element does. At least one base check
# is mapped (spec-version, name-version, …), and any that are use the same shape.
base_mapped = [x for x in base if x.get("regulations")]
assert len(base_mapped) >= 1, "base format checks should carry crosswalk mappings"
assert {"framework", "ref", "basis"} <= set(base_mapped[0]["regulations"][0]), base_mapped[0]
# The Korean label a registry declares for its element rides alongside the English
# one. The contract itself stays English (asserted elsewhere); this is what lets a
# client render the row in Korean without translating the contract.
assert all("labelKo" in x for x in checks), "labelKo not exposed"
assert any(x["labelKo"] for x in g7), "no G7 element carries its Korean label"
# The checks this pipeline writes itself carry a threshold or a spec version in
# their label, so they cannot be looked up whole. They are matched by pattern
# against the same catalog the reports use, and every check now arrives with a
# Korean label and detail. Without them a Korean reader got seventeen English
# requirement names, each followed by an English measurement, under a Korean
# heading.
assert all("detailKo" in x for x in checks), "detailKo not exposed"
assert all(x["labelKo"] for x in base), (
    "every format check carries a Korean label",
    [x["id"] for x in base if not x["labelKo"]])
assert any(x["detailKo"] for x in base), "no format check carries a Korean detail"
# Why an element could not be judged. validate-sbom.sh marks the checks with
# nothing in this document to measure (package coverage over an ML-BOM that has
# no packages) as naKind "not-applicable", and both CLI reports render them as
# N/A. Dropping the field here made the UI draw them as ordinary warnings, count
# them into the mandatory denominator (6/8 instead of 6/6) and fold them into the
# "needs a person" tally (21 instead of 14).
assert all("naKind" in x for x in checks), "naKind not exposed"
na = [x for x in checks if x["naKind"] == "not-applicable"]
assert len(na) >= 1, "an ML-BOM with no packages must mark package checks N/A"
assert all(x["source"] == "na" for x in na), ("N/A rows carry source na", na[0])
cisa = [x for x in checks if x["id"].startswith("cisa-")]
assert len(cisa) >= 20, ("the 2026 minimum elements should be measured too", len(cisa))
assert any(x["labelKo"] for x in cisa), "no CISA element carries its Korean label"
# What a person has to establish, for the elements no scan can settle and for the
# one checkable in a form this report cannot see (a detached signature). The .md
# and .html reports have carried these all along; the UI could not see them.
guided = [x for x in checks if x.get("reviewGuide")]
assert len(guided) >= 1, "reviewGuide not exposed"
assert {"how", "howKo", "docUrl"} <= set(guided[0]["reviewGuide"]), guided[0]
assert any(x["id"] == "cisa-sbom-author-signature" for x in guided), (
    "the detached-signature note is the one a reader most needs")
PY
    then
        pass "conformance_summary exposes the full G7 checklist with cluster/source/crosswalk"
    else
        fail "conformance checks exposure / G7 split / crosswalk is wrong"
    fi
    rm -f "$OUT"/conf_1.0_*
else
    echo "  SKIP: jq not available for conformance generation"
fi

echo "== conformance_summary passes through pipelineStepsFailed =="
# validate-sbom.sh already dedupes/orders/caps this off the SBOM's own
# bomlens:pipeline-step-failed properties; conformance_summary must pass it
# through, and default to []/0 for a report generated before this field
# existed (an old _conformance.json on disk, or one hand-crafted without it),
# rather than surfacing a missing key as null and breaking the frontend type.
if command -v jq >/dev/null 2>&1; then
    jq '.metadata.properties = [
      {"name":"bomlens:pipeline-step-failed","value":"normalize"},
      {"name":"bomlens:pipeline-step-failed","value":"enrich-cpe"},
      {"name":"bomlens:pipeline-step-failed","value":"normalize"}
    ]' "$ROOT_DIR/tests/fixtures/good-cyclonedx.json" > "$OUT/psfweb_1.0_bom.json"
    PROJECT=psfweb GEN_AT=2026-01-01 bash "$ROOT_DIR/docker/lib/validate-sbom.sh" \
        "$OUT/psfweb_1.0_bom.json" "$OUT/psfweb_1.0" >/dev/null 2>&1
    if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
c = server.conformance_summary("psfweb_1.0")
assert c is not None, "no conformance summary"
assert c.get("pipelineStepsFailed") == ["normalize", "enrich-cpe"], (
    "pipelineStepsFailed not passed through / not deduped", c.get("pipelineStepsFailed"))
assert c.get("pipelineStepsFailedMore") == 0, c.get("pipelineStepsFailedMore")
PY
    then
        pass "conformance_summary passes through pipelineStepsFailed, deduped"
    else
        fail "conformance_summary did not pass through pipelineStepsFailed"
    fi
    rm -f "$OUT"/psfweb_1.0_*

    # An old report predates the field entirely -- absence, not null or a crash.
    PROJECT=psfold GEN_AT=2026-01-01 bash "$ROOT_DIR/docker/lib/validate-sbom.sh" \
        "$ROOT_DIR/tests/fixtures/good-cyclonedx.json" "$OUT/psfold_1.0" >/dev/null 2>&1
    jq 'del(.pipelineStepsFailed, .pipelineStepsFailedMore)' \
        "$OUT/psfold_1.0_conformance.json" > "$OUT/psfold_1.0_conformance.json.tmp" \
        && mv "$OUT/psfold_1.0_conformance.json.tmp" "$OUT/psfold_1.0_conformance.json"
    if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
c = server.conformance_summary("psfold_1.0")
assert c is not None, "no conformance summary"
assert c.get("pipelineStepsFailed") == [], ("an old report must default to []", c.get("pipelineStepsFailed"))
assert c.get("pipelineStepsFailedMore") == 0, ("an old report must default to 0", c.get("pipelineStepsFailedMore"))
PY
    then
        pass "an old report with no pipelineStepsFailed key defaults to [] and 0"
    else
        fail "an old report without pipelineStepsFailed was not defaulted safely"
    fi
    rm -f "$OUT"/psfold_1.0_*
else
    echo "  SKIP: jq not available for conformance generation"
fi

echo "== ai profile summary (ai_profile_summary) =="
# generate-ai-profile.sh re-aggregates the conformance + SBOM artifacts into a
# governance card. ai_profile_summary must return the light rollup for an AI SBOM
# and None when no profile exists (non-AI scan).
if command -v jq >/dev/null 2>&1; then
    PROJECT=aip GEN_AT=2026-01-01 bash "$ROOT_DIR/docker/lib/validate-sbom.sh" \
        "$ROOT_DIR/tests/fixtures/aibom-owasp-1_7.json" "$OUT/aip_1.0" >/dev/null 2>&1
    # A matching _bom.json carrying one behavioral-use license flag (test-aibom.sh
    # pattern) so licenseReview is non-empty, plus the bomlens:assessment:* verdict
    # assess-ai-risk.sh would stamp so riskAssessment is populated.
    jq '.components[0].properties = ((.components[0].properties // []) + [
          {name:"bomlens:licenseReview",value:"behavioral-use"},
          {name:"bomlens:assessment:overall",value:"conditional"},
          {name:"bomlens:assessment:axes",value:"license"},
          {name:"bomlens:assessment:license",value:"conditional"},
          {name:"bomlens:assessment:license:keys",value:"llama-community"},
          {name:"bomlens:assessment:reasons",value:"Llama community license"}])' \
        "$ROOT_DIR/tests/fixtures/aibom-owasp-1_7.json" > "$OUT/aip_1.0_bom.json"
    bash "$ROOT_DIR/docker/lib/generate-ai-profile.sh" "$OUT/aip_1.0" "aip" >/dev/null 2>&1
    if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
p = server.ai_profile_summary("aip_1.0")
assert p is not None, "no ai profile summary"
assert p["conformanceResult"] in ("pass", "warn", "fail", "unknown"), p["conformanceResult"]
g7 = p["g7"]
assert {"total", "auto", "present", "gap", "review", "clusters"} <= set(g7), g7
assert g7["total"] >= 40, ("expected full G7 checklist", g7["total"])
assert len(g7["clusters"]) >= 7, "clusters not summarized"
assert {"cluster", "total", "present", "gap", "review"} <= set(g7["clusters"][0]), g7["clusters"][0]
# Light payload: the big arrays are dropped from the card summary.
assert "reviewItems" not in g7, "reviewItems must be dropped from the card summary"
lic = p["licenseReview"]
assert lic["total"] >= 1 and lic["behavioral"] >= 1, lic
assert "items" not in lic, "licenseReview.items must be dropped from the card summary"
xw = p["regulatoryCrosswalk"]
assert xw["disclaimer"], "crosswalk disclaimer missing"
assert len(xw["frameworks"]) >= 1, "no crosswalk frameworks in profile"
assert {"id", "title", "total", "present", "gap", "review"} <= set(xw["frameworks"][0]), xw["frameworks"][0]
assert "elements" not in xw["frameworks"][0], "crosswalk elements must be dropped from the card summary"
# Model risk assessment (assess-ai-risk.sh verdicts re-aggregated by
# generate-ai-profile.sh): counts + per-model verdicts with the registry's
# joined summary/conditions and the always-riding disclaimer must pass through.
ra = p.get("riskAssessment")
assert isinstance(ra, dict), "riskAssessment dropped from the profile card"
assert ra["counts"] == {"ok": 0, "conditional": 1, "caution": 0, "review": 0}, ra["counts"]
assert ra["disclaimer"], "risk assessment disclaimer missing"
assert len(ra["models"]) == 1, ra["models"]
m0 = ra["models"][0]
assert m0["overall"] == "conditional", m0
assert m0["axes"].get("license") == "conditional" and "security" not in m0["axes"], m0["axes"]
assert m0["reasons"] == ["Llama community license"], m0["reasons"]
assert m0["summary"], "registry summary not joined onto the model verdict"
assert all({"id", "label", "label_ko"} <= set(c) for c in m0["conditions"]), m0["conditions"]
# Non-AI scan (no profile artifact) -> None.
assert server.ai_profile_summary("nope_9.9") is None, "expected None without a profile"
PY
    then
        pass "ai_profile_summary returns the light G7/license/crosswalk rollup, None without a profile"
    else
        fail "ai_profile_summary is wrong"
    fi
    rm -f "$OUT"/aip_1.0_*
else
    echo "  SKIP: jq not available for ai-profile generation"
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

echo "== AI model risk verdict surfaced + counted (sbom_summary) =="
# assess-ai-risk.sh stamps bomlens:assessment:* (and enrich-aibom.sh the
# bomlens:hf:scan:* / bomlens:weights:*) on machine-learning-model and data
# components. sbom_summary must surface them per-row (assessment/assessmentAxes/
# assessmentReasons/hfScanStatus/weightFormats), only for those AI types, and
# aggregate assessCounts over the MODEL verdicts (datasets excluded). A scan
# with no assessed model must omit the assessCounts key entirely.
cat > "$OUT/aimr_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX",
 "components":[
   {"name":"llama-model","version":"3.1","type":"machine-learning-model","purl":"pkg:huggingface/meta/llama@3.1",
    "properties":[{"name":"bomlens:assessment:overall","value":"caution"},
                  {"name":"bomlens:assessment:axes","value":"license,security,datasets"},
                  {"name":"bomlens:assessment:reasons","value":"Llama community license; pickle weights present"},
                  {"name":"bomlens:hf:scan:status","value":"suspicious"},
                  {"name":"bomlens:weights:formats","value":"bin,safetensors"}]},
   {"name":"clean-model","version":"1.0","type":"machine-learning-model",
    "properties":[{"name":"bomlens:assessment:overall","value":"ok"},
                  {"name":"bomlens:assessment:axes","value":"license,security"}]},
   {"name":"nc-dataset","version":"1.0","type":"data",
    "properties":[{"name":"bomlens:assessment:overall","value":"review"},
                  {"name":"bomlens:assessment:axes","value":"license,signals"}]},
   {"name":"plain-lib","version":"2.0","type":"library",
    "properties":[{"name":"bomlens:assessment:overall","value":"review"}]},
   {"name":"bare-model","version":"0.1","type":"machine-learning-model"}
 ]}
JSON
cat > "$OUT/aimrnone_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX",
 "components":[
   {"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"},
   {"name":"bare-model","version":"0.1","type":"machine-learning-model"}
 ]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
s = server.sbom_summary("aimr_1.0")
rows = {r["name"]: r for r in s["componentList"]}
m = rows["llama-model"]
assert m["assessment"] == "caution", m
assert m["assessmentAxes"] == "license,security,datasets", m
assert m["assessmentReasons"] == "Llama community license; pickle weights present", m
assert m["hfScanStatus"] == "suspicious", m
assert m["weightFormats"] == "bin,safetensors", m
assert rows["clean-model"]["assessment"] == "ok", rows["clean-model"]
assert "hfScanStatus" not in rows["clean-model"], rows["clean-model"]   # no property -> absent
assert rows["nc-dataset"]["assessment"] == "review", rows["nc-dataset"]
assert "assessment" not in rows["plain-lib"], rows["plain-lib"]  # type-gated: never on a library
assert "assessment" not in rows["bare-model"], rows["bare-model"]  # unassessed -> absent
# KPI: models only (the caution llama + the ok clean-model); the review dataset
# and the review-stamped library must NOT count.
assert s["assessCounts"] == {"ok": 1, "conditional": 0, "caution": 1, "review": 0}, s
# No assessed model (bare model / plain libraries) -> the key is omitted entirely.
assert "assessCounts" not in server.sbom_summary("aimrnone_1.0"), \
    server.sbom_summary("aimrnone_1.0")
PY
then
    pass "assessment surfaced per-row (AI types only) + assessCounts over model verdicts"
else
    fail "AI model risk verdict summary is wrong (see assertion above)"
fi
rm -f "$OUT"/aimr_1.0_* "$OUT"/aimrnone_1.0_*

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

echo "== pipeline-step-failed property (sbom_summary) =="
# mark_pipeline_warning (docker/lib/pipeline-step.sh) appends one
# bomlens:pipeline-step-failed property per failed best-effort step, so the
# same name can repeat; sbom_summary must collect all of them, not just the
# first. A document with none must surface an empty list, not a missing key.
cat > "$OUT/pipefail_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"pipefail","version":"1.0"},"properties":[{"name":"bomlens:pipeline-step-failed","value":"enrich-cpe"},{"name":"bomlens:pipeline-step-failed","value":"generate-notice"}]},"components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
cat > "$OUT/pipeok_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"pipeok","version":"1.0"}},"components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
assert server.sbom_summary("pipefail_1.0")["pipelineStepsFailed"] == ["enrich-cpe", "generate-notice"]
assert server.sbom_summary("pipeok_1.0")["pipelineStepsFailed"] == []
PY
then
    pass "pipelineStepsFailed collects every occurrence (empty list when none)"
else
    fail "pipelineStepsFailed not surfaced correctly"
fi
rm -f "$OUT"/pipefail_1.0_* "$OUT"/pipeok_1.0_*

echo "== pipeline-step-failed: dedup, per-id cap, and list cap (untrusted input) =="
# On an --analyze run this property comes from a supplier's document, so it is
# untrusted: mark_pipeline_warning can record the same step twice (a
# re-analyzed document), a step id could be arbitrarily long, and there is no
# limit on how many distinct ids a document could carry. sbom_summary must
# dedupe (order preserved), cap one id's length, and cap the list length while
# counting the rest.
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os, json
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

out_dir = os.environ["SBOM_OUTPUT_DIR"]
long_value = "x" * 300
props = (
    [{"name": "bomlens:pipeline-step-failed", "value": "enrich-cpe"}] * 2
    + [{"name": "bomlens:pipeline-step-failed", "value": long_value}]
    + [{"name": "bomlens:pipeline-step-failed", "value": f"step-{i}"} for i in range(25)]
)
with open(os.path.join(out_dir, "pipebig_1.0_bom.json"), "w") as f:
    json.dump(
        {
            "bomFormat": "CycloneDX",
            "metadata": {"component": {"name": "pipebig", "version": "1.0"}, "properties": props},
            "components": [{"name": "flask", "version": "2.0", "type": "library", "purl": "pkg:pypi/flask@2.0"}],
        },
        f,
    )

summary = server.sbom_summary("pipebig_1.0")
steps = summary["pipelineStepsFailed"]
# 27 distinct values in (enrich-cpe once deduped + the long one + 25 step-N),
# capped to 20; the other 7 are counted, not shown.
assert steps.count("enrich-cpe") == 1, steps
assert len(steps) == 20, steps
assert summary["pipelineStepsFailedMore"] == 7, summary["pipelineStepsFailedMore"]
assert len(steps[1]) == 100, len(steps[1])
PY
then
    pass "pipelineStepsFailed dedupes, caps id length at 100 and the list at 20"
else
    fail "pipelineStepsFailed untrusted-input handling is wrong (see assertion above)"
fi
rm -f "$OUT"/pipebig_1.0_*

echo "== sbom-oversized property (sbom_summary) =="
# When entrypoint.sh's size-cap check stamps bomlens:sbom-oversized, the
# summary must surface it too; absent -> None.
cat > "$OUT/big_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"big","version":"1.0"},"properties":[{"name":"bomlens:sbom-oversized","value":"104857601 bytes"}]},"components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
cat > "$OUT/small_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"small","version":"1.0"}},"components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
assert server.sbom_summary("big_1.0")["sbomOversizedBytes"] == "104857601 bytes"
assert server.sbom_summary("small_1.0")["sbomOversizedBytes"] is None
PY
then
    pass "sbomOversizedBytes surfaced from metadata (None when absent)"
else
    fail "sbomOversizedBytes not surfaced correctly"
fi
rm -f "$OUT"/big_1.0_* "$OUT"/small_1.0_*

echo "== stale upload sweep: TTL-expired uploads are removed, active/young ones are not =="
UPDIR="$OUT/.uploads"
mkdir -p "$UPDIR"
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os, time
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

old_token = "a" * 32
active_token = "b" * 32
young_token = "c" * 32
junk_name = "not-a-token-dir"

for name in (old_token, active_token, young_token, junk_name):
    d = os.path.join(server.UPLOAD_DIR, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "f"), "w") as f:
        f.write("x")

now = time.time()
old_mtime = now - server.UPLOAD_TTL_SECONDS - 3600
young_mtime = now - 60
for name in (old_token, active_token, junk_name):
    os.utime(os.path.join(server.UPLOAD_DIR, name), (old_mtime, old_mtime))
os.utime(os.path.join(server.UPLOAD_DIR, young_token), (young_mtime, young_mtime))

server._active_upload_tokens.add(active_token)
server._sweep_stale_uploads(now=now)

assert not os.path.isdir(os.path.join(server.UPLOAD_DIR, old_token)), \
    "expired inactive upload was not swept"
assert os.path.isdir(os.path.join(server.UPLOAD_DIR, active_token)), \
    "active upload was wrongly swept despite being expired"
assert os.path.isdir(os.path.join(server.UPLOAD_DIR, young_token)), \
    "young upload was wrongly swept"
assert os.path.isdir(os.path.join(server.UPLOAD_DIR, junk_name)), \
    "an unrecognized directory name was wrongly swept"

# Throttling: a sweep call inside the throttle window must be a no-op, even
# with a fresh TTL-expired entry sitting there ready to be removed.
new_stale = "d" * 32
d = os.path.join(server.UPLOAD_DIR, new_stale)
os.makedirs(d, exist_ok=True)
stale_mtime = now - server.UPLOAD_TTL_SECONDS - 3600
os.utime(d, (stale_mtime, stale_mtime))
server._sweep_stale_uploads(now=now + 1)
assert os.path.isdir(d), "sweep ran again inside its throttle window"
server._sweep_stale_uploads(now=now + server._UPLOAD_SWEEP_INTERVAL_SECONDS + 1)
assert not os.path.isdir(d), "sweep did not run again once the throttle window elapsed"

# Boundary shapes for _UPLOAD_ENTRY_RE, past the throttle window above: a
# git-clone scratch dir IS swept (same rules as an upload token); a too-short
# hex string, an uppercase one, and a name carrying a trailing newline are all
# left alone -- the last one is the regression check for match()+"$" silently
# accepting "token\n" that fullmatch() closes.
later = now + 3 * server._UPLOAD_SWEEP_INTERVAL_SECONDS
git_token = "git-" + "e" * 16
short_hex = "a" * 31
upper_hex = "A" * 32
newline_name = "a" * 32 + "\n"
newline_created = False
for name in (git_token, short_hex, upper_hex, newline_name):
    try:
        entry = os.path.join(server.UPLOAD_DIR, name)
        os.makedirs(entry, exist_ok=True)
        os.utime(entry, (stale_mtime, stale_mtime))
        if name == newline_name:
            newline_created = True
    except OSError:
        pass  # newline_name may not be creatable on every filesystem
server._sweep_stale_uploads(now=later)
assert not os.path.isdir(os.path.join(server.UPLOAD_DIR, git_token)), \
    "an expired git-clone scratch dir was not swept"
assert os.path.isdir(os.path.join(server.UPLOAD_DIR, short_hex)), \
    "a too-short hex name was wrongly swept"
assert os.path.isdir(os.path.join(server.UPLOAD_DIR, upper_hex)), \
    "an uppercase-hex name was wrongly swept (regex is lowercase-only)"
if newline_created:
    assert os.path.isdir(os.path.join(server.UPLOAD_DIR, newline_name)), \
        "a name with a trailing newline was wrongly swept (match()+'$' vs fullmatch() regression)"
else:
    raise AssertionError("test setup: could not create a directory with a trailing newline "
                          "in its name on this filesystem -- the fullmatch() regression check "
                          "above did not run; investigate rather than silently skip")
PY
then
    pass "stale upload sweep: TTL-expired+inactive removed, active/young/unrecognized kept, throttled"
else
    fail "stale upload sweep behaved incorrectly"
fi
rm -rf "$UPDIR"

echo "== /scans caching: unchanged BOM reuses the cached row, changed BOM recomputes =="
cat > "$OUT/cache1_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"cache1","version":"1.0"}},"components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os, json
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

bom_path = os.path.join(server.OUTPUT_DIR, "cache1_1.0_bom.json")

scans1 = server.list_scans()
row1 = next((s for s in scans1 if s["id"] == "cache1_1.0"), None)
assert row1 is not None, "scan not listed on first call"
assert row1["components"] == 1, "first parse: wrong component count (%r)" % (row1,)

# Preserve mtime AND size, then corrupt the JSON (the cache key is (mtime_ns,
# size), not mtime alone, so the replacement must match the original's byte
# length or this would just be exercising cache invalidation, not a hit). A
# correct cache must return the cached row without re-reading this file: if
# it tried, the entry would silently vanish (add_scan swallows JSONDecodeError).
st = os.stat(bom_path)
mtime_ns = st.st_mtime_ns
corrupt = ("not json " * 30)[: st.st_size].ljust(st.st_size, "x")
with open(bom_path, "w") as f:
    f.write(corrupt)
assert os.path.getsize(bom_path) == st.st_size, "test setup: corrupted content changed size"
# ns=, not the float-seconds form: st_mtime (float) loses the sub-second
# precision st_mtime_ns has, so round-tripping through it would silently
# produce a DIFFERENT nanosecond value than the original -- exactly the kind
# of drift the server's cache key (st_mtime_ns, size) is deliberately precise
# enough to no longer treat as "unchanged".
os.utime(bom_path, ns=(mtime_ns, mtime_ns))

scans2 = server.list_scans()
row2 = next((s for s in scans2 if s["id"] == "cache1_1.0"), None)
assert row2 is not None, "cached row vanished after the file was corrupted at the same (mtime, size)"
assert row2 == row1, "cached row content changed even though (mtime, size) did not"

# Now really change the file and bump its mtime: the cache must invalidate.
with open(bom_path, "w") as f:
    json.dump({
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": "cache1", "version": "1.0"}},
        "components": [
            {"name": "flask", "version": "2.0", "type": "library", "purl": "pkg:pypi/flask@2.0"},
            {"name": "lodash", "version": "4.0", "type": "library", "purl": "pkg:npm/lodash@4.0"},
        ],
    }, f)
os.utime(bom_path, ns=(mtime_ns + 5_000_000_000, mtime_ns + 5_000_000_000))

scans3 = server.list_scans()
row3 = next((s for s in scans3 if s["id"] == "cache1_1.0"), None)
assert row3 is not None, "scan missing after a real content change"
assert row3["components"] == 2, "cache did not invalidate after the mtime changed (%r)" % (row3,)
PY
then
    pass "/scans row cache: reused when unchanged, invalidated on a real mtime-bearing change"
else
    fail "/scans row caching behaved incorrectly"
fi
rm -f "$OUT/cache1_1.0_bom.json"

echo "== /scans caching: a Trivy report written after the BOM is still picked up =="
# A scan in progress is listed here too (list_scans walks the whole OUTPUT_DIR,
# not just finished runs), and Trivy finishes after the BOM's own enrichment
# steps are done writing to it. A request landing in that exact gap must not
# freeze maxSeverity at null forever once security_summary has something to say.
mkdir -p "$OUT/secrace_1.0"
cat > "$OUT/secrace_1.0/secrace_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"secrace","version":"1.0"}},"components":[{"name":"flask","version":"2.0","type":"library","purl":"pkg:pypi/flask@2.0"}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os, json
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

scans1 = server.list_scans()
row1 = next((s for s in scans1 if s["id"] == "secrace_1.0"), None)
assert row1 is not None, "scan not listed before its security report exists"
assert row1["maxSeverity"] is None, "maxSeverity should be null with no security report yet (%r)" % (row1,)

# Write the security report. This does not touch the BOM at all (no reason
# to: writing a sibling file has no bearing on the BOM's own mtime) -- which
# is exactly the real ordering this test exists to cover: Trivy runs and
# writes _security.json after the BOM's enrichment steps already finished.
# If sec_sig were missing from the cache key, only bom_sig would still be
# unchanged here, so this file's absence from the key is what this test
# actually exercises -- do not re-touch bom_path's mtime as a "safety" step,
# that would silently change bom_sig instead and make the test pass for the
# wrong reason.
sec = {"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL", "VulnerabilityID": "CVE-2024-0001"}]}]}
with open(os.path.join(server.OUTPUT_DIR, "secrace_1.0", "secrace_1.0_security.json"), "w") as f:
    json.dump(sec, f)

scans2 = server.list_scans()
row2 = next((s for s in scans2 if s["id"] == "secrace_1.0"), None)
assert row2 is not None, "scan missing after its security report was written"
assert row2["maxSeverity"] == "CRITICAL", \
    "cache did not pick up the security report written after the BOM (%r)" % (row2,)
PY
then
    pass "/scans row cache: a security report written after the BOM is picked up, not stuck at the pre-Trivy row"
else
    fail "/scans row cache missed a security report written after the BOM"
fi
rm -rf "$OUT/secrace_1.0"

echo "== /scans caching: legacy flat and run-subfolder layouts sharing an id do not clobber each other =="
# list_scans() lists a legacy flat OUTPUT_DIR/foo_1.0_bom.json AND a run
# subfolder OUTPUT_DIR/foo_1.0/foo_1.0_bom.json under the SAME id "foo_1.0" if
# both exist (a pre-upgrade scan plus a fresh re-scan of the same
# project/version). A cache keyed by run_id alone would let one call's
# add_scan() overwrite the other's cache slot, so the wrong row is served.
cat > "$OUT/dup_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"dup-flat","version":"1.0"}},"components":[{"name":"a","version":"1","type":"library","purl":"pkg:pypi/a@1"}]}
JSON
mkdir -p "$OUT/dup_1.0"
cat > "$OUT/dup_1.0/dup_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"dup-folder","version":"1.0"}},"components":[{"name":"a","version":"1","type":"library","purl":"pkg:pypi/a@1"},{"name":"b","version":"1","type":"library","purl":"pkg:pypi/b@1"}]}
JSON
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

for _ in range(2):  # twice: once cold, once with both cache slots populated
    rows = [s for s in server.list_scans() if s["id"] == "dup_1.0"]
    assert len(rows) == 2, "expected both the flat and the subfolder row, got %r" % (rows,)
    projects = sorted(r["project"] for r in rows)
    assert projects == ["dup-flat", "dup-folder"], \
        "one layout's row was replaced by the other's (%r)" % (rows,)
    counts = sorted(r["components"] for r in rows)
    assert counts == [1, 2], "component counts got mixed up between the two rows (%r)" % (rows,)
PY
then
    pass "/scans: flat-layout and subfolder-layout rows for the same id stay distinct across repeated calls"
else
    fail "flat and subfolder layouts sharing an id clobbered each other's cached row"
fi
rm -f "$OUT/dup_1.0_bom.json"
rm -rf "$OUT/dup_1.0"

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
# Opt-in SPDX export: an allowlisted artifact that must surface in list_results.
cat > "$OUT/cfg_2.0/cfg_2.0_bom.spdx.json" <<'JSON'
{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"cfg",
 "packages":[{"SPDXID":"SPDXRef-Package-flask","name":"flask","versionInfo":"2.0"}]}
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
    # What the Overview prints as the scan's provenance when `target` cannot say
    # it (an uploaded filename, a scanned folder). Part of the sidecar contract:
    # scan-sbom.sh writes the same key for CLI runs.
    "sourceLabel": "",
    "project": "cfg",
    "version": "2.0",
    "notice": True,
    "security": True,
    "spdx": True,
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
expected_keys = {"source", "target", "sourceLabel", "project", "version",
                 "notice", "security", "spdx", "deepLicense", "identifyVendored",
                 "includeOsv", "byteStable"}
assert set(got) == expected_keys, set(got)
# No secret material is ever stored.
assert not any(k in got for k in ("token", "cred", "scanoss_cred", "gitToken",
                                  "SCANOSS_API_KEY")), got

# The sidecar is excluded from the artifact listing and the download bundle.
names = [r["name"] for r in server.list_results("cfg_2.0")]
assert server.SCANMETA_NAME not in names, names
assert "cfg_2.0_bom.json" in names, names
# The SPDX export is an allowlisted artifact suffix, so it is listed/downloadable.
assert "cfg_2.0_bom.spdx.json" in names, names

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
# An AI SBOM names the model as the document's own component and lists only its
# datasets under components[]. The list must recognise it as an AI scan and
# count the model, or the same scan reads as a plain SBOM of 1 component here
# and as a model of 2 on its own page.
cat > "$OUT/aimodel_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":
  {"name":"bert-base-uncased","version":"86b5e093","type":"machine-learning-model"}},
 "components":[{"name":"bookcorpus","version":"d917559b","type":"data"}]}
JSON
scans=$(curl -fsS "$BASE/scans" 2>/dev/null)
detail=$(curl -fsS "$BASE/scan?id=aimodel_1.0" 2>/dev/null)
if echo "$scans" | SCAN_DETAIL="$detail" python3 -c "
import os, sys, json
s = next(x for x in json.load(sys.stdin) if x['id'] == 'aimodel_1.0')
assert s['isAiScan'] is True, s
assert s['componentType'] == 'machine-learning-model', s
assert s['project'] == 'bert-base-uncased' and s['version'] == '86b5e093', s
assert s['components'] == json.loads(os.environ['SCAN_DETAIL'])['sbom']['components'], s
"; then
    pass "/scans reports a root-component AI model as an AI scan, counted as /scan does"
else
    fail "/scans mislabelled an AI SBOM whose model is the root component" "$scans"
fi
curl -fsS -X POST "$BASE/scan-delete?id=aimodel_1.0" >/dev/null 2>&1
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

echo "== Host/Origin: a DNS-rebound or cross-site browser request is rejected =="
# Loopback binding alone does not stop DNS rebinding — a page at a domain that
# resolves to 127.0.0.1 still reaches this port, with the browser sending that
# domain as Host. Host is checked on every request; Origin additionally covers
# a classic cross-site POST, where Host is correctly this server but Origin
# names the page that issued the request.
h_code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: evil.example" "$BASE/capabilities")
[ "$h_code" = "403" ] && pass "a forged Host header is rejected (403)" || fail "forged Host returned $h_code (expected 403)"

cat > "$OUT/hostcheck_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}
JSON
o_code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Origin: http://evil.example" "$BASE/scan-delete?id=hostcheck_1.0")
[ "$o_code" = "403" ] && pass "a cross-site Origin on /scan-delete is rejected (403)" || fail "cross-site Origin returned $o_code (expected 403)"
[ -f "$OUT/hostcheck_1.0_bom.json" ] && pass "the rejected /scan-delete did not actually delete anything" || fail "scan-delete ran despite the rejected Origin"

del_ok=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/scan-delete?id=hostcheck_1.0")
[ "$del_ok" = "200" ] && pass "the same request with no Origin (an ordinary browser/curl call) still succeeds" || fail "legitimate scan-delete (no Origin) returned $del_ok (expected 200)"

es_code=$(curl -s -o /dev/null -w '%{http_code}' -N -H "Origin: http://evil.example" "$BASE/scan-stream?project=hostcheck2&version=1.0&source=current-dir")
[ "$es_code" = "403" ] && pass "a cross-site Origin on /scan-stream is rejected (403) before any scan starts" || fail "cross-site Origin on /scan-stream returned $es_code (expected 403)"
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
# Regression: _yocto_vex.json was missing from ARTIFACT_SUFFIXES, so a real
# deliverable (entrypoint.sh's own ARTIFACTS array already treats it as one)
# was invisible in /scan, undeletable via /scan-delete, and absent from
# /download-all's bundle.
cat > "$OUT/demo_1.0/demo_1.0_yocto_vex.json" <<'JSON'
{"judgements":{"fixed":3,"notAffected":1,"affected":0},"unresolved":2}
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
# The listing carries the input the scan ran with, from the run-folder sidecar.
# Without it an analyzed supplier SBOM is indistinguishable from a source scan:
# both declare "application" as the root component type, so the UI called the
# submitted SBOM a Source scan.
cat > "$OUT/demo_1.0/.scanmeta.json" <<'JSON'
{"source":"sbom-upload","sourceLabel":"vendor.cdx.json","project":"demo","version":"1.0"}
JSON
scans=$(curl -fsS "$BASE/scans" 2>/dev/null)
if echo "$scans" | python3 -c "
import sys, json
d = json.load(sys.stdin)
s = next(x for x in d if x['id'] == 'demo_1.0')
assert s['inputSource'] == 'sbom-upload', s
# A run with no sidecar reports null rather than guessing.
t = next(x for x in d if x['id'] == 'demo_1.0_20260101-120000')
assert t['inputSource'] is None, t
"; then
    pass "/scans reports the saved input source (null when there is no sidecar)"
else
    fail "/scans did not report inputSource" "$scans"
fi
rm -f "$OUT/demo_1.0/.scanmeta.json"
# /scan?id=<run_id> re-opens the scan from its folder.
if curl -fsS "$BASE/scan?id=demo_1.0" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['ok'] is True and d['id'] == 'demo_1.0', d
assert d['sbom']['components'] == 2 and d['security']['TOTAL'] == 1, d
names = [r['name'] for r in d['results']]
assert 'demo_1.0_security_epss.json' in names, names
assert 'demo_1.0_yocto_vex.json' in names, names
assert d['yoctoVex'] == {'fixed': 3, 'notAffected': 1, 'affected': 0, 'unresolved': 2}, d['yoctoVex']
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
assert {'demo_1.0_bom.json','demo_1.0_security.json','demo_1.0_security_epss.json','demo_1.0_yocto_vex.json'} <= names, names
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
# Same _yocto_vex.json regression as the subfolder fixture above, but here the
# flat-layout delete path matters: it iterates ARTIFACT_SUFFIXES to remove each
# {prefix}_* file individually (no whole-folder rmtree), so a missing suffix
# leaves this exact kind of file orphaned on disk.
cat > "$OUT/legacy_1.0_yocto_vex.json" <<'JSON'
{"judgements":{"fixed":1,"notAffected":0,"affected":0},"unresolved":0}
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
assert {'legacy_1.0_bom.json','legacy_1.0_security.json','legacy_1.0_yocto_vex.json'} <= names, names
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
if [ ! -f "$OUT/legacy_1.0_bom.json" ] && [ ! -f "$OUT/legacy_1.0_yocto_vex.json" ]; then
    pass "/scan-delete left no legacy flat artifact behind (incl. yocto_vex)"
else
    fail "legacy flat artifacts still present after delete" "$(ls "$OUT"/legacy_1.0_* 2>/dev/null)"
fi

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
  echo "TRUSCA_PROJECT_ID=${TRUSCA_PROJECT_ID:-}"
  echo "AI_USAGE_CONTEXT=${AI_USAGE_CONTEXT:-}"
  echo "CONFORMANCE_PROFILE=${CONFORMANCE_PROFILE:-}"
  echo "PROJECT_LICENSE=${PROJECT_LICENSE:-}"
  echo "SBOM_AUTHOR=${SBOM_AUTHOR:-}"
  echo "REPORT_LANG=${REPORT_LANG:-}"
  echo "MODE=${MODE:-}"
  echo "TARGET_FILE=${TARGET_FILE:-}"
  echo "TARGET_DIR=${TARGET_DIR:-}"
  echo "ANALYZE_SBOM=${ANALYZE_SBOM:-}"
  echo "YOCTO_BUILD_DIR=${YOCTO_BUILD_DIR:-}"
  # Counted here, while the scan is running: an extracted upload tree is removed
  # once the scan finishes, so a later check would always find it empty.
  echo "TARGET_DIR_FILES=$([ -n "${TARGET_DIR:-}" ] && find "$TARGET_DIR" -type f 2>/dev/null | wc -l | tr -d ' ' || echo 0)"; } > "${STUB_ENV_FILE:-/dev/null}"
write_bom() {
    printf '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"a","version":"1"},{"type":"library","name":"b","version":"2"}]}' \
        > "${PROJECT_NAME}_${PROJECT_VERSION}_bom.json"
}
case "$mode" in
    ok) write_bom; echo "[stub] done" ;;
    progress) echo "[firmware-cvedb-progress] 42%"; write_bom ;;
    deepcve-progress) echo "[deep-cve-progress] 55%"; write_bom ;;
    fail) echo "[stub] scanner exploded" >&2; exit 1 ;;
    # Mirrors #109's Node fallback quality gate: an [ERROR] block explaining
    # what happened, then a separate one-line [ERROR] right before exit. Both
    # must reach the failed-scan card, not just the last ("see above") line.
    error-block)
        echo "[ERROR] The dependency resolver failed and the fallback scan found none of the project's declared dependencies."
        echo "        Commit a lockfile that matches package.json, or run 'npm install' once so a resolvable lockfile is present, then re-scan."
        echo "[ERROR] fallback SBOM discarded (see above)."
        exit 1
        ;;
    # The real merged text of #109's apply_node_fallback_quality_gate
    # (docker/lib/source-detect.sh), verbatim -- this is what actually reaches
    # a web UI scan's log today, not a stand-in.
    error-block-real)
        echo "[ERROR] The dependency resolver failed and the fallback scan found none of the project's declared dependencies (direct-deps-only manifest reading), so the result would misrepresent the scan as covering the dependency tree when it covers none of it."
        echo "        Commit a lockfile (package-lock.json, npm-shrinkwrap.json, yarn.lock or pnpm-lock.yaml) that matches package.json if one is missing, or run 'npm install'/'pnpm install' once so a resolvable lockfile is present, then re-scan."
        echo "        Or scan from an environment where cdxgen itself can run (Docker access for the web UI's source scan; a working docker.sock for the CLI's transitive resolution) instead of relying on this direct-deps-only fallback."
        exit 1
        ;;
    # A raw upstream HTTP response body (as the TRUSCA/Dependency-Track upload
    # failure paths print) must never reach the card, indented or not.
    error-response-leak)
        echo "[ERROR] TRUSCA ingest failed (HTTP 500)"
        echo "Response: {\"secret\": \"do-not-leak-me\"}"
        exit 1
        ;;
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

# A Yocto build directory, offered to the stub server as a picked scan target.
# Pointing the directory input at one must analyze the image SBOM the build
# published instead of scanning the build tree — the same decision the CLI makes
# (scripts/scan-sbom.sh), which is why the detection lives in both.
YOCTOROOT="$WORK/poky-build"
mkdir -p "$YOCTOROOT/conf" "$YOCTOROOT/tmp/deploy/images/qemux86-64"
echo 'BBLAYERS = "x"' > "$YOCTOROOT/conf/bblayers.conf"
printf '%s' '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[{"type":"Tool","name":"bitbake"}]}' \
    > "$YOCTOROOT/tmp/deploy/images/qemux86-64/core-image-minimal.rootfs.spdx.json"
# A second picked folder that is NOT a Yocto build, to prove an ordinary
# directory scan still goes to ROOTFS.
PLAINROOT="$WORK/plainroot"; mkdir -p "$PLAINROOT/etc"; echo 'ID=debian' > "$PLAINROOT/etc/os-release"

SRV2_PID=""
cleanup2() { [ -n "$SRV2_PID" ] && kill "$SRV2_PID" 2>/dev/null; }
trap 'cleanup2; cleanup' EXIT
SBOM_OUTPUT_DIR="$OUT2" UI_PORT="$PORT2" SBOM_UI_HOST_DIR="$WORK" \
    SBOM_UI_SCAN_ROOTS="$YOCTOROOT|/host/poky-build
$PLAINROOT|/host/plainroot" \
    SBOM_RUN_SCAN="$WORK/bin/run-scan" SBOM_DOCKER_SOCK="$WORK/no-such.sock" \
    SBOM_LIB_DIR="$WORK/no-such-lib" \
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

echo deepcve-progress > "$STUB_MODE_FILE"
events=$(sse_events "project=deepprog&version=1.0&source=current-dir")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
progs = [e for e in evs if e['event'] == 'progress']
assert len(progs) == 1, 'expected one progress event, got %d' % len(progs)
assert progs[0]['data'] == {'phase': 'deepcve', 'percent': 55}, progs[0]['data']
assert not any('deep-cve-progress' in str(e['data']) for e in evs if e['event'] == 'log'), \
    'progress marker leaked into log events'
"; then
    pass "deep-cve progress marker becomes a progress event on its own phase (not duplicated as log)"
else
    fail "deep-cve progress event contract violated" "$events"
fi

echo fail > "$STUB_MODE_FILE"
events=$(sse_events "project=bad&version=1.0&source=current-dir")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
dones = [e for e in evs if e['event'] == 'done']
assert len(dones) == 1 and dones[0]['data']['ok'] is False, evs
# No [ERROR]-marked line at all: nothing to show beyond the generic fallback
# the frontend already falls back to (run.failedBody) when this is null.
assert dones[0]['data'].get('errorMessage') is None, evs
"; then
    pass "scanner exit 1 ends the stream with done ok:false"
else
    fail "failed scan did not report done ok:false" "$events"
fi

# Mirrors #109's Node fallback quality gate: an explanation block, then a
# separate one-line block right before exit. Both must reach errorMessage in
# order, not just the last ("see above") line.
echo error-block > "$STUB_MODE_FILE"
events=$(sse_events "project=errblock&version=1.0&source=current-dir")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
dones = [e for e in evs if e['event'] == 'done']
assert len(dones) == 1 and dones[0]['data']['ok'] is False, evs
msg = dones[0]['data'].get('errorMessage')
assert msg is not None, evs
assert 'dependency resolver failed' in msg, msg
assert 'Commit a lockfile' in msg, msg
assert msg.endswith('fallback SBOM discarded (see above).'), msg
# No sse('error') was sent for this run (a plain exit 1, no rc==-1/exception
# path), so errorMessage is the only place this reached the client.
assert not [e for e in evs if e['event'] == 'error'], evs
"; then
    pass "a multi-block scanner failure reaches errorMessage in order, not just the last block"
else
    fail "multi-block [ERROR] capture did not reach errorMessage as expected" "$events"
fi

# The real merged wording (#109, docker/lib/source-detect.sh's
# apply_node_fallback_quality_gate), not a stand-in: guards against the stub
# above drifting stale if that file's message ever changes without this test
# changing too.
if grep -qF "The dependency resolver failed and the fallback scan found none of the project's declared dependencies (direct-deps-only manifest reading)" \
    "$ROOT_DIR/docker/lib/source-detect.sh" \
    && grep -qF "Commit a lockfile (package-lock.json, npm-shrinkwrap.json, yarn.lock or pnpm-lock.yaml)" \
        "$ROOT_DIR/docker/lib/source-detect.sh"; then
    pass "the stub's real-wording case still matches docker/lib/source-detect.sh verbatim"
else
    fail "docker/lib/source-detect.sh's Node fallback quality gate wording changed; update the error-block-real stub and this test to match"
fi
echo error-block-real > "$STUB_MODE_FILE"
events=$(sse_events "project=errblockreal&version=1.0&source=current-dir")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
dones = [e for e in evs if e['event'] == 'done']
assert len(dones) == 1 and dones[0]['data']['ok'] is False, evs
msg = dones[0]['data'].get('errorMessage')
assert msg is not None, evs
assert len(msg) == 500, len(msg)
assert msg.startswith('...'), msg
# The real block is 687 chars raw, so the cap cuts into the first (diagnostic)
# sentence -- both actionable guidance sentences, at the tail, must survive
# in full: that's what a reader actually needs to act on.
assert msg.endswith(
    \"or run 'npm install'/'pnpm install' once so a resolvable lockfile is present, then re-scan.\n\"
    \"Or scan from an environment where cdxgen itself can run (Docker access for the web UI's source scan; \"
    \"a working docker.sock for the CLI's transitive resolution) instead of relying on this direct-deps-only fallback.\"
), msg
"; then
    pass "the real #109 Node-fallback message is captured and the 500-char cap keeps both guidance sentences intact"
else
    fail "the real #109 Node-fallback message was not captured as expected" "$events"
fi

# A raw upstream HTTP response body (as printed on the TRUSCA/Dependency-Track
# upload failure paths) must never reach the client, regardless of indentation.
echo error-response-leak > "$STUB_MODE_FILE"
events=$(sse_events "project=respleak&version=1.0&source=current-dir")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
dones = [e for e in evs if e['event'] == 'done']
assert len(dones) == 1 and dones[0]['data']['ok'] is False, evs
msg = dones[0]['data'].get('errorMessage')
# The raw line still streams to the live log as always (unchanged, pre-existing
# behavior); only errorMessage -- the new field a card would show prominently
# -- must never carry the response body.
assert msg == '[ERROR] TRUSCA ingest failed (HTTP 500)', msg
assert 'do-not-leak-me' not in msg, msg
assert any('do-not-leak-me' in str(e['data']) for e in evs if e['event'] == 'log'), \
    'expected the raw Response: line to still be in the live log, unaffected'
"; then
    pass "a raw Response: body line never reaches errorMessage, only the [ERROR] line above it"
else
    fail "a Response: line leaked into errorMessage" "$events"
fi

echo "== _scrub_error_text: credential/token-shaped text is masked before display =="
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

scrub = server._scrub_error_text
assert "hunter2" not in scrub("Upload to https://user:hunter2@example.com/api failed")
assert "***@example.com" in scrub("Upload to https://user:hunter2@example.com/api failed")
assert "abcdef1234567890abcdef1234567890" not in scrub(
    "Authorization: Bearer abcdef1234567890abcdef1234567890")
assert "dXNlcjpwYXNz" not in scrub("curl: Authorization: Basic dXNlcjpwYXNz")
assert "deadbeefdeadbeefdeadbeef" not in scrub("curl failed: token=deadbeefdeadbeefdeadbeef1234")
assert "0123456789abcdef0123456789abcdef01234567" not in scrub(
    "hash mismatch: 0123456789abcdef0123456789abcdef01234567")
assert "QWxhZGRpbjpvcGVuIHNlc2FtZQ==QWxhZGRpbjpvcGVuIHNlc2FtZQ==" not in scrub(
    "blob: QWxhZGRpbjpvcGVuIHNlc2FtZQ==QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
# Ordinary text with no credential-shaped substring survives untouched.
assert scrub("[ERROR] TARGET_FILE not found: /src/demo.zip") == "[ERROR] TARGET_FILE not found: /src/demo.zip"
print("ok")
PY
then
    pass "URL userinfo, Authorization/Bearer, token=, hex and base64 blobs are all masked"
else
    fail "_scrub_error_text let a credential/token-shaped substring through"
fi

echo "== _ScanErrorTracker: block grouping, dedup and the 500-char cap =="
if SBOM_OUTPUT_DIR="$OUT" python3 - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

# A repeated identical block (e.g. a retried step logging the same [ERROR]
# twice) is kept only once, not duplicated.
t = server._ScanErrorTracker()
t.feed("[ERROR] source dir not found: /src")
t.feed("[ERROR] source dir not found: /src")
assert t.result() == "[ERROR] source dir not found: /src", t.result()

# An [ERROR] block still open at end-of-stream (no trailing blank/marker line)
# is still captured.
t2 = server._ScanErrorTracker()
t2.feed("[ERROR] top")
t2.feed("        continues here")
assert t2.result() == "[ERROR] top\ncontinues here", t2.result()

# Over the 500-char cap: the front is cut, not the end, with a leading "...".
t3 = server._ScanErrorTracker()
t3.feed("[ERROR] " + ("lorem ipsum dolor sit amet " * 30))
res = t3.result()
assert len(res) == 500, len(res)
assert res.startswith("..."), res
assert res.endswith("lorem ipsum dolor sit amet"), res
print("ok")
PY
then
    pass "the tracker dedupes identical blocks, flushes an unterminated block, and caps at 500 chars from the front"
else
    fail "_ScanErrorTracker grouping/dedup/cap behavior regressed"
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
assert errs and 'Docker socket' in errs[0]['data']['detail'], evs
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
assert any(e['event'] == 'error' and 'unknown input type' in e['data']['detail'] for e in evs), evs
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
assert any(e['event'] == 'error' and 'git clone failed' in e['data']['detail'] for e in evs), evs
assert [e for e in evs if e['event'] == 'done'][0]['data']['ok'] is False
"; then
    pass "failed git clone reports error + done ok:false"
else
    fail "git clone failure contract violated" "$events"
fi

echo "== zip-upload: hostile archives are rejected before extraction (zip-slip / tar traversal / tar symlink) =="
# safe_extract_zip() and the zip-upload tar branch (server.py) are the only
# things standing between an uploaded archive and the filesystem outside the
# scan's own extraction directory. Exercise all three guards end to end
# through the real upload + scan-stream endpoints, not just the function in
# isolation, so a regression in the wiring (not just the check itself) fails
# a test.
python3 - "$WORK/slip.zip" <<'ZIPSLIP'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("../../../../tmp/evil-zip-slip.txt", "pwned")
ZIPSLIP
ztoken=$(curl -fsS -F "kind=zip" -F "file=@$WORK/slip.zip" "$BASE2/upload?kind=zip" 2>/dev/null \
         | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
events=$(sse_events "project=zipslip&version=1.0&source=zip-upload&token=$ztoken")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
errs = [e for e in evs if e['event'] == 'error']
assert errs and 'unsafe path in archive' in errs[0]['data']['detail'], evs
assert [e for e in evs if e['event'] == 'done'][0]['data']['ok'] is False
"; then
    pass "zip-slip member (../../../../tmp/...) is rejected, not extracted"
else
    fail "zip-slip contract violated" "$events"
fi
[ -e /tmp/evil-zip-slip.txt ] && fail "zip-slip actually wrote outside the extraction dir" || pass "zip-slip left no file outside the extraction dir"
rm -f /tmp/evil-zip-slip.txt

python3 - "$WORK/slip.tar" <<'TARSLIP'
import sys, tarfile, io
with tarfile.open(sys.argv[1], "w") as t:
    data = b"pwned"
    info = tarfile.TarInfo(name="../evil-tar-slip.txt")
    info.size = len(data)
    t.addfile(info, io.BytesIO(data))
TARSLIP
ttoken=$(curl -fsS -F "kind=zip" -F "file=@$WORK/slip.tar" "$BASE2/upload?kind=zip" 2>/dev/null \
         | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
events=$(sse_events "project=tarslip&version=1.0&source=zip-upload&token=$ttoken")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
errs = [e for e in evs if e['event'] == 'error']
assert errs and 'unsafe path in archive' in errs[0]['data']['detail'], evs
assert [e for e in evs if e['event'] == 'done'][0]['data']['ok'] is False
"; then
    pass "tar member (../evil-tar-slip.txt) is rejected, not extracted"
else
    fail "tar path-traversal contract violated" "$events"
fi

python3 - "$WORK/symlink.tar" <<'TARSYM'
import sys, tarfile
with tarfile.open(sys.argv[1], "w") as t:
    link = tarfile.TarInfo(name="escape")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc"
    t.addfile(link)
TARSYM
stoken=$(curl -fsS -F "kind=zip" -F "file=@$WORK/symlink.tar" "$BASE2/upload?kind=zip" 2>/dev/null \
         | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
events=$(sse_events "project=tarsym&version=1.0&source=zip-upload&token=$stoken")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
errs = [e for e in evs if e['event'] == 'error']
assert errs and 'unsafe link in archive' in errs[0]['data']['detail'], evs
assert [e for e in evs if e['event'] == 'done'][0]['data']['ok'] is False
"; then
    pass "tar symlink member pointing outside the archive is rejected"
else
    fail "tar symlink contract violated" "$events"
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

echo "== model upload: the file is read where it lies, as MODELFILE =="
# The one AI input that needs no image and no network: the scan runs in this
# container, so the mode has to arrive with the uploaded file's own path.
echo ok > "$STUB_MODE_FILE"
printf 'GGUF\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
    > "$WORK/w.gguf"
mtoken=$(curl -fsS -F "kind=model" -F "file=@$WORK/w.gguf" "$BASE2/upload?kind=model" 2>/dev/null \
         | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
rm -f "$WORK/stub-env"
sse_events "project=mdl&version=1.0&source=model-upload&token=$mtoken" >/dev/null
if [ "$(sed -n 's/^MODE=//p' "$WORK/stub-env")" = "MODELFILE" ] \
   && grep -q '^TARGET_FILE=.*\.gguf$' "$WORK/stub-env"; then
    pass "model-upload -> MODE=MODELFILE with TARGET_FILE"
else
    fail "model upload did not route to MODELFILE" "$(cat "$WORK/stub-env")"
fi
# A REAL scan launch (not a test manually poking _active_upload_tokens) must
# both claim the token while it runs and release + clean it up once the SSE
# stream reaches its "done" event -- the finally block's own contract, now
# reordered (rmtree before the active-tracking discard) and exercised here
# through the actual HTTP path, not just called as a bare function.
if [ ! -d "$OUT2/.uploads/$mtoken" ]; then
    pass "a real scan-stream consumes and cleans up its upload token's directory"
else
    fail "upload token directory survived a completed real scan" "$OUT2/.uploads/$mtoken"
fi
# The usage scenario tailors the risk verdict for a model file exactly as it
# does for a model named on HuggingFace. Uploaded again: a scan consumes the
# upload, so replaying the first token would fail before reaching the env.
mtoken2=$(curl -fsS -F "kind=model" -F "file=@$WORK/w.gguf" "$BASE2/upload?kind=model" 2>/dev/null \
          | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
rm -f "$WORK/stub-env"
sse_events "project=mdl&version=1.0&source=model-upload&token=$mtoken2&usage=product" >/dev/null
if [ "$(sed -n 's/^AI_USAGE_CONTEXT=//p' "$WORK/stub-env")" = "product" ]; then
    pass "usage scenario reaches a model-file scan"
else
    fail "usage not forwarded for model-upload" "$(cat "$WORK/stub-env")"
fi

echo "== an upload actively feeding a RUNNING scan survives even a far-expired TTL =="
# The earlier "cleaned up after a completed scan" check above cannot tell
# active-tracking apart from the pre-existing finally-block rmtree -- both
# leave an empty directory once the scan is done either way. This proves the
# actual claim: while the scan is still running (hang mode, real heartbeat),
# age the upload dir on disk past even this server's 24h default TTL, then
# hit /scans (the real sweep, in the real server process) and check the
# directory is still there specifically because _active_upload_tokens says so
# -- not because the TTL happened not to have elapsed yet.
echo hang > "$STUB_MODE_FILE"
rm -f "$STUB_HEARTBEAT"
htoken=$(curl -fsS -F "kind=model" -F "file=@$WORK/w.gguf" "$BASE2/upload?kind=model" 2>/dev/null \
         | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
curl -sN --max-time 10 "$BASE2/scan-stream?project=hangup&version=1.0&source=model-upload&token=$htoken" \
    >/dev/null 2>&1 &
hang_curl_pid=$!
hb_seen=0
for _ in $(seq 1 30); do
    [ -s "$STUB_HEARTBEAT" ] && { hb_seen=1; break; }
    sleep 0.1
done
if [ "$hb_seen" = 1 ]; then
    python3 - "$OUT2/.uploads/$htoken" <<'PY'
import os, sys, time
os.utime(sys.argv[1], (time.time() - 30 * 3600, time.time() - 30 * 3600))
PY
    curl -fsS "$BASE2/scans" >/dev/null 2>&1
    if [ -d "$OUT2/.uploads/$htoken" ]; then
        pass "an upload token claimed by a running scan is not swept, even 30h past the TTL"
    else
        fail "a running scan's own upload directory was swept out from under it"
    fi
else
    fail "hang-mode scan never started (no heartbeat) -- could not exercise this check"
fi
kill "$hang_curl_pid" 2>/dev/null
wait "$hang_curl_pid" 2>/dev/null
echo ok > "$STUB_MODE_FILE"

echo "== package upload: extension decides the scan mode =="
# jar and OS packages are read as a file (BINARY); a wheel carries no manifest
# syft reads from the file itself, so it is unpacked and scanned as a directory.
echo ok > "$STUB_MODE_FILE"
: > "$WORK/lib2.jar"
jtoken=$(curl -fsS -F "kind=package" -F "file=@$WORK/lib2.jar" "$BASE2/upload?kind=package" 2>/dev/null \
         | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
rm -f "$WORK/stub-env"
sse_events "project=pkg&version=1.0&source=package-upload&token=$jtoken" >/dev/null
if [ "$(sed -n 's/^MODE=//p' "$WORK/stub-env")" = "BINARY" ] \
   && grep -q '^TARGET_FILE=.*\.jar$' "$WORK/stub-env"; then
    pass "package-upload (.jar) -> MODE=BINARY with TARGET_FILE"
else
    fail "jar did not route to BINARY" "$(cat "$WORK/stub-env")"
fi

python3 - "$WORK/pkg.whl" <<'WHL'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("demo-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n")
WHL
wtoken=$(curl -fsS -F "kind=package" -F "file=@$WORK/pkg.whl" "$BASE2/upload?kind=package" 2>/dev/null \
         | python3 -c "import sys,json;print(json.load(sys.stdin).get('token',''))" 2>/dev/null)
rm -f "$WORK/stub-env"
sse_events "project=whl&version=1.0&source=package-upload&token=$wtoken" >/dev/null
if [ "$(sed -n 's/^MODE=//p' "$WORK/stub-env")" = "ROOTFS" ] \
   && [ -n "$(sed -n 's/^TARGET_DIR=//p' "$WORK/stub-env")" ]; then
    pass "package-upload (.whl) -> unpacked, MODE=ROOTFS with TARGET_DIR"
else
    fail "wheel did not route to ROOTFS" "$(cat "$WORK/stub-env")"
fi
# Counted by the stub while the scan ran; the extracted tree is cleaned up
# afterwards, so checking here would always see an empty directory.
if [ "$(sed -n 's/^TARGET_DIR_FILES=//p' "$WORK/stub-env")" -gt 0 ] 2>/dev/null; then
    pass "wheel contents were extracted before the directory scan"
else
    fail "wheel was not extracted" "$(cat "$WORK/stub-env")"
fi

echo "== license: the outbound license reaches the scan env, and only when given =="
echo ok > "$STUB_MODE_FILE"
rm -f "$WORK/stub-env"
sse_events "project=lic1&version=1.0&source=current-dir&license=Apache-2.0" >/dev/null
if [ "$(sed -n 's/^PROJECT_LICENSE=//p' "$WORK/stub-env")" = "Apache-2.0" ]; then
    pass "license=Apache-2.0 -> PROJECT_LICENSE in the run-scan env"
else
    fail "outbound license did not reach the scan env" "$(cat "$WORK/stub-env")"
fi
# Omitted -> empty, which is what leaves the conflict check off. An empty value
# must not become some default, or every scan would claim an outbound license.
rm -f "$WORK/stub-env"
sse_events "project=lic2&version=1.0&source=current-dir" >/dev/null
if [ -z "$(sed -n 's/^PROJECT_LICENSE=//p' "$WORK/stub-env")" ]; then
    pass "no license param -> PROJECT_LICENSE stays empty (conflict check off)"
else
    fail "PROJECT_LICENSE was set without a license param" "$(cat "$WORK/stub-env")"
fi

echo "== sbom_author: the SBOM author reaches the scan env verbatim, and only when given =="
# URL-encode via Python (comma/space/parens/ampersand/Korean all need it; the
# ampersand especially, or it would be read as a second query parameter).
urlenc() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
rm -f "$WORK/stub-env"
sse_events "project=auth1&version=1.0&source=current-dir&sbom_author=$(urlenc "ACME Corp")" >/dev/null
if [ "$(sed -n 's/^SBOM_AUTHOR=//p' "$WORK/stub-env")" = "ACME Corp" ]; then
    pass "sbom_author=ACME Corp -> SBOM_AUTHOR in the run-scan env"
else
    fail "SBOM author did not reach the scan env" "$(cat "$WORK/stub-env")"
fi
rm -f "$WORK/stub-env"
sse_events "project=auth2&version=1.0&source=current-dir" >/dev/null
if [ -z "$(sed -n 's/^SBOM_AUTHOR=//p' "$WORK/stub-env")" ]; then
    pass "no sbom_author param -> SBOM_AUTHOR stays empty (left out of the SBOM)"
else
    fail "SBOM_AUTHOR was set without a sbom_author param" "$(cat "$WORK/stub-env")"
fi
# This path (the in-process scan) is a subprocess env var, not a docker-run
# argv or a shell command line, so a legal entity name reaches it byte for
# byte -- no comma/parens/ampersand stripping, matching --sbom-author on the
# CLI (see stamp-document-metadata.sh's jq --arg, and scan-sbom.sh's own
# printf %q path, both verified end to end for the same two values below).
rm -f "$WORK/stub-env"
sse_events "project=auth3&version=1.0&source=current-dir&sbom_author=$(urlenc 'SK Telecom Co., Ltd.')" >/dev/null
if [ "$(sed -n 's/^SBOM_AUTHOR=//p' "$WORK/stub-env")" = "SK Telecom Co., Ltd." ]; then
    pass "a legal-entity name with a comma reaches SBOM_AUTHOR unchanged"
else
    fail "SK Telecom Co., Ltd. was mangled" "$(cat "$WORK/stub-env")"
fi
rm -f "$WORK/stub-env"
sse_events "project=auth4&version=1.0&source=current-dir&sbom_author=$(urlenc '(주)에스케이 & 파트너스')" >/dev/null
if [ "$(sed -n 's/^SBOM_AUTHOR=//p' "$WORK/stub-env")" = "(주)에스케이 & 파트너스" ]; then
    pass "a Korean legal-entity name with parens/ampersand reaches SBOM_AUTHOR unchanged"
else
    fail "(주)에스케이 & 파트너스 was mangled" "$(cat "$WORK/stub-env")"
fi

echo "== lang: the request's language decides REPORT_LANG, not this server's own locale =="
rm -f "$WORK/stub-env"
sse_events "project=lang1&version=1.0&source=current-dir&lang=ko" >/dev/null
if [ "$(sed -n 's/^REPORT_LANG=//p' "$WORK/stub-env")" = "ko" ]; then
    pass "lang=ko -> REPORT_LANG=ko in the run-scan env"
else
    fail "lang=ko did not reach the scan env as REPORT_LANG" "$(cat "$WORK/stub-env")"
fi
rm -f "$WORK/stub-env"
sse_events "project=lang2&version=1.0&source=current-dir&lang=en" >/dev/null
if [ "$(sed -n 's/^REPORT_LANG=//p' "$WORK/stub-env")" = "en" ]; then
    pass "lang=en -> REPORT_LANG=en in the run-scan env"
else
    fail "lang=en did not reach the scan env as REPORT_LANG" "$(cat "$WORK/stub-env")"
fi
# Omitted and out-of-allowlist both fall back to en -- a typo in the query
# param is not a reason to fail a scan, same rule as conformance_profile.
rm -f "$WORK/stub-env"
sse_events "project=lang3&version=1.0&source=current-dir" >/dev/null
if [ "$(sed -n 's/^REPORT_LANG=//p' "$WORK/stub-env")" = "en" ]; then
    pass "no lang param -> REPORT_LANG defaults to en"
else
    fail "REPORT_LANG did not default to en with no lang param" "$(cat "$WORK/stub-env")"
fi
rm -f "$WORK/stub-env"
sse_events "project=lang4&version=1.0&source=current-dir&lang=fr" >/dev/null
if [ "$(sed -n 's/^REPORT_LANG=//p' "$WORK/stub-env")" = "en" ]; then
    pass "lang=fr (not en/ko) falls back to REPORT_LANG=en"
else
    fail "an out-of-allowlist lang value did not fall back to en" "$(cat "$WORK/stub-env")"
fi

echo "== _env_flag_value: sanitizer for the sibling docker-run -e argument =="
if python3 - "$ROOT_DIR" <<'PY'
import sys, os
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

# A legal entity name keeps the punctuation it actually needs -- this is the
# same sanitizer PROJECT_NAME goes through, so widening it here also fixes a
# name like "SK Telecom Co., Ltd." losing its comma there.
assert server._env_flag_value("SK Telecom Co., Ltd.") == "SK Telecom Co., Ltd.", server._env_flag_value("SK Telecom Co., Ltd.")
assert server._env_flag_value("(주)에스케이 & 파트너스") == "(주)에스케이 & 파트너스", server._env_flag_value("(주)에스케이 & 파트너스")
assert server._env_flag_value("O'Reilly Media") == "O'Reilly Media", server._env_flag_value("O'Reilly Media")

# $ and backticks are still stripped -- the two bytes that actually start a
# command substitution -- even though the now-wider charset keeps the
# parentheses around them (a legal entity name may need those too, e.g. a
# "(주)" prefix); the result is inert literal text, not two bytes short of a
# shell command. This value is not a shell string anywhere it goes (see the
# SBOM_AUTHOR forwarding tests above and scan-sbom.sh's own printf %q path),
# but the sanitizer keeps stripping $ and ` anyway as its own docstring's
# defense-in-depth describes.
mangled = server._env_flag_value("Evil $(touch /tmp/PWNED) `touch /tmp/PWNED2`")
assert "$" not in mangled and "`" not in mangled, mangled
assert mangled == "Evil (touch /tmp/PWNED) touch /tmp/PWNED2", mangled

# Still bounded.
assert len(server._env_flag_value("x" * 300)) == 256
PY
then
    pass "_env_flag_value keeps legal-entity punctuation and still strips shell metacharacters"
else
    fail "_env_flag_value sanitizer check failed (see assertion above)"
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

echo "== AI usage scenario param (usage= -> AI_USAGE_CONTEXT) =="
echo ok > "$STUB_MODE_FILE"
# An out-of-allowlist value is refused before the stream starts (HTTP 400 JSON),
# so a crafted scenario can never reach the scan environment.
code=$(curl -s -o "$WORK/usage-400" -w '%{http_code}' \
    "$BASE2/scan-stream?project=use&version=1.0&source=current-dir&usage=commercial")
if [ "$code" = "400" ] && python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$WORK/usage-400" 2>/dev/null; then
    pass "invalid usage value is rejected pre-stream (400 JSON)"
else
    fail "invalid usage returned $code (expected 400 JSON)"
fi
# A valid scenario is accepted (normal SSE run) and reaches run-scan as
# AI_USAGE_CONTEXT with the exact allowlist literal.
rm -f "$WORK/stub-env"
events=$(sse_events "project=use&version=1.0&source=current-dir&usage=redistribute")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
assert [e for e in evs if e['event'] == 'done'][0]['data']['ok'] is True, evs
" && [ "$(sed -n 's/^AI_USAGE_CONTEXT=//p' "$WORK/stub-env")" = "redistribute" ]; then
    pass "valid usage accepted; AI_USAGE_CONTEXT reaches the run-scan env"
else
    fail "valid usage did not reach the run-scan env" "$(cat "$WORK/stub-env" 2>/dev/null)"
fi
# No usage param -> the var stays unset (assessment runs without a scenario).
rm -f "$WORK/stub-env"
sse_events "project=use2&version=1.0&source=current-dir" >/dev/null
if [ -z "$(sed -n 's/^AI_USAGE_CONTEXT=//p' "$WORK/stub-env")" ]; then
    pass "no usage param -> AI_USAGE_CONTEXT not set"
else
    fail "AI_USAGE_CONTEXT leaked without a usage param" "$(cat "$WORK/stub-env")"
fi

# Conversion needs the pipeline helper + syft in this image, or a sibling scanner
# container. This second server has neither: no docker socket, and SBOM_LIB_DIR
# points at nothing so the helper is missing however the developer's machine is
# equipped (a host syft would otherwise make the first server capable). The export
# must then say so plainly instead of failing opaquely.
echo "== Yocto build directory routes to ANALYZE through the scan stream =="
echo ok > "$STUB_MODE_FILE"
yev=$(sse_events "project=yocto&version=1.0&source=rootfs-dir&target=$YOCTOROOT")
if echo "$yev" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
logs = [e['data'] for e in evs if e['event'] == 'log']
done = [e['data'] for e in evs if e['event'] == 'done']
assert len(done) == 1, evs
d = done[0]
assert d['ok'] is True, d
# The run is an SBOM analysis, not a directory scan of the build tree.
assert d['mode'] == 'ANALYZE', d['mode']
# The result page must say what this turned out to be, and name the folder.
assert d['scanConfig']['source'] == 'yocto-build-dir', d['scanConfig']
assert d['scanConfig']['sourceLabel'] == '/host/poky-build', d['scanConfig']
# The folder the user picked is kept, so a re-scan replays the same detection.
assert d['scanConfig']['target'].endswith('poky-build'), d['scanConfig']
assert any('Yocto build directory' in ln for ln in logs), logs
assert any('Image SBOM' in ln for ln in logs), logs
"; then
    pass "a picked Yocto build directory is analyzed as its image SBOM"
else
    fail "Yocto build directory routing failed" "$yev"
fi

# The scanner has to receive the document, not the folder: ANALYZE_SBOM points at
# the file the build published, and no directory target is set.
if grep -q '^MODE=ANALYZE$' "$WORK/stub-env" \
   && grep -q '^ANALYZE_SBOM=.*/tmp/deploy/images/qemux86-64/core-image-minimal.rootfs.spdx.json$' "$WORK/stub-env" \
   && grep -q '^TARGET_DIR=$' "$WORK/stub-env"; then
    pass "the scanner is handed the image SBOM (ANALYZE_SBOM), not the build tree"
else
    fail "wrong scan environment for a Yocto build directory" "$(cat "$WORK/stub-env")"
fi
# ANALYZE with no explicit conformance_profile defaults to skt-submission (a
# document under submission review), not the "default" a generated SBOM gets.
if grep -q '^CONFORMANCE_PROFILE=skt-submission$' "$WORK/stub-env"; then
    pass "ANALYZE defaults the conformance profile to skt-submission"
else
    fail "ANALYZE conformance profile default" "$(cat "$WORK/stub-env")"
fi

echo "== conformance_profile param (-> CONFORMANCE_PROFILE) =="
echo ok > "$STUB_MODE_FILE"
# No param, not ANALYZE -> the "default" profile (matches the CLI's default).
rm -f "$WORK/stub-env"
sse_events "project=cp1&version=1.0&source=current-dir" >/dev/null
if grep -q '^CONFORMANCE_PROFILE=default$' "$WORK/stub-env"; then
    pass "no conformance_profile param -> default profile for a generated SBOM"
else
    fail "conformance profile default for a generated SBOM" "$(cat "$WORK/stub-env")"
fi
# An explicit choice is honored regardless of mode.
rm -f "$WORK/stub-env"
sse_events "project=cp2&version=1.0&source=current-dir&conformance_profile=skt-submission" >/dev/null
if grep -q '^CONFORMANCE_PROFILE=skt-submission$' "$WORK/stub-env"; then
    pass "an explicit conformance_profile is honored"
else
    fail "explicit conformance_profile" "$(cat "$WORK/stub-env")"
fi
# An unrecognized value is not a client error (unlike usage=): it warns and
# falls back to the per-mode default, same rule scan-sbom.sh applies to an
# unknown --conformance-profile.
rm -f "$WORK/stub-env"
events=$(sse_events "project=cp3&version=1.0&source=current-dir&conformance_profile=bogus")
if echo "$events" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
assert [e for e in evs if e['event'] == 'done'][0]['data']['ok'] is True, evs
" && grep -q '^CONFORMANCE_PROFILE=default$' "$WORK/stub-env"; then
    pass "an unrecognized conformance_profile falls back to default, scan still runs"
else
    fail "unrecognized conformance_profile handling" "$events / $(cat "$WORK/stub-env" 2>/dev/null)"
fi

# A picked folder that is not a Yocto build must still be a directory scan —
# the detection may not take over an ordinary rootfs target.
pev=$(sse_events "project=plain&version=1.0&source=rootfs-dir&target=$PLAINROOT")
if echo "$pev" | python3 -c "
import sys, json
done = [e['data'] for e in json.load(sys.stdin) if e['event'] == 'done']
assert len(done) == 1, done
assert done[0]['mode'] == 'ROOTFS', done[0]['mode']
assert done[0]['scanConfig']['source'] == 'rootfs-dir', done[0]['scanConfig']
"; then
    pass "an ordinary picked folder still runs as a directory scan"
else
    fail "plain directory scan regressed" "$pev"
fi

# A Yocto build directory with no SPDX document stops the run and says which
# setting produces one, instead of falling back to scanning the build tree.
NOSBOMROOT="$YOCTOROOT/tmp/deploy/images/empty-machine"
mkdir -p "$NOSBOMROOT/conf"
echo 'BBLAYERS = "x"' > "$NOSBOMROOT/conf/bblayers.conf"
nev=$(sse_events "project=nosbom&version=1.0&source=rootfs-dir&target=$NOSBOMROOT")
if echo "$nev" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
errs = [e['data']['detail'] for e in evs if e['event'] == 'error']
done = [e['data'] for e in evs if e['event'] == 'done']
assert errs and 'neither an SPDX SBOM' in errs[0], evs
assert 'create-spdx-3.0' in errs[0], errs
assert len(done) == 1 and done[0]['ok'] is False, done
"; then
    pass "a build directory with no SBOM fails with the setting to add"
else
    fail "no-SBOM build directory handling wrong" "$nev"
fi

# A real SPDX 2.x deploy directory holds the archive and nothing else, so the
# browser has to find and analyze the archive itself.
AROOT="$YOCTOROOT/tmp/deploy/images/archive-only"
mkdir -p "$AROOT/conf" "$AROOT/tmp/deploy/images/m1"
echo 'BBLAYERS = "x"' > "$AROOT/conf/bblayers.conf"
: > "$AROOT/tmp/deploy/images/m1/img.rootfs.spdx.tar.zst"
aev=$(sse_events "project=arch&version=1.0&source=rootfs-dir&target=$AROOT")
if echo "$aev" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
logs = [e['data'] for e in evs if e['event'] == 'log']
done = [e['data'] for e in evs if e['event'] == 'done']
assert len(done) == 1 and done[0]['mode'] == 'ANALYZE', evs
assert done[0]['scanConfig']['source'] == 'yocto-build-dir', done[0]['scanConfig']
assert any('inside this archive' in ln for ln in logs), logs
"; then
    pass "an archive-only build directory is analyzed as the archive"
else
    fail "archive-only routing wrong" "$aev"
fi
if grep -q '^ANALYZE_SBOM=.*\.spdx\.tar\.zst$' "$WORK/stub-env"; then
    pass "the scanner is handed the archive"
else
    fail "the archive did not reach the scanner" "$(cat "$WORK/stub-env")"
fi

# A build that produced no SPDX still recorded what it shipped. Reading those
# records beats refusing: the image package manifest is the installed set, the
# license manifest carries the licenses, and cve-check the verdicts.
MFROOT="$YOCTOROOT/tmp/deploy/images/manifest-only"
mkdir -p "$MFROOT/conf" "$MFROOT/tmp/deploy/images/qemuarm" "$MFROOT/tmp/deploy/licenses/img-20260101" "$MFROOT/tmp/log/cve"
echo 'BBLAYERS = "x"' > "$MFROOT/conf/bblayers.conf"
printf 'busybox core2-64 1.36.1\nlibz1 core2-64 1.3\n' \
    > "$MFROOT/tmp/deploy/images/qemuarm/img-qemuarm.rootfs.manifest"
printf 'PACKAGE NAME: busybox\nPACKAGE VERSION: 1.36.1\nRECIPE NAME: busybox\nLICENSE: GPL-2.0-only\n\n' \
    > "$MFROOT/tmp/deploy/licenses/img-20260101/license.manifest"
printf '{"version":"1","package":[{"name":"busybox","version":"1.36.1","issue":[{"id":"CVE-2022-28391","status":"Unpatched","scorev3":"9.8","summary":"x","link":"y"}]}]}\n' \
    > "$MFROOT/tmp/log/cve/cve-summary.json"
mev=$(sse_events "project=mfonly&version=1.0&source=rootfs-dir&target=$MFROOT")
if echo "$mev" | python3 -c "
import sys, json
evs = json.load(sys.stdin)
logs = [e['data'] for e in evs if e['event'] == 'log']
done = [e['data'] for e in evs if e['event'] == 'done']
assert len(done) == 1 and done[0]['ok'] is True, evs
assert done[0]['mode'] == 'ANALYZE', done[0]['mode']
assert done[0]['scanConfig']['source'] == 'yocto-build-dir', done[0]['scanConfig']
assert any('reading the manifests' in ln for ln in logs), logs
"; then
    pass "a build with no SPDX is read from the manifests it did write"
else
    fail "manifest fallback failed" "$mev"
fi

# The scanner is pointed at the build directory itself, since the records it
# needs are spread across it — and no document is claimed to exist.
if grep -q '^MODE=ANALYZE$' "$WORK/stub-env" \
   && grep -q '^ANALYZE_SBOM=$' "$WORK/stub-env"; then
    pass "the manifest path hands over the build directory, not a document"
else
    fail "wrong scan environment for the manifest fallback" "$(cat "$WORK/stub-env")"
fi

# The recorded source is not an input the form offers, so re-scanning one comes
# back as the directory input it was picked with — and detection runs again.
rev=$(sse_events "project=yocto&version=1.0&source=yocto-build-dir&target=$YOCTOROOT")
if echo "$rev" | python3 -c "
import sys, json
done = [e['data'] for e in json.load(sys.stdin) if e['event'] == 'done']
assert len(done) == 1, done
assert done[0]['ok'] is True, done[0]
assert done[0]['mode'] == 'ANALYZE', done[0]['mode']
assert done[0]['scanConfig']['source'] == 'yocto-build-dir', done[0]['scanConfig']
"; then
    pass "re-scanning a Yocto scan replays the folder and detects it again"
else
    fail "re-scan of a Yocto build directory failed" "$rev"
fi

echo "== SPDX export without a converter =="
caps2=$(curl -fsS "$BASE2/capabilities" 2>/dev/null)
if echo "$caps2" | python3 -c "
import sys, json
c = json.load(sys.stdin)
assert c.get('spdxExport') is False, c
assert c.get('spdxSibling') is False, c
" 2>/dev/null; then
    pass "/capabilities reports spdxExport false with no syft and no docker"
else
    fail "/capabilities spdxExport wrong" "$caps2"
fi
mkdir -p "$OUT2/spdxnone_1.0"
echo '{"bomFormat":"CycloneDX"}' > "$OUT2/spdxnone_1.0/spdxnone_1.0_bom.json"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE2/spdx-export?id=spdxnone_1.0")
[ "$code" = "503" ] && pass "/spdx-export reports 503 when no converter is available" || fail "/spdx-export unavailable returned $code (expected 503)"

echo "== concurrent scans of the same project do not share a run folder =="
# Two scans of the same project+version resolved to the same run folder, and the
# artifacts inside are named from project/version rather than from the folder,
# so both containers wrote the same filenames in the same place. Post-processing
# rewrites each artifact in place, so the moves interleaved and the surviving
# file mixed both runs. Measured: log4j-core 2.14.1 reports 14 vulnerabilities
# alone and 0 in both tabs when scanned twice at once.
if python3 - "$SERVER" <<'CLAIMPY'
import importlib.util, sys
from datetime import datetime
spec = importlib.util.spec_from_file_location("server", sys.argv[1])
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

claim = server.claim_run_id
FIXED = datetime(2026, 9, 3, 14, 0, 0)

# Nothing in flight: the plain prefix, exactly as before.
assert claim("app_1.0", set()) == "app_1.0"

# One in flight: the second scan is pushed onto its own folder.
active = {"app_1.0"}
second = claim("app_1.0", active, now=FIXED)
assert second != "app_1.0", second
assert second.startswith("app_1.0_"), second

# Three tabs at once. The timestamp is second-resolution, so the second and
# third would collide on it alone — which is the case this exists for, and the
# one a two-tab test would pass straight through.
active = set()
ids = []
for _ in range(3):
    got = claim("race_1", active, now=FIXED)
    active.add(got)          # the caller registers under the same lock
    ids.append(got)
assert len(set(ids)) == 3, ids

# A finished scan of another project is irrelevant.
assert claim("other_2.0", {"app_1.0"}) == "other_2.0"

# ?timestamp=true still opts in explicitly, with nothing in flight.
forced = claim("app_1.0", set(), now=FIXED, force_suffix=True)
assert forced.startswith("app_1.0_"), forced
assert forced != "app_1.0"

# Every id has to survive the path barrier the write side applies.
for rid in ids + [second, forced]:
    assert server.scan_id_ok(rid), rid
print("ok")
CLAIMPY
then
    pass "a run folder is claimed per concurrent scan, three-way collision included"
else
    fail "concurrent scans still resolve to the same run folder"
fi

# The claim is released on every exit, including a client that closed the stream
# mid-scan. A name left behind would push every later scan of that project onto
# a suffixed folder for the life of the process.
n_add=$(grep -c "_scan_active.add(" "$SERVER")
n_del=$(grep -c "_scan_active.discard(" "$SERVER")
if [ "$n_add" = "1" ] && [ "$n_del" -ge "2" ]; then
    pass "the claim is released on the early-return path and in the finally"
else
    fail "claim/release are unbalanced (add=$n_add, discard=$n_del)"
fi

echo "== sibling image refresh: an already-present image is re-pulled quietly =="
# _sibling_image_present only means the tag was pulled at SOME point; the sibling
# firmware/aibom/deep-cve image (and the base scanner image, for on-demand SPDX)
# can otherwise sit on a stale `:latest` layer forever. run_sibling_scan /
# convert_bom_to_spdx now call refresh_sibling_image_quietly(image, on_log) in
# that case, real `docker pull`, bounded by a STALL timeout (not elapsed time) so
# it never meaningfully delays a scan. A fake `docker` on PATH stands in for the
# daemon; _SIBLING_REFRESH_STALL_SECS shortens the stall bound so a simulated
# stalled pull gives up in ~1s instead of the real-world 12s default.
FAKEDOCKER="$WORK/fakedockerbin"; mkdir -p "$FAKEDOCKER"
FAKE_DOCKER_LOG="$WORK/fakedocker.log"
cat > "$FAKEDOCKER/docker" <<'STUB'
#!/usr/bin/env bash
echo "docker $*" >> "${FAKE_DOCKER_LOG:-/dev/null}"
case "${1:-}" in
  pull)
    case "${FAKE_DOCKER_PULL_MODE:-uptodate}" in
      uptodate)
        echo "Status: Image is up to date for ${2:-image}"
        exit 0 ;;
      fail)
        echo "Error response from daemon: pull access denied" >&2
        exit 1 ;;
      stall)
        sleep 30
        exit 0 ;;
      partial)
        # One real layer-status line (matches server.PullProgress's format), then
        # nothing — a download that started but stopped making progress.
        echo "17a39c0ba978: Downloading"
        sleep 30
        exit 0 ;;
    esac
    ;;
  run) exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$FAKEDOCKER/docker"

# Case 1: the fake pull reports up to date immediately -> refresh finishes in a
# fraction of a second, and the scan proceeds all the way to the sibling `docker
# run`. _sibling_image_present is stubbed (this is not a test of the presence
# check itself), but refresh_sibling_image_quietly runs FOR REAL against the
# fake docker on PATH.
if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER:$PATH" FAKE_DOCKER_LOG="$FAKE_DOCKER_LOG" \
   FAKE_DOCKER_PULL_MODE=uptodate python3 - "$ROOT_DIR" <<'PY'
import os, sys, time
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

server._self_container_id = lambda: "selfcid000000"
server._sibling_image_present = lambda image: True

run_out = server.OUTPUT_DIR + "/run_1"
logs = []
started = time.monotonic()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    logs.append, model_id="openai/clip",
)
elapsed = time.monotonic() - started
assert rc == 0, (rc, logs)
assert elapsed < 5, "an up-to-date refresh must not meaningfully delay the scan (%.1fs)" % elapsed
assert any("launching" in ln for ln in logs), logs
STUB_LOG = os.environ["FAKE_DOCKER_LOG"]
with open(STUB_LOG) as fh:
    calls = fh.read()
assert "docker pull ghcr.io/sktelecom/bomlens-aibom:1.5.0" in calls, calls
assert "docker run" in calls, "the scan must still reach the sibling docker run"
PY
then
    pass "an up-to-date fake pull finishes fast and the scan reaches the sibling docker run"
else
    fail "up-to-date refresh case failed (see assertion above)"
fi

# Case 2: the fake pull hangs with NO output at all (offline / blocked network).
# With the stall bound shortened to ~1s, refresh_sibling_image_quietly must give
# up quickly and the scan must still proceed — the refresh is best-effort and
# must never be the thing that fails a scan.
: > "$FAKE_DOCKER_LOG"
if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER:$PATH" FAKE_DOCKER_LOG="$FAKE_DOCKER_LOG" \
   FAKE_DOCKER_PULL_MODE=stall _SIBLING_REFRESH_STALL_SECS=1 python3 - "$ROOT_DIR" <<'PY'
import os, sys, time
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server
assert server._SIBLING_REFRESH_STALL_SECS == 1.0, server._SIBLING_REFRESH_STALL_SECS

server._self_container_id = lambda: "selfcid000000"
server._sibling_image_present = lambda image: True

run_out = server.OUTPUT_DIR + "/run_1"
logs = []
started = time.monotonic()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-aibom:1.5.0", "AIBOM", run_out,
    logs.append, model_id="openai/clip",
)
elapsed = time.monotonic() - started
assert rc == 0, (rc, logs)
assert elapsed < 10, "a fully stalled refresh must give up quickly, not hang (%.1fs)" % elapsed
assert any("skipped" in ln for ln in logs), logs
assert any("launching" in ln for ln in logs), logs
PY
then
    pass "a fully stalled fake pull is given up on quickly and the scan still proceeds"
else
    fail "stalled refresh case failed (see assertion above)"
fi

# Case 3: the fake pull prints one real layer line (a download actually started)
# and then stalls — same outcome as case 2 (the scan must proceed), and this
# also exercises the PullProgress reader path inside the refresh.
: > "$FAKE_DOCKER_LOG"
if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER:$PATH" FAKE_DOCKER_LOG="$FAKE_DOCKER_LOG" \
   FAKE_DOCKER_PULL_MODE=partial _SIBLING_REFRESH_STALL_SECS=1 python3 - "$ROOT_DIR" <<'PY'
import os, sys, time
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

server._self_container_id = lambda: "selfcid000000"
server._sibling_image_present = lambda image: True

run_out = server.OUTPUT_DIR + "/run_1"
logs = []
started = time.monotonic()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-deep-cve:1.5.0", "IMAGE", run_out,
    logs.append, target_image="ghcr.io/library/nginx:1.25",
)
elapsed = time.monotonic() - started
assert rc == 0, (rc, logs)
assert elapsed < 10, "a stalled-after-progress refresh must give up quickly too (%.1fs)" % elapsed
assert any("launching" in ln for ln in logs), logs
PY
then
    pass "a fake pull that starts and then stalls still lets the scan proceed"
else
    fail "partial-progress refresh case failed (see assertion above)"
fi

# Case 4: the fake pull exits immediately with a non-zero code (a rejected pull,
# not a stall) — also best-effort, also must not block the scan.
: > "$FAKE_DOCKER_LOG"
if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER:$PATH" FAKE_DOCKER_LOG="$FAKE_DOCKER_LOG" \
   FAKE_DOCKER_PULL_MODE=fail python3 - "$ROOT_DIR" <<'PY'
import os, sys, time
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

server._self_container_id = lambda: "selfcid000000"
server._sibling_image_present = lambda image: True

run_out = server.OUTPUT_DIR + "/run_1"
logs = []
started = time.monotonic()
rc = server.run_sibling_scan(
    "ghcr.io/sktelecom/bomlens-firmware:1.5.0", "FIRMWARE", run_out,
    logs.append, upload_file=server.UPLOAD_DIR + "/tok/fw.bin",
)
elapsed = time.monotonic() - started
assert rc == 0, (rc, logs)
assert elapsed < 5, "an immediately-failing pull must not delay the scan (%.1fs)" % elapsed
assert any("skipped" in ln for ln in logs), logs
PY
then
    pass "a fake pull that exits with an error is skipped without blocking the scan"
else
    fail "failing-pull refresh case failed (see assertion above)"
fi

# convert_bom_to_spdx's sibling scanner-image path takes the same refresh branch;
# confirm it also runs to completion with a real (fake) docker pull on PATH.
: > "$FAKE_DOCKER_LOG"
if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER:$PATH" FAKE_DOCKER_LOG="$FAKE_DOCKER_LOG" \
   FAKE_DOCKER_PULL_MODE=uptodate python3 - "$ROOT_DIR" <<'PY'
import os, sys, time
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

captured = {}
def fake_stream(args, on_log, **kw):
    captured["args"] = args
    return 0
server._stream_cmd = fake_stream
server._sibling_image_present = lambda image: True
server._self_container_id = lambda: "selfcid000000"
server.docker_cli_present = lambda: True
server.docker_capable = lambda: True
server.spdx_convert_capable = lambda: False

bom = server.OUTPUT_DIR + "/run_1/run_1_bom.json"
spdx = server.OUTPUT_DIR + "/run_1/run_1_bom.spdx.json"
started = time.monotonic()
rc = server.convert_bom_to_spdx(bom, spdx, False, lambda ln: None)
elapsed = time.monotonic() - started
assert rc == 0, rc
assert elapsed < 5, "an up-to-date refresh must not meaningfully delay SPDX export (%.1fs)" % elapsed
assert "--entrypoint" in captured["args"], captured["args"]
PY
then
    pass "the on-demand SPDX sibling also refreshes an already-present scanner image"
else
    fail "SPDX sibling refresh case failed (see assertion above)"
fi

echo "== firmware/AI sibling cancel: docker-stop-style, not raw docker kill =="
# Regression: _stream_cmd used to send a signal-less `docker
# kill` (immediate SIGKILL, zero grace) when a firmware/AI scan's client
# disconnected, giving the sibling's own cleanup no chance to run. It now
# sends `docker stop -t CANCEL_GRACE_SECONDS`, the same grace every other
# cancel path uses, driven against the real _stream_cmd (not a fake) with a
# fake docker on PATH so the actual argv it constructs is what gets checked.
: > "$FAKE_DOCKER_LOG"
if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER:$PATH" FAKE_DOCKER_LOG="$FAKE_DOCKER_LOG" \
   python3 - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

logs = []
rc = server._stream_cmd(
    ["sh", "-c", "echo hi; sleep 30"],
    logs.append,
    cancel=lambda: True,
    container="fake-container-123",
)
with open(os.environ["FAKE_DOCKER_LOG"]) as fh:
    calls = fh.read()
assert "docker kill" not in calls, calls
assert "docker stop -t %d fake-container-123" % server.CANCEL_GRACE_SECONDS in calls, calls
PY
then
    pass "cancelling a firmware/AI sibling scan emits docker stop, not docker kill"
else
    fail "firmware/AI sibling cancel did not use docker-stop-style argv"
fi

echo "== image download size estimate matches the host docker architecture =="
# _image_download_bytes() used to always read the amd64 entry off a multi-arch
# manifest, regardless of the daemon that would actually pull the image. A
# fake `docker` on PATH stands in both for `docker version` (the daemon's
# reported architecture) and `docker manifest inspect --verbose` (the
# per-platform layer sizes), so this checks host-architecture matching,
# aarch64/x86_64 alias normalization, and the amd64 fallback (a manifest that
# has not published the host's architecture yet, or a daemon that cannot be
# asked) without a real docker or registry.
FAKEDOCKER2="$WORK/fakedockerbin2"; mkdir -p "$FAKEDOCKER2"
MANIFEST_MULTI="$WORK/manifest-multi.json"
cat > "$MANIFEST_MULTI" <<'JSON'
[
  {"Descriptor": {"platform": {"architecture": "amd64", "os": "linux"}},
   "SchemaV2Manifest": {"layers": [{"size": 100000000}]}},
  {"Descriptor": {"platform": {"architecture": "arm64", "os": "linux"}},
   "SchemaV2Manifest": {"layers": [{"size": 222000000}]}}
]
JSON
MANIFEST_SINGLE_AMD64="$WORK/manifest-single-amd64.json"
cat > "$MANIFEST_SINGLE_AMD64" <<'JSON'
{"Descriptor": {"platform": {"architecture": "amd64", "os": "linux"}},
 "SchemaV2Manifest": {"layers": [{"size": 50000000}]}}
JSON
cat > "$FAKEDOCKER2/docker" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  version)
    if [ "${DOCKER_STUB_VERSION_FAIL:-0}" = "1" ]; then
      echo "Error: cannot connect to the Docker daemon" >&2
      exit 1
    fi
    if [ -n "${VERSION_FAIL_ONCE_MARKER:-}" ] && [ ! -f "$VERSION_FAIL_ONCE_MARKER" ]; then
      : > "$VERSION_FAIL_ONCE_MARKER"
      echo "Error: cannot connect to the Docker daemon (not up yet)" >&2
      exit 1
    fi
    echo "${DOCKER_STUB_ARCH:-amd64}"
    exit 0
    ;;
  manifest)
    case "${4:-}" in
      *multi-arch-image*) cat "$MANIFEST_MULTI_FILE" ;;
      *single-arch-image*) cat "$MANIFEST_SINGLE_FILE" ;;
      *) echo '{}' ;;
    esac
    exit 0
    ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$FAKEDOCKER2/docker"

if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER2:$PATH" \
   MANIFEST_MULTI_FILE="$MANIFEST_MULTI" MANIFEST_SINGLE_FILE="$MANIFEST_SINGLE_AMD64" \
   DOCKER_STUB_ARCH=arm64 python3 - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

multi = server._image_download_bytes("ghcr.io/sktelecom/multi-arch-image:latest")
assert multi == 222000000, multi
single = server._image_download_bytes("ghcr.io/sktelecom/single-arch-image:latest")
assert single == 50000000, single
PY
then
    pass "an arm64 daemon gets the arm64 entry, and falls back to the amd64 entry when arm64 was never published"
else
    fail "arm64-daemon size selection did not match expectations"
fi

if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER2:$PATH" \
   MANIFEST_MULTI_FILE="$MANIFEST_MULTI" MANIFEST_SINGLE_FILE="$MANIFEST_SINGLE_AMD64" \
   DOCKER_STUB_ARCH=aarch64 python3 - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

size = server._image_download_bytes("ghcr.io/sktelecom/multi-arch-image:latest")
assert size == 222000000, size
PY
then
    pass "a daemon reporting uname-style aarch64 is normalized to the arm64 manifest entry"
else
    fail "aarch64-to-arm64 normalization did not select the arm64 entry"
fi

if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER2:$PATH" \
   MANIFEST_MULTI_FILE="$MANIFEST_MULTI" MANIFEST_SINGLE_FILE="$MANIFEST_SINGLE_AMD64" \
   DOCKER_STUB_ARCH=x86_64 python3 - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

size = server._image_download_bytes("ghcr.io/sktelecom/multi-arch-image:latest")
assert size == 100000000, size
PY
then
    pass "a daemon reporting uname-style x86_64 is normalized to the amd64 manifest entry"
else
    fail "x86_64-to-amd64 normalization did not select the amd64 entry"
fi

if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER2:$PATH" \
   MANIFEST_MULTI_FILE="$MANIFEST_MULTI" MANIFEST_SINGLE_FILE="$MANIFEST_SINGLE_AMD64" \
   DOCKER_STUB_VERSION_FAIL=1 python3 - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

size = server._image_download_bytes("ghcr.io/sktelecom/multi-arch-image:latest")
assert size == 100000000, size
PY
then
    pass "a daemon that cannot report its architecture falls back to the amd64 entry"
else
    fail "a failed docker version call did not fall back to the amd64 entry"
fi

# The failure above must not be cached: the web UI or desktop app can start
# before Docker Desktop/Colima itself is up, so the first `docker version`
# call can fail transiently. Only a value actually read gets cached; a failed
# call falls back to amd64 for that one call and tries again next time.
if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER2:$PATH" \
   MANIFEST_MULTI_FILE="$MANIFEST_MULTI" MANIFEST_SINGLE_FILE="$MANIFEST_SINGLE_AMD64" \
   VERSION_FAIL_ONCE_MARKER="$WORK/version-fail-once-marker" DOCKER_STUB_ARCH=arm64 \
   python3 - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

first = server._host_docker_architecture()
assert first == "amd64", first
assert server._host_arch_cache is None, server._host_arch_cache

second = server._host_docker_architecture()
assert second == "arm64", second
assert server._host_arch_cache == "arm64", server._host_arch_cache
PY
then
    pass "a docker version call that fails once (daemon not up yet) is not cached, so the next call reads the real architecture"
else
    fail "a transient docker-version failure poisoned the architecture cache with amd64"
fi

# The same failure, one level up: _image_download_bytes() must not cache the
# amd64-guess size it computes while the architecture read is still failing,
# or the process would show that wrong size for this image forever even once
# the daemon comes up.
if SBOM_OUTPUT_DIR="$OUT" PATH="$FAKEDOCKER2:$PATH" \
   MANIFEST_MULTI_FILE="$MANIFEST_MULTI" MANIFEST_SINGLE_FILE="$MANIFEST_SINGLE_AMD64" \
   VERSION_FAIL_ONCE_MARKER="$WORK/version-fail-once-marker-2" DOCKER_STUB_ARCH=arm64 \
   python3 - "$ROOT_DIR" <<'PY'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "docker", "web"))
import server

image = "ghcr.io/sktelecom/multi-arch-image:latest"
first = server._image_download_bytes(image)
assert first == 100000000, first  # amd64 guess: the daemon was not up yet
assert image not in server._download_size_cache, server._download_size_cache

second = server._image_download_bytes(image)
assert second == 222000000, second  # daemon is up now: the real arm64 size
assert server._download_size_cache[image] == 222000000, server._download_size_cache
PY
then
    pass "a download-size estimate made while the daemon was not up yet is not cached, and is recomputed correctly once it is"
else
    fail "an amd64 guess from a not-yet-ready daemon was cached as the image's download size"
fi

echo "== supplier VEX verdicts (POST /vex-verdict) =="
# vex_1.0: one finding with a purl (foo), one Trivy resolved no PkgIdentifier
# for (bar) -- exercises both join keys _vex_verdict_index uses.
cat > "$OUT/vex_1.0_bom.json" <<'JSON'
{"bomFormat":"CycloneDX","metadata":{"component":{"name":"vex","version":"1.0"}},
 "components":[{"name":"foo","version":"1.0","type":"library","purl":"pkg:npm/foo@1.0"},
               {"name":"bar","version":"2.0","type":"library"}]}
JSON
cat > "$OUT/vex_1.0_security.json" <<'JSON'
{"Results":[{"Vulnerabilities":[
  {"VulnerabilityID":"CVE-2024-10001","Severity":"HIGH","PkgName":"foo","InstalledVersion":"1.0",
   "PkgIdentifier":{"PURL":"pkg:npm/foo@1.0"}},
  {"VulnerabilityID":"CVE-2024-10002","Severity":"LOW","PkgName":"bar","InstalledVersion":"2.0"}
]}]}
JSON

# -- adversarial cases: none of these may write vex_1.0_vex.json --
bad_id=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -d '{"cve":"CVE-2024-10001","state":"fixed","purl":"pkg:npm/foo@1.0"}' \
    "$BASE/vex-verdict?id=../../etc/passwd")
[ "$bad_id" = "400" ] && pass "/vex-verdict blocks a traversal scan id (400)" || fail "traversal id returned $bad_id (expected 400)"

missing_scan=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -d '{"cve":"CVE-2024-10001","state":"fixed","purl":"pkg:npm/foo@1.0"}' \
    "$BASE/vex-verdict?id=vex_nosuchscan_1.0")
[ "$missing_scan" = "404" ] && pass "/vex-verdict 404s for a scan with no _bom.json" || fail "nonexistent scan returned $missing_scan (expected 404)"

bad_json=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -d '{not json' "$BASE/vex-verdict?id=vex_1.0")
[ "$bad_json" = "400" ] && pass "/vex-verdict rejects malformed JSON (400)" || fail "malformed JSON returned $bad_json (expected 400)"

bad_state=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -d '{"cve":"CVE-2024-10001","state":"definitely_affected","purl":"pkg:npm/foo@1.0"}' \
    "$BASE/vex-verdict?id=vex_1.0")
[ "$bad_state" = "400" ] && pass "/vex-verdict rejects an unrecognized state (400)" || fail "bad state returned $bad_state (expected 400)"

bad_cve=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -d '{"cve":"not-an-advisory-id","state":"fixed","purl":"pkg:npm/foo@1.0"}' \
    "$BASE/vex-verdict?id=vex_1.0")
[ "$bad_cve" = "400" ] && pass "/vex-verdict rejects a CVE id outside the known advisory namespaces (400)" || fail "bad cve id returned $bad_cve (expected 400)"

no_identity=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -d '{"cve":"CVE-2024-10001","state":"fixed"}' "$BASE/vex-verdict?id=vex_1.0")
[ "$no_identity" = "400" ] && pass "/vex-verdict rejects a verdict with neither purl nor pkg+installed (400)" || fail "no component identity returned $no_identity (expected 400)"

big_detail=$(python3 -c "import json; print(json.dumps({'cve':'CVE-2024-10001','state':'fixed','purl':'pkg:npm/foo@1.0','detail':'x'*3000}))")
oversized=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -d "$big_detail" "$BASE/vex-verdict?id=vex_1.0")
[ "$oversized" = "400" ] && pass "/vex-verdict rejects a detail note over the length cap (400)" || fail "oversized detail returned $oversized (expected 400)"

cross_origin=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Content-Type: application/json" \
    -H "Origin: http://evil.example" \
    -d '{"cve":"CVE-2024-10001","state":"fixed","purl":"pkg:npm/foo@1.0"}' \
    "$BASE/vex-verdict?id=vex_1.0")
[ "$cross_origin" = "403" ] && pass "a cross-site Origin on /vex-verdict is rejected (403)" || fail "cross-site Origin returned $cross_origin (expected 403)"

[ -f "$OUT/vex_1.0_vex.json" ] && fail "an adversarial /vex-verdict request wrote a sidecar anyway" "$(cat "$OUT/vex_1.0_vex.json")" \
    || pass "no _vex.json sidecar was written by any of the rejected requests above"

# -- a real save, then read it back through the same summary the UI consumes --
save_resp=$(curl -fsS -X POST -H "Content-Type: application/json" \
    -d '{"cve":"CVE-2024-10001","state":"not_affected","purl":"pkg:npm/foo@1.0","detail":"not reachable from our code"}' \
    "$BASE/vex-verdict?id=vex_1.0")
echo "$save_resp" | python3 -c "
import sys, json
r = json.load(sys.stdin)
assert r['ok'] is True, r
v = r['verdict']
assert v['state'] == 'not_affected', v
assert v['detail'] == 'not reachable from our code', v
assert v['source'] == 'user', v
assert v['firstRecordedAt'] == v['updatedAt'], v  # first save: identical
" && pass "a valid /vex-verdict save returns the stored record" || fail "save response is wrong" "$save_resp"

# The fallback-keyed CVE (no purl in the Trivy finding) saved by pkg+installed.
curl -fsS -X POST -H "Content-Type: application/json" \
    -d '{"cve":"CVE-2024-10002","state":"under_investigation","pkg":"bar","installed":"2.0"}' \
    "$BASE/vex-verdict?id=vex_1.0" >/dev/null

if curl -fsS "$BASE/scan?id=vex_1.0" 2>/dev/null | python3 -c "
import sys, json
vulns = {v['id']: v for v in json.load(sys.stdin)['security']['vulnerabilities']}
assert vulns['CVE-2024-10001']['vexState'] == 'not_affected', vulns['CVE-2024-10001']
assert vulns['CVE-2024-10001']['vexDetail'] == 'not reachable from our code', vulns['CVE-2024-10001']
assert vulns['CVE-2024-10002']['vexState'] == 'under_investigation', vulns['CVE-2024-10002']
# the vendor Status axis (absent here) and the supplier's own vexState are
# separate fields -- saving one must not invent or touch the other.
assert 'status' not in vulns['CVE-2024-10001'], vulns['CVE-2024-10001']
"; then
    pass "saved verdicts are joined onto the matching vulnerability rows (purl and pkg+installed both)"
else
    fail "verdicts did not join back onto /scan?id= as expected"
fi

# Editing the same (purl, cve) verdict updates in place -- one record, not two
# -- and keeps the original firstRecordedAt.
first_recorded=$(python3 -c "import json; print(json.load(open('$OUT/vex_1.0_vex.json'))['verdicts'][0]['firstRecordedAt'])")
curl -fsS -X POST -H "Content-Type: application/json" \
    -d '{"cve":"CVE-2024-10001","state":"affected","purl":"pkg:npm/foo@1.0","detail":"reassessed"}' \
    "$BASE/vex-verdict?id=vex_1.0" >/dev/null
if python3 -c "
import json
d = json.load(open('$OUT/vex_1.0_vex.json'))
matching = [v for v in d['verdicts'] if v['cve'] == 'CVE-2024-10001']
assert len(matching) == 1, matching  # updated in place, not appended
v = matching[0]
assert v['state'] == 'affected', v
assert v['detail'] == 'reassessed', v
assert v['firstRecordedAt'] == '$first_recorded', v
assert v['updatedAt'] >= v['firstRecordedAt'], v
"; then
    pass "re-saving the same verdict updates it in place and keeps firstRecordedAt"
else
    fail "re-saving the same verdict duplicated it or lost firstRecordedAt"
fi

# When a request carries both purl and pkg+installed, purl decides the key on
# write, exactly as it does on read (a row is looked up by its own purl first,
# falling back to name+installed only when the row has none). A mismatched
# pkg/installed sent alongside the real purl must not fork off a second record
# or move the join off the purl-keyed one.
curl -fsS -X POST -H "Content-Type: application/json" \
    -d '{"cve":"CVE-2024-10001","state":"fixed","purl":"pkg:npm/foo@1.0","pkg":"someone-elses-name","installed":"9.9.9"}' \
    "$BASE/vex-verdict?id=vex_1.0" >/dev/null
if python3 -c "
import json
d = json.load(open('$OUT/vex_1.0_vex.json'))
matching = [v for v in d['verdicts'] if v['cve'] == 'CVE-2024-10001']
assert len(matching) == 1, matching  # still one record, updated not forked
assert matching[0]['state'] == 'fixed', matching[0]
"; then
    pass "purl and pkg+installed sent together key on purl alone, on write"
else
    fail "sending purl alongside a mismatched pkg+installed forked the record"
fi
if curl -fsS "$BASE/scan?id=vex_1.0" 2>/dev/null | python3 -c "
import sys, json
vulns = {v['id']: v for v in json.load(sys.stdin)['security']['vulnerabilities']}
assert vulns['CVE-2024-10001']['vexState'] == 'fixed', vulns['CVE-2024-10001']
"; then
    pass "the purl-keyed write above still joins back through the purl-keyed read"
else
    fail "the purl-preferring write did not join back on read"
fi

curl -fsS -X POST "$BASE/scan-delete?id=vex_1.0" >/dev/null 2>&1
[ -f "$OUT/vex_1.0_vex.json" ] && fail "/scan-delete left the VEX sidecar behind" \
    || pass "/scan-delete removes the VEX verdict sidecar along with the rest of the scan"

echo "== external vulnerability lookup (GET /advisory, GET /package-advisories) =="
# Three dedicated server instances so these tests never touch the real
# api.osv.dev: one backed by a canned stub (success paths + input validation,
# which must 400 before any request would be dispatched), one with the
# feature off, one pointed at an address that refuses the connection outright
# (the offline path, distinct from "OSV said no").
cat > "$WORK/osv-stub.py" <<'STUBPY'
import json, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
VULNS = {
    "CVE-TEST-CVSS3": {
        "id": "CVE-TEST-CVSS3", "summary": "cvss3 test", "details": "d" * 50,
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "references": [{"url": "https://example.com/%d" % i} for i in range(20)],
        "aliases": ["GHSA-xxxx"], "modified": "2024-01-01T00:00:00Z", "published": "2023-01-01T00:00:00Z",
        "affected": [{"package": {"ecosystem": "npm", "name": "foo"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]}],
    },
    "CVE-TEST-DBSEV": {
        "id": "CVE-TEST-DBSEV", "summary": "db severity test",
        "database_specific": {"severity": "CRITICAL"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}],
    },
    "CVE-TEST-CVSS4": {
        "id": "CVE-TEST-CVSS4", "summary": "cvss4 only",
        "severity": [{"type": "CVSS_V4",
                      "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
    },
    "CVE-TEST-LONG": {
        "id": "CVE-TEST-LONG", "summary": "long test", "details": "x" * 5000,
        "references": [{"url": "https://example.com/%d" % i} for i in range(50)],
    },
}
QUERY = {
    "pkg-with-more-pages": {"vulns": [VULNS["CVE-TEST-CVSS3"]], "next_page_token": "abc"},
    "pkg-clean": {"vulns": []},
}

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        b = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.startswith("/v1/vulns/"):
            v = VULNS.get(self.path[len("/v1/vulns/"):])
            self._send(200, v) if v else self._send(404, {"code": 5, "message": "not found"})
        else:
            self._send(404, {})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        name = (body.get("package") or {}).get("name")
        self._send(200, QUERY.get(name, {"vulns": []}))

    def log_message(self, fmt, *args):
        pass

ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
STUBPY

OSVSTUB_PORT=$((PORT + 2))
python3 "$WORK/osv-stub.py" "$OSVSTUB_PORT" > "$WORK/osv-stub.log" 2>&1 &
OSVSTUB_PID=$!
disown "$OSVSTUB_PID" 2>/dev/null || true

PORT3=$((PORT + 3)); BASE3="http://127.0.0.1:${PORT3}"; OUT3="$WORK/out3"; mkdir -p "$OUT3"
OSV_API_BASE="http://127.0.0.1:${OSVSTUB_PORT}" SBOM_OUTPUT_DIR="$OUT3" UI_PORT="$PORT3" \
    python3 "$SERVER" > "$WORK/server3.log" 2>&1 &
SRV3_PID=$!
disown "$SRV3_PID" 2>/dev/null || true

PORT4=$((PORT + 4)); BASE4="http://127.0.0.1:${PORT4}"; OUT4="$WORK/out4"; mkdir -p "$OUT4"
EXTERNAL_LOOKUP=false OSV_API_BASE="http://127.0.0.1:1" SBOM_OUTPUT_DIR="$OUT4" UI_PORT="$PORT4" \
    python3 "$SERVER" > "$WORK/server4.log" 2>&1 &
SRV4_PID=$!
disown "$SRV4_PID" 2>/dev/null || true

PORT5=$((PORT + 5)); BASE5="http://127.0.0.1:${PORT5}"; OUT5="$WORK/out5"; mkdir -p "$OUT5"
OSV_API_BASE="http://127.0.0.1:1" SBOM_OUTPUT_DIR="$OUT5" UI_PORT="$PORT5" \
    python3 "$SERVER" > "$WORK/server5.log" 2>&1 &
SRV5_PID=$!
disown "$SRV5_PID" 2>/dev/null || true

cleanup_osv() {
    for p in "$OSVSTUB_PID" "$SRV3_PID" "$SRV4_PID" "$SRV5_PID"; do
        [ -n "$p" ] && kill "$p" 2>/dev/null
    done
}
trap 'cleanup_osv; cleanup2; cleanup' EXIT

ready3=0
for _ in $(seq 1 30); do
    if curl -fsS "$BASE3/capabilities" >/dev/null 2>&1; then ready3=1; break; fi
    kill -0 "$SRV3_PID" 2>/dev/null || { echo "[ERROR] lookup server exited early:"; cat "$WORK/server3.log"; exit 1; }
    sleep 0.3
done
[ "$ready3" = 1 ] && pass "OSV-stub-backed server is up" || { fail "OSV-stub-backed server did not become ready" "$(tail -5 "$WORK/server3.log")"; exit 1; }
for base in "$BASE4" "$BASE5"; do
    ok=0
    for _ in $(seq 1 30); do
        if curl -fsS "$base/capabilities" >/dev/null 2>&1; then ok=1; break; fi
        sleep 0.3
    done
    [ "$ok" = 1 ] || { fail "server at $base did not become ready"; exit 1; }
done

echo "-- input validation (400 before any OSV request is made) --"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE3/advisory?id=../../etc/passwd")
[ "$code" = "400" ] && pass "/advisory rejects a traversal id" || fail "/advisory traversal id returned $code (expected 400)"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE3/advisory?id=")
[ "$code" = "400" ] && pass "/advisory rejects an empty id" || fail "/advisory empty id returned $code (expected 400)"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE3/advisory?id=CVE-$(printf '1%.0s' $(seq 1 70))")
[ "$code" = "400" ] && pass "/advisory rejects an id over 64 chars" || fail "/advisory long id returned $code (expected 400)"
code=$(curl -s -o /dev/null -w '%{http_code}' -G "$BASE3/advisory" --data-urlencode $'id=CVE-2021-44228\r\nX-Injected: 1')
[ "$code" = "400" ] && pass "/advisory rejects an id with CR/LF" || fail "/advisory CRLF id returned $code (expected 400)"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE3/advisory?id=UNKNOWN-1234")
[ "$code" = "400" ] && pass "/advisory rejects an id with an unrecognized prefix" || fail "/advisory unknown-prefix id returned $code (expected 400)"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE3/package-advisories?ecosystem=bogus&name=lodash&version=4.17.20")
[ "$code" = "400" ] && pass "/package-advisories rejects an unknown ecosystem slug" || fail "/package-advisories bogus ecosystem returned $code (expected 400)"
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE3/package-advisories?ecosystem=npm&name=lodash")
[ "$code" = "400" ] && pass "/package-advisories rejects a missing required parameter" || fail "/package-advisories missing version returned $code (expected 400)"
code=$(curl -s -o /dev/null -w '%{http_code}' -G "$BASE3/package-advisories" --data-urlencode "ecosystem=npm" --data-urlencode $'name=lo\x01dash' --data-urlencode "version=1.0.0")
[ "$code" = "400" ] && pass "/package-advisories rejects a control character in name" || fail "/package-advisories control-char name returned $code (expected 400)"

echo "-- disabled feature: 403 with no OSV request ever attempted --"
if curl -fsS "$BASE4/capabilities" 2>/dev/null | python3 -c "import sys,json;assert json.load(sys.stdin)['externalLookup'] is False" 2>/dev/null; then
    pass "/capabilities reports externalLookup false when EXTERNAL_LOOKUP=false"
else
    fail "/capabilities externalLookup should be false"
fi
code=$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' "$BASE4/advisory?id=CVE-2021-44228")
[ "$code" = "403" ] && pass "/advisory is disabled (403) and OSV_API_BASE (unreachable) is never contacted" || fail "/advisory disabled returned $code (expected 403)"
code=$(curl -s --max-time 3 -o /dev/null -w '%{http_code}' "$BASE4/package-advisories?ecosystem=npm&name=lodash&version=4.17.20")
[ "$code" = "403" ] && pass "/package-advisories is disabled (403)" || fail "/package-advisories disabled returned $code (expected 403)"

echo "-- offline: connection refused surfaces as 503, fast --"
code=$(curl -s --max-time 3 -o "$WORK/osv-offline-body" -w '%{http_code}' "$BASE5/advisory?id=CVE-2021-44228")
if [ "$code" = "503" ] && grep -q '"offline"' "$WORK/osv-offline-body"; then
    pass "/advisory reports offline (503) when OSV cannot be reached, well under the timeout"
else
    fail "/advisory offline path returned $code" "$(cat "$WORK/osv-offline-body")"
fi

echo "-- successful lookups against the OSV stub --"
body=$(curl -fsS "$BASE3/advisory?id=CVE-TEST-CVSS3" 2>/dev/null)
if echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['found'] is True, d
assert d['severity'] == 'CRITICAL', d
assert d['cvss'] == 9.8, d
assert d['cvssVector'] == 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', d
assert d['source'] == 'osv', d
assert len(d['refs']) == 12, d
"; then
    pass "/advisory computes a CVSS 3.1 base score from OSV's vector"
else
    fail "/advisory CVSS_V3 score computation failed" "$body"
fi

body=$(curl -fsS "$BASE3/advisory?id=CVE-TEST-DBSEV" 2>/dev/null)
if echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['severity'] == 'CRITICAL', d
assert d['cvss'] is None, d
"; then
    pass "/advisory prefers database_specific.severity over a computed score"
else
    fail "/advisory database_specific.severity priority failed" "$body"
fi

body=$(curl -fsS "$BASE3/advisory?id=CVE-TEST-CVSS4" 2>/dev/null)
if echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['severity'] == 'UNKNOWN', d
assert d['cvss'] is None, d
assert d['cvssVector'].startswith('CVSS:4.0'), d
"; then
    pass "/advisory leaves cvss null for a CVSS_V4-only vector, but keeps the vector"
else
    fail "/advisory CVSS_V4-only handling failed" "$body"
fi

body=$(curl -fsS "$BASE3/advisory?id=CVE-2099-00000" 2>/dev/null)
if echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d == {'id': 'CVE-2099-00000', 'found': False, 'source': 'osv'}, d
"; then
    pass "/advisory turns an OSV 404 into a normal found:false result, not an error"
else
    fail "/advisory 404 handling failed" "$body"
fi

body=$(curl -fsS "$BASE3/advisory?id=CVE-TEST-LONG" 2>/dev/null)
if echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert len(d['description']) == 600, len(d['description'])
assert len(d['refs']) == 12, len(d['refs'])
"; then
    pass "/advisory caps description and refs length"
else
    fail "/advisory length caps failed" "$body"
fi

body=$(curl -fsS "$BASE3/package-advisories?ecosystem=npm&name=pkg-with-more-pages&version=1.0.0" 2>/dev/null)
if echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['found'] is True, d
assert len(d['items']) == 1, d
assert d['truncated'] is True, d
"; then
    pass "/package-advisories reports truncated:true when OSV returns a next_page_token"
else
    fail "/package-advisories truncation flag failed" "$body"
fi

body=$(curl -fsS "$BASE3/package-advisories?ecosystem=npm&name=pkg-clean&version=1.0.0" 2>/dev/null)
if echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d == {'found': False, 'items': [], 'truncated': False}, d
"; then
    pass "/package-advisories reports found:false with no vulnerabilities"
else
    fail "/package-advisories clean-package handling failed" "$body"
fi

echo "== stale upload sweep: really wired to GET /scans and POST /upload, not just callable =="
# Every assertion above calls _sweep_stale_uploads() directly. This is the
# black-box check that the two real HTTP endpoints actually reach it: a
# pre-aged upload dir created before its server even starts (no need to wait
# out the real TTL), then one real curl call. Each endpoint gets its OWN
# freshly started server so the 5-minute sweep throttle -- a module-global
# that starts at 0 for a brand new process -- can never make the second
# server's first sweep call a no-op regardless of what the first one did.
#
# $1 = port offset, $2 = "scans" or "upload"; PASS/FAIL directly via pass/fail.
sweep_wiring_check() {
    local port out token srv_pid rdy curl_out curl_rc swept
    port="$((PORT + $1))"
    out="$WORK/out$1"
    token="ffeeddccbbaa99887766554433221100"
    mkdir -p "$out/.uploads/$token"
    : > "$out/.uploads/$token/f"
    python3 - "$out/.uploads/$token" <<'PY'
import os, sys, time
old = time.time() - 7200
os.utime(sys.argv[1], (old, old))
PY
    SBOM_OUTPUT_DIR="$out" UI_PORT="$port" SBOM_UPLOAD_TTL_HOURS=1 \
        python3 "$SERVER" > "$WORK/server$1.log" 2>&1 &
    srv_pid=$!
    disown "$srv_pid" 2>/dev/null || true
    rdy=0
    for _ in $(seq 1 30); do
        if curl -fsS "http://127.0.0.1:${port}/capabilities" >/dev/null 2>&1; then rdy=1; break; fi
        kill -0 "$srv_pid" 2>/dev/null || break
        sleep 0.3
    done
    if [ "$rdy" != 1 ]; then
        fail "wiring-test server (port offset $1) did not start" "$(cat "$WORK/server$1.log" 2>/dev/null)"
        kill "$srv_pid" 2>/dev/null
        return
    fi
    if [ "$2" = "scans" ]; then
        curl_out=$(curl -sS -w '\nHTTP_CODE=%{http_code}' "http://127.0.0.1:${port}/scans" 2>&1)
    else
        curl_out=$(curl -sS -w '\nHTTP_CODE=%{http_code}' -F "kind=zip" -F "file=@$SERVER;filename=x.zip" \
            "http://127.0.0.1:${port}/upload?kind=zip" 2>&1)
    fi
    curl_rc=$?
    # Deliberately runs AFTER self._send() (so a large rmtree never delays the
    # response), which means curl returning is not proof the sweep has run
    # yet -- the client can see the full response body before the server
    # thread gets past that line. Poll briefly instead of checking once.
    swept=0
    for _ in $(seq 1 20); do
        [ -d "$out/.uploads/$token" ] || { swept=1; break; }
        sleep 0.1
    done
    if [ "$swept" = 1 ]; then
        pass "a real HTTP call to $2 sweeps a pre-aged stale upload"
    else
        fail "a real HTTP GET/POST to $2 did not sweep a real pre-aged stale upload" \
            "curl exit=$curl_rc: $curl_out"
    fi
    kill "$srv_pid" 2>/dev/null
}
sweep_wiring_check 6 scans
sweep_wiring_check 7 upload

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
