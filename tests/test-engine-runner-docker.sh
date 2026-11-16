#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-engine-runner-docker.sh - the engine runner's Docker backend for real.
#
# Runs bomlens_runner against the local Docker daemon, with the workspace as
# a host folder (bind) and then as a named volume mounted by subpath:
#   - a source scan of examples/nodejs: plan, stage 1, stage 2, the result
#     manifest checked, no container left, the source tree unchanged;
#   - a cancelled scan: no container left, the source unchanged;
#   - an image scan of a small public image.
#
# Usage: BOMLENS_TEST_IMAGE=<image with a repo digest> tests/test-engine-runner-docker.sh
# The image must have a registry digest (pull it, or push it to a registry):
# the runner runs repository@sha256 only. Needs docker, python3 (3.10+), jq.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${BOMLENS_TEST_IMAGE:?set BOMLENS_TEST_IMAGE}"
NET=bomlens-runner-egress
VOL=bomlens-runner-ws
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
tree_hash() { (cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 cat | sha | cut -d' ' -f1); }

for tool in docker python3 jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "[ERROR] $tool is required"; exit 1; }
done
ENGINE="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$IMAGE" | head -1)"
[ -n "$ENGINE" ] || { echo "[ERROR] $IMAGE has no repository digest"; exit 1; }
tag="${IMAGE##*:}"; [ "$tag" = "$IMAGE" ] && tag=latest
ENGINE="${ENGINE%@*}:${tag}@${ENGINE#*@}"
echo "engine image: $ENGINE"

WORK="$(mktemp -d "${KIND_WORK_BASE:-${TMPDIR:-/tmp}}/bomlens-docker.XXXXXX")"
cleanup() {
    [ -n "${KEEP_WORK:-}" ] && { echo "Kept: $WORK"; return; }
    docker ps -aq --filter label=app.kubernetes.io/part-of=bomlens-engine --filter label=example.com/suite=docker \
        | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    # Stage 1 wrote some of these as root; the image's entrypoint is not sh.
    docker run --rm --entrypoint sh -v "$WORK:/w" "$IMAGE" -c 'rm -rf /w/*' >/dev/null 2>&1 || true
    docker volume rm "$VOL" >/dev/null 2>&1 || true
    rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
docker network create "$NET" >/dev/null 2>&1 || true
WS="$WORK/ws"; mkdir -p "$WS"

# A subshell that becomes the python process (exec), so a signal sent to the
# background job's pid reaches the runner.
run_scan() (  # run_scan <strategy> <workspace> <command> <args...>
    strategy="$1" workspace="$2"; shift 2
    PIDFILE="${PIDFILE:-}" PYTHONPATH="$ROOT_DIR/runner/src" STRATEGY="$strategy" WSV="$workspace" WSROOT="$WS" ENGINE="$ENGINE" NET="$NET" \
        exec python3 - "$@" <<'PY'
import json, os, signal, sys, threading
from pathlib import Path
from bomlens_runner import Images, RunnerPolicy, Volume, run_image_scan, run_source_scan, BomLensError
from bomlens_runner.docker import DockerBackend, DockerCli, DockerOptions


class LoggingCli(DockerCli):
    """Prints a failed docker command's error, so a failure here says why."""

    def run(self, argv, timeout):
        done = super().run(argv, timeout)
        if done.returncode != 0 and argv[0] not in ("image", "inspect", "rm"):
            print(f"[docker {argv[0]}] " + done.stderr.decode("utf-8", "replace").strip()[:500], file=sys.stderr)
        return done


cancel = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: cancel.set())
if os.environ.get("PIDFILE"):
    Path(os.environ["PIDFILE"]).write_text(str(os.getpid()))
policy = RunnerPolicy(images=Images.parse(os.environ["ENGINE"]), workspace=Volume("ws", Path(os.environ["WSROOT"])),
                      uid=os.getuid(), gid=os.getgid(), 
                      stage2_env={"GENERATE_SECURITY": "false", "ENRICH_EOL": "false"},
                      image_env={"GENERATE_SECURITY": "false"})
backend = DockerBackend(DockerOptions(volume_strategy=os.environ["STRATEGY"], workspace=os.environ["WSV"],
                                      egress_network=os.environ["NET"], instance_labels={"example.com/suite": "docker"}),
                        cli=LoggingCli())
cmd, scan_id, scan_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
log = lambda stage, line: print(f"[{stage}] {line}", file=sys.stderr, flush=True)
try:
    if cmd == "source":
        r = run_source_scan(policy, backend, scan_id=scan_id, project="demo", version="1.0", scan_dir=scan_dir,
                            source=scan_dir / "src", on_log=log, cancel=cancel.is_set)
    else:
        r = run_image_scan(policy, backend, scan_id=scan_id, target=sys.argv[4], project="alpine", version="3.20",
                           scan_dir=scan_dir, on_log=log, cancel=cancel.is_set)
except BomLensError as exc:
    print(json.dumps({"error": type(exc).__name__, "message": str(exc)}))
    sys.exit(1)
print(json.dumps({"output_dir": str(r.output_dir), **r.as_metadata()}))
PY
)
live() { docker ps --all -q --filter label=example.com/suite=docker --filter "label=bomlens.engine/scan=$1" | wc -l | tr -d ' '; }

source_scan() {  # source_scan <strategy> <workspace> <scan id>
    local strategy="$1" workspace="$2" id="$3" d="$WS/$3"
    echo "== source scan ($strategy) =="
    mkdir -p "$d"; cp -R "$ROOT_DIR/examples/nodejs" "$d/src"
    local before rc out n
    before="$(tree_hash "$d/src")"
    set +e
    run_scan "$strategy" "$workspace" source "$id" "$d" > "$WORK/$id.json" 2> "$WORK/$id.log"
    rc=$?
    set -e
    [ "$rc" = 0 ] && pass "$strategy: the source scan exits 0" \
        || fail "$strategy: exit $rc" "$(cat "$WORK/$id.json"; grep -v '^\[cdxgen\]' "$WORK/$id.log" | tail -15)"
    case "$(jq -r .run_status "$WORK/$id.json" 2>/dev/null)" in
        succeeded|succeeded_degraded) pass "$strategy: run status $(jq -r .run_status "$WORK/$id.json")" ;;
        *) fail "$strategy: run status $(jq -r .run_status "$WORK/$id.json" 2>/dev/null)" \
               "$(jq -c .stages "$WORK/$id.json" 2>/dev/null | cut -c1-600; grep -v '^\[cdxgen\]' "$WORK/$id.log" | tail -25)" ;;
    esac
    out="$(jq -r '.output_dir // empty' "$WORK/$id.json")"
    n="$(jq '.components | length' "$out/demo_1.0_bom.json" 2>/dev/null || echo 0)"
    [ "${n:-0}" -ge 5 ] && pass "$strategy: the SBOM has $n components" || fail "$strategy: the SBOM has ${n:-no} components"
    [ "$(tree_hash "$d/src")" = "$before" ] && pass "$strategy: the source tree is unchanged" || fail "$strategy: the source changed"
    [ "$(live "$id")" = 0 ] && pass "$strategy: no container is left" || fail "$strategy: containers left"
}

source_scan bind "$WS" d1

# Named volume: the same folder, as a volume that binds it, mounted by subpath.
docker volume create --driver local --opt type=none --opt o=bind --opt "device=$WS" "$VOL" >/dev/null
source_scan named "$VOL" d2

echo "== cancel =="
mkdir -p "$WS/d3"; cp -R "$ROOT_DIR/examples/nodejs" "$WS/d3/src"
before="$(tree_hash "$WS/d3/src")"
PIDFILE="$WORK/d3.pid" run_scan bind "$WS" source d3 "$WS/d3" > "$WORK/d3.json" 2> "$WORK/d3.log" &
rpid=$!
for _ in $(seq 1 120); do
    [ -n "$(docker ps -q --filter label=bomlens.engine/scan=d3 --filter label=app.kubernetes.io/component=engine-stage1)" ] && break
    sleep 1
done
sleep 3
# The runner writes its own pid: the job's pid may be a shell around it.
if [ -s "$WORK/d3.pid" ]; then kill -TERM "$(cat "$WORK/d3.pid")"; else kill -TERM "$rpid" 2>/dev/null || true; fi
wait "$rpid" || true
[ "$(jq -r .error "$WORK/d3.json" 2>/dev/null)" = ScanCancelled ] && pass "SIGTERM cancels the scan" || fail "cancel: $(cat "$WORK/d3.json")"
[ "$(live d3)" = 0 ] && pass "a cancelled scan leaves no container" || fail "containers left after cancel"
[ "$(tree_hash "$WS/d3/src")" = "$before" ] && pass "a scan cancelled in stage 1 leaves the source unchanged" || fail "the cancelled scan changed the source"

echo "== image scan =="
mkdir -p "$WS/d4"
set +e
run_scan bind "$WS" image d4 "$WS/d4" alpine:3.20 > "$WORK/d4.json" 2> "$WORK/d4.log"
rc=$?
set -e
[ "$rc" = 0 ] && pass "the image scan exits 0" || fail "image scan exit $rc" "$(cat "$WORK/d4.json"; tail -15 "$WORK/d4.log")"
out="$(jq -r '.output_dir // empty' "$WORK/d4.json")"
jq -e '[.components[] | select(.name == "musl")] | length > 0' "$out/alpine_3.20_bom.json" >/dev/null 2>&1 \
    && pass "the image SBOM lists musl" || fail "the image SBOM does not list musl"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
