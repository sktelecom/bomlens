#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.
#
# capture-demo-data.sh — freeze a folder of finished scans into the JSON the
# published read-only demo reads instead of calling a server.
#
# The demo is the same SPA as the app; only its data source differs. Rather
# than hand-write that data (which would drift from the server contract the
# moment a field changes), this script starts the real docker/web/server.py
# against a folder of real scan output and saves what it answers. The shapes
# are therefore the server's shapes, by construction.
#
# Usage:
#   scripts/capture-demo-data.sh <scan-output-dir> [dest-dir]
#
#   <scan-output-dir>  A folder holding one sub-folder per finished scan, as
#                      produced by `scan-sbom.sh -o <dir>`. Every run folder in
#                      it is captured; move anything you do not want published
#                      out of the way first.
#   [dest-dir]         Where to write (default: docs/demo/data).
#
# What lands in dest-dir:
#   capabilities.json        what the UI may offer (writes forced off)
#   scans.json               the recent-scans list
#   scan-<run_id>.json       one finished scan's full result payload
#   results-<run_id>.json    that run's artifact listing
#   files/<run_id>/<name>    each artifact, downloadable as-is
#   files/<run_id>.zip       the run's "download all" bundle

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-}"
DEST="${2:-$ROOT/docs/demo/data}"
PORT="${DEMO_CAPTURE_PORT:-8899}"

if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
    echo "[ERROR] Usage: $0 <scan-output-dir> [dest-dir]" >&2
    echo "        <scan-output-dir> must be a folder of finished scan runs." >&2
    exit 1
fi
SRC="$(cd "$SRC" && pwd)"

for tool in python3 curl zip; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[ERROR] '$tool' is required but not installed." >&2
        exit 1
    }
done

# Run folders are the sub-folders holding a *_bom.json. A stray folder without
# one would produce an empty scan detail, so skip it rather than publish it.
RUNS=()
for d in "$SRC"/*/; do
    [ -d "$d" ] || continue
    name="$(basename "$d")"
    case "$name" in .*) continue ;; esac
    compgen -G "$d"'*_bom.json' >/dev/null 2>&1 || {
        echo "[WARN] skipping '$name' — no *_bom.json in it"
        continue
    }
    RUNS+=("$name")
done

if [ ${#RUNS[@]} -eq 0 ]; then
    echo "[ERROR] No finished scan runs found in $SRC" >&2
    echo "        Produce some first, e.g.:" >&2
    echo "        scripts/scan-sbom.sh --project Demo --version 1.0.0 \\" >&2
    echo "            --target examples/java-maven --generate-only -o $SRC" >&2
    exit 1
fi

echo "[INFO] capturing ${#RUNS[@]} run(s) from $SRC"

SERVER_LOG="$(mktemp)"
SBOM_OUTPUT_DIR="$SRC" UI_PORT="$PORT" python3 "$ROOT/docker/web/server.py" \
    >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    rm -f "$SERVER_LOG"
}
trap cleanup EXIT

# Wait for the port rather than sleeping a fixed amount: a cold start varies.
for _ in $(seq 1 40); do
    curl -fsS "http://127.0.0.1:$PORT/capabilities" -o /dev/null 2>/dev/null && break
    kill -0 "$SERVER_PID" 2>/dev/null || {
        echo "[ERROR] server.py exited during startup:" >&2
        cat "$SERVER_LOG" >&2
        exit 1
    }
    sleep 0.25
done
curl -fsS "http://127.0.0.1:$PORT/capabilities" -o /dev/null 2>/dev/null || {
    echo "[ERROR] server.py did not answer on port $PORT" >&2
    cat "$SERVER_LOG" >&2
    exit 1
}

rm -rf "$DEST"
mkdir -p "$DEST/files"

fetch() { # fetch <path> <dest-file>
    curl -fsS "http://127.0.0.1:$PORT$1" -o "$2" || {
        echo "[ERROR] GET $1 failed" >&2
        exit 1
    }
}

fetch "/scans" "$DEST/scans.json"

# Capabilities decide which controls the UI offers. Every one of them leads to
# a write the demo cannot serve, so force the whole set off — the bundle also
# refuses these paths, but a capability left on would still render a dead
# button. Kept as a jq-free python edit so the script needs no extra tool.
fetch "/capabilities" "$DEST/capabilities.json"
python3 - "$DEST/capabilities.json" <<'PY'
import json, sys
p = sys.argv[1]
caps = json.load(open(p))
for k in ("firmware", "scanoss", "docker", "aibom", "deepCve", "spdxExport",
          "hfAuth", "firmwareSibling", "aibomSibling", "deepCveSibling",
          "spdxSibling"):
    if k in caps:
        caps[k] = False
caps["hostDir"] = ""
caps["scanRoots"] = []
json.dump(caps, open(p, "w"), indent=1)
PY

for run in "${RUNS[@]}"; do
    echo "[INFO]   $run"
    enc="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$run")"
    fetch "/scan?id=$enc" "$DEST/scan-$run.json"
    fetch "/results?id=$enc" "$DEST/results-$run.json"
    mkdir -p "$DEST/files/$run"
    # Artifacts are copied rather than re-fetched: /file streams the same bytes
    # and copying keeps the run folder's names exactly as results[] reports them.
    #
    # Markdown reports are the exception. This folder ends up inside the MkDocs
    # docs tree, where any *.md is taken as a page to render — it would be turned
    # into HTML (so the download would 404) and would fail `--strict` for not
    # being in the nav. Every one of them ships an .html twin carrying the same
    # report, so dropping them costs the demo nothing.
    find "$SRC/$run" -maxdepth 1 -type f ! -name '*.md' \
        -exec cp {} "$DEST/files/$run/" \;
    (cd "$DEST/files" && zip -qr "$run.zip" "$run")

    # Keep the listings honest about what was copied: a name left in results[]
    # would render a download link to a file that is not there.
    python3 - "$DEST/scan-$run.json" "$DEST/results-$run.json" <<'PY'
import json, sys

def drop_markdown(results):
    return [r for r in results if not r.get("name", "").endswith(".md")]

scan_path, results_path = sys.argv[1], sys.argv[2]

scan = json.load(open(scan_path))
scan["results"] = drop_markdown(scan.get("results", []))
json.dump(scan, open(scan_path, "w"))

json.dump(drop_markdown(json.load(open(results_path))), open(results_path, "w"))
PY
done

echo "[INFO] wrote $DEST ($(du -sh "$DEST" | cut -f1))"
echo "[INFO] build the demo bundle with:"
echo "         cd docker/web/frontend && BASE_PATH=/bomlens/demo/ \\"
echo "           VITE_DEMO_DATA_BASE=/bomlens/demo/data npm run build"
