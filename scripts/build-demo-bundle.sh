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
# build-demo-bundle.sh — build the web UI as the read-only demo and place it
# where MkDocs will pick it up (docs/demo/).
#
# The demo is the same SPA as the app, built with two settings: a base path,
# because the site lives under /bomlens/, and a data base, which switches the
# API layer from "call the server" to "read the captured JSON" (lib/demo.ts).
# The captured JSON itself is committed under docs/demo/data/ and produced by
# scripts/capture-demo-data.sh — this script never touches it.
#
# The bundle is deliberately NOT committed: CI runs this before `mkdocs build`,
# and mkdocs copies docs/demo/ into the site as-is.
#
# Usage: scripts/build-demo-bundle.sh
#   DEMO_BASE_PATH   URL path the site is served from (default /bomlens/demo/)
#   DEMO_DATA_BASE   URL path of the captured data (default /bomlens/demo/data)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND="$ROOT/docker/web/frontend"
DEST="$ROOT/docs/demo"
BASE_PATH="${DEMO_BASE_PATH:-/bomlens/demo/}"
DATA_BASE="${DEMO_DATA_BASE:-/bomlens/demo/data}"

if [ ! -d "$DEST/data" ]; then
    echo "[ERROR] $DEST/data is missing — the demo has no data to show." >&2
    echo "        Capture it first:" >&2
    echo "        scripts/capture-demo-data.sh <scan-output-dir>" >&2
    exit 1
fi

echo "[INFO] building the demo bundle (base=$BASE_PATH data=$DATA_BASE)"
cd "$FRONTEND"
npm ci --no-audit --no-fund
BASE_PATH="$BASE_PATH" VITE_DEMO_DATA_BASE="$DATA_BASE" npm run build

# Replace the previous bundle but keep data/ — it is the committed input, not
# an output, and rebuilding must never be able to delete it.
find "$DEST" -mindepth 1 -maxdepth 1 ! -name data ! -name '.gitignore' \
    -exec rm -rf {} +
cp -R "$FRONTEND/dist/." "$DEST/"

echo "[INFO] demo bundle in $DEST"
