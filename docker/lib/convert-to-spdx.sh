#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# convert-to-spdx.sh — export the finished CycloneDX BOM as SPDX 2.3 JSON via
# `syft convert` (the reverse of convert-to-cdx.sh). SPDX is an ADDITIONAL
# artifact: CycloneDX stays the pipeline's working format (normalize, notice,
# security and upload all consume it), so this runs after every enrichment and
# never mutates its input. CycloneDX-only data (vulnerabilities, bomlens:*
# properties) has no SPDX equivalent and does not carry over — the SPDX file is
# a format conversion, not a second source of truth.
#
# What SPDX does have a place for is carried across afterwards: syft's converter
# writes a package only for what it counts as software, which leaves out the
# container images a firmware holds and the distribution it runs. SPDX has a
# relationship for a package that holds other packages, so those go in as
# packages and the membership as CONTAINS (spdx-containers.py).
#
# Usage: convert-to-spdx.sh <input_cyclonedx.json> <output_spdx.json> [--stable]
#   --stable  pin creationInfo.created and the random documentNamespace UUID so
#             repeated runs are byte-identical (mirrors normalize-sbom.sh --stable).
set -e

INPUT="$1"
OUTPUT="$2"
MODE="${3:-}"

if [ -z "$INPUT" ] || [ ! -f "$INPUT" ]; then
    echo "[spdx] input SBOM not found: $INPUT" >&2
    exit 1
fi
if [ -z "$OUTPUT" ]; then
    echo "[spdx] output path required (usage: convert-to-spdx.sh <input> <output.spdx.json> [--stable])" >&2
    exit 1
fi
if ! command -v syft >/dev/null 2>&1; then
    echo "[spdx] ERROR: syft not available in this image; cannot export SPDX." >&2
    exit 1
fi

if ! syft convert "$INPUT" -o spdx-json="$OUTPUT" >/dev/null 2>&1; then
    echo "[spdx] ERROR: syft convert to SPDX failed for: $INPUT" >&2
    exit 1
fi

if [ ! -s "$OUTPUT" ] || ! jq -e '.spdxVersion != null and .SPDXID != null' "$OUTPUT" >/dev/null 2>&1; then
    echo "[spdx] ERROR: produced output is not valid SPDX JSON: $OUTPUT" >&2
    exit 1
fi

# syft names the converted document "unknown" (it does not carry the CycloneDX
# root component over as the document name); use the BOM's stamped root instead.
DOC_NAME=$(jq -r '[.metadata.component.name, .metadata.component.version] | map(select(. != null and . != "")) | join("-")' "$INPUT")
if [ -n "$DOC_NAME" ]; then
    TMP="${OUTPUT}.name.tmp"
    if jq --arg n "$DOC_NAME" '.name = $n' "$OUTPUT" > "$TMP" 2>/dev/null; then
        mv "$TMP" "$OUTPUT"
    else
        rm -f "$TMP"
    fi
fi

LIB_DIR="$(cd "$(dirname "$0")" && pwd)"

# Runs before the containers step, which attaches what it adds to whatever the
# document describes: naming that root first means the images hang off the real
# component rather than off syft's blank wrapper.
SPDX_DOC_ROOT="$LIB_DIR/spdx-document-root.py"
if [ -f "$SPDX_DOC_ROOT" ] && command -v python3 >/dev/null 2>&1; then
    python3 "$SPDX_DOC_ROOT" "$INPUT" "$OUTPUT" \
        || echo "[spdx] WARN: the document root was left unnamed." >&2
fi

# Best-effort, and after the rename so the document is otherwise final: the SPDX
# file is an additional artifact and the scan has already produced everything else
# by now, so a failure here costs the memberships rather than the run.
SPDX_CONTAINERS="$LIB_DIR/spdx-containers.py"
if [ -f "$SPDX_CONTAINERS" ] && command -v python3 >/dev/null 2>&1; then
    python3 "$SPDX_CONTAINERS" "$INPUT" "$OUTPUT" \
        || echo "[spdx] WARN: containers were not carried into the SPDX file." >&2
fi

if [ "$MODE" = "--stable" ]; then
    # syft stamps the current time in creationInfo.created and a random UUID in
    # documentNamespace; pin both so BYTE_STABLE runs stay byte-identical.
    TMP="${OUTPUT}.stable.tmp"
    if jq '
        .creationInfo.created = "1970-01-01T00:00:00Z"
        | .documentNamespace = "https://github.com/sktelecom/bomlens/spdxdocs/\(.name)"
    ' "$OUTPUT" > "$TMP" 2>/dev/null; then
        mv "$TMP" "$OUTPUT"
    else
        rm -f "$TMP"
        echo "[spdx] WARN: could not pin timestamp/namespace for byte-stable output." >&2
    fi
fi

NPKG=$(jq '[.packages[]?]|length' "$OUTPUT" 2>/dev/null || echo 0)
echo "[spdx] SPDX ready: $OUTPUT (packages=$NPKG)"
