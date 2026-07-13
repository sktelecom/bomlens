#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
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
