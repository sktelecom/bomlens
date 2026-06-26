#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# scan-aibom.sh — generate an AI SBOM for a HuggingFace model with the OWASP
# AIBOM Generator, emitting CycloneDX 1.7.
#
# Usage: scan-aibom.sh <hf_model_id> <output_sbom.json> <version>
#   produces <output_sbom.json> (CycloneDX 1.7, machine-learning-model + modelCard)
#
# The generator (owasp-aibom-generator, Apache-2.0) lives ONLY in the opt-in
# `bomlens-aibom` image and fetches model-card metadata from the HuggingFace API
# (network). It writes both a 1.6 file and a `<out>_1_7.json` variant; we keep the
# 1.7 one to match the AI-path format decision. The common post-processing
# (normalize/notice/risk) then runs on it unchanged — normalize preserves the 1.7
# specVersion and the modelCard.
set -e

MODEL_ID="$1"
OUTPUT="$2"
VERSION="${3:-unknown}"

if [ -z "$MODEL_ID" ]; then
    echo "[aibom] a HuggingFace model id is required (usage: scan-aibom.sh <owner/name> <out.json> <version>)" >&2
    exit 1
fi
if [ -z "$OUTPUT" ]; then
    echo "[aibom] output path is required" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BASE="$WORK/aibom.json"   # absolute (mktemp -d), so it survives the cwd change below

# Resolve the generator. The reliable form is running the module from the cloned
# repo dir: its data files (model-field registry, SPDX schema) load by relative
# path, and a bare `pip install` drops them. The `aibom` console script is only a
# fallback. Absent both => this is the base image, not the opt-in aibom image.
AIBOM_DIR="${AIBOM_DIR:-/opt/aibom-generator}"

echo "[aibom] generating AI SBOM for $MODEL_ID (OWASP AIBOM Generator)"
# Writes the 1.6 file to $BASE and a sibling 1.7 variant to <base>_1_7.json.
gen_rc=0
if [ -f "$AIBOM_DIR/src/cli.py" ]; then
    ( cd "$AIBOM_DIR" && python3 -m src.cli "$MODEL_ID" --version "$VERSION" --output "$BASE" ) >&2 || gen_rc=$?
elif command -v aibom >/dev/null 2>&1; then
    aibom "$MODEL_ID" --version "$VERSION" --output "$BASE" >&2 || gen_rc=$?
else
    echo "[aibom] ERROR: owasp-aibom-generator not installed in this image." >&2
    echo "[aibom]   Rebuild the aibom image: docker build --build-arg SBOM_AIBOM=true -t bomlens-aibom ./docker" >&2
    exit 1
fi
if [ "$gen_rc" -ne 0 ]; then
    echo "[aibom] ERROR: generation failed for $MODEL_ID (check the model id and HuggingFace network access)." >&2
    exit 1
fi

V17="${BASE%.json}_1_7.json"
if [ -f "$V17" ] && jq empty "$V17" >/dev/null 2>&1; then
    cp "$V17" "$OUTPUT"
    echo "[aibom] kept CycloneDX 1.7 output"
elif [ -f "$BASE" ] && jq empty "$BASE" >/dev/null 2>&1; then
    cp "$BASE" "$OUTPUT"
    echo "[aibom] WARNING: 1.7 variant absent; kept the generator's default output ($(jq -r '.specVersion // "?"' "$BASE"))." >&2
else
    echo "[aibom] ERROR: generator produced no valid SBOM." >&2
    exit 1
fi

# A written, well-formed file is not enough. When the generator cannot reach the
# model card (offline, or a nonexistent/private model id) it still exits 0 and
# emits a degraded stub with no modelCard. Treat that as a hard failure so an
# empty ML-BOM is never trusted as a real supply-chain artifact — offline use is
# not supported (docs/guides/ai-model.md).
ml_with_card=$(jq '[.components[]? | select(.type=="machine-learning-model" and ((.modelCard? // {}) | length) > 0)] | length' "$OUTPUT" 2>/dev/null || echo 0)
if [ "${ml_with_card:-0}" -lt 1 ]; then
    echo "[aibom] ERROR: the generated ML-BOM carries no model card for $MODEL_ID." >&2
    echo "[aibom]   The card could not be collected — this happens offline or for a" >&2
    echo "[aibom]   nonexistent/private model id. AIBOM needs HuggingFace network access." >&2
    rm -f "$OUTPUT"
    exit 1
fi
echo "[aibom] model card present ($ml_with_card model component(s) with a card)."
