#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# reachability.sh - judge whether the Go code a vulnerability lives in is
# reached (--reachability), and write the judgements as a CycloneDX VEX.
#
# Usage: reachability.sh <sbom.json> <out_prefix> <source|binary> [<go executable>]
#   produces  <out_prefix>_reachability.cdx.json
#
# source: stage 1 ran govulncheck in the Go image with the source tree, once
#         per Go module and per GOOS, and left
#         <out_prefix>_govulncheck_stage1.{json,err,rc} beside the SBOM
#         (build-prep.sh): the streams, standard error, and in .rc the run
#         list headed by the nonce this run gave stage 1. They are read here
#         only when that nonce is REACHABILITY_NONCE (an earlier run's files
#         are not this run's), and removed either way.
# binary: govulncheck -mode=binary runs here on the executable; the Go
#         vulnerability database (vuln.go.dev) is read over the network.
#
# The SBOM and the security report are not changed here; scan-security.sh reads
# the VEX to mark its findings. Standard output is one JSON line from
# assess-reachability.py. Exit status: 0 written, 2 failed, 3 the database
# could not be reached, 10 govulncheck is not in this image, 11 nothing to judge
# (no Go component, or stage 1 did not run govulncheck for this run), 12 more
# Go modules than stage 1 judges.
set -e

SBOM="$1"; OUT_PREFIX="$2"; MODE="$3"; TARGET="${4:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VEX="${OUT_PREFIX}_reachability.cdx.json"
STAGE1="${OUT_PREFIX}_govulncheck_stage1"

rm -f "$VEX"
if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo '{"status": "failed", "detail": "SBOM not found"}'
    exit 2
fi
if ! jq -e '[.components[]? | recurse(.components[]?) | (.purl // "") | select(startswith("pkg:golang/"))] | length > 0' \
        "$SBOM" >/dev/null 2>&1; then
    rm -f "$STAGE1.json" "$STAGE1.err" "$STAGE1.rc"
    echo '{"status": "no_input", "detail": "the SBOM has no Go component"}'
    exit 11
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

case "$MODE" in
    source)
        if [ ! -f "$STAGE1.rc" ]; then
            rm -f "$STAGE1.json" "$STAGE1.err"
            echo '{"status": "no_input", "detail": "stage 1 did not run govulncheck (no go.mod in the source tree, no Go toolchain in its image, or an older scan-sbom.sh)"}'
            exit 11
        fi
        mv "$STAGE1.rc" "$work/runs"; mv "$STAGE1.err" "$work/err" 2>/dev/null || : > "$work/err"
        mv "$STAGE1.json" "$work/out.json" 2>/dev/null || : > "$work/out.json"
        nonce="$(sed -n 's/^nonce //p' "$work/runs" | head -1)"
        if [ -z "${REACHABILITY_NONCE:-}" ] || [ "$nonce" != "$REACHABILITY_NONCE" ]; then
            echo '{"status": "no_input", "detail": "the govulncheck output beside the SBOM is not from this run (an earlier or another scan left it); it was removed"}'
            exit 11
        fi
        if grep -q '^too_large' "$work/runs"; then
            # shellcheck disable=SC2046  # two numbers, split on purpose
            set -- $(sed -n 's/^too_large //p' "$work/runs" | head -1 | tr -cd '0-9 ')
            echo "{\"status\": \"too_large\", \"detail\": \"the source tree has ${1:-more} Go modules, over the ${2:-20} that are judged\"}"
            exit 12
        fi
        rc="$work/runs"
        ;;
    binary)
        if ! command -v govulncheck >/dev/null 2>&1; then
            echo '{"status": "not_installed", "detail": "govulncheck is not in this image"}'
            exit 10
        fi
        if [ -z "$TARGET" ] || [ ! -f "$TARGET" ]; then
            echo '{"status": "no_input", "detail": "no executable to read"}'
            exit 11
        fi
        rc=0
        timeout 600 govulncheck -mode=binary -format json "$TARGET" \
            > "$work/out.json" 2> "$work/err" || rc=$?
        ;;
    *)
        echo "{\"status\": \"failed\", \"detail\": \"unknown mode $MODE\"}"
        exit 2 ;;
esac

# rc: one exit status (binary), or the run list stage 1 wrote (source).
python3 -I "$SCRIPT_DIR/assess-reachability.py" "$SBOM" "$work/out.json" "${rc:-1}" "$work/err" "$MODE" "$VEX"
