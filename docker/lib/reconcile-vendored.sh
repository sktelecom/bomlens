#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# reconcile-vendored.sh — drop vendored matches the package-manager scan already covers.
#
# Usage: reconcile-vendored.sh <base_sbom> <vendored_sbom>
#   Rewrites <vendored_sbom> in place, removing every component whose name (case-
#   insensitive) already appears in <base_sbom>. Prints the number dropped.
#
# Why: when --identify-vendored runs on a normal package-managed project, SCANOSS
# may file-match a declared dependency (e.g. node_modules/lodash). That would land
# as a duplicate pkg:github component with a possibly-wrong CPE — over-detection
# and false CVEs. The authoritative package-manager identity wins; only genuinely
# new finds (real vendored source) survive. The generic merge-sbom.sh dedup cannot
# do this (different PURL ecosystems never match) and must stay unchanged — layered
# server SBOMs legitimately repeat names across layers.
#
# Best-effort: any error leaves the vendored SBOM untouched and reports 0 dropped.
set -e

BASE="$1"
VEND="$2"

if [ -z "$BASE" ] || [ -z "$VEND" ] || [ ! -f "$BASE" ] || [ ! -f "$VEND" ]; then
    echo 0; exit 0
fi
if ! command -v jq >/dev/null 2>&1; then
    echo 0; exit 0
fi

before=$(jq '[.components[]?] | length' "$VEND" 2>/dev/null || echo 0)
known=$(jq -c '[.components[]?.name // empty | ascii_downcase] | unique' "$BASE" 2>/dev/null || echo '[]')

TMP="$(mktemp)"
if jq --argjson known "$known" \
        '.components |= map(select((((.name // "") | ascii_downcase) as $n | ($known | index($n))) | not))' \
        "$VEND" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$VEND"
else
    rm -f "$TMP"
fi

after=$(jq '[.components[]?] | length' "$VEND" 2>/dev/null || echo "$before")
echo $((before - after))
