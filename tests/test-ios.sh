#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-ios.sh — regression tests for iOS lockfile coverage (CocoaPods + SPM).
#
# Guards the defect where a CocoaPods project produced an EMPTY SBOM: cdxgen's swift
# language image has no `pod` CLI, so its CocoaPods cataloger yields zero components.
# BomLens fills the gap in post-processing by parsing Podfile.lock with syft.
#
# Two layers:
#   (1) No-Docker (always runs in CI): merge a canned cocoapods SBOM into an empty scan
#       via merge-sbom.sh, asserting the pods (incl. transitive) land with provenance.
#   (2) Docker (skipped when unavailable): identify-cocoapods.sh runs syft on a real
#       Podfile.lock and must return the full transitive set, offline, with no `pod`.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required for iOS coverage tests"; exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- (1) No-Docker: cocoapods components merge into an empty scan --------------------
echo "== iOS-1: CocoaPods components merge into an empty scan (no Docker) =="
if bash "$LIB/merge-sbom.sh" "$WORK/merged.json" "App" "1.0" \
        "$FIX/ios-empty-scan.json" "$FIX/ios-cocoapods-aux.json" >/dev/null 2>&1; then
    n=$(jq '[.components[]? | select((.purl // "") | startswith("pkg:cocoapods/"))] | length' "$WORK/merged.json" 2>/dev/null || echo 0)
    [ "${n:-0}" -eq 3 ] \
        && pass "3 cocoapods components merged into a previously empty scan" \
        || fail "expected 3 cocoapods components after merge, got ${n:-0}"
    # transitive Alamofire (only Moya is a direct dep) must be present
    jq -e '[.components[]? | select(.name=="Alamofire" and (.purl|startswith("pkg:cocoapods/")))] | length == 1' "$WORK/merged.json" >/dev/null 2>&1 \
        && pass "transitive pod (Alamofire) present after merge" \
        || fail "transitive pod (Alamofire) missing after merge"
    # subspec name Moya/Core preserved (URL-encoded in the purl)
    jq -e '[.components[]? | select(.purl=="pkg:cocoapods/Moya%2FCore@15.0.0")] | length == 1' "$WORK/merged.json" >/dev/null 2>&1 \
        && pass "subspec pod (Moya/Core) preserved" \
        || fail "subspec pod (Moya/Core) missing after merge"
    # provenance retained
    jq -e '[.components[]? | select((.purl//"")|startswith("pkg:cocoapods/")) | .properties[]? | select(.name=="bomlens:layer" and .value=="cocoapods")] | length >= 1' "$WORK/merged.json" >/dev/null 2>&1 \
        && pass "cocoapods provenance (bomlens:layer) retained through merge" \
        || fail "cocoapods provenance lost in merge"
    # dependency graph carried through the merge (Moya -> Moya/Core -> Alamofire)
    jq -e '[.dependencies[]? | select(.ref=="pkg:cocoapods/Moya@15.0.0" and (.dependsOn|index("pkg:cocoapods/Moya%2FCore@15.0.0")))] | length == 1' "$WORK/merged.json" >/dev/null 2>&1 \
        && pass "dependency edge Moya -> Moya/Core preserved through merge" \
        || fail "dependency edge Moya -> Moya/Core missing after merge"
    jq -e '[.dependencies[]? | select(.ref=="pkg:cocoapods/Moya%2FCore@15.0.0" and (.dependsOn|index("pkg:cocoapods/Alamofire@5.8.1")))] | length == 1' "$WORK/merged.json" >/dev/null 2>&1 \
        && pass "transitive edge Moya/Core -> Alamofire preserved through merge" \
        || fail "transitive edge Moya/Core -> Alamofire missing after merge"
else
    fail "merge-sbom.sh failed on cocoapods aux SBOM"
fi

# --- (2) Docker: identify-cocoapods.sh parses a real Podfile.lock via syft -----------
echo "== iOS-2: identify-cocoapods.sh parses Podfile.lock via syft, offline (Docker) =="
IMG="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/bomlens:latest}"
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    # Mount the current-branch script over the image so the test tracks source, not a
    # possibly-stale published image. --network none proves no `pod`/network dependency.
    if docker run --rm --network none \
        -v "$LIB/identify-cocoapods.sh":/usr/local/lib/sbom/identify-cocoapods.sh:ro \
        -v "$LIB/parse-podfile-lock.py":/usr/local/lib/sbom/parse-podfile-lock.py:ro \
        -v "$FIX/ios-cocoapods":/src:ro \
        --entrypoint bash "$IMG" \
        -c '/usr/local/lib/sbom/identify-cocoapods.sh /src /tmp/coco.json 1.0 >/dev/null 2>&1; cat /tmp/coco.json' \
        > "$WORK/coco.json" 2>/dev/null && jq -e . "$WORK/coco.json" >/dev/null 2>&1; then
        n=$(jq '[.components[]? | select((.purl // "") | startswith("pkg:cocoapods/"))] | length' "$WORK/coco.json" 2>/dev/null || echo 0)
        [ "${n:-0}" -eq 3 ] \
            && pass "syft returned the full transitive pod set (3) from Podfile.lock, offline" \
            || fail "expected 3 cocoapods components from syft, got ${n:-0}"
        jq -e '[.components[]? | select(.name=="Alamofire")] | length == 1' "$WORK/coco.json" >/dev/null 2>&1 \
            && pass "transitive pod (Alamofire) identified by syft" \
            || fail "transitive pod (Alamofire) missing from syft output"
        # graph reconstructed from Podfile.lock nested lists
        jq -e '[.dependencies[]? | select(.ref=="pkg:cocoapods/Moya%2FCore@15.0.0" and (.dependsOn|index("pkg:cocoapods/Alamofire@5.8.1")))] | length == 1' "$WORK/coco.json" >/dev/null 2>&1 \
            && pass "dependency graph rebuilt from Podfile.lock (Moya/Core -> Alamofire)" \
            || fail "dependency graph edge missing from identify-cocoapods output"
    else
        fail "identify-cocoapods.sh did not produce a valid SBOM in image $IMG"
    fi
else
    echo "  SKIP: docker unavailable — skipping the syft-backed CocoaPods test"
fi

echo
echo "iOS coverage: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
