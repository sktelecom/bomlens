#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-ios.sh — regression tests for iOS lockfile coverage (CocoaPods; SPM is
# covered by cdxgen's offline Package.resolved support and needs no fixture here).
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

# --- (1b) No-Docker: pod licences from the trunk podspecs ----------------------------
# identify-cocoapods.sh with a stand-in syft (the canned output below) and the podspecs
# read from fixtures instead of the CDN. Only trunk pods are asked; a subspec takes its
# pod's licence; FETCH_LICENSE=false and --byte-stable keep the lookup off.
echo "== iOS-3: CocoaPods pod licences come from the trunk podspecs (no Docker) =="
PLF="$FIX/ios-cocoapods-licenses"
mkdir -p "$WORK/bin"
printf '#!/bin/sh\ncat "%s"\n' "$PLF/syft-output.json" > "$WORK/bin/syft"
chmod +x "$WORK/bin/syft"
lic_of() { jq -r --arg n "$2" '[.components[] | select(.name == $n) | .licenses[0].license | (.id // .name // empty)] | first // ""' "$1"; }
if PATH="$WORK/bin:$PATH" COCOAPODS_LICENSE_FIXTURE_DIR="$PLF/podspecs" FETCH_LICENSE=true BYTE_STABLE=false \
        bash "$LIB/identify-cocoapods.sh" "$PLF" "$WORK/podlic.json" 1.0 >/dev/null 2>"$WORK/podlic.log"; then
    n=$(jq '[.components[]? | select((.purl // "") | startswith("pkg:cocoapods/"))] | length' "$WORK/podlic.json")
    [ "$n" -eq 8 ] && pass "8 pods identified from the stand-in syft output" || fail "expected 8 pods, got $n"
    [ "$(lic_of "$WORK/podlic.json" Alamofire)" = "MIT" ] \
        && pass "trunk pod licence written as an SPDX id (Alamofire MIT)" \
        || fail "Alamofire licence: $(lic_of "$WORK/podlic.json" Alamofire)"
    [ "$(lic_of "$WORK/podlic.json" Moya)" = "MIT" ] && [ "$(lic_of "$WORK/podlic.json" Moya/Core)" = "MIT" ] \
        && pass "licence object form and lower-case id read; the subspec takes its pod's licence" \
        || fail "Moya / Moya/Core licence: $(lic_of "$WORK/podlic.json" Moya) / $(lic_of "$WORK/podlic.json" Moya/Core)"
    [ "$(lic_of "$WORK/podlic.json" Quick)" = "Apache License, Version 2.0" ] \
        && pass "free-text licence kept as a licence name for normalize to map (quoted name in SPEC REPOS)" \
        || fail "Quick licence: $(lic_of "$WORK/podlic.json" Quick)"
    [ -z "$(lic_of "$WORK/podlic.json" AcmeKit)" ] && [ -z "$(lic_of "$WORK/podlic.json" GitPod)" ] \
        && pass "pods from another spec repo or a git source are not given a trunk licence" \
        || fail "non-trunk pods got a licence: AcmeKit=$(lic_of "$WORK/podlic.json" AcmeKit) GitPod=$(lic_of "$WORK/podlic.json" GitPod)"
    [ -z "$(lic_of "$WORK/podlic.json" Missing)" ] && [ -z "$(lic_of "$WORK/podlic.json" NoLicPod)" ] \
        && pass "a pod without a podspec or without a licence in it stays without one" \
        || fail "Missing/NoLicPod got a licence"
    jq -e '[.components[] | select(.name == "Alamofire") | .properties[] | select(.name == "bomlens:licenseSource" and .value == "CocoaPods trunk podspec")] | length == 1' "$WORK/podlic.json" >/dev/null \
        && pass "a filled licence is marked bomlens:licenseSource" \
        || fail "bomlens:licenseSource missing on Alamofire"
    grep -q "6 pods asked, 4 filled, 1 podspecs without a licence, 1 not found" "$WORK/podlic.log" \
        && pass "the lookup summary counts asked, filled, without a licence and not found" \
        || fail "lookup summary line not as expected" "$(grep 'licence lookup' "$WORK/podlic.log")"
    cp "$WORK/podlic.json" "$WORK/podlic-norm.json"
    bash "$LIB/normalize-sbom.sh" "$WORK/podlic-norm.json" >/dev/null 2>&1
    [ "$(lic_of "$WORK/podlic-norm.json" Quick)" = "Apache-2.0" ] \
        && pass "normalize maps the podspec licence text to its SPDX id (Quick Apache-2.0)" \
        || fail "normalized Quick licence: $(lic_of "$WORK/podlic-norm.json" Quick)"
else
    fail "identify-cocoapods.sh failed with the stand-in syft" "$(cat "$WORK/podlic.log")"
fi
for off in "FETCH_LICENSE=false BYTE_STABLE=false" "FETCH_LICENSE=true BYTE_STABLE=true"; do
    # shellcheck disable=SC2086
    env PATH="$WORK/bin:$PATH" COCOAPODS_LICENSE_FIXTURE_DIR="$PLF/podspecs" $off \
        bash "$LIB/identify-cocoapods.sh" "$PLF" "$WORK/podlic-off.json" 1.0 >/dev/null 2>"$WORK/podlic-off.log" || true
    jq -e '[.components[] | select((.licenses // []) | length > 0)] | length == 0' "$WORK/podlic-off.json" >/dev/null 2>&1 \
        && grep -q "licence lookup off" "$WORK/podlic-off.log" \
        && pass "$off: no lookup, and the log says the pods have no licence" \
        || fail "$off: the lookup ran or the log did not say it was off"
done
# A CDN that does not answer: the first request fails, the rest are not tried, and
# the warning names the fix. Port 9 on the loopback refuses the connection at once.
cp "$WORK/podlic-off.json" "$WORK/podlic-down.json"
if COCOAPODS_CDN_URL="http://127.0.0.1:9" python3 "$LIB/fetch-cocoapods-licenses.py" \
        "$WORK/podlic-down.json" "$PLF/App/Podfile.lock" > "$WORK/podlic-down.out" 2>"$WORK/podlic-down.log"; then
    jq -e '.lookup_failed == 6 and .filled == 0' "$WORK/podlic-down.out" >/dev/null 2>&1 \
        && grep -q "SBOM_EXTRA_CA_CERTS" "$WORK/podlic-down.log" \
        && pass "an unreachable CDN fails all lookups after one request and points at SBOM_EXTRA_CA_CERTS" \
        || fail "unreachable CDN not reported as expected" "$(cat "$WORK/podlic-down.out" "$WORK/podlic-down.log")"
else
    fail "fetch-cocoapods-licenses.py exited non-zero on an unreachable CDN"
fi
# A licence already on the component is never replaced.
jq '(.components[] | select(.name == "Alamofire")) .licenses = [{"license": {"id": "BSD-3-Clause"}}]' \
    "$WORK/podlic-off.json" > "$WORK/podlic-keep.json"
COCOAPODS_LICENSE_FIXTURE_DIR="$PLF/podspecs" python3 "$LIB/fetch-cocoapods-licenses.py" \
    "$WORK/podlic-keep.json" "$PLF/App/Podfile.lock" >/dev/null 2>&1
[ "$(lic_of "$WORK/podlic-keep.json" Alamofire)" = "BSD-3-Clause" ] \
    && pass "a licence the component already has is kept" \
    || fail "existing licence replaced: $(lic_of "$WORK/podlic-keep.json" Alamofire)"
# A lockfile without SPEC REPOS (CocoaPods before 1.7) asks about every pod.
jq '.components[].licenses = []' "$FIX/ios-cocoapods-aux.json" > "$WORK/podlic-legacy.json"
COCOAPODS_LICENSE_FIXTURE_DIR="$PLF/podspecs" python3 "$LIB/fetch-cocoapods-licenses.py" \
    "$WORK/podlic-legacy.json" "$FIX/ios-cocoapods/App/Podfile.lock" >/dev/null 2>&1
[ "$(lic_of "$WORK/podlic-legacy.json" Alamofire)" = "MIT" ] \
    && pass "a lockfile without SPEC REPOS still gets trunk licences" \
    || fail "legacy lockfile: Alamofire licence $(lic_of "$WORK/podlic-legacy.json" Alamofire)"

# --- (2) Docker: identify-cocoapods.sh parses a real Podfile.lock via syft -----------
echo "== iOS-2: identify-cocoapods.sh parses Podfile.lock via syft, offline (Docker) =="
IMG="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/bomlens:latest}"
# The run below is --network none on purpose (the identification must need no
# `pod` and no network), which means the image has to be on the machine already.
# Treat a missing image the same as a missing Docker: skipped, not failed. A
# machine that never had the image cannot answer this question either way, and
# reporting that as a defect sends someone looking for a bug in the parser.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 \
   && ! docker image inspect "$IMG" >/dev/null 2>&1; then
    echo "  SKIP: $IMG is not on this machine — pull it to exercise the syft-backed CocoaPods test"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    # Mount the current-branch script over the image so the test tracks source, not a
    # possibly-stale published image. --network none proves no `pod`/network dependency.
    if docker run --rm --network none \
        -v "$LIB/identify-cocoapods.sh":/usr/local/lib/sbom/identify-cocoapods.sh:ro \
        -v "$LIB/parse-podfile-lock.py":/usr/local/lib/sbom/parse-podfile-lock.py:ro \
        -v "$LIB/cdx-version.sh":/usr/local/lib/sbom/cdx-version.sh:ro \
        -v "$FIX/ios-cocoapods":/src:ro \
        -e FETCH_LICENSE=false \
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
