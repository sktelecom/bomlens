#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-android-scope.sh — Android (AGP) release-scope regression.
#
# Guards docker/lib/build-prep.sh: an Android source scan must report only the
# deployable release runtime classpath, not AGP's build/test toolchain
# (androidTestUtil, the Unified Test Platform, lint, ddmlib, grpc/netty) or the
# pre-resolution duplicate versions cdxgen emits from the other configurations.
#
# This runs the real android-sdk image against tests/fixtures/android-scope and
# resolves the full androidx graph from Google Maven, so it is slow and
# network-dependent — it lives in the nightly (best-effort) lane, never on the
# per-PR path. It self-skips when docker or the image is unavailable.
#
# Usage: ./tests/test-android-scope.sh
# Env:
#   SBOM_ANDROID_IMAGE  android-sdk image to test
#                       (default: ghcr.io/sktelecom/bomlens-android-sdk34:latest)
#   VERBOSE=true        print the build-prep log on failure
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
PREP="$REPO/docker/lib/build-prep.sh"
FIXTURE="$REPO/tests/fixtures/android-scope"
IMG="${SBOM_ANDROID_IMAGE:-ghcr.io/sktelecom/bomlens-android-sdk34:latest}"
VERBOSE="${VERBOSE:-false}"

# Work under the repo (/Users/... on macOS) so Docker Desktop file sharing
# mounts it; mktemp -d defaults to /var/folders, which Docker does not share.
WORK="$SCRIPT_DIR/test-workspace/android-scope"
rm -rf "$WORK"; mkdir -p "$WORK/gcache"

c_green='\033[0;32m'; c_red='\033[0;31m'; c_yellow='\033[0;33m'; c_reset='\033[0m'
PASS=0; FAIL=0
pass() { echo -e "  ${c_green}PASS${c_reset} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${c_red}FAIL${c_reset} $1"; FAIL=$((FAIL+1)); [ -n "${2:-}" ] && echo "        ↳ $2"; }

echo "▶ Android release-scope regression ($IMG)"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo -e "  ${c_yellow}SKIP${c_reset} docker unavailable"; exit 0
fi
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    if ! docker pull "$IMG" >/dev/null 2>&1; then
        echo -e "  ${c_yellow}SKIP${c_reset} android image not available: $IMG"; exit 0
    fi
fi
command -v jq >/dev/null 2>&1 || { echo -e "  ${c_yellow}SKIP${c_reset} jq unavailable"; exit 0; }

# Regex for AGP build/test toolchain purls that must NOT appear in a release SBOM.
TOOLCHAIN='utp|grpc|netty|ddmlib|net[.]java[.]dev[.]jna|com[.]android[.]tools|testing[.]platform'

# Run build-prep in the android image exactly as generate_sbom_cdxgen does, and
# echo the produced BOM path (empty on failure). $1 = extra `docker run` env args.
run_scan() {
    local tag="$1" extra="$2" src="$WORK/src-$1"
    rm -rf "$src"; cp -R "$FIXTURE" "$src"
    # shellcheck disable=SC2086
    docker run --rm -u 0:0 \
        -v "$src":/app -v "$WORK/gcache":/root/.gradle \
        -e HOME=/tmp/sbomhome \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        $extra \
        --entrypoint sh "$IMG" \
        -c "$(cat "$PREP")" _ /app "/app/bom.json" 1.6 > "$WORK/$tag.log" 2>&1
    [ -f "$src/bom.json" ] && echo "$src/bom.json"
}

count() { jq -r '.components | length' "$1"; }
toolchain_count() {
    jq -r --arg re "$TOOLCHAIN" \
        '[.components[].purl // "" | select(test($re))] | length' "$1"
}
has_direct() {
    jq -e --arg d "$2" '[.components[].purl // "" | select(contains($d))] | length > 0' \
        "$1" >/dev/null
}
dump_log() { [ "$VERBOSE" = true ] && { echo "        --- $1 ---"; sed -n '1,40p' "$1"; }; }

# --- Default scan: the fix is on; expect the release runtime scope only. ---
BOM="$(run_scan default "")"
if [ -z "$BOM" ]; then
    fail "default scan produced a BOM" "no bom.json (see $WORK/default.log)"
    dump_log "$WORK/default.log"
else
    n="$(count "$BOM")"; tc="$(toolchain_count "$BOM")"
    if [ "$tc" -eq 0 ]; then
        pass "no build/test toolchain components ($tc)"
    else
        fail "no build/test toolchain components" "$tc toolchain purls remain"
        dump_log "$WORK/default.log"
    fi
    miss=""
    for d in appcompat okhttp gson; do has_direct "$BOM" "$d" || miss="$miss $d"; done
    if [ -z "$miss" ]; then pass "all direct dependencies present (appcompat, okhttp, gson)"
    else fail "all direct dependencies present" "missing:$miss"; fi
    # Recall not collapsed (release transitives kept) and toolchain gone: the
    # release runtime closure of these 3 deps lands well inside this band, far
    # from the ~125-component full-configuration graph.
    if [ "$n" -ge 30 ] && [ "$n" -le 80 ]; then
        pass "component count in release band ($n, expected 30..80)"
    else
        fail "component count in release band" "got $n (expected 30..80)"
        dump_log "$WORK/default.log"
    fi
fi

# --- Contrast: opt out and confirm the fixture really does drag in the toolchain
# (so a green default run means the filter removed it, not that it was absent). ---
FULL="$(run_scan fullgraph "-e BOMLENS_ANDROID_FULL_GRAPH=1")"
if [ -z "$FULL" ]; then
    fail "full-graph scan produced a BOM" "no bom.json (see $WORK/fullgraph.log)"
    dump_log "$WORK/fullgraph.log"
else
    ftc="$(toolchain_count "$FULL")"
    if [ "$ftc" -gt 0 ]; then
        pass "opt-out keeps the toolchain ($ftc purls) — filter is what removes it"
    else
        fail "opt-out keeps the toolchain" "fixture no longer drags in the toolchain; assertion is vacuous"
    fi
fi

echo ""
echo "Android scope: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
