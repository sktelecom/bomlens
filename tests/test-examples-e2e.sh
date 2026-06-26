#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-examples-e2e.sh — scan every bundled example project exactly as a user
# would (`scan-sbom.sh --all`), verifying that SBOM + notice + security artifacts
# are produced and valid. This is the "real usage" environment check.
#
# Usage:
#   ./tests/test-examples-e2e.sh
# Env:
#   SBOM_SCANNER_IMAGE   scanner image (default: sbom-scanner:test)
#   ONLY="go python"     restrict to a subset of example dirs
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
SCAN="$REPO/scripts/scan-sbom.sh"
EXAMPLES="$REPO/examples"
SCANNER_IMG="${SBOM_SCANNER_IMAGE:-sbom-scanner:test}"
WORK_ROOT="$SCRIPT_DIR/test-workspace/examples-e2e"
rm -rf "$WORK_ROOT"; mkdir -p "$WORK_ROOT"

c_green='\033[0;32m'; c_red='\033[0;31m'; c_yellow='\033[0;33m'; c_reset='\033[0m'
PASS=0; FAIL=0; SKIP=0; FAILED=()
pass() { echo -e "  ${c_green}PASS${c_reset} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${c_red}FAIL${c_reset} $1"; FAIL=$((FAIL+1)); FAILED+=("$1"); [ -n "${2:-}" ] && echo "        ↳ $2"; }
skip() { echo -e "  ${c_yellow}SKIP${c_reset} $1"; SKIP=$((SKIP+1)); }

if ! docker image inspect "$SCANNER_IMG" >/dev/null 2>&1; then
    echo "[ERROR] scanner image '$SCANNER_IMG' not found. Build it first:"
    echo "        docker build -t $SCANNER_IMG ./docker"
    exit 1
fi

# Example dirs that represent a buildable source project (docker/ is image-only).
ALL_PROJECTS=(java-maven java-gradle nodejs python go ruby php rust dotnet swift)
if [ -n "${ONLY:-}" ]; then read -r -a PROJECTS <<< "$ONLY"; else PROJECTS=("${ALL_PROJECTS[@]}"); fi

echo "=================================================="
echo " sbom-tools Examples E2E  (image: $SCANNER_IMG)"
echo " projects: ${PROJECTS[*]}"
echo "=================================================="

for proj in "${PROJECTS[@]}"; do
    src="$EXAMPLES/$proj"
    echo ""
    echo "▶ $proj"
    if [ ! -d "$src" ]; then skip "$proj (example dir missing)"; continue; fi

    w="$(mktemp -d "$WORK_ROOT/${proj}.XXXXXX")"
    cp -R "$src/." "$w/" 2>/dev/null
    ( cd "$w" && SBOM_SCANNER_IMAGE="$SCANNER_IMG" bash "$SCAN" \
        --project "$proj" --version "1.0" --all --generate-only ) > "$w/_scan.log" 2>&1
    rc=$?

    # scan-sbom.sh writes each run into a per-run subfolder
    # <base>/<project>_<version>/ (SBOM_OUTPUT_FLAT=1 would restore the flat
    # layout). The base here is the work dir, so artifacts land under $w/<run>/.
    rd="$w/${proj}_1.0"
    bom="$rd/${proj}_1.0_bom.json"
    # Assert the BOM is CycloneDX, carries the input project name (not cdxgen's
    # source coords or a temp path), and has an array components (not null).
    if [ "$rc" -eq 0 ] && [ -f "$bom" ] && jq -e --arg p "$proj" \
        '.bomFormat=="CycloneDX" and .metadata.component.name==$p and (.components|type)=="array"' \
        "$bom" >/dev/null 2>&1; then
        pass "$proj: valid CycloneDX SBOM (name + array components)"
        ncomp=$(jq '[.components[]?]|length' "$bom" 2>/dev/null || echo 0)
        if [ "${ncomp:-0}" -gt 0 ]; then
            pass "$proj: SBOM has components ($ncomp)"
        else
            fail "$proj: SBOM has components" "0 components — dependency resolution may have failed"
        fi
    else
        fail "$proj: valid CycloneDX SBOM" "rc=$rc; $(grep -iE 'error|fail' "$w/_scan.log" | tail -2 | tr '\n' ' ')"
    fi

    if [ -f "$rd/${proj}_1.0_NOTICE.txt" ] && [ -f "$rd/${proj}_1.0_NOTICE.html" ]; then
        pass "$proj: notice (txt+html)"
    else
        fail "$proj: notice (txt+html)"
    fi

    if [ -f "$rd/${proj}_1.0_security.json" ] && [ -f "$rd/${proj}_1.0_security.md" ] \
       && jq -e '.Results' "$rd/${proj}_1.0_security.json" >/dev/null 2>&1; then
        pass "$proj: security report (json+md, valid Trivy)"
    else
        fail "$proj: security report"
    fi
    rm -rf "$w"
done

echo ""
echo "=================================================="
echo -e " ${c_green}PASS=$PASS${c_reset}  ${c_red}FAIL=$FAIL${c_reset}  ${c_yellow}SKIP=$SKIP${c_reset}"
if [ "$FAIL" -gt 0 ]; then echo " Failed:"; for t in "${FAILED[@]}"; do echo "   - $t"; done; fi
echo "=================================================="
[ "$FAIL" -eq 0 ]
