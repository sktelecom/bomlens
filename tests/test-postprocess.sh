#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-postprocess.sh — No-Docker unit tests for the SBOM post-processing
# scripts (normalize-sbom.sh, stamp-metadata.sh, generate-notice.sh), driven by
# regression fixtures for the defects from the verification report:
#   B-1  --byte-stable leaks cdxgen's random venv name
#   B-3  cdxgen emits components:null + a temp upload path as the root name
#   B-2  metadata.component carries source coordinates, not the input identity
#   B-4  NOTICE duplicates license texts; "Expat" is not normalized to MIT
# Pure jq/bash, so it runs in CI without Docker or a scanner image.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required for post-process unit tests"; exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== B-1: --byte-stable normalizes cdxgen venv name =="
cp "$FIX/venv-leak-a.json" "$WORK/a.json"
cp "$FIX/venv-leak-b.json" "$WORK/b.json"
bash "$LIB/normalize-sbom.sh" "$WORK/a.json" --stable >/dev/null 2>&1
bash "$LIB/normalize-sbom.sh" "$WORK/b.json" --stable >/dev/null 2>&1
if diff -q "$WORK/a.json" "$WORK/b.json" >/dev/null 2>&1; then
    pass "two inputs differing only in venv name are byte-identical after --stable"
else
    fail "byte-stable normalization left a difference" "$(diff "$WORK/a.json" "$WORK/b.json" | head)"
fi
if ! grep -Eq 'cdxgen-venv-[A-Za-z0-9]+' "$WORK/a.json"; then
    pass "no random venv suffix remains"
else
    fail "random cdxgen-venv suffix still present"
fi

echo "== B-3: null components coerced to an array =="
cp "$FIX/null-components.json" "$WORK/n.json"
bash "$LIB/normalize-sbom.sh" "$WORK/n.json" >/dev/null 2>&1
ctype=$(jq -r '.components | type' "$WORK/n.json" 2>/dev/null)
if [ "$ctype" = "array" ]; then pass "components is an array (was null)"; else fail "components type is '$ctype', expected array"; fi

echo "== B-2/B-3: metadata stamped from input, temp path gone =="
cp "$FIX/null-components.json" "$WORK/m.json"
bash "$LIB/stamp-metadata.sh" "$WORK/m.json" "MyProj" "2.0.0" >/dev/null 2>&1
nm=$(jq -r '.metadata.component.name' "$WORK/m.json")
ver=$(jq -r '.metadata.component.version' "$WORK/m.json")
purl=$(jq -r '.metadata.component.purl // "ABSENT"' "$WORK/m.json")
[ "$nm" = "MyProj" ] && pass "metadata.component.name = input project" || fail "name='$nm', expected MyProj"
[ "$ver" = "2.0.0" ] && pass "metadata.component.version = input version" || fail "version='$ver', expected 2.0.0"
[ "$purl" = "ABSENT" ] && pass "stale purl dropped" || fail "purl still present: $purl"
if ! grep -Eq 'host-output|\.uploads|extracted' "$WORK/m.json"; then
    pass "no internal temp path leaks into the SBOM"
else
    fail "temp upload path still present in metadata"
fi

echo "== B-4: NOTICE dedupes license texts and normalizes Expat to MIT =="
cp "$FIX/license-aliases.json" "$WORK/l.json"
bash "$LIB/generate-notice.sh" "$WORK/l.json" "$WORK/notice" "FixtureProj" >/dev/null 2>&1
NOTICE="$WORK/notice_NOTICE.txt"
if [ -f "$NOTICE" ]; then
    apa=$(grep -c '^----------------------------- Apache-2.0 ' "$NOTICE")
    mit=$(grep -c '^----------------------------- MIT ' "$NOTICE")
    [ "$apa" = "1" ] && pass "Apache-2.0 license text appears exactly once" || fail "Apache-2.0 text appears ${apa}x (dedupe regression)"
    [ "$mit" = "1" ] && pass "MIT license text appears exactly once" || fail "MIT text appears ${mit}x"
    if ! grep -q "Expat" "$NOTICE"; then
        pass "Expat alias normalized away"
    else
        fail "Expat license not normalized to MIT"
    fi
    if awk '/^License: MIT$/{f=1;next} /^License: /{f=0} f&&/mccabe/{ok=1} END{exit !ok}' "$NOTICE"; then
        pass "mccabe (Expat) grouped under MIT"
    else
        fail "mccabe not grouped under MIT"
    fi
else
    fail "generate-notice.sh did not produce $NOTICE"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
