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

echo "== V13-2: normalize-sbom.sh maps bom.json license aliases to SPDX ids =="
cp "$FIX/license-aliases.json" "$WORK/c.json"
bash "$LIB/normalize-sbom.sh" "$WORK/c.json" >/dev/null 2>&1
# Free-text alias in .expression is promoted to a proper .license.id.
mccabe_id=$(jq -r '.components[] | select(.name=="mccabe") | .licenses[0].license.id // "ABSENT"' "$WORK/c.json")
[ "$mccabe_id" = "MIT" ] && pass "Expat expression promoted to license id MIT" || fail "mccabe license id='$mccabe_id', expected MIT"
# Free-text alias in .license.name is promoted as well.
cov_id=$(jq -r '.components[] | select(.name=="coverage") | .licenses[0].license.id // "ABSENT"' "$WORK/c.json")
[ "$cov_id" = "Apache-2.0" ] && pass "free-text license name promoted to id Apache-2.0" || fail "coverage license id='$cov_id', expected Apache-2.0"
# A valid-but-wrong upstream id (cdxgen 0BSD mislabel) is preserved, not guessed.
flask_id=$(jq -r '.components[] | select(.name=="flask") | .licenses[0].license.id // "ABSENT"' "$WORK/c.json")
flask_url=$(jq -r '.components[] | select(.name=="flask") | .licenses[0].license.url // "ABSENT"' "$WORK/c.json")
[ "$flask_id" = "0BSD" ] && pass "valid-but-wrong upstream id (0BSD) preserved, not rewritten" || fail "flask license id='$flask_id', expected 0BSD"
[ "$flask_url" = "https://opensource.org/licenses/0BSD" ] && pass "license url preserved" || fail "flask license url='$flask_url'"
# A non-mappable free-text string and a genuine compound expression are untouched.
date_expr=$(jq -r '.components[] | select(.name=="python-dateutil") | .licenses[0].expression // "ABSENT"' "$WORK/c.json")
[ "$date_expr" = "Dual License" ] && pass "unmappable free text (Dual License) left untouched" || fail "dateutil expression='$date_expr', expected Dual License"
pkg_expr=$(jq -r '.components[] | select(.name=="packaging") | .licenses[0].expression // "ABSENT"' "$WORK/c.json")
[ "$pkg_expr" = "Apache-2.0 OR BSD-2-Clause" ] && pass "compound expression left untouched" || fail "packaging expression='$pkg_expr'"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
