#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-aibom.sh — No-Docker checks that the common post-processing keeps an AI
# SBOM intact. The OWASP AIBOM Generator (run in the opt-in image, not here)
# emits CycloneDX 1.7; the fixture tests/fixtures/aibom-owasp-1_7.json is a real
# captured output. We drive normalize-sbom.sh and generate-notice.sh over it and
# assert that the 1.7 specVersion, the modelCard, and the model license survive.
# Pure jq/bash, so it runs in CI without Docker, a scanner image, or the network.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); }

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required for aibom post-process tests"; exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== fixture is a CycloneDX 1.7 AI SBOM with a model card =="
cp "$FIX/aibom-owasp-1_7.json" "$WORK/a.json"
spec=$(jq -r '.specVersion' "$WORK/a.json")
[ "$spec" = "1.7" ] && pass "fixture specVersion is 1.7" || fail "fixture specVersion='$spec', expected 1.7"
if jq -e '[.components[] | select(.type=="machine-learning-model" and has("modelCard"))] | length >= 1' "$WORK/a.json" >/dev/null 2>&1; then
    pass "fixture has a machine-learning-model component with a modelCard"
else
    fail "fixture lacks a model component with a modelCard"
fi

echo "== normalize-sbom.sh preserves the 1.7 specVersion and the modelCard =="
bash "$LIB/normalize-sbom.sh" "$WORK/a.json" >/dev/null 2>&1
spec=$(jq -r '.specVersion' "$WORK/a.json")
[ "$spec" = "1.7" ] && pass "specVersion stays 1.7 after normalize (not clobbered to 1.6)" || fail "specVersion='$spec' after normalize, expected 1.7"
if jq -e '[.components[] | select(.type=="machine-learning-model" and has("modelCard"))] | length >= 1' "$WORK/a.json" >/dev/null 2>&1; then
    pass "modelCard survives normalize"
else
    fail "modelCard lost during normalize"
fi
mlid=$(jq -r '.components[] | select(.type=="machine-learning-model") | .licenses[0].license.id // .licenses[0].license.name // "ABSENT"' "$WORK/a.json")
[ "$mlid" = "Apache-2.0" ] && pass "model license stays Apache-2.0" || fail "model license='$mlid', expected Apache-2.0"

echo "== scan-aibom.sh keeps the generator's 1.7 variant =="
# Mock the OWASP generator (no network/image): a fake `aibom` on PATH writes a 1.6
# file to --output and the 1.7 variant to <out>_1_7.json (the captured fixture).
# This exercises scan-aibom.sh's output-selection without HuggingFace.
mkdir -p "$WORK/bin"
cat > "$WORK/bin/aibom" <<MOCK
#!/bin/bash
out=""; prev=""
for a in "\$@"; do [ "\$prev" = "--output" ] && out="\$a"; prev="\$a"; done
[ -n "\$out" ] || exit 1
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "\$out"
cp "$FIX/aibom-owasp-1_7.json" "\${out%.json}_1_7.json"
exit 0
MOCK
chmod +x "$WORK/bin/aibom"
if PATH="$WORK/bin:$PATH" bash "$LIB/scan-aibom.sh" "google-bert/bert-base-uncased" "$WORK/out.json" "1.0.0" >/dev/null 2>&1; then
    kept=$(jq -r '.specVersion' "$WORK/out.json" 2>/dev/null)
    [ "$kept" = "1.7" ] && pass "scan-aibom.sh kept the 1.7 output (not the 1.6 default)" || fail "kept specVersion='$kept', expected 1.7"
else
    fail "scan-aibom.sh failed against the mock generator"
fi

echo "== generate-notice.sh lists the model license =="
bash "$LIB/generate-notice.sh" "$WORK/a.json" "$WORK/notice" "bert-base-uncased" >/dev/null 2>&1
NOTICE="$WORK/notice_NOTICE.txt"
if [ -f "$NOTICE" ] && grep -q "Apache-2.0" "$NOTICE"; then
    pass "NOTICE lists Apache-2.0"
else
    fail "NOTICE missing or has no Apache-2.0 entry"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
