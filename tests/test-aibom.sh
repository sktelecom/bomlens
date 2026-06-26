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

echo "== scan-aibom.sh rejects a card-less stub (degraded offline output) =="
# Same mock shape, but the 1.7 variant carries a model component with NO
# modelCard — the degraded stub the generator emits when it cannot reach the
# card (offline, or a nonexistent/private model id). The gate must hard-fail and
# leave no artifact, not pass an empty ML-BOM off as a real supply-chain output.
cat > "$WORK/bin/aibom" <<MOCK
#!/bin/bash
out=""; prev=""
for a in "\$@"; do [ "\$prev" = "--output" ] && out="\$a"; prev="\$a"; done
[ -n "\$out" ] || exit 1
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "\$out"
echo '{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"machine-learning-model","name":"stub"}]}' > "\${out%.json}_1_7.json"
exit 0
MOCK
chmod +x "$WORK/bin/aibom"
if PATH="$WORK/bin:$PATH" bash "$LIB/scan-aibom.sh" "ghost/missing-model" "$WORK/stub.json" "1.0.0" >/dev/null 2>&1; then
    fail "scan-aibom.sh rejects a card-less stub" "exited 0 instead of failing"
elif [ -f "$WORK/stub.json" ]; then
    fail "scan-aibom.sh rejects a card-less stub" "left a stub artifact behind"
else
    pass "scan-aibom.sh rejects a card-less stub and leaves no artifact"
fi

echo "== generate-notice.sh lists the model license =="
bash "$LIB/generate-notice.sh" "$WORK/a.json" "$WORK/notice" "bert-base-uncased" >/dev/null 2>&1
NOTICE="$WORK/notice_NOTICE.txt"
if [ -f "$NOTICE" ] && grep -q "Apache-2.0" "$NOTICE"; then
    pass "NOTICE lists Apache-2.0"
else
    fail "NOTICE missing or has no Apache-2.0 entry"
fi

echo "== validate-sbom.sh adds G7 minimum-element checks for an AI SBOM =="
bash "$LIB/validate-sbom.sh" "$FIX/aibom-owasp-1_7.json" "$WORK/conf" "bert-base-uncased" >/dev/null 2>&1
CONF="$WORK/conf_conformance.json"
if [ -f "$CONF" ]; then
    g7n=$(jq '[.checks[] | select(.id|startswith("g7-"))] | length' "$CONF")
    [ "$g7n" -ge 5 ] && pass "G7 checks present ($g7n)" || fail "expected >=5 G7 checks, got $g7n"
    licst=$(jq -r '.checks[] | select(.id=="g7-model-license") | .status' "$CONF")
    [ "$licst" = "pass" ] && pass "g7-model-license passes (Apache-2.0 present)" || fail "g7-model-license='$licst', expected pass"
    # Passing checks carry the actual SBOM values as evidence ("met with these").
    licev=$(jq -r '.checks[] | select(.id=="g7-model-license") | (.evidence // []) | join(",")' "$CONF")
    echo "$licev" | grep -q "Apache-2.0" && pass "g7-model-license evidence shows Apache-2.0" || fail "g7-model-license evidence='$licev', expected Apache-2.0"
    idev=$(jq -r '.checks[] | select(.id=="g7-model-id") | (.evidence // []) | length' "$CONF")
    [ "$idev" -ge 1 ] && pass "g7-model-id carries evidence (the PURL/CPE)" || fail "g7-model-id evidence is empty"
    # A warn-status element has nothing to show, so its evidence stays empty.
    hashev=$(jq -r '.checks[] | select(.id=="g7-model-hash") | (.evidence // []) | length' "$CONF")
    [ "$hashev" -eq 0 ] && pass "g7-model-hash (warn) carries no evidence" || fail "g7-model-hash evidence should be empty"
    # The known engine gaps (no hashes, no openness axis) must surface as warnings.
    hashst=$(jq -r '.checks[] | select(.id=="g7-model-hash") | .status' "$CONF")
    [ "$hashst" = "warn" ] && pass "g7-model-hash warns (integrity gap surfaced)" || fail "g7-model-hash='$hashst', expected warn"
    openst=$(jq -r '.checks[] | select(.id=="g7-openness") | .status' "$CONF")
    [ "$openst" = "warn" ] && pass "g7-openness warns (4-axis not declared)" || fail "g7-openness='$openst', expected warn"
    # G7 checks are advisory: they must not flip the overall result to fail.
    res=$(jq -r '.result' "$CONF")
    [ "$res" != "fail" ] && pass "advisory G7 warnings do not fail the overall result" || fail "overall result is fail; G7 should be warn-only"
else
    fail "validate-sbom.sh did not produce a conformance report"
fi

echo "== generate-notice.sh flags AI restrictive licenses for review =="
bash "$LIB/generate-notice.sh" "$FIX/notice-ai-licenses.json" "$WORK/rev" "demo" >/dev/null 2>&1
RTXT="$WORK/rev_NOTICE.txt"
if [ -f "$RTXT" ] && grep -q "License review needed" "$RTXT"; then
    pass "NOTICE has a license-review section"
    grep -q "behavioral-use" "$RTXT" && grep -q "Llama" "$RTXT" && pass "Llama community license flagged behavioral-use" || fail "Llama not flagged behavioral-use"
    grep -q "non-commercial" "$RTXT" && grep -q "CC-BY-NC-4.0" "$RTXT" && pass "CC-BY-NC flagged non-commercial" || fail "CC-BY-NC not flagged non-commercial"
    # An ordinary MIT component must NOT land in the review section.
    if awk '/License review needed/{f=1} /SPDX standard/{f=0} f&&/ordinary-lib/{bad=1} END{exit !bad}' "$RTXT"; then
        fail "MIT component wrongly listed for review"
    else
        pass "ordinary MIT component not flagged"
    fi
else
    fail "NOTICE has no license-review section for restrictive licenses"
fi

echo "== a normal (non-AI) NOTICE has no review section =="
bash "$LIB/generate-notice.sh" "$FIX/license-aliases.json" "$WORK/norm" "x" >/dev/null 2>&1
if grep -q "License review needed" "$WORK/norm_NOTICE.txt" 2>/dev/null; then
    fail "review section appeared for a normal software scan"
else
    pass "no review section for a normal software scan"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
