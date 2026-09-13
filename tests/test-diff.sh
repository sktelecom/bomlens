#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-diff.sh — No-Docker checks for diff-ai-model.py, the reader behind
# MODE=DIFF (comparing two already-generated AI-model SBOMs for drift).
#
# Every fixture is a minimal CycloneDX document built here, not committed:
# the cases only need one machine-learning-model component each, and writing
# them inline keeps the specific property/hash/license combination each
# assertion needs right next to the assertion.
#
# Pure python3/jq, so it runs in CI without Docker, an image, or the network.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIFFER="$ROOT_DIR/docker/lib/diff-ai-model.py"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); }

for tool in python3 jq; do
    command -v "$tool" >/dev/null 2>&1 || { echo "[ERROR] $tool is required"; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

run_diff() {   # $1=old $2=new $3=out -> sets RC
    python3 "$DIFFER" "$WORK/$1" "$WORK/$2" "$WORK/$3" 2>"$WORK/$3.err"
    RC=$?
}

# A base model component, HuggingFace-shaped: group+name+purl match what
# enrich-aibom.sh actually produces (tests/fixtures/aibom-owasp-1_7.json).
base_model() {   # $1=license $2=hash $3=extra properties json array (may be empty "[]")
    jq -n --arg lic "$1" --arg hash "$2" --argjson extra "$3" '
      {bomFormat:"CycloneDX", specVersion:"1.7", version:1,
       metadata:{timestamp:"2026-01-01T00:00:00Z"},
       components:[{
         type:"machine-learning-model",
         "bom-ref":"pkg:huggingface/acme/widget@v1",
         group:"acme", name:"widget", version:"v1",
         purl:"pkg:huggingface/acme/widget@v1",
         licenses:[{license:{id:$lic}}],
         hashes:[{alg:"SHA-256", content:$hash}],
         properties:$extra
       }]}'
}

echo "== a clean re-scan of the same model reports no drift =="
base_model Apache-2.0 "$(printf 'a%.0s' {1..64})" '[{"name":"bomlens:assessment:overall","value":"ok"}]' > "$WORK/old1.json"
cp "$WORK/old1.json" "$WORK/new1.json"
run_diff old1.json new1.json out1.json
if [ "$RC" -eq 0 ]; then
    pass "identical scans exit 0"
    [ "$(jq '.summary.matchedPairs' "$WORK/out1.json")" = "1" ] && pass "the model is matched" || fail "not matched"
    [ "$(jq '.summary.verdictEscalations' "$WORK/out1.json")" = "0" ] && pass "no escalation" || fail "false escalation"
    [ "$(jq '.summary.licenseChanges' "$WORK/out1.json")" = "0" ] && pass "no license change" || fail "false license change"
    [ "$(jq '.summary.hashMismatches' "$WORK/out1.json")" = "0" ] && pass "no hash mismatch" || fail "false hash mismatch"
    [ "$(jq -r '.matched[0].matchedOn' "$WORK/out1.json")" = "huggingface-id" ] \
        && pass "matched on the HuggingFace id" || fail "wrong match tier"
else
    fail "identical scans should exit 0" "$(cat "$WORK/out1.json.err")"
fi

echo "== a risk verdict that got worse is reported as an escalation =="
base_model Apache-2.0 "$(printf 'a%.0s' {1..64})" '[{"name":"bomlens:assessment:overall","value":"ok"},{"name":"bomlens:assessment:license","value":"ok"}]' > "$WORK/old2.json"
base_model Apache-2.0 "$(printf 'a%.0s' {1..64})" '[{"name":"bomlens:assessment:overall","value":"caution"},{"name":"bomlens:assessment:license","value":"caution"}]' > "$WORK/new2.json"
run_diff old2.json new2.json out2.json
if [ "$RC" -eq 0 ]; then
    [ "$(jq '.summary.verdictEscalations' "$WORK/out2.json")" = "1" ] && pass "escalation counted" || fail "escalation not counted"
    esc=$(jq -r '[.matched[0].verdictChanges[] | select(.axis=="overall") | .escalated] | .[0]' "$WORK/out2.json")
    [ "$esc" = "true" ] && pass "overall axis flagged escalated" || fail "overall axis not flagged escalated"
    old_v=$(jq -r '.matched[0].verdictChanges[] | select(.axis=="overall") | .old' "$WORK/out2.json")
    new_v=$(jq -r '.matched[0].verdictChanges[] | select(.axis=="overall") | .new' "$WORK/out2.json")
    [ "$old_v/$new_v" = "ok/caution" ] && pass "old/new verdict values recorded" || fail "old/new verdict values wrong: $old_v/$new_v"
    [ "$(jq -r '.matched[0].flags | index("verdict-escalation")' "$WORK/out2.json")" != "null" ] \
        && pass "verdict-escalation flag set" || fail "verdict-escalation flag missing"
else
    fail "verdict escalation case should exit 0" "$(cat "$WORK/out2.json.err")"
fi

echo "== a verdict that only improves is NOT reported as an escalation =="
base_model Apache-2.0 "$(printf 'a%.0s' {1..64})" '[{"name":"bomlens:assessment:overall","value":"caution"}]' > "$WORK/old2b.json"
base_model Apache-2.0 "$(printf 'a%.0s' {1..64})" '[{"name":"bomlens:assessment:overall","value":"ok"}]' > "$WORK/new2b.json"
run_diff old2b.json new2b.json out2b.json
if [ "$RC" -eq 0 ]; then
    [ "$(jq '.summary.verdictEscalations' "$WORK/out2b.json")" = "0" ] && pass "an improving verdict is not an escalation" || fail "an improvement was wrongly flagged as an escalation"
    esc=$(jq -r '[.matched[0].verdictChanges[] | select(.axis=="overall") | .escalated] | .[0]' "$WORK/out2b.json")
    [ "$esc" = "false" ] && pass "escalated=false on an improvement" || fail "escalated flag wrong on an improvement: $esc"
else
    fail "improving-verdict case should exit 0" "$(cat "$WORK/out2b.json.err")"
fi

echo "== a declared license change is reported =="
base_model Apache-2.0 "$(printf 'a%.0s' {1..64})" '[]' > "$WORK/old3.json"
base_model MIT         "$(printf 'a%.0s' {1..64})" '[]' > "$WORK/new3.json"
run_diff old3.json new3.json out3.json
if [ "$RC" -eq 0 ]; then
    [ "$(jq '.summary.licenseChanges' "$WORK/out3.json")" = "1" ] && pass "license change counted" || fail "license change not counted"
    old_l=$(jq -r '.matched[0].licenseChange.old[0]' "$WORK/out3.json")
    new_l=$(jq -r '.matched[0].licenseChange.new[0]' "$WORK/out3.json")
    [ "$old_l/$new_l" = "Apache-2.0/MIT" ] && pass "old/new license text recorded" || fail "license text wrong: $old_l/$new_l"
    [ "$(jq -r '.matched[0].flags | index("license-change")' "$WORK/out3.json")" != "null" ] \
        && pass "license-change flag set" || fail "license-change flag missing"
    [ "$(jq '.summary.hashMismatches' "$WORK/out3.json")" = "0" ] && pass "hash unaffected by the license change" || fail "hash wrongly flagged"
else
    fail "license change case should exit 0" "$(cat "$WORK/out3.json.err")"
fi

echo "== the same declared name/purl but a different weight hash is a mismatch (the headline case) =="
base_model Apache-2.0 "$(printf 'a%.0s' {1..64})" '[]' > "$WORK/old4.json"
base_model Apache-2.0 "$(printf 'b%.0s' {1..64})" '[]' > "$WORK/new4.json"
run_diff old4.json new4.json out4.json
if [ "$RC" -eq 0 ]; then
    [ "$(jq '.summary.hashMismatches' "$WORK/out4.json")" = "1" ] && pass "hash mismatch counted" || fail "hash mismatch not counted"
    [ "$(jq -r '.matched[0].flags | index("hash-mismatch")' "$WORK/out4.json")" != "null" ] \
        && pass "hash-mismatch flag set" || fail "hash-mismatch flag missing"
    [ "$(jq '.summary.licenseChanges' "$WORK/out4.json")" = "0" ] && pass "license unaffected by the hash change" || fail "license wrongly flagged"
    grep -q "HASH MISMATCH" "$WORK/out4.json.err" && pass "the human summary calls out the hash mismatch" || fail "human summary missing the hash mismatch line"
else
    fail "hash mismatch case should exit 0" "$(cat "$WORK/out4.json.err")"
fi

echo "== a component present in only one of the two documents is unmatched, not silently dropped =="
base_model Apache-2.0 "$(printf 'a%.0s' {1..64})" '[]' > "$WORK/old5.json"
jq '.components[0].name = "gizmo" | .components[0].purl = "pkg:huggingface/acme/gizmo@v1" | .components[0]["bom-ref"] = "pkg:huggingface/acme/gizmo@v1"' \
    "$WORK/old5.json" > "$WORK/new5.json"
run_diff old5.json new5.json out5.json
if [ "$RC" -eq 0 ]; then
    [ "$(jq '.summary.matchedPairs' "$WORK/out5.json")" = "0" ] && pass "no false match between two different models" || fail "wrongly matched two different models"
    [ "$(jq '.unmatched | length' "$WORK/out5.json")" = "2" ] && pass "both components reported as unmatched" || fail "unmatched count wrong"
    sides=$(jq -r '[.unmatched[].side] | sort | join(",")' "$WORK/out5.json")
    [ "$sides" = "new,old" ] && pass "one unmatched on each side" || fail "unmatched sides wrong: $sides"
else
    fail "unmatched case should exit 0" "$(cat "$WORK/out5.json.err")"
fi

echo "== a model-file scan (pkg:generic, no HuggingFace id) still matches without one =="
jq -n --arg h1 "$(printf 'c%.0s' {1..64})" '
  {bomFormat:"CycloneDX", specVersion:"1.7", version:1,
   components:[{type:"machine-learning-model", name:"local-model", version:"1.0",
     purl:("pkg:generic/local-model@1.0?checksum=sha256:" + $h1),
     hashes:[{alg:"SHA-256", content:$h1}]}]}' > "$WORK/old6.json"
jq -n --arg h2 "$(printf 'd%.0s' {1..64})" '
  {bomFormat:"CycloneDX", specVersion:"1.7", version:1,
   components:[{type:"machine-learning-model", name:"local-model", version:"1.0",
     purl:("pkg:generic/local-model@1.0?checksum=sha256:" + $h2),
     hashes:[{alg:"SHA-256", content:$h2}]}]}' > "$WORK/new6.json"
run_diff old6.json new6.json out6.json
if [ "$RC" -eq 0 ]; then
    [ "$(jq '.summary.matchedPairs' "$WORK/out6.json")" = "1" ] && pass "a re-delivered model file matches by name" || fail "model-file re-delivery not matched"
    # The checksum qualifier is stripped before matching (it is the very thing
    # being compared), so this matches on the purl's type+name — pkg:generic
    # carries no namespace, so a HuggingFace-id match never applies here.
    [ "$(jq -r '.matched[0].matchedOn' "$WORK/out6.json")" = "purl-name" ] && pass "matched on purl-name (checksum qualifier ignored for matching)" || fail "matched on the wrong tier"
    [ "$(jq '.summary.hashMismatches' "$WORK/out6.json")" = "1" ] && pass "the re-delivered file's changed hash is caught" || fail "hash change on a model file was missed"
else
    fail "model-file matching case should exit 0" "$(cat "$WORK/out6.json.err")"
fi

echo "== tool errors are distinguished from a clean comparison =="
run_diff old1.json does-not-exist.json out7.json
[ "$RC" -eq 1 ] && grep -q "new SBOM not found" "$WORK/out7.json.err" \
    && pass "a missing file exits 1 with a clear message" || fail "missing-file handling wrong (rc=$RC)"

echo '{not json' > "$WORK/bad.json"
run_diff bad.json old1.json out8.json
[ "$RC" -eq 1 ] && grep -q "could not read" "$WORK/out8.json.err" \
    && pass "invalid JSON exits 1 with a clear message" || fail "invalid-JSON handling wrong (rc=$RC)"

echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "$WORK/nomodel1.json"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "$WORK/nomodel2.json"
run_diff nomodel1.json nomodel2.json out9.json
[ "$RC" -eq 1 ] && grep -q "nothing to compare" "$WORK/out9.json.err" \
    && pass "neither side having a model exits 1, not a silent empty report" || fail "no-model handling wrong (rc=$RC)"

echo ""
echo "=========================================="
echo " model diff: $PASS passed, $FAIL failed"
echo "=========================================="
[ "$FAIL" -eq 0 ] || exit 1
