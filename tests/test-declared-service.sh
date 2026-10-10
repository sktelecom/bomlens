#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-declared-service.sh: No-Docker checks for docker/lib/apply-declared-service.py,
# the step that writes the AI service a publisher declared (and the model's
# declared input and output kinds, training compute and adversarial testing)
# into the CycloneDX SBOM. The contract under test: only a declaration the SPDX
# converter accepts is applied; what is written is marked as the publisher's
# declaration; applying is idempotent and byte-stable; the result is valid
# CycloneDX 1.7; observed model values win over declared ones; and the G7
# system-level checks read the declared service while an SBOM without one
# reads exactly as before. Pure jq/python, offline.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures/spdx3"
APPLY="$LIB/apply-declared-service.py"
CONV="$LIB/convert-to-spdx3-ai.py"
BOM="$FIX/bom-ai-sample.json"
SVC="$FIX/declaration-service.json"
PLAIN="$FIX/declaration-complete.json"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/cdx"

applied() {  # <name> <declaration> [bom]: a fresh copy of the SBOM with the declaration applied
    cp "${3:-$BOM}" "$WORK/$1.json"
    python3 -I "$APPLY" "$WORK/$1.json" "$2" >"$WORK/$1.log" 2>&1
}
state_of() { python3 -I "$CONV" check --bom "$1" --declaration "$2" 2>/dev/null | jq -r .service.state; }
g7() {  # <sbom> <prefix>: the G7 system-level rows of its conformance check
    bash "$LIB/validate-sbom.sh" "$1" "$WORK/$2" x >/dev/null 2>&1
    jq -c '[.checks[] | select(.id|startswith("g7-slp")) | {id, status, source, detail}]' "$WORK/$2_conformance.json"
}

echo "== the declared service is written to services[] =="
applied svc "$SVC"
[ $? -eq 0 ] && pass "the step succeeds" || fail "the step failed" "$(cat "$WORK/svc.log")"
S="$WORK/svc.json"
app=$(jq -c '[.services[] | select(.["bom-ref"]=="service:declared/acme-support-assistant")] | first' "$S")
{ [ "$(echo "$app" | jq -c '[.name, .version, .provider.name, .endpoints, .description != null]')" \
    = '["Acme Support Assistant","2.3.0","Acme Corp",["https://support.acme.example/assistant"],true]' ] \
  && [ "$(echo "$app" | jq -c '[.externalReferences[] | "\(.type) \(.url)"]')" = '["documentation https://support.acme.example/ai-disclosure"]' ]; } \
    && pass "the application service carries name, version, provider, endpoint, description and the disclosure page" \
    || fail "application service" "$app"
{ [ "$(echo "$app" | jq -c '[.data[] | [.flow, .classification, (.source // .destination)[0]]]')" \
    = '[["inbound","personal data","https://support.acme.example/chat"],["outbound","personal data","https://api.translate.example/v1"]]' ] \
  && [ "$(echo "$app" | jq -r '[.data[].description] | length')" = "2" ]; } \
    && pass "each data flow is CycloneDX serviceData" || fail "service data" "$(echo "$app" | jq -c .data)"
props=$(echo "$app" | jq -r '[.properties[] | "\(.name)=\(.value)"] | join(" ")')
case "$props" in
    "bomlens:origin=declared-input bomlens:service:kind=application bomlens:service:domain=customer support bomlens:service:autonomyType=no bomlens:service:input=text bomlens:service:output=text bomlens:service:releaseTime=2025-06-01T00:00:00Z bomlens:service:declarationDigest="*)
        pass "the service is marked declared-input and carries domain, autonomy, input, output and release time" ;;
    *) fail "service properties" "$props" ;;
esac
ext=$(jq -c '[.services[] | select(.["bom-ref"]=="service:declared-external/translate")] | first' "$S")
[ "$(echo "$ext" | jq -c '[.name, .version, .provider.name, .endpoints[0], ([.properties[] | "\(.name)=\(.value)"] | join(" "))]')" \
  = '["Example Translate","2025-05","Example Inc","https://api.translate.example/v1","bomlens:origin=declared-input bomlens:service:kind=external-model bomlens:service:declarationKey=translate"]' ] \
    && pass "the external model is its own service, kind external-model, identity only" || fail "external model service" "$ext"
[ "$(jq -c '[.dependencies[] | select(.ref | startswith("service:"))]' "$S")" \
  = '[{"ref":"service:declared/acme-support-assistant","dependsOn":["pkg:huggingface/acme/support-adapter@1a2b3c4d","service:declared-external/translate"]},{"ref":"service:declared-external/translate","dependsOn":[]}]' ] \
    && pass "the service depends on the model and on the external model" || fail "dependencies" "$(jq -c '.dependencies' "$S")"
[ "$(jq -c '.declarations.claims' "$S")" \
  = '[{"bom-ref":"claim:declared/acme-support-assistant/1","target":"service:declared/acme-support-assistant","predicate":"ISO/IEC 42001:2023","reasoning":"publisher'"'"'s declaration, not verified by BomLens"}]' ] \
    && pass "the standard is a claim on the service, said to be the publisher's declaration" || fail "claims" "$(jq -c .declarations "$S")"
[ "$(state_of "$S" "$SVC")" = "applied" ] && pass "the converter's check reads it as applied" || fail "state=$(state_of "$S" "$SVC")"

echo "== the model's declared values are written on the model, marked as declared =="
mprops=$(jq -r '[.metadata.component.properties[] | select(.name | test("^bomlens:(regulatory|declared|model:declarationDigest)")) | "\(.name)=\(.value)"] | join("|")' "$S")
case "$mprops" in
    "bomlens:regulatory:trainingComputeFlops=3.2e21|bomlens:regulatory:trainingComputeBasis=6 x parameters x training tokens, from the training logs|bomlens:regulatory:adversarialTesting=yes|bomlens:declared=bomlens:regulatory:trainingComputeFlops|bomlens:declared=bomlens:regulatory:trainingComputeBasis|bomlens:declared=bomlens:regulatory:adversarialTesting|bomlens:declared=modelCard.modelParameters.inputs|bomlens:declared=modelCard.modelParameters.outputs|bomlens:model:declarationDigest="*)
        pass "regulatory properties, one bomlens:declared per written item, and the digest" ;;
    *) fail "model properties" "$mprops" ;;
esac
[ "$(jq -c '.metadata.component.modelCard.modelParameters | [.inputs, .outputs, .task]' "$S")" = '[[{"format":"text"}],[{"format":"text"}],"text-generation"]' ] \
    && pass "input and output kinds become modelCard inputs and outputs formats, the rest of the card kept" \
    || fail "model card formats" "$(jq -c .metadata.component.modelCard.modelParameters "$S")"
# Observed formats win: the scan's inputs stay, the declared kind is not written.
jq '.metadata.component.modelCard.modelParameters.inputs = [{"format": "image"}]' "$BOM" > "$WORK/observed-bom.json"
applied observed "$SVC" "$WORK/observed-bom.json"
O="$WORK/observed.json"
{ [ "$(jq -c '.metadata.component.modelCard.modelParameters | [.inputs, .outputs]' "$O")" = '[[{"format":"image"}],[{"format":"text"}]]' ] \
  && [ "$(jq -r '[.metadata.component.properties[] | select(.name=="bomlens:declared:observedKept") | .value] | join(",")' "$O")" = "modelCard.modelParameters.inputs" ] \
  && ! jq -e '.metadata.component.properties[] | select(.name=="bomlens:declared" and .value=="modelCard.modelParameters.inputs")' "$O" >/dev/null \
  && grep -q "the observed values are kept" "$WORK/observed.log"; } \
    && pass "inputs the scan recorded are kept, recorded in bomlens:declared:observedKept" \
    || fail "observed formats" "$(jq -c '.metadata.component | {mp: .modelCard.modelParameters, p: .properties}' "$O")"
cp "$O" "$WORK/observed-again.json"
python3 -I "$APPLY" "$WORK/observed-again.json" "$SVC" >/dev/null 2>&1
cmp -s "$O" "$WORK/observed-again.json" && pass "and applying again keeps the observed inputs" || fail "observed inputs changed on a second run"
# A model with no card gets one only for the declared kinds, and gives it back.
jq 'del(.metadata.component.modelCard)' "$BOM" > "$WORK/nocard-bom.json"
applied nocard "$SVC" "$WORK/nocard-bom.json"
{ [ "$(jq -c '.metadata.component.modelCard' "$WORK/nocard.json")" = '{"modelParameters":{"inputs":[{"format":"text"}],"outputs":[{"format":"text"}]}}' ] \
  && [ "$(jq -r '[.metadata.component.properties[] | select(.name=="bomlens:declared") | .value] | map(select(startswith("modelCard"))) | join(",")' "$WORK/nocard.json")" \
     = "modelCard,modelCard.modelParameters,modelCard.modelParameters.inputs,modelCard.modelParameters.outputs" ]; } \
    && pass "a card the step creates is named as declared" || fail "created card" "$(jq -c .metadata.component.modelCard "$WORK/nocard.json")"
python3 -I "$APPLY" "$WORK/nocard.json" "$PLAIN" >/dev/null 2>&1
[ "$(jq -S . "$WORK/nocard.json")" = "$(jq -S . "$WORK/nocard-bom.json")" ] \
    && pass "and a declaration without those values removes it again" || fail "created card left behind" "$(jq -c .metadata.component.modelCard "$WORK/nocard.json")"

echo "== applying is idempotent and byte-stable =="
cp "$S" "$WORK/twice.json"
python3 -I "$APPLY" "$WORK/twice.json" "$SVC" >/dev/null 2>&1
cmp -s "$S" "$WORK/twice.json" && pass "applying the same declaration twice gives the same bytes" || fail "a second run changed the SBOM"
applied again "$SVC"
cmp -s "$S" "$WORK/again.json" && pass "two runs on fresh copies give the same bytes (no clock, no random id)" || fail "fresh runs differ"
jq '.service.packageVersion = "2.4.0" | .service.standardCompliance = [] | .service.externalModels = []
    | .service.dataFlows[0].name = "Chat questions"' "$SVC" > "$WORK/svc-b.json"
cp "$S" "$WORK/a-then-b.json"
python3 -I "$APPLY" "$WORK/a-then-b.json" "$WORK/svc-b.json" >/dev/null 2>&1
applied only-b "$WORK/svc-b.json"
cmp -s "$WORK/a-then-b.json" "$WORK/only-b.json" \
    && pass "a changed declaration replaces the earlier one: the same bytes as applying it alone" || fail "earlier declared service not replaced"
{ ! jq -e '.declarations' "$WORK/only-b.json" >/dev/null \
  && [ "$(jq '[.services[] | select(.["bom-ref"] | startswith("service:declared-external/"))] | length' "$WORK/only-b.json")" = "0" ] \
  && [ "$(jq '[.dependencies[] | select(.ref | startswith("service:declared-external/"))] | length' "$WORK/only-b.json")" = "0" ] \
  && [ "$(jq -r '.services[0].data[0].name' "$WORK/only-b.json")" = "Chat questions" ]; } \
    && pass "claims, external models and their dependencies go with it; a data flow keeps its name" || fail "replacement leftovers"
cp "$S" "$WORK/removed.json"
python3 -I "$APPLY" "$WORK/removed.json" "$PLAIN" >/dev/null 2>&1
[ "$(jq -S . "$WORK/removed.json")" = "$(jq -S . "$BOM")" ] \
    && pass "a declaration with no service and no model values takes everything back out" || fail "leftovers after removal" \
    "$(diff <(jq -S . "$BOM") <(jq -S . "$WORK/removed.json") | head -20)"
[ "$(state_of "$WORK/removed.json" "$PLAIN")" = "none" ] && pass "and the check reads none" || fail "state after removal"
# A service declared after the scan is pendingScan; the next scan applies it.
[ "$(state_of "$S" "$WORK/svc-b.json")" = "pendingScan" ] && [ "$(state_of "$WORK/a-then-b.json" "$WORK/svc-b.json")" = "applied" ] \
    && pass "a changed declaration reads pendingScan until applied, then applied" || fail "pendingScan to applied"
# The SPDX 3.0.1 document is the same bytes from the same SBOM and declaration.
mkdir -p "$WORK/s1" "$WORK/s2"
python3 -I "$CONV" convert --bom "$S" --declaration "$SVC" --out-dir "$WORK/s1" --prefix=p --stable 2>/dev/null
python3 -I "$CONV" convert --bom "$WORK/again.json" --declaration "$SVC" --out-dir "$WORK/s2" --prefix=p --stable 2>/dev/null
{ cmp -s "$WORK/s1/p_bom.spdx3.json" "$WORK/s2/p_bom.spdx3.json" && [ "$(jq -r .service.state "$WORK/s1/p_spdx3-check.json")" = "applied" ]; } \
    && pass "--stable SPDX output is byte-identical and records the service as applied" || fail "spdx3 --stable output"

echo "== a declaration that is not accepted leaves the SBOM as it was =="
unchanged() {  # <label> <bom> <declaration>
    cp "$2" "$WORK/u.json"
    python3 -I "$APPLY" "$WORK/u.json" "$3" >/dev/null 2>&1; rc=$?
    { [ "$rc" -eq 0 ] && cmp -s "$2" "$WORK/u.json"; } && pass "unchanged: $1" || fail "changed: $1 (rc=$rc)"
}
jq '.service.owner = "x"' "$SVC" > "$WORK/bad-key.json"
unchanged "a refused declaration (unknown key in the service)" "$BOM" "$WORK/bad-key.json"
cp "$S" "$WORK/applied-copy.json"
unchanged "a refused declaration keeps an earlier applied service too" "$WORK/applied-copy.json" "$WORK/bad-key.json"
printf 'not json' > "$WORK/junk.json"
unchanged "a declaration that is not JSON" "$BOM" "$WORK/junk.json"
unchanged "a declaration file that does not exist" "$BOM" "$WORK/missing.json"
jq '.metadata.component = (.components[0]) | .components = .components[1:] | .dependencies = []' "$BOM" > "$WORK/dsroot.json"
unchanged "a service on a dataset document" "$WORK/dsroot.json" "$SVC"
unchanged "no service and no model values on an SBOM without either" "$BOM" "$PLAIN"

echo "== edge cases =="
jq '.service.name = ""' "$SVC" > "$WORK/decl-noname.json"
applied noname "$WORK/decl-noname.json"
{ ! jq -e '.services' "$WORK/noname.json" >/dev/null \
  && jq -e '.metadata.component.properties[] | select(.name=="bomlens:regulatory:trainingComputeFlops")' "$WORK/noname.json" >/dev/null \
  && grep -q "has no name, which CycloneDX requires" "$WORK/noname.log"; } \
    && pass "a service with no name is not written (CycloneDX requires one); the model values still are" || fail "unnamed service"
# (the datasets' roles are left out: a role needs the model's bom-ref to check.)
jq 'del(.metadata.component["bom-ref"])' "$BOM" > "$WORK/noref-bom.json"
jq 'del(.datasets[].role)' "$SVC" > "$WORK/decl-norole.json"
applied noref "$WORK/decl-norole.json" "$WORK/noref-bom.json"
{ [ "$(jq -c '[.dependencies[] | select(.ref=="service:declared/acme-support-assistant") | .dependsOn]' "$WORK/noref.json")" = '[["service:declared-external/translate"]]' ] \
  && grep -q "has no bom-ref" "$WORK/noref.log"; } \
    && pass "a model with no bom-ref gets no dependency from the service, and the log says why" || fail "model without bom-ref"
jq '.service.name = "Ünïcode 서비스"' "$SVC" > "$WORK/decl-uni.json"
applied uni "$WORK/decl-uni.json"
{ [ "$(jq -r '.services[0]["bom-ref"]' "$WORK/uni.json")" = "service:declared/n-code" ] && grep -q "Ünïcode 서비스" "$WORK/uni.json"; } \
    && pass "the bom-ref slug is plain ASCII and the name is kept as UTF-8 text" || fail "unicode name: $(jq -r '.services[0]["bom-ref"]' "$WORK/uni.json")"

echo "== the G7 system-level checks read the declared service =="
before=$(g7 "$BOM" plain)
after=$(g7 "$S" svc)
row() { echo "$1" | jq -r --arg id "$2" '.[] | select(.id==$id) | "\(.status)/\(.source)/\(.detail)"'; }
for id in g7-slp-name g7-slp-producer g7-slp-data-flow g7-slp-data-usage g7-slp-io g7-slp-app-area; do
    [ "$(row "$after" "$id")" = "pass/declared/present (publisher's declaration, not verified by BomLens)" ] \
        && pass "$id passes as the publisher's declaration" || fail "$id with a service: $(row "$after" "$id")"
done
for id in g7-slp-data-flow g7-slp-data-usage g7-slp-io g7-slp-app-area; do
    [ "$(row "$before" "$id")" = "warn/na/requires human review (no automated source)" ] \
        && pass "$id stays a review item without a service" || fail "$id without a service: $(row "$before" "$id")"
done
[ "$(jq -c '[.checks[] | select(.id=="g7-slp-data-flow") | .evidence[]]' "$WORK/svc_conformance.json")" = '["inbound: personal data","outbound: personal data"]' ] \
    && pass "the data flows are the evidence" || fail "data flow evidence"
cp "$WORK/plain_conformance.json" "$WORK/plain-before.json"
g7 "$WORK/removed.json" plain >/dev/null
[ "$(jq -S 'del(.generatedAt)' "$WORK/plain-before.json")" = "$(jq -S 'del(.generatedAt)' "$WORK/plain_conformance.json")" ] \
    && pass "an SBOM whose declared service was taken out reads exactly as one that never had it" || fail "conformance differs after removal"
grep -q "publisher's declaration, not verified by BomLens" "$WORK/svc_conformance.md" \
  && grep -q "publisher&apos;s declaration, not verified by BomLens" "$WORK/svc_conformance.html" \
    && pass "the Markdown and HTML reports say the values are the publisher's declaration" || fail "reports do not name the declaration"
REPORT_LANG=ko bash "$LIB/validate-sbom.sh" "$S" "$WORK/svcko" x >/dev/null 2>&1
{ grep -q "발행자 선언, BomLens가 확인하지 않음" "$WORK/svcko_conformance.md" \
  && [ "$(jq -r '.checks[] | select(.id=="g7-slp-io") | .detail_ko' "$WORK/svcko_conformance.json")" = "있음 (발행자 선언, BomLens가 확인하지 않음)" ]; } \
    && pass "the Korean report and detail_ko say so too" || fail "Korean declared detail"
s_review=$(jq -r '[.checks[] | select(.source=="na")] | length' "$WORK/svc_conformance.json")
p_review=$(jq -r '[.checks[] | select(.source=="na")] | length' "$WORK/plain-before.json")
[ $((p_review - s_review)) -eq 4 ] && pass "four review items become declared values ($p_review -> $s_review)" || fail "review count $p_review -> $s_review"
# Standard serviceData from another tool counts for the data flow, without
# being called a declaration.
jq '.services = [{"name": "gateway", "data": [{"flow": "inbound", "classification": "public"}]}]' "$BOM" > "$WORK/other-tool.json"
other=$(g7 "$WORK/other-tool.json" other)
{ [ "$(row "$other" g7-slp-data-flow)" = "pass/declared/present" ] \
  && [ "$(row "$other" g7-slp-io)" = "warn/na/requires human review (no automated source)" ] \
  && [ "$(row "$other" g7-slp-name)" = "warn/declared/not present in the SBOM" ]; } \
    && pass "another tool's serviceData satisfies the data flow; its service is not a declared system" \
    || fail "other tool's service" "$other"
# A declared service next to another tool's data is not called only a declaration.
jq --slurpfile s "$S" '.services = $s[0].services + [{"name": "gateway", "data": [{"flow": "inbound", "classification": "public"}]}]' \
    "$S" > "$WORK/mixed.json"
mixed=$(g7 "$WORK/mixed.json" mixed)
[ "$(row "$mixed" g7-slp-data-flow)" = "pass/declared/present" ] \
    && pass "data flows from both a declaration and another tool read as present" || fail "mixed data flows: $(row "$mixed" g7-slp-data-flow)"

# A card the step created only for the declared kinds is not a model card;
# the kinds still answer the model input/output element. A real card counts as before.
card_io() { bash "$LIB/validate-sbom.sh" "$1" "$WORK/$2" x >/dev/null 2>&1
            jq -r '[.checks[] | select(.id=="g7-model-card" or .id=="g7-model-io") | "\(.id)=\(.status)"] | join(" ")' "$WORK/$2_conformance.json"; }
cp "$WORK/nocard-bom.json" "$WORK/nocard2.json"
python3 -I "$APPLY" "$WORK/nocard2.json" "$SVC" >/dev/null 2>&1
[ "$(card_io "$WORK/nocard2.json" nocard2)" = "g7-model-card=warn g7-model-io=pass" ] \
    && pass "a step-created card does not satisfy g7-model-card; g7-model-io passes from the declared kinds" \
    || fail "step-created card: $(card_io "$WORK/nocard2.json" nocard2)"
[ "$(card_io "$WORK/nocard-bom.json" nocard0)" = "g7-model-card=warn g7-model-io=warn" ] \
    && pass "the same model without the declaration reads the same for the card" || fail "no card baseline"
[ "$(card_io "$S" svccard)" = "g7-model-card=pass g7-model-io=pass" ] \
    && pass "a scanned card with declared kinds added still satisfies g7-model-card" || fail "real card: $(card_io "$S" svccard)"
jq '.metadata.component.modelCard.modelParameters.task = "text-generation"' "$WORK/nocard2.json" > "$WORK/nocard3.json"
[ "$(card_io "$WORK/nocard3.json" nocard3)" = "g7-model-card=pass g7-model-io=pass" ] \
    && pass "a card with any content the step did not write counts" || fail "card with own content: $(card_io "$WORK/nocard3.json" nocard3)"

echo "== what the step writes is valid CycloneDX 1.7 =="
cp "$S" "$WORK/cdx/service.json"
cp "$O" "$WORK/cdx/observed.json"
cp "$WORK/nocard.json" "$WORK/cdx/removed-card.json"
cp "$WORK/only-b.json" "$WORK/cdx/service-b.json"
cp "$WORK/noref.json" "$WORK/cdx/noref.json"
cp "$WORK/uni.json" "$WORK/cdx/unicode.json"
if [ "${BOMLENS_CDX_SCHEMA:-}" = "1" ] || command -v cyclonedx >/dev/null 2>&1 || [ -n "${CYCLONEDX_CLI:-}" ]; then
    if cdxout=$(bash "$ROOT_DIR/scripts/check-cdx-schema.sh" "$WORK"/cdx/*.json 2>&1); then
        pass "SBOMs with a declared service validate against the CycloneDX 1.7 schema"
    else
        fail "an SBOM with a declared service fails the CycloneDX 1.7 schema" "$cdxout"
    fi
else
    echo "  SKIP: CycloneDX CLI not available (set BOMLENS_CDX_SCHEMA=1 to download the pinned one)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
