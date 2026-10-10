#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-spdx3-ai.sh — No-Docker checks for docker/lib/convert-to-spdx3-ai.py, the
# step that writes an AI SBOM as an SPDX 3.0.1 AI and Dataset profile document.
# The contract under test: values come from the CycloneDX document, a fixed
# rule, or the publisher's declaration, and nothing else; required fields the
# specification gives no "unknown" value stay empty and mark the document a
# draft; base models are identified, never filled from the model; a declaration
# that names a field, value or dataset the scan does not have is refused.
# Pure jq/python, offline.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures/spdx3"
CONV="$LIB/convert-to-spdx3-ai.py"
MAP="$LIB/spdx3-ai-map.json"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
OUT="$WORK/out"; mkdir -p "$OUT"
P=acme_1.0
DOC="$OUT/${P}_bom.spdx3.json"
CHK="$OUT/${P}_spdx3-check.json"

convert() {  # [declaration]
    rm -f "$OUT"/*
    if [ -n "${1:-}" ]; then
        python3 -I "$CONV" convert --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix "$P" \
            --declaration "$1" --stable 2>"$WORK/err"
    else
        python3 -I "$CONV" convert --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix "$P" \
            --stable 2>"$WORK/err"
    fi
}
el() { jq -c --arg t "$1" --arg n "$2" '[.["@graph"][] | select(.type==$t and .name==$n)] | first' "$DOC"; }
rels() { jq -r --arg r "$1" '[.["@graph"][] | select(.relationshipType==$r)] | length' "$DOC"; }
status_of() { jq -r --arg l "$1" --arg f "$2" '[.elements[] | select(.label==$l) | .fields[] | select(.id==$f) | .status] | first // ""' "$CHK"; }

echo "== the document has the SPDX 3.0.1 shape =="
convert
[ $? -eq 0 ] && pass "convert succeeds on an AI SBOM with no declaration" || fail "convert failed" "$(cat "$WORK/err")"
[ "$(jq -r '.["@context"]' "$DOC")" = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld" ] && pass "the official context is used" || fail "context=$(jq -r '.["@context"]' "$DOC")"
model_id=$(el ai_AIPackage support-adapter | jq -r .spdxId)
[ "$(jq -r '[.["@graph"][] | select(.type=="SpdxDocument") | .rootElement[0]] | first' "$DOC")" = "$model_id" ] && pass "the model is the document's root element" || fail "rootElement is not the model"
[ "$(jq '[.["@graph"][] | select(.type=="dataset_DatasetPackage")] | length' "$DOC")" -eq 3 ] && pass "each dataset becomes a dataset_DatasetPackage" || fail "dataset elements=$(jq '[.["@graph"][] | select(.type=="dataset_DatasetPackage")] | length' "$DOC")"
[ "$(jq -r '[.["@graph"][] | select(.type=="CreationInfo") | .created] | first' "$DOC")" = "1970-01-01T00:00:00Z" ] && pass "--stable pins the creation time" || fail "created not pinned"
undef=$(jq -r '[.["@graph"][] | select(.spdxId? != null) | .spdxId] as $ids
  | [.["@graph"][] | (.from?, (.to? // [])[], .subject?, (.rootElement? // [])[]) | select(. != null)
     | select(startswith("https://")) | select(. as $x | $ids | index($x) | not)] | unique | join(" ")' "$DOC")
[ -z "$undef" ] && pass "every reference points at an element in the document" || fail "dangling references" "$undef"

echo "== without a declaration it is a draft, and only for the right reasons =="
missing=$(jq -r '[.elements[] | .label as $l | .fields[] | select(.status=="missingRequired") | "\($l):\(.id)"] | sort | join(" ")' "$CHK")
want="document:createdBy org/open-ds:builtTime org/open-ds:originatedBy org/open-ds:releaseTime org/pii-ds:builtTime org/pii-ds:originatedBy org/pii-ds:releaseTime org/upstream:builtTime org/upstream:originatedBy org/upstream:releaseTime support-adapter:releaseTime"
[ "$missing" = "$want" ] && pass "the open required fields are exactly the undeclarable ones" || fail "missing='$missing'"
[ "$(jq -r .draft "$CHK")" = "true" ] && pass "the check says draft" || fail "draft=$(jq -r .draft "$CHK")"
case "$(jq -r '[.["@graph"][] | select(.type=="SpdxDocument") | .comment] | first' "$DOC")" in DRAFT:*) pass "the document says draft" ;; *) fail "document comment does not say DRAFT" ;; esac
grep -q "Required, not filled" "$OUT/${P}_spdx3-check.md" && pass "the readable check lists what is missing" || fail "check .md has no missing list"

echo "== nothing is estimated =="
m=$(el ai_AIPackage support-adapter)
{ [ "$(echo "$m" | jq 'has("releaseTime") or has("builtTime")')" = "false" ] && ! grep -q '2025-04-15T09:30' "$DOC"; } \
    && pass "no release or build time is filled, and the revision time is not used as one" || fail "a date was filled without a declaration"
[ "$(echo "$m" | jq 'has("ai_safetyRiskAssessment")')" = "false" ] && pass "the card's safety prose is not turned into a grade" || fail "safetyRiskAssessment was set"
[ "$(el dataset_DatasetPackage org/open-ds | jq -r '.dataset_hasSensitivePersonalInformation // "absent"')" = "absent" ] \
    && pass "a dataset without a pii signal is not called free of personal data" || fail "hasSensitivePersonalInformation on open-ds"
[ "$(el dataset_DatasetPackage org/pii-ds | jq -r '.dataset_hasSensitivePersonalInformation')" = "yes" ] && pass "a pii signal reads yes" || fail "pii-ds sensitive=$(el dataset_DatasetPackage org/pii-ds | jq -r '.dataset_hasSensitivePersonalInformation')"
[ "$(el dataset_DatasetPackage org/pii-ds | jq -r '.dataset_datasetAvailability // "absent"')" = "absent" ] && pass "a gated dataset gets no availability value" || fail "gated dataset has availability"
[ "$(el dataset_DatasetPackage org/open-ds | jq -c '.dataset_datasetType')" = '["text"]' ] && pass "a text task gives the text dataset type" || fail "open-ds type=$(el dataset_DatasetPackage org/open-ds | jq -c '.dataset_datasetType')"
[ "$(el dataset_DatasetPackage org/pii-ds | jq -c '.dataset_datasetType')" = '["audio"]' ] && pass "a modality tag gives the dataset type" || fail "pii-ds type"
[ "$(el dataset_DatasetPackage org/upstream | jq -c '.dataset_datasetType')" = '["noAssertion"]' ] && pass "no signal gives noAssertion, the type's own unknown value" || fail "upstream type"
[ "$(status_of org/upstream datasetType)" = "noAssertion" ] && pass "and the check counts it as unknown, not filled" || fail "upstream datasetType status=$(status_of org/upstream datasetType)"

echo "== licences are written only as SPDX ids the input states =="
lic_of() { jq -r --arg id "$1" '[.["@graph"][] | select(.relationshipType=="hasDeclaredLicense" and .from==$id) | .to[]] | map(split("/") | last) | join(",")' "$DOC"; }
[ "$(lic_of "$model_id")" = "Apache-2.0" ] && pass "the model's SPDX id is used" || fail "model licence=$(lic_of "$model_id")"
[ "$(lic_of "$(el dataset_DatasetPackage org/pii-ds | jq -r .spdxId)")" = "expandedlicensing_NoAssertionLicense" ] \
    && pass "a licence name with no SPDX id is NoAssertionLicense" || fail "pii-ds licence=$(lic_of "$(el dataset_DatasetPackage org/pii-ds | jq -r .spdxId)")"
grep -q "Declared licence named 'llama3'" "$DOC" && pass "and the name is kept in an annotation" || fail "llama3 name not annotated"
base=$(el software_Package org/base-instruct | jq -r .spdxId)
root_base=$(el software_Package org/base | jq -r .spdxId)
{ [ "$(lic_of "$base")" = "Apache-2.0" ] && [ "$(lic_of "$root_base")" = "expandedlicensing_NoAssertionLicense" ]; } \
    && pass "a hub licence tag maps only when it names one SPDX licence" || fail "base licences=$(lic_of "$base")/$(lic_of "$root_base")"

echo "== base models are identified, not filled from the model =="
b=$(el software_Package org/base-instruct)
{ [ "$(echo "$b" | jq 'has("suppliedBy") or has("verifiedUsing") or has("software_packageVersion") or has("releaseTime")')" = "false" ] \
  && [ "$(echo "$b" | jq -r .software_primaryPurpose)" = "model" ]; } \
    && pass "a base model carries only its identity" || fail "base model element: $b"
chain=$(jq -r --arg m "$model_id" '[.["@graph"][] | select(.relationshipType=="descendantOf")] | map((.from|split("/")|last) + ">" + (.to[0]|split("/")|last)) | join(" ")' "$DOC")
[ "$chain" = "pkg%3Ahuggingface%2Facme%2Fsupport-adapter%401a2b3c4d>org%2Fbase-instruct org%2Fbase-instruct>org%2Fbase pkg%3Ahuggingface%2Facme%2Fsupport-adapter%401a2b3c4d>org%2Fother dataset%3Ahuggingface%2Forg%2Fopen-ds>dataset%3Ahuggingface%2Forg%2Fupstream" ] \
    && pass "the lineage, a merge's other parent and a dataset's source are descendantOf" || fail "descendantOf=$chain"
[ "$(jq -r '[.["@graph"][] | select(.type=="LifecycleScopedRelationship") | "\(.relationshipType)/\(.scope)/\(.to[0]|split("/")|last)"] | join(" ")' "$DOC")" = "dependsOn/runtime/org%2Fbase-instruct" ] \
    && pass "an adapter depends on its base model's weights at runtime" || fail "adapter relationship missing"
[ "$(jq '[.["@graph"][] | select(.type=="software_File") | .verifiedUsing[0].hashValue] | length' "$DOC")" -eq 1 ] && [ "$(rels contains)" -eq 1 ] \
    && pass "each weight file is a software_File with its digest" || fail "weight files not written"
[ "$(echo "$m" | jq -r '.extension[0].extension_cdxProperty[0] | "\(.extension_cdxPropName)=\(.extension_cdxPropValue)"')" = "bomlens:weights:scope=adapter" ] \
    && pass "the weights scope rides in a CdxPropertiesExtension" || fail "weights scope extension"
[ "$(echo "$m" | jq -r .ai_limitation)" = "$(printf 'Answers only in English.\nNot for medical advice.')" ] && pass "limitations are joined one per line" || fail "limitation='$(echo "$m" | jq -r .ai_limitation)'"
[ "$(echo "$m" | jq -c '[.externalRef[] | .externalRefType]')" = '["vcs","documentation"]' ] && pass "the commit and the paper become external references" || fail "externalRef"
[ "$(echo "$m" | jq -r .software_downloadLocation)" = "https://huggingface.co/acme/support-adapter/tree/main" ] && pass "the download location is the model's own, not a dataset's" || fail "downloadLocation"

echo "== a card-declared dataset's role is not assumed =="
[ "$(rels other)" -eq 2 ] && [ "$(rels trainedOn)" -eq 0 ] && pass "without a declaration the card's datasets are 'other'" || fail "other=$(rels other) trainedOn=$(rels trainedOn)"
grep -q "unverified source 'Wikipedia dump 2023-01'" "$CHK" && pass "a source named in words is listed for review" || fail "unverified source not in the check"

echo "== a complete declaration fills the document =="
convert "$FIX/declaration-complete.json"
[ $? -eq 0 ] && pass "convert accepts the declaration" || fail "convert refused" "$(cat "$WORK/err")"
[ "$(jq -r .draft "$CHK")" = "false" ] && pass "every required field is filled" || fail "still draft: $(jq -r '[.elements[] | .label as $l | .fields[] | select(.status=="missingRequired") | "\($l):\(.id)"] | join(" ")' "$CHK")"
{ [ "$(rels trainedOn)" -eq 2 ] && [ "$(rels testedOn)" -eq 1 ]; } && pass "declared roles become trainedOn and testedOn" || fail "trainedOn=$(rels trainedOn) testedOn=$(rels testedOn)"
m=$(el ai_AIPackage support-adapter)
[ "$(echo "$m" | jq -r .releaseTime)" = "2025-04-15T00:00:00Z" ] && pass "the declared release time is written" || fail "releaseTime"
[ "$(echo "$m" | jq -c '[.ai_hyperparameter[] | "\(.key)=\(.value)"]')" = '["learning_rate=2e-5","lora_rank=16"]' ] && pass "hyperparameters are DictionaryEntry pairs" || fail "hyperparameter"
[ "$(echo "$m" | jq -r .ai_useSensitivePersonalInformation)" = "noAssertion" ] && pass "a declared unknown is written as noAssertion" || fail "useSensitivePersonalInformation"
b=$(el software_Package org/base-instruct)
{ [ "$(echo "$b" | jq -r .software_packageVersion)" = "a8b602d9dafd3a75d382e62757d83d89fca3be54" ] \
  && [ "$(echo "$b" | jq -r .software_packageUrl)" = "pkg:huggingface/org/base-instruct@a8b602d9dafd3a75d382e62757d83d89fca3be54" ] \
  && [ "$(el software_Package org/base | jq 'has("software_packageVersion")')" = "false" ]; } \
    && pass "a declared base revision lands on that base model only" || fail "base revision placement"
{ [ "$(el dataset_DatasetPackage 'Support logs 2025' | jq -r .software_downloadLocation)" = "https://data.example.internal/support-logs-2025" ] \
  && [ "$(el dataset_DatasetPackage 'Support logs 2025' | jq -r .dataset_hasSensitivePersonalInformation)" = "yes" ]; } \
    && pass "a dataset the hub does not hold is written from the declaration" || fail "local dataset"
[ "$(el dataset_DatasetPackage org/open-ds | jq 'has("ai_hyperparameter") or has("dataset_intendedUse")')" = "false" ] && pass "declared values stay on the element they name" || fail "declared values leaked"
grep -q "Values from the publisher's declaration" "$DOC" && pass "declared values are annotated as declared" || fail "no declaration annotation"
[ "$(jq -r '[.["@graph"][] | select(.type=="CreationInfo") | .createdBy[0]] | first | split("/") | last' "$DOC")" = "Organization%3AAcme%20AI%20Lab" ] \
    && pass "the declared author is the creator, not the tool" || fail "createdBy"
# The screens tie each checked element to the declaration item that fills it,
# and show filled values without reading the document.
[ "$(jq -c '[.elements[] | .declarationKey // "-"]' "$CHK")" = '["document","model","huggingface:org/open-ds","huggingface:org/pii-ds","huggingface:org/upstream","local:support-logs-2025"]' ] \
    && pass "each checked element names the declaration item it maps to" || fail "declarationKey: $(jq -c '[.elements[] | .declarationKey]' "$CHK")"
{ [ "$(jq -r '.elements[] | select(.declarationKey=="model") | .fields[] | select(.id=="hyperparameter") | .display' "$CHK")" = "learning_rate=2e-5, lora_rank=16" ] \
  && [ "$(jq -r '.elements[0].fields[0].display' "$CHK")" = "Acme AI Lab" ] \
  && [ "$(jq '[.elements[].fields[] | select(.status=="optional" or .status=="missingRequired" or .status=="judgment") | has("display")] | any' "$CHK")" = "false" ]; } \
    && pass "a filled field carries a display value, an empty one none" || fail "display values"

echo "== a declaration the scan does not match is refused =="
refuse() {  # $1 label, $2 jq edit applied to the complete declaration
    jq "$2" "$FIX/declaration-complete.json" > "$WORK/bad.json"
    python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/bad.json" >"$WORK/bad.out" 2>/dev/null
    rc=$?
    { [ "$rc" -eq 2 ] && jq -e '.refused | length > 0' "$WORK/bad.out" >/dev/null; } && pass "refused: $1" || fail "not refused: $1 (rc=$rc)"
}
refuse "an unknown key" '.model.licence = "MIT"'
refuse "a model licence that is neither a hub tag nor an SPDX id" '.model.license = "my own terms"'
refuse "a value outside the field's list" '.model.safetyRiskAssessment = "critical"'
refuse "noAssertion on a field with no unknown value" '.model.safetyRiskAssessment = "noAssertion"'
refuse "noAssertion mixed with values" '.datasets[3].datasetType = ["text", "noAssertion"]'
refuse "a date not in UTC form" '.model.releaseTime = "2025-04-15"'
refuse "a date that does not exist" '.model.releaseTime = "2025-02-30T00:00:00Z"'
refuse "an address with an unclosed IPv6 bracket" '.datasets[3].downloadLocation = "https://[::1"'
refuse "a dataset the scan does not have" '.datasets[0].ref = "huggingface:org/elsewhere"'
refuse "a base model the scan did not find" '.model.baseModels[0].ref = "org/unrelated"'
refuse "a dataset given both ref and local" '.datasets[0].local = "x"'
refuse "a hub-less dataset with no address" 'del(.datasets[3].downloadLocation)'
refuse "an address that is not a URL" '.model.downloadLocation = "registry internal"'
refuse "relationships before they are supported" '.relationships = [{"from":"a"}]'
refuse "the wrong schema" '.schema = "other/1"'
refuse "a role on a dataset the card does not name" '.datasets[2].role = "trainedOn"'
refuse "a name on a scanned dataset" '.datasets[0].name = "Other"'
refuse "the same base model twice" '.model.baseModels += [{"ref": "org/base-instruct", "revision": "abc"}]'
refuse "a structured hyperparameter value" '.model.hyperparameter = [{"key": "x", "value": {"y": [1]}}]'
refuse "a hyperparameter key twice" '.model.hyperparameter = [{"key": "x", "value": "1"}, {"key": "x", "value": "2"}]'
refuse "a file address" '.datasets[3].downloadLocation = "file://host/etc/passwd"'
refuse "an address longer than the limit" ".datasets[3].downloadLocation = (\"https://example.com/\" + (\"a\" * 5000))"
refuse "text longer than the limit" '.model.informationAboutTraining = ("a" * 5000)'
printf '\xff\xfe{}' > "$WORK/notutf8.json"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/notutf8.json" >/dev/null 2>&1
[ $? -eq 2 ] && pass "refused: a file that is not UTF-8" || fail "non-UTF-8 not refused with 2"
python3 -I -c "print('[' * 100000 + ']' * 100000)" > "$WORK/deep.json"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/deep.json" >/dev/null 2>&1
[ $? -eq 2 ] && pass "refused: nesting too deep" || fail "deep nesting not refused with 2"
python3 -I -c "import json; print(json.dumps({'schema': 'bomlens-ai-declaration/1', 'pad': 'x' * 1100000}))" > "$WORK/big.json"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/big.json" >/dev/null 2>&1
[ $? -eq 2 ] && pass "refused: a file over the size limit" || fail "oversized file not refused with 2"
{ printf '\xef\xbb\xbf'; cat "$FIX/declaration-complete.json"; } > "$WORK/bom-mark.json"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/bom-mark.json" >/dev/null 2>&1
[ $? -eq 0 ] && pass "a UTF-8 file with a byte-order mark is read" || fail "a UTF-8 BOM file was refused"
# A document about a dataset takes no model fields, roles or extra datasets.
jq '.metadata.component = (.components[0]) | .components = .components[1:] | .dependencies = []' \
    "$FIX/bom-ai-sample.json" > "$WORK/dsroot.json"
printf '%s' '{"schema":"bomlens-ai-declaration/1","datasets":[{"local":"x","name":"X","downloadLocation":"https://example.com/x"}]}' > "$WORK/dsroot-decl.json"
python3 -I "$CONV" check --bom "$WORK/dsroot.json" --declaration "$WORK/dsroot-decl.json" >/dev/null 2>&1
[ $? -eq 2 ] && pass "refused: a dataset the hub does not hold, on a dataset document" || fail "local accepted on a dataset document"
printf '{"schema": "bomlens-ai-declaration/1",' > "$WORK/broken.json"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/broken.json" >/dev/null 2>&1
[ $? -eq 2 ] && pass "refused: a file that is not JSON" || fail "broken JSON not refused"

echo "== output is deterministic =="
convert "$FIX/declaration-complete.json"; mkdir -p "$WORK/first"; cp "$OUT"/* "$WORK/first/"
convert "$FIX/declaration-complete.json"
same=1
for f in "$WORK/first"/*; do cmp -s "$f" "$OUT/$(basename "$f")" || same=0; done
[ "$same" -eq 1 ] && pass "two runs with --stable give byte-identical document and check" || fail "--stable output differs between runs"

echo "== the empty declaration round-trips =="
python3 -I "$CONV" template --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix "$P" 2>/dev/null
T="$OUT/${P}_ai-declaration.template.json"
{ [ -f "$T" ] && [ "$(jq -c '[.model.baseModels[].ref]' "$T")" = '["org/base-instruct","org/base","org/other"]' ] \
  && [ "$(jq -r '.model | has("releaseTime") and (has("name") | not)' "$T")" = "true" ] \
  && [ "$(jq '.datasets | length' "$T")" -eq 3 ]; } && pass "the template lists the fields a person fills" || fail "template content" "$(head -c 400 "$T")"
[ "$(jq -c '[.datasets[] | has("role")]' "$T")" = '[true,true,false]' ] \
    && pass "only the datasets the card names are offered a role" || fail "template roles: $(jq -c '[.datasets[] | {ref, role}]' "$T")"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$T" >/dev/null 2>&1
[ $? -eq 0 ] && pass "an untouched template is accepted (empty means not declared)" || fail "the template itself is refused"

echo "== the mapping agrees with the SPDX 3.0.1 schema =="
schema_out=$(python3 -I - "$MAP" "$FIX/spdx-json-schema-extract.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
s = json.load(open(sys.argv[2]))
problems = []
# An element key that is not an SPDX class names its class in spdxType.
cls = {etype: ("CreationInfo" if etype == "document" else spec.get("spdxType", etype))
       for etype, spec in m["elements"].items()}
for etype, c in cls.items():
    if c not in s["classes"]:
        problems.append(f"{etype}: '{c}' is not a class in the schema extract")
ref_types = set(s["enums"]["prop_ExternalRef_externalRefType"])
purposes = set(s["enums"]["prop_software_SoftwareArtifact_software_primaryPurpose"])
for etype, spec in m["elements"].items():
    props = set(s["classes"][cls[etype]]["properties"])
    for f in spec["fields"]:
        key = f["json"]
        if key.startswith("extension:"):
            if "extension" not in props:
                problems.append(f"{etype}.{f['id']}: {cls[etype]} takes no extension")
            continue
        if key.startswith("externalRef:"):
            if "externalRef" not in props:
                problems.append(f"{etype}.{f['id']}: {cls[etype]} takes no externalRef")
            if key[len("externalRef:"):] not in ref_types:
                problems.append(f"{etype}.{f['id']}: '{key}' is not an ExternalRefType")
            continue
        if key == "software_primaryPurpose" and f["source"]["kind"] == "const" \
                and f["source"]["value"] not in purposes:
            problems.append(f"{etype}.{f['id']}: {f['source']['value']!r} is not a SoftwarePurpose")
        if key not in props:
            problems.append(f"{etype}.{f['id']}: '{key}' is not a property of {cls[etype]}")
        if "enum" in f:
            allowed = None
            for k, v in s["enums"].items():
                if k.endswith("_" + key):
                    allowed = set(v)
            if allowed is None:
                problems.append(f"{etype}.{f['id']}: no enumeration for '{key}' in the schema")
            elif not set(f["enum"]) <= allowed:
                problems.append(f"{etype}.{f['id']}: {sorted(set(f['enum']) - allowed)} not allowed")
    for f in spec["fields"]:
        key = f["json"]
        if key.startswith(("extension:", "externalRef:")) or key not in props:
            continue
        schema_array = key in set(s["classes"][cls[etype]]["arrays"])
        written_array = f["max"] == "*" or bool(f.get("jsonArray"))
        if schema_array != written_array:
            problems.append(f"{etype}.{f['id']}: the schema writes '{key}' as "
                            f"{'an array' if schema_array else 'a single value'}, the mapping as "
                            f"{'an array' if written_array else 'a single value'}")
# What the machine-readable schema itself requires.
if s["classes"]["CreationInfo"]["required"] != ["created", "createdBy", "specVersion", "type"]:
    problems.append("CreationInfo.required changed in the schema")
if "dataset_datasetType" not in s["classes"]["dataset_DatasetPackage"]["required"]:
    problems.append("dataset_datasetType is no longer required by the schema")
# The narrowed cardinalities the specification pages give and the schema does
# not carry: kept here as constants, and the mapping must match them.
pages = {"ai_AIPackage": {"software_packageVersion": 1, "software_downloadLocation": 1,
                          "software_primaryPurpose": 1, "suppliedBy": 1, "releaseTime": 1, "originatedBy": 0},
         "dataset_DatasetPackage": {"originatedBy": 1, "builtTime": 1, "releaseTime": 1,
                                    "dataset_datasetType": 1, "software_downloadLocation": 1,
                                    "software_primaryPurpose": 1, "suppliedBy": 0, "software_packageVersion": 0}}
# The declared service is an ai_AIPackage: the same page, the same counts.
pages["service"] = {k: v for k, v in pages["ai_AIPackage"].items() if k != "originatedBy"}
if m["elements"]["service"].get("spdxType") != "ai_AIPackage":
    problems.append("service is not written as ai_AIPackage")
for etype, want in pages.items():
    got = {f["json"]: f["min"] for f in m["elements"][etype]["fields"]}
    for k, v in want.items():
        if got.get(k) != v:
            problems.append(f"{etype}.{k}: min {got.get(k)} in the mapping, {v} on the specification page")
print("\n".join(problems))
PY
)
[ -z "$schema_out" ] && pass "every mapped property and value exists in SPDX 3.0.1, and required counts match the spec" || fail "mapping and schema disagree" "$schema_out"
# In the 3.0.1 context the bare value "extension" expands to the Core extension
# property, so claiming that profile fails the official SHACL validation.
[ "$(jq '.profiles | index("extension")' "$MAP")" = "null" ] \
    && pass "the extension profile is not claimed (the context expands it to a property)" || fail "profiles claim extension"

echo "== the complete document validates against the SPDX 3.0.1 JSON schema =="
# Full JSON-schema validation needs the jsonschema package; without it this is
# skipped, and the array and property checks above still run.
convert "$FIX/declaration-complete.json"
JSPY=""
for py in python3 python3.13 python3.12 python3.11; do
    if command -v "$py" >/dev/null 2>&1 && "$py" -c "import jsonschema" 2>/dev/null; then JSPY="$py"; break; fi
done
if [ -n "$JSPY" ]; then
    verr=$("$JSPY" - "$FIX/spdx-json-schema.json" "$DOC" <<'PY'
import json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
errs = sorted(jsonschema.Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
print("\n".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:10]))
PY
)
    [ -z "$verr" ] && pass "the complete document is valid SPDX 3.0.1 JSON" || fail "schema errors" "$verr"
    convert
    verr=$("$JSPY" - "$FIX/spdx-json-schema.json" "$DOC" <<'PY'
import json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
v = jsonschema.Draft202012Validator(schema)
# A draft lacks createdBy, which CreationInfo requires. Where a validator
# reports that error differs between jsonschema versions (on the node, or on
# the whole graph through unevaluatedProperties), so: the draft must fail, and
# adding only an author must make it valid.
out = []
if not list(v.iter_errors(doc)):
    out.append("the draft passed the schema; expected the missing createdBy to fail it")
ci = next(n for n in doc["@graph"] if n.get("type") == "CreationInfo")
if "createdBy" in ci:
    out.append("the draft already has createdBy")
agent = "https://example.org/spdx/agent-test"
ci["createdBy"] = [agent]
doc["@graph"].append({"type": "Organization", "spdxId": agent, "creationInfo": ci["@id"], "name": "Test"})
errs = sorted(v.iter_errors(doc), key=lambda e: list(e.path))
out += [f"{list(e.path)}: {e.message[:200]}" for e in errs[:10]]
print("\n".join(out))
PY
)
    [ -z "$verr" ] && pass "a draft fails the schema only for the author it lacks" || fail "draft schema errors" "$verr"
else
    echo "  SKIP: jsonschema not installed; full schema validation not run"
fi

echo "== licences given as an expression or a hub tag =="
jq '.metadata.component.licenses = [{"expression": "MIT OR Apache-2.0"}]
    | .components[1].licenses = [{"license": {"name": "apache-2.0"}}]' "$FIX/bom-ai-sample.json" > "$WORK/lic.json"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/lic.json" --out-dir "$OUT" --prefix "$P" --stable 2>/dev/null
model_id=$(el ai_AIPackage support-adapter | jq -r .spdxId)
[ "$(lic_of "$model_id")" = "MIT%20OR%20Apache-2.0" ] && pass "an SPDX expression is kept as written" || fail "expression licence=$(lic_of "$model_id")"
[ "$(lic_of "$(el dataset_DatasetPackage org/pii-ds | jq -r .spdxId)")" = "Apache-2.0" ] && pass "a hub tag that names one SPDX licence maps to it" || fail "hub tag licence"
convert
[ "$(jq -r .counts.declared "$CHK")" = "0" ] && [ "$(jq -r .counts.noAssertion "$CHK")" = "1" ] \
    && pass "an unknown filled by the rule is not counted as declared" || fail "counts=$(jq -c .counts "$CHK")"

echo "== real generator output converts too =="
# The generator leaves its scan job at the root and the model under
# components[]; the converter has to find the model either way.
for f in aibom-owasp-1_7.json aibom-datasets-1_7.json; do
    rm -f "$OUT"/*
    if python3 -I "$CONV" convert --bom "$ROOT_DIR/tests/fixtures/$f" --out-dir "$OUT" --prefix gen --stable 2>/dev/null \
       && [ "$(jq -r '[.["@graph"][] | select(.type=="ai_AIPackage") | .name] | first' "$OUT/gen_bom.spdx3.json")" = "bert-base-uncased" ]; then
        pass "$f converts with the model as its subject"
    else
        fail "$f did not convert to a model document"
    fi
done

echo "== sources a publisher declares for a dataset =="
# A hub dataset already read is linked as it is; one not read yet and one
# named in words get elements of their own, marked declared and for review.
jq '.datasets[0].sources = [
      {"ref": "huggingface:org/upstream", "relation": "extended"},
      {"ref": "huggingface:org/new-src", "relation": "other"},
      {"name": "Wikipedia dump 2023-01", "license": "cc-by-sa-3.0", "relation": "extended"}]
    | .datasets[3].sources = [{"name": "Call-centre transcripts", "relation": "other"}]' \
   "$FIX/declaration-complete.json" > "$WORK/decl-src.json"
before=$(convert "$FIX/declaration-complete.json"; rels descendantOf)
convert "$WORK/decl-src.json"
[ $? -eq 0 ] && pass "a declaration with sources is accepted" || fail "sources refused" "$(cat "$WORK/err")"
[ "$(rels descendantOf)" -eq $((before + 3)) ] \
    && pass "a source already traced is not linked twice; the others are linked" || fail "descendantOf $before -> $(rels descendantOf)"
{ [ "$(el dataset_DatasetPackage org/new-src | jq -r .software_downloadLocation)" = "https://huggingface.co/datasets/org/new-src" ] \
  && [ "$(el dataset_DatasetPackage 'Wikipedia dump 2023-01' | jq -r .name)" = "Wikipedia dump 2023-01" ]; } \
    && pass "a hub source not read yet and a source named in words get their own elements" || fail "declared source elements"
jq -e '[.["@graph"][] | select(.type=="simplelicensing_LicenseExpression") | .simplelicensing_licenseExpression] | index("CC-BY-SA-3.0") != null' "$DOC" >/dev/null \
    && pass "a declared hub licence tag is written as its SPDX id" || fail "declared source licence"
{ grep -q "declared source org/new-src is read at the next scan" "$CHK" \
  && grep -q "source 'Call-centre transcripts' declared by the publisher, not verified" "$CHK" \
  && grep -q "not verified by the tool" "$DOC"; } \
    && pass "declared sources are listed for review and annotated as not verified" || fail "declared source review"
grep -q "no sources stated for org/pii-ds" "$CHK" && ! grep -q "no sources stated for org/open-ds" "$CHK" \
    && pass "a dataset with no source on record is listed for review" || fail "sources not stated"
if [ -n "${JSPY:-}" ]; then
    # The declared elements lack what only a scan or a later declaration can
    # give (dates, makers): when the schema finds the document incomplete, the
    # check has to say it is a draft.
    "$JSPY" -c "
import json, sys, jsonschema
schema = json.load(open(sys.argv[1])); doc = json.load(open(sys.argv[2])); chk = json.load(open(sys.argv[3]))
errs = list(jsonschema.Draft202012Validator(schema).iter_errors(doc))
assert not errs or chk['draft'] is True, 'schema errors in a document the check calls complete'
" "$FIX/spdx-json-schema.json" "$DOC" "$CHK" \
        && pass "the document with declared sources says it is a draft" || fail "declared sources draft state"
fi
jq '.datasets[0].sources = [{"name": "Gated crawl", "license": "openrail++"}]' "$FIX/declaration-complete.json" > "$WORK/decl-src2.json"
convert "$WORK/decl-src2.json"
{ jq -e '[.relationships[] | select(.type == "hasDeclaredLicense" and .status == "noAssertion")] | length > 0' "$CHK" >/dev/null \
  && grep -q "not an SPDX identifier, recorded as NoAssertionLicense" "$DOC" \
  && ! jq -e '[.["@graph"][] | select(.simplelicensing_licenseExpression == "openrail++")] | length > 0' "$DOC" >/dev/null; } \
    && pass "a declared licence that is not an SPDX id is kept in words, the expression NoAssertion" \
    || fail "unmapped declared licence written as an expression"
grep -q "no sources stated for org/upstream" "$CHK" && fail "a traced source is listed as having no sources" \
    || pass "sources found only by tracing are not listed as missing theirs"
refuse "a source with both ref and name" '.datasets[0].sources = [{"ref": "huggingface:a/b", "name": "x"}]'
refuse "a dataset as its own source, spelled differently" '.datasets[0].sources = [{"ref": "huggingface:Org/Open-DS"}]'
refuse "a source whose name is only spaces" '.datasets[0].sources = [{"name": "   "}]'
refuse "a hub source on data the hub does not hold" '.datasets[3].sources = [{"ref": "huggingface:a/b"}]'
refuse "a licence on a hub source" '.datasets[0].sources = [{"ref": "huggingface:a/b", "license": "mit"}]'
refuse "a licence that is neither a hub tag nor an SPDX id" '.datasets[0].sources = [{"name": "x", "license": "my own terms"}]'
refuse "a dataset as its own source" '.datasets[0].sources = [{"ref": "huggingface:org/open-ds"}]'
refuse "a source listed twice" '.datasets[0].sources = [{"name": "X"}, {"name": "x"}]'
refuse "an unknown relation" '.datasets[0].sources = [{"name": "x", "relation": "derived"}]'
python3 -I "$CONV" template --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix "$P" 2>/dev/null
[ "$(jq -c '[.datasets[].sources]' "$OUT/${P}_ai-declaration.template.json")" = '[[],[],[]]' ] \
    && pass "the template offers an empty sources list for every dataset" || fail "template sources"

echo "== the model's licence a publisher declares =="
# The licence the scan read stands; a declared one fills its place only when
# the scan has none as an SPDX id, and one that differs is listed for review.
model_lic() { jq -r '([.["@graph"][] | select(.type=="ai_AIPackage") | .spdxId] | first) as $m
  | [.["@graph"][] | select(.relationshipType=="hasDeclaredLicense" and .from==$m) | .to[]] | map(split("/") | last) | join(",")' "$DOC"; }
model_lic_status() { jq -r '[.relationships[] | select(.type=="hasDeclaredLicense")] | first | .status' "$CHK"; }
jq '.model.license = "MIT"' "$FIX/declaration-complete.json" > "$WORK/decl-lic.json"
convert "$WORK/decl-lic.json"
{ [ $? -eq 0 ] && [ "$(model_lic)" = "Apache-2.0" ] && [ "$(model_lic_status)" = "auto" ] \
  && grep -q "declared model licence 'MIT' differs from the one the scan read (Apache-2.0)" "$CHK"; } \
    && pass "a declared licence that differs from the scanned one is listed for review, the scan's kept" \
    || fail "differing declared licence: $(model_lic) $(model_lic_status)"
jq '.model.license = "apache-2.0"' "$FIX/declaration-complete.json" > "$WORK/decl-lic.json"
convert "$WORK/decl-lic.json"
! grep -q "declared model licence" "$CHK" && pass "a declared licence that agrees with the scan raises nothing" || fail "agreeing licence listed for review"
jq 'del(.metadata.component.licenses)' "$FIX/bom-ai-sample.json" > "$WORK/nolic.json"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/nolic.json" --out-dir "$OUT" --prefix "$P" --declaration "$WORK/decl-lic.json" --stable 2>/dev/null
{ [ "$(model_lic)" = "Apache-2.0" ] && [ "$(model_lic_status)" = "declared" ] \
  && grep -q "Licence from the publisher's declaration: apache-2.0." "$DOC"; } \
    && pass "a declared licence fills a model the scan found none for, as declared" \
    || fail "declared licence on an unlicensed model: $(model_lic) $(model_lic_status)"
jq '.model.license = "llama3.1"' "$FIX/declaration-complete.json" > "$WORK/decl-lic2.json"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/nolic.json" --out-dir "$OUT" --prefix "$P" --declaration "$WORK/decl-lic2.json" --stable 2>/dev/null
{ [ "$(model_lic)" = "expandedlicensing_NoAssertionLicense" ] && [ "$(model_lic_status)" = "noAssertion" ] \
  && grep -q "Licence declared by the publisher as 'llama3.1'; not an SPDX identifier" "$DOC"; } \
    && pass "a declared hub tag with no SPDX id is kept in words" || fail "unmapped declared model licence: $(model_lic)"
python3 -I "$CONV" template --bom "$WORK/nolic.json" --out-dir "$OUT" --prefix nolic 2>/dev/null
python3 -I "$CONV" template --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix withlic 2>/dev/null
{ [ "$(jq -r '.model.license' "$OUT/nolic_ai-declaration.template.json")" = "" ] \
  && [ "$(jq -r '.model | has("license")' "$OUT/withlic_ai-declaration.template.json")" = "false" ]; } \
    && pass "the template asks for the licence only when the scan found none" || fail "template licence question"
lic_case() {  # <bom jq edit> <declared licence>
    jq "$1" "$FIX/bom-ai-sample.json" > "$WORK/lic-bom.json"
    jq --arg l "$2" '.model.license = $l' "$FIX/declaration-complete.json" > "$WORK/lic-decl.json"
    rm -f "$OUT"/*
    python3 -I "$CONV" convert --bom "$WORK/lic-bom.json" --out-dir "$OUT" --prefix "$P" --declaration "$WORK/lic-decl.json" --stable 2>/dev/null
}
lic_case '.metadata.component.licenses = [{"license": {"id": "GPL-3.0-only"}}]' "gpl-3.0-only"
{ [ "$(model_lic)" = "GPL-3.0-only" ] && ! grep -q "declared model licence" "$CHK"; } \
    && pass "an SPDX id declared in another case is the scanned one, not a difference" || fail "case-only difference listed: $(model_lic)"
lic_case 'del(.metadata.component.licenses)' "LicenseRef-acme-model"
{ [ "$(model_lic)" = "LicenseRef-acme-model" ] && [ "$(model_lic_status)" = "declared" ]; } \
    && pass "a declared LicenseRef- is written as an expression" || fail "LicenseRef licence: $(model_lic) $(model_lic_status)"
lic_case '.metadata.component.licenses = [{"license": {"name": "llama3"}}]' "mit"
{ [ "$(model_lic)" = "expandedlicensing_NoAssertionLicense" ] \
  && grep -q "declared model licence 'mit' differs from the one the scan read (llama3)" "$CHK"; } \
    && pass "a declared licence against a card's named licence is listed for review, not filled in" \
    || fail "named card licence overridden: $(model_lic)"
lic_case '.metadata.component.licenses = [{"license": {"name": "other"}}]' "mit"
{ [ "$(model_lic)" = "MIT" ] && [ "$(model_lic_status)" = "declared" ] && ! grep -q "declared model licence" "$CHK" \
  && grep -q "The scan read the licence named 'other'" "$DOC"; } \
    && pass "a card that says only 'other' takes the declared licence, and the card's word is kept" \
    || fail "'other' card licence: $(model_lic) $(model_lic_status)"
python3 -I "$CONV" template --bom "$WORK/lic-bom.json" --out-dir "$OUT" --prefix other 2>/dev/null
[ "$(jq -r '.model.license' "$OUT/other_ai-declaration.template.json")" = "" ] \
    && pass "the template asks for the licence when the card says only 'other'" || fail "template on an 'other' card"
jq '.model.license = "   "' "$FIX/declaration-complete.json" > "$WORK/lic-blank.json"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/lic-blank.json" >/dev/null 2>&1
[ $? -eq 0 ] && pass "a licence of only spaces is no answer, as in the builder and the web UI" || fail "blank licence refused"
refuse "a model licence that is not text" '.model.license = []'
# A model built from the declaration alone: its SBOM's licence is the declared
# one; a later declaration with another one asks for a new scan.
jq '.metadata.component.licenses = [{"license": {"name": "apache-2.0"}}]
    | .metadata.component.properties += [{"name": "bomlens:origin", "value": "declared-input"}]' \
   "$FIX/bom-ai-sample.json" > "$WORK/declared-bom.json"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/declared-bom.json" --out-dir "$OUT" --prefix "$P" --declaration "$FIX/declaration-complete.json" --stable 2>/dev/null
{ [ "$(model_lic)" = "Apache-2.0" ] && [ "$(model_lic_status)" = "declared" ]; } \
    && pass "a declared model's licence is recorded as declared, also when the current declaration leaves it out" \
    || fail "declared-input licence: $(model_lic) $(model_lic_status)"
jq '.model.license = "mit"' "$FIX/declaration-complete.json" > "$WORK/lic-mit.json"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/declared-bom.json" --out-dir "$OUT" --prefix "$P" --declaration "$WORK/lic-mit.json" --stable 2>/dev/null
{ [ "$(model_lic)" = "Apache-2.0" ] \
  && grep -q "declared model licence 'mit' is not the one this SBOM was built with (Apache-2.0); scan again to apply it" "$CHK"; } \
    && pass "a changed licence on a declared model asks for a new scan; the SBOM's is the one recorded" \
    || fail "declared-input licence change: $(model_lic)"
python3 -I "$CONV" template --bom "$WORK/declared-bom.json" --out-dir "$OUT" --prefix decl 2>/dev/null
[ "$(jq -r '.model | has("license")' "$OUT/decl_ai-declaration.template.json")" = "false" ] \
    && pass "the template does not ask a declared model for its licence again" || fail "template asks a declared model"
# A declared model has no card: a dataset without a role is one the
# declaration named, and the check says so.
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/declared-bom.json" --out-dir "$OUT" --prefix "$P" --stable 2>/dev/null
{ [ "$(jq '[.relationships[] | select(.note == "declared dataset, role not stated")] | length' "$CHK")" -eq 2 ] \
  && [ "$(jq '[.relationships[] | select(.note == "card-declared dataset, role not stated")] | length' "$CHK")" -eq 0 ] \
  && ! grep -q "declared in the model card" "$DOC"; } \
    && pass "a declared model's datasets are not said to come from a model card" \
    || fail "declared-input dataset notes: $(jq -c '[.relationships[] | .note // empty]' "$CHK")"
# The declaration's authors, which a declared model's SBOM records in
# metadata.authors (marked as from the declaration), stay the declaration's:
# declared status and the declared kind of agent, not a scan's --sbom-author.
jq '.metadata.authors = [{"name": "Acme AI Lab"}]
    | .metadata.properties = ((.metadata.properties // []) + [{"name": "bomlens:sbom-author-source", "value": "declaration"}])' \
   "$WORK/declared-bom.json" > "$WORK/declared-authors-bom.json"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/declared-authors-bom.json" --out-dir "$OUT" --prefix "$P" \
    --declaration "$FIX/declaration-complete.json" --stable 2>/dev/null
{ [ "$(status_of document createdBy)" = "declared" ] \
  && [ "$(jq -r '[.["@graph"][] | select(.type=="CreationInfo") | .createdBy[0]] | first | split("/") | last' "$DOC")" = "Organization%3AAcme%20AI%20Lab" ] \
  && ! grep -q -- "--sbom-author" "$DOC" \
  && [ "$(jq -r '[.elements[] | select(.label=="document") | .fields[0].source // "none"] | first' "$CHK")" = "none" ]; } \
    && pass "authors the SBOM took from the declaration count as declared, with their declared kind" \
    || fail "declaration-sourced authors: status=$(status_of document createdBy)"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/declared-authors-bom.json" --out-dir "$OUT" --prefix "$P" --stable 2>/dev/null
[ "$(status_of document createdBy)" = "declared" ] \
    && pass "without the declaration file, the recorded names still stand as declared" \
    || fail "declaration-sourced authors without a declaration: $(status_of document createdBy)"
# A scan's own --sbom-author (no marker) is still the scan's.
jq '.metadata.authors = [{"name": "Scan Runner"}]' "$WORK/declared-bom.json" > "$WORK/scan-author-bom.json"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/scan-author-bom.json" --out-dir "$OUT" --prefix "$P" \
    --declaration "$FIX/declaration-complete.json" --stable 2>/dev/null
[ "$(status_of document createdBy)" = "auto" ] && grep -q -- "--sbom-author" "$DOC" \
    && pass "an author the scan was given is still the scan's" || fail "scan author status=$(status_of document createdBy)"

echo "== the service the model runs in =="
# A declared service is an ai_AIPackage with primaryPurpose application that
# depends on the model at runtime; an external API model is identified only.
SVC="$FIX/declaration-service.json"
convert "$SVC"
[ $? -eq 0 ] && pass "a declaration with a service is accepted" || fail "service refused" "$(cat "$WORK/err")"
[ "$(jq -r .draft "$CHK")" = "false" ] && pass "a service with its five required fields keeps the document complete" \
    || fail "service draft: $(jq -r '[.elements[] | .label as $l | .fields[] | select(.status=="missingRequired") | "\($l):\(.id)"] | join(" ")' "$CHK")"
s=$(el ai_AIPackage "Acme Support Assistant")
{ [ "$(echo "$s" | jq -r .software_primaryPurpose)" = "application" ] \
  && [ "$(echo "$s" | jq -r '"\(.software_packageVersion) \(.software_downloadLocation) \(.releaseTime)"')" = "2.3.0 https://support.acme.example/assistant 2025-06-01T00:00:00Z" ] \
  && [ "$(echo "$s" | jq -r '.suppliedBy | split("/") | last')" = "Organization%3AAcme%20Corp" ]; } \
    && pass "the service is an ai_AIPackage with primaryPurpose application and the declared values" \
    || fail "service element: $s"
{ [ "$(echo "$s" | jq -c '[.ai_domain, .ai_autonomyType, .ai_standardCompliance, .ai_informationAboutApplication != null]')" = '[["customer support"],"no",["ISO/IEC 42001:2023"],true]' ] \
  && [ "$(echo "$s" | jq -c '[.externalRef[] | "\(.externalRefType) \(.locator[0])"]')" = '["documentation https://support.acme.example/ai-disclosure"]' ]; } \
    && pass "domain, autonomy, standards and the disclosure page are written as SPDX AI properties" || fail "service AI fields: $s"
m=$(el ai_AIPackage support-adapter)
[ "$(jq -r '[.["@graph"][] | select(.type=="SpdxDocument") | .rootElement] | first | length' "$DOC")" = "1" ] \
  && [ "$(jq -r '[.["@graph"][] | select(.type=="SpdxDocument") | .rootElement[0]] | first' "$DOC")" = "$(echo "$m" | jq -r .spdxId)" ] \
    && pass "the model stays the document's only root element" || fail "rootElement changed"
deps=$(jq -r '[.["@graph"][] | select(.type=="LifecycleScopedRelationship" and (.from | contains("/service/")))
  | "\(.relationshipType)/\(.scope)/\(.to[0] | split("/") | .[-2])"] | join(" ")' "$DOC")
[ "$deps" = "dependsOn/runtime/model dependsOn/runtime/external-model" ] \
    && pass "the service depends at runtime on the model and on the external model" || fail "service relationships: $deps"
x=$(el software_Package "Example Translate")
{ [ "$(echo "$x" | jq -r .software_primaryPurpose)" = "model" ] \
  && [ "$(echo "$x" | jq -c '[has("software_downloadLocation"), has("releaseTime"), .software_packageVersion]')" = '[false,false,"2025-05"]' ] \
  && [ "$(echo "$x" | jq -c '[.externalRef[] | "\(.externalRefType) \(.locator[0])"]')" = '["other https://api.translate.example/v1"]' ] \
  && jq -e --arg id "$(echo "$x" | jq -r .spdxId)" '[.["@graph"][] | select(.type=="Annotation" and .subject==$id and (.statement | contains("only its identity is known")))] | length == 1' "$DOC" >/dev/null; } \
    && pass "an external API model is a software_Package with its identity and endpoint, annotated as declared" || fail "external model: $x"
flows=$(echo "$s" | jq -c '[.extension[].extension_cdxProperty[] | select(.extension_cdxPropName=="bomlens:service:dataFlow") | .extension_cdxPropValue | fromjson | .flow]')
{ [ "$flows" = '["inbound","outbound"]' ] \
  && [ "$(echo "$s" | jq '[.extension[] | select(.extension_cdxProperty[0].extension_cdxPropName=="bomlens:service:dataFlow")] | length')" = "1" ]; } \
    && pass "each data flow is one entry of one extension, as CycloneDX serviceData JSON" || fail "data flows: $flows"
regs=$(echo "$m" | jq -r '[.extension[].extension_cdxProperty[] | "\(.extension_cdxPropName)=\(.extension_cdxPropValue)"] | join(" ")')
[ "$regs" = "bomlens:weights:scope=adapter bomlens:model:input=text bomlens:model:output=text bomlens:regulatory:trainingComputeFlops=3.2e21 bomlens:regulatory:trainingComputeBasis=6 x parameters x training tokens, from the training logs bomlens:regulatory:adversarialTesting=yes" ] \
    && pass "the model's regulatory fields and modalities are extension entries, after the weights scope" || fail "model extensions: $regs"
{ [ "$(jq -c '[.elements[] | select(.declarationKey=="service" or (.declarationKey // "" | startswith("externalModel:"))) | "\(.type) \(.declarationKey)"]' "$CHK")" = '["service service","externalModel externalModel:translate"]' ] \
  && [ "$(jq -r '.elements[] | select(.type=="service") | .fields[] | select(.id=="dataFlows") | .display' "$CHK")" = "inbound: personal data, outbound: personal data" ]; } \
    && pass "the check names the service and the external model by their mapping keys" || fail "check service elements"
{ [ "$(jq -r .service.state "$CHK")" = "pendingScan" ] && [ "$(jq -r '.service.digest | length' "$CHK")" = "64" ] \
  && grep -q "the declared service is not in the CycloneDX SBOM yet" "$CHK" \
  && grep -q "^## Service" "$OUT/${P}_spdx3-check.md"; } \
    && pass "a service the SBOM does not carry yet is pendingScan, listed for review" || fail "service state: $(jq -c .service "$CHK")"
digest=$(jq -r .service.digest "$CHK")
# The CycloneDX step marks the service it writes with the check's digest.
cdx_service() {  # <digest> <kind>
    jq --arg d "$1" --arg k "$2" '.services = [{"bom-ref": "service:declared/x", "name": "Acme Support Assistant",
        "properties": [{"name": "bomlens:origin", "value": "declared-input"},
                       {"name": "bomlens:service:kind", "value": $k},
                       {"name": "bomlens:service:declarationDigest", "value": $d}]}]' "$FIX/bom-ai-sample.json"
}
cdx_service "$digest" application > "$WORK/svc-bom.json"
python3 -I "$CONV" check --bom "$WORK/svc-bom.json" --declaration "$SVC" > "$WORK/svc-check.json" 2>/dev/null
{ [ "$(jq -r .service.state "$WORK/svc-check.json")" = "applied" ] && ! grep -q "declared service" "$WORK/svc-check.json"; } \
    && pass "a service the SBOM carries with the same digest is applied" || fail "applied: $(jq -c .service "$WORK/svc-check.json")"
jq '.service.packageVersion = "2.4.0"' "$SVC" > "$WORK/svc-changed.json"
python3 -I "$CONV" check --bom "$WORK/svc-bom.json" --declaration "$WORK/svc-changed.json" > "$WORK/svc-check.json" 2>/dev/null
{ [ "$(jq -r .service.state "$WORK/svc-check.json")" = "pendingScan" ] \
  && grep -q "the declared service differs from the one in the CycloneDX SBOM" "$WORK/svc-check.json"; } \
    && pass "a service changed after the scan is pendingScan" || fail "changed: $(jq -c .service "$WORK/svc-check.json")"
python3 -I "$CONV" check --bom "$WORK/svc-bom.json" --declaration "$FIX/declaration-complete.json" > "$WORK/svc-check.json" 2>/dev/null
{ [ "$(jq -r .service.state "$WORK/svc-check.json")" = "pendingScan" ] \
  && grep -q "records a declared service the declaration does not have" "$WORK/svc-check.json"; } \
    && pass "a service removed from the declaration is pendingScan until the next scan" || fail "removed: $(jq -c .service "$WORK/svc-check.json")"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$FIX/declaration-complete.json" > "$WORK/svc-check.json" 2>/dev/null
[ "$(jq -c .service "$WORK/svc-check.json")" = '{"state":"none"}' ] && pass "no service on either side is none" || fail "none: $(jq -c .service "$WORK/svc-check.json")"
# A data flow can be named, as CycloneDX serviceData is.
jq '.service.dataFlows[0].name = "  Chat questions "' "$SVC" > "$WORK/svc-named.json"
convert "$WORK/svc-named.json"
named=$(el ai_AIPackage "Acme Support Assistant" | jq -r '[.extension[].extension_cdxProperty[] | select(.extension_cdxPropName=="bomlens:service:dataFlow") | .extension_cdxPropValue | fromjson | .name // empty] | join("|")')
[ "$named" = "Chat questions" ] && pass "a data flow's name is accepted, trimmed and written with the flow" || fail "data flow name: $named"
# Reordering a list whose order means nothing is not a change; a new value is.
digest_of() { python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$1" 2>/dev/null | jq -r .service.digest; }
jq '.service.domain = ["support", "customer support"] | .service.standardCompliance = ["ISO/IEC 42001:2023", "ISO/IEC 23894:2023"]
    | .service.dataFlows[0].source = ["https://a.example/1", "https://a.example/2"]' "$SVC" > "$WORK/order-a.json"
jq '.service.domain |= reverse | .service.standardCompliance |= reverse | .service.dataFlows |= reverse
    | .service.dataFlows[1].source |= reverse | .service.inputModality = ["text"] | .model.outputModality = ["text"]' \
    "$WORK/order-a.json" > "$WORK/order-b.json"
jq '.service.domain += ["health"]' "$WORK/order-a.json" > "$WORK/order-c.json"
da=$(digest_of "$WORK/order-a.json"); db=$(digest_of "$WORK/order-b.json"); dc=$(digest_of "$WORK/order-c.json")
{ [ "${#da}" = "64" ] && [ "$da" = "$db" ] && [ "$da" != "$dc" ]; } \
    && pass "reordering domains, standards, data flows and addresses keeps the digest; a new domain changes it" \
    || fail "order-insensitive digest: a=$da b=$db c=$dc"
jq '.service.externalModels += [{"key": "ocr", "name": "Example OCR"}]' "$SVC" > "$WORK/order-d.json"
jq '.service.externalModels |= reverse' "$WORK/order-d.json" > "$WORK/order-e.json"
[ "$(digest_of "$WORK/order-d.json")" = "$(digest_of "$WORK/order-e.json")" ] \
    && pass "reordering the external models keeps the digest" || fail "external models order changed the digest"
# The model's declared values count without a service: the CycloneDX step
# records the digest on the model component then.
jq '.model.inputModality = ["text"] | .model.adversarialTesting = "no"' "$FIX/declaration-complete.json" > "$WORK/mv.json"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/mv.json" > "$WORK/mv-check.json" 2>/dev/null
mvd=$(jq -r .service.digest "$WORK/mv-check.json")
{ [ "$(jq -r .service.state "$WORK/mv-check.json")" = "pendingScan" ] && [ "${#mvd}" = "64" ] \
  && grep -q "are not in the CycloneDX SBOM yet" "$WORK/mv-check.json"; } \
    && pass "declared model values the SBOM does not carry yet are pendingScan" || fail "model values pending: $(jq -c .service "$WORK/mv-check.json")"
jq --arg d "$mvd" '.metadata.component.properties += [{"name": "bomlens:model:declarationDigest", "value": $d}]' \
    "$FIX/bom-ai-sample.json" > "$WORK/mv-bom.json"
python3 -I "$CONV" check --bom "$WORK/mv-bom.json" --declaration "$WORK/mv.json" > "$WORK/mv-check.json" 2>/dev/null
[ "$(jq -r .service.state "$WORK/mv-check.json")" = "applied" ] \
    && pass "the model's digest on the model component makes them applied" || fail "model values applied: $(jq -c .service "$WORK/mv-check.json")"
python3 -I "$CONV" check --bom "$WORK/mv-bom.json" --declaration "$FIX/declaration-complete.json" > "$WORK/mv-check.json" 2>/dev/null
{ [ "$(jq -r .service.state "$WORK/mv-check.json")" = "pendingScan" ] \
  && grep -q "records declared model values the declaration does not have" "$WORK/mv-check.json"; } \
    && pass "model values removed from the declaration are pendingScan until the next scan" || fail "model values removed: $(jq -c .service "$WORK/mv-check.json")"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$WORK/mv-bom.json" --out-dir "$OUT" --prefix "$P" --declaration "$WORK/mv.json" --stable 2>/dev/null
{ grep -q "^## Declared model values in the CycloneDX SBOM" "$OUT/${P}_spdx3-check.md" && ! grep -q "^## Service" "$OUT/${P}_spdx3-check.md"; } \
    && pass "the readable check names the model values, not a service, when no service is declared" || fail "model-only check text"
jq '.service.name = ""' "$SVC" > "$WORK/svc-noname.json"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/svc-noname.json" > "$WORK/svc-check.json" 2>/dev/null
{ [ "$(jq -r .service.state "$WORK/svc-check.json")" = "pendingScan" ] \
  && grep -q "has no name, so the CycloneDX SBOM cannot carry it" "$WORK/svc-check.json"; } \
    && pass "a service with no name says the SBOM cannot carry it until it is named" || fail "unnamed service: $(jq -c .service "$WORK/svc-check.json")"
jq 'del(.service.releaseTime, .service.autonomyType)' "$SVC" > "$WORK/svc-draft.json"
convert "$WORK/svc-draft.json"
{ [ $? -eq 0 ] && [ "$(jq -r .draft "$CHK")" = "true" ] \
  && [ "$(jq -r '[.elements[] | select(.type=="service") | .fields[] | select(.status=="missingRequired" or .status=="judgment") | "\(.id):\(.status)"] | join(" ")' "$CHK")" = "releaseTime:missingRequired autonomyType:judgment" ]; } \
    && pass "a service missing a required field makes a draft; autonomy is left to the publisher" || fail "service draft: $(jq -c .counts "$CHK")"
# Without a service, or with only the template's empty one, the output is the
# same bytes: the document, the check (but for the declaration's digest) and
# the readable check.
convert "$FIX/declaration-complete.json"; mkdir -p "$WORK/nosvc"; cp "$OUT"/* "$WORK/nosvc/"
python3 -I "$CONV" template --bom "$FIX/bom-ai-sample.json" --out-dir "$WORK" --prefix tpl 2>/dev/null
jq --slurpfile t "$WORK/tpl_ai-declaration.template.json" '.service = $t[0].service' "$FIX/declaration-complete.json" > "$WORK/emptysvc.json"
convert "$WORK/emptysvc.json"
{ cmp -s "$WORK/nosvc/${P}_bom.spdx3.json" "$DOC" && cmp -s "$WORK/nosvc/${P}_spdx3-check.md" "$OUT/${P}_spdx3-check.md" \
  && [ "$(jq -S 'del(.inputs.declaration)' "$WORK/nosvc/${P}_spdx3-check.json")" = "$(jq -S 'del(.inputs.declaration)' "$CHK")" ]; } \
    && pass "an empty service gives the same bytes as no service" || fail "an empty service changed the output"
! grep -q '/service/' "$DOC" && [ "$(jq -r .service.state "$CHK")" = "none" ] \
    && pass "and declares no service" || fail "an empty service was written"
refuse_s() {  # $1 label, $2 jq edit applied to the service declaration
    jq "$2" "$SVC" > "$WORK/bad.json"
    python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/bad.json" >"$WORK/bad.out" 2>/dev/null
    rc=$?
    { [ "$rc" -eq 2 ] && jq -e '.refused | length > 0' "$WORK/bad.out" >/dev/null; } && pass "refused: $1" || fail "not refused: $1 (rc=$rc)"
}
refuse_s "an unknown key in the service" '.service.owner = "x"'
refuse_s "primaryPurpose in the service (it is fixed)" '.service.primaryPurpose = "application"'
refuse_s "a service supplier that is not an organization" '.service.suppliedBy = {"name": "Acme Corp"}'
refuse_s "a service supplier given as a person" '.service.suppliedBy.type = "Person"'
refuse_s "a modality outside the list" '.service.inputModality = ["speech"]'
refuse_s "a model modality outside the list" '.model.outputModality = ["pdf"]'
refuse_s "an autonomy value outside the list" '.service.autonomyType = "partial"'
refuse_s "a service address with a file scheme" '.service.downloadLocation = "file:///srv/app"'
refuse_s "a disclosure page that is not an address" '.service.disclosureUrl = "see our website"'
refuse_s "a data flow direction outside CycloneDX's list" '.service.dataFlows[0].flow = "inward"'
refuse_s "a data flow with no classification" '.service.dataFlows[0].classification = " "'
refuse_s "a data flow source that is not an address" '.service.dataFlows[0].source = ["chat window"]'
refuse_s "a data flow destination with a javascript scheme" '.service.dataFlows[1].destination = ["javascript:alert(1)"]'
refuse_s "an unknown key in a data flow" '.service.dataFlows[0].governance = "x"'
refuse_s "a data flow name that is not text" '.service.dataFlows[0].name = 5'
refuse_s "a data flow name longer than the limit" '.service.dataFlows[0].name = ("a" * 300)'
refuse_s "a data flow description longer than the limit" '.service.dataFlows[0].description = ("a" * 5000)'
refuse_s "an external model key twice" '.service.externalModels += [{"key": "translate", "name": "Other"}]'
refuse_s "an external model key with capitals" '.service.externalModels[0].key = "Translate"'
refuse_s "an external model with no name" '.service.externalModels[0].name = ""'
refuse_s "an unknown key in an external model" '.service.externalModels[0].licence = "MIT"'
refuse_s "an external model endpoint that is not an address" '.service.externalModels[0].endpoint = "api.translate"'
refuse_s "training compute that is not a number" '.model.trainingComputeFlops = "about 1e24"'
refuse_s "training compute of zero" '.model.trainingComputeFlops = "0.0e5"'
refuse_s "negative training compute" '.model.trainingComputeFlops = "-3e24"'
refuse_s "training compute given as a JSON number" '.model.trainingComputeFlops = 3.2e24'
refuse_s "an adversarial testing value outside the list" '.model.adversarialTesting = "partly"'
refuse_s "a service that is not an object" '.service = ["x"]'
refuse_s "relationships, still reserved" '.relationships = [{"from": "service", "to": "model"}]'
printf '%s' '{"schema":"bomlens-ai-declaration/1","service":{"name":"S","packageVersion":"1","downloadLocation":"https://s.example","suppliedBy":{"type":"Organization","name":"O"},"releaseTime":"2025-01-01T00:00:00Z"}}' > "$WORK/dsroot-svc.json"
python3 -I "$CONV" check --bom "$WORK/dsroot.json" --declaration "$WORK/dsroot-svc.json" >"$WORK/bad.out" 2>/dev/null
{ [ $? -eq 2 ] && grep -q "describes a dataset, not a model" "$WORK/bad.out"; } \
    && pass "refused: a service on a dataset document" || fail "service accepted on a dataset document"
jq '.model.trainingComputeFlops = "1500000"' "$SVC" > "$WORK/svc-int.json"
python3 -I "$CONV" check --bom "$FIX/bom-ai-sample.json" --declaration "$WORK/svc-int.json" >/dev/null 2>&1
[ $? -eq 0 ] && pass "training compute written as a plain integer is accepted" || fail "integer training compute refused"
T="$WORK/tpl_ai-declaration.template.json"
{ [ "$(jq -c '.service | keys_unsorted' "$T")" = '["name","packageVersion","downloadLocation","suppliedBy","releaseTime","informationAboutApplication","domain","autonomyType","inputModality","outputModality","dataFlows","standardCompliance","disclosureUrl","externalModels"]' ] \
  && [ "$(jq -c '[.model.inputModality, .model.trainingComputeFlops, .model.adversarialTesting]' "$T")" = '[[],"",""]' ] \
  && [ "$(jq -c 'keys_unsorted' "$T")" = '["schema","document","model","datasets","service","relationships"]' ]; } \
    && pass "the template offers an empty service and the model's regulatory fields" || fail "template service: $(jq -c .service "$T")"
python3 -I "$CONV" template --bom "$WORK/dsroot.json" --out-dir "$WORK" --prefix dstpl 2>/dev/null
[ "$(jq 'has("service")' "$WORK/dstpl_ai-declaration.template.json")" = "false" ] \
    && pass "a dataset document's template offers no service" || fail "dataset template has a service"
if [ -n "${JSPY:-}" ]; then
    convert "$SVC"
    verr=$("$JSPY" - "$FIX/spdx-json-schema.json" "$DOC" <<'PY'
import json, sys
import jsonschema
schema = json.load(open(sys.argv[1]))
doc = json.load(open(sys.argv[2]))
errs = sorted(jsonschema.Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
print("\n".join(f"{list(e.path)}: {e.message[:200]}" for e in errs[:10]))
PY
)
    [ -z "$verr" ] && pass "the document with a service is valid SPDX 3.0.1 JSON" || fail "service schema errors" "$verr"
fi

echo "== bad input is reported, not written =="
echo '{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"library","name":"x"}]}' > "$WORK/lib.json"
python3 -I "$CONV" convert --bom "$WORK/lib.json" --out-dir "$OUT" --prefix x 2>/dev/null
[ $? -eq 3 ] && pass "an SBOM with no model or dataset is refused with its own exit code (3)" || fail "non-AI SBOM accepted"
python3 -I "$CONV" convert --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix "../escape" 2>/dev/null
[ $? -eq 1 ] && pass "a prefix that is a path is refused" || fail "path prefix accepted"
python3 -I "$CONV" convert --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix=.. 2>/dev/null
[ $? -eq 1 ] && pass "a prefix of .. is refused" || fail ".. prefix accepted"

echo "== the prefix a scan gives a project named in Korean =="
# entrypoint.sh keeps [A-Za-z0-9.-]: a project named only in Korean becomes
# "_1.0", and one starting with "-" keeps the dash.
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix=_1.0 2>/dev/null \
  && [ -f "$OUT/_1.0_bom.spdx3.json" ] && pass "a prefix that starts with _ is written" || fail "_1.0 prefix refused"
python3 -I "$CONV" template --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix=-x_1.0 2>/dev/null \
  && [ -f "$OUT/-x_1.0_ai-declaration.template.json" ] && pass "a prefix that starts with - is taken as --prefix=" || fail "-x prefix refused"

echo "== the check records what it was made from =="
convert "$FIX/declaration-complete.json"
{ [ "$(jq -r .inputs.bom "$CHK")" = "$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$FIX/bom-ai-sample.json")" ] \
  && [ "$(jq -r .inputs.declaration "$CHK")" = "$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$FIX/declaration-complete.json")" ] \
  && [ "$(jq -r '.inputs.tool | length' "$CHK")" = "64" ] \
  && [ "$(jq -r .declaration.state "$CHK")" = "applied" ]; } \
    && pass "the check holds the digests of the SBOM, the declaration and the converter" || fail "inputs: $(jq -c '{inputs, declaration}' "$CHK")"
convert
{ [ "$(jq -r .inputs.declaration "$CHK")" = "null" ] && [ "$(jq -r .declaration.state "$CHK")" = "none" ]; } \
    && pass "without a declaration the check says none" || fail "no-declaration inputs"

echo "== a refused declaration with --declaration-fallback =="
jq '.model.license = "my own terms"' "$FIX/declaration-complete.json" > "$WORK/refused.json"
rm -f "$OUT"/*
python3 -I "$CONV" convert --bom "$FIX/bom-ai-sample.json" --out-dir "$OUT" --prefix "$P" \
    --declaration "$WORK/refused.json" --declaration-fallback --stable 2>/dev/null
rc=$?
{ [ "$rc" -eq 2 ] && [ -f "$DOC" ] && [ "$(jq -r .draft "$CHK")" = "true" ] \
  && [ "$(jq -r .declaration.state "$CHK")" = "refused" ] \
  && jq -e '.declaration.reasons | any(test("license"))' "$CHK" >/dev/null; } \
    && pass "the document is written without it, exit 2, and the check keeps the reasons" || fail "fallback rc=$rc $(jq -c .declaration "$CHK" 2>/dev/null)"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
