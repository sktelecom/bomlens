#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-spdx3-official.sh — validate the SPDX 3.0.1 AI documents
# convert-to-spdx3-ai.py writes with the official SPDX 3 validator
# (spdx3-validate: the SPDX 3.0.1 SHACL model and JSON schema). test-spdx3-ai.sh
# checks the same documents against the JSON schema only; this adds the SHACL
# constraints (classes, vocabularies, value types). Documents are made offline
# from the test fixtures.
#
# A document with an author must pass, even one the converter's check calls a
# draft: the narrowed 1..1 counts of the specification pages are not in the
# SHACL model. One without an author must fail for that (CreationInfo.createdBy)
# and nothing else.
#
# Needs spdx3-validate on PATH (or SPDX3_VALIDATE): pip install --require-hashes
# -r tests/spdx3-validate-requirements.txt. Run nightly, not per PR.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures/spdx3"
CONV="$LIB/convert-to-spdx3-ai.py"
VALIDATE="${SPDX3_VALIDATE:-spdx3-validate}"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "$2" | head -40 | sed 's/^/        /'; FAIL=$((FAIL + 1)); }

command -v "$VALIDATE" >/dev/null 2>&1 || { echo "[ERROR] $VALIDATE not found; install tests/spdx3-validate-requirements.txt"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# convert <name> <bom> [declaration]: writes $WORK/<name>_bom.spdx3.json
convert() {
    if [ -n "${3:-}" ]; then
        python3 -I "$CONV" convert --bom "$2" --declaration "$3" --out-dir "$WORK" --prefix "$1" --stable >/dev/null 2>&1
    else
        python3 -I "$CONV" convert --bom "$2" --out-dir "$WORK" --prefix "$1" --stable >/dev/null 2>&1
    fi
}

complete() {  # <name> <label>
    if out=$("$VALIDATE" -q -s 3.0.1 --json "$WORK/$1_bom.spdx3.json" 2>&1); then
        pass "$2 passes the official validation"
    else
        fail "$2 fails the official validation" "$out"
    fi
}

draft() {  # <name> <label>
    out=$("$VALIDATE" -q -s 3.0.1 --json "$WORK/$1_bom.spdx3.json" 2>&1) && { fail "$2: a draft passed; expected the missing author to fail it"; return; }
    n=$(printf '%s\n' "$out" | grep -c "^Violation of type")
    if [ "$n" -eq 1 ] && printf '%s\n' "$out" | grep -q "MinCountConstraintComponent" \
       && printf '%s\n' "$out" | grep -q "Core/createdBy"; then
        pass "$2 fails only for the author it lacks"
    else
        fail "$2 fails for more than the missing author ($n violations)" "$out"
    fi
}

echo "== a scanned model =="
convert full "$FIX/bom-ai-sample.json" "$FIX/declaration-complete.json"
complete full "the model with a complete declaration"
convert draft "$FIX/bom-ai-sample.json"
draft draft "the model with no declaration"

echo "== the service the model runs in =="
# The service is an ai_AIPackage (primaryPurpose application) with its data
# flows as extension JSON text; an external API model is a software_Package.
convert service "$FIX/bom-ai-sample.json" "$FIX/declaration-service.json"
complete service "the model with a declared service and an external model"
jq 'del(.service.releaseTime, .service.suppliedBy)' "$FIX/declaration-service.json" > "$WORK/decl-svc-draft.json"
convert svcdraft "$FIX/bom-ai-sample.json" "$WORK/decl-svc-draft.json"
complete svcdraft "a service the check calls a draft (no release time, no supplier)"
jq 'del(.document)' "$FIX/declaration-service.json" > "$WORK/decl-svc-noauthor.json"
convert svcnoauthor "$FIX/bom-ai-sample.json" "$WORK/decl-svc-noauthor.json"
draft svcnoauthor "the service document with no author"

echo "== licences and sources the publisher declares =="
jq 'del(.metadata.component.licenses)' "$FIX/bom-ai-sample.json" > "$WORK/nolic.json"
jq '.model.license = "apache-2.0"
    | .datasets[0].sources = [
        {"ref": "huggingface:org/upstream", "relation": "extended"},
        {"ref": "huggingface:org/new-src", "relation": "other"},
        {"name": "Wikipedia dump 2023-01", "license": "cc-by-sa-3.0", "relation": "extended"},
        {"name": "Gated crawl", "license": "openrail++"}]' \
   "$FIX/declaration-complete.json" > "$WORK/decl-more.json"
convert more "$WORK/nolic.json" "$WORK/decl-more.json"
complete more "the model with a declared licence and declared sources"

echo "== a model described from its declaration alone =="
jq '.model.license = "llama3.1"' "$FIX/declaration-complete.json" > "$WORK/decl-lic.json"
python3 -I "$LIB/declare-ai-model.py" "$WORK/decl-lic.json" "$WORK/declared.json" acme 1.0 --offline >/dev/null 2>&1
convert declared "$WORK/declared.json" "$WORK/decl-lic.json"
complete declared "the declared model"

echo "== a dataset on its own =="
jq '.metadata.component = (.components[0]) | .components = .components[1:] | .dependencies = []' \
    "$FIX/bom-ai-sample.json" > "$WORK/dsroot.json"
convert dataset "$WORK/dsroot.json"
draft dataset "the dataset document"

echo "== real generator output =="
for f in aibom-owasp-1_7.json aibom-datasets-1_7.json; do
    convert "gen-${f%%.json}" "$ROOT_DIR/tests/fixtures/$f"
    draft "gen-${f%%.json}" "$f"
done

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
