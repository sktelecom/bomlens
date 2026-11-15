#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-external-aibom.sh: No-Docker tests for reading AI BOMs that other tools
# wrote. Each sample in tests/fixtures/external-aibom (see NOTICE.md there) goes
# through the conformance step. The G7 checks must come out, a value that a tool
# keeps in its own property must count and name that property, and a tool that
# does not carry a value must still be reported as missing.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FX="$ROOT_DIR/tests/fixtures/external-aibom"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# $1 sample file, $2 name. Writes $WORK/$2_conformance.json.
conform() {
    bash "$LIB/validate-sbom.sh" "$1" "$WORK/$2" "$2" >"$WORK/$2.log" 2>&1
    [ -s "$WORK/$2_conformance.json" ]
}
# $1 name, $2 element id, $3 jq expression over that check.
check_is() {
    local got
    got="$(jq -r --arg id "$2" ".checks[] | select(.id==\$id) | $3" "$WORK/$1_conformance.json" 2>/dev/null)"
    printf '%s' "$got"
}

echo "== every sample is read and gets the 51 G7 checks =="
for f in "$FX"/*.cdx.json; do
    n="$(basename "$f" .cdx.json)"
    if conform "$f" "$n"; then
        c="$(jq '[.checks[] | select(.id | startswith("g7-"))] | length' "$WORK/${n}_conformance.json")"
        [ "$c" = "51" ] && pass "$n: 51 G7 checks" || fail "$n: $c G7 checks, expected 51" "$(tail -3 "$WORK/$n.log")"
    else
        fail "$n: no conformance result" "$(tail -3 "$WORK/$n.log")"
    fi
done

echo "== AIsbom: the hub values it keeps in properties count =="
n=aisbom-model
[ "$(check_is $n g7-model-id .status)" = "pass" ] && [ "$(check_is $n g7-model-id '.via[0]')" = "aisbom:hf:repo_id" ] \
    && pass "model identifier read from aisbom:hf:repo_id" || fail "model identifier" "$(check_is $n g7-model-id .detail)"
[ "$(check_is $n g7-model-license .status)" = "pass" ] && [ "$(check_is $n g7-model-license '.via[0]')" = "aisbom:hf:license" ] \
    && pass "model licence read from aisbom:hf:license" || fail "model licence" "$(check_is $n g7-model-license .detail)"
[ "$(check_is $n g7-model-version .status)" = "pass" ] && [ "$(check_is $n g7-model-version '.via[0]')" = "aisbom:hf:revision" ] \
    && pass "model version read from aisbom:hf:revision" || fail "model version" "$(check_is $n g7-model-version .detail)"
[ "$(check_is $n g7-model-hash-value .status)" = "pass" ] \
    && pass "hash comes from the standard field, no property named" || fail "model hash" "$(check_is $n g7-model-hash-value .detail)"
[ "$(check_is $n g7-model-hash-value '.via // "none"')" = "none" ] \
    && pass "a value in a standard field names no tool property" || fail "via on a standard field"

echo "== AIBoMGen CLI: standard fields, and the lifecycle phase =="
n=aibomgen-cli-model
for id in g7-model-id g7-model-version g7-model-license g7-model-producer g7-model-hash-value g7-model-card; do
    [ "$(check_is $n $id .status)" = "pass" ] && pass "$id passes" || fail "$id" "$(check_is $n $id .detail)"
done
[ "$(check_is $n g7-meta-gen-context .status)" = "pass" ] && [ "$(check_is $n g7-meta-gen-context '.via[0]')" = "metadata.lifecycles" ] \
    && pass "generation context read from metadata.lifecycles" || fail "generation context" "$(check_is $n g7-meta-gen-context .detail)"
[ "$(check_is $n g7-model-id '.via // "none"')" = "none" ] \
    && pass "a purl needs no tool property" || fail "via on a purl"

echo "== k8s-aibom: lifecycle read, model facts it does not carry stay missing =="
n=k8s-aibom-llama-cpp-chat
[ "$(check_is $n g7-meta-gen-context .status)" = "pass" ] && [ "$(check_is $n g7-meta-gen-context '.via[0]')" = "metadata.lifecycles" ] \
    && pass "generation context read from metadata.lifecycles" || fail "generation context" "$(check_is $n g7-meta-gen-context .detail)"
for id in g7-model-id g7-model-version g7-model-license g7-model-hash-value; do
    [ "$(check_is $n $id .status)" = "warn" ] && pass "$id reported missing" || fail "$id not reported missing" "$(check_is $n $id .detail)"
done
jq '(.components[] | select(.type=="machine-learning-model") | .properties) += [{"name":"k8s-aibom:model:revision","value":"abc123"}]' \
    "$FX/k8s-aibom-llama-cpp-chat.cdx.json" > "$WORK/k8s-rev.cdx.json"
conform "$WORK/k8s-rev.cdx.json" k8s-rev
[ "$(check_is k8s-rev g7-model-version .status)" = "pass" ] && [ "$(check_is k8s-rev g7-model-version '.via[0]')" = "k8s-aibom:model:revision" ] \
    && pass "model version read from k8s-aibom:model:revision when the tool resolved one" || fail "k8s model revision" "$(check_is k8s-rev g7-model-version .detail)"

echo "== Cisco AI BOM: nothing is invented =="
n=cisco-aibom-app
for id in g7-model-license g7-model-version g7-model-hash-value g7-model-card; do
    [ "$(check_is $n $id .status)" = "warn" ] && pass "$id reported missing" || fail "$id not reported missing" "$(check_is $n $id .detail)"
done
[ "$(jq '[.checks[] | select(.via != null)] | length' "$WORK/${n}_conformance.json")" = "0" ] \
    && pass "no value is credited to a tool property" || fail "a value was credited to a tool property"

echo "== risk assessment uses the hub licence AIsbom recorded =="
cp "$FX/aisbom-model.cdx.json" "$WORK/risk.json"
bash "$LIB/assess-ai-risk.sh" "$WORK/risk.json" >/dev/null 2>&1
[ "$(jq -r '.components[0].properties[] | select(.name=="bomlens:assessment:license") | .value' "$WORK/risk.json")" = "ok" ] \
    && pass "apache-2.0 in aisbom:hf:license is judged, not read as undeclared" || fail "licence verdict" "$(jq -c '.components[0].properties' "$WORK/risk.json" | cut -c1-300)"
jq '.components[0].licenses = [{"license":{"id":"GPL-3.0-only"}}]' "$FX/aisbom-model.cdx.json" > "$WORK/risk2.json"
bash "$LIB/assess-ai-risk.sh" "$WORK/risk2.json" >/dev/null 2>&1
[ "$(jq -r '.components[0].properties[] | select(.name=="bomlens:assessment:license:keys") | .value' "$WORK/risk2.json")" != "permissive" ] \
    && pass "licenses[] wins over the hub value when both exist" || fail "licenses[] did not win"

echo "== a BOM written by BomLens itself is unchanged =="
conform "$ROOT_DIR/tests/fixtures/aibom-owasp-1_7.json" own
[ "$(jq '[.checks[] | select(.via != null)] | length' "$WORK/own_conformance.json")" = "0" ] \
    && pass "no via on a BomLens model SBOM" || fail "via appeared on a BomLens model SBOM"

echo
echo "External AI BOM: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
