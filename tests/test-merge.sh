#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-merge.sh — No-Docker unit tests for merge-sbom.sh (MERGE mode's engine).
#
# MERGE was the thinnest-covered scan mode: the only automated coverage was one
# purl-dedupe check in the container e2e suite, which runs on push/dispatch
# only. This suite drives the pure bash+jq merger directly against fixtures on
# every PR: layer tagging, first-layer-wins dedupe (purl and name@version
# fallback), dependency-graph union, malformed-input handling, and the
# MERGE_ROOT_FROM root/spec preservation the AI path depends on.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MERGE="$ROOT_DIR/docker/lib/merge-sbom.sh"
FIX="$ROOT_DIR/tests/fixtures"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required for merge unit tests"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== dedupe: overlapping layers, first layer wins =="
# good-cyclonedx {express,lodash} + cdxgen-node-managed {lodash,express,axios}:
# three unique purls; the shared two must carry the FIRST layer's tag.
out="$WORK/merged.json"
bash "$MERGE" "$out" "server" "1.0" "$FIX/good-cyclonedx.json" "$FIX/cdxgen-node-managed.json" >/dev/null 2>&1
ntotal=$(jq '.components | length' "$out" 2>/dev/null)
[ "$ntotal" = "3" ] && pass "3 unique components from 2+3 inputs" || fail "expected 3 components, got $ntotal"
first_layer=$(jq -r '.components[] | select(.name=="express") | .properties[] | select(.name=="bomlens:layer") | .value' "$out")
[ "$first_layer" = "supplier-app" ] && pass "shared component keeps the first layer's tag (supplier-app)" || fail "express layer='$first_layer', expected supplier-app"
axios_layer=$(jq -r '.components[] | select(.name=="axios") | .properties[] | select(.name=="bomlens:layer") | .value' "$out")
[ "$axios_layer" = "webapp" ] && pass "layer tag names each input's root component" || fail "axios layer='$axios_layer', expected webapp"
root=$(jq -r '.metadata.component.name + "@" + .metadata.component.version + " " + .specVersion' "$out")
[ "$root" = "server@1.0 1.6" ] && pass "fresh 1.6 root stamped with the caller's identity" || fail "root/spec='$root', expected server@1.0 1.6"

echo "== dependency graph: edges survive, same-ref dependsOn unioned, empty edges dropped =="
# Layer C reuses layer A's express ref with a different dependsOn: the merged
# entry must union both lists. lodash's empty-dependsOn entry must be dropped.
cat > "$WORK/layer-c.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"application","name":"binlayer","version":"1"}},
 "components":[{"type":"library","name":"openssl","version":"3.0.1","purl":"pkg:generic/openssl@3.0.1"}],
 "dependencies":[{"ref":"pkg:npm/express@4.18.2","dependsOn":["pkg:generic/openssl@3.0.1"]}]}
EOF
bash "$MERGE" "$out" "server" "1.0" "$FIX/good-cyclonedx.json" "$WORK/layer-c.json" >/dev/null 2>&1
edges=$(jq -c '[.dependencies[] | select(.ref=="pkg:npm/express@4.18.2") | .dependsOn] | first | sort' "$out")
[ "$edges" = '["pkg:generic/openssl@3.0.1","pkg:npm/lodash@4.17.21"]' ] \
    && pass "same-ref dependsOn lists unioned across layers" \
    || fail "express dependsOn=$edges"
lodash_edge=$(jq '[.dependencies[] | select(.ref=="pkg:npm/lodash@4.17.21")] | length' "$out")
[ "$lodash_edge" = "0" ] && pass "empty-dependsOn entries dropped" || fail "lodash empty edge kept"

echo "== rootless input gets a positional layer-<i> tag =="
jq 'del(.metadata.component)' "$FIX/cdxgen-node-managed.json" > "$WORK/rootless.json"
bash "$MERGE" "$out" "server" "1.0" "$FIX/good-cyclonedx.json" "$WORK/rootless.json" >/dev/null 2>&1
axios_layer=$(jq -r '.components[] | select(.name=="axios") | .properties[] | select(.name=="bomlens:layer") | .value' "$out")
[ "$axios_layer" = "layer-1" ] && pass "rootless input tagged layer-1" || fail "axios layer='$axios_layer', expected layer-1"

echo "== purl-less components dedupe by name@version =="
cat > "$WORK/nopurl-a.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"a","type":"application"}},
 "components":[{"type":"library","name":"zlib","version":"1.3"},{"type":"library","name":"pcre","version":"8.45"}]}
EOF
cat > "$WORK/nopurl-b.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"b","type":"application"}},
 "components":[{"type":"library","name":"zlib","version":"1.3"},{"type":"library","name":"zlib","version":"1.2.11"}]}
EOF
bash "$MERGE" "$out" "server" "1.0" "$WORK/nopurl-a.json" "$WORK/nopurl-b.json" >/dev/null 2>&1
n=$(jq '.components | length' "$out")
[ "$n" = "3" ] && pass "zlib@1.3 deduped, zlib@1.2.11 kept apart (3 total)" || fail "expected 3, got $n"

echo "== malformed inputs: skipped with a warning; all-invalid aborts =="
echo '{ not json' > "$WORK/broken.json"
errlog="$WORK/err.log"
if bash "$MERGE" "$out" "server" "1.0" "$FIX/good-cyclonedx.json" "$WORK/broken.json" >/dev/null 2>"$errlog"; then
    grep -q "skipping missing or invalid SBOM" "$errlog" \
        && pass "invalid layer skipped with a warning, merge continues" \
        || fail "no skip warning emitted" "$(cat "$errlog")"
    n=$(jq '.components | length' "$out")
    [ "$n" = "2" ] && pass "valid layer's components survive (2)" || fail "expected 2 components, got $n"
else
    fail "merge aborted although one input was valid"
fi
if bash "$MERGE" "$out" "server" "1.0" "$WORK/broken.json" "$WORK/broken.json" >/dev/null 2>&1; then
    fail "all-invalid inputs must exit non-zero"
else
    pass "all-invalid inputs exit non-zero"
fi
if bash "$MERGE" "$out" "server" "1.0" "$FIX/good-cyclonedx.json" >/dev/null 2>&1; then
    fail "fewer than 2 inputs must exit non-zero"
else
    pass "fewer than 2 inputs exit non-zero"
fi

echo "== MERGE_ROOT_FROM: ML-BOM keeps its spec and root, renamed to the caller =="
# The AI path merges an application SBOM into a 1.7 ML-BOM without downgrading
# it to 1.6 or losing the model root; the generator's ephemeral job-id root name
# is overridden with the caller-supplied identity.
if MERGE_ROOT_FROM="$FIX/aibom-owasp-1_7.json" bash "$MERGE" "$out" "bert-app" "2.0" \
    "$FIX/aibom-owasp-1_7.json" "$FIX/cdxgen-node-managed.json" >/dev/null 2>&1; then
    spec=$(jq -r '.specVersion' "$out")
    [ "$spec" = "1.7" ] && pass "specVersion 1.7 preserved" || fail "specVersion='$spec', expected 1.7"
    rootname=$(jq -r '.metadata.component.name + "@" + .metadata.component.version' "$out")
    [ "$rootname" = "bert-app@2.0" ] && pass "preserved root renamed to the caller's identity" || fail "root='$rootname', expected bert-app@2.0"
    jq -e '.metadata.component.purl' "$out" >/dev/null \
        && pass "preserved root keeps its other fields (purl)" \
        || fail "preserved root lost its fields"
    jq -e '.components[] | select(.name=="bert-base-uncased") | .modelCard' "$out" >/dev/null \
        && pass "model component's modelCard survives the merge" \
        || fail "modelCard lost from the model component"
else
    fail "MERGE_ROOT_FROM merge failed"
fi

echo "== MERGE_ROOT_FROM: malformed base falls back to a fresh 1.6 root with a warning =="
if MERGE_ROOT_FROM="$WORK/broken.json" bash "$MERGE" "$out" "server" "1.0" \
    "$FIX/good-cyclonedx.json" "$FIX/cdxgen-node-managed.json" >/dev/null 2>"$errlog"; then
    spec=$(jq -r '.specVersion + " " + .metadata.component.name' "$out")
    [ "$spec" = "1.6 server" ] && pass "fresh 1.6 root used when the base is malformed" || fail "got '$spec'"
else
    fail "merge failed on malformed MERGE_ROOT_FROM (should fall back)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
