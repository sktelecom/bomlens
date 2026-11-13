#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-ai-usage.sh: No-Docker unit tests for the AI usage pass of a source scan.
#
# build-prep.sh runs cdxgen's `ai` and `mcp` analyses inside the cdxgen
# container and merges them into the SBOM with a node script it carries inline.
# This suite extracts that script and drives it against the recorded cdxgen
# 13.5.0 output for tests/fixtures/ai-usage (a service calling a hosted model,
# a hub model loaded locally, MCP configurations, instruction files), plus a
# sample of the text-matching noise the analysis reports on a codebase that
# talks about models. It then checks that the conformance report, the NOTICE
# and the AI risk assessment leave the AI usage items out.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
SRC="$ROOT_DIR/tests/fixtures/ai-usage"
REC="$ROOT_DIR/tests/fixtures/ai-usage-cdxgen"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required"; exit 1; }
command -v node >/dev/null 2>&1 || { echo "[ERROR] node is required"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The recorded output names the scanned tree /app; point it at the fixture.
for k in ai mcp main noise; do
    sed "s#\"/app#\"$SRC#g; s#file:/app/#file:$SRC/#g" "$REC/$k.json" > "$WORK/$k.json"
done
awk '/<<.AI_USAGE_JS.$/ { f = 1; next } /^AI_USAGE_JS$/ { f = 0 } f' "$LIB/build-prep.sh" > "$WORK/merge.js"
[ -s "$WORK/merge.js" ] && pass "merge script extracted from build-prep.sh" || { fail "merge script not found in build-prep.sh"; exit 1; }

B="$WORK/bom.json"
cp "$WORK/main.json" "$B"
log=$(node "$WORK/merge.js" "$B" "$SRC" "$WORK/ai.json" "$WORK/mcp.json" 2>&1)
echo "  $log"

usage() { jq -r --arg u "$1" '[(.components // [])[], (.services // [])[]]
    | map(select(any(.properties[]?; .name == "bomlens:ai:usage" and .value == $u)) | .name) | sort | join(",")' "$B"; }
p() { jq -r --arg n "$1" --arg k "$2" '[(.components // [])[], (.services // [])[]] | map(select(.name == $n))[0]
    | [.properties[]? | select(.name == $k) | .value] | join(",")' "$B"; }

echo "== what the fixture uses =="
[ "$(usage model)" = "Llama-3.1-8B-Instruct,gpt-4o" ] && pass "two models" || fail "models: $(usage model)"
[ "$(usage ai-service)" = "OpenAI API" ] && pass "one AI service" || fail "AI services: $(usage ai-service)"
[ "$(usage mcp-server)" = "docs,fs,github" ] && pass "three MCP servers" || fail "MCP servers: $(usage mcp-server)"
[ "$(usage mcp-config)" = "mcp.json,mcp.json" ] && pass "two MCP configuration files" || fail "MCP configs: $(usage mcp-config)"
inst=$(jq -r '[.components[] | select(any(.properties[]?; .name == "bomlens:ai:usage" and .value == "instruction-file"))
    | [.properties[] | select(.name == "bomlens:ai:path") | .value][0]] | sort | join(",")' "$B")
[ "$inst" = ".cursor/rules/style.mdc,.github/copilot-instructions.md,AGENTS.md" ] \
    && pass "instruction files, cdxgen's and the ones it misses, each once" || fail "instruction files: $inst"
[ "$(jq '[.components[] | select(.purl | . != null and startswith("pkg:pypi/"))] | length' "$B")" = "2" ] \
    && pass "the language pass's packages are kept" || fail "pypi components changed"

echo "== corrections =="
[ "$(jq -r '.components[] | select(.name == "gpt-4o") | .purl' "$B")" = "pkg:generic/openai/gpt-4o" ] \
    && pass "hosted model keeps a generic purl" || fail "gpt-4o purl"
[ "$(p Llama-3.1-8B-Instruct cdx:ai:provider)" = "huggingface" ] && pass "hub model's provider taken from its purl" \
    || fail "Llama provider: $(p Llama-3.1-8B-Instruct cdx:ai:provider)"
svc_deps=$(jq -r '(.services[] | select(.name == "OpenAI API") | .["bom-ref"]) as $s
    | [.dependencies[] | select(.ref == $s) | .dependsOn[]] | join(",")' "$B")
gpt_ref=$(jq -r '.components[] | select(.name == "gpt-4o") | .["bom-ref"]' "$B")
[ "$svc_deps" = "$gpt_ref" ] && pass "the OpenAI service depends on gpt-4o only" || fail "OpenAI API dependsOn: $svc_deps"
[ "$(p "OpenAI API" cdx:ai:modelId)" = "gpt-4o" ] && [ "$(p "OpenAI API" cdx:ai:modelCount)" = "1" ] \
    && pass "the service's model list follows" || fail "OpenAI API modelId=$(p "OpenAI API" cdx:ai:modelId)"
llama_root=$(jq -r '.metadata.component["bom-ref"] as $r | (.components[] | select(.name == "Llama-3.1-8B-Instruct") | .["bom-ref"]) as $l
    | [.dependencies[] | select(.ref == $r) | .dependsOn[] | select(. == $l)] | length' "$B")
[ "$llama_root" = "1" ] && pass "the locally loaded model hangs from the project root" || fail "Llama not under the root"
[ "$(p github bomlens:ai:reviewReason)" = "unpinned-package" ] && pass "unpinned npx package flagged" \
    || fail "github: $(p github bomlens:ai:reviewReason)"
[ "$(p fs bomlens:ai:reviewReason)" = "broad-filesystem-access" ] && pass "filesystem root flagged, pinned version not" \
    || fail "fs: $(p fs bomlens:ai:reviewReason)"
[ "$(p docs bomlens:ai:reviewReason)" = "unencrypted-transport" ] && pass "plain-http endpoint flagged" \
    || fail "docs: $(p docs bomlens:ai:reviewReason)"
[ "$(p gpt-4o bomlens:ai:scope)" = "runtime" ] && [ "$(p github bomlens:ai:scope)" = "development" ] \
    && pass "scope: code is runtime, editor configuration is development" || fail "scope"

echo "== nothing leaks =="
if grep -q "$SRC" "$B"; then fail "an absolute path of the scanned tree is in the SBOM" "$(grep -o "${SRC}[^\"]*" "$B" | head -2)"
else pass "no absolute path of the scanned tree"; fi
grep -q "fixture-placeholder-value" "$B" && fail "an MCP environment value was copied" || pass "MCP environment values stay out"
grep -q "helpful assistant" "$B" && fail "a prompt text was copied" || pass "prompt texts stay out"
dup=$(jq '[(.components // [])[], (.services // [])[] | .["bom-ref"]] | group_by(.) | map(select(length > 1)) | length' "$B")
[ "$dup" = "0" ] && pass "bom-refs are unique" || fail "$dup duplicated bom-ref(s)"
dangling=$(jq '([(.components // [])[], (.services // [])[] | .["bom-ref"]] + [.metadata.component["bom-ref"]]) as $refs
    | [.dependencies[] | .ref, .dependsOn[]? | select(. as $x | $refs | index($x) | not)] | length' "$B")
[ "$dangling" = "0" ] && pass "every dependency reference resolves" || fail "$dangling dangling dependency reference(s)"

echo "== text-matching noise is left out =="
N="$WORK/noise-bom.json"
cp "$WORK/main.json" "$N"
log=$(node "$WORK/merge.js" "$N" "$SRC" "$WORK/noise.json" "$WORK/missing.json" 2>&1)
echo "  $log"
case "$log" in *"left out as not plausible: 6 model(s), 1 file(s), 2 service(s)"*) pass "words, placeholders, tests, docs and catch-all ids dropped" ;;
    *) fail "noise not dropped as expected" "$log" ;; esac
# Only the fixture's own instruction files can come in: the noise sample names none.
[ "$(jq '[(.components // [])[], (.services // [])[] | select(any(.properties[]?; .name == "bomlens:ai:usage" and .value != "instruction-file"))] | length' "$N")" = "0" ] \
    && pass "no model or service from the noise" || fail "noise reached the SBOM"

echo "== the existing dependency graph keeps its meaning =="
# A root with an empty dependsOn means "whatever nothing points at is direct";
# AI items must not fill it.
E="$WORK/empty-root.json"
jq '(.metadata.component["bom-ref"]) as $r | .dependencies |= map(if .ref == $r then .dependsOn = [] else . end)' "$WORK/main.json" > "$E"
node "$WORK/merge.js" "$E" "$SRC" "$WORK/ai.json" "$WORK/mcp.json" >/dev/null 2>&1
[ "$(jq -r '(.metadata.component["bom-ref"]) as $r | [.dependencies[] | select(.ref == $r) | .dependsOn[]] | length' "$E")" = "0" ] \
    && pass "an empty root dependsOn stays empty" || fail "AI items were hung from an empty root"
D="$WORK/no-graph.json"
jq 'del(.dependencies)' "$WORK/main.json" > "$D"
node "$WORK/merge.js" "$D" "$SRC" "$WORK/ai.json" "$WORK/mcp.json" >/dev/null 2>&1
jq -e '(.dependencies // []) | length == 0' "$D" >/dev/null && jq -e '[.services[]?] | length == 4' "$D" >/dev/null \
    && pass "an SBOM without a graph gets no graph, only the items" || fail "a dependency graph was invented"

echo "== endpoints, versions and links =="
M2="$WORK/mcp-cred.json"
jq '(.services[] | select(.name == "docs") | .endpoints) = ["https://user:s3cr3t@docs.example.com/mcp?token=abc#x"]
    | (.components[] | .properties[]? | select(.name == "cdx:mcp:configuredEndpoints") | .value) |= "https://user:s3cr3t@docs.example.com/mcp?token=abc"' \
    "$WORK/mcp.json" > "$M2"
C="$WORK/cred.json"
cp "$WORK/main.json" "$C"
node "$WORK/merge.js" "$C" "$SRC" "$WORK/ai.json" "$M2" >/dev/null 2>&1
if grep -qE 's3cr3t|token=abc' "$C"; then fail "an endpoint credential reached the SBOM"; else pass "endpoint user info and query are removed"; fi
jq -e '[.services[] | select(.name == "docs") | .endpoints[]] == ["https://docs.example.com/mcp"]' "$C" >/dev/null \
    && pass "the endpoint itself is kept" || fail "docs endpoint: $(jq -c '.services[] | select(.name == "docs") | .endpoints' "$C")"
T="$WORK/tree"
mkdir -p "$T/.cursor" "$WORK/outside/rules" "$T/.github"
printf '{"mcpServers":{"a":{"command":"npx","args":["-y","pkg-a@latest"]},"b":{"command":"npx","args":["pkg-b@^1.2.0"]},"c":{"command":"npx","args":["pkg-c@1.2.3"]},"d":{"command":"uvx","args":["tool-d==0.4.1"]},"e":{"command":"uvx","args":["tool-e"]}}}\n' > "$T/.cursor/mcp.json"
printf 'secret rules\n' > "$WORK/outside/rules/x.instructions.md"
ln -s "$WORK/outside/rules" "$T/.github/instructions"
jq -n --arg f "$T/.cursor/mcp.json" '{bomFormat:"CycloneDX", specVersion:"1.6",
    metadata:{component:{"bom-ref":"app", name:"app"}},
    services: ["a","b","c","d","e"] | map({"bom-ref":("urn:service:mcp:" + .), name: .,
        properties:[{name:"cdx:mcp:serviceType", value:"configured-server"}, {name:"cdx:mcp:configKey", value:("mcpServers." + .)}, {name:"internal:SrcFile", value:$f}]})}' > "$T/mcp-in.json"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"app","name":"app"}},"components":[]}' > "$T/bom.json"
node "$WORK/merge.js" "$T/bom.json" "$T" "$WORK/missing.json" "$T/mcp-in.json" >/dev/null 2>&1
unp=$(jq -r '[.services[] | select(any(.properties[]; .name == "bomlens:ai:reviewReason" and .value == "unpinned-package")) | .name] | sort | join(",")' "$T/bom.json")
[ "$unp" = "a,b,e" ] && pass "latest and a range are unpinned, exact versions are not" || fail "unpinned: $unp (expected a,b,e)"
# The tree's own .github/instructions is a link out of the tree: nothing is read through it.
if jq -e '[.components[]? | select(any(.properties[]?; .name == "bomlens:ai:path" and (.value | startswith(".github/instructions"))))] | length == 0' "$T/bom.json" >/dev/null; then
    pass "an instruction folder linked out of the tree is not read"
else
    fail "a file outside the tree was recorded through a link"
fi

echo "== the reports leave AI usage out =="
bash "$LIB/validate-sbom.sh" "$WORK/main.json" "$WORK/c-main" x >/dev/null 2>&1
bash "$LIB/validate-sbom.sh" "$B" "$WORK/c-ai" x >/dev/null 2>&1
if [ -f "$WORK/c-ai_conformance.json" ] && diff <(jq -S '.checks' "$WORK/c-main_conformance.json") <(jq -S '.checks' "$WORK/c-ai_conformance.json") >/dev/null; then
    pass "conformance checks are the same with and without AI usage"
else
    fail "conformance checks changed"
fi
jq -e '[.checks[] | tostring | test("G7")] | any | not' "$WORK/c-ai_conformance.json" >/dev/null 2>&1 \
    && pass "no G7 checks for a model the code only calls" || fail "G7 checks were added"
bash "$LIB/generate-notice.sh" "$B" "$WORK/n" x >/dev/null 2>&1
if [ -f "$WORK/n_NOTICE.txt" ] && ! grep -qE "gpt-4o|Llama|AGENTS|mcp\.json" "$WORK/n_NOTICE.txt"; then
    pass "NOTICE lists no AI usage item"
else
    fail "NOTICE lists AI usage items or was not written"
fi
cp "$B" "$WORK/assess.json"
bash "$LIB/assess-ai-risk.sh" "$WORK/assess.json" >/dev/null 2>&1
jq -e '[.components[] | .properties[]? | select(.name | startswith("bomlens:assessment:"))] | length == 0' "$WORK/assess.json" >/dev/null \
    && pass "the AI risk assessment does not judge a model the code only calls" || fail "usage-detected model was assessed"

echo "== wiring =="
grep -q 'opted_out "${BOMLENS_NO_AI_USAGE:-}"' "$LIB/build-prep.sh" && pass "BOMLENS_NO_AI_USAGE turns the pass off" || fail "opt-out missing"
grep -q 'BOMLENS_NO_AI_USAGE BOMLENS_AI_USAGE_TIMEOUT' "$LIB/source-detect.sh" && pass "both settings reach the cdxgen container" \
    || fail "settings not in BUILD_PREP_ENV_NAMES"

echo
echo "AI usage: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
