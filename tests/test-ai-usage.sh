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

echo "== hub lookup of the referenced models (resolve-models.py) =="
RM="$LIB/resolve-models.py"
cp -R "$ROOT_DIR/tests/fixtures/hf-models" "$WORK/hub"
HUB="file://$WORK/hub"
# The scan's own SBOM: the fixture's two models, plus one the hub has no record of.
base_in() {
    jq '.components += [{"type":"machine-learning-model","bom-ref":"pkg:huggingface/acme/gone","name":"gone",
        "purl":"pkg:huggingface/acme/gone","properties":[{"name":"bomlens:ai:usage","value":"model"}]}]' "$B" > "$1"
}
R="$WORK/resolved.json"
base_in "$R"
BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$R" 2>"$WORK/rm.log"; rc=$?
[ "$rc" = "0" ] && pass "every lookup got an answer, exit 0" || fail "exit $rc" "$(cat "$WORK/rm.log")"
rp() { jq -r --arg n "$1" --arg k "$2" '.components[] | select(.name == $n) | [.properties[]? | select(.name == $k) | .value] | join(",")' "$R"; }
[ "$(rp Llama-3.1-8B-Instruct bomlens:ai:resolved)" = "huggingface" ] && pass "a hub model the hub answered for is marked resolved" || fail "Llama resolved: $(rp Llama-3.1-8B-Instruct bomlens:ai:resolved)"
[ "$(jq -r '.components[] | select(.name == "Llama-3.1-8B-Instruct") | .licenses[0].license.name' "$R")" = "llama3.1" ] \
    && pass "the licence is the card's tag, as written" || fail "licence"
[ "$(rp Llama-3.1-8B-Instruct bomlens:hf:gated)" = "manual" ] && pass "gated state recorded" || fail "gated"
[ "$(rp Llama-3.1-8B-Instruct bomlens:weights:formats)" = "bin,safetensors" ] && [ "$(rp Llama-3.1-8B-Instruct bomlens:weights:pickleFiles)" = "1" ] \
    && pass "weight formats and the pickle count recorded" || fail "weights: $(rp Llama-3.1-8B-Instruct bomlens:weights:formats) / $(rp Llama-3.1-8B-Instruct bomlens:weights:pickleFiles)"
[ "$(rp Llama-3.1-8B-Instruct bomlens:weights:file | tr ',' '\n' | grep -c .)" = "3" ] \
    && pass "a digest per LFS weight file, none for files the hub holds no digest for" || fail "weight digests"
[ "$(rp Llama-3.1-8B-Instruct bomlens:lineage:chain)" = "meta-llama/Llama-3.1-8B:llama3.1 > acme/loop-a:apache-2.0" ] \
    && pass "base-model chain walked and stopped at a loop" || fail "chain: $(rp Llama-3.1-8B-Instruct bomlens:lineage:chain)"
jq -e '.components[] | select(.name == "Llama-3.1-8B-Instruct") | .externalReferences | any(.type == "website" and .url == "https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct")' "$R" >/dev/null \
    && pass "link to the model's hub page" || fail "hub page link"
[ "$(rp gone bomlens:ai:resolved)" = "unreadable" ] && [ "$(rp gone bomlens:ai:resolvedStatus)" = "404" ] \
    && pass "a model the hub has no record of is marked unreadable with the status, nothing guessed" || fail "gone: $(rp gone bomlens:ai:resolved)"
[ "$(jq -r '.components[] | select(.name == "gone") | .licenses // "none"' "$R")" = "none" ] && pass "no licence is invented for it" || fail "gone got a licence"
[ "$(rp gpt-4o bomlens:ai:resolved)" = "" ] && pass "a hosted model with no hub page is left alone" || fail "gpt-4o was touched"

# Running it again changes nothing.
cp "$R" "$WORK/resolved-1.json"
BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$R" 2>/dev/null
diff -q <(jq -S . "$WORK/resolved-1.json") <(jq -S . "$R") >/dev/null && pass "a second run leaves the SBOM as it was" || fail "second run changed the SBOM"

# The token is never written down.
RT="$WORK/token.json"; base_in "$RT"
HF_TOKEN="hf_fixture_token_value" BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$RT" 2>"$WORK/rm-token.log"
if grep -q "hf_fixture_token_value" "$RT" "$WORK/rm-token.log"; then fail "HF_TOKEN reached the SBOM or the log"; else pass "HF_TOKEN stays out of the SBOM and the log"; fi

echo "== the hub cannot be reached, or too many models =="
U="$WORK/unreachable.json"
jq 'del(.components[] | select(.type == "machine-learning-model")) | .components += ["a/one","a/two","a/three"] | .components |= map(if type == "string" then
      {"type":"machine-learning-model","bom-ref":("pkg:huggingface/" + .),"name":(split("/")[1]),"purl":("pkg:huggingface/" + .),
       "properties":[{"name":"bomlens:ai:usage","value":"model"}]} else . end)' "$B" > "$U"
BOMLENS_HF_API_BASE="http://127.0.0.1:9" python3 "$RM" "$U" 2>"$WORK/rm-u.log"; rc=$?
[ "$rc" = "3" ] && pass "unreachable hub: exit 3, so the step is recorded as degraded" || fail "unreachable exit $rc"
ur=$(jq -r '[.components[] | select(.name == "one" or .name == "two" or .name == "three") | [.properties[] | select(.name == "bomlens:ai:resolved") | .value][0]] | join(",")' "$U")
[ "$ur" = "unreachable,unreachable,not-attempted" ] && pass "it stops asking after two silent answers" || fail "states: $ur"
L="$WORK/limit.json"; base_in "$L"
MODEL_RESOLVE_MAX=1 BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$L" 2>/dev/null
[ "$(jq -r '[.components[] | select(.type == "machine-learning-model") | [.properties[]? | select(.name == "bomlens:ai:resolved") | .value][0] // "-"] | join(",")' "$L")" = "-,huggingface,not-attempted" ] \
    && pass "MODEL_RESOLVE_MAX bounds the lookups; the rest are marked not-attempted" || fail "limit: $(jq -c '[.components[] | select(.type == "machine-learning-model") | .name]' "$L")"
NONE="$WORK/none.json"; jq 'del(.components[] | select(.type == "machine-learning-model"))' "$B" > "$NONE"
BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$NONE" 2>/dev/null; [ "$?" = "0" ] && pass "no model referenced: nothing to look up, exit 0" || fail "no-model exit"

echo "== busy hub, base-model conflict, one-segment ids, malformed model SBOMs =="
BUSY="$WORK/hub-busy"; cp -R "$WORK/hub" "$BUSY"; printf '{ "__status": 503 }\n' > "$BUSY/models/meta-llama/Llama-3.1-8B-Instruct.json"
V="$WORK/busy.json"; base_in "$V"
BOMLENS_HF_API_BASE="file://$BUSY" python3 "$RM" "$V" 2>/dev/null; rc=$?
[ "$rc" = "3" ] && [ "$(jq -r '.components[] | select(.name == "Llama-3.1-8B-Instruct") | [.properties[] | select(.name == "bomlens:ai:resolved" or .name == "bomlens:ai:resolvedStatus") | .value] | join(",")' "$V")" = "unreachable,503" ] \
    && pass "a 503 or 429 from the hub is a hub problem (unreachable, exit 3), not an unreadable model" || fail "busy hub: rc=$rc"
# A fine-tune under an open licence whose base model passes its terms on.
FT="$WORK/hub-ft"; cp -R "$WORK/hub" "$FT"; mkdir -p "$FT/models/acme"
printf '{ "id": "acme/tuned", "cardData": { "license": "apache-2.0", "base_model": "meta-llama/Llama-3.1-8B" }, "siblings": [] }\n' > "$FT/models/acme/tuned.json"
jq -n '{bomFormat:"CycloneDX", specVersion:"1.6", components:[{type:"machine-learning-model","bom-ref":"t",name:"tuned",purl:"pkg:huggingface/acme/tuned",properties:[{name:"bomlens:ai:usage",value:"model"}]}]}' > "$WORK/ft.json"
BOMLENS_HF_API_BASE="file://$FT" python3 "$RM" "$WORK/ft.json" 2>/dev/null
[ "$(jq -r '.components[0] | [.properties[] | select(.name == "bomlens:lineage:conflict") | .value][0]' "$WORK/ft.json")" = "true" ] \
    && pass "a base model whose licence passes on to derivatives is recorded as a conflict" || fail "no lineage conflict recorded"
cp "$WORK/ft.json" "$WORK/ft-verdict.json"; bash "$LIB/assess-ai-risk.sh" "$WORK/ft-verdict.json" >/dev/null 2>&1
[ "$(jq -r '.components[0] | [.properties[] | select(.name == "bomlens:assessment:overall") | .value][0]' "$WORK/ft-verdict.json")" = "caution" ] \
    && pass "the verdict reads that conflict (caution), as for a scanned model" || fail "verdict ignores the conflict"
# One-segment hub ids (gpt2).
mkdir -p "$WORK/hub/models"; printf '{ "id": "gpt2", "cardData": { "license": "mit" }, "siblings": [] }\n' > "$WORK/hub/models/gpt2.json"
jq -n '{bomFormat:"CycloneDX", specVersion:"1.6", components:[{type:"machine-learning-model","bom-ref":"g",name:"gpt2",purl:"pkg:huggingface/gpt2",properties:[{name:"bomlens:ai:usage",value:"model"}]}]}' > "$WORK/gpt2.json"
BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$WORK/gpt2.json" 2>/dev/null
[ "$(jq -r '.components[0] | [.properties[] | select(.name == "bomlens:ai:resolved") | .value][0]' "$WORK/gpt2.json")" = "resolved" ] || \
  [ "$(jq -r '.components[0] | [.properties[] | select(.name == "bomlens:ai:resolved") | .value][0]' "$WORK/gpt2.json")" = "huggingface" ] \
    && pass "a one-segment hub id (gpt2) is looked up" || fail "gpt2 not resolved"
# A model SBOM of an unexpected shape costs its own link, never the lookups.
for bad in '{"bomFormat":"CycloneDX","components":5}' '{"bomFormat":"CycloneDX","serialNumber":5,"components":[{"type":"machine-learning-model","bom-ref":7,"purl":5}]}' \
           '{"bomFormat":"CycloneDX","serialNumber":"urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79","version":true,"components":[{"type":"machine-learning-model","bom-ref":"m","name":"meta-llama/Llama-3.1-8B-Instruct"}]}'; do
    printf '%s\n' "$bad" > "$WORK/bad_bom.json"; M="$WORK/bad-case.json"; base_in "$M"
    BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$M" "$WORK/bad_bom.json" 2>/dev/null; rc=$?
    [ "$rc" = "0" ] && [ "$(jq -r '.components[] | select(.name == "Llama-3.1-8B-Instruct") | [.properties[] | select(.name == "bomlens:ai:resolved") | .value][0]' "$M")" = "huggingface" ] \
        && pass "malformed model SBOM ($(printf '%s' "$bad" | cut -c1-45)...): lookups still written" || fail "malformed model SBOM lost the lookups (rc=$rc)"
done
jq -e '.components[] | select(.name == "Llama-3.1-8B-Instruct") | .externalReferences[] | select(.type == "bom") | .url | endswith("/1#m")' "$M" >/dev/null \
    && pass "version: true is not a version (the link uses 1)" || fail "boolean version"
# The base-model lookups count against the time budget.
BUD="$WORK/budget.json"; base_in "$BUD"
MODEL_RESOLVE_BUDGET=1 BOMLENS_HF_API_BASE="$HUB" python3 -c "
import time, runpy, sys
sys.argv = ['x', '$BUD']
import importlib.util
spec = importlib.util.spec_from_file_location('rm', '$RM'); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
orig = m.hf_dataset.fetch_model
def slow(*a, **k):
    time.sleep(1.2); return orig(*a, **k)
m.hf_dataset.fetch_model = slow
sys.exit(m.main(sys.argv))" 2>/dev/null; rc=$?
[ "$rc" = "3" ] && pass "a spent time budget marks the models not reached not-attempted (exit 3)" || fail "budget: rc=$rc"
# Running it again after the hub started answering differently leaves nothing of the old answer.
AGAIN="$WORK/again.json"; base_in "$AGAIN"
BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$AGAIN" 2>/dev/null
BOMLENS_HF_API_BASE="file://$BUSY" python3 "$RM" "$AGAIN" 2>/dev/null
jq -e '.components[] | select(.name == "Llama-3.1-8B-Instruct") | (.licenses == null) and ([.properties[] | select(.name | startswith("bomlens:weights:") or startswith("bomlens:lineage:"))] | length == 0) and ([.externalReferences[]? | select(.type == "website")] | length == 0)' "$AGAIN" >/dev/null \
    && pass "a changed answer replaces the earlier one instead of sitting beside it" || fail "stale facts survived a second run"

echo "== linking a model's own SBOM =="
modelsbom() {  # modelsbom <file> <serial or empty> <purl>
    jq -n --arg serial "$2" --arg purl "$3" '{bomFormat:"CycloneDX", specVersion:"1.7"}
        + (if $serial == "" then {} else {serialNumber: $serial} end)
        + {version: 2, metadata:{component:{"bom-ref":"scan-job", type:"application", name:"job"}},
           components:[{type:"machine-learning-model","bom-ref":"model-ref/1", name:"Llama-3.1-8B-Instruct", purl:$purl}]}' > "$1"
}
MS="$WORK/llama_1.0_bom.json"
modelsbom "$MS" "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" "pkg:huggingface/meta-llama/Llama-3.1-8B-Instruct@0e9e39f"
K="$WORK/linked.json"; base_in "$K"
MODEL_SBOM_LABELS="my llama.json" BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$K" "$MS" 2>"$WORK/rm-link.log"
link=$(jq -r '.components[] | select(.name == "Llama-3.1-8B-Instruct") | .externalReferences[] | select(.type == "bom") | .url' "$K")
[ "$link" = "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/2#model-ref%2F1" ] && pass "BOM-Link: urn:cdx:<serial>/<version>#<bom-ref, percent-encoded>" || fail "link: $link"
[ "$(jq -r '.components[] | select(.name == "Llama-3.1-8B-Instruct") | [.properties[] | select(.name == "bomlens:ai:modelSbom") | .value][0]' "$K")" = "my llama.json" ] \
    && pass "the link carries the name the user gave the file, not the mount name" || fail "label"
NOSER="$WORK/noserial_bom.json"; modelsbom "$NOSER" "" "pkg:huggingface/meta-llama/Llama-3.1-8B-Instruct"
K2="$WORK/linked2.json"; base_in "$K2"
BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$K2" "$NOSER" 2>"$WORK/rm-link2.log"
jq -e '[.components[] | .externalReferences[]? | select(.type == "bom")] | length == 0' "$K2" >/dev/null && grep -q "no serial number" "$WORK/rm-link2.log" \
    && pass "a model SBOM with no serial number is reported and not linked" || fail "no-serial case"
OTHER="$WORK/other_bom.json"; modelsbom "$OTHER" "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" "pkg:huggingface/someone/else-model"
K3="$WORK/linked3.json"; base_in "$K3"
BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$K3" "$OTHER" 2>"$WORK/rm-link3.log"
jq -e '[.components[] | .externalReferences[]? | select(.type == "bom")] | length == 0' "$K3" >/dev/null && grep -q "does not reference" "$WORK/rm-link3.log" \
    && pass "a model SBOM for a model the code does not reference is reported and not linked" || fail "other-model case"
echo '{"not":"cyclonedx"}' > "$WORK/junk.json"
K4="$WORK/linked4.json"; base_in "$K4"
BOMLENS_HF_API_BASE="$HUB" python3 "$RM" "$K4" "$WORK/junk.json" 2>"$WORK/rm-link4.log"; [ "$?" = "0" ] && grep -q "not a CycloneDX" "$WORK/rm-link4.log" \
    && pass "a file that is not CycloneDX is reported, the scan goes on" || fail "junk case"

echo "== the verdict, and what stays out =="
cp "$R" "$WORK/verdict.json"
bash "$LIB/assess-ai-risk.sh" "$WORK/verdict.json" >/dev/null 2>&1
av() { jq -r --arg n "$1" '.components[] | select(.name == $n) | [.properties[]? | select(.name == "bomlens:assessment:overall") | .value][0] // "none"' "$WORK/verdict.json"; }
[ "$(av Llama-3.1-8B-Instruct)" = "conditional" ] && pass "a model the hub answered for is judged on its licence and weight files" || fail "Llama verdict: $(av Llama-3.1-8B-Instruct)"
[ "$(av gpt-4o)" = "none" ] && [ "$(av gone)" = "none" ] && pass "a hosted model, and one the hub could not read, get no verdict" || fail "gpt-4o: $(av gpt-4o), gone: $(av gone)"
bash "$LIB/validate-sbom.sh" "$WORK/verdict.json" "$WORK/c-res" x >/dev/null 2>&1
diff -q <(jq -S '.checks' "$WORK/c-main_conformance.json") <(jq -S '.checks' "$WORK/c-res_conformance.json") >/dev/null \
    && pass "the conformance checks still leave resolved models out (no G7 for a summary)" || fail "conformance changed with resolved models"

echo "== wiring =="
grep -q 'opted_out "${BOMLENS_NO_AI_USAGE:-}"' "$LIB/build-prep.sh" && pass "BOMLENS_NO_AI_USAGE turns the pass off" || fail "opt-out missing"
grep -q 'BOMLENS_NO_AI_USAGE BOMLENS_AI_USAGE_TIMEOUT' "$LIB/source-detect.sh" && pass "both settings reach the cdxgen container" \
    || fail "settings not in BUILD_PREP_ENV_NAMES"
grep -q 'MODEL_RESOLVE=%s' "$ROOT_DIR/scripts/scan-sbom.sh" && grep -q 'resolve-models python3' "$ROOT_DIR/docker/entrypoint.sh" \
    && pass "--resolve-models reaches the resolve-models step" || fail "resolve-models wiring missing"

echo
echo "AI usage: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
