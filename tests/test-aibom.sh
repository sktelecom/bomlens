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

echo "== scan-aibom.sh forwards HF_TOKEN without leaking it =="
# A private/gated model resolves only when huggingface_hub finds HF_TOKEN in the
# environment, so the variable must reach the generator untouched. It must never
# reach the logs: this mock records what it received, and the same run's combined
# output is then searched for the value.
HF_SENTINEL="hf_sentinel_do_not_leak_9f3a"
cat > "$WORK/bin/aibom" <<MOCK
#!/bin/bash
out=""; prev=""
for a in "\$@"; do [ "\$prev" = "--output" ] && out="\$a"; prev="\$a"; done
[ -n "\$out" ] || exit 1
printf '%s' "\${HF_TOKEN:-<unset>}" > "$WORK/seen-token.txt"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "\$out"
cp "$FIX/aibom-owasp-1_7.json" "\${out%.json}_1_7.json"
exit 0
MOCK
chmod +x "$WORK/bin/aibom"
if HF_TOKEN="$HF_SENTINEL" PATH="$WORK/bin:$PATH" \
   bash "$LIB/scan-aibom.sh" "my-org/private-llm" "$WORK/tok.json" "1.0.0" \
   > "$WORK/tok.log" 2>&1; then
    seen=$(cat "$WORK/seen-token.txt" 2>/dev/null)
    [ "$seen" = "$HF_SENTINEL" ] \
        && pass "HF_TOKEN reaches the generator unchanged" \
        || fail "HF_TOKEN reaches the generator unchanged" "generator saw '$seen'"
    if grep -qF "$HF_SENTINEL" "$WORK/tok.log"; then
        fail "scan-aibom.sh keeps HF_TOKEN out of its output" "the token appears in the log"
    else
        pass "scan-aibom.sh keeps HF_TOKEN out of its output"
    fi
    grep -q "HuggingFace auth: enabled" "$WORK/tok.log" \
        && pass "scan-aibom.sh reports the auth state without the value" \
        || fail "scan-aibom.sh reports the auth state without the value" "no auth line in the log"
else
    fail "scan-aibom.sh runs with HF_TOKEN set" "exited non-zero against the mock generator"
fi

echo "== scan-aibom.sh refuses a fabricated card when the model could not be read =="
# The real failure mode observed against HuggingFace: the generator's fetch gets a
# 401, it logs a warning, returns empty metadata, and then fills the card with
# generic defaults — "transformer", "text-generation", string in/out. The result
# is a well-formed ML-BOM with a NON-empty modelCard describing nothing, which
# sails past the card-present gate and yields a conformance report that reads as
# a pass. This mock reproduces that shape exactly: warning on stderr, exit 0,
# plausible card.
cat > "$WORK/bin/aibom" <<MOCK
#!/bin/bash
out=""; prev=""
for a in "\$@"; do [ "\$prev" = "--output" ] && out="\$a"; prev="\$a"; done
[ -n "\$out" ] || exit 1
mid=""
for a in "\$@"; do case "\$a" in -*) ;; *) [ -z "\$mid" ] && mid="\$a" ;; esac; done
echo "Error fetching model info for \$mid: 401 Client Error." >&2
echo "Error fetching model card for \$mid: 401 Client Error." >&2
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "\$out"
cat > "\${out%.json}_1_7.json" <<'STUB'
{"bomFormat":"CycloneDX","specVersion":"1.7","components":[{"type":"machine-learning-model","name":"private-test-model","modelCard":{"modelParameters":{"modelArchitecture":"transformer","task":"text-generation"}}}]}
STUB
exit 0
MOCK
chmod +x "$WORK/bin/aibom"
if PATH="$WORK/bin:$PATH" bash "$LIB/scan-aibom.sh" "my-org/private-test-model" "$WORK/fake.json" "1.0.0" \
   > "$WORK/fake.log" 2>&1; then
    fail "scan-aibom.sh refuses a fabricated model card" "exited 0 on an unreadable model"
elif [ -f "$WORK/fake.json" ]; then
    fail "scan-aibom.sh refuses a fabricated model card" "left the fabricated SBOM behind"
else
    pass "scan-aibom.sh refuses a fabricated model card and leaves no artifact"
fi
grep -q "placeholder values" "$WORK/fake.log" \
    && pass "the refusal says the values were placeholders, not the model" \
    || fail "the refusal explains itself" "no placeholder wording in the message"
# 401 with no credential must point at HF_TOKEN; the same 401 with one must not.
grep -q "no credential was supplied" "$WORK/fake.log" \
    && pass "an unauthenticated 401 points at HF_TOKEN" \
    || fail "an unauthenticated 401 points at HF_TOKEN" "hint missing"
HF_TOKEN="$HF_SENTINEL" PATH="$WORK/bin:$PATH" \
    bash "$LIB/scan-aibom.sh" "my-org/private-test-model" "$WORK/fake2.json" "1.0.0" \
    > "$WORK/fake2.log" 2>&1 || true
if grep -q "despite a credential" "$WORK/fake2.log" && ! grep -qF "$HF_SENTINEL" "$WORK/fake2.log"; then
    pass "an authenticated 401 says the token lacks access, without echoing it"
else
    fail "an authenticated 401 says the token lacks access" "wrong hint or the token leaked"
fi
# A model that IS readable must still pass: no warning line, real card kept.
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
if PATH="$WORK/bin:$PATH" bash "$LIB/scan-aibom.sh" "google-bert/bert-base-uncased" "$WORK/ok.json" "1.0.0" >/dev/null 2>&1; then
    pass "a readable model is still accepted (the new gate does not over-reject)"
else
    fail "a readable model is still accepted" "the new gate rejected a good run"
fi

echo "== the card-less failure hint depends on whether a token was supplied =="
# Same degraded stub as above. Anonymous and authenticated runs fail for
# different reasons (no credential vs. no access), so they must say so — and
# neither may echo the token.
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
env -u HF_TOKEN PATH="$WORK/bin:$PATH" \
    bash "$LIB/scan-aibom.sh" "my-org/private-llm" "$WORK/anon.json" "1.0.0" \
    > "$WORK/anon.log" 2>&1 || true
HF_TOKEN="$HF_SENTINEL" PATH="$WORK/bin:$PATH" \
    bash "$LIB/scan-aibom.sh" "my-org/private-llm" "$WORK/auth.json" "1.0.0" \
    > "$WORK/auth.log" 2>&1 || true
if grep -q "set HF_TOKEN" "$WORK/anon.log" && ! grep -q "set HF_TOKEN" "$WORK/auth.log"; then
    pass "the anonymous failure names HF_TOKEN and the authenticated one does not"
else
    fail "the anonymous failure names HF_TOKEN and the authenticated one does not" \
         "anon/auth hints did not differ as expected"
fi
if grep -qF "$HF_SENTINEL" "$WORK/auth.log"; then
    fail "the authenticated failure hint hides the token" "the token appears in the log"
else
    pass "the authenticated failure hint hides the token"
fi

echo "== generate-notice.sh lists the model license =="
bash "$LIB/generate-notice.sh" "$WORK/a.json" "$WORK/notice" "bert-base-uncased" >/dev/null 2>&1
NOTICE="$WORK/notice_NOTICE.txt"
if [ -f "$NOTICE" ] && grep -q "Apache-2.0" "$NOTICE"; then
    pass "NOTICE lists Apache-2.0"
else
    fail "NOTICE missing or has no Apache-2.0 entry"
fi

echo "== validate-sbom.sh adds registry-driven G7 minimum-element checks =="
bash "$LIB/validate-sbom.sh" "$FIX/aibom-owasp-1_7.json" "$WORK/conf" "bert-base-uncased" >/dev/null 2>&1
CONF="$WORK/conf_conformance.json"
if [ -f "$CONF" ]; then
    # The registry maps the full G7 set (7 clusters, 50 elements + an openness
    # facet), so expect the whole checklist, not just the six model checks.
    g7n=$(jq '[.checks[] | select(.id|startswith("g7-"))] | length' "$CONF")
    [ "$g7n" -ge 40 ] && pass "full G7 checklist present ($g7n checks)" || fail "expected >=40 G7 checks, got $g7n"
    # Every G7 check carries a cluster and a data source (the new schema fields).
    clusters=$(jq -r '[.checks[] | select(.id|startswith("g7-")) | .cluster] | unique | length' "$CONF")
    [ "$clusters" -ge 7 ] && pass "G7 checks span the 7 clusters ($clusters)" || fail "expected 7 clusters, got $clusters"
    srcset=$(jq -r '[.checks[] | select(.id|startswith("g7-")) | .source] | unique | sort | join(",")' "$CONF")
    echo "$srcset" | grep -q "auto" && echo "$srcset" | grep -q "na" && pass "G7 checks tag data source (auto..na: $srcset)" || fail "G7 source tags missing (got '$srcset')"

    licst=$(jq -r '.checks[] | select(.id=="g7-model-license") | .status' "$CONF")
    [ "$licst" = "pass" ] && pass "g7-model-license passes (Apache-2.0 present)" || fail "g7-model-license='$licst', expected pass"
    # Passing checks carry the actual SBOM values as evidence ("met with these").
    licev=$(jq -r '.checks[] | select(.id=="g7-model-license") | (.evidence // []) | join(",")' "$CONF")
    echo "$licev" | grep -q "Apache-2.0" && pass "g7-model-license evidence shows Apache-2.0" || fail "g7-model-license evidence='$licev', expected Apache-2.0"
    liccl=$(jq -r '.checks[] | select(.id=="g7-model-license") | .cluster' "$CONF")
    [ "$liccl" = "models" ] && pass "g7-model-license grouped under the models cluster" || fail "g7-model-license cluster='$liccl', expected models"
    idev=$(jq -r '.checks[] | select(.id=="g7-model-id") | (.evidence // []) | length' "$CONF")
    [ "$idev" -ge 1 ] && pass "g7-model-id carries evidence (the PURL/CPE)" || fail "g7-model-id evidence is empty"

    # Before enrichment the fixture has no hashes / no openness props, so these
    # auto/inferred model checks warn (integrity + openness gaps, surfaced honestly).
    hashst=$(jq -r '.checks[] | select(.id=="g7-model-hash-value") | .status' "$CONF")
    [ "$hashst" = "warn" ] && pass "g7-model-hash-value warns pre-enrich (integrity gap)" || fail "g7-model-hash-value='$hashst', expected warn"
    openst=$(jq -r '.checks[] | select(.id=="g7-model-openness") | .status' "$CONF")
    [ "$openst" = "warn" ] && pass "g7-model-openness warns pre-enrich (not assessed)" || fail "g7-model-openness='$openst', expected warn"

    # Clusters with no automated source (system data flow, KPI, …) are surfaced as
    # review items (source=na, warn), never silently dropped or faked as pass.
    naflow=$(jq -r '.checks[] | select(.id=="g7-slp-data-flow") | "\(.source)/\(.status)"' "$CONF")
    [ "$naflow" = "na/warn" ] && pass "g7-slp-data-flow marked review (na/warn)" || fail "g7-slp-data-flow='$naflow', expected na/warn"

    # G7 checks are advisory: they must not flip the overall result to fail.
    res=$(jq -r '.result' "$CONF")
    [ "$res" != "fail" ] && pass "advisory G7 warnings do not fail the overall result" || fail "overall result is fail; G7 should be warn-only"
else
    fail "validate-sbom.sh did not produce a conformance report"
fi

echo "== enrichment flips the model integrity + openness checks to pass =="
# enrich-aibom.sh injects LFS SHA-256 hashes and openness:* properties from the
# HuggingFace API; that path needs the network, so here we simulate its output
# (inject a hash + openness props) and confirm the G7 evaluator then passes them.
jq '(.components[] | select(.type=="machine-learning-model")) |= (
      .hashes = [{"alg":"SHA-256","content":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}]
      | .properties = ((.properties // []) + [
          {"name":"openness:weights","value":"open-weight"},
          {"name":"openness:training-data","value":"open-data"}
        ]))' "$FIX/aibom-owasp-1_7.json" > "$WORK/enriched.json"
bash "$LIB/validate-sbom.sh" "$WORK/enriched.json" "$WORK/conf2" "bert-base-uncased" >/dev/null 2>&1
CONF2="$WORK/conf2_conformance.json"
hv=$(jq -r '.checks[] | select(.id=="g7-model-hash-value") | .status' "$CONF2")
ha=$(jq -r '.checks[] | select(.id=="g7-model-hash-alg") | .status' "$CONF2")
op=$(jq -r '.checks[] | select(.id=="g7-model-openness") | .status' "$CONF2")
{ [ "$hv" = "pass" ] && [ "$ha" = "pass" ]; } && pass "model integrity checks pass after enrichment" || fail "hash-value='$hv' hash-alg='$ha', expected pass"
[ "$op" = "pass" ] && pass "model openness check passes after enrichment" || fail "g7-model-openness='$op', expected pass"

echo "== per-model coverage: one non-compliant model in a multi-model SBOM is named =="
# ANY-model presence would hide the unlicensed second model; the registry's
# missingPath semantics must warn and list it (old cov() behavior).
jq '.components += [{"type":"machine-learning-model","name":"m2","version":"1"}]' \
    "$FIX/aibom-owasp-1_7.json" > "$WORK/multi.json"
bash "$LIB/validate-sbom.sh" "$WORK/multi.json" "$WORK/conf3" "multi" >/dev/null 2>&1
mm=$(jq -r '.checks[] | select(.id=="g7-model-license") | "\(.status)|\(.detail)|\(.missing|join(","))"' "$WORK/conf3_conformance.json")
case "$mm" in
    "warn|1/2 model component(s)|m2") pass "multi-model license gap warns with the offender named" ;;
    *) fail "g7-model-license on 2 models = '$mm', expected warn|1/2 model component(s)|m2" ;;
esac

echo "== a broken registry fails loudly, not silently =="
# A jq syntax error in one cdxPath must not silently drop the G7 section: the
# evaluator warns on stderr and the base checks + overall result survive.
sed 's/length > 0/length >(BROKEN/' "$LIB/g7-registry.json" > "$WORK/broken-reg.json"
BRLOG=$(G7_REGISTRY="$WORK/broken-reg.json" bash "$LIB/validate-sbom.sh" "$FIX/aibom-owasp-1_7.json" "$WORK/conf4" "broken" 2>&1)
grep -q "G7 registry evaluation failed" <<<"$BRLOG" && pass "broken registry warns on stderr" || fail "no loud warning for a broken registry"
bshape=$(jq -r '"g7=\([.checks[]|select(.id|startswith("g7-"))]|length) base=\([.checks[]|select(.id|startswith("g7-")|not)]|length) result=\(.result)"' "$WORK/conf4_conformance.json")
[ "$bshape" = "g7=0 base=11 result=pass" ] && pass "base checks and result survive a broken registry" || fail "report shape '$bshape' after broken registry"

echo "== legacy CycloneDX tools array does not false-negative the tool checks =="
# metadata.tools as a bare array (pre-1.5 shape) used to hard-error inside the
# expression and read as "not present" while the base tools check passed.
jq '.metadata.tools = [{"name":"syft","version":"1.0"}]' "$FIX/aibom-owasp-1_7.json" > "$WORK/legacy.json"
bash "$LIB/validate-sbom.sh" "$WORK/legacy.json" "$WORK/conf5" "legacy" >/dev/null 2>&1
tl=$(jq -r '[.checks[] | select(.id=="g7-meta-tool-name" or .id=="g7-meta-tool-version") | .status] | unique | join(",")' "$WORK/conf5_conformance.json")
[ "$tl" = "pass" ] && pass "legacy tools array satisfies tool name/version" || fail "tool checks on legacy array = '$tl', expected pass"

echo "== prose openness declarations still count (supplier SBOM without openness:* props) =="
jq '(.components[]|select(.type=="machine-learning-model")).description = "Open-weight model trained on open data." | del(.components[].properties)' \
    "$FIX/aibom-owasp-1_7.json" > "$WORK/prose.json"
bash "$LIB/validate-sbom.sh" "$WORK/prose.json" "$WORK/conf6" "prose" >/dev/null 2>&1
po=$(jq -r '.checks[] | select(.id=="g7-model-openness") | .status' "$WORK/conf6_conformance.json")
[ "$po" = "pass" ] && pass "prose openness declaration passes (no property convention required)" || fail "g7-model-openness on prose = '$po', expected pass"

echo "== ref-only dataset references count as dataset names =="
jq '(.components[]|select(.type=="machine-learning-model")).modelCard.modelParameters.datasets = [{"ref":"dataset-a"},{"ref":"dataset-b"}]' \
    "$FIX/aibom-owasp-1_7.json" > "$WORK/refds.json"
bash "$LIB/validate-sbom.sh" "$WORK/refds.json" "$WORK/conf7" "refds" >/dev/null 2>&1
ds=$(jq -r '.checks[] | select(.id=="g7-ds-name") | "\(.status)|\(.evidence|join(","))"' "$WORK/conf7_conformance.json")
case "$ds" in
    pass*dataset-a*) pass "ref-only dataset references pass with the refs as evidence" ;;
    *) fail "g7-ds-name on ref-only datasets = '$ds', expected pass with dataset-a evidence" ;;
esac

echo "== human reports separate review items from warnings =="
# na (no automated source) elements must not inflate the warning count; the MD
# headline carries a distinct "needs review" figure.
grep -q "needs review:" "$WORK/conf_conformance.md" && pass "MD headline carries a needs-review count" || fail "MD headline lacks needs review"
nw=$(jq '[.checks[] | select(.status=="warn" and .source!="na")] | length' "$CONF")
hw=$(grep -o 'warnings: [0-9]*' "$WORK/conf_conformance.md" | grep -o '[0-9]*')
[ "$hw" = "$nw" ] && pass "MD warning count excludes review items ($hw)" || fail "MD warnings=$hw, expected $nw (na excluded)"
grep -q "Needs review:" "$WORK/conf_conformance.html" && pass "HTML report carries a needs-review pill" || fail "HTML lacks the needs-review pill"

echo "== 2-layer merge keeps the ML-BOM root (1.7 + modelCard) and fills infrastructure =="
# A tiny application layer (one library + a dep edge) merged onto the model SBOM.
cat > "$WORK/app.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"component":{"type":"application","name":"serving-app","version":"1.0"}},
 "components":[{"type":"library","name":"flask","version":"3.0.0","purl":"pkg:pypi/flask@3.0.0","bom-ref":"flask"}],
 "dependencies":[{"ref":"serving-app","dependsOn":["flask"]}]}
JSON
MERGE_ROOT_FROM="$FIX/aibom-owasp-1_7.json" bash "$LIB/merge-sbom.sh" \
    "$WORK/merged.json" "combo" "1.0" "$FIX/aibom-owasp-1_7.json" "$WORK/app.json" >/dev/null 2>&1
mspec=$(jq -r '.specVersion' "$WORK/merged.json")
[ "$mspec" = "1.7" ] && pass "MERGE_ROOT_FROM preserves the ML-BOM specVersion 1.7 (not downgraded to 1.6)" || fail "merged specVersion='$mspec', expected 1.7"
# The preserved root must carry the CALLER's identity, not the generator's
# ephemeral job id (the OWASP root is named "job-<timestamp>").
mroot=$(jq -r '"\(.metadata.component.name)@\(.metadata.component.version)"' "$WORK/merged.json")
[ "$mroot" = "combo@1.0" ] && pass "preserved root renamed to the caller's project/version" || fail "merged root='$mroot', expected combo@1.0"
mcard=$(jq '[.components[] | select(.type=="machine-learning-model" and (.modelCard!=null))] | length' "$WORK/merged.json")
[ "$mcard" -ge 1 ] && pass "model component + modelCard survive the merge" || fail "modelCard lost in merge"
mflask=$(jq '[.components[] | select(.name=="flask")] | length' "$WORK/merged.json")
[ "$mflask" -ge 1 ] && pass "application software component merged in (infrastructure layer)" || fail "flask not merged"
bash "$LIB/validate-sbom.sh" "$WORK/merged.json" "$WORK/mconf" "combo" >/dev/null 2>&1
infra=$(jq -r '.checks[] | select(.id=="g7-infra-software") | .status' "$WORK/mconf_conformance.json")
[ "$infra" = "pass" ] && pass "g7-infra-software flips to pass on the merged BOM" || fail "g7-infra-software='$infra', expected pass"

echo "== regulation crosswalk: registry integrity =="
XW="$LIB/regulation-crosswalk.json"
jq empty "$XW" >/dev/null 2>&1 && pass "regulation-crosswalk.json is valid JSON" || fail "regulation-crosswalk.json is not valid JSON"
# Drift guard: every mapped element id must exist in the G7 registry, else the
# crosswalk has rotted against a renamed/removed element and would silently map
# nothing.
unknown=$(comm -23 <(jq -r '.map | keys[]' "$XW" | sort -u) \
                   <(jq -r '.clusters[].elements[].id' "$LIB/g7-registry.json" | sort -u))
[ -z "$unknown" ] && pass "every crosswalk element id exists in g7-registry.json" || fail "crosswalk maps unknown G7 element id(s)" "$unknown"
undecl=$(comm -23 <(jq -r '.map[][].framework' "$XW" | sort -u) \
                  <(jq -r '.frameworks | keys[]' "$XW" | sort -u))
[ -z "$undecl" ] && pass "every crosswalk framework is declared" || fail "crosswalk references undeclared framework(s)" "$undecl"
[ -n "$(jq -r '.disclaimer // ""' "$XW")" ] && pass "crosswalk carries a no-certification disclaimer" || fail "crosswalk lacks a disclaimer"

echo "== regulation crosswalk: surfaced in the AI conformance report =="
# $CONF is the AI-fixture conformance JSON from the G7 section above.
xwf=$(jq -r '.regulatoryCrosswalk.frameworks | length' "$CONF" 2>/dev/null)
[ "${xwf:-0}" -ge 1 ] && pass "AI conformance JSON has a regulatoryCrosswalk ($xwf framework(s))" || fail "regulatoryCrosswalk missing from AI conformance JSON"
regn=$(jq '[.checks[] | select((.regulations // []) | length > 0)] | length' "$CONF")
[ "$regn" -ge 1 ] && pass "G7 checks carry regulation refs ($regn tagged)" || fail "no G7 check carries regulations"
grep -q "Regulatory crosswalk" "$WORK/conf_conformance.md" && pass "MD carries the crosswalk section" || fail "MD lacks the crosswalk section"
grep -q "does not certify" "$WORK/conf_conformance.md" && pass "MD crosswalk states the no-certification disclaimer" || fail "MD lacks the disclaimer"
grep -q "Regulatory crosswalk" "$WORK/conf_conformance.html" && pass "HTML carries the crosswalk section" || fail "HTML lacks the crosswalk section"

echo "== regulation crosswalk: informational only (result + G7 count unchanged) =="
# Re-run with the crosswalk disabled (env points at a nonexistent file): the
# crosswalk must never add/remove a check or move the overall result.
REGULATION_CROSSWALK="$WORK/nope.json" bash "$LIB/validate-sbom.sh" "$FIX/aibom-owasp-1_7.json" "$WORK/confx" "x" >/dev/null 2>&1
r_with=$(jq -r '.result' "$CONF"); r_without=$(jq -r '.result' "$WORK/confx_conformance.json")
[ "$r_with" = "$r_without" ] && pass "result identical with/without the crosswalk ($r_with)" || fail "result changed: with=$r_with without=$r_without"
[ "$(jq 'has("regulatoryCrosswalk")' "$WORK/confx_conformance.json")" = "false" ] && pass "no crosswalk file -> no regulatoryCrosswalk (graceful)" || fail "regulatoryCrosswalk present despite disabled crosswalk"
g7_with=$(jq '[.checks[]|select(.id|startswith("g7-"))]|length' "$CONF")
g7_without=$(jq '[.checks[]|select(.id|startswith("g7-"))]|length' "$WORK/confx_conformance.json")
[ "$g7_with" = "$g7_without" ] && pass "G7 check count unchanged by the crosswalk ($g7_with)" || fail "G7 count differs: with=$g7_with without=$g7_without"

echo "== G7 fill-in guidance: registry integrity =="
GD="$LIB/g7-guidance.json"
jq empty "$GD" >/dev/null 2>&1 && pass "g7-guidance.json is valid JSON" || fail "g7-guidance.json is not valid JSON"
# Same drift guard as the crosswalk: guidance keyed by an element id that no
# longer exists would silently show nothing.
gunknown=$(comm -23 <(jq -r '.map | keys[]' "$GD" | sort -u) \
                    <(jq -r '.clusters[].elements[].id' "$LIB/g7-registry.json" | sort -u))
[ -z "$gunknown" ] && pass "every guidance element id exists in g7-registry.json" || fail "guidance maps unknown G7 element id(s)" "$gunknown"
badentry=$(jq -r '.map | to_entries[] | select((.value.snippet // "") == "" or ((.value.docUrl // "") | startswith("https://") | not)) | .key' "$GD")
[ -z "$badentry" ] && pass "every guidance entry has a snippet and an https doc URL" || fail "guidance entries are incomplete" "$badentry"

echo "== G7 fill-in guidance: surfaced in the AI conformance report =="
gn=$(jq '[.checks[] | select((.guidance.snippet // "") != "")] | length' "$CONF")
[ "$gn" -ge 1 ] && pass "G7 checks carry fill-in guidance ($gn tagged)" || fail "no G7 check carries guidance"
grep -q "How to fill the gaps" "$WORK/conf_conformance.md" && pass "MD carries the fill-in section" || fail "MD lacks the fill-in section"
# HTML carries the same guidance inline, in the evidence column of the row it
# belongs to, rather than as a section of its own.
grep -q 'details class="fix"' "$WORK/conf_conformance.html" && pass "HTML carries the fill-in fragment inline" || fail "HTML lacks the inline fill-in fragment"
grep -q "How to fill this" "$WORK/conf_conformance.html" && pass "HTML labels the inline fragment" || fail "HTML lacks the inline fragment label"
grep -q '<a href="https://cyclonedx.org/' "$WORK/conf_conformance.html" && pass "HTML links the reference doc" || fail "HTML leaves the reference URL as text"
grep -q 'How to fill the gaps' "$WORK/conf_conformance.html" && fail "HTML still carries the standalone fill-in section" || pass "HTML has no standalone fill-in section"

echo "== conformance HTML: table legibility =="
grep -q '<td class="num">1</td>' "$WORK/conf_conformance.html" && pass "rows are numbered" || fail "rows carry no number column"
grep -q 'class="s-review"' "$WORK/conf_conformance.html" && pass "review rows have their own status colour" || fail "review rows reuse the warn colour"
grep -q 'td.req{white-space:nowrap' "$WORK/conf_conformance.html" && pass "the required cell does not wrap" || fail "the required cell can wrap one glyph per line"
grep -q 'href="https://huggingface.co/' "$WORK/conf_conformance.html" && pass "the project name links to the model repository" || fail "the project name is not linked"
# The fragment text itself must reach the reader, not just the heading.
grep -q '"alg": "SHA-256"' "$WORK/conf_conformance.md" && pass "MD prints the CycloneDX fragment" || fail "MD lacks the fragment body"
# Scope: the section covers gaps only. g7-model-license passes on this fixture,
# so its guidance must NOT appear — a report that lists satisfied elements as
# things to fix would be actively misleading.
gapmd=$(sed -n '/## How to fill the gaps/,/^## Regulatory/p' "$WORK/conf_conformance.md")
if printf '%s' "$gapmd" | grep -q "^### Model license$"; then
    fail "the fill-in section is scoped to gaps" "a passing element (Model license) was listed"
else
    pass "the fill-in section is scoped to gaps (passing elements excluded)"
fi

echo "== G7 fill-in guidance: informational only (result + G7 count unchanged) =="
G7_GUIDANCE="$WORK/nope.json" bash "$LIB/validate-sbom.sh" "$FIX/aibom-owasp-1_7.json" "$WORK/confg" "x" >/dev/null 2>&1
rg_with=$(jq -r '.result' "$CONF"); rg_without=$(jq -r '.result' "$WORK/confg_conformance.json")
[ "$rg_with" = "$rg_without" ] && pass "result identical with/without the guidance ($rg_with)" || fail "result changed: with=$rg_with without=$rg_without"
gcount=$(jq '[.checks[] | select(has("guidance"))] | length' "$WORK/confg_conformance.json")
[ "$gcount" = "0" ] && pass "no guidance file -> no guidance keys (graceful)" || fail "guidance present despite a disabled registry ($gcount)"
g7g_with=$(jq '[.checks[]|select(.id|startswith("g7-"))]|length' "$CONF")
g7g_without=$(jq '[.checks[]|select(.id|startswith("g7-"))]|length' "$WORK/confg_conformance.json")
[ "$g7g_with" = "$g7g_without" ] && pass "G7 check count unchanged by the guidance ($g7g_with)" || fail "G7 count differs: with=$g7g_with without=$g7g_without"

echo "== AI compliance profile re-aggregates conformance + license flags =="
# Reuse the AI-fixture conformance from the G7 section ($WORK/conf_conformance.json);
# give the profile a matching _bom.json carrying one behavioral-use license flag.
jq '.components[0].properties = ((.components[0].properties // []) + [{name:"bomlens:licenseReview",value:"behavioral-use"}])' \
   "$FIX/aibom-owasp-1_7.json" > "$WORK/conf_bom.json"
bash "$LIB/generate-ai-profile.sh" "$WORK/conf" "demo" >/dev/null 2>&1
PROF="$WORK/conf_ai-profile.json"
if [ -f "$PROF" ]; then
    pass "ai-profile artifacts written for an AI SBOM"
    cl=$(jq -r '.g7.clusters | length' "$PROF")
    [ "$cl" = "7" ] && pass "profile rolls up all 7 G7 clusters" || fail "profile clusters=$cl, expected 7"
    inv=$(jq -r '(.g7.present + .g7.gap + .g7.review)' "$PROF"); tot=$(jq -r '.g7.total' "$PROF")
    [ "$inv" = "$tot" ] && pass "G7 present+gap+review == total ($tot)" || fail "G7 counts inconsistent: $inv vs $tot"
    lf=$(jq -r '.licenseReview.total' "$PROF"); lb=$(jq -r '.licenseReview.behavioral' "$PROF")
    { [ "$lf" -ge 1 ] && [ "$lb" -ge 1 ]; } && pass "license-review flag surfaced ($lf total, $lb behavioral-use)" || fail "license flag not surfaced (total=$lf, behavioral=$lb)"
    xf=$(jq -r '.regulatoryCrosswalk.frameworks | length' "$PROF")
    [ "$xf" -ge 1 ] && pass "profile carries the regulatory crosswalk ($xf framework(s))" || fail "profile lacks the crosswalk"
    grep -q "re-aggregates the conformance and SBOM artifacts" "$WORK/conf_ai-profile.md" && pass "MD states it re-aggregates existing artifacts" || fail "MD lacks the re-aggregation note"
    grep -q "AI compliance profile" "$WORK/conf_ai-profile.html" && pass "HTML profile rendered" || fail "HTML profile missing"
    # The profile lists the closable gaps and delegates the fragments to the
    # conformance report, so the two artifacts stay complementary, not duplicated.
    gi=$(jq -r '.g7.gapItems | length' "$PROF"); gc=$(jq -r '.g7.gap' "$PROF")
    [ "$gi" = "$gc" ] && pass "profile gapItems match the gap count ($gc)" || fail "gapItems=$gi but gap=$gc"
    grep -q "How to close the gaps" "$WORK/conf_ai-profile.md" && pass "MD carries the close-the-gaps section" || fail "MD lacks the close-the-gaps section"
    if grep -q '```json' "$WORK/conf_ai-profile.md"; then
        fail "the profile delegates fragments to the conformance report" "it embedded a fragment itself"
    else
        pass "the profile delegates fragments to the conformance report"
    fi
else
    fail "generate-ai-profile.sh produced no profile for an AI SBOM"
fi

echo "== AI compliance profile self-gates on non-AI SBOMs =="
# A plain conformance report (no G7 checks) must yield no profile at all.
printf '{"project":"x","format":"CycloneDX","result":"pass","checks":[{"id":"spec-version","label":"x","required":true,"status":"pass"}]}' > "$WORK/plain_conformance.json"
echo '{"bomFormat":"CycloneDX","components":[]}' > "$WORK/plain_bom.json"
bash "$LIB/generate-ai-profile.sh" "$WORK/plain" "x" >/dev/null 2>&1
[ ! -f "$WORK/plain_ai-profile.json" ] && pass "no profile written for a non-AI SBOM (self-gated)" || fail "profile wrongly written for a non-AI SBOM"

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

echo "== G7 registry: Korean labels/cluster names cover every element/cluster =="
# Drift guard mirroring the crosswalk one: the ko reports look up label_ko by id
# and name_ko by cluster id, so a new element/cluster without a Korean string
# would silently render English. Fail here so ko strings cannot drift.
REG="$LIB/g7-registry.json"
miss_lk=$(jq -r '[.clusters[].elements[] | select(has("label") and ((.label_ko // "")==""))] | length' "$REG")
[ "$miss_lk" = "0" ] && pass "every element with a label has a non-empty label_ko" || fail "$miss_lk G7 element(s) missing label_ko"
miss_nk=$(jq -r '[.clusters[] | select(((.name // "")=="") or ((.name_ko // "")==""))] | length' "$REG")
[ "$miss_nk" = "0" ] && pass "every cluster has a name and name_ko" || fail "$miss_nk cluster(s) missing name/name_ko"

echo "== report string catalog is valid and has no unfilled placeholders in ko output =="
CAT="$LIB/i18n/report-strings.ko.json"
jq empty "$CAT" >/dev/null 2>&1 && pass "report-strings.ko.json is valid JSON" || fail "report-strings.ko.json is not valid JSON"

echo "== ko conformance report renders Korean while the JSON stays English =="
REPORT_LANG=ko bash "$LIB/validate-sbom.sh" "$FIX/aibom-owasp-1_7.json" "$WORK/koconf" "bert-base-uncased" >/dev/null 2>&1
# JSON is a contract: it must match the English JSON byte-for-byte (bar the timestamp).
if diff <(jq 'del(.generatedAt)' "$CONF") <(jq 'del(.generatedAt)' "$WORK/koconf_conformance.json") >/dev/null 2>&1; then
    pass "ko conformance JSON == en conformance JSON (contract stays English)"
else
    fail "ko conformance JSON diverged from the English JSON"
fi
grep -q '<html lang="ko">' "$WORK/koconf_conformance.html" && pass "ko conformance HTML sets lang=ko" || fail "ko conformance HTML lang is not ko"
grep -q 'SBOM 적합성 보고서' "$WORK/koconf_conformance.html" && pass "ko conformance HTML h1 is Korean" || fail "ko conformance HTML h1 not localized"
grep -q '모델 라이선스' "$WORK/koconf_conformance.md" && pass "ko conformance MD localizes a G7 element label" || fail "ko conformance MD label not localized"
grep -q '사람 검토 필요' "$WORK/koconf_conformance.md" && pass "ko conformance MD localizes a review detail" || fail "ko conformance MD detail not localized"
# Data/identifiers must survive verbatim in the ko report.
grep -q 'Apache-2.0' "$WORK/koconf_conformance.md" && pass "ko conformance keeps the license id verbatim" || fail "ko conformance dropped the license id"
grep -q '✅' "$WORK/koconf_conformance.md" && pass "ko conformance keeps the status emoji" || fail "ko conformance dropped the status emoji"
# The English default must be untouched (same fixture, no REPORT_LANG).
grep -q 'SBOM Conformance Report' "$WORK/conf_conformance.html" && pass "en (default) conformance stays English" || fail "en default conformance drifted"

echo "== ko AI compliance profile renders Korean while the JSON stays English =="
cp "$WORK/conf_bom.json" "$WORK/koconf_bom.json" 2>/dev/null
REPORT_LANG=ko bash "$LIB/generate-ai-profile.sh" "$WORK/koconf" "demo" >/dev/null 2>&1
if [ -f "$WORK/koconf_ai-profile.json" ]; then
    grep -q '<html lang="ko">' "$WORK/koconf_ai-profile.html" && pass "ko profile HTML sets lang=ko" || fail "ko profile HTML lang is not ko"
    grep -q 'AI 준수 개요' "$WORK/koconf_ai-profile.html" && pass "ko profile HTML h1 is Korean" || fail "ko profile h1 not localized"
    grep -q '클러스터별 G7 최소 요소' "$WORK/koconf_ai-profile.md" && pass "ko profile cluster heading is Korean" || fail "ko profile heading not localized"
    grep -qE '^\| (메타데이터|모델|인프라) ' "$WORK/koconf_ai-profile.md" && pass "ko profile localizes cluster display names (name_ko)" || fail "ko profile cluster names not localized"
    if diff <(jq 'del(.generatedAt)' "$WORK/conf_ai-profile.json") <(jq 'del(.generatedAt)' "$WORK/koconf_ai-profile.json") >/dev/null 2>&1; then
        pass "ko profile JSON == en profile JSON (contract stays English)"
    else
        fail "ko profile JSON diverged from the English JSON"
    fi
else
    fail "ko profile produced no output"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
