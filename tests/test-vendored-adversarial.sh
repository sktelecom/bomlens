#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-vendored-adversarial.sh — adversarial No-Docker tests for --identify-vendored.
#
# Hammers the vendored-OSS identification pipeline (identify-vendored.sh +
# normalize-sbom.sh CPE synthesis + reconcile-vendored.sh + suggest-vendored.sh)
# with hostile and malformed SCANOSS output: injection in versions/names/paths,
# missing fields, weird version forms, huge result sets, and over-detection edges.
# A mock `scanoss-py` feeds crafted raw JSON, so this runs in CI without Docker or
# a network. Every case asserts: no crash, a spec-valid CycloneDX SBOM out, and —
# critically — no malformed CPE that could make Trivy reject the whole SBOM.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq required"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Mock scanoss-py: copy the fixture named by $SCANOSS_RAW_FIXTURE to the --output path.
mkdir -p "$WORK/bin"
printf '%s\n' '#!/bin/bash' \
  'o="";p="";for a in "$@";do [ "$p" = "--output" ] && o="$a";p="$a";done' \
  '[ -n "$o" ] && cp "$SCANOSS_RAW_FIXTURE" "$o" 2>/dev/null;exit 0' > "$WORK/bin/scanoss-py"
chmod +x "$WORK/bin/scanoss-py"

# identify <raw_file> <out_file> — run identify-vendored.sh with the mock.
identify() {
    local raw="$1" out="$2" src="$WORK/src"
    rm -rf "$src"; mkdir -p "$src"; echo 'int main(void){return 0;}' > "$src/m.c"
    SCANOSS_RAW_FIXTURE="$raw" PATH="$WORK/bin:$PATH" \
        bash "$LIB/identify-vendored.sh" "$src" "$out" "1.0" >/dev/null 2>&1
}
# valid_cdx <file> — true if it parses and components is an array.
valid_cdx() { jq -e '.bomFormat=="CycloneDX" and ((.components|type)=="array")' "$1" >/dev/null 2>&1; }
# cpe_fields <file> <name> — number of ':' fields in the component's cpe (0 = none).
cpe_fields() { jq -r --arg n "$2" '.components[]|select(.name==$n)|.cpe // "" | if .=="" then 0 else (split(":")|length) end' "$1" 2>/dev/null | head -1; }

echo "== CPE injection: hostile versions must never produce a malformed CPE =="
# Regression for the confirmed bug: a ':' / space / wildcard in the SCANOSS version
# shifted the 13-field cpe:2.3 grammar (14+ fields), which can make Trivy reject the
# whole SBOM. Such versions must yield NO cpe (identified-only), not a broken one.
for v in '1.0:evil va*l' '1.0 2.0' '*' 'a:b:c:d' '"; DROP' '1.0
2.0'; do
    raw="$WORK/raw.json"
    jq -n --arg v "$v" '{"src/x.c":[{id:"file",component:"openssl",version:$v,purl:["pkg:github/openssl/openssl"],licenses:[{name:"Apache-2.0"}],matched:"100%"}]}' > "$raw"
    identify "$raw" "$WORK/v.json"
    bash "$LIB/normalize-sbom.sh" "$WORK/v.json" >/dev/null 2>&1
    nf=$(cpe_fields "$WORK/v.json" openssl)
    if valid_cdx "$WORK/v.json" && [ "${nf:-0}" = "0" ]; then
        pass "hostile version [$(printf '%q' "$v")] -> no cpe, valid SBOM"
    else
        fail "hostile version [$(printf '%q' "$v")] produced cpe with $nf fields" "$(jq -c '.components[0].cpe' "$WORK/v.json" 2>/dev/null)"
    fi
done

echo "== legit versions still synthesize a valid 13-field cpe =="
for v in '3.0.0' '1.1.1w' '3.0.0-beta2' '1_1_1w'; do
    raw="$WORK/raw.json"
    jq -n --arg v "$v" '{"src/x.c":[{id:"file",component:"openssl",version:$v,purl:["pkg:github/openssl/openssl"],matched:"100%"}]}' > "$raw"
    identify "$raw" "$WORK/v.json"; bash "$LIB/normalize-sbom.sh" "$WORK/v.json" >/dev/null 2>&1
    nf=$(cpe_fields "$WORK/v.json" openssl)
    [ "${nf:-0}" = "13" ] && pass "legit version [$v] -> valid 13-field cpe" || fail "legit version [$v] cpe fields=$nf (expected 13)"
done

echo "== git-tag version normalization (strip component-/v- prefix) =="
jq -n '{"a.c":[{id:"file",component:"openssl",version:"openssl-3.0.0",purl:["pkg:github/openssl/openssl"],matched:"100%"}],
        "b.c":[{id:"file",component:"zlib",version:"v1.2.13",purl:["pkg:github/madler/zlib"],matched:"100%"}]}' > "$WORK/raw.json"
identify "$WORK/raw.json" "$WORK/v.json"
ov=$(jq -r '.components[]|select(.name=="openssl")|.version' "$WORK/v.json")
zv=$(jq -r '.components[]|select(.name=="zlib")|.version' "$WORK/v.json")
[ "$ov" = "3.0.0" ] && pass "openssl-3.0.0 -> 3.0.0" || fail "openssl version='$ov'"
[ "$zv" = "1.2.13" ] && pass "v1.2.13 -> 1.2.13" || fail "zlib version='$zv'"

echo "== malformed / missing fields degrade gracefully (no crash, valid SBOM) =="
# missing version, missing component, missing purl, empty purl array
jq -n '{"a.c":[{id:"file",component:"foo",purl:["pkg:github/foo/foo"],matched:"100%"}],
        "b.c":[{id:"file",version:"1.0",purl:["pkg:github/bar/bar"],matched:"90%"}],
        "c.c":[{id:"file",component:"baz",version:"1.0",matched:"100%"}],
        "d.c":[{id:"file",component:"qux",version:"1.0",purl:[],matched:"100%"}]}' > "$WORK/raw.json"
identify "$WORK/raw.json" "$WORK/v.json"
valid_cdx "$WORK/v.json" && pass "missing-field matches -> valid SBOM" || fail "missing-field matches broke the SBOM"
# component with no name (no component, no purl) must be dropped, not emitted blank
jq -n '{"a.c":[{id:"file",version:"1.0",matched:"100%"}]}' > "$WORK/raw.json"
identify "$WORK/raw.json" "$WORK/v.json"
nblank=$(jq '[.components[]|select((.name//"")=="")]|length' "$WORK/v.json" 2>/dev/null || echo 99)
[ "$nblank" = "0" ] && pass "nameless match dropped (no blank component)" || fail "emitted $nblank blank-name component(s)"

echo "== only snippet/none ids -> zero components =="
jq -n '{"a.c":[{id:"snippet",component:"x",version:"1",purl:["pkg:github/x/x"],matched:"30%"}],
        "b.c":[{id:"none"}]}' > "$WORK/raw.json"
identify "$WORK/raw.json" "$WORK/v.json"
n=$(jq '[.components[]?]|length' "$WORK/v.json"); { valid_cdx "$WORK/v.json" && [ "$n" = "0" ]; } && pass "snippet/none only -> 0 components" || fail "snippet/none produced $n components"

echo "== invalid / empty / non-JSON scanoss output -> graceful empty =="
printf 'not json {{{' > "$WORK/raw.json"; identify "$WORK/raw.json" "$WORK/v.json"
{ valid_cdx "$WORK/v.json" && [ "$(jq '[.components[]?]|length' "$WORK/v.json")" = "0" ]; } && pass "invalid JSON -> valid empty SBOM" || fail "invalid JSON not handled"
: > "$WORK/raw.json"; identify "$WORK/raw.json" "$WORK/v.json"
valid_cdx "$WORK/v.json" && pass "empty output -> valid empty SBOM" || fail "empty output not handled"

echo "== duplicate components across files dedupe by purl =="
jq -n '{"a.c":[{id:"file",component:"openssl",version:"3.0.0",purl:["pkg:github/openssl/openssl"],matched:"100%"}],
        "b.c":[{id:"file",component:"openssl",version:"3.0.0",purl:["pkg:github/openssl/openssl"],matched:"100%"}],
        "c.c":[{id:"file",component:"openssl",version:"3.0.0",purl:["pkg:github/openssl/openssl"],matched:"100%"}]}' > "$WORK/raw.json"
identify "$WORK/raw.json" "$WORK/v.json"
n=$(jq '[.components[]?]|length' "$WORK/v.json"); [ "$n" = "1" ] && pass "3 matches of openssl -> 1 component" || fail "dedupe failed, got $n"

echo "== name / path injection: jq survives, names preserved for escaping downstream =="
xss='<img src=x onerror=alert(1)>'
jq -n --arg x "$xss" '{"../../etc/passwd":[{id:"file",component:$x,version:"1.0",purl:["pkg:github/a/b"],matched:"100%"}]}' > "$WORK/raw.json"
identify "$WORK/raw.json" "$WORK/v.json"
valid_cdx "$WORK/v.json" && pass "XSS name + traversal path -> valid SBOM (no crash)" || fail "injection broke identify"
# NOTICE.html must escape the hostile component name (no raw <img ...>).
bash "$LIB/generate-notice.sh" "$WORK/v.json" "$WORK/n" "Proj" >/dev/null 2>&1
if [ -f "$WORK/n_NOTICE.html" ]; then
    if grep -qF '<img src=x onerror' "$WORK/n_NOTICE.html"; then
        fail "NOTICE.html did NOT escape the hostile component name (XSS)"
    else
        pass "NOTICE.html escapes the hostile component name"
    fi
else
    pass "NOTICE.html not produced for injected name (acceptable)"
fi

echo "== large result set (2000 matches) completes and stays well-formed =="
jq -n '[range(0;2000)] | map({key:("f\(.).c"),value:[{id:"file",component:("lib\(.)"),version:"1.0",purl:["pkg:github/o/lib\(.)"],matched:"100%"}]}) | from_entries' > "$WORK/raw.json"
identify "$WORK/raw.json" "$WORK/v.json"
n=$(jq '[.components[]?]|length' "$WORK/v.json" 2>/dev/null || echo 0)
{ valid_cdx "$WORK/v.json" && [ "${n:-0}" -ge 1900 ]; } && pass "2000-match scan -> valid SBOM ($n components)" || fail "large scan degraded (n=$n)"

echo "== reconcile: exact name match only (substring must NOT be dropped) =="
base="$WORK/base.json"; vend="$WORK/vend.json"
jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",version:1,components:[{name:"ssl",version:"1",purl:"pkg:npm/ssl@1"}]}' > "$base"
jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",version:1,components:[{name:"openssl",version:"3.0.0",purl:"pkg:github/openssl/openssl"}]}' > "$vend"
dropped=$(bash "$LIB/reconcile-vendored.sh" "$base" "$vend")
keep=$(jq '[.components[]?]|length' "$vend")
{ [ "$dropped" = "0" ] && [ "$keep" = "1" ]; } && pass "'ssl' base does not drop 'openssl' vendored (exact-match only)" || fail "substring wrongly reconciled (dropped=$dropped)"

echo "== reconcile: case-insensitive exact match drops the duplicate =="
jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",version:1,components:[{name:"OpenSSL",version:"3",purl:"pkg:npm/openssl@3"}]}' > "$base"
jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",version:1,components:[{name:"openssl",version:"3.0.0",purl:"pkg:github/openssl/openssl"},{name:"liblfds",version:"6.1.1",purl:"pkg:github/liblfds/liblfds"}]}' > "$vend"
dropped=$(bash "$LIB/reconcile-vendored.sh" "$base" "$vend")
keep=$(jq -r '[.components[].name]|join(",")' "$vend")
{ [ "$dropped" = "1" ] && [ "$keep" = "liblfds" ]; } && pass "case-insensitive dup dropped, real find kept" || fail "dropped=$dropped keep='$keep'"

echo "== reconcile: empty/null base components -> nothing dropped, no crash =="
jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",version:1,components:null}' > "$base"
jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",version:1,components:[{name:"liblfds",version:"6.1.1",purl:"pkg:github/liblfds/liblfds"}]}' > "$vend"
dropped=$(bash "$LIB/reconcile-vendored.sh" "$base" "$vend" 2>/dev/null)
{ [ "${dropped:-x}" = "0" ] && [ "$(jq '[.components[]?]|length' "$vend")" = "1" ]; } && pass "null base components -> 0 dropped, vendored intact" || fail "null base mishandled (dropped='$dropped')"

echo "== suggest: boundary + non-trigger cases =="
sb="$WORK/sug.json"; csrc="$WORK/csrc"; rm -rf "$csrc"; mkdir -p "$csrc"; echo 'int x;' > "$csrc/a.c"
# headers-only C tree (only .h) still counts as C/C++
rm -rf "$WORK/hsrc"; mkdir -p "$WORK/hsrc"; echo 'int x;' > "$WORK/hsrc/a.h"
jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",version:1,metadata:{},components:[]}' > "$sb"
IDENTIFY_VENDORED=false bash "$LIB/suggest-vendored.sh" "$sb" "$WORK/hsrc" >/dev/null 2>&1
jq -e '.metadata.properties[]?|select(.name=="bomlens:suggest-identify-vendored")' "$sb" >/dev/null 2>&1 && pass "headers-only C tree triggers suggestion" || fail "headers-only tree did not trigger"
# manifest in a subdir -> detect_lang at root is still 'unknown', so suggestion is allowed;
# manifest at ROOT must NOT trigger.
jq -n '{bomFormat:"CycloneDX",specVersion:"1.6",version:1,metadata:{},components:[]}' > "$sb"
echo '{"name":"x"}' > "$csrc/package.json"
IDENTIFY_VENDORED=false bash "$LIB/suggest-vendored.sh" "$sb" "$csrc" >/dev/null 2>&1
jq -e '.metadata.properties[]?|select(.name=="bomlens:suggest-identify-vendored")' "$sb" >/dev/null 2>&1 && fail "root manifest wrongly triggered suggestion" || pass "root package.json suppresses suggestion"

echo "== byte-stable: identical mock input -> byte-identical normalized output =="
jq -n '{"a.c":[{id:"file",component:"openssl",version:"3.0.0",purl:["pkg:github/openssl/openssl"],matched:"100%"}]}' > "$WORK/raw.json"
identify "$WORK/raw.json" "$WORK/s1.json"; identify "$WORK/raw.json" "$WORK/s2.json"
bash "$LIB/normalize-sbom.sh" "$WORK/s1.json" --stable >/dev/null 2>&1
bash "$LIB/normalize-sbom.sh" "$WORK/s2.json" --stable >/dev/null 2>&1
if diff -q "$WORK/s1.json" "$WORK/s2.json" >/dev/null 2>&1; then pass "two identical scans are byte-identical after --stable"; else fail "byte-stable diff" "$(diff "$WORK/s1.json" "$WORK/s2.json" | head)"; fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
