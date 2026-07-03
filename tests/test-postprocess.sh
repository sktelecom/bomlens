#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# test-postprocess.sh — No-Docker unit tests for the SBOM post-processing
# scripts (normalize-sbom.sh, stamp-metadata.sh, generate-notice.sh), driven by
# regression fixtures for the defects from the verification report:
#   B-1  --byte-stable leaks cdxgen's random venv name
#   B-3  cdxgen emits components:null + a temp upload path as the root name
#   B-2  metadata.component carries source coordinates, not the input identity
#   B-4  NOTICE duplicates license texts; "Expat" is not normalized to MIT
# Pure jq/bash, so it runs in CI without Docker or a scanner image.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required for post-process unit tests"; exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== B-1: --byte-stable normalizes cdxgen venv name =="
cp "$FIX/venv-leak-a.json" "$WORK/a.json"
cp "$FIX/venv-leak-b.json" "$WORK/b.json"
bash "$LIB/normalize-sbom.sh" "$WORK/a.json" --stable >/dev/null 2>&1
bash "$LIB/normalize-sbom.sh" "$WORK/b.json" --stable >/dev/null 2>&1
if diff -q "$WORK/a.json" "$WORK/b.json" >/dev/null 2>&1; then
    pass "two inputs differing only in venv name are byte-identical after --stable"
else
    fail "byte-stable normalization left a difference" "$(diff "$WORK/a.json" "$WORK/b.json" | head)"
fi
if ! grep -Eq 'cdxgen-venv-[A-Za-z0-9]+' "$WORK/a.json"; then
    pass "no random venv suffix remains"
else
    fail "random cdxgen-venv suffix still present"
fi

echo "== B-3: null components coerced to an array =="
cp "$FIX/null-components.json" "$WORK/n.json"
bash "$LIB/normalize-sbom.sh" "$WORK/n.json" >/dev/null 2>&1
ctype=$(jq -r '.components | type' "$WORK/n.json" 2>/dev/null)
if [ "$ctype" = "array" ]; then pass "components is an array (was null)"; else fail "components type is '$ctype', expected array"; fi

echo "== B-2/B-3: metadata stamped from input, temp path gone =="
cp "$FIX/null-components.json" "$WORK/m.json"
bash "$LIB/stamp-metadata.sh" "$WORK/m.json" "MyProj" "2.0.0" >/dev/null 2>&1
nm=$(jq -r '.metadata.component.name' "$WORK/m.json")
ver=$(jq -r '.metadata.component.version' "$WORK/m.json")
purl=$(jq -r '.metadata.component.purl // "ABSENT"' "$WORK/m.json")
[ "$nm" = "MyProj" ] && pass "metadata.component.name = input project" || fail "name='$nm', expected MyProj"
[ "$ver" = "2.0.0" ] && pass "metadata.component.version = input version" || fail "version='$ver', expected 2.0.0"
[ "$purl" = "ABSENT" ] && pass "stale purl dropped" || fail "purl still present: $purl"
if ! grep -Eq 'host-output|\.uploads|extracted' "$WORK/m.json"; then
    pass "no internal temp path leaks into the SBOM"
else
    fail "temp upload path still present in metadata"
fi

echo "== src-latest: cdxgen src@latest root is stamped over, never delivered as 'src' =="
# Regression for the Black Duck codelocation collision: two unrelated source SBOMs
# both came out as metadata.component = src/latest (pkg:generic/src@latest), so the
# second import was blocked as a duplicate codelocation. The stamp must replace it
# with the caller's project name.
cp "$FIX/src-latest-root.json" "$WORK/s.json"
bash "$LIB/stamp-metadata.sh" "$WORK/s.json" "AcmeApp" "1.2.3" >/dev/null 2>&1
sname=$(jq -r '.metadata.component.name' "$WORK/s.json")
spurl=$(jq -r '.metadata.component.purl // "ABSENT"' "$WORK/s.json")
[ "$sname" = "AcmeApp" ] && pass "src@latest root renamed to input project" || fail "name='$sname', expected AcmeApp"
[ "$sname" != "src" ] && pass "root name is no longer the generic 'src'" || fail "root name still 'src'"
[ "$spurl" = "ABSENT" ] && pass "pkg:generic/src@latest purl dropped" || fail "purl still present: $spurl"

echo "== final net: stamp fails closed on the placeholder name and on bad input =="
# The engine-agnostic net must reject 'src'/'app' as the stamped name (a colliding
# codelocation), not silently pass it through.
cp "$FIX/src-latest-root.json" "$WORK/g.json"
if bash "$LIB/stamp-metadata.sh" "$WORK/g.json" "src" "1.0.0" >/dev/null 2>&1; then
    fail "stamp accepted the generic placeholder 'src' as a project name"
else
    pass "stamp rejects 'src' as a project name (exit != 0)"
fi
# A missing jq or invalid JSON is a build/runtime defect; stamp must fail closed so a
# mis-named SBOM is never delivered, rather than warn-and-exit-0 as before.
printf 'not json{' > "$WORK/bad.json"
if bash "$LIB/stamp-metadata.sh" "$WORK/bad.json" "AcmeApp" "1.0.0" >/dev/null 2>&1; then
    fail "stamp exited 0 on invalid JSON (should fail closed)"
else
    pass "stamp fails closed on invalid JSON (exit != 0)"
fi

echo "== B-4: NOTICE dedupes license texts and normalizes Expat to MIT =="
cp "$FIX/license-aliases.json" "$WORK/l.json"
bash "$LIB/generate-notice.sh" "$WORK/l.json" "$WORK/notice" "FixtureProj" >/dev/null 2>&1
NOTICE="$WORK/notice_NOTICE.txt"
if [ -f "$NOTICE" ]; then
    apa=$(grep -c '^----------------------------- Apache-2.0 ' "$NOTICE")
    mit=$(grep -c '^----------------------------- MIT ' "$NOTICE")
    [ "$apa" = "1" ] && pass "Apache-2.0 license text appears exactly once" || fail "Apache-2.0 text appears ${apa}x (dedupe regression)"
    [ "$mit" = "1" ] && pass "MIT license text appears exactly once" || fail "MIT text appears ${mit}x"
    if ! grep -q "Expat" "$NOTICE"; then
        pass "Expat alias normalized away"
    else
        fail "Expat license not normalized to MIT"
    fi
    if awk '/^License: MIT$/{f=1;next} /^License: /{f=0} f&&/mccabe/{ok=1} END{exit !ok}' "$NOTICE"; then
        pass "mccabe (Expat) grouped under MIT"
    else
        fail "mccabe not grouped under MIT"
    fi
else
    fail "generate-notice.sh did not produce $NOTICE"
fi

echo "== B-5: NOTICE shows source location + attribution per component =="
# A component with a vcs externalReference, one with only a purl (registry inferred),
# and one carrying component.copyright. Source must never be blank when a purl exists,
# and attribution must never be blank (copyright, else an honest "not captured").
cat > "$WORK/src.json" <<'JSON'
{"components":[
 {"name":"logback","version":"1.4","purl":"pkg:maven/ch.qos.logback/logback@1.4",
  "externalReferences":[{"type":"vcs","url":"https://github.com/qos-ch/logback"}],
  "licenses":[{"license":{"id":"Apache-2.0"}}]},
 {"name":"hikari","version":"5.0.1","purl":"pkg:maven/com.zaxxer/HikariCP@5.0.1",
  "licenses":[{"license":{"id":"Apache-2.0"}}]},
 {"name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0",
  "copyright":"Copyright (c) azer","licenses":[{"license":{"id":"MIT"}}]}
]}
JSON
bash "$LIB/generate-notice.sh" "$WORK/src.json" "$WORK/srcn" "SrcProj" >/dev/null 2>&1
STXT="$WORK/srcn_NOTICE.txt"; SHTML="$WORK/srcn_NOTICE.html"
if [ -f "$STXT" ] && [ -f "$SHTML" ]; then
    grep -q "Source: https://github.com/qos-ch/logback" "$STXT" \
        && pass "vcs externalReference used as source location" \
        || fail "vcs source location missing in TXT"
    grep -q "Source: https://repo1.maven.org/maven2/com/zaxxer/HikariCP/5.0.1/" "$STXT" \
        && pass "maven source location inferred from purl when no externalReference" \
        || fail "purl-inferred maven source missing"
    grep -q "Source: https://www.npmjs.com/package/left-pad/v/1.3.0" "$STXT" \
        && pass "npm source location inferred from purl" \
        || fail "purl-inferred npm source missing"
    grep -q "Copyright: Copyright (c) azer" "$STXT" \
        && pass "component.copyright shown verbatim as attribution" \
        || fail "copyright attribution missing"
    if awk '/^  - hikari@5.0.1$/{f=1;next} /^  - /{f=0} f&&/Copyright: holders not captured/{ok=1} END{exit !ok}' "$STXT"; then
        pass "attribution falls back to honest 'not captured' (never blank)"
    else
        fail "missing attribution fallback for a component without copyright"
    fi
    grep -q '<a href="https://github.com/qos-ch/logback">' "$SHTML" \
        && pass "http(s) source rendered as a link in HTML" \
        || fail "HTML source link missing"
else
    fail "generate-notice.sh did not produce source/attribution NOTICE"
fi

echo "== B-6: NOTICE PDF — rendered when weasyprint present, skipped gracefully otherwise =="
# generate-notice.sh must not die when the PDF renderer is absent, and must produce
# the PDF (and report it) when weasyprint is on PATH. We force the absent case with a
# PATH that has only the tools the script needs (jq, the coreutils it calls).
NOTICE_LOG="$WORK/pdf.log"
bash "$LIB/generate-notice.sh" "$WORK/src.json" "$WORK/pdfn" "PdfProj" >"$NOTICE_LOG" 2>&1
RC=$?
[ "$RC" -eq 0 ] && pass "generate-notice.sh exits 0 regardless of PDF renderer presence" \
    || fail "generate-notice.sh failed (rc=$RC)"
[ -f "$WORK/pdfn_NOTICE.txt" ] && [ -f "$WORK/pdfn_NOTICE.html" ] \
    && pass "TXT/HTML still produced on the PDF path" || fail "TXT/HTML missing on PDF path"
if command -v weasyprint >/dev/null 2>&1; then
    { [ -f "$WORK/pdfn_NOTICE.pdf" ] && grep -q "generated PDF" "$NOTICE_LOG"; } \
        && pass "weasyprint present: PDF rendered and reported" \
        || fail "weasyprint present but PDF not produced"
else
    { [ ! -f "$WORK/pdfn_NOTICE.pdf" ] && grep -q "PDF skipped" "$NOTICE_LOG"; } \
        && pass "weasyprint absent: PDF skipped with a log line (graceful, not silent)" \
        || fail "PDF skip not handled gracefully"
fi

echo "== V13-2: normalize-sbom.sh maps bom.json license aliases to SPDX ids =="
cp "$FIX/license-aliases.json" "$WORK/c.json"
bash "$LIB/normalize-sbom.sh" "$WORK/c.json" >/dev/null 2>&1
# Free-text alias in .expression is promoted to a proper .license.id.
mccabe_id=$(jq -r '.components[] | select(.name=="mccabe") | .licenses[0].license.id // "ABSENT"' "$WORK/c.json")
[ "$mccabe_id" = "MIT" ] && pass "Expat expression promoted to license id MIT" || fail "mccabe license id='$mccabe_id', expected MIT"
# Free-text alias in .license.name is promoted as well.
cov_id=$(jq -r '.components[] | select(.name=="coverage") | .licenses[0].license.id // "ABSENT"' "$WORK/c.json")
[ "$cov_id" = "Apache-2.0" ] && pass "free-text license name promoted to id Apache-2.0" || fail "coverage license id='$cov_id', expected Apache-2.0"
# A valid-but-wrong upstream id (cdxgen 0BSD mislabel) is preserved, not guessed.
flask_id=$(jq -r '.components[] | select(.name=="flask") | .licenses[0].license.id // "ABSENT"' "$WORK/c.json")
flask_url=$(jq -r '.components[] | select(.name=="flask") | .licenses[0].license.url // "ABSENT"' "$WORK/c.json")
[ "$flask_id" = "0BSD" ] && pass "valid-but-wrong upstream id (0BSD) preserved, not rewritten" || fail "flask license id='$flask_id', expected 0BSD"
[ "$flask_url" = "https://opensource.org/licenses/0BSD" ] && pass "license url preserved" || fail "flask license url='$flask_url'"
# A non-mappable free-text string and a genuine compound expression are untouched.
date_expr=$(jq -r '.components[] | select(.name=="python-dateutil") | .licenses[0].expression // "ABSENT"' "$WORK/c.json")
[ "$date_expr" = "Dual License" ] && pass "unmappable free text (Dual License) left untouched" || fail "dateutil expression='$date_expr', expected Dual License"
pkg_expr=$(jq -r '.components[] | select(.name=="packaging") | .licenses[0].expression // "ABSENT"' "$WORK/c.json")
[ "$pkg_expr" = "Apache-2.0 OR BSD-2-Clause" ] && pass "compound expression left untouched" || fail "packaging expression='$pkg_expr'"

echo "== vendored: identify-vendored.sh promotes file matches, drops snippets =="
# Mock scanoss-py (no network/image needed): write the raw SCANOSS fixture to the
# tool's --output path so identify-vendored.sh's jq transform is exercised.
mkdir -p "$WORK/bin" "$WORK/srctree/src"
echo 'int main(void){return 0;}' > "$WORK/srctree/src/main.c"
cat > "$WORK/bin/scanoss-py" <<'MOCK'
#!/bin/bash
out=""; prev=""
for a in "$@"; do [ "$prev" = "--output" ] && out="$a"; prev="$a"; done
[ -n "$out" ] && cp "$SCANOSS_RAW_FIXTURE" "$out"
exit 0
MOCK
chmod +x "$WORK/bin/scanoss-py"
export SCANOSS_RAW_FIXTURE="$FIX/scanoss-raw.json"
PATH="$WORK/bin:$PATH" bash "$LIB/identify-vendored.sh" "$WORK/srctree" "$WORK/vend.json" "26.4.0" >/dev/null 2>&1
vn=$(jq '[.components[]?] | length' "$WORK/vend.json" 2>/dev/null || echo 0)
[ "$vn" = "2" ] && pass "two full-file matches promoted (openssl, liblfds)" || fail "vendored components=$vn, expected 2"
if jq -e '[.components[] | select(.name=="somelib")] | length == 0' "$WORK/vend.json" >/dev/null 2>&1; then
    pass "snippet-only match (somelib) not promoted to a component"
else
    fail "snippet match leaked into components"
fi
if jq -e '.components[] | select(.name=="openssl") | .properties[]? | select(.name=="bomlens:identifiedBy" and .value=="scanoss")' "$WORK/vend.json" >/dev/null 2>&1; then
    pass "vendored components carry bomlens:identifiedBy=scanoss"
else
    fail "missing bomlens:identifiedBy=scanoss provenance"
fi
# OSSKB returns git-tag versions (e.g. "openssl-3.0.0"); they must be normalized
# or the synthesized CPE is malformed and Trivy matches nothing (found via the
# real-OSSKB spike). The component version must be the bare "3.0.0".
ssl_ver=$(jq -r '.components[] | select(.name=="openssl") | .version' "$WORK/vend.json")
[ "$ssl_ver" = "3.0.0" ] && pass "git-tag version normalized (openssl-3.0.0 -> 3.0.0)" || fail "version='$ssl_ver', expected 3.0.0 (normalization)"

echo "== vendored: identify -> merge -> normalize completes the PURL->CVE chain =="
# Merge the vendored components with a sparse cdxgen C/C++ SBOM, then normalize.
bash "$LIB/merge-sbom.sh" "$WORK/merged.json" "trelay" "26.4.0" \
    "$FIX/cdxgen-cpp-sparse.json" "$WORK/vend.json" >/dev/null 2>&1
if jq -e '.components[] | select(.name=="openssl")' "$WORK/merged.json" >/dev/null 2>&1; then
    pass "vendored openssl survived the merge into the project SBOM"
else
    fail "openssl missing after merge"
fi
bash "$LIB/normalize-sbom.sh" "$WORK/merged.json" >/dev/null 2>&1
# openssl: no SCANOSS cpe, but the map yields one -> Trivy can now match CVEs.
ssl_cpe=$(jq -r '.components[] | select(.name=="openssl") | .cpe // "ABSENT"' "$WORK/merged.json")
[ "$ssl_cpe" = "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*" ] \
    && pass "openssl PURL mapped to a Trivy-matchable cpe ($ssl_cpe)" \
    || fail "openssl cpe='$ssl_cpe' (PURL->CVE chain broken)"
# niche liblfds: no NVD record -> identified only, original PURL preserved.
lfds_cpe=$(jq -r '.components[] | select(.name=="liblfds") | .cpe // "ABSENT"' "$WORK/merged.json")
lfds_purl=$(jq -r '.components[] | select(.name=="liblfds") | .purl // "ABSENT"' "$WORK/merged.json")
[ "$lfds_cpe" = "ABSENT" ] && pass "niche liblfds left without a cpe (no NVD record)" || fail "liblfds unexpectedly got cpe='$lfds_cpe'"
[ "$lfds_purl" = "pkg:github/liblfds/liblfds" ] && pass "liblfds keeps its identifying PURL" || fail "liblfds purl='$lfds_purl'"
if jq -e '.components[] | select(.name=="openssl") | .properties[]? | select(.name=="bomlens:layer" and .value=="vendored")' "$WORK/merged.json" >/dev/null 2>&1; then
    pass "vendored provenance (bomlens:layer=vendored) survives normalize"
else
    fail "vendored layer marker lost"
fi

echo "== suggest: nudge only for C/C++ source, no manifest, sparse SBOM =="
mkdir -p "$WORK/csrc"
echo 'int main(void){return 0;}' > "$WORK/csrc/main.c"
cp "$FIX/cdxgen-cpp-sparse.json" "$WORK/sug.json"
IDENTIFY_VENDORED=false bash "$LIB/suggest-vendored.sh" "$WORK/sug.json" "$WORK/csrc" >/dev/null 2>&1
if jq -e '.metadata.properties[]? | select(.name=="bomlens:suggest-identify-vendored" and .value=="true")' "$WORK/sug.json" >/dev/null 2>&1; then
    pass "C/C++ + no manifest + sparse SBOM -> suggestion recorded"
else
    fail "expected suggestion property was not set"
fi
# Negative: a package manager manifest present -> no nudge (cdxgen already resolves).
mkdir -p "$WORK/nodesrc"
echo 'int main(void){return 0;}' > "$WORK/nodesrc/main.c"
echo '{"name":"x"}' > "$WORK/nodesrc/package.json"
cp "$FIX/cdxgen-cpp-sparse.json" "$WORK/sug2.json"
IDENTIFY_VENDORED=false bash "$LIB/suggest-vendored.sh" "$WORK/sug2.json" "$WORK/nodesrc" >/dev/null 2>&1
if jq -e '.metadata.properties[]? | select(.name=="bomlens:suggest-identify-vendored")' "$WORK/sug2.json" >/dev/null 2>&1; then
    fail "suggested even though a package manifest is present"
else
    pass "no nudge when a package manager manifest exists"
fi
# Negative: already enabled -> never nudge.
cp "$FIX/cdxgen-cpp-sparse.json" "$WORK/sug3.json"
IDENTIFY_VENDORED=true bash "$LIB/suggest-vendored.sh" "$WORK/sug3.json" "$WORK/csrc" >/dev/null 2>&1
if jq -e '.metadata.properties[]? | select(.name=="bomlens:suggest-identify-vendored")' "$WORK/sug3.json" >/dev/null 2>&1; then
    fail "nudged even though --identify-vendored is already on"
else
    pass "no nudge when --identify-vendored is already enabled"
fi

echo "== vendored: reconciliation prevents over-detection on a managed project =="
# A SCANOSS result that file-matches a declared dependency (lodash, already found
# by the package manager) plus a genuine vendored find (liblfds). Reconciliation
# must drop the duplicate and keep the new one, so enabling --identify-vendored on
# a normal managed project does not balloon the SBOM or invent false CVEs.
mkdir -p "$WORK/bin2" "$WORK/mtree/src"
echo 'int main(void){return 0;}' > "$WORK/mtree/src/main.c"
cat > "$WORK/bin2/scanoss-py" <<'MOCK'
#!/bin/bash
out=""; prev=""
for a in "$@"; do [ "$prev" = "--output" ] && out="$a"; prev="$a"; done
[ -n "$out" ] && cp "$SCANOSS_RAW_FIXTURE" "$out"
exit 0
MOCK
chmod +x "$WORK/bin2/scanoss-py"
export SCANOSS_RAW_FIXTURE="$FIX/scanoss-raw-managed.json"
PATH="$WORK/bin2:$PATH" bash "$LIB/identify-vendored.sh" "$WORK/mtree" "$WORK/vend2.json" "1.0.0" >/dev/null 2>&1
vraw=$(jq '[.components[]?]|length' "$WORK/vend2.json" 2>/dev/null || echo 0)
[ "$vraw" = "2" ] && pass "SCANOSS produced 2 matches (lodash + liblfds)" || fail "expected 2 raw vendored matches, got $vraw"

# Reconcile against the managed cdxgen SBOM (which already declares lodash).
dropped=$(bash "$LIB/reconcile-vendored.sh" "$FIX/cdxgen-node-managed.json" "$WORK/vend2.json")
[ "$dropped" = "1" ] && pass "reconcile drops 1 match already covered by the package manager" || fail "reconcile dropped '$dropped', expected 1"
if jq -e '[.components[] | select((.name|ascii_downcase)=="lodash")] | length == 0' "$WORK/vend2.json" >/dev/null 2>&1; then
    pass "duplicate lodash removed from the vendored set"
else
    fail "duplicate lodash survived reconciliation (over-detection)"
fi
if jq -e '[.components[] | select(.name=="liblfds")] | length == 1' "$WORK/vend2.json" >/dev/null 2>&1; then
    pass "genuine vendored find (liblfds) preserved"
else
    fail "real vendored component liblfds was wrongly dropped"
fi

# Merge the reconciled set into the managed SBOM: lodash stays single (the npm
# authoritative one), liblfds is added — no double counting.
bash "$LIB/merge-sbom.sh" "$WORK/mmerged.json" "webapp" "1.0.0" \
    "$FIX/cdxgen-node-managed.json" "$WORK/vend2.json" >/dev/null 2>&1
lodash_n=$(jq '[.components[] | select((.name|ascii_downcase)=="lodash")] | length' "$WORK/mmerged.json")
total_n=$(jq '[.components[]?] | length' "$WORK/mmerged.json")
[ "$lodash_n" = "1" ] && pass "merged SBOM has exactly one lodash (no duplicate)" || fail "lodash appears ${lodash_n}x after merge"
[ "$total_n" = "4" ] && pass "merged total = 3 managed + 1 new vendored (no double count)" || fail "merged total=$total_n, expected 4"
# The surviving lodash is the authoritative package-manager identity (pkg:npm).
lodash_purl=$(jq -r '.components[] | select((.name|ascii_downcase)=="lodash") | .purl' "$WORK/mmerged.json")
[ "$lodash_purl" = "pkg:npm/lodash@4.17.21" ] && pass "package-manager identity (pkg:npm) wins over the SCANOSS pkg:github match" || fail "lodash purl='$lodash_purl', expected pkg:npm"

echo "== F-1: firmware CPE enrichment (Plan 1) — whitelist + version normalization =="
cp "$FIX/firmware-no-cpe.json" "$WORK/fw.json"
bash "$LIB/enrich-cpe.sh" "$WORK/fw.json" >/dev/null 2>&1
# OpenWRT package-revision suffix (-5) stripped so the cpe version matches NVD.
bb_cpe=$(jq -r '.components[] | select(.name=="busybox") | .cpe' "$WORK/fw.json")
[ "$bb_cpe" = "cpe:2.3:a:busybox:busybox:1.30.1:*:*:*:*:*:*:*" ] \
    && pass "busybox cpe version normalized 1.30.1-5 -> 1.30.1 (Trivy-matchable)" \
    || fail "busybox cpe='$bb_cpe', expected upstream version 1.30.1"
# A component with NO cpe at all gets one from the whitelist.
dr_cpe=$(jq -r '.components[] | select(.name=="dropbear") | .cpe' "$WORK/fw.json")
[ "$dr_cpe" = "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2019.78:*:*:*:*:*:*:*" ] \
    && pass "dropbear (no cpe) gets a whitelisted cpe with correct NVD vendor/product" \
    || fail "dropbear cpe='$dr_cpe', expected dropbear_ssh_project:dropbear_ssh:2019.78"
# A non-whitelisted name must NOT be touched (false-positive guard).
unk_cpe=$(jq -r '.components[] | select(.name=="some-internal-thing") | .cpe // "ABSENT"' "$WORK/fw.json")
[ "$unk_cpe" = "ABSENT" ] && pass "non-whitelisted component left without a cpe (no false-positive CVEs)" || fail "unexpected cpe on unknown component: $unk_cpe"
# A whitelisted name not in our map (luci-base) keeps syft's cpe unchanged.
lu_cpe=$(jq -r '.components[] | select(.name=="luci-base") | .cpe' "$WORK/fw.json")
case "$lu_cpe" in cpe:2.3:a:luci-base:*) pass "non-mapped component keeps its existing cpe untouched" ;; *) fail "luci-base cpe changed unexpectedly: $lu_cpe" ;; esac
# License enrichment: a whitelisted name with a confirmed spdx_license and no
# license yet gets a CycloneDX licenses[] from the curated map.
bb_lic=$(jq -r '.components[] | select(.name=="busybox") | (.licenses // [])[0].license.id // "ABSENT"' "$WORK/fw.json")
[ "$bb_lic" = "GPL-2.0-only" ] \
    && pass "busybox (license-null) gets confirmed SPDX GPL-2.0-only" \
    || fail "busybox license='$bb_lic', expected GPL-2.0-only"
# A dual/multi license is written as a single SPDX expression entry.
dm_lic=$(jq -r '.components[] | select(.name=="dnsmasq") | (.licenses // [])[0].expression // "ABSENT"' "$WORK/fw.json")
[ "$dm_lic" = "GPL-2.0-only OR GPL-3.0-only" ] \
    && pass "dnsmasq dual license written as an SPDX expression" \
    || fail "dnsmasq expression='$dm_lic', expected GPL-2.0-only OR GPL-3.0-only"
# Provenance property marks the inferred license.
bb_src=$(jq -r '.components[] | select(.name=="busybox") | [(.properties // [])[] | select(.name=="bomlens:licenseSource") | .value][0] // "ABSENT"' "$WORK/fw.json")
[ "$bb_src" = "name-map" ] && pass "enriched license carries bomlens:licenseSource=name-map" || fail "busybox licenseSource='$bb_src', expected name-map"
# A pre-existing license is NEVER overwritten (syft is trusted) and gets no marker.
ipt_lic=$(jq -r '.components[] | select(.name=="iptables") | (.licenses // [])[0].license.id // "ABSENT"' "$WORK/fw.json")
[ "$ipt_lic" = "Apache-2.0" ] && pass "pre-existing license preserved (no overwrite)" || fail "iptables license='$ipt_lic', expected the pre-set Apache-2.0"
ipt_src=$(jq -r '.components[] | select(.name=="iptables") | [(.properties // [])[]? | select(.name=="bomlens:licenseSource")] | length' "$WORK/fw.json")
[ "$ipt_src" = "0" ] && pass "untouched license gets no bomlens:licenseSource marker" || fail "iptables wrongly marked as name-map enriched"
# A non-whitelisted name stays license-null (no guessed license).
unk_lic=$(jq -r '.components[] | select(.name=="some-internal-thing") | (.licenses // []) | length' "$WORK/fw.json")
[ "$unk_lic" = "0" ] && pass "non-whitelisted component left license-null (no wrong license)" || fail "unexpected license on unknown component"

# Idempotent: a second run changes nothing.
cp "$WORK/fw.json" "$WORK/fw2.json"
bash "$LIB/enrich-cpe.sh" "$WORK/fw2.json" >/dev/null 2>&1
if diff -q "$WORK/fw.json" "$WORK/fw2.json" >/dev/null 2>&1; then pass "enrich-cpe.sh is idempotent"; else fail "second enrich-cpe run changed the SBOM"; fi

echo "== F-2: firmware cve-bin-tool CVEs merge into the Trivy security contract (Plan 2) =="
# Sidecar (Trivy-shaped) + a Trivy report must merge into one .Results[].Vulnerabilities[]
# file without breaking the contract server.py security_summary reads.
echo '{"Results":[{"Target":"sbom","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-2020-1111","PkgName":"libfoo","InstalledVersion":"1.0","Severity":"LOW","CVSS":{"nvd":{"V3Score":3.1}}}]}]}' > "$WORK/trivy.json"
jq -s '{ Results: ((.[0].Results // []) + (.[1].Results // [])) } + (.[0] | del(.Results))' \
    "$WORK/trivy.json" "$FIX/cvebintool-sidecar.json" > "$WORK/sec.json"
total_v=$(jq '[.Results[].Vulnerabilities[]?] | length' "$WORK/sec.json")
[ "$total_v" = "2" ] && pass "Trivy + cve-bin-tool findings coexist in one report (1+1=2)" || fail "merged vuln count=$total_v, expected 2"
has_cbt=$(jq '[.Results[].Vulnerabilities[]? | select(.VulnerabilityID=="CVE-2021-42378")] | length' "$WORK/sec.json")
[ "$has_cbt" = "1" ] && pass "cve-bin-tool CVE present after merge" || fail "cve-bin-tool CVE missing after merge"
# CVSS must extract from BOTH sources via the same flatten the report uses.
cbt_cvss=$(jq -r '[ .Results[]?.Vulnerabilities[]? | select(.VulnerabilityID=="CVE-2021-42378")
    | ([ (.CVSS // {}) | to_entries[] | .value | (.V3Score // .V2Score) ] | map(select(.!=null)) | (max // null)) ][0]' "$WORK/sec.json")
[ "$cbt_cvss" = "7.2" ] && pass "cve-bin-tool CVSS score readable by the report flatten" || fail "cve-bin-tool CVSS='$cbt_cvss', expected 7.2"

echo "== D-4: validate-sbom.sh emits a conformance report for clean SPDX Tag-Value =="
# grep -c exits 1 on zero matches, so the old `grep -cE … || echo 0` appended a
# second "0" for every empty count. pkg:generic is always 0 in a clean SBOM, so
# the count became "0\n0", which broke --argjson under set -e and aborted the
# function — a well-formed Tag-Value input never got a conformance report.
bash "$LIB/validate-sbom.sh" "$FIX/supplier-clean-tagvalue.spdx" "$WORK/tv" "supplier" >/dev/null 2>&1
if [ -f "$WORK/tv_conformance.json" ] && [ -f "$WORK/tv_conformance.md" ] && [ -f "$WORK/tv_conformance.html" ]; then
    pass "clean Tag-Value SBOM produces conformance json+md+html"
    tv_gen=$(jq -r '.checks[] | select(.id=="no-generic") | .status' "$WORK/tv_conformance.json")
    [ "$tv_gen" = "pass" ] && pass "no-generic check evaluates (generic count 0 no longer aborts)" || fail "no-generic status='$tv_gen', expected pass"
    tv_res=$(jq -r '.result' "$WORK/tv_conformance.json")
    [ "$tv_res" = "pass" ] && pass "clean Tag-Value overall result is pass" || fail "Tag-Value result='$tv_res', expected pass"
else
    fail "validate-sbom.sh produced no conformance report for clean Tag-Value input"
fi

echo "== range-dedup: pypi manifest range lower bound is dropped when the installed sibling exists =="
# Regression for the SCA-benchmark py-range report: cdxgen (after build-prep's
# `pip install`) emits BOTH the requirements.txt range lower bound (flask@2.0,
# carrying cdx:pypi:versionSpecifiers) and the installed version (flask@3.1.3).
# The lower bound is a constraint, not an installed artifact — it must be dropped so
# it stops producing a duplicate component and phantom CVEs. urllib3 (installed only,
# no range sibling) must survive; left-pad (npm, has a specifier but is NOT pypi)
# must survive — the fix is pypi-scoped.
cp "$FIX/py-range-duplicate.json" "$WORK/pr.json"
bash "$LIB/normalize-sbom.sh" "$WORK/pr.json" >/dev/null 2>&1
present() { jq -e --arg p "$1" '[.components[].purl] | index($p) != null' "$WORK/pr.json" >/dev/null 2>&1; }
if ! present "pkg:pypi/flask@2.0"; then pass "flask range lower bound (2.0) dropped"; else fail "flask@2.0 still present"; fi
if present "pkg:pypi/flask@3.1.3"; then pass "flask installed version (3.1.3) kept"; else fail "flask@3.1.3 was dropped"; fi
if ! present "pkg:pypi/requests@2.25"; then pass "requests range lower bound (2.25) dropped"; else fail "requests@2.25 still present"; fi
if present "pkg:pypi/urllib3@2.7.0"; then pass "urllib3 (installed only, no range sibling) kept"; else fail "urllib3@2.7.0 was over-dropped"; fi
if present "pkg:npm/left-pad@1.3.0"; then pass "npm component with a specifier is untouched (pypi-scoped)"; else fail "left-pad dropped — fix is not pypi-scoped"; fi
pr_count=$(jq '.components | length' "$WORK/pr.json")
[ "$pr_count" = "4" ] && pass "component count 6 -> 4 (two phantom range bounds removed)" || fail "component count=$pr_count, expected 4"
pr_specs=$(jq '[.components[] | select((.purl|startswith("pkg:pypi/")) and ((.properties//[])[]?|select(.name=="cdx:pypi:versionSpecifiers")))] | length' "$WORK/pr.json")
[ "$pr_specs" = "0" ] && pass "no pypi component retains a versionSpecifiers range bound" || fail "$pr_specs pypi range bound(s) remain"
pr_dangling=$(jq '[.dependencies[]? | (.ref, (.dependsOn[]?)) | select(test("pkg:pypi/(flask@2.0|requests@2.25)$"))] | length' "$WORK/pr.json")
[ "$pr_dangling" = "0" ] && pass "dependency graph has no dangling refs to dropped components" || fail "$pr_dangling dangling dependency ref(s) remain"

echo "== os-src: deb/apk/rpm components get aquasecurity:trivy:Src* for Trivy CVE matching =="
# Regression for the SCA-benchmark os-vuln-zero report: Trivy matches distro
# advisories by SOURCE package name, which it only reads from its own
# aquasecurity:trivy:SrcName property — the `upstream` purl qualifier syft emits
# is ignored, so a syft-generated container SBOM scanned with `trivy sbom` got
# the distro and packages recognized but ZERO OS vulnerabilities, silently.
# normalize-sbom.sh must synthesize Src* from the purl.
cp "$FIX/os-pkgs-src.json" "$WORK/os.json"
bash "$LIB/normalize-sbom.sh" "$WORK/os.json" >/dev/null 2>&1
srcprop() { jq -r --arg n "$1" --arg p "aquasecurity:trivy:$2" \
    '[.components[] | select(.name==$n) | (.properties // [])[] | select(.name==$p) | .value] | first // "ABSENT"' "$WORK/os.json"; }
[ "$(srcprop libssl3 SrcName)" = "openssl" ] && pass "deb: SrcName from upstream qualifier (libssl3 -> openssl)" || fail "libssl3 SrcName='$(srcprop libssl3 SrcName)', expected openssl"
[ "$(srcprop libssl3 SrcVersion)" = "3.0.17" ] && pass "deb: SrcVersion split from version" || fail "libssl3 SrcVersion='$(srcprop libssl3 SrcVersion)', expected 3.0.17"
[ "$(srcprop libssl3 SrcRelease)" = "1~deb12u3" ] && pass "deb: SrcRelease split from version" || fail "libssl3 SrcRelease='$(srcprop libssl3 SrcRelease)', expected 1~deb12u3"
[ "$(srcprop base-files SrcName)" = "base-files" ] && pass "deb: SrcName falls back to package name (no upstream)" || fail "base-files SrcName='$(srcprop base-files SrcName)'"
[ "$(srcprop base-files SrcVersion)" = "12.4+deb12u12" ] && pass "deb: native version kept whole (no revision)" || fail "base-files SrcVersion='$(srcprop base-files SrcVersion)'"
[ "$(srcprop base-files SrcRelease)" = "ABSENT" ] && pass "deb: no SrcRelease for a native package" || fail "base-files SrcRelease='$(srcprop base-files SrcRelease)', expected absent"
[ "$(srcprop dash SrcEpoch)" = "1" ] && pass "deb: epoch split out of the version (1:0.5.12-2)" || fail "dash SrcEpoch='$(srcprop dash SrcEpoch)', expected 1"
[ "$(srcprop dash SrcVersion)" = "0.5.12" ] && pass "deb: epoch-stripped SrcVersion" || fail "dash SrcVersion='$(srcprop dash SrcVersion)', expected 0.5.12"
[ "$(srcprop libgtk2.0-0 SrcName)" = "gtk+2.0" ] && pass "deb: percent-encoded upstream decoded (gtk%2B2.0 -> gtk+2.0)" || fail "libgtk2.0-0 SrcName='$(srcprop libgtk2.0-0 SrcName)', expected gtk+2.0"
[ "$(srcprop libgtk2.0-0 SrcVersion)" = "2.24.33" ] && pass "deb: source version taken from upstream@version" || fail "libgtk2.0-0 SrcVersion='$(srcprop libgtk2.0-0 SrcVersion)', expected 2.24.33"
[ "$(srcprop libcrypto3 SrcName)" = "openssl" ] && pass "apk: SrcName from upstream (libcrypto3 -> openssl)" || fail "libcrypto3 SrcName='$(srcprop libcrypto3 SrcName)'"
[ "$(srcprop libcrypto3 SrcVersion)" = "3.0.8-r3" ] && pass "apk: version kept whole (no release split)" || fail "libcrypto3 SrcVersion='$(srcprop libcrypto3 SrcVersion)', expected 3.0.8-r3"
[ "$(srcprop openssl-libs SrcName)" = "openssl" ] && pass "rpm: SrcName parsed from source-RPM filename" || fail "openssl-libs SrcName='$(srcprop openssl-libs SrcName)', expected openssl"
[ "$(srcprop openssl-libs SrcVersion)" = "3.0.1" ] && pass "rpm: SrcVersion parsed from source-RPM filename" || fail "openssl-libs SrcVersion='$(srcprop openssl-libs SrcVersion)', expected 3.0.1"
[ "$(srcprop openssl-libs SrcRelease)" = "43.el9_0" ] && pass "rpm: SrcRelease parsed from source-RPM filename" || fail "openssl-libs SrcRelease='$(srcprop openssl-libs SrcRelease)', expected 43.el9_0"
[ "$(srcprop openssl-libs SrcEpoch)" = "1" ] && pass "rpm: SrcEpoch from the epoch qualifier" || fail "openssl-libs SrcEpoch='$(srcprop openssl-libs SrcEpoch)', expected 1"
[ "$(srcprop pre-enriched SrcName)" = "custom-src" ] && pass "existing SrcName left untouched (Trivy-generated SBOMs)" || fail "pre-enriched SrcName='$(srcprop pre-enriched SrcName)', expected custom-src"
pre_n=$(jq '[.components[] | select(.name=="pre-enriched") | (.properties // [])[] | select(.name=="aquasecurity:trivy:SrcName")] | length' "$WORK/os.json")
[ "$pre_n" = "1" ] && pass "no duplicate SrcName added to a pre-enriched component" || fail "pre-enriched has $pre_n SrcName properties, expected 1"
npm_n=$(jq '[.components[] | select(.name=="lodash") | (.properties // [])[] | select(.name | startswith("aquasecurity:trivy:"))] | length' "$WORK/os.json")
[ "$npm_n" = "0" ] && pass "non-OS purl (npm) untouched" || fail "lodash got $npm_n trivy propert(ies), expected 0"
bash "$LIB/normalize-sbom.sh" "$WORK/os.json" >/dev/null 2>&1
total_src=$(jq '[.components[].properties[]? | select(.name=="aquasecurity:trivy:SrcName")] | length' "$WORK/os.json")
[ "$total_src" = "7" ] && pass "idempotent: second normalize adds no duplicate properties" || fail "SrcName count after 2nd run = $total_src, expected 7"

echo "== sec-fail: a failed Trivy run is recorded in the report, not passed off as 0 findings =="
# Regression for the SCA-benchmark follow-up report: any Trivy failure (SBOM
# decode error, vulnerability-DB download failure) was swallowed as a WARN and
# the report came back {"Results":[]} — indistinguishable from a clean scan.
# scan-security.sh must stamp a ScanError marker and say so in the MD/HTML.
FAKEBIN="$WORK/fakebin"
mkdir -p "$FAKEBIN"
cat > "$FAKEBIN/trivy" <<'SH'
#!/bin/sh
echo "2026-07-03T00:00:00Z	FATAL	Fatal error	run error: sbom scan error: SBOM decode error: CycloneDX decode error: invalid specification version" >&2
exit 1
SH
chmod +x "$FAKEBIN/trivy"
echo '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}' > "$WORK/secfail-bom.json"
PATH="$FAKEBIN:$PATH" SECURITY_ENRICH=false \
    bash "$LIB/scan-security.sh" "$WORK/secfail-bom.json" "$WORK/secfail" proj >/dev/null 2>&1 \
    || fail "scan-security.sh exited non-zero on an engine failure (must stay report-only)"
err_msg=$(jq -r '.ScanError.Message // "ABSENT"' "$WORK/secfail_security.json")
case "$err_msg" in
    *"invalid specification version"*) pass "ScanError.Message carries the Trivy fatal line" ;;
    *) fail "ScanError.Message='$err_msg', expected the Trivy fatal line" ;;
esac
[ "$(jq -r '.ScanError.Engine // "ABSENT"' "$WORK/secfail_security.json")" = "Trivy" ] \
    && pass "ScanError.Engine = Trivy" || fail "ScanError.Engine missing"
[ "$(jq '.Results | length' "$WORK/secfail_security.json")" = "0" ] \
    && pass "Results stays an empty array (downstream contract intact)" \
    || fail "Results is not an empty array on failure"
grep -q "Scan failed" "$WORK/secfail_security.md" \
    && pass "markdown report says the scan failed" \
    || fail "markdown report still reads like a clean 0-findings result"
grep -q "No known vulnerabilities found" "$WORK/secfail_security.md" \
    && fail "markdown report still claims 'No known vulnerabilities found' after a failure" \
    || pass "markdown report does not claim a clean result"
grep -q "Scan failed" "$WORK/secfail_security.html" \
    && pass "html report says the scan failed" \
    || fail "html report still reads like a clean 0-findings result"

echo "== sec-ok: a successful Trivy run gets no ScanError marker =="
cat > "$FAKEBIN/trivy" <<'SH'
#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    [ "$1" = "--output" ] && { out="$2"; shift; }
    shift
done
echo '{"SchemaVersion":2,"Results":[{"Target":"sbom","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-2020-1111","PkgName":"libfoo","InstalledVersion":"1.0","Severity":"LOW"}]}]}' > "$out"
exit 0
SH
chmod +x "$FAKEBIN/trivy"
PATH="$FAKEBIN:$PATH" SECURITY_ENRICH=false \
    bash "$LIB/scan-security.sh" "$WORK/secfail-bom.json" "$WORK/secok" proj >/dev/null 2>&1 \
    || fail "scan-security.sh failed on a successful engine run"
[ "$(jq -r 'has("ScanError")' "$WORK/secok_security.json")" = "false" ] \
    && pass "no ScanError on a successful run" || fail "ScanError present on a successful run"
[ "$(jq '[.Results[].Vulnerabilities[]?] | length' "$WORK/secok_security.json")" = "1" ] \
    && pass "findings intact on a successful run" || fail "findings lost on a successful run"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
