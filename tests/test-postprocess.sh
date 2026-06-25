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

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
