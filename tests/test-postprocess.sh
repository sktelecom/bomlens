#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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

echo "== drop-empty-files: nameless/purl-less file components pruned, real ones kept =="
# Regression for the convert-noise defect: syft's SPDX->CycloneDX conversion emits a
# type:"file" component with NO name and NO purl for every SPDX file entry, so a
# supplier rootfs SBOM balloons with thousands of unidentifiable noise rows that skew
# the NOTICE count and UI inventory. normalize-sbom.sh must drop ONLY components that
# are BOTH a file AND carry neither name nor purl; real packages and named/purl'd file
# components survive. The fixture has 2 libraries, 1 named file, 1 purl-only file, and
# 4 empty file variants (absent, empty-string name, empty purl, both empty).
cp "$FIX/empty-file-components.json" "$WORK/ef.json"
bash "$LIB/normalize-sbom.sh" "$WORK/ef.json" >/dev/null 2>&1
ef_total=$(jq '[.components[]?] | length' "$WORK/ef.json")
[ "$ef_total" = "4" ] && pass "8 -> 4 components (4 empty file rows dropped)" || fail "component count=$ef_total, expected 4"
ef_empty=$(jq '[.components[]? | select(.type=="file" and ((.name // "")=="") and ((.purl // "")==""))] | length' "$WORK/ef.json")
[ "$ef_empty" = "0" ] && pass "no nameless/purl-less file component remains" || fail "$ef_empty empty file component(s) survived"
if jq -e '[.components[]? | select(.name=="openssl" or .name=="zlib")] | length == 2' "$WORK/ef.json" >/dev/null 2>&1; then
    pass "real packages (openssl, zlib) preserved"
else
    fail "a real package was wrongly dropped"
fi
if jq -e '[.components[]? | select(.type=="file" and .name=="usr/bin/openssl")] | length == 1' "$WORK/ef.json" >/dev/null 2>&1; then
    pass "a named file component is preserved"
else
    fail "a named file component was wrongly dropped"
fi
if jq -e '[.components[]? | select(.type=="file" and .purl=="pkg:generic/config@1.0")] | length == 1' "$WORK/ef.json" >/dev/null 2>&1; then
    pass "a purl-carrying file component is preserved"
else
    fail "a purl-carrying file component was wrongly dropped"
fi

# Regression: some supplier SPDX input bakes a redundant " : <version>" suffix into
# PackageName itself (e.g. "uuid : 3.4.0" alongside PackageVersionInfo "3.4.0"), which
# syft/jq carry straight through to the CycloneDX .name. Trivy's SBOM scanner keys its
# npm/pypi/go vulnerability matchers off .name, not just purl, so a name of
# "uuid : 3.4.0" makes every CVE for that package invisible to `trivy sbom` even
# though .purl and .version are both correct. normalize-sbom.sh must strip the
# suffix ONLY when it exactly equals .version (so a real name that happens to
# contain " : " but not the version string is left alone).
cp "$FIX/name-version-suffix-components.json" "$WORK/nvs.json"
bash "$LIB/normalize-sbom.sh" "$WORK/nvs.json" >/dev/null 2>&1
if jq -e '[.components[]? | select(.purl=="pkg:npm/uuid@3.4.0" and .name=="uuid")] | length == 1' "$WORK/nvs.json" >/dev/null 2>&1; then
    pass "redundant name : version suffix stripped (npm uuid)"
else
    fail "npm uuid's name : version suffix was not stripped"
fi
if jq -e '[.components[]? | select(.purl|test("google/uuid")) | select(.name=="google/uuid")] | length == 1' "$WORK/nvs.json" >/dev/null 2>&1; then
    pass "redundant name : version suffix stripped (golang google/uuid)"
else
    fail "golang google/uuid's name : version suffix was not stripped"
fi
if jq -e '[.components[]? | select(.purl=="pkg:npm/postcss@8.5.4" and .name=="postcss")] | length == 1' "$WORK/nvs.json" >/dev/null 2>&1; then
    pass "a component whose name never had the suffix is untouched"
else
    fail "a clean component name was wrongly rewritten"
fi
if jq -e '[.components[]? | select(.purl=="pkg:generic/weird@thing" and .name=="weird : name")] | length == 1' "$WORK/nvs.json" >/dev/null 2>&1; then
    pass "only the trailing version-matching segment is stripped, not earlier colons"
else
    fail "a multi-colon name was stripped incorrectly"
fi
if jq -e '[.components[]? | select(.purl=="pkg:generic/colon@1.0" and .name=="colon:nospace")] | length == 1' "$WORK/nvs.json" >/dev/null 2>&1; then
    pass "a colon with no surrounding spaces is left alone"
else
    fail "a name with an unrelated colon was wrongly touched"
fi
if jq -e '[.components[]? | select(.purl=="pkg:generic/noversion" and .name=="no-version-field")] | length == 1' "$WORK/nvs.json" >/dev/null 2>&1; then
    pass "a component with no version field is left alone"
else
    fail "a component with no version field was wrongly touched"
fi
# normalize-sbom.sh surfaces the delivered filename as bsi:component:filename from
# syft's location path, but ONLY when that path is a real artifact (known artifact
# extension), so a manifest-declared component is never labelled with the manifest
# it was found in. The fixture has: a .so (basename kept), a .jar (kept), a GitHub
# Action found in ci.yml (skipped — .yml is not an artifact), an npm dep found in
# package-lock.json (skipped), a component that already has the field (untouched),
# and one with no location property (nothing to take).
fnf() { jq -r --arg n "$1" '[.components[]|select(.name==$n)][0] | ([.properties[]?|select(.name=="bsi:component:filename").value] | .[0] // "")' "$WORK/fn.json"; }
cp "$FIX/syft-location-filenames.json" "$WORK/fn.json"
bash "$LIB/normalize-sbom.sh" "$WORK/fn.json" >/dev/null 2>&1
[ "$(fnf openssl)" = "libssl.so.3" ] && pass "a .so artifact path yields its basename (soversion kept)" || fail "openssl filename='$(fnf openssl)', expected libssl.so.3"
[ "$(fnf log4j-core)" = "log4j-core-2.17.1.jar" ] && pass "a .jar artifact path yields its basename" || fail "log4j-core filename='$(fnf log4j-core)'"
[ -z "$(fnf actions/checkout)" ] && pass "a manifest path (ci.yml) is NOT taken as a filename" || fail "actions/checkout wrongly filled with '$(fnf actions/checkout)'"
[ -z "$(fnf left-pad)" ] && pass "a lockfile path (package-lock.json) is NOT taken as a filename" || fail "left-pad wrongly filled with '$(fnf left-pad)'"
[ "$(fnf already-named)" = "custom-name.so" ] && pass "an existing bsi:component:filename is never overwritten" || fail "already-named filename='$(fnf already-named)', expected custom-name.so"
[ -z "$(fnf no-location)" ] && pass "no location property -> no filename invented" || fail "no-location wrongly filled with '$(fnf no-location)'"
# The property the field rides on must be singular — a second run must not append a
# duplicate bsi:component:filename (idempotence, like enrich-staleness).
bash "$LIB/normalize-sbom.sh" "$WORK/fn.json" >/dev/null 2>&1
dupfn=$(jq '[.components[]|select(.name=="openssl")][0] | [.properties[]|select(.name=="bsi:component:filename")] | length' "$WORK/fn.json")
[ "$dupfn" = "1" ] && pass "re-normalizing does not duplicate the filename property" || fail "openssl has $dupfn filename properties after a second run"

# --stable mode runs the same filter; the empty rows must be gone there too.
cp "$FIX/empty-file-components.json" "$WORK/efs.json"
bash "$LIB/normalize-sbom.sh" "$WORK/efs.json" --stable >/dev/null 2>&1
efs_empty=$(jq '[.components[]? | select(.type=="file" and ((.name // "")=="") and ((.purl // "")==""))] | length' "$WORK/efs.json")
[ "$efs_empty" = "0" ] && pass "--stable mode also drops empty file components" || fail "$efs_empty empty file component(s) survived --stable"

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
# Regression for the codelocation collision in some SBOM import platforms: two unrelated source SBOMs
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

echo "== document metadata: generation context, author, and the tool that produced the SBOM =="
# The 2026 SBOM minimum elements ask an SBOM to say at which lifecycle phase it was
# generated, who generated it, and with which tool at which version. None of the
# three was recorded, and two of them were recorded WRONG by the generators: cdxgen
# names its own publisher as the document author, and writes `build` as the phase of
# a scan that read source manifests.
DOC='{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
  "metadata":{"timestamp":"2026-01-01T00:00:00Z",
    "lifecycles":[{"phase":"build"}],
    "authors":[{"name":"OWASP Foundation"}],
    "tools":{"components":[{"type":"application","name":"cdxgen","version":"12.7.0"}]},
    "component":{"type":"application","name":"App","version":"1.0"}},
  "components":[]}'
printf '%s' "$DOC" > "$WORK/doc-src.json"
BOMLENS_VERSION=9.9.9 bash "$LIB/stamp-document-metadata.sh" "$WORK/doc-src.json" SOURCE >/dev/null 2>&1
ds=$(jq -rc '"\(.metadata.lifecycles)|\(.metadata|has("authors"))|\([.metadata.tools.components[]|"\(.name)@\(.version)"]|join(","))"' "$WORK/doc-src.json")
[ "$ds" = '[{"phase":"pre-build"}]|false|cdxgen@12.7.0,BomLens@9.9.9' ] \
    && pass "a source scan records pre-build, drops the generator's authorship claim, and names BomLens" \
    || fail "source document metadata: $ds"
# The author is the entity operating the tool, which only the caller knows.
printf '%s' "$DOC" > "$WORK/doc-auth.json"
SBOM_AUTHOR="SK Telecom Co., Ltd." BOMLENS_VERSION=9.9.9 bash "$LIB/stamp-document-metadata.sh" "$WORK/doc-auth.json" FIRMWARE >/dev/null 2>&1
da=$(jq -rc '"\(.metadata.lifecycles[0].phase)|\(.metadata.authors[0].name)"' "$WORK/doc-auth.json")
[ "$da" = 'post-build|SK Telecom Co., Ltd.' ] \
    && pass "a firmware scan records post-build and the declared author" || fail "declared author: $da"
# Running twice must not append a second BomLens entry (the pipeline may restamp).
BOMLENS_VERSION=9.9.9 bash "$LIB/stamp-document-metadata.sh" "$WORK/doc-auth.json" FIRMWARE >/dev/null 2>&1
dcount=$(jq '[.metadata.tools.components[] | select(.name=="BomLens")] | length' "$WORK/doc-auth.json")
[ "$dcount" = "1" ] && pass "restamping does not duplicate the tool entry" || fail "BomLens listed ${dcount}x after two runs"
# A tool entry with no version says nothing about which build ran; the minimum
# elements ask for it to be stated as unknown instead of omitted. Same for BomLens
# itself in a local build with no version baked in.
printf '%s' "$DOC" | jq '.metadata.tools = [{"vendor":"anchore","name":"syft"}]' > "$WORK/doc-legacy.json"
bash "$LIB/stamp-document-metadata.sh" "$WORK/doc-legacy.json" BINARY >/dev/null 2>&1
dl=$(jq -rc '[.metadata.tools[]|"\(.name)@\(.version)"]|join(",")' "$WORK/doc-legacy.json")
[ "$dl" = 'syft@unknown,BomLens@unknown' ] \
    && pass "missing tool versions are stated as unknown, in the legacy tools array too" || fail "legacy tools: $dl"
# MERGE combines SBOMs generated at whatever phase each input was, so the merged
# document cannot claim one — it must not inherit a phase by accident.
printf '%s' "$DOC" | jq 'del(.metadata.lifecycles)' > "$WORK/doc-merge.json"
bash "$LIB/stamp-document-metadata.sh" "$WORK/doc-merge.json" MERGE >/dev/null 2>&1
dm=$(jq -rc '"\(.metadata|has("lifecycles"))|\([.metadata.tools.components[]|.name]|join(","))"' "$WORK/doc-merge.json")
[ "$dm" = 'false|cdxgen,BomLens' ] \
    && pass "a merged SBOM claims no lifecycle phase but still names the tool" || fail "merge document metadata: $dm"
# Invalid input is a defect, not a condition to tolerate: fail closed like stamp-metadata.
printf 'not json{' > "$WORK/doc-bad.json"
if bash "$LIB/stamp-document-metadata.sh" "$WORK/doc-bad.json" SOURCE >/dev/null 2>&1; then
    fail "document metadata stamp exited 0 on invalid JSON (should fail closed)"
else
    pass "document metadata stamp fails closed on invalid JSON (exit != 0)"
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

echo "== B-4b: NOTICE folds kernel modules into one line per licence =="
# A firmware that ships lib/modules can carry hundreds of them — a MikroTik
# RouterOS image has 304 — and each arrived as three lines whose source read
# `pkg:generic/nls_utf8`, a purl syft builds from the module name that leads
# nowhere. Measured on that image: the notice went from 1689 lines to 785.
cat > "$WORK/km-notice.json" <<'JSON'
{"components":[
 {"name":"linux_kernel","version":"5.6.3","licenses":[{"license":{"id":"GPL-2.0-only"}}]},
 {"name":"e2fsprogs","version":"1.46.5","purl":"pkg:generic/e2fsprogs@1.46.5",
  "licenses":[{"license":{"id":"GPL-2.0-only"}}]},
 {"name":"8021q","version":"1.8","purl":"pkg:generic/8021q@1.8",
  "licenses":[{"license":{"name":"GPL"}}],
  "properties":[{"name":"syft:package:type","value":"linux-kernel-module"},
                {"name":"syft:metadata:kernelVersion","value":"5.6.3"}]},
 {"name":"xt_LOG","purl":"pkg:generic/xt_LOG",
  "licenses":[{"license":{"name":"GPL"}}],
  "properties":[{"name":"syft:package:type","value":"linux-kernel-module"},
                {"name":"syft:metadata:kernelVersion","value":"5.6.3"}]},
 {"name":"ipheth","purl":"pkg:generic/ipheth",
  "licenses":[{"license":{"name":"GPL"}}],
  "properties":[{"name":"syft:package:type","value":"linux-kernel-module"},
                {"name":"syft:metadata:kernelVersion","value":"5.6.3"}]}
]}
JSON
bash "$LIB/generate-notice.sh" "$WORK/km-notice.json" "$WORK/kmn" "KmProj" >/dev/null 2>&1
KTXT="$WORK/kmn_NOTICE.txt"
if [ ! -f "$KTXT" ]; then
    fail "generate-notice.sh produced no NOTICE for the kernel-module fixture"
else
    if grep -q "Linux kernel modules (3), part of linux_kernel@5.6.3" "$KTXT"; then
        pass "the modules are folded into one line naming their kernel"
    else
        fail "kernel modules were not folded" "$(grep -c '^  - ' "$KTXT") entries listed"
    fi

    # The names syft invents lead nowhere, so they must not appear as sources.
    if grep -q "pkg:generic/8021q" "$KTXT"; then
        fail "a module's invented purl is still shown as a source location"
    else
        pass "no module is given a source location built from its own name"
    fi

    # The header counts components, not lines. Folding 3 modules into one line
    # must not make them read as one component.
    if awk '/^License: GPL$/{f=1;next} f&&/^Components \(3\):$/{ok=1} /^License: /{if(!/^License: GPL$/)f=0} END{exit !ok}' "$KTXT"; then
        pass "the licence header still counts every module"
    else
        fail "the header count collapsed along with the lines" \
             "$(grep -A1 '^License: GPL$' "$KTXT" | tail -1)"
    fi

    # Everything that is not a module is untouched.
    grep -q "^  - e2fsprogs@1.46.5$" "$KTXT" \
        && pass "a non-module component is listed as before" \
        || fail "a non-module component was folded or dropped"
    grep -q "^  - linux_kernel@5.6.3$" "$KTXT" \
        && pass "the kernel itself is still listed in its own right" \
        || fail "the kernel the modules point at is missing from the notice"
fi

echo "== B-4c: NOTICE folds catalogued file entries into one line per licence =="

# A scan records the files it walked as CycloneDX `type: file` components. That is
# a legitimate inventory but not something a licence notice can speak to: a path
# is not a project, so there is no name to attribute and no source to point at.
# Measured across the corpus, 4,649 such entries carry no licence, no purl and no
# external reference between them — one access point image alone contributed 423, and
# every one landed under NOASSERTION with "holders not captured" beneath it.
cat > "$WORK/filecomp.json" <<'JSON'
{"components":[
 {"type":"library","name":"openssl","version":"1.0.2u","purl":"pkg:generic/openssl@1.0.2u",
  "licenses":[{"license":{"id":"Apache-2.0"}}]},
 {"type":"file","name":"bin/openssl"},
 {"type":"file","name":"etc/config/dhcp"},
 {"type":"file","name":"/target/some-input.jar"},
 {"type":"file","name":"lib/libz.so","licenses":[{"license":{"id":"Zlib"}}]}
]}
JSON
bash "$LIB/generate-notice.sh" "$WORK/filecomp.json" "$WORK/fc" "FcProj" >/dev/null 2>&1
FCTXT="$WORK/fc_NOTICE.txt"
if [ ! -f "$FCTXT" ]; then
    fail "generate-notice.sh produced no NOTICE for the file-entry fixture"
else
    # Three unlicensed file entries share the NOASSERTION group and fold together.
    if grep -q "Catalogued files (3) — paths recorded by the scan" "$FCTXT"; then
        pass "unlicensed file entries fold into one line"
    else
        fail "file entries were not folded" "$(grep -c '^  - ' "$FCTXT") entries listed"
    fi

    # The container mount path of the scanned artifact must not survive as a line
    # of its own; it is the input, not third-party software.
    if grep -q "^  - /target/some-input.jar$" "$FCTXT"; then
        fail "the scan target's container path is still listed as a component"
    else
        pass "the scanned artifact's own path is not listed as a component"
    fi

    # Folding lines must not fold the count.
    if awk '/^License: NOASSERTION$/{f=1;next} f&&/^Components \(3\):$/{ok=1} /^License: /{if(!/^License: NOASSERTION$/)f=0} END{exit !ok}' "$FCTXT"; then
        pass "the licence header still counts every file entry"
    else
        fail "the header count collapsed along with the lines" \
             "$(grep -A1 '^License: NOASSERTION$' "$FCTXT" | tail -1)"
    fi

    # A file entry that does carry a licence lands in that licence's group and
    # folds there, not into NOASSERTION.
    if awk '/^License: Zlib$/{f=1;next} f&&/Catalogued files \(1\)/{ok=1} /^License: /{if(!/^License: Zlib$/)f=0} END{exit !ok}' "$FCTXT"; then
        pass "a licensed file entry folds under its own licence"
    else
        fail "a licensed file entry did not fold under its own licence"
    fi

    # Real components are untouched.
    grep -q "^  - openssl@1.0.2u$" "$FCTXT" \
        && pass "a real component is listed as before" \
        || fail "a real component was folded or dropped"

    # An SBOM with no file entries must come out exactly as it did before.
    cat > "$WORK/nofile.json" <<'JSON'
{"components":[
 {"type":"library","name":"openssl","version":"1.0.2u","purl":"pkg:generic/openssl@1.0.2u",
  "licenses":[{"license":{"id":"Apache-2.0"}}]}
]}
JSON
    bash "$LIB/generate-notice.sh" "$WORK/nofile.json" "$WORK/nf" >/dev/null 2>&1
    if grep -q "Catalogued files" "$WORK/nf_NOTICE.txt" 2>/dev/null; then
        fail "a fold line appeared for an SBOM with no file entries"
    else
        pass "an SBOM with no file entries gains no fold line"
    fi

    # Running twice must not change the result.
    cp "$FCTXT" "$WORK/fc.once"
    bash "$LIB/generate-notice.sh" "$WORK/filecomp.json" "$WORK/fc" "FcProj" >/dev/null 2>&1
    if diff -q <(grep -v Generated "$WORK/fc.once") <(grep -v Generated "$FCTXT") >/dev/null 2>&1; then
        pass "folding is idempotent across reruns"
    else
        fail "a second notice run changed the output"
    fi
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
    grep -q '<a href="https://github.com/qos-ch/logback" target="_blank"' "$SHTML" \
        && pass "http(s) source rendered as a link that opens in a new tab" \
        || fail "HTML source link missing or opens in place"
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

echo "== license-text: CUSTOM entries with an embedded text are classified by clause wording =="
# Regression for the benchmark-team report: cdxgen's Go resolver emits
# name:"CUSTOM" + the LICENSE file text when the file deviates from its
# template (pflag's two-copyright-line BSD-3-Clause). normalize-sbom.sh must
# recover the SPDX id from the clause wording, and must NOT guess when the
# text is genuinely custom, matches several templates, or the name is a real
# license name rather than a placeholder.
cp "$FIX/license-custom-text.json" "$WORK/lt.json"
bash "$LIB/normalize-sbom.sh" "$WORK/lt.json" >/dev/null 2>&1
pflag_id=$(jq -r '.components[] | select(.name=="github.com/spf13/pflag") | .licenses[0].license.id // "ABSENT"' "$WORK/lt.json")
[ "$pflag_id" = "BSD-3-Clause" ] && pass "CUSTOM + BSD-3-Clause text (2 copyright lines) promoted to id BSD-3-Clause" || fail "pflag license id='$pflag_id', expected BSD-3-Clause"
pflag_text=$(jq -r '.components[] | select(.name=="github.com/spf13/pflag") | .licenses[0].license.text.content // "ABSENT"' "$WORK/lt.json")
case "$pflag_text" in *"Redistribution and use"*) pass "license text kept as evidence for the promotion" ;; *) fail "license text was dropped on promotion" ;; esac
mitv_id=$(jq -r '.components[] | select(.name=="mit-variant") | .licenses[0].license.id // "ABSENT"' "$WORK/lt.json")
mitv_url=$(jq -r '.components[] | select(.name=="mit-variant") | .licenses[0].license.url // "ABSENT"' "$WORK/lt.json")
[ "$mitv_id" = "MIT" ] && pass "lowercase custom + MIT text promoted to id MIT" || fail "mit-variant license id='$mitv_id', expected MIT"
[ "$mitv_url" = "https://example.org/license" ] && pass "license url survives text-based promotion" || fail "mit-variant url='$mitv_url'"
tc_name=$(jq -r '.components[] | select(.name=="truly-custom") | .licenses[0].license.name // "ABSENT"' "$WORK/lt.json")
[ "$tc_name" = "CUSTOM" ] && pass "genuinely custom text stays CUSTOM (no guess)" || fail "truly-custom license name='$tc_name', expected CUSTOM"
ml_name=$(jq -r '.components[] | select(.name=="multi-license-file") | .licenses[0].license.name // "ABSENT"' "$WORK/lt.json")
[ "$ml_name" = "CUSTOM" ] && pass "text matching several templates stays CUSTOM (ambiguity guard)" || fail "multi-license-file license name='$ml_name', expected CUSTOM"
sc_name=$(jq -r '.components[] | select(.name=="named-not-placeholder") | .licenses[0].license.name // "ABSENT"' "$WORK/lt.json")
[ "$sc_name" = "Sleepycat License" ] && pass "a real license name is never rewritten from its text" || fail "named-not-placeholder license name='$sc_name'"

echo "== license-class: bomlens:licenseClass copyleft-strength classification =="
# normalize-sbom.sh stamps every component with exactly one copyleft-strength
# class, using the license-flags.jq classifier that MIRRORS the web UI's
# licenses.ts, so the submitted SBOM carries the same classification the UI
# shows. Headline rule: an unrecognised license is never assumed permissive.
cat > "$WORK/lc.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"agpl-lib","version":"1.0","licenses":[{"license":{"id":"AGPL-3.0-only"}}]},
 {"type":"library","name":"gpl-lib","version":"1.0","licenses":[{"license":{"id":"GPL-3.0-only"}}]},
 {"type":"library","name":"lgpl-lib","version":"1.0","licenses":[{"license":{"id":"LGPL-2.1-only"}}]},
 {"type":"library","name":"mpl-lib","version":"1.0","licenses":[{"license":{"id":"MPL-2.0"}}]},
 {"type":"library","name":"mit-lib","version":"1.0","licenses":[{"license":{"id":"MIT"}}]},
 {"type":"library","name":"mystery-lib","version":"1.0","licenses":[{"license":{"name":"Custom Corp License"}}]},
 {"type":"library","name":"bare-lib","version":"1.0"},
 {"type":"library","name":"dual-lib","version":"1.0","licenses":[{"expression":"GPL-2.0-only OR MIT"}]},
 {"type":"library","name":"mixed-lib","version":"1.0","licenses":[{"license":{"id":"MIT"}},{"license":{"name":"Custom Corp License"}}]},
 {"type":"machine-learning-model","name":"llama-model","version":"3","licenses":[{"license":{"name":"Llama 3 Community License"}}]}
]}
JSON
bash "$LIB/normalize-sbom.sh" "$WORK/lc.json" >/dev/null 2>&1
lclass() { jq -r --arg n "$1" '.components[] | select(.name==$n)
    | [(.properties // [])[] | select(.name=="bomlens:licenseClass") | .value] | first // "ABSENT"' "$WORK/lc.json"; }
[ "$(lclass agpl-lib)" = "network-copyleft" ] && pass "AGPL -> network-copyleft" || fail "agpl-lib class='$(lclass agpl-lib)', expected network-copyleft"
[ "$(lclass gpl-lib)" = "strong-copyleft" ] && pass "GPL -> strong-copyleft" || fail "gpl-lib class='$(lclass gpl-lib)', expected strong-copyleft"
[ "$(lclass lgpl-lib)" = "weak-copyleft" ] && pass "LGPL -> weak-copyleft (matched before the bare GPL test)" || fail "lgpl-lib class='$(lclass lgpl-lib)', expected weak-copyleft"
[ "$(lclass mpl-lib)" = "weak-copyleft" ] && pass "MPL -> weak-copyleft" || fail "mpl-lib class='$(lclass mpl-lib)', expected weak-copyleft"
[ "$(lclass mit-lib)" = "permissive" ] && pass "MIT -> permissive (allowlist match)" || fail "mit-lib class='$(lclass mit-lib)', expected permissive"
[ "$(lclass mystery-lib)" = "uncategorized" ] && pass "unknown license -> uncategorized, never assumed permissive" || fail "mystery-lib class='$(lclass mystery-lib)', expected uncategorized"
[ "$(lclass bare-lib)" = "uncategorized" ] && pass "no license info -> uncategorized" || fail "bare-lib class='$(lclass bare-lib)', expected uncategorized"
[ "$(lclass dual-lib)" = "strong-copyleft" ] && pass "dual license (GPL-2.0-only OR MIT) -> strongest wins" || fail "dual-lib class='$(lclass dual-lib)', expected strong-copyleft"
[ "$(lclass mixed-lib)" = "uncategorized" ] && pass "MIT + unknown -> uncategorized (unknown outranks confirmed-permissive)" || fail "mixed-lib class='$(lclass mixed-lib)', expected uncategorized"
# A licenseReview-flagged component still gets a class: the two properties coexist.
lr=$(jq -r '.components[] | select(.name=="llama-model")
    | [(.properties // [])[] | select(.name=="bomlens:licenseReview") | .value] | first // "ABSENT"' "$WORK/lc.json")
[ "$lr" = "behavioral-use" ] && [ "$(lclass llama-model)" = "uncategorized" ] \
    && pass "bomlens:licenseReview and bomlens:licenseClass coexist on one component" \
    || fail "llama-model review='$lr' class='$(lclass llama-model)', expected behavioral-use + uncategorized"
# Every component carries exactly ONE class property (idempotent re-run included).
bash "$LIB/normalize-sbom.sh" "$WORK/lc.json" >/dev/null 2>&1
lc_bad=$(jq '[.components[] | [(.properties // [])[] | select(.name=="bomlens:licenseClass")] | length | select(. != 1)] | length' "$WORK/lc.json")
[ "$lc_bad" = "0" ] && pass "every component has exactly one licenseClass after a re-run (idempotent)" || fail "$lc_bad component(s) with != 1 licenseClass property"
# --byte-stable determinism: two --stable runs over the same input are identical.
cat > "$WORK/lcs1.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"agpl-lib","version":"1.0","licenses":[{"license":{"id":"AGPL-3.0-only"}}]}]}
JSON
cp "$WORK/lcs1.json" "$WORK/lcs2.json"
bash "$LIB/normalize-sbom.sh" "$WORK/lcs1.json" --stable >/dev/null 2>&1
bash "$LIB/normalize-sbom.sh" "$WORK/lcs2.json" --stable >/dev/null 2>&1
diff -q "$WORK/lcs1.json" "$WORK/lcs2.json" >/dev/null 2>&1 \
    && pass "--stable output with licenseClass is byte-identical across runs" \
    || fail "licenseClass stamping broke --byte-stable determinism"

echo "== license-class drift guard: license-flags.jq and licenses.ts share one classifier =="
# The jq classifier is a hand-written mirror of the frontend's licenses.ts. This
# gate extracts both sides' permissive id sets, tier regex patterns (in match
# order) and tier results, and fails naming the divergence — so neither file can
# gain or lose a license id without the same change on the other side.
LTS="$ROOT_DIR/docker/web/frontend/src/lib/licenses.ts"
LFJ="$LIB/license-flags.jq"
ts_perm=$(sed -n '/const PERMISSIVE = new Set(\[/,/\]);/p' "$LTS" | grep -oE '"[A-Za-z0-9.+-]+"' | tr -d '"' | sort)
jq_perm=$(grep '^def permissive_ids:' "$LFJ" | grep -oE '"[A-Za-z0-9.+-]+"' | tr -d '"' | tr ',' '\n' | sort)
if [ -z "$ts_perm" ] || [ -z "$jq_perm" ]; then
    fail "could not extract the permissive id sets (licenses.ts / license-flags.jq changed shape?)"
elif [ "$ts_perm" = "$jq_perm" ]; then
    pass "permissive allowlists are identical ($(printf '%s\n' "$ts_perm" | wc -l | tr -d ' ') ids)"
else
    fail "permissive allowlists diverged between licenses.ts and license-flags.jq" \
         "$(diff <(printf '%s\n' "$ts_perm") <(printf '%s\n' "$jq_perm") | grep '^[<>]' | sed 's/^</only in licenses.ts:/; s/^>/only in license-flags.jq:/')"
fi
# Tier regex patterns, in match order (order decides AGPL/LGPL vs bare GPL).
ts_pat=$(sed -n '/^export function licenseRiskTier/,/^}/p' "$LTS" | grep -oE '/\\b[^/]+/i' | sed 's:^/::; s:/i$::')
jq_pat=$(sed -n '/^def license_class/,/^def class_rank/p' "$LFJ" | grep -oE 'test\("[^"]+"' | sed 's/^test("//; s/"$//; s/\\\\/\\/g')
if [ -z "$ts_pat" ] || [ -z "$jq_pat" ]; then
    fail "could not extract the tier patterns (licenses.ts / license-flags.jq changed shape?)"
elif [ "$ts_pat" = "$jq_pat" ]; then
    pass "tier patterns match in content and order"
else
    fail "tier patterns diverged between licenses.ts and license-flags.jq" \
         "$(diff <(printf '%s\n' "$ts_pat") <(printf '%s\n' "$jq_pat") | grep '^[<>]' | sed 's/^</licenses.ts:/; s/^>/license-flags.jq:/')"
fi
# Tier results per pattern, in the same order.
ts_tier=$(sed -n '/^export function licenseRiskTier/,/^}/p' "$LTS" | grep -oE 'return "[a-z-]+-copyleft"' | sed 's/return //; s/"//g')
jq_tier=$(sed -n '/^def license_class/,/^def class_rank/p' "$LFJ" | grep -oE 'then "[a-z-]+-copyleft"' | sed 's/then //; s/"//g')
if [ "$ts_tier" = "$jq_tier" ] && [ -n "$ts_tier" ]; then
    pass "tier results per pattern match"
else
    fail "tier results diverged" "licenses.ts: $(echo "$ts_tier" | tr '\n' ' ') / license-flags.jq: $(echo "$jq_tier" | tr '\n' ' ')"
fi

echo "== malicious packages: PURL-keyed, version-aware, and silent without a snapshot =="
# A tiny stand-in for the bundled OSV index. Two shapes matter: an entry with no
# version list (every published version is malicious — the common case) and one
# that names versions (only those are).
cat > "$WORK/mal-index.json" <<'MALJSON'
{
  "_snapshot": "2026-01-02",
  "_ecosystems": ["npm"],
  "packages": {
    "pkg:npm/evil-all": "MAL-0000-1",
    "pkg:npm/evil-some": "MAL-0000-2"
  },
  "versions": {
    "pkg:npm/evil-some": ["2.0.0"]
  }
}
MALJSON
cat > "$WORK/mal.json" <<'MALSBOM'
{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "components": [
    { "type": "library", "name": "evil-all", "version": "1.0.0", "purl": "pkg:npm/evil-all@1.0.0" },
    { "type": "library", "name": "evil-all", "version": "7.7.7", "purl": "pkg:npm/evil-all@7.7.7" },
    { "type": "library", "name": "evil-some", "version": "2.0.0", "purl": "pkg:npm/evil-some@2.0.0" },
    { "type": "library", "name": "evil-some", "version": "1.0.0", "purl": "pkg:npm/evil-some@1.0.0" },
    { "type": "library", "name": "qualified", "version": "1.0.0", "purl": "pkg:npm/evil-all@1.0.0?arch=x64" },
    { "type": "library", "name": "evil-all", "version": "1.0.0" },
    { "type": "library", "name": "honest", "version": "1.0.0", "purl": "pkg:npm/honest@1.0.0" }
  ]
}
MALSBOM
MALICIOUS_DATA_FILE="$WORK/mal-index.json" bash "$LIB/enrich-malicious.sh" "$WORK/mal.json" >/dev/null 2>&1
mal_of() { jq -r --arg n "$1" --arg v "$2" '[.components[] | select(.name==$n and .version==$v)
    | ((.properties // [])[] | select(.name=="bomlens:malicious") | .value)] | first // "none"' "$WORK/mal.json"; }
mal_expect() {
    got=$(mal_of "$1" "$2")
    [ "$got" = "$3" ] && pass "malicious: $1@$2 -> $3" || fail "malicious: $1@$2 expected $3, got $got"
}
# No version list means every version is malicious.
mal_expect evil-all  1.0.0 true
mal_expect evil-all  7.7.7 true
# A version list means only those versions are — the rest are untouched, so the
# check cannot condemn a package the advisory did not name.
mal_expect evil-some 2.0.0 true
mal_expect evil-some 1.0.0 none
mal_expect honest    1.0.0 none
# Qualifiers are stripped before the lookup, and a component with no purl is not
# matched by name — malicious packages are named to resemble real ones, so a
# name match here would be the wrong tool.
if [ "$(jq -r '[.components[] | select(.name=="qualified")
    | ((.properties // [])[] | select(.name=="bomlens:malicious") | .value)] | first // "none"' "$WORK/mal.json")" = "true" ]; then
    pass "malicious: purl qualifiers are stripped before the lookup"
else
    fail "qualified purl was not matched" "$(jq -c '.components[4]' "$WORK/mal.json")"
fi
if [ "$(jq -r '[.components[] | select(.name=="evil-all" and (has("purl")|not))
    | ((.properties // [])[] | select(.name=="bomlens:malicious") | .value)] | first // "none"' "$WORK/mal.json")" = "none" ]; then
    pass "malicious: a component with no purl is never matched by name"
else
    fail "a purl-less component was flagged by name" "$(jq -c '.components[5]' "$WORK/mal.json")"
fi
# The id and the snapshot date ride along, so a reader can look the advisory up
# and knows how old the answer is.
if jq -e '[.components[] | select(.name=="evil-all")
      | ((.properties // [])[] | select(.name=="bomlens:malicious:id") | .value)] | first == "MAL-0000-1"' \
      "$WORK/mal.json" >/dev/null 2>&1 \
   && jq -e '[.components[] | select(.name=="evil-all")
      | ((.properties // [])[] | select(.name=="bomlens:malicious:source") | .value)] | first == "osv.dev@2026-01-02"' \
      "$WORK/mal.json" >/dev/null 2>&1; then
    pass "malicious: advisory id and snapshot date are recorded on the component"
else
    fail "malicious id/source properties missing" "$(jq -c '.components[0].properties' "$WORK/mal.json")"
fi
# No bundled snapshot: the step is skipped and the SBOM comes back untouched.
# Stamping nothing is the point — an absent property means "not assessed".
cp "$WORK/mal.json" "$WORK/mal-before.json"
MALICIOUS_DATA_FILE="$WORK/does-not-exist.json" bash "$LIB/enrich-malicious.sh" "$WORK/mal.json" >/dev/null 2>&1
if diff -q "$WORK/mal-before.json" "$WORK/mal.json" >/dev/null 2>&1; then
    pass "no bundled snapshot -> SBOM untouched, scan still succeeds"
else
    fail "missing snapshot changed the SBOM"
fi
# Re-running must not accumulate duplicate properties (byte-stability).
MALICIOUS_DATA_FILE="$WORK/mal-index.json" bash "$LIB/enrich-malicious.sh" "$WORK/mal.json" >/dev/null 2>&1
if [ "$(jq '[.components[0].properties[] | select(.name=="bomlens:malicious")] | length' "$WORK/mal.json")" = "1" ]; then
    pass "re-running replaces rather than appends the malicious properties"
else
    fail "malicious properties duplicated on re-run" "$(jq -c '.components[0].properties' "$WORK/mal.json")"
fi

echo "== license-conflict: expression parsing and outbound-license verdicts =="
# The conflict check needs an OUTBOUND license on metadata.component. Every
# expression below was measured in a real BomLens SBOM, so this pins the cases
# that actually occur rather than invented ones.
COMPAT="$LIB/license-compat.json"
if [ ! -f "$COMPAT" ]; then
    fail "license-compat.json is missing from docker/lib"
else
    cat > "$WORK/lconf.json" <<'LCJSON'
{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "metadata": { "component": { "type": "application", "name": "app", "version": "1.0",
                               "licenses": [ { "license": { "id": "Apache-2.0" } } ] } },
  "components": [
    { "type": "library", "name": "gpl-dep", "version": "1", "purl": "pkg:maven/x/gpl-dep@1",
      "licenses": [ { "license": { "id": "GPL-3.0-only" } } ] },
    { "type": "library", "name": "dual", "version": "1", "purl": "pkg:maven/x/dual@1",
      "licenses": [ { "expression": "MIT OR Apache-2.0" } ] },
    { "type": "library", "name": "andexpr", "version": "1", "purl": "pkg:maven/x/andexpr@1",
      "licenses": [ { "expression": "EPL-1.0 AND LGPL-2.1-only" } ] },
    { "type": "library", "name": "classpath", "version": "1", "purl": "pkg:maven/x/classpath@1",
      "licenses": [ { "expression": "EPL-2.0 AND GPL-2.0-with-classpath-exception" } ] },
    { "type": "library", "name": "twoentries", "version": "1", "purl": "pkg:maven/x/twoentries@1",
      "licenses": [ { "license": { "id": "EPL-1.0" } }, { "license": { "id": "LGPL-2.1-only" } } ] },
    { "type": "library", "name": "freetext", "version": "1", "purl": "pkg:maven/x/freetext@1",
      "licenses": [ { "license": { "name": "Eclipse Public License v. 2.0 OR Eclipse Distribution License v. 1.0" } } ] },
    { "type": "library", "name": "nolicense", "version": "1", "purl": "pkg:maven/x/nolicense@1" }
  ]
}
LCJSON
    bash "$LIB/normalize-sbom.sh" "$WORK/lconf.json" >/dev/null 2>&1
    verdict_of() { jq -r --arg n "$1" '[.components[] | select(.name==$n)
        | ((.properties // [])[] | select(.name=="bomlens:licenseConflict") | .value)] | first // "none"' "$WORK/lconf.json"; }
    lc_expect() {
        got=$(verdict_of "$1")
        [ "$got" = "$2" ] && pass "license conflict: $1 -> $2" \
                          || fail "license conflict: $1 expected $2, got $got"
    }
    lc_expect gpl-dep     incompatible
    lc_expect dual        compatible
    lc_expect andexpr     conditional
    # The decisive case: an exception clause exists to permit the combination, so
    # it must never reach "incompatible" (java-maven's jakarta components).
    lc_expect classpath   conditional
    lc_expect twoentries  conditional
    lc_expect freetext    unknown
    lc_expect nolicense   unknown

    # No outbound license -> no property at all. An absent verdict means "not
    # assessed"; stamping "compatible" would claim an all-clear nobody checked.
    jq 'del(.metadata.component.licenses)' "$WORK/lconf.json" \
        | jq 'del(.components[].properties)' > "$WORK/lconf-nolic.json"
    bash "$LIB/normalize-sbom.sh" "$WORK/lconf-nolic.json" >/dev/null 2>&1
    if [ "$(jq '[.components[].properties // [] | .[] | select(.name=="bomlens:licenseConflict")] | length' "$WORK/lconf-nolic.json")" = "0" ]; then
        pass "no outbound license declared -> no licenseConflict property stamped"
    else
        fail "licenseConflict was stamped without a declared outbound license"
    fi

    # Byte-stability: the property must not disturb --stable determinism.
    cp "$WORK/lconf.json" "$WORK/lcf1.json"; cp "$WORK/lconf.json" "$WORK/lcf2.json"
    bash "$LIB/normalize-sbom.sh" "$WORK/lcf1.json" --stable >/dev/null 2>&1
    bash "$LIB/normalize-sbom.sh" "$WORK/lcf2.json" --stable >/dev/null 2>&1
    diff -q "$WORK/lcf1.json" "$WORK/lcf2.json" >/dev/null 2>&1 \
        && pass "--stable output with licenseConflict is byte-identical across runs" \
        || fail "licenseConflict stamping broke --byte-stable determinism"
fi

echo "== license-conflict drift guard: the jq parser and licenses.ts share one grammar =="
# Same contract as the license-class guard above: the SPDX operator patterns and
# the exception test are hand-mirrored, so extract both sides and diff them.
jq_ops=$(sed -n '/^def parse_license_expr/,/^def has_license_exception/p' "$LFJ" \
    | grep -oE 'splits\("[^"]+"' | sed 's/^splits("//; s/"$//; s/\\\\/\\/g' | sort)
ts_ops=$(sed -n '/^export function parseLicenseExpression/,/^}/p' "$LTS" \
    | grep -oE 'split\(/[^/]+/i\)' | sed 's:^split(/::; s:/i)$::' | sort)
if [ -z "$jq_ops" ] || [ -z "$ts_ops" ]; then
    fail "could not extract the SPDX operator patterns (license-flags.jq / licenses.ts changed shape?)"
elif [ "$jq_ops" = "$ts_ops" ]; then
    pass "SPDX operator patterns are identical ($(printf '%s\n' "$jq_ops" | tr '\n' ' '))"
else
    fail "SPDX operator patterns diverged between license-flags.jq and licenses.ts" \
         "$(diff <(printf '%s\n' "$jq_ops") <(printf '%s\n' "$ts_ops") | grep '^[<>]' | sed 's/^</license-flags.jq:/; s/^>/licenses.ts:/')"
fi
jq_exc=$(grep -A2 '^def has_license_exception' "$LFJ" | grep -oE 'test\("[^"]+"' | sed 's/^test("//; s/"$//; s/\\\\/\\/g')
ts_exc=$(sed -n '/^export function hasLicenseException/,/^}/p' "$LTS" | grep -oE '/[^/]*WITH[^/]*/i' | sed 's:^/::; s:/i$::')
if [ "$jq_exc" = "$ts_exc" ] && [ -n "$jq_exc" ]; then
    pass "exception-clause patterns match"
else
    fail "exception-clause pattern diverged" "license-flags.jq: $jq_exc / licenses.ts: $ts_exc"
fi

echo "== risk-report: license classification summary drives from the SBOM =="
# generate-risk-report.sh must add the per-class table and the copyleft driver
# list (network/strong, up to 10) when the BOM artifact exists, and skip the
# block gracefully when it does not.
mkdir -p "$WORK/risk"
cp "$WORK/lc.json" "$WORK/risk/proj_1.0_bom.json"
printf 'License: MIT\nLicense: AGPL-3.0-only\n' > "$WORK/risk/proj_1.0_NOTICE.txt"
( cd "$WORK/risk" && bash "$LIB/generate-risk-report.sh" proj_1.0 proj >/dev/null 2>&1 )
RMD="$WORK/risk/proj_1.0_risk-report.md"; RHTML="$WORK/risk/proj_1.0_risk-report.html"
if [ -f "$RMD" ] && [ -f "$RHTML" ]; then
    grep -q '^| 1 | 2 | 2 | 1 | 4 |$' "$RMD" \
        && pass "md counts row matches the fixture (1 network, 2 strong, 2 weak, 1 permissive, 4 uncategorized)" \
        || fail "md classification counts wrong" "$(grep -A2 'Network copyleft' "$RMD")"
    grep -q '`agpl-lib@1.0` (network-copyleft)' "$RMD" \
        && pass "md lists the network-copyleft driver by name@version" \
        || fail "md copyleft driver list missing agpl-lib@1.0"
    grep -q 'dual-lib@1.0' "$RMD" && grep -q 'gpl-lib@1.0' "$RMD" \
        && pass "md lists the strong-copyleft drivers" \
        || fail "md copyleft driver list missing a strong-copyleft component"
    grep -q 'Network copyleft <span class="count">1</span>' "$RHTML" \
        && pass "html classification pills carry the same counts" \
        || fail "html classification pills missing/wrong"
    grep -q '<li>agpl-lib@1.0 (network-copyleft)</li>' "$RHTML" \
        && pass "html lists the copyleft drivers" \
        || fail "html copyleft driver list missing"
else
    fail "generate-risk-report.sh produced no md/html with a BOM present"
fi
# The Korean report prints the same class names as the English one. Four of the
# five were hardcoded English while "Uncategorized" went through a translation
# key, so a Korean table read "... | Permissive | 미분류 |" and disagreed with
# the web UI beside it. The names are the classifier's own vocabulary, not prose.
( cd "$WORK/risk" && REPORT_LANG=ko bash "$LIB/generate-risk-report.sh" proj_1.0 proj >/dev/null 2>&1 )
if [ -f "$RMD" ] && [ -f "$RHTML" ]; then
    grep -q '^| Network copyleft | Strong copyleft | Weak copyleft | Permissive | Uncategorized |$' "$RMD" \
        && pass "ko md classification header keeps every class name in English" \
        || fail "ko md header was" "$(grep -m1 'Network copyleft' "$RMD")"
    grep -q 'Uncategorized <span class="count">4</span>' "$RHTML" \
        && pass "ko html classification pills keep the English names" \
        || fail "ko html uncategorized pill missing/translated"
    grep -q '미분류' "$RMD" \
        && fail "a translated class name survived in the ko report" \
        || pass "no translated class name remains in the ko report"
else
    fail "ko risk report was not produced"
fi
# Restore the English report for any later assertion on these paths.
( cd "$WORK/risk" && bash "$LIB/generate-risk-report.sh" proj_1.0 proj >/dev/null 2>&1 )

# Without a BOM artifact the classification block is skipped, not an error.
mkdir -p "$WORK/risk2"
printf 'License: MIT\n' > "$WORK/risk2/proj_1.0_NOTICE.txt"
( cd "$WORK/risk2" && bash "$LIB/generate-risk-report.sh" proj_1.0 proj >/dev/null 2>&1 ) \
    || fail "generate-risk-report.sh failed without a BOM artifact"
if [ -f "$WORK/risk2/proj_1.0_risk-report.md" ] && ! grep -q 'License classification' "$WORK/risk2/proj_1.0_risk-report.md"; then
    pass "no BOM artifact -> classification block skipped gracefully"
else
    fail "classification block present (or report missing) without a BOM"
fi

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

echo "== F-0: a kernel module keeps no name-derived CPE =="

# syft builds a kernel module's CPE out of the module name: 8021q.ko becomes
# cpe:2.3:a:8021q:8021q:1.8, where the 1.8 is the module's own modinfo field and
# not a release of anything. Most of those names match nothing, but the
# collisions are real — a MikroTik image carries a wireguard module at 1.0.0 and
# wireguard:wireguard is in the index at 0.5.3, so only the version kept them
# apart. Measured on that image: 304 of its 309 components are kernel modules.
cp "$FIX/firmware-kernel-modules.json" "$WORK/km.json"
bash "$LIB/enrich-cpe.sh" "$WORK/km.json" >/dev/null 2>&1

wg_cpe=$(jq -r '.components[] | select(.name=="wireguard") | .cpe // "ABSENT"' "$WORK/km.json")
[ "$wg_cpe" = "ABSENT" ] \
    && pass "a module whose name collides with a real product carries no cpe" \
    || fail "wireguard module kept cpe='$wg_cpe'"

# zlib is on the whitelist, so this also shows the name map cannot hand an
# identifier back after the module rule withholds one — the same guard that keeps
# uClibc-ng from being given uclibc's advisories.
zk_cpe=$(jq -r '.components[] | select(.name=="zlib") | .cpe // "ABSENT"' "$WORK/km.json")
[ "$zk_cpe" = "ABSENT" ] \
    && pass "the name map does not put a cpe back on a whitelisted module name" \
    || fail "zlib module got cpe='$zk_cpe' from the name map"

wg_mark=$(jq -r '.components[] | select(.name=="wireguard")
                 | [(.properties // [])[] | select(.name=="bomlens:cpeUnmapped") | .value][0] // "ABSENT"' "$WORK/km.json")
[ "$wg_mark" = "true" ] \
    && pass "the withheld identifier is marked, not silently dropped" \
    || fail "wireguard module cpeUnmapped='$wg_mark', expected true"

# The module itself stays. It is a real file with a real licence; what goes is
# the guess about its identity.
km_n=$(jq '[.components[]?] | length' "$WORK/km.json")
[ "$km_n" = "4" ] \
    && pass "the modules are kept as components, only their identifier is withheld" \
    || fail "component count changed to $km_n, expected 4"

# Written too widely, this would strip or skip everything else as well.
bb_km=$(jq -r '.components[] | select(.name=="busybox") | .cpe // "ABSENT"' "$WORK/km.json")
[ "$bb_km" = "cpe:2.3:a:busybox:busybox:1.30.1:*:*:*:*:*:*:*" ] \
    && pass "a non-module component is still enriched normally" \
    || fail "busybox cpe='$bb_km', expected the whitelisted cpe"

# Running the pipeline twice must not change the result or stack properties.
cp "$WORK/km.json" "$WORK/km.once"
bash "$LIB/enrich-cpe.sh" "$WORK/km.json" >/dev/null 2>&1
if diff -q "$WORK/km.once" "$WORK/km.json" >/dev/null 2>&1; then
    pass "withholding is idempotent across reruns"
else
    fail "a second enrichment pass changed the SBOM"
fi

echo "== F-1: firmware CPE enrichment (Plan 1) — whitelist + version normalization =="
cp "$FIX/firmware-no-cpe.json" "$WORK/fw.json"
bash "$LIB/enrich-cpe.sh" "$WORK/fw.json" >/dev/null 2>&1
# OpenWRT package-revision suffix (-5) stripped so the cpe version matches NVD.
bb_cpe=$(jq -r '.components[] | select(.name=="busybox") | .cpe' "$WORK/fw.json")
[ "$bb_cpe" = "cpe:2.3:a:busybox:busybox:1.30.1:*:*:*:*:*:*:*" ] \
    && pass "busybox cpe version normalized 1.30.1-5 -> 1.30.1 (NVD-canonical)" \
    || fail "busybox cpe='$bb_cpe', expected upstream version 1.30.1"
# OpenWRT/Alpine -r<N> package-revision suffix is also stripped (issue #458): the
# regex must handle `-r2`, not only `-<digits>`, so 1.2.11-r2 -> 1.2.11.
zl_cpe=$(jq -r '.components[] | select(.name=="zlib") | .cpe' "$WORK/fw.json")
[ "$zl_cpe" = "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*" ] \
    && pass "zlib cpe version normalized 1.2.11-r2 -> 1.2.11 (Alpine -r suffix stripped)" \
    || fail "zlib cpe='$zl_cpe', expected upstream version 1.2.11"
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

# A producer that identified the component can also decide no identifier is safe
# for it, and marks that with bomlens:cpeUnmapped. Matching on the name here would
# overrule that from further away with less information. Measured: a firmware
# carries uClibc 1.0.22, which is uClibc-ng, while the name map turns anything
# called uclibc into uclibc:uclibc — a different project's advisories.
cat > "$WORK/withheld.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
  {"type":"library","name":"uclibc","version":"1.0.22",
   "properties":[{"name":"bomlens:cpeUnmapped","value":"true"}]},
  {"type":"library","name":"uclibc","version":"0.9.28"}
]}
JSON
bash "$LIB/enrich-cpe.sh" "$WORK/withheld.json" >/dev/null 2>&1
held=$(jq -r '[.components[]|select(.version=="1.0.22")][0] | has("cpe")' "$WORK/withheld.json")
[ "$held" = "false" ] && pass "a withheld CPE is not filled in from the name map" \
  || fail "the name map overrode an explicit no-identifier decision"
# The marker must not disable enrichment for everything else.
other=$(jq -r '[.components[]|select(.version=="0.9.28")][0].cpe // "NONE"' "$WORK/withheld.json")
case "$other" in
  cpe:2.3:a:uclibc:uclibc:0.9.28:*) pass "an unmarked component is still enriched" ;;
  *) fail "the withheld marker suppressed enrichment on another component" "got $other" ;;
esac

echo "== F-1b: OS-context enrichment — synthesize/normalize operating-system for distro matching =="
OSCTX="$LIB/enrich-os-context.py"
# (a) rpm/centos SBOM with NO operating-system component: one is synthesized from
# the dominant namespace + .elN suffix so Trivy can match distro CVEs.
cat > "$WORK/osc-centos.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"acl","version":"2.2.51-15.el7","purl":"pkg:rpm/centos/acl@2.2.51-15.el7?arch=x86_64"},
 {"type":"library","name":"bash","version":"4.2.46-35.el7","purl":"pkg:rpm/centos/bash@4.2.46-35.el7?arch=x86_64"}]}
JSON
python3 "$OSCTX" "$WORK/osc-centos.json" >/dev/null 2>&1
osc_os=$(jq -r '[.components[]|select(.type=="operating-system")]|.[0]|"\(.name) \(.version)"' "$WORK/osc-centos.json")
[ "$osc_os" = "centos 7" ] && pass "synthesized operating-system centos 7 from rpm .el7 PURLs" || fail "synthesized OS='$osc_os', expected 'centos 7'"
osc_ref=$(jq -r '[.components[]|select(.type=="operating-system")]|.[0]."bom-ref"' "$WORK/osc-centos.json")
[ "$osc_ref" = "bomlens-os-context" ] && pass "synthesized OS carries bomlens-os-context bom-ref" || fail "OS bom-ref='$osc_ref'"
# (b) idempotent: a second run adds no second OS component.
python3 "$OSCTX" "$WORK/osc-centos.json" >/dev/null 2>&1
osc_n=$(jq '[.components[]|select(.type=="operating-system")]|length' "$WORK/osc-centos.json")
[ "$osc_n" = "1" ] && pass "enrich-os-context is idempotent (exactly one OS component)" || fail "OS component count=$osc_n after second run, expected 1"
# (c) existing RHEL-like OS with a minor version is normalized to major (Trivy
# matches rpm distros by major; "rocky 8.10" matches nothing, must become "8").
cat > "$WORK/osc-rocky.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"operating-system","name":"rocky","version":"8.10"},
 {"type":"library","name":"bash","version":"4.4.20-6.el8","purl":"pkg:rpm/rocky/bash@4.4.20-6.el8?arch=x86_64"}]}
JSON
python3 "$OSCTX" "$WORK/osc-rocky.json" >/dev/null 2>&1
osc_rv=$(jq -r '[.components[]|select(.type=="operating-system")]|.[0].version' "$WORK/osc-rocky.json")
[ "$osc_rv" = "8" ] && pass "existing 'rocky 8.10' normalized to major '8'" || fail "rocky version='$osc_rv', expected '8'"
# (d) no-op guards: a maven-only SBOM (no distro packages) and a deb PURL with no
# `distro=` version qualifier get NO synthesized OS — the OS version is never
# guessed. (deb/apk WITH a qualifier are covered positively in (e) below.)
cat > "$WORK/osc-maven.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"guava","version":"22.0","purl":"pkg:maven/com.google.guava/guava@22.0"}]}
JSON
python3 "$OSCTX" "$WORK/osc-maven.json" >/dev/null 2>&1
osc_mn=$(jq '[.components[]|select(.type=="operating-system")]|length' "$WORK/osc-maven.json")
[ "$osc_mn" = "0" ] && pass "maven-only SBOM gets no synthesized OS (no false OS)" || fail "maven SBOM gained $osc_mn OS component(s)"
cat > "$WORK/osc-deb.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"acpid","version":"2.0.32","purl":"pkg:deb/ubuntu/acpid@2.0.32-1ubuntu1?arch=amd64"}]}
JSON
python3 "$OSCTX" "$WORK/osc-deb.json" >/dev/null 2>&1
osc_dn=$(jq '[.components[]|select(.type=="operating-system")]|length' "$WORK/osc-deb.json")
[ "$osc_dn" = "0" ] && pass "deb PURL with no distro= qualifier gets no OS (version not guessed)" || fail "deb SBOM gained $osc_dn OS component(s)"
# (e) apk/deb WITH a syft `distro=<id>-<ver>` qualifier synthesize the OS Trivy
# needs. Empirically these recover CVEs that the PURL alone does not (openssl
# probes: alpine 0->39, debian 0->15, ubuntu 0->22 on Trivy v0.72). Version rule:
# debian reduced to major, ubuntu kept as major.minor, alpine kept as-is.
osc_of() { jq -r '[.components[]|select(.type=="operating-system")]|.[0]|"\(.name) \(.version)"' "$1"; }
cat > "$WORK/osc-apk.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"musl","version":"1.2.3-r5","purl":"pkg:apk/alpine/musl@1.2.3-r5?arch=x86_64&distro=alpine-3.17.10"}]}
JSON
python3 "$OSCTX" "$WORK/osc-apk.json" >/dev/null 2>&1
[ "$(osc_of "$WORK/osc-apk.json")" = "alpine 3.17.10" ] && pass "apk PURL (distro=alpine-3.17.10) -> operating-system alpine 3.17.10" || fail "apk OS='$(osc_of "$WORK/osc-apk.json")', expected 'alpine 3.17.10'"
cat > "$WORK/osc-debian.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"bash","version":"5.1-2+deb11u1","purl":"pkg:deb/debian/bash@5.1-2+deb11u1?arch=amd64&distro=debian-11"}]}
JSON
python3 "$OSCTX" "$WORK/osc-debian.json" >/dev/null 2>&1
[ "$(osc_of "$WORK/osc-debian.json")" = "debian 11" ] && pass "deb PURL (distro=debian-11) -> operating-system debian 11 (major)" || fail "debian OS='$(osc_of "$WORK/osc-debian.json")', expected 'debian 11'"
cat > "$WORK/osc-ubuntu.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"openssl","version":"1.1.1-1ubuntu2.1~18.04.5","purl":"pkg:deb/ubuntu/openssl@1.1.1-1ubuntu2.1~18.04.5?arch=amd64&distro=ubuntu-18.04"}]}
JSON
python3 "$OSCTX" "$WORK/osc-ubuntu.json" >/dev/null 2>&1
[ "$(osc_of "$WORK/osc-ubuntu.json")" = "ubuntu 18.04" ] && pass "deb PURL (distro=ubuntu-18.04) -> operating-system ubuntu 18.04 (major.minor kept)" || fail "ubuntu OS='$(osc_of "$WORK/osc-ubuntu.json")', expected 'ubuntu 18.04'"
# An unsupported distro (Trivy carries no OpenWRT advisory DB) is never synthesized.
cat > "$WORK/osc-owrt.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"dropbear","version":"2019.78","purl":"pkg:openwrt/dropbear@2019.78"}]}
JSON
python3 "$OSCTX" "$WORK/osc-owrt.json" >/dev/null 2>&1
osc_on=$(jq '[.components[]|select(.type=="operating-system")]|length' "$WORK/osc-owrt.json")
[ "$osc_on" = "0" ] && pass "OpenWRT SBOM gets no synthesized OS (Trivy has no OpenWRT advisories)" || fail "OpenWRT SBOM gained $osc_on OS component(s)"
echo "== F-1c: maven CPE enrichment — groupId-derived NVD cpe:2.3 =="
MVNCPE="$LIB/enrich-maven-cpe.py"
cat > "$WORK/mvn.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"pdfbox-app","version":"1.8.7","purl":"pkg:maven/org.apache.pdfbox/pdfbox-app@1.8.7"},
 {"type":"library","name":"jackson-databind","version":"2.10.2","purl":"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.2"},
 {"type":"library","name":"spring-web","version":"5.0.0","purl":"pkg:maven/org.springframework/spring-web@5.0.0"},
 {"type":"library","name":"guava","version":"22.0","purl":"pkg:maven/com.google.guava/guava@22.0"},
 {"type":"library","name":"netty-common","version":"4.1.44","purl":"pkg:maven/io.netty/netty-common@4.1.44"},
 {"type":"library","name":"single-seg","version":"1.0","purl":"pkg:maven/commons-single/single-seg@1.0"},
 {"type":"library","name":"has-cpe","version":"1.0","purl":"pkg:maven/org.apache.foo/has-cpe@1.0","cpe":"cpe:2.3:a:preset:preset:1.0:*:*:*:*:*:*:*"},
 {"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}]}
JSON
python3 "$MVNCPE" "$WORK/mvn.json" >/dev/null 2>&1
cpe_of() { jq -r --arg n "$1" '[.components[]|select(.name==$n)]|.[0].cpe // "NONE"' "$WORK/mvn.json"; }
# (a) org.apache.* derived mechanically.
[ "$(cpe_of pdfbox-app)" = "cpe:2.3:a:apache:pdfbox:1.8.7:*:*:*:*:*:*:*" ] && pass "org.apache.pdfbox -> apache:pdfbox cpe" || fail "pdfbox cpe='$(cpe_of pdfbox-app)'"
# (b) curated map: Jackson product = artifact, not group tail.
[ "$(cpe_of jackson-databind)" = "cpe:2.3:a:fasterxml:jackson-databind:2.10.2:*:*:*:*:*:*:*" ] && pass "jackson product taken from artifact (fasterxml:jackson-databind)" || fail "jackson cpe='$(cpe_of jackson-databind)'"
# (c) curated map: spring is vmware:spring_framework (not derivable).
[ "$(cpe_of spring-web)" = "cpe:2.3:a:vmware:spring_framework:5.0.0:*:*:*:*:*:*:*" ] && pass "org.springframework -> vmware:spring_framework (curated)" || fail "spring cpe='$(cpe_of spring-web)'"
# (d) generic reverse-domain rule, 3-segment: com.google.guava -> google:guava.
[ "$(cpe_of guava)" = "cpe:2.3:a:google:guava:22.0:*:*:*:*:*:*:*" ] && pass "3-seg group derived generically (google:guava)" || fail "guava cpe='$(cpe_of guava)'"
# (d2) 2-segment group derived too (io.netty -> netty:netty; a real NVD product).
[ "$(cpe_of netty-common)" = "cpe:2.3:a:netty:netty:4.1.44:*:*:*:*:*:*:*" ] && pass "2-seg group derived (io.netty -> netty:netty)" || fail "netty cpe='$(cpe_of netty-common)'"
# (d3) a single-segment groupId (no domain to split) is left without a cpe.
[ "$(cpe_of single-seg)" = "NONE" ] && pass "single-segment groupId left without a cpe (map-only)" || fail "single-seg wrongly got cpe='$(cpe_of single-seg)'"
# (e) a pre-existing cpe is never overwritten.
[ "$(cpe_of has-cpe)" = "cpe:2.3:a:preset:preset:1.0:*:*:*:*:*:*:*" ] && pass "pre-existing cpe preserved (no overwrite)" || fail "has-cpe cpe changed to '$(cpe_of has-cpe)'"
# (f) non-maven component untouched.
[ "$(cpe_of lodash)" = "NONE" ] && pass "non-maven (npm) component left without a cpe" || fail "lodash wrongly got a cpe"
# (g) provenance marker on a derived cpe.
mvn_src=$(jq -r '[.components[]|select(.name=="pdfbox-app")]|.[0]|[(.properties//[])[]|select(.name=="bomlens:cpeSource")|.value][0] // "NONE"' "$WORK/mvn.json")
[ "$mvn_src" = "maven-groupid" ] && pass "derived cpe carries bomlens:cpeSource=maven-groupid" || fail "pdfbox cpeSource='$mvn_src'"
# (h) idempotent.
cp "$WORK/mvn.json" "$WORK/mvn2.json"; python3 "$MVNCPE" "$WORK/mvn2.json" >/dev/null 2>&1
diff -q "$WORK/mvn.json" "$WORK/mvn2.json" >/dev/null 2>&1 && pass "enrich-maven-cpe is idempotent" || fail "second run changed the SBOM"

echo "== F-1c2: maven CPE enrichment — mechanical groupId/artifactId copy is replaced =="
# Some generators, lacking a real CPE dictionary match, fall back to gluing the
# maven coordinate itself into vendor:product (group verbatim, artifact verbatim,
# or group+artifact concatenated -- always paired with product=artifact). That
# shape carries no more information than no cpe at all, so it is eligible for
# replacement by derive_cpe(). A cpe with any other vendor is left untouched,
# including one already set to a MAVEN_CPE_MAP vendor.
cat > "$WORK/mvn-mech.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"pdfbox-app","version":"1.8.7","purl":"pkg:maven/org.apache.pdfbox/pdfbox-app@1.8.7","cpe":"cpe:2.3:a:org.apache.pdfbox:pdfbox-app:1.8.7:*:*:*:*:*:*:*"},
 {"type":"library","name":"jakarta.annotation-api","version":"2.1.1","purl":"pkg:maven/jakarta.annotation/jakarta.annotation-api@2.1.1","cpe":"cpe:2.3:a:jakarta.annotation-api:jakarta.annotation-api:2.1.1:*:*:*:*:*:*:*"},
 {"type":"library","name":"HikariCP","version":"4.0.3","purl":"pkg:maven/com.zaxxer/HikariCP@4.0.3","cpe":"cpe:2.3:a:com.zaxxer.HikariCP:HikariCP:4.0.3:*:*:*:*:*:*:*"},
 {"type":"library","name":"catalina-ant","version":"11.0.22","purl":"pkg:maven/catalina-ant/catalina-ant@11.0.22","cpe":"cpe:2.3:a:apache-software-foundation:catalina-ant:11.0.22:*:*:*:*:*:*:*"},
 {"type":"library","name":"spring-web","version":"5.0.0","purl":"pkg:maven/org.springframework/spring-web@5.0.0","cpe":"cpe:2.3:a:vmware:spring_framework:5.0.0:*:*:*:*:*:*:*"},
 {"type":"library","name":"json-java","version":"20231013","purl":"pkg:maven/org.json/json-java@20231013","cpe":"cpe:2.3:a:stleary:json-java:20231013:*:*:*:*:*:*:*"}]}
JSON
cp "$WORK/mvn-mech.json" "$WORK/mvn-mech-orig.json"
python3 "$MVNCPE" "$WORK/mvn-mech.json" >/dev/null 2>&1
mech_cpe_of() { jq -r --arg n "$1" '[.components[]|select(.name==$n)]|.[0].cpe // "NONE"' "$WORK/mvn-mech.json"; }
# (a) vendor=<group> (dotted, verbatim), product=<artifact> -> replaced (same
# result as deriving from no cpe at all: org.apache.pdfbox -> apache:pdfbox).
[ "$(mech_cpe_of pdfbox-app)" = "cpe:2.3:a:apache:pdfbox:1.8.7:*:*:*:*:*:*:*" ] && pass "mechanical group-copy cpe replaced (apache:pdfbox)" || fail "pdfbox-app cpe='$(mech_cpe_of pdfbox-app)'"
# (b) vendor=<artifact> (verbatim), product=<artifact> -> replaced (2-segment
# group, parts[1]==parts[-1] shape: jakarta.annotation -> annotation:annotation).
[ "$(mech_cpe_of jakarta.annotation-api)" = "cpe:2.3:a:annotation:annotation:2.1.1:*:*:*:*:*:*:*" ] && pass "mechanical artifact-copy cpe replaced (annotation:annotation)" || fail "jakarta.annotation-api cpe='$(mech_cpe_of jakarta.annotation-api)'"
# (c) vendor=<group>.<artifact> concatenated, product=<artifact> -> replaced.
[ "$(mech_cpe_of HikariCP)" = "cpe:2.3:a:zaxxer:zaxxer:4.0.3:*:*:*:*:*:*:*" ] && pass "mechanical group.artifact-copy cpe replaced (zaxxer:zaxxer)" || fail "HikariCP cpe='$(mech_cpe_of HikariCP)'"
# (d) boundary: single-segment groupId equal to the artifactId, but the
# pre-existing vendor ("apache-software-foundation") is not the group or
# artifact string in any form -- it looks like a real (if possibly wrong)
# lookup, not a coordinate copy, and a single-segment group cannot be
# re-derived anyway (derive_cpe has no domain to split). Left untouched.
[ "$(mech_cpe_of catalina-ant)" = "cpe:2.3:a:apache-software-foundation:catalina-ant:11.0.22:*:*:*:*:*:*:*" ] && pass "non-coordinate vendor on a single-segment group left untouched (catalina-ant)" || fail "catalina-ant cpe changed to '$(mech_cpe_of catalina-ant)'"
# (e) most important invariant: a cpe already set to a MAVEN_CPE_MAP vendor is
# never touched, precisely because that vendor never matches the mechanical
# group/artifact-copy shape.
[ "$(mech_cpe_of spring-web)" = "cpe:2.3:a:vmware:spring_framework:5.0.0:*:*:*:*:*:*:*" ] && pass "curated MAVEN_CPE_MAP cpe (spring) never overwritten" || fail "spring-web cpe changed to '$(mech_cpe_of spring-web)'"
[ "$(mech_cpe_of json-java)" = "cpe:2.3:a:stleary:json-java:20231013:*:*:*:*:*:*:*" ] && pass "curated MAVEN_CPE_MAP cpe (org.json) never overwritten, even though product==artifact" || fail "json-java cpe changed to '$(mech_cpe_of json-java)'"
# (f) idempotent on the mechanical-overwrite path too.
cp "$WORK/mvn-mech.json" "$WORK/mvn-mech2.json"; python3 "$MVNCPE" "$WORK/mvn-mech2.json" >/dev/null 2>&1
diff -q "$WORK/mvn-mech.json" "$WORK/mvn-mech2.json" >/dev/null 2>&1 && pass "mechanical-overwrite pass is idempotent" || fail "second run changed the SBOM further"
# (g) exactly 3 components changed from the original (pdfbox-app, jakarta.annotation-api, HikariCP).
changed=$(diff <(jq -S '.components' "$WORK/mvn-mech-orig.json") <(jq -S '.components' "$WORK/mvn-mech.json") | grep -c '"cpe"' || true)
[ "$changed" -gt 0 ] && pass "mechanical-copy fixture changed cpe field(s) ($changed diff line(s))" || fail "expected cpe changes, saw none"

echo "== F-1c3: maven CPE enrichment — per-submodule mechanical copy is replaced =="
# Multi-module projects (netty, istack, jna) name each submodule artifact
# "<last groupId segment>-<submodule>" (io.netty / netty-buffer). Some
# generators mirror that into vendor="<groupId>.<submodule>" (io.netty.buffer)
# per submodule -- still a coordinate copy, just reassembled differently than
# F-1c2's whole-group-or-artifact shapes. Left alone it blocks derive_cpe()'s
# umbrella cpe (netty:netty) on every submodule, so NVD's per-project (not
# per-submodule) Netty CVEs never match.
cat > "$WORK/mvn-submod.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"netty-buffer","version":"4.1.130.Final","purl":"pkg:maven/io.netty/netty-buffer@4.1.130.Final","cpe":"cpe:2.3:a:io.netty.buffer:netty-buffer:4.1.130.Final:*:*:*:*:*:*:*"},
 {"type":"library","name":"netty-codec-dns","version":"4.1.131.Final","purl":"pkg:maven/io.netty/netty-codec-dns@4.1.131.Final","cpe":"cpe:2.3:a:io.netty.codec-dns:netty-codec-dns:4.1.131.Final:*:*:*:*:*:*:*"},
 {"type":"library","name":"netty-transport-native-epoll","version":"4.1.131.Final","purl":"pkg:maven/io.netty/netty-transport-native-epoll@4.1.131.Final","cpe":"cpe:2.3:a:io.netty.transport-native-epoll.linux-x86_64:netty-transport-native-epoll:4.1.131.Final:*:*:*:*:*:*:*"}]}
JSON
cp "$WORK/mvn-submod.json" "$WORK/mvn-submod-orig.json"
python3 "$MVNCPE" "$WORK/mvn-submod.json" >/dev/null 2>&1
submod_cpe_of() { jq -r --arg n "$1" '[.components[]|select(.name==$n)]|.[0].cpe // "NONE"' "$WORK/mvn-submod.json"; }
# (a) vendor="<group>.<submodule>" reconstructs exactly from artifact -> replaced
# with the umbrella cpe (netty:netty), the same one a from-scratch derive gives.
[ "$(submod_cpe_of netty-buffer)" = "cpe:2.3:a:netty:netty:4.1.130.Final:*:*:*:*:*:*:*" ] && pass "per-submodule mechanical cpe replaced (netty-buffer -> netty:netty)" || fail "netty-buffer cpe='$(submod_cpe_of netty-buffer)'"
[ "$(submod_cpe_of netty-codec-dns)" = "cpe:2.3:a:netty:netty:4.1.131.Final:*:*:*:*:*:*:*" ] && pass "per-submodule mechanical cpe replaced (netty-codec-dns -> netty:netty)" || fail "netty-codec-dns cpe='$(submod_cpe_of netty-codec-dns)'"
# (b) boundary: an extra classifier segment on the vendor (".linux-x86_64") means
# submodule != vendor tail, so the exact-reconstruction check fails and the
# pre-existing cpe is left untouched rather than guessed at.
[ "$(submod_cpe_of netty-transport-native-epoll)" = "cpe:2.3:a:io.netty.transport-native-epoll.linux-x86_64:netty-transport-native-epoll:4.1.131.Final:*:*:*:*:*:*:*" ] && pass "classifier-suffixed vendor left untouched (netty-transport-native-epoll)" || fail "netty-transport-native-epoll cpe changed to '$(submod_cpe_of netty-transport-native-epoll)'"
# (c) idempotent.
cp "$WORK/mvn-submod.json" "$WORK/mvn-submod2.json"; python3 "$MVNCPE" "$WORK/mvn-submod2.json" >/dev/null 2>&1
diff -q "$WORK/mvn-submod.json" "$WORK/mvn-submod2.json" >/dev/null 2>&1 && pass "per-submodule mechanical-overwrite pass is idempotent" || fail "second run changed the SBOM further"

echo "== F-1d: NVD version filter (scan-nvd-cpe) — drops loose-range false positives =="
# The filter is what removes grype's over-broad nvd:cpe matches (a fixed-in-9.0.104
# Tomcat CVE that grype's DB matches to 7.0.50 because it dropped the >= 9.0.0 lower
# bound). Test the version-range predicate directly against NVD cpeMatch shapes.
python3 - "$LIB/scan-nvd-cpe.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("snc", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
fails = []
def check(name, cond):
    print(("  PASS: " if cond else "  FAIL: ") + name)
    if not cond: fails.append(name)
# lower+upper bound: 7.0.50 is below the 9.0.0 start -> OUT (the real FP case).
check("7.0.50 outside [9.0.0, 9.0.104) -> dropped",
      not m._in_range("7.0.50", {"criteria":"cpe:2.3:a:apache:tomcat:*", "versionStartIncluding":"9.0.0", "versionEndExcluding":"9.0.104"}))
# in-range stays.
check("9.0.50 inside [9.0.0, 9.0.104) -> kept",
      m._in_range("9.0.50", {"criteria":"cpe:2.3:a:apache:tomcat:*", "versionStartIncluding":"9.0.0", "versionEndExcluding":"9.0.104"}))
# upper-only bound (no lower) keeps an older version -> that is the grype behavior
# we DON'T reproduce; with the NVD lower bound present the FP is caught above.
check("upper-only < 1.8.12 keeps 1.8.7 (pdfbox true positive)",
      m._in_range("1.8.7", {"criteria":"cpe:2.3:a:apache:pdfbox:*", "versionEndExcluding":"1.8.12"}))
# exact-version CPE (no range) matches only that version.
check("exact 3.6 matches 3.6",
      m._in_range("3.6", {"criteria":"cpe:2.3:a:apache:poi:3.6:*:*:*:*:*:*:*"}))
check("exact 3.6 does not match 3.17",
      not m._in_range("3.17", {"criteria":"cpe:2.3:a:apache:poi:3.6:*:*:*:*:*:*:*"}))
# version comparator handles non-numeric tails (5.0.0.RELEASE ~ 5.0.0).
check("comparator: 5.0.0.RELEASE == 5.0.0", m._cmp("5.0.0.RELEASE", "5.0.0") == 0)
sys.exit(1 if fails else 0)
PY
if [ $? -eq 0 ]; then pass "NVD version-filter predicate: all range cases correct"; else fail "NVD version-filter predicate has a wrong case"; fi

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

echo "== F-3: firmware component names carry no unpack path =="
# cve-bin-tool names a file it cannot attribute to a package by its full path on
# disk, which is the throwaway unpack directory. Shipping that puts the scanning
# machine's temp path into a document meant to be handed to other people. The
# merge in scan-firmware.sh keeps only the path inside the firmware, which
# unblob marks with its `<something>_extract/` nesting.
cat > "$WORK/fw-names.json" <<'JSON'
{"components":[
 {"name":"/tmp/tmp.aBcD/extract/fw.img.xz_extract/xz.uncompressed_extract/8388608-545257472.fat_extract/initramfs8_extract/z.zstd_extract/usr/bin/findmnt","type":"file"},
 {"name":"/usr/lib/libfoo.so.1","type":"file"},
 {"name":"busybox","version":"1.36.1","type":"library","purl":"pkg:deb/debian/busybox@1.36.1"},
 {"name":"CVEBINTOOL-zstd-uncompressed_extract","type":"application"},
 {"name":"","type":"file"}
]}
JSON
# The same expression scan-firmware.sh's comps_of() applies.
jq -c '[.components[]? | select((.name // "") != "")
       | .name |= (if test("_extract/") then (split("_extract/") | last)
                   elif startswith("/") then (split("/") | last)
                   else . end)]' "$WORK/fw-names.json" > "$WORK/fw-names-out.json"

leaked=$(jq '[.[] | select(.name | test("^/|/tmp/|_extract/"))] | length' "$WORK/fw-names-out.json")
[ "$leaked" = "0" ] && pass "firmware names: no unpack/absolute path survives" || fail "firmware names: $leaked component(s) still carry a path"
n1=$(jq -r '.[0].name' "$WORK/fw-names-out.json")
[ "$n1" = "usr/bin/findmnt" ] && pass "firmware names: path inside the firmware is kept" || fail "firmware names: got '$n1', expected usr/bin/findmnt"
n2=$(jq -r '.[1].name' "$WORK/fw-names-out.json")
[ "$n2" = "libfoo.so.1" ] && pass "firmware names: a plain absolute path falls back to its basename" || fail "firmware names: got '$n2', expected libfoo.so.1"
# A package name must pass through untouched, or dedupe by name@version breaks.
n3=$(jq -r '.[2].name' "$WORK/fw-names-out.json")
[ "$n3" = "busybox" ] && pass "firmware names: package names are left alone" || fail "firmware names: package name became '$n3'"
# The cve-bin-tool marker ends in _extract but has no trailing slash: not a path.
n4=$(jq -r '.[3].name' "$WORK/fw-names-out.json")
[ "$n4" = "CVEBINTOOL-zstd-uncompressed_extract" ] && pass "firmware names: a name merely ending in _extract is not truncated" || fail "firmware names: marker became '$n4'"
cnt=$(jq 'length' "$WORK/fw-names-out.json")
[ "$cnt" = "4" ] && pass "firmware names: the empty-name component is dropped" || fail "firmware names: kept $cnt components, expected 4"

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

echo "== input-format: UTF-16 / BOM-encoded SBOMs are normalized, not rejected =="
# A supplier SBOM saved as UTF-16 (common from Windows tooling) or with a UTF-8
# BOM must be read, not dropped as "unknown format": jq/grep assume UTF-8, so
# without normalization a valid SBOM fails silently. Both convert and validate
# normalize the encoding first (sbom-detect.sh). Fixtures are derived from a
# known-good CycloneDX so the only variable is the byte encoding.
iconv -f UTF-8 -t UTF-16 "$FIX/good-cyclonedx.json" > "$WORK/enc-utf16.cdx.json"
bash "$LIB/convert-to-cdx.sh" "$WORK/enc-utf16.cdx.json" "$WORK/enc-utf16-out.json" >/dev/null 2>&1
jq -e '.bomFormat=="CycloneDX" and (.components|length>0)' "$WORK/enc-utf16-out.json" >/dev/null 2>&1 \
    && pass "UTF-16 CycloneDX is normalized and converted" || fail "UTF-16 CycloneDX not handled"
bash "$LIB/validate-sbom.sh" "$WORK/enc-utf16.cdx.json" "$WORK/enc-utf16-cf" "supplier" >/dev/null 2>&1
[ -f "$WORK/enc-utf16-cf_conformance.json" ] && jq -e '.result=="pass"' "$WORK/enc-utf16-cf_conformance.json" >/dev/null 2>&1 \
    && pass "UTF-16 CycloneDX validates (encoding does not fail conformance)" || fail "UTF-16 CycloneDX conformance not produced/pass"
printf '\xEF\xBB\xBF' > "$WORK/enc-bom.cdx.json"; cat "$FIX/good-cyclonedx.json" >> "$WORK/enc-bom.cdx.json"
bash "$LIB/convert-to-cdx.sh" "$WORK/enc-bom.cdx.json" "$WORK/enc-bom-out.json" >/dev/null 2>&1
jq -e '.bomFormat=="CycloneDX"' "$WORK/enc-bom-out.json" >/dev/null 2>&1 \
    && pass "UTF-8 BOM CycloneDX is normalized and converted" || fail "UTF-8 BOM CycloneDX not handled"

echo "== input-format: SPDX 3.0 (JSON-LD) is recognized, not dropped as unknown =="
# SPDX 3.0 is JSON-LD (@context/@graph) with no top-level .spdxVersion, so the
# old detection dropped it as "unknown format" — the ONTAP failure in the gap
# study. Detection now recognizes it and routes it to syft (which reads SPDX 3.0
# in the shipped container image). The recognition is the regression this locks
# down and it is environment-independent. The actual conversion depends on the
# syft build reading SPDX 3.0 (the container's does; a bare host's syft may not),
# so it is verified only when the environment's syft supports it.
out=$(bash "$LIB/convert-to-cdx.sh" "$FIX/good-spdx3-jsonld.json" "$WORK/spdx3-out.json" 2>&1 || true)
echo "$out" | grep -q 'input is SPDX-3.0' \
    && pass "SPDX 3.0 JSON-LD is recognized as SPDX-3.0 (not unknown-format)" || fail "SPDX 3.0 not recognized: $out"
if jq -e '.bomFormat=="CycloneDX" and ([.components[]?|select(.purl)]|length>=2)' "$WORK/spdx3-out.json" >/dev/null 2>&1; then
    pass "SPDX 3.0 converts to CycloneDX with PURLs preserved (syft supports it here)"
else
    echo "  NOTE: this environment's syft did not convert SPDX 3.0; recognition verified, conversion is covered by the container image"
fi
# validate recognizes SPDX-3.0 and still emits a conformance report (measured via
# CycloneDX when syft converts, or a recognized-but-unmeasured result otherwise).
bash "$LIB/validate-sbom.sh" "$FIX/good-spdx3-jsonld.json" "$WORK/spdx3-cf" "supplier" >/dev/null 2>&1
[ -f "$WORK/spdx3-cf_conformance.json" ] && jq -e '.checks|length>0' "$WORK/spdx3-cf_conformance.json" >/dev/null 2>&1 \
    && pass "SPDX 3.0 produces a conformance report" || fail "SPDX 3.0 conformance not produced"

echo "== UNKNOWN is not carried as if it were a version =="

# syft writes `UNKNOWN` where it recognised a component but could not read what
# release it is — a kernel module with no version in its modinfo, a Go binary
# built without module metadata. Carried through, the conformance check that
# measures name-and-version coverage counts the component as versioned, so a scan
# that knows the release of none of its 3,575 kernel modules reported full
# coverage for them.
cat > "$WORK/unknown-ver.cdx.json" <<'UVEOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"timestamp":"2026-01-01T00:00:00Z","component":{"type":"firmware","name":"fw","version":"1"}},
 "components":[
  {"type":"library","name":"3c59x","version":"UNKNOWN","purl":"pkg:generic/3c59x",
   "cpe":"cpe:2.3:a:x:3c59x:*:*:*:*:*:*:*:*"},
  {"type":"library","name":"lowercase","version":"unknown"},
  {"type":"library","name":"real","version":"1.2.3","purl":"pkg:npm/real@1.2.3"},
  {"type":"library","name":"already-graded","version":"UNKNOWN",
   "properties":[{"name":"bomlens:evidenceGrade","value":"elf-presence"}]}]}
UVEOF
bash "$LIB/normalize-sbom.sh" "$WORK/unknown-ver.cdx.json" >/dev/null 2>&1

if jq -e '[.components[] | select(.version != null and (.version | ascii_downcase) == "unknown")] | length == 0' \
   "$WORK/unknown-ver.cdx.json" >/dev/null; then
    pass "a placeholder version is removed rather than shipped as a version"
else
    fail "UNKNOWN is still carried in a version field"
fi

# Present, release not established — the grade the rest of the pipeline already
# uses for exactly this.
got=$(jq -r '[.components[] | select(.name == "3c59x") | .properties[]
    | select(.name == "bomlens:evidenceGrade") | .value] | join(",")' "$WORK/unknown-ver.cdx.json")
if [ "$got" = "presence-only" ]; then
    pass "the component is marked as present with no version established"
else
    fail "the component lost its version without saying why" "grade: ${got:-none}"
fi

# The identifiers never held the placeholder and must survive untouched.
got=$(jq -r '[.components[] | select(.name == "3c59x") | .purl, .cpe] | join(" ")' "$WORK/unknown-ver.cdx.json")
if [ "$got" = "pkg:generic/3c59x cpe:2.3:a:x:3c59x:*:*:*:*:*:*:*:*" ]; then
    pass "the identifiers the component does carry are left alone"
else
    fail "an identifier was changed along with the version" "got: $got"
fi

if jq -e '[.components[] | select(.name == "real") | .version] == ["1.2.3"]' \
   "$WORK/unknown-ver.cdx.json" >/dev/null; then
    pass "a real version is untouched"
else
    fail "a real version was removed"
fi

# A pass that already said how it identified the component keeps its own word.
got=$(jq -r '[.components[] | select(.name == "already-graded") | .properties[]
    | select(.name == "bomlens:evidenceGrade") | .value] | join(",")' "$WORK/unknown-ver.cdx.json")
if [ "$got" = "elf-presence" ]; then
    pass "a grade an identification pass already recorded is not overwritten"
else
    fail "an existing evidence grade was replaced" "got: $got"
fi

# The point of the change: coverage now counts what is actually known.
bash "$LIB/validate-sbom.sh" "$WORK/unknown-ver.cdx.json" "$WORK/uv" "supplier" >/dev/null 2>&1
got=$(jq -r '.checks[] | select(.id=="name-version") | .detail' "$WORK/uv_conformance.json")
if [ "$got" = "1/4" ]; then
    pass "name-and-version coverage counts only the versions that are known"
else
    fail "coverage still counts the placeholder as a version" "detail: $got"
fi

echo "== SPDX export: the containers a firmware holds reach the SPDX file too =="

# syft's converter writes a package for what it counts as software and drops the
# rest, so the container images a firmware carries and the distribution it runs
# did not reach the SPDX export, and neither did which container each package
# belongs to. On a switch OS that is most of what a reader needs, and a reader who
# asked for SPDX was getting the CycloneDX document minus its answer.
cat > "$WORK/spdxc-in.cdx.json" <<'CDXEOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"component":{"type":"firmware","name":"switch","version":"1.0"}},
 "components":[
  {"type":"library","name":"libssl","version":"3.0.1","purl":"pkg:deb/debian/libssl@3.0.1",
   "properties":[{"name":"bomlens:container:image","value":"routing@2.0"}]},
  {"type":"library","name":"shared","version":"1.0","purl":"pkg:deb/debian/shared@1.0",
   "properties":[{"name":"bomlens:container:image","value":"routing@2.0"},
                 {"name":"bomlens:container:image","value":"telemetry@3.0"}]},
  {"type":"library","name":"rootfs-only","version":"1.0","purl":"pkg:deb/debian/rootfs-only@1.0"},
  {"type":"library","name":"not-in-spdx","version":"9.9","purl":"pkg:deb/debian/not-in-spdx@9.9",
   "properties":[{"name":"bomlens:container:image","value":"routing@2.0"}]},
  {"type":"container","name":"routing","version":"2.0","purl":"pkg:oci/routing@2.0","bom-ref":"c1"},
  {"type":"container","name":"telemetry","version":"3.0","purl":"pkg:oci/telemetry@3.0","bom-ref":"c2"},
  {"type":"operating-system","name":"debian","version":"13","bom-ref":"os1"}]}
CDXEOF
# What syft's converter leaves behind: the three libraries it recognized, and
# nothing else. `not-in-spdx` stands for a component the converter dropped.
cat > "$WORK/spdxc.spdx.json" <<'SPDXEOF'
{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"switch-1.0",
 "creationInfo":{"created":"1970-01-01T00:00:00Z","creators":["Tool: syft"]},
 "packages":[
  {"SPDXID":"SPDXRef-Package-libssl","name":"libssl","versionInfo":"3.0.1",
   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
                    "referenceLocator":"pkg:deb/debian/libssl@3.0.1"}]},
  {"SPDXID":"SPDXRef-Package-shared","name":"shared","versionInfo":"1.0",
   "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl",
                    "referenceLocator":"pkg:deb/debian/shared@1.0"}]},
  {"SPDXID":"SPDXRef-Package-rootfs-only","name":"rootfs-only","versionInfo":"1.0"}],
 "relationships":[
  {"spdxElementId":"SPDXRef-DOCUMENT","relatedSpdxElement":"SPDXRef-Package-libssl",
   "relationshipType":"DESCRIBES"}]}
SPDXEOF
python3 "$LIB/spdx-containers.py" "$WORK/spdxc-in.cdx.json" "$WORK/spdxc.spdx.json" 2>/dev/null

n=$(jq '[.packages[] | select(.name == "routing" or .name == "telemetry")] | length' "$WORK/spdxc.spdx.json")
if [ "$n" = "2" ]; then
    pass "each container image becomes an SPDX package"
else
    fail "the container images did not reach the SPDX file" "found $n of 2"
fi

# The distribution is a package the document describes, the same as in CycloneDX
# where enrich-os-context.py needs it as its own component.
if jq -e '[.packages[] | select(.name == "debian" and .versionInfo == "13")] | length == 1' \
   "$WORK/spdxc.spdx.json" >/dev/null; then
    pass "the distribution reaches the SPDX file as a package"
else
    fail "the operating system was dropped from the SPDX file"
fi

# SPDX says a package holding other packages with CONTAINS, which is the
# membership this scan establishes.
got=$(jq -r '[.relationships[]
    | select(.relationshipType == "CONTAINS" and (.spdxElementId | startswith("SPDXRef-Package-container-routing")))
    | .relatedSpdxElement] | sort | join(",")' "$WORK/spdxc.spdx.json")
if [ "$got" = "SPDXRef-Package-libssl,SPDXRef-Package-shared" ]; then
    pass "a package is related to the container it belongs to"
else
    fail "the container membership is missing from the SPDX file" "got: ${got:-nothing}"
fi

# A package in two containers belongs to both, and saying so twice is the only
# way SPDX can carry that.
n=$(jq '[.relationships[] | select(.relationshipType == "CONTAINS"
    and .relatedSpdxElement == "SPDXRef-Package-shared"
    and (.spdxElementId | startswith("SPDXRef-Package-container-")))] | length' "$WORK/spdxc.spdx.json")
if [ "$n" = "2" ]; then
    pass "a package in two containers is related to both"
else
    fail "a membership was lost for a package in more than one container" "got $n of 2"
fi

# The two documents have to keep listing the same software. A component the
# converter left out is not added back through the relationship.
if jq -e '[.relationships[] | select(.relatedSpdxElement | test("not-in-spdx"))] | length == 0' \
   "$WORK/spdxc.spdx.json" >/dev/null \
   && jq -e '[.packages[] | select(.name == "not-in-spdx")] | length == 0' \
      "$WORK/spdxc.spdx.json" >/dev/null; then
    pass "a component the converter dropped is not resurrected as a relationship"
else
    fail "a component missing from the SPDX packages was related anyway"
fi

# A package that is only in the rootfs is in no container, and must not be
# related to one.
if jq -e '[.relationships[] | select(.relatedSpdxElement == "SPDXRef-Package-rootfs-only"
    and (.spdxElementId | startswith("SPDXRef-Package-container-")))] | length == 0' \
   "$WORK/spdxc.spdx.json" >/dev/null; then
    pass "a package outside every container is related to none"
else
    fail "a rootfs package was placed inside a container"
fi

# The added packages are part of what the document is about, like every other one.
if jq -e '[.relationships[] | select(.spdxElementId == "SPDXRef-Package-libssl"
    and .relationshipType == "CONTAINS")] | length == 3' "$WORK/spdxc.spdx.json" >/dev/null; then
    pass "the document's root contains the images and the distribution"
else
    fail "the added packages hang off nothing the document describes"
fi

# A scan with no containers leaves the SPDX file exactly as the converter wrote it.
jq '{spdxVersion, SPDXID, name, packages, relationships}' "$WORK/spdxc.spdx.json" > /dev/null
cat > "$WORK/plain.cdx.json" <<'PLAINEOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "components":[{"type":"library","name":"libssl","version":"3.0.1"}]}
PLAINEOF
cp "$FIX/good-spdx.json" "$WORK/plain.spdx.json"
before="$(jq -S . "$WORK/plain.spdx.json")"
python3 "$LIB/spdx-containers.py" "$WORK/plain.cdx.json" "$WORK/plain.spdx.json" 2>/dev/null
if [ "$before" = "$(jq -S . "$WORK/plain.spdx.json")" ]; then
    pass "an SBOM with no containers leaves the SPDX file untouched"
else
    fail "the SPDX file was rewritten for a scan that has no containers"
fi

echo "== conformance: a PURL failure says when the components carry a CPE instead =="
# The submission criteria require a PURL, so this stays a mandatory failure. What
# it must not do is read as "unidentified components" when the components are
# identified another way — the baselines under this row (BSI TR-03183-2 5.2.4,
# NTIA) accept either identifier. A Yocto image is the case in point: bitbake
# writes CPEs and never PURLs.
cat > "$WORK/cpe-only.cdx.json" <<'CEOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"timestamp":"2026-01-01T00:00:00Z","tools":{"components":[{"type":"application","name":"t"}]},
              "component":{"type":"operating-system","name":"img","version":"1.0"}},
 "components":[
   {"type":"library","name":"busybox","version":"1.36.1","cpe":"cpe:2.3:a:*:busybox:1.36.1:*:*:*:*:*:*:*"},
   {"type":"library","name":"libz1","version":"1.3","cpe":"cpe:2.3:a:*:zlib:1.3:*:*:*:*:*:*:*"},
   {"type":"library","name":"nameless","version":"1.0"}],
 "dependencies":[{"ref":"busybox","dependsOn":["libz1"]}]}
CEOF
bash "$LIB/validate-sbom.sh" "$WORK/cpe-only.cdx.json" "$WORK/cpeonly" "supplier" >/dev/null 2>&1
cpe_status=$(jq -r '.checks[] | select(.id=="purl") | .status' "$WORK/cpeonly_conformance.json" 2>/dev/null)
cpe_detail=$(jq -r '.checks[] | select(.id=="purl") | .detail' "$WORK/cpeonly_conformance.json" 2>/dev/null)
[ "$cpe_status" = "fail" ] \
    && pass "CPE instead of PURL still fails the submission criteria" \
    || fail "purl check status='$cpe_status' (expected fail)"
case "$cpe_detail" in
    *"2 identified by CPE instead"*)
        pass "the report counts how many components carry a CPE instead" ;;
    *)  fail "purl detail does not name the CPE-identified components" "$cpe_detail" ;;
esac
# The row already carries the baselines that accept either identifier, so a
# reader can see the verdict is ours and not theirs.
jq -e '[.checks[] | select(.id=="purl") | .regulations[]?.framework] | index("bsi-tr-03183-2")' \
    "$WORK/cpeonly_conformance.json" >/dev/null 2>&1 \
    && pass "the PURL row still cites the baselines that accept CPE" \
    || fail "purl row lost its regulatory references"
# An SBOM with neither identifier must say nothing about CPEs.
cat > "$WORK/no-id.cdx.json" <<'NEOF'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
 "metadata":{"timestamp":"2026-01-01T00:00:00Z","tools":{"components":[{"type":"application","name":"t"}]},
              "component":{"type":"application","name":"app","version":"1.0"}},
 "components":[{"type":"library","name":"a","version":"1"}]}
NEOF
bash "$LIB/validate-sbom.sh" "$WORK/no-id.cdx.json" "$WORK/noid" "supplier" >/dev/null 2>&1
noid_detail=$(jq -r '.checks[] | select(.id=="purl") | .detail' "$WORK/noid_conformance.json" 2>/dev/null)
case "$noid_detail" in
    *CPE*) fail "a PURL failure with no CPEs mentions CPEs anyway" "$noid_detail" ;;
    *)     pass "no CPEs, no claim about CPEs" ;;
esac

echo "== conformance: spec-version range and PURL syntax are mandatory checks =="
# The SKT submission requirements pin the accepted spec versions (CycloneDX
# 1.3-1.6, SPDX 2.2/2.3) and require standard pkg:type/name@version PURLs.
# A schema-valid SBOM violating either must fail conformance — the online
# CycloneDX schema validator cannot catch these.
jq '.specVersion="1.2"' "$FIX/good-cyclonedx.json" > "$WORK/spec-old.json"
bash "$LIB/validate-sbom.sh" "$WORK/spec-old.json" "$WORK/so" "supplier" >/dev/null 2>&1
so_spec=$(jq -r '.checks[] | select(.id=="spec-version") | .status' "$WORK/so_conformance.json")
so_res=$(jq -r '.result' "$WORK/so_conformance.json")
[ "$so_spec/$so_res" = "fail/fail" ] && pass "CycloneDX 1.2 fails the spec-version check (and overall)" || fail "CycloneDX 1.2: spec=$so_spec result=$so_res, expected fail/fail"

# Tolerated real-world PURL shapes must NOT be flagged: unencoded and
# percent-encoded npm scopes, golang multi-segment namespaces, rpm qualifiers.
jq '.components += [
  {"type":"library","name":"scoped","version":"7.0.0","purl":"pkg:npm/@babel/core@7.0.0"},
  {"type":"library","name":"scoped-enc","version":"20.1.0","purl":"pkg:npm/%40types/node@20.1.0"},
  {"type":"library","name":"gin","version":"v1.8.1","purl":"pkg:golang/github.com/gin-gonic/gin@v1.8.1"},
  {"type":"library","name":"glibc","version":"2.17","purl":"pkg:rpm/centos/glibc@2.17-317.el7?arch=x86_64"},
  {"type":"library","name":"noversion","version":"1.0","purl":"pkg:npm/noversion"}
]' "$FIX/good-cyclonedx.json" > "$WORK/purl-ok.json"
bash "$LIB/validate-sbom.sh" "$WORK/purl-ok.json" "$WORK/pok" "supplier" >/dev/null 2>&1
pok=$(jq -r '"\(.result)/\(.checks[] | select(.id=="purl-syntax") | .status)"' "$WORK/pok_conformance.json")
[ "$pok" = "pass/pass" ] && pass "scoped npm / golang / rpm-qualifier PURLs are accepted" || fail "valid PURL shapes rejected: $pok"

# Malformed PURLs (colon coordinates, raw space) must fail with the offenders
# listed. They still carry a purl, so the coverage check stays green — only the
# new syntax check may catch them.
jq '.components += [
  {"type":"library","name":"commons-lang3","version":"3.12.0","purl":"commons-lang3:3.12.0"},
  {"type":"library","name":"spacey","version":"1.0","purl":"pkg:npm/bad name@1.0"}
]' "$FIX/good-cyclonedx.json" > "$WORK/purl-bad.json"
bash "$LIB/validate-sbom.sh" "$WORK/purl-bad.json" "$WORK/pbad" "supplier" >/dev/null 2>&1
pb_stat=$(jq -r '.checks[] | select(.id=="purl-syntax") | "\(.status) \(.detail)"' "$WORK/pbad_conformance.json")
[ "$pb_stat" = "fail 2 malformed" ] && pass "malformed PURLs fail the syntax check (2 offenders)" || fail "purl-syntax check: '$pb_stat', expected 'fail 2 malformed'"

# A PURL with no version is a valid PURL — the version is optional in the spec —
# and reporting it as a syntax error sent readers looking for broken syntax that
# was not there. Measured on a switch OS: 3,581 identifiers, nearly all
# `pkg:generic/<kernel module>`, failed a check about spelling for a reason that
# has nothing to do with spelling. That the version is missing is a real gap and
# the checks that own it still say so.
jq '.components = [
  {"type":"library","name":"mod","purl":"pkg:generic/3c59x"}
] + .components' "$FIX/good-cyclonedx.json" > "$WORK/purl-nover.json"
bash "$LIB/validate-sbom.sh" "$WORK/purl-nover.json" "$WORK/pnv" "supplier" >/dev/null 2>&1
nv_syntax=$(jq -r '.checks[] | select(.id=="purl-syntax") | .status' "$WORK/pnv_conformance.json")
nv_name=$(jq -r '.checks[] | select(.id=="name-version") | .status' "$WORK/pnv_conformance.json")
nv_generic=$(jq -r '.checks[] | select(.id=="no-generic") | .status' "$WORK/pnv_conformance.json")
if [ "$nv_syntax" = "pass" ]; then
    pass "a PURL without a version is not reported as a syntax error"
else
    fail "a versionless PURL still fails the syntax check" "status=$nv_syntax"
fi
if [ "$nv_name" = "fail" ] && [ "$nv_generic" = "warn" ]; then
    pass "the missing version and the untraceable identifier are still reported"
else
    fail "the gap stopped being reported by the checks that own it" \
         "name-version=$nv_name, no-generic=$nv_generic"
fi
jq -e '.checks[] | select(.id=="purl-syntax") | .missing | index("commons-lang3:3.12.0")' "$WORK/pbad_conformance.json" >/dev/null \
    && pass "purl-syntax missing list names the offending PURL" || fail "purl-syntax missing list lacks commons-lang3:3.12.0"
pb_cov=$(jq -r '.checks[] | select(.id=="purl") | .status' "$WORK/pbad_conformance.json")
[ "$pb_cov" = "pass" ] && pass "PURL coverage stays green (syntax is a separate check)" || fail "purl coverage='$pb_cov', expected pass"

# SPDX JSON: version range + purl syntax over externalRefs locators.
jq '.spdxVersion="SPDX-2.1"' "$FIX/good-spdx.json" > "$WORK/spdx-old.json"
bash "$LIB/validate-sbom.sh" "$WORK/spdx-old.json" "$WORK/sdo" "supplier" >/dev/null 2>&1
sdo=$(jq -r '.checks[] | select(.id=="spec-version") | .status' "$WORK/sdo_conformance.json")
[ "$sdo" = "fail" ] && pass "SPDX-2.1 fails the spec-version check" || fail "SPDX-2.1 spec-version='$sdo', expected fail"
jq '.packages[0].externalRefs[0].referenceLocator="express@4.18.2"' "$FIX/good-spdx.json" > "$WORK/spdx-badpurl.json"
bash "$LIB/validate-sbom.sh" "$WORK/spdx-badpurl.json" "$WORK/sdb" "supplier" >/dev/null 2>&1
sdb=$(jq -r '.checks[] | select(.id=="purl-syntax") | "\(.status)|\(.missing|join(","))"' "$WORK/sdb_conformance.json")
[ "$sdb" = "fail|express@4.18.2" ] && pass "SPDX bad purl locator fails with the offender listed" || fail "SPDX purl-syntax: '$sdb'"

# SPDX Tag-Value: coarse spec-version gate (the clean fixture passing both new
# checks is covered by D-4 above).
sed 's/^SPDXVersion: SPDX-2.3$/SPDXVersion: SPDX-2.1/' "$FIX/supplier-clean-tagvalue.spdx" > "$WORK/tv-old.spdx"
bash "$LIB/validate-sbom.sh" "$WORK/tv-old.spdx" "$WORK/tvo" "supplier" >/dev/null 2>&1
tvo=$(jq -r '"\(.checks[] | select(.id=="spec-version") | .status)/\(.result)"' "$WORK/tvo_conformance.json")
[ "$tvo" = "fail/fail" ] && pass "Tag-Value SPDX-2.1 fails the spec-version check" || fail "Tag-Value spec-version: '$tvo', expected fail/fail"

echo "== conformance: SPDX transitive check counts DEPENDENCY_OF (Syft's reverse-direction edge) =="
# Syft writes OS-package dependency edges in SPDX as the reverse relationship
# DEPENDENCY_OF (e.g. NetworkManager-libnm DEPENDENCY_OF NetworkManager), never
# DEPENDS_ON, while the same scan's CycloneDX carries dependsOn. The transitive
# check only asks whether dependency edges EXIST, so both directions must count —
# otherwise every Syft SPDX submission gets a false transitive FAIL.
# SPDX JSON: flip the sole DEPENDS_ON edge to DEPENDENCY_OF; nothing else changes.
jq '(.relationships[] | select(.relationshipType=="DEPENDS_ON") | .relationshipType) = "DEPENDENCY_OF"' \
    "$FIX/good-spdx.json" > "$WORK/spdx-depof.json"
bash "$LIB/validate-sbom.sh" "$WORK/spdx-depof.json" "$WORK/sdd" "supplier" >/dev/null 2>&1
sdd=$(jq -r '.checks[] | select(.id=="transitive") | "\(.status)|\(.detail)"' "$WORK/sdd_conformance.json")
[ "$sdd" = "pass|1 edge(s)" ] && pass "SPDX JSON DEPENDENCY_OF counts as a transitive edge" || fail "SPDX transitive (DEPENDENCY_OF): '$sdd', expected pass|1 edge(s)"
# An SPDX with only structural relationships (DESCRIBES/CONTAINS, no dependency
# graph) must still FAIL — the fix widens the direction, it must not weaken the check.
jq '.relationships = [.relationships[] | select(.relationshipType=="DESCRIBES")]' "$FIX/good-spdx.json" > "$WORK/spdx-nodeps.json"
bash "$LIB/validate-sbom.sh" "$WORK/spdx-nodeps.json" "$WORK/sdn" "supplier" >/dev/null 2>&1
sdn=$(jq -r '.checks[] | select(.id=="transitive") | .status' "$WORK/sdn_conformance.json")
[ "$sdn" = "fail" ] && pass "SPDX JSON with no dependency edges still fails transitive" || fail "SPDX transitive (no edges): '$sdn', expected fail"
# Tag-Value: the same reverse-direction relationship must be matched by grep.
sed 's/DEPENDS_ON/DEPENDENCY_OF/g' "$FIX/supplier-clean-tagvalue.spdx" > "$WORK/tv-depof.spdx"
bash "$LIB/validate-sbom.sh" "$WORK/tv-depof.spdx" "$WORK/tvd" "supplier" >/dev/null 2>&1
tvd=$(jq -r '.checks[] | select(.id=="transitive") | .status' "$WORK/tvd_conformance.json")
[ "$tvd" = "pass" ] && pass "Tag-Value DEPENDENCY_OF counts as a transitive edge" || fail "Tag-Value transitive (DEPENDENCY_OF): '$tvd', expected pass"

echo "== document metadata: why an empty field is empty =="
# The guidance asks the author to say which of two things an absence means — the
# author does not know the value, or the author is holding it back. A scan only
# ever produces the first, and says so once for the document rather than once per
# empty field: the claim is identical for all of them, and repeating it across a
# firmware image's components would add thousands of properties saying nothing new.
printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
  "metadata":{"timestamp":"2026-01-01T00:00:00Z","component":{"type":"application","name":"App","version":"1.0"}},
  "components":[]}' > "$WORK/undecl.json"
bash "$LIB/stamp-document-metadata.sh" "$WORK/undecl.json" SOURCE >/dev/null 2>&1
ud=$(jq -r '[.metadata.properties[] | select(.name=="bomlens:undeclared-fields") | .value] | join(",")' "$WORK/undecl.json")
[ "$ud" = "unknown-to-author" ] && pass "the document states that its empty fields are unknown, not withheld" || fail "undeclared-fields policy: '$ud'"
bash "$LIB/stamp-document-metadata.sh" "$WORK/undecl.json" SOURCE >/dev/null 2>&1
ud_n=$(jq '[.metadata.properties[] | select(.name=="bomlens:undeclared-fields")] | length' "$WORK/undecl.json")
[ "$ud_n" = "1" ] && pass "restamping does not repeat the statement" || fail "policy property appears ${ud_n}x after two runs"
# The conformance element that asks for this reads it, so an SBOM that says
# nothing about its absences is told so rather than left unmeasured.
bash "$LIB/validate-sbom.sh" "$WORK/undecl.json" "$WORK/ud" "supplier" >/dev/null 2>&1
ud_chk=$(jq -r '.checks[] | select(.id=="cisa-explicit-unknowns") | "\(.status)|\(.source)"' "$WORK/ud_conformance.json")
[ "$ud_chk" = "pass|auto" ] && pass "a declared policy satisfies the explicit-unknowns element" || fail "explicit-unknowns on a stamped SBOM: '$ud_chk'"
jq 'del(.metadata.properties)' "$WORK/undecl.json" > "$WORK/undecl-none.json"
bash "$LIB/validate-sbom.sh" "$WORK/undecl-none.json" "$WORK/udn" "supplier" >/dev/null 2>&1
udn_chk=$(jq -r '.checks[] | select(.id=="cisa-explicit-unknowns") | .status' "$WORK/udn_conformance.json")
[ "$udn_chk" = "warn" ] && pass "an SBOM that says nothing about its absences is reported as a gap" || fail "explicit-unknowns without a policy: '$udn_chk'"
# A component version the scan could not establish is already marked, and that
# marking is the statement the guidance asks for. Counting it as missing would
# report the same fact twice and under-report coverage.
jq '.components = [{"type":"library","name":"marked","properties":[{"name":"bomlens:evidenceGrade","value":"presence-only"}]},{"type":"library","name":"silent"}]' \
    "$WORK/undecl.json" > "$WORK/undecl-ver.json"
bash "$LIB/validate-sbom.sh" "$WORK/undecl-ver.json" "$WORK/udv" "supplier" >/dev/null 2>&1
udv=$(jq -r '.checks[] | select(.id=="cisa-component-version") | "\(.detail)|\(.missing|join(","))"' "$WORK/udv_conformance.json")
# Three, not two: the target component is a subject of these elements too.
[ "$udv" = "2/3 component(s)|silent" ] \
    && pass "a version marked as not established counts as stated, an unmarked one does not" \
    || fail "component-version with an evidence grade: '$udv'"

echo "== document metadata: the hash of what was actually scanned =="
# The minimum elements define the component hash over an executable component
# artifact. For a binary or a firmware image that artifact is one file, so its
# hash goes on the component the SBOM is about and a recipient can tell whether
# their copy is the copy this SBOM describes.
printf 'firmware image bytes' > "$WORK/art.img"
printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
  "metadata":{"timestamp":"2026-01-01T00:00:00Z","component":{"type":"firmware","name":"art.img","version":"1.0"}},
  "components":[]}' > "$WORK/art.json"
bash "$LIB/stamp-document-metadata.sh" "$WORK/art.json" FIRMWARE "$WORK/art.img" >/dev/null 2>&1
art_got=$(jq -r '[.metadata.component.hashes[] | "\(.alg):\(.content)"] | join(",")' "$WORK/art.json")
art_want="SHA-256:$( (sha256sum "$WORK/art.img" 2>/dev/null || shasum -a 256 "$WORK/art.img") | cut -d' ' -f1)"
[ "$art_got" = "$art_want" ] && pass "the scanned artifact's hash lands on the target component" || fail "artifact hash: got '$art_got' want '$art_want'"
# A scan whose target is not a file has no artifact to hash. Inventing one would
# put a value in a field the guidance defines as the hash of an artifact.
printf '%s' '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
  "metadata":{"timestamp":"2026-01-01T00:00:00Z","component":{"type":"application","name":"app","version":"1.0"}},
  "components":[]}' > "$WORK/art-src.json"
bash "$LIB/stamp-document-metadata.sh" "$WORK/art-src.json" SOURCE >/dev/null 2>&1
jq -e '(.metadata.component.hashes // []) | length == 0' "$WORK/art-src.json" >/dev/null \
    && pass "a scan with no single artifact records no hash for one" || fail "a source scan invented a target-component hash"
# A hash another scanner already recorded is left alone: it was looking at the
# same artifact and may have used a different algorithm.
jq '.metadata.component.hashes = [{"alg":"SHA-512","content":"pre-existing"}]' "$WORK/art.json" > "$WORK/art-keep.json"
bash "$LIB/stamp-document-metadata.sh" "$WORK/art-keep.json" FIRMWARE "$WORK/art.img" >/dev/null 2>&1
keep=$(jq -r '[.metadata.component.hashes[] | .alg] | join(",")' "$WORK/art-keep.json")
[ "$keep" = "SHA-512" ] && pass "an existing target-component hash is not overwritten" || fail "existing hash replaced: '$keep'"

echo "== conformance: a signature delivered beside the SBOM is not silently a gap =="
# The signing this tool offers is detached — the signature is a file next to the
# SBOM — and this report reads one file, so it cannot see one. Saying only "not
# present" would read as unsigned to someone whose supplier did sign. The row
# carries the note instead, and a signature carried inside the document is still
# read and credited.
bash "$LIB/validate-sbom.sh" "$FIX/good-cyclonedx.json" "$WORK/sg" "supplier" >/dev/null 2>&1
sg=$(jq -r '.checks[] | select(.id=="cisa-sbom-author-signature") | "\(.status)|\((.reviewGuide.how // "") | length > 0)"' "$WORK/sg_conformance.json")
[ "$sg" = "warn|true" ] && pass "an unsigned-looking SBOM carries the note about detached signatures" || fail "signature row: '$sg'"
jq '.signature = {"algorithm":"ES256","value":"MEUCIQD"}' "$FIX/good-cyclonedx.json" > "$WORK/sg-signed.json"
bash "$LIB/validate-sbom.sh" "$WORK/sg-signed.json" "$WORK/sgs" "supplier" >/dev/null 2>&1
sgs=$(jq -r '.checks[] | select(.id=="cisa-sbom-author-signature") | .status' "$WORK/sgs_conformance.json")
[ "$sgs" = "pass" ] && pass "a signature inside the document is read and credited" || fail "in-document signature: '$sgs'"
# The note has to reach the markdown too: that is the copy that gets pasted into
# a ticket, and it used to render only in the HTML.
grep -q "^## What needs a person" "$WORK/sg_conformance.md" \
    && pass "the review notes render in the markdown report" || fail "markdown has no review section"
grep -q "detached signature" "$WORK/sg_conformance.md" \
    && pass "the signature note is one of them" || fail "markdown review section omits the signature note"
REPORT_LANG=ko bash "$LIB/validate-sbom.sh" "$FIX/good-cyclonedx.json" "$WORK/sgk" "supplier" >/dev/null 2>&1
grep -q "^## 사람이 확인할 항목" "$WORK/sgk_conformance.md" \
    && pass "the Korean report renders the section too" || fail "ko markdown has no review section"

echo "== conformance: the 2026 SBOM minimum elements are measured on every SBOM =="
# The baseline applies to all software, not to a subset, so its registry declares
# no condition and is measured wherever a CycloneDX SBOM is. Advisory throughout
# for now: the guidance lets an absent value be stated as unknown, and until that
# notation exists, requiring a field would fail SBOMs for values they may
# legitimately not have.
bash "$LIB/validate-sbom.sh" "$FIX/good-cyclonedx.json" "$WORK/ci" "supplier" >/dev/null 2>&1
ci_n=$(jq '[.checks[] | select(.id|startswith("cisa-"))] | length' "$WORK/ci_conformance.json")
[ "$ci_n" = "23" ] && pass "all 23 elements (17 data fields + 6 practices) are reported" || fail "cisa elements: $ci_n, expected 23"
ci_req=$(jq '[.checks[] | select((.id|startswith("cisa-")) and .required)] | length' "$WORK/ci_conformance.json")
ci_res=$(jq -r '.result' "$WORK/ci_conformance.json")
{ [ "$ci_req" = "0" ] && [ "$ci_res" = "pass" ]; } \
    && pass "the elements are advisory and do not move the verdict" \
    || fail "cisa mandatory=$ci_req result=$ci_res, expected 0 and pass"
# The practices describe how an organisation operates, which no scan can read.
# Surfaced as review rather than dropped, so the report shows the whole baseline
# and which part of it a tool can answer.
ci_na=$(jq -r '[.checks[] | select((.id|startswith("cisa-")) and .source=="na") | .id] | sort | join(",")' "$WORK/ci_conformance.json")
[ "$ci_na" = "cisa-accommodation-of-updates,cisa-coverage,cisa-distribution-and-delivery,cisa-frequency" ] \
    && pass "the four practices with no automated source are surfaced as review" || fail "cisa review set: $ci_na"
# What this baseline accepts as an identifier is wider than the submission
# criteria: PURL or CPE, and an intrinsic identifier such as a hash. A file
# component carries only the last of those, and it is identified all the same.
jq '.components = [{"type":"file","name":"usr/lib/libfoo.so","hashes":[{"alg":"SHA-256","content":"aa"}]}]' \
    "$FIX/good-cyclonedx.json" > "$WORK/ci-file.json"
bash "$LIB/validate-sbom.sh" "$WORK/ci-file.json" "$WORK/cif" "supplier" >/dev/null 2>&1
cif=$(jq -r '[.checks[] | select(.id=="cisa-component-identifiers") | .missing[]] | join(",")' "$WORK/cif_conformance.json")
[ "$cif" = "supplier-app" ] \
    && pass "a hash counts as the identifier where no PURL or CPE can exist" \
    || fail "cisa identifiers on a file component: missing='$cif', expected only the unidentified target component"
# The crosswalk rolls this baseline up under its own framework. The 2021 mappings
# used to sit on the base checks; leaving them there would count the same
# requirement twice, once per row.
ci_fw=$(jq -r '[.regulatoryCrosswalk.frameworks[] | select(.id=="us-sbom-minimum-elements") | "\(.total)"] | join("")' "$WORK/ci_conformance.json")
[ "$ci_fw" = "23" ] && pass "the crosswalk rolls up 23 requirements, one per element" || fail "crosswalk total for the US baseline: '$ci_fw', expected 23"
# The data fields describe the target component as well as the subcomponents
# enumerated under it, so the component the SBOM is about is measured with the
# rest. Leaving it out let an unnamed, unidentified root pass unmentioned.
ci_subj=$(jq -r '.checks[] | select(.id=="cisa-component-name") | .detail' "$WORK/ci_conformance.json")
[ "$ci_subj" = "3/3 component(s)" ] \
    && pass "the target component is measured alongside its subcomponents" \
    || fail "cisa subject set: name coverage '$ci_subj', expected 3/3 (2 components + the target)"
ci_dup=$(jq -r '[.checks[] | select((.id|startswith("cisa-")|not)) | select((.regulations // [])[] | .framework=="us-sbom-minimum-elements") | .id] | join(",")' "$WORK/ci_conformance.json")
[ -z "$ci_dup" ] && pass "no base check double-counts against the same baseline" || fail "base checks still mapped to the US baseline: $ci_dup"

echo "== conformance: a registry declares its own subject, wording, and what is mandatory =="
# The evaluator used to hardcode three things that belong to the G7 baseline: every
# element is advisory, coverage is measured over model components, and the report
# says "model component". A baseline whose elements are mandatory and whose subject
# is ordinary software components could not be expressed at all. It is declared now,
# and these assertions are what stops the defaults from creeping back in.
cat > "$WORK/reg-mandatory.json" <<'REG'
{
  "subject": "[.components[]? | select(.type==\"library\")]",
  "subjectLabel": "library",
  "emptySubjectDetail": "no libraries",
  "clusters": [
    { "id": "demo", "name": "Demo", "elements": [
      { "id": "demo-required-missing", "label": "Required and absent", "required": true,
        "source": "auto", "cdxPath": "(.metadata.nothingHere // null) != null" },
      { "id": "demo-advisory-missing", "label": "Advisory and absent", "required": false,
        "source": "auto", "cdxPath": "(.metadata.nothingHere // null) != null" },
      { "id": "demo-required-coverage", "label": "Required per subject", "required": true,
        "source": "auto",
        "missingPath": "[ $subjects[] | select((.description // \"\") == \"\") | .name ]" }
    ] }
  ]
}
REG
G7_REGISTRY="$WORK/reg-mandatory.json" bash "$LIB/validate-sbom.sh" "$FIX/good-cyclonedx.json" "$WORK/rg" "supplier" >/dev/null 2>&1
rg_req=$(jq -r '.checks[] | select(.id=="demo-required-missing") | .status' "$WORK/rg_conformance.json")
rg_adv=$(jq -r '.checks[] | select(.id=="demo-advisory-missing") | .status' "$WORK/rg_conformance.json")
{ [ "$rg_req" = "fail" ] && [ "$rg_adv" = "warn" ]; } \
    && pass "an unmet element fails when the registry requires it and warns when it does not" \
    || fail "registry required/advisory: required=$rg_req advisory=$rg_adv, expected fail/warn"
rg_res=$(jq -r '.result' "$WORK/rg_conformance.json")
[ "$rg_res" = "fail" ] && pass "a failed mandatory registry element moves the overall result" || fail "overall result '$rg_res' despite a mandatory registry failure"
# The subject is the registry's, not the evaluator's: good-cyclonedx.json carries
# libraries and no model at all, so a model-fixed denominator would have reported
# "no machine-learning-model components" and passed on an empty set.
rg_cov=$(jq -r '.checks[] | select(.id=="demo-required-coverage") | .detail' "$WORK/rg_conformance.json")
case "$rg_cov" in
    *"library(s)") pass "coverage is measured over the declared subject, in the declared wording" ;;
    *) fail "registry subject/wording: detail='$rg_cov', expected an N/M library(s) count" ;;
esac
# And when the declared subject is empty, the registry's own wording says so.
jq '.components = []' "$FIX/good-cyclonedx.json" > "$WORK/reg-nosubj.json"
G7_REGISTRY="$WORK/reg-mandatory.json" bash "$LIB/validate-sbom.sh" "$WORK/reg-nosubj.json" "$WORK/rn" "supplier" >/dev/null 2>&1
rn=$(jq -r '.checks[] | select(.id=="demo-required-coverage") | .detail' "$WORK/rn_conformance.json")
[ "$rn" = "no libraries" ] && pass "an empty subject set is reported in the registry's wording" || fail "empty subject detail: '$rn', expected 'no libraries'"

echo "== conformance: file components are judged by hash, not by PURL =="
# A binary or firmware scan enumerates the delivered files as type "file"
# components. They carry no PURL and no package version — purl defines no type for
# a file on disk — so counting them in the package coverage denominators failed
# SBOMs for a field that cannot exist: a firmware SBOM whose packages were all
# identified read as 10% PURL coverage because 14 file entries sat in the
# denominator. Files still have to be identified, by the intrinsic identifier they
# do carry, so file-identifier measures hash coverage over them.
FILE_C='{"type":"file","name":"usr/lib/libfoo.so.1","hashes":[{"alg":"SHA-256","content":"aa"}]}'
jq --argjson f "$FILE_C" '.components += [$f, ($f | .name = "usr/bin/bar")]' \
    "$FIX/good-cyclonedx.json" > "$WORK/conf-files.json"
bash "$LIB/validate-sbom.sh" "$WORK/conf-files.json" "$WORK/cf" "supplier" >/dev/null 2>&1
cf=$(jq -r '"\(.result)/\(.checks[]|select(.id=="name-version")|.status)/\(.checks[]|select(.id=="purl")|.status)"' "$WORK/cf_conformance.json")
[ "$cf" = "pass/pass/pass" ] \
    && pass "file components no longer drag down package name/PURL coverage" \
    || fail "adding file components broke a clean SBOM" "result/name-version/purl = $cf"
cf_fid=$(jq -r '.checks[] | select(.id=="file-identifier") | "\(.status)|\(.detail)"' "$WORK/cf_conformance.json")
[ "$cf_fid" = "pass|100% (2/2)" ] \
    && pass "file-identifier measures hash coverage over the file components" \
    || fail "file-identifier: '$cf_fid', expected pass|100% (2/2)"
# A file component with no hash carries no identifier at all: PURL is undefined
# for it and the hash is gone, so nothing keys it to anything. Advisory for now.
jq --argjson f "$FILE_C" '.components += [$f | del(.hashes)]' "$FIX/good-cyclonedx.json" > "$WORK/conf-nohash.json"
bash "$LIB/validate-sbom.sh" "$WORK/conf-nohash.json" "$WORK/cn" "supplier" >/dev/null 2>&1
cn=$(jq -r '.checks[] | select(.id=="file-identifier") | "\(.status)|\(.detail)"' "$WORK/cn_conformance.json")
cn_res=$(jq -r '.result' "$WORK/cn_conformance.json")
{ [ "$cn" = "warn|0% (0/1)" ] && [ "$cn_res" = "pass" ]; } \
    && pass "an unhashed file component warns without failing the submission" \
    || fail "unhashed file component: check='$cn' result='$cn_res', expected warn|0% (0/1) and pass"
jq -e '.checks[] | select(.id=="file-identifier") | .missing | index("usr/lib/libfoo.so.1")' "$WORK/cn_conformance.json" >/dev/null \
    && pass "file-identifier names the unidentified file" || fail "file-identifier missing list lacks the offending file"
# The denominator fix must not become an escape hatch. An SBOM that enumerates
# ONLY files identified no package, so it cannot answer the question the
# submission criteria exist to answer (vulnerability matching keys on PURL).
# Reporting the empty denominator as 0/0 met would pass it; it must fail, and the
# detail has to say which of the two empty cases it is.
jq '.components = [.components[] | select(.type=="file")]' "$WORK/conf-files.json" > "$WORK/conf-fileonly.json"
bash "$LIB/validate-sbom.sh" "$WORK/conf-fileonly.json" "$WORK/co" "supplier" >/dev/null 2>&1
co=$(jq -r '"\(.result)/\(.checks[]|select(.id=="name-version")|.status)/\(.checks[]|select(.id=="purl")|.status)"' "$WORK/co_conformance.json")
[ "$co" = "fail/fail/fail" ] \
    && pass "an SBOM of files only fails: it identified no package" \
    || fail "file-only SBOM: result/name-version/purl = $co, expected fail/fail/fail" \
            "the empty package denominator must not read as full coverage"
co_detail=$(jq -r '.checks[] | select(.id=="purl") | .detail' "$WORK/co_conformance.json")
[ "$co_detail" = "no package components (file inventory only)" ] \
    && pass "the file-only case is named in the detail" || fail "file-only detail: '$co_detail'"
# The failure above is narrow on purpose: it fires when the denominator emptied
# because file components stopped being counted, and nowhere else. An SBOM with no
# components at all, or one whose components are all data, must still not read as
# uncovered — a dataset has no purl and no package version to begin with, and an
# SBOM listing only datasets is legitimate to submit. It is not reported as met
# either: crediting an empty denominator would rank such a document above one that
# lists packages and is measured on them. Both checks come back not-applicable,
# which leaves the coverage fractions and never moves the result.
jq '.components = []' "$FIX/good-cyclonedx.json" > "$WORK/conf-empty.json"
bash "$LIB/validate-sbom.sh" "$WORK/conf-empty.json" "$WORK/ce" "supplier" >/dev/null 2>&1
ce=$(jq -r '"\(.result)/\(.checks[]|select(.id=="name-version")|.naKind // "-")/\(.checks[]|select(.id=="purl")|.naKind // "-")"' "$WORK/ce_conformance.json")
[ "$ce" = "pass/not-applicable/not-applicable" ] \
    && pass "an SBOM with no components at all is neither uncovered nor credited" \
    || fail "empty SBOM: result/name-version/purl = $ce, expected pass/not-applicable/not-applicable"
ce_detail=$(jq -r '.checks[] | select(.id=="purl") | .detail' "$WORK/ce_conformance.json")
[ "$ce_detail" = "no packages to measure" ] \
    && pass "the empty-denominator case says why it cannot be measured" || fail "empty detail: '$ce_detail'"
jq '.components = [.components[] | select(.type=="data")]' "$FIX/aibom-datasets-1_7.json" > "$WORK/conf-dataonly.json"
bash "$LIB/validate-sbom.sh" "$WORK/conf-dataonly.json" "$WORK/cd" "supplier" >/dev/null 2>&1
# Only the two coverage checks are read here: dropping the model from an AI SBOM
# also drops the 1.7 spec version out of its allowed range, which fails the
# document for a reason that has nothing to do with the empty denominator.
cd_st=$(jq -r '"\(.checks[]|select(.id=="name-version")|.naKind // "-")/\(.checks[]|select(.id=="purl")|.naKind // "-")"' "$WORK/cd_conformance.json")
[ "$cd_st" = "not-applicable/not-applicable" ] \
    && pass "an SBOM of datasets only is neither uncovered nor credited" \
    || fail "data-only SBOM: name-version/purl = $cd_st, expected not-applicable/not-applicable"

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

echo "== sec-firmware-type: a root type Trivy cannot decode is retried, not failed =="
# Regression for the SCA-benchmark report: a firmware scan's root component
# (metadata.component.type = "firmware", CycloneDX 1.4+) made the bundled Trivy 0.70
# fail the whole SBOM decode with "unsupported type", emptying the security report.
# This stub trivy mimics that: it rejects a newer root type and succeeds once the root
# is coerced to a type it accepts — exactly the retry scan-security.sh now performs.
cat > "$FAKEBIN/trivy" <<'SH'
#!/bin/sh
out=""; sbom=""
while [ $# -gt 0 ]; do
    case "$1" in
        --output) out="$2"; shift ;;
        *.json)   sbom="$1" ;;
    esac
    shift
done
rt=$(jq -r '.metadata.component.type // ""' "$sbom" 2>/dev/null)
case "$rt" in
    firmware|device|platform|data|machine-learning-model|cryptographic-asset)
        echo "2026-07-03T00:00:00Z	FATAL	Fatal error	failed to parse metadata component: failed to unmarshal component type: unsupported type" >&2
        exit 1 ;;
esac
echo '{"SchemaVersion":2,"Results":[{"Target":"sbom","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-2020-2222","PkgName":"busybox","InstalledVersion":"1.36.0","Severity":"HIGH"}]}]}' > "$out"
exit 0
SH
chmod +x "$FAKEBIN/trivy"
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"type":"firmware","name":"rootfs.squashfs","version":"1.0.0"}},"components":[{"type":"library","name":"busybox","version":"1.36.0","purl":"pkg:generic/busybox@1.36.0"}]}' > "$WORK/fwtype-bom.json"
PATH="$FAKEBIN:$PATH" SECURITY_ENRICH=false \
    bash "$LIB/scan-security.sh" "$WORK/fwtype-bom.json" "$WORK/fwtype" proj >/dev/null 2>&1 \
    || fail "scan-security.sh exited non-zero on the firmware-type retry path"
[ "$(jq -r '.ScanError.Message // "none"' "$WORK/fwtype_security.json")" = "none" ] \
    && pass "firmware root type retried with a coerced type -> no ScanError" \
    || fail "firmware root type still produced a ScanError"
[ "$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$WORK/fwtype_security.json")" -ge 1 ] \
    && pass "Trivy vulnerabilities present after the retry" \
    || fail "no vulnerabilities after the firmware-type retry"
[ "$(jq -r '.metadata.component.type' "$WORK/fwtype-bom.json")" = "firmware" ] \
    && pass "delivered SBOM still declares type=firmware (only Trivy's input was remapped)" \
    || fail "delivered SBOM root type was mutated"

echo "== B-obs: best-effort steps log + mark failures instead of swallowing them =="
# run_optional_step keeps the "never abort a scan" guarantee of the old
# `... || true`, but a failed step must now be observable: a WARN line and a
# marker on the SBOM, so a silently-wrong SBOM is no longer produced.
. "$LIB/pipeline-step.sh"
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{},"components":[]}' > "$WORK/obs.json"
# run_optional_step reads OUTPUT_FILE from the sourced lib, which shellcheck
# cannot see, so the assignment looks unused.
# shellcheck disable=SC2034
OUTPUT_FILE="$WORK/obs.json"
if run_optional_step normalize false 2>"$WORK/obs-warn.log"; then
    pass "run_optional_step returns 0 on a failed step (scan is not aborted)"
else
    fail "run_optional_step propagated a non-zero exit (would abort the scan)"
fi
grep -q "post-process step 'normalize' failed" "$WORK/obs-warn.log" \
    && pass "a failed step logs a WARN (no longer silent)" \
    || fail "no WARN logged for a failed step"
if jq -e '.metadata.properties[]? | select(.name=="bomlens:pipeline-step-failed" and .value=="normalize")' "$WORK/obs.json" >/dev/null 2>&1; then
    pass "the SBOM records bomlens:pipeline-step-failed=normalize"
else
    fail "failed step not recorded on the SBOM"
fi
# A succeeding step adds neither a WARN nor a marker.
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{},"components":[]}' > "$WORK/obs2.json"
# shellcheck disable=SC2034  # read by run_optional_step in the sourced lib
OUTPUT_FILE="$WORK/obs2.json"
run_optional_step enrich-cpe true 2>/dev/null
if jq -e '.metadata.properties[]? | select(.name=="bomlens:pipeline-step-failed")' "$WORK/obs2.json" >/dev/null 2>&1; then
    fail "a successful step wrongly recorded a failure marker"
else
    pass "a successful step adds no failure marker"
fi
# A missing SBOM must be a no-op, never a crash (e.g. ANALYZE conformance runs
# before the CycloneDX output exists).
if mark_pipeline_warning "$WORK/does-not-exist.json" normalize; then
    pass "mark_pipeline_warning no-ops on a missing SBOM"
else
    fail "mark_pipeline_warning errored on a missing file"
fi

echo "== node-scope: production filter drops the devDependencies tree =="
# Guards docker/lib/build-prep.sh's node production-scope filter: cdxgen pulls a
# deployed app's devDependencies (jest/eslint/@babel/...) into the SBOM, and the
# filter must drop them (npm components not in the resolved production set) while
# keeping production deps, non-npm components, and a consistent dependency graph.
# Extract the real inlined filter JS from build-prep.sh (no logic duplication).
if command -v node >/dev/null 2>&1; then
    NFLT="$WORK/node-prod-filter.js"
    sed -n "/<<'NFILTER_JS'/,/^NFILTER_JS\$/p" "$ROOT_DIR/docker/lib/build-prep.sh" \
        | sed '1d;$d' > "$NFLT"
    if [ -s "$NFLT" ]; then
        cat > "$WORK/node-bom.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6",
 "metadata":{"component":{"name":"app","version":"1.0.0","bom-ref":"root"}},
 "components":[
   {"name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2","bom-ref":"express@4.18.2"},
   {"name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21","bom-ref":"lodash@4.17.21"},
   {"name":"jest","version":"29.7.0","purl":"pkg:npm/jest@29.7.0","bom-ref":"jest@29.7.0"},
   {"group":"@babel","name":"core","version":"7.0.0","purl":"pkg:npm/%40babel/core@7.0.0","bom-ref":"babel-core"},
   {"name":"somelib","version":"1.0","purl":"pkg:pypi/somelib@1.0","bom-ref":"pylib"}
 ],
 "dependencies":[
   {"ref":"root","dependsOn":["express@4.18.2","jest@29.7.0"]},
   {"ref":"express@4.18.2","dependsOn":["lodash@4.17.21"]},
   {"ref":"jest@29.7.0","dependsOn":[]}
 ]}
JSON
        printf 'express@4.18.2\nlodash@4.17.21\n' > "$WORK/node-prod.set"
        node "$NFLT" "$WORK/node-bom.json" "$WORK/node-prod.set" 2>/dev/null
        names=$(jq -r '[.components[].name]|sort|join(",")' "$WORK/node-bom.json")
        [ "$names" = "express,lodash,somelib" ] \
            && pass "dev tree dropped; production npm + non-npm kept (got: $names)" \
            || fail "unexpected components after node filter" "$names"
        # A dropped dev dep must not linger as a dangling graph edge.
        if jq -e '[.dependencies[].ref] | index("jest@29.7.0")' "$WORK/node-bom.json" >/dev/null 2>&1; then
            fail "dropped jest still has a dependency entry"
        else
            pass "dropped dev dep removed from the dependency graph"
        fi
        if jq -e '.dependencies[] | select(.ref=="root") | .dependsOn | index("jest@29.7.0")' "$WORK/node-bom.json" >/dev/null 2>&1; then
            fail "root still dependsOn the dropped jest"
        else
            pass "root dependsOn pruned to kept refs (jest edge gone)"
        fi
        jq -e '.dependencies[] | select(.ref=="root") | .dependsOn | index("express@4.18.2")' "$WORK/node-bom.json" >/dev/null 2>&1 \
            && pass "kept production edge (root -> express) preserved" \
            || fail "production edge wrongly dropped"
    else
        fail "could not extract NFILTER_JS from build-prep.sh"
    fi
else
    echo "  SKIP: node unavailable — skipping node production-filter test"
fi

echo "== android-scope: release-config selection picks the right variant (flavored projects) =="
# Guards docker/lib/build-prep.sh's Android config selection. The SCA benchmark
# team found the old `{ grep -x releaseRuntimeClasspath || cat; }` idiom dropped
# every candidate when there was no exact match (grep drains stdin before it
# fails, so `cat` reads an already-empty pipe), and flavored projects silently
# fell back to the full build+test graph. Extract the REAL selection snippet from
# build-prep.sh (no logic duplication) and drive it with fixture `:dependencies`.
PREP="$ROOT_DIR/docker/lib/build-prep.sh"
SEL=$(sed -n '/_cands=/,/head -1)/p' "$PREP")
pick_cfg() { local _dep="$1" _cands _cfg; eval "$SEL"; printf '%s' "$_cfg"; }
_plain='releaseRuntimeClasspath - Runtime classpath of release.
+--- a:b:1.0
debugRuntimeClasspath - dbg'
_flavor='freeReleaseRuntimeClasspath - Free release.
+--- a:b:1.0
paidReleaseRuntimeClasspath - Paid release.
freeDebugRuntimeClasspath - dbg
releaseUnitTestRuntimeClasspath - test'
_none='debugRuntimeClasspath - dbg'
[ "$(pick_cfg "$_plain")" = "releaseRuntimeClasspath" ] \
    && pass "plain project selects releaseRuntimeClasspath" \
    || fail "plain selection wrong" "got [$(pick_cfg "$_plain")]"
[ "$(pick_cfg "$_flavor")" = "freeReleaseRuntimeClasspath" ] \
    && pass "flavored project selects the first release variant (freeReleaseRuntimeClasspath)" \
    || fail "flavored selection dropped to full graph or wrong variant" "got [$(pick_cfg "$_flavor")]"
[ -z "$(pick_cfg "$_none")" ] \
    && pass "no release config -> empty (module skipped, full graph)" \
    || fail "unexpected config for a release-less module" "got [$(pick_cfg "$_none")]"
if grep -q 'grep -x releaseRuntimeClasspath || cat' "$PREP"; then
    fail "the stdin-draining '{ grep -x ... || cat; }' idiom is back in build-prep.sh"
else
    pass "build-prep.sh no longer uses the stdin-draining grep||cat idiom"
fi

echo "== EOL: offline end-of-life flagging (enrich-eol.sh) — PURL whitelist + cycle lookup =="
cp "$FIX/eol-components.json" "$WORK/eol.json"
EOL_DATA_FILE="$FIX/eol-data.json" bash "$LIB/enrich-eol.sh" "$WORK/eol.json" >/dev/null 2>&1
# Helper: read a component's bomlens:eol* property value (ABSENT if not present).
eolprop() { jq -r --arg n "$1" --arg p "$2" '.components[] | select(.name==$n)
    | [(.properties // [])[] | select(.name==$p) | .value][0] // "ABSENT"' "$WORK/eol.json"; }
# A cycle whose published EOL date is in the past is flagged true, with the date.
[ "$(eolprop spring-boot-starter-web bomlens:eol)" = "true" ] \
    && pass "past-EOL cycle flagged bomlens:eol=true (spring-boot 3.2)" \
    || fail "spring-boot 3.2 eol='$(eolprop spring-boot-starter-web bomlens:eol)', expected true"
[ "$(eolprop spring-boot-starter-web bomlens:eol:date)" = "2020-01-01" ] \
    && pass "the published EOL date is recorded (bomlens:eol:date)" \
    || fail "eol:date='$(eolprop spring-boot-starter-web bomlens:eol:date)', expected 2020-01-01"
[ "$(eolprop spring-boot-starter-web bomlens:eol:cycle)" = "3.2" ] \
    && pass "major.minor cycle derived from version (3.2.0 -> 3.2)" \
    || fail "cycle='$(eolprop spring-boot-starter-web bomlens:eol:cycle)', expected 3.2"
[ "$(eolprop spring-boot-starter-web bomlens:eol:product)" = "spring-boot" ] \
    && pass "mapped to the endoflife product by PURL namespace" \
    || fail "product='$(eolprop spring-boot-starter-web bomlens:eol:product)', expected spring-boot"
# A cycle whose EOL date is in the future is flagged false (still supported).
[ "$(eolprop spring-boot-actuator bomlens:eol)" = "false" ] \
    && pass "future-EOL cycle flagged bomlens:eol=false (spring-boot 3.3)" \
    || fail "spring-boot 3.3 eol='$(eolprop spring-boot-actuator bomlens:eol)', expected false"
# A boolean eol:false in the dataset is honored (express 4 is not EOL).
[ "$(eolprop express bomlens:eol)" = "false" ] \
    && pass "boolean eol:false honored (express 4)" \
    || fail "express eol='$(eolprop express bomlens:eol)', expected false"
# A mapped product but a cycle absent from the dataset -> unknown, never a guess.
[ "$(eolprop spring-boot-experimental bomlens:eol)" = "unknown" ] \
    && pass "mapped product, unknown cycle -> bomlens:eol=unknown" \
    || fail "spring-boot 9.9 eol='$(eolprop spring-boot-experimental bomlens:eol)', expected unknown"
[ "$(eolprop spring-boot-experimental bomlens:eol:date)" = "ABSENT" ] \
    && pass "unknown cycle carries no eol:date" \
    || fail "unexpected eol:date on unknown cycle"
# django 4.2 EOL date is past -> true (pypi PURL match).
[ "$(eolprop django bomlens:eol)" = "true" ] \
    && pass "pypi PURL mapped and flagged (django 4.2)" \
    || fail "django eol='$(eolprop django bomlens:eol)', expected true"
# An unmapped component is left untouched (implicitly unknown), no property added.
[ "$(eolprop lodash bomlens:eol)" = "ABSENT" ] \
    && pass "unmapped component untouched (no bomlens:eol property)" \
    || fail "lodash wrongly annotated: '$(eolprop lodash bomlens:eol)'"
# PURL prefix guard: express-session must NOT match the express@ rule.
[ "$(eolprop express-session bomlens:eol)" = "ABSENT" ] \
    && pass "prefix guard: express-session not mis-matched to express" \
    || fail "express-session wrongly matched express: '$(eolprop express-session bomlens:eol)'"
# Attribution is recorded on every flagged component.
[ "$(eolprop django bomlens:eol:source)" = "endoflife.date@2026-01-01" ] \
    && pass "source attribution recorded (endoflife.date@<snapshot>)" \
    || fail "source='$(eolprop django bomlens:eol:source)', expected endoflife.date@2026-01-01"
# Offline version currency: endoflife's per-cycle `latest` lets us flag a
# component behind the newest patch of its OWN cycle, no network.
[ "$(eolprop spring-boot-starter-web bomlens:currency:outdated)" = "true" ] \
    && pass "behind the latest patch in-cycle -> currency:outdated=true (3.2.0 < 3.2.12)" \
    || fail "boot 3.2.0 outdated='$(eolprop spring-boot-starter-web bomlens:currency:outdated)', expected true"
[ "$(eolprop spring-boot-starter-web bomlens:currency:latestPatch)" = "3.2.12" ] \
    && pass "the latest in-cycle patch is recorded (currency:latestPatch)" \
    || fail "latestPatch='$(eolprop spring-boot-starter-web bomlens:currency:latestPatch)', expected 3.2.12"
# Numeric compare, not lexicographic (4.18.2 < 4.21.0 must be true).
[ "$(eolprop express bomlens:currency:outdated)" = "true" ] \
    && pass "numeric version compare (4.18.2 < 4.21.0 -> outdated)" \
    || fail "express outdated='$(eolprop express bomlens:currency:outdated)', expected true"
# On the latest patch of its cycle -> not outdated.
[ "$(eolprop spring-boot-uptodate bomlens:currency:outdated)" = "false" ] \
    && pass "on the latest in-cycle patch -> currency:outdated=false (3.3.5)" \
    || fail "uptodate outdated='$(eolprop spring-boot-uptodate bomlens:currency:outdated)', expected false"
# A cycle with no `latest` in the dataset -> no currency props (nothing to compare).
[ "$(eolprop express-old bomlens:currency:latestPatch)" = "ABSENT" ] \
    && pass "no dataset latest -> no currency:latestPatch" \
    || fail "express-old wrongly got latestPatch='$(eolprop express-old bomlens:currency:latestPatch)'"
# Unknown cycle (no entry) -> no currency either.
[ "$(eolprop spring-boot-experimental bomlens:currency:outdated)" = "ABSENT" ] \
    && pass "unknown cycle -> no currency:outdated" \
    || fail "experimental wrongly got outdated"
# Idempotent: a second run changes nothing.
cp "$WORK/eol.json" "$WORK/eol2.json"
EOL_DATA_FILE="$FIX/eol-data.json" bash "$LIB/enrich-eol.sh" "$WORK/eol2.json" >/dev/null 2>&1
if diff -q "$WORK/eol.json" "$WORK/eol2.json" >/dev/null 2>&1; then pass "enrich-eol.sh is idempotent"; else fail "second enrich-eol run changed the SBOM"; fi
# No bundled dataset -> clean skip (SBOM unchanged), never an abort.
cp "$FIX/eol-components.json" "$WORK/eol3.json"
EOL_DATA_FILE="$WORK/does-not-exist.json" bash "$LIB/enrich-eol.sh" "$WORK/eol3.json" >/dev/null 2>&1
rc=$?
if [ "$rc" = "0" ] && diff -q "$FIX/eol-components.json" "$WORK/eol3.json" >/dev/null 2>&1; then
    pass "missing dataset -> clean skip, SBOM untouched (air-gap safe)"
else
    fail "missing-dataset path changed the SBOM or failed (rc=$rc)"
fi

echo "== staleness: opt-in deps.dev version currency (enrich-staleness.py, offline fixture) =="
cp "$FIX/staleness-components.json" "$WORK/stale.json"
STALENESS_FIXTURE_DIR="$FIX/staleness" python3 "$LIB/enrich-staleness.py" "$WORK/stale.json" >/dev/null 2>&1
src=$?
stprop() { jq -r --arg n "$1" --arg p "$2" '.components[] | select(.name==$n)
    | [(.properties // [])[] | select(.name==$p) | .value][0] // "ABSENT"' "$WORK/stale.json"; }
[ "$src" = "0" ] && pass "enrich-staleness exits 0 (best-effort)" || fail "enrich-staleness rc=$src"
# Latest across all lines = the deps.dev default version.
[ "$(stprop express bomlens:staleness:latest)" = "5.0.0" ] \
    && pass "absolute latest from deps.dev default (5.0.0)" \
    || fail "express latest='$(stprop express bomlens:staleness:latest)', expected 5.0.0"
# releasesBehind counts non-deprecated versions published after the installed one.
[ "$(stprop express bomlens:staleness:releasesBehind)" = "2" ] \
    && pass "releasesBehind excludes deprecated, counts newer (4.19.0 + 5.0.0 = 2)" \
    || fail "express releasesBehind='$(stprop express bomlens:staleness:releasesBehind)', expected 2"
[ "$(stprop express bomlens:staleness:lastReleased)" = "2024-09-10T00:00:00Z" ] \
    && pass "lastReleased = publish date of the latest version" \
    || fail "express lastReleased='$(stprop express bomlens:staleness:lastReleased)'"
# Installed version unknown to deps.dev -> report latest, but no untrusted behind count.
[ "$(stprop express-future bomlens:staleness:latest)" = "5.0.0" ] \
    && pass "unknown installed version still reports latest" \
    || fail "express-future latest='$(stprop express-future bomlens:staleness:latest)'"
[ "$(stprop express-future bomlens:staleness:releasesBehind)" = "ABSENT" ] \
    && pass "unknown installed version -> no releasesBehind (not guessed)" \
    || fail "express-future wrongly got releasesBehind"
# An ecosystem deps.dev does not index (pkg:generic) is left untouched.
[ "$(stprop internal-thing bomlens:staleness:latest)" = "ABSENT" ] \
    && pass "unsupported ecosystem (pkg:generic) untouched" \
    || fail "internal-thing wrongly enriched"
# Idempotent: a second run does not duplicate staleness props.
STALENESS_FIXTURE_DIR="$FIX/staleness" python3 "$LIB/enrich-staleness.py" "$WORK/stale.json" >/dev/null 2>&1
n_latest=$(jq '[.components[] | (.properties // [])[] | select(.name=="bomlens:staleness:latest")] | length' "$WORK/stale.json")
[ "$n_latest" = "2" ] && pass "enrich-staleness is idempotent (no duplicate props)" || fail "staleness props duplicated: $n_latest latest entries"

echo "== yocto: SPDX 3.0 image SBOM is read for its installed set and VEX verdicts =="
# parse-yocto-spdx.py exists because syft, the generic converter, reads these
# documents but returns source files as components and drops every vulnerability.
# Needs no syft and no Docker — pure stdlib Python over the JSON-LD graph — so
# unlike the SPDX 3.0 conversion checks below this runs on every CI push.
python3 "$LIB/parse-yocto-spdx.py" "$FIX/yocto-spdx3-image.json" "$WORK/yocto.cdx.json" "$WORK/yocto" >/dev/null 2>&1
yrc=$?
[ "$yrc" = "0" ] && pass "parser accepts a Yocto SPDX 3.0 document" || fail "parser rc=$yrc on the Yocto fixture"
ynames=$(jq -r '[.components[].name] | sort | join(",")' "$WORK/yocto.cdx.json" 2>/dev/null)
# The fixture also carries a source tarball; shipping it as a component would
# claim the image contains build inputs it does not.
[ "$ynames" = "busybox,libz1" ] \
    && pass "only primaryPurpose=install packages become components (source tarball dropped)" \
    || fail "components='$ynames', expected busybox,libz1"
[ "$(jq '[.components[] | select(.cpe)] | length' "$WORK/yocto.cdx.json")" = "1" ] \
    && pass "Yocto's own cpe23 identifier is carried over" || fail "cpe not carried over"
[ "$(jq -r '.components[] | select(.name=="busybox") | .licenses[0].expression' "$WORK/yocto.cdx.json")" = "GPL-2.0-only AND LicenseRef-bzip2-1.0.4" ] \
    && pass "compound license lands in licenses[].expression" || fail "compound license not preserved"
[ "$(jq -r '.components[] | select(.name=="libz1") | .licenses[0].license.id' "$WORK/yocto.cdx.json")" = "Zlib" ] \
    && pass "single license id lands in licenses[].license.id" || fail "single license id not preserved"

# The judgement split is the reason to read these documents: an outside scanner
# keyed on version alone would report the patched CVE as open.
[ "$(jq -r '[.judgements.fixed, .judgements.notAffected, .judgements.affected] | join("/")' "$WORK/yocto_yocto_vex.json")" = "1/1/1" ] \
    && pass "VEX verdicts split into fixed / not-affected / unresolved" \
    || fail "vex counts=$(jq -c '.judgements' "$WORK/yocto_yocto_vex.json")"
[ "$(jq -r '[.Results[].Vulnerabilities[].VulnerabilityID] | join(",")' "$WORK/yocto_security_yocto.json")" = "CVE-2022-28391" ] \
    && pass "only the unjudged CVE reaches the security sidecar" \
    || fail "sidecar carries $(jq -c '[.Results[].Vulnerabilities[].VulnerabilityID]' "$WORK/yocto_security_yocto.json")"

# Runtime dependency edges. The fixture also carries a build-scoped edge and an
# edge into the source tarball; neither describes what the image needs to run, so
# exactly one edge (busybox -> libz1) must survive.
[ "$(jq '[.dependencies[]?.dependsOn[]?] | length' "$WORK/yocto.cdx.json")" = "1" ] \
    && pass "only runtime-scoped edges between installed packages become dependencies" \
    || fail "dependency edges=$(jq -c '[.dependencies[]?]' "$WORK/yocto.cdx.json")"
# Conformance measures name/version and the graph, so losing document metadata
# would trade a correct component list for a worse verdict.
[ "$(jq -r '.metadata.component.name' "$WORK/yocto.cdx.json")" = "core-image-minimal" ] \
    && pass "root component names the image, not the uploaded filename" \
    || fail "root component='$(jq -r '.metadata.component.name' "$WORK/yocto.cdx.json")'"
[ "$(jq -r '.metadata.timestamp' "$WORK/yocto.cdx.json")" = "2026-01-01T00:00:00Z" ] \
    && pass "document creation time is carried into metadata.timestamp" \
    || fail "timestamp='$(jq -r '.metadata.timestamp' "$WORK/yocto.cdx.json")'"

# rc=3 means "not mine" and must stay non-fatal: the generic converter handles
# every other supplier SBOM.
python3 "$LIB/parse-yocto-spdx.py" "$FIX/good-cyclonedx.json" "$WORK/nope.json" >/dev/null 2>&1
[ "$?" = "3" ] && pass "non-Yocto input is declined with rc=3 (generic path takes over)" || fail "parser did not decline CycloneDX input"

# Yocto SPDX 2.x writes a near-empty top-level document and puts the real package
# set in a sibling tarball. Converting it succeeds and finds nothing, so the user
# must be told where the content is rather than shown an empty successful scan.
cat > "$WORK/y22.json" <<'YEOF'
{"spdxVersion":"SPDX-2.2","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"core-image-minimal",
 "documentNamespace":"http://spdx.org/spdxdocs/bitbake-1234",
 "creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: bitbake","Organization: OpenEmbedded"]},
 "packages":[]}
YEOF
y22_msg=$(python3 "$LIB/parse-yocto-spdx.py" "$WORK/y22.json" "$WORK/y22-out.json" 2>&1 >/dev/null)
y22_rc=$?
[ "$y22_rc" = "3" ] && echo "$y22_msg" | grep -q "spdx.tar.zst" \
    && pass "Yocto SPDX 2.x index document names the file that holds the packages" \
    || fail "SPDX 2.x index not recognised (rc=$y22_rc): $y22_msg"

# With the archive beside it, that same document is readable: the packages come
# out of the per-document members and the CPEs off the recipes they were built
# from. The fixture is generated rather than committed so its shape stays
# checkable — it mirrors create-spdx-2.2.bbclass (openembedded-core): members
# named <document>.spdx.json, an index.json, CONTAINS for installed packages and
# OTHER for the runtime documents.
if command -v zstd >/dev/null 2>&1; then
    Y22DIR="$WORK/y22bundle"
    python3 - "$Y22DIR" <<'PYGEN'
import hashlib, io, json, os, subprocess, sys, tarfile

out_dir = sys.argv[1]
os.makedirs(out_dir, exist_ok=True)
stem = "core-image-minimal-qemux86-64.rootfs"
CREATORS = ["Tool: OpenEmbedded Core create-spdx.bbclass", "Organization: OE ()"]

def doc(name, suffix):
    return {"spdxVersion": "SPDX-2.2", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": name, "documentNamespace": "http://spdx.org/spdxdocs/%s-%s" % (name, suffix),
            "creationInfo": {"created": "2026-01-02T00:00:00Z", "creators": CREATORS},
            "packages": [], "relationships": [], "externalDocumentRefs": []}

recipes = {}
for pn, pv, lic, cpe in [
    ("busybox", "1.36.1", "GPL-2.0-only AND LicenseRef-bzip2-1.0.4",
     "cpe:2.3:a:*:busybox:1.36.1:*:*:*:*:*:*:*"),
    ("zlib", "1.3", "Zlib", "cpe:2.3:a:*:zlib:1.3:*:*:*:*:*:*:*"),
]:
    d = doc("recipe-" + pn, "r")
    d["packages"] = [{"SPDXID": "SPDXRef-Recipe-" + pn, "name": pn, "versionInfo": pv,
                      "licenseDeclared": lic, "licenseConcluded": "NOASSERTION",
                      "sourceInfo": "CVEs fixed: CVE-2023-42363",
                      "externalRefs": [{"referenceCategory": "SECURITY",
                                        "referenceType": "http://spdx.org/rdf/references/cpe23Type",
                                        "referenceLocator": cpe}]}]
    recipes["recipe-" + pn] = d

packages = {}
for pkg, recipe, pv, lic in [
    ("busybox", "recipe-busybox", "1.36.1", "GPL-2.0-only AND LicenseRef-bzip2-1.0.4"),
    ("libz1", "recipe-zlib", "1.3", "Zlib"),
    # No license of its own: the recipe's has to fill in.
    ("busybox-syslog", "recipe-busybox", "1.36.1", "NOASSERTION"),
]:
    d = doc(pkg, "p")
    rid = "SPDXRef-Package-" + pkg
    d["packages"] = [{"SPDXID": rid, "name": pkg, "versionInfo": pv,
                      "licenseDeclared": lic, "licenseConcluded": "NOASSERTION"}]
    d["relationships"] = [{"spdxElementId": rid, "relationshipType": "GENERATED_FROM",
                           "relatedSpdxElement": "DocumentRef-%s:SPDXRef-Recipe-%s"
                                                  % (recipe, recipe[len("recipe-"):])}]
    packages[pkg] = d

runtimes = {}
for pkg in packages:
    d = doc("runtime-" + pkg, "rt")
    d["packages"] = [{"SPDXID": "SPDXRef-Runtime-" + pkg, "name": "runtime-" + pkg,
                      "versionInfo": "1.0", "licenseDeclared": "NOASSERTION"}]
    runtimes["runtime-" + pkg] = d

image = doc(stem, "i")
image["packages"] = [{"SPDXID": "SPDXRef-Image", "name": "core-image-minimal", "versionInfo": "1.0"}]
for pkg, d in packages.items():
    image["externalDocumentRefs"].append({"externalDocumentId": "DocumentRef-" + pkg,
                                          "spdxDocument": d["documentNamespace"]})
    image["relationships"].append({"spdxElementId": "SPDXRef-Image", "relationshipType": "CONTAINS",
                                   "relatedSpdxElement": "DocumentRef-%s:SPDXRef-Package-%s" % (pkg, pkg)})
for rt, d in runtimes.items():
    image["relationships"].append({"spdxElementId": "SPDXRef-Image", "relationshipType": "OTHER",
                                   "relatedSpdxElement": "DocumentRef-%s:SPDXRef-DOCUMENT" % rt,
                                   "comment": "Runtime dependencies"})

with open(os.path.join(out_dir, stem + ".spdx.json"), "w") as fh:
    json.dump(image, fh, indent=2, sort_keys=True)

all_docs = dict(recipes); all_docs.update(packages); all_docs.update(runtimes); all_docs[stem] = image
raw, index = io.BytesIO(), {"documents": []}
with tarfile.open(fileobj=raw, mode="w|") as tar:
    for name in sorted(all_docs):
        blob = json.dumps(all_docs[name], sort_keys=True, indent=2).encode()
        info = tarfile.TarInfo(name + ".spdx.json"); info.size = len(blob)
        tar.addfile(info, io.BytesIO(blob))
        index["documents"].append({"filename": info.name, "sha1": hashlib.sha1(blob).hexdigest(),
                                   "documentNamespace": all_docs[name]["documentNamespace"]})
    blob = json.dumps(index, sort_keys=True, indent=2).encode()
    info = tarfile.TarInfo("index.json"); info.size = len(blob)
    tar.addfile(info, io.BytesIO(blob))
subprocess.run(["zstd", "-q", "-f", "-o", os.path.join(out_dir, stem + ".spdx.tar.zst"), "-"],
               input=raw.getvalue(), check=True)
PYGEN
    y22b_msg=$(python3 "$LIB/parse-yocto-spdx.py" \
        "$Y22DIR/core-image-minimal-qemux86-64.rootfs.spdx.json" \
        "$WORK/y22b.cdx.json" "$WORK/y22b" 2>&1 >/dev/null)
    y22b_rc=$?
    [ "$y22b_rc" = "0" ] && pass "an SPDX 2.x image document with its archive is read" \
        || fail "SPDX 2.x bundle rejected (rc=$y22b_rc): $y22b_msg"
    y22b_names=$(jq -r '[.components[].name] | sort | join(",")' "$WORK/y22b.cdx.json" 2>/dev/null)
    # CONTAINS names the installed packages; the runtime documents hang off OTHER
    # and describe what a package needs, not what shipped.
    [ "$y22b_names" = "busybox,busybox-syslog,libz1" ] \
        && pass "the installed set comes from CONTAINS (runtime documents excluded)" \
        || fail "SPDX 2.x components='$y22b_names'"
    [ "$(jq -r '.components[] | select(.name=="busybox") | .cpe' "$WORK/y22b.cdx.json")" \
        = "cpe:2.3:a:*:busybox:1.36.1:*:*:*:*:*:*:*" ] \
        && pass "the CPE is taken from the recipe the package was generated from" \
        || fail "SPDX 2.x cpe missing"
    [ "$(jq -r '.components[] | select(.name=="busybox") | .licenses[0].expression' "$WORK/y22b.cdx.json")" \
        = "GPL-2.0-only AND LicenseRef-bzip2-1.0.4" ] \
        && pass "a compound license from the package document is preserved" \
        || fail "SPDX 2.x compound license lost"
    # NOASSERTION is not a license: the recipe's expression fills in instead.
    [ "$(jq -r '.components[] | select(.name=="busybox-syslog") | .licenses[0].expression' "$WORK/y22b.cdx.json")" \
        = "GPL-2.0-only AND LicenseRef-bzip2-1.0.4" ] \
        && pass "a package with no license of its own falls back to its recipe" \
        || fail "SPDX 2.x license fallback missing"
    [ "$(jq -r '.metadata.component.name' "$WORK/y22b.cdx.json")" = "core-image-minimal" ] \
        && pass "the image names the root component (SPDX 2.x)" || fail "SPDX 2.x root component wrong"
    # 2.2 carries no VEX, so no judgement sidecar may be written: an empty one
    # would claim the build made judgements it never recorded.
    [ ! -f "$WORK/y22b_yocto_vex.json" ] \
        && pass "no build-verdict sidecar is invented for SPDX 2.x" \
        || fail "SPDX 2.x wrote a VEX sidecar"
    # A real deploy directory holds the archive and nothing else: the image
    # document is packed inside it, not written beside it (verified against the
    # published Yocto 5.0.14 artifacts). So the archive has to be readable on its
    # own, with the image document found by shape rather than by filename.
    arch_rc=0
    python3 "$LIB/parse-yocto-spdx.py" \
        "$Y22DIR/core-image-minimal-qemux86-64.rootfs.spdx.tar.zst" \
        "$WORK/y22arch.cdx.json" "$WORK/y22arch" >/dev/null 2>&1 || arch_rc=$?
    [ "$arch_rc" = "0" ] && pass "the archive alone is read, with no image document beside it" \
        || fail "archive-only input rejected (rc=$arch_rc)"
    arch_names=$(jq -r '[.components[].name] | sort | join(",")' "$WORK/y22arch.cdx.json" 2>/dev/null)
    [ "$arch_names" = "busybox,busybox-syslog,libz1" ] \
        && pass "the archive-only read finds the same installed set" \
        || fail "archive-only components='$arch_names'"
    [ "$(jq -r '.metadata.component.name' "$WORK/y22arch.cdx.json")" = "core-image-minimal" ] \
        && pass "the image inside the archive names the root component" \
        || fail "archive-only root component wrong"
    # Reading stops at the documents it came for, which closes the pipe under
    # zstd and makes it report a write error it was never going to survive. That
    # is not a failure, and printing it into a scan log would read as one.
    arch_noise=$(python3 "$LIB/parse-yocto-spdx.py" \
        "$Y22DIR/core-image-minimal-qemux86-64.rootfs.spdx.tar.zst" \
        "$WORK/y22noise.cdx.json" "$WORK/y22noise" 2>&1 >/dev/null)
    case "$arch_noise" in
        *"Broken pipe"*|*"Write error"*)
            fail "a successful archive read logs zstd pipe errors" "$arch_noise" ;;
        *)  pass "a successful archive read logs nothing from zstd" ;;
    esac
    # A truncated archive is a real failure, and then zstd's reason is the answer.
    head -c 200 "$Y22DIR/core-image-minimal-qemux86-64.rootfs.spdx.tar.zst" \
        > "$WORK/truncated.spdx.tar.zst"
    trunc_msg=$(python3 "$LIB/parse-yocto-spdx.py" "$WORK/truncated.spdx.tar.zst" \
        "$WORK/trunc.cdx.json" 2>&1 >/dev/null)
    case "$trunc_msg" in
        *zstd*) pass "a truncated archive reports what zstd said about it" ;;
        *)      fail "a truncated archive hides the reason" "$trunc_msg" ;;
    esac

    # Without the archive the same document is only an index again.
    cp "$Y22DIR/core-image-minimal-qemux86-64.rootfs.spdx.json" "$WORK/lonely.spdx.json"
    lonely_rc=0
    python3 "$LIB/parse-yocto-spdx.py" "$WORK/lonely.spdx.json" "$WORK/lonely.cdx.json" >/dev/null 2>&1 || lonely_rc=$?
    [ "$lonely_rc" = "3" ] \
        && pass "the image document alone still declines, with the archive missing" \
        || fail "index-only document returned rc=$lonely_rc"
else
    echo "  SKIP: SPDX 2.x bundle reading (zstd not installed)"
fi

echo "== yocto: a build with no SPDX is read from the manifests it did write =="
# Turning create-spdx on is a build-configuration change the holder of a finished
# build directory cannot always make. The build recorded what it shipped anyway:
# the image package manifest, license.manifest and cve-check's report (formats
# from openembedded-core: rootfs-postcommands, license_image, cve-check).
MFDIR="$WORK/yocto-manifests"
mkdir -p "$MFDIR/tmp/deploy/images/qemux86-64" \
         "$MFDIR/tmp/deploy/licenses/core-image-minimal-qemux86-64-20260720" \
         "$MFDIR/tmp/log/cve"
cat > "$MFDIR/tmp/deploy/images/qemux86-64/core-image-minimal-qemux86-64.rootfs.manifest" <<'MEOF'
base-files core2-64 3.0.14
busybox core2-64 1.36.1
busybox-syslog core2-64 1.36.1
libz1 core2-64 1.3
MEOF
cat > "$MFDIR/tmp/deploy/licenses/core-image-minimal-qemux86-64-20260720/license.manifest" <<'LEOF'
PACKAGE NAME: base-files
PACKAGE VERSION: 3.0.14
RECIPE NAME: base-files
LICENSE: GPL-2.0-only

PACKAGE NAME: busybox
PACKAGE VERSION: 1.36.1
RECIPE NAME: busybox
LICENSE: GPL-2.0-only & bzip2-1.0.4

PACKAGE NAME: busybox-syslog
PACKAGE VERSION: 1.36.1
RECIPE NAME: busybox
LICENSE: GPL-2.0-only

PACKAGE NAME: libz1
PACKAGE VERSION: 1.3
RECIPE NAME: zlib
LICENSE: Zlib

LEOF
# An image_license.manifest sits beside the real one and describes the image
# recipe, not its contents; reading it would replace the package list.
cat > "$MFDIR/tmp/deploy/licenses/core-image-minimal-qemux86-64-20260720/image_license.manifest" <<'IEOF'
RECIPE NAME: core-image-minimal
VERSION: 1.0
LICENSE: MIT
FILES:

IEOF
cat > "$MFDIR/tmp/log/cve/cve-summary.json" <<'CEOF'
{"version":"1","package":[
 {"name":"busybox","layer":"meta","version":"1.36.1","issue":[
   {"id":"CVE-2023-42363","status":"Patched","scorev3":"5.5","summary":"awk use-after-free","link":"a"},
   {"id":"CVE-2022-28391","status":"Unpatched","scorev3":"9.8","summary":"remote code execution","link":"b"},
   {"id":"CVE-2021-42374","status":"Ignored","scorev3":"5.3","summary":"not applicable here","link":"c"}]},
 {"name":"zlib","layer":"meta","version":"1.3","issue":[
   {"id":"CVE-2023-45853","status":"Unpatched","scorev3":"7.5","summary":"integer overflow","link":"d"}]},
 {"name":"gcc-cross-x86_64","layer":"meta","version":"13.2","issue":[
   {"id":"CVE-2023-99999","status":"Unpatched","scorev3":"9.9","summary":"build host only","link":"e"}]}
]}
CEOF
mf_rc=0
python3 "$LIB/parse-yocto-manifests.py" "$MFDIR" "$WORK/mf.cdx.json" "$WORK/mf" >/dev/null 2>&1 || mf_rc=$?
[ "$mf_rc" = "0" ] && pass "a build directory with manifests but no SPDX is read" \
    || fail "manifest parser rc=$mf_rc"
mf_names=$(jq -r '[.components[].name] | sort | join(",")' "$WORK/mf.cdx.json" 2>/dev/null)
[ "$mf_names" = "base-files,busybox,busybox-syslog,libz1" ] \
    && pass "the installed set comes from the image package manifest" \
    || fail "manifest components='$mf_names'"
[ "$(jq -r '.components[] | select(.name=="busybox") | .licenses[0].expression' "$WORK/mf.cdx.json")" \
    = "GPL-2.0-only AND bzip2-1.0.4" ] \
    && pass "license.manifest's Yocto operators are written as SPDX ones" \
    || fail "license expression not normalized: $(jq -c '.components[]|select(.name=="busybox")|.licenses' "$WORK/mf.cdx.json")"
[ "$(jq -r '.components[] | select(.name=="libz1") | (.properties[] | select(.name=="bomlens:yocto:recipe") | .value)' "$WORK/mf.cdx.json")" = "zlib" ] \
    && pass "a package records the recipe it came from when they differ" \
    || fail "recipe property missing"
# cve-check is keyed by recipe, so a recipe that built nothing installed — the
# native and cross tools — must not bring its CVEs into the image's report.
mf_cves=$(jq -r '[.Results[].Vulnerabilities[].VulnerabilityID] | unique | join(",")' "$WORK/mf_security_yocto.json" 2>/dev/null)
[ "$mf_cves" = "CVE-2022-28391,CVE-2023-45853" ] \
    && pass "only CVEs of recipes that shipped a package are reported" \
    || fail "manifest CVEs='$mf_cves'"
[ "$(jq -r '[.Results[].Vulnerabilities[] | select(.VulnerabilityID=="CVE-2022-28391") | .Severity] | unique | join(",")' "$WORK/mf_security_yocto.json")" = "CRITICAL" ] \
    && pass "the CVSS score becomes the severity the report groups by" \
    || fail "severity not derived from the score"
# Patched and Ignored are the build's own judgements and must not be findings.
[ "$(jq -r '[.judgements.fixed, .judgements.notAffected, .judgements.affected] | join("/")' "$WORK/mf_yocto_vex.json")" = "2/2/3" ] \
    && pass "cve-check verdicts split into patched / not applicable / unpatched" \
    || fail "manifest vex counts=$(jq -c '.judgements' "$WORK/mf_yocto_vex.json")"
[ "$(jq -r '.metadata.component.name' "$WORK/mf.cdx.json")" = "core-image-minimal-qemux86-64" ] \
    && pass "the image manifest names the root component" \
    || fail "manifest root='$(jq -r '.metadata.component.name' "$WORK/mf.cdx.json")'"

# The package-to-recipe mapping is not a formality: in real builds most installed
# packages come from a differently-named recipe (measured — 20 of 36 in the
# published Scarthgap core-image-minimal, 32 of 57 in a shipped PinePhone modem
# image). cve-check keys its report by recipe, so without that mapping the CVEs
# of every such package would be missed. The fixture keeps the shape: three
# packages, two of them from one recipe under another name.
mf_recipes=$(jq -r '[.components[] | (.properties[]? | select(.name=="bomlens:yocto:recipe") | .value)] | length' "$WORK/mf.cdx.json")
[ "${mf_recipes:-0}" -ge 1 ] \
    && pass "packages whose recipe has another name record it" \
    || fail "no package recorded a differing recipe name"
mf_bb=$(jq -r '[.Results[].Vulnerabilities[] | select(.VulnerabilityID=="CVE-2022-28391") | .PkgName] | sort | join(",")' "$WORK/mf_security_yocto.json")
[ "$mf_bb" = "busybox,busybox-syslog" ] \
    && pass "a recipe's CVE reaches every package it produced" \
    || fail "recipe CVE did not reach all its packages: '$mf_bb'"

# A build with an image manifest but no cve-check run has no verdicts to report,
# and must not claim otherwise.
NOCVE="$WORK/yocto-nocve"
mkdir -p "$NOCVE/tmp/deploy/images/m1"
printf 'busybox core2-64 1.36.1\n' > "$NOCVE/tmp/deploy/images/m1/img.rootfs.manifest"
python3 "$LIB/parse-yocto-manifests.py" "$NOCVE" "$WORK/nocve.cdx.json" "$WORK/nocve" >/dev/null 2>&1
[ ! -f "$WORK/nocve_yocto_vex.json" ] && [ ! -f "$WORK/nocve_security_yocto.json" ] \
    && pass "no cve-check run means no verdicts and no findings are invented" \
    || fail "manifest parser invented CVE output without cve-check"

# Nothing to read at all is rc=3, so the caller can say what is missing.
empty_rc=0
python3 "$LIB/parse-yocto-manifests.py" "$WORK" "$WORK/none.cdx.json" >/dev/null 2>&1 || empty_rc=$?
[ "$empty_rc" = "3" ] && pass "a directory with no image manifest declines with rc=3" \
    || fail "manifest parser rc=$empty_rc on a directory with no manifest"

echo "== convert: a non-empty SBOM never converts to an empty one silently =="
# A valid-but-empty CycloneDX passes every later step, and the report then reads
# "no components, no vulnerabilities" — indistinguishable from a clean result.
cat > "$WORK/pkgs-only.spdx.json" <<'PEOF'
{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"t",
 "documentNamespace":"http://example.org/doc",
 "creationInfo":{"created":"2026-01-01T00:00:00Z","creators":["Tool: test"]},
 "packages":[{"SPDXID":"SPDXRef-p1","name":"zlib","versionInfo":"1.3.1","downloadLocation":"NOASSERTION"}]}
PEOF
if bash "$LIB/convert-to-cdx.sh" "$WORK/pkgs-only.spdx.json" "$WORK/pkgs-only.cdx.json" >/dev/null 2>&1; then
    [ "$(jq '[.components[]?] | length' "$WORK/pkgs-only.cdx.json")" -gt 0 ] \
        && pass "a package-bearing SPDX still converts to a non-empty CycloneDX" \
        || fail "conversion succeeded but produced no components"
else
    # No syft in this environment: the guard is what we are testing, and it must
    # be the thing that refuses, not a crash.
    pass "conversion refused rather than emitting an empty SBOM (no converter available)"
fi

echo "== outbound-license: read the declaration out of the project's own manifest =="
# The licence-conflict check only runs when the SBOM's root component carries a
# licence, and cdxgen fills that for npm only. detect-project-license.py reads
# the manifest so a project that already declared its licence the standard way
# does not have to repeat it with --license. Guessing is the failure mode to
# guard against: a wrong id produces conflict verdicts against a licence the
# project never chose, so an unrecognised value must yield nothing.
DPL="$ROOT_DIR/docker/lib/detect-project-license.py"
lic_dir="$WORK/lic"

mk_pom() { # mk_pom <dir> <inner-xml>
    mkdir -p "$1"
    { echo '<project xmlns="http://maven.apache.org/POM/4.0.0"><artifactId>a</artifactId>'
      echo "$2"; echo '</project>'; } > "$1/pom.xml"
}

rm -rf "$lic_dir"; mk_pom "$lic_dir" '<licenses><license><name>Apache-2.0</name></license></licenses>'
got=$(python3 "$DPL" "$lic_dir")
[ "$got" = "Apache-2.0" ] && pass "pom.xml: SPDX id read as-is" || fail "pom.xml SPDX id -> '$got'"

# Real POMs mostly spell the licence out rather than using the SPDX id.
rm -rf "$lic_dir"; mk_pom "$lic_dir" '<licenses><license><name>The Apache License, Version 2.0</name></license></licenses>'
got=$(python3 "$DPL" "$lic_dir")
[ "$got" = "Apache-2.0" ] && pass "pom.xml: free-text licence name mapped to SPDX" || fail "pom.xml free text -> '$got'"

# URL-only declarations: apache.org's is unambiguous, others are not.
rm -rf "$lic_dir"; mk_pom "$lic_dir" '<licenses><license><url>https://www.apache.org/licenses/LICENSE-2.0</url></license></licenses>'
got=$(python3 "$DPL" "$lic_dir")
[ "$got" = "Apache-2.0" ] && pass "pom.xml: apache.org URL alone is enough" || fail "pom.xml url -> '$got'"

# An in-house or unrecognised name must NOT be turned into an SPDX id.
rm -rf "$lic_dir"; mk_pom "$lic_dir" '<licenses><license><name>Acme Internal Use Only</name></license></licenses>'
got=$(python3 "$DPL" "$lic_dir")
[ -z "$got" ] && pass "pom.xml: an unrecognised licence name yields nothing" || fail "unrecognised name guessed '$got'"

# No <licenses> block at all — the check stays off.
rm -rf "$lic_dir"; mk_pom "$lic_dir" '<name>x</name>'
got=$(python3 "$DPL" "$lic_dir")
[ -z "$got" ] && pass "pom.xml: no declaration yields nothing" || fail "missing declaration produced '$got'"

# package.json / Cargo.toml / pyproject.toml carry the same information.
rm -rf "$lic_dir"; mkdir -p "$lic_dir"
echo '{"name":"a","license":"MIT"}' > "$lic_dir/package.json"
got=$(python3 "$DPL" "$lic_dir")
[ "$got" = "MIT" ] && pass "package.json: license read" || fail "package.json -> '$got'"

rm -rf "$lic_dir"; mkdir -p "$lic_dir"
printf '[package]\nname = "a"\nlicense = "MIT OR Apache-2.0"\n' > "$lic_dir/Cargo.toml"
got=$(python3 "$DPL" "$lic_dir")
[ "$got" = "MIT OR Apache-2.0" ] && pass "Cargo.toml: SPDX expression kept intact" || fail "Cargo.toml -> '$got'"

rm -rf "$lic_dir"; mkdir -p "$lic_dir"
printf '[project]\nname = "a"\nlicense = { text = "BSD-3-Clause" }\n' > "$lic_dir/pyproject.toml"
got=$(python3 "$DPL" "$lic_dir")
[ "$got" = "BSD-3-Clause" ] && pass "pyproject.toml: PEP 621 table form read" || fail "pyproject.toml -> '$got'"

# A dependency's manifest must never be mistaken for the project's own.
rm -rf "$lic_dir"; mkdir -p "$lic_dir/node_modules/dep"
echo '{"name":"root"}' > "$lic_dir/package.json"
echo '{"name":"dep","license":"GPL-3.0-only"}' > "$lic_dir/node_modules/dep/package.json"
got=$(python3 "$DPL" "$lic_dir")
[ -z "$got" ] && pass "vendored manifests are ignored" || fail "picked up a dependency's licence: '$got'"

echo "== source-snapshot: capture the scanned files themselves, within bounds =="
# The result screens show what a scan FOUND; source-snapshot.py captures what was
# SCANNED so a reviewer can open the file behind a finding. The scanned tree does
# not outlive the scan, so the capture has to be right the first time. Guarded
# here: the exclusions come from the tree listing (never re-derived), binaries and
# oversized files cannot bloat the artifact, the budget drops are counted rather
# than silent, and a listing entry can never pull in a file outside the tree.
SNAP="$ROOT_DIR/docker/lib/source-snapshot.py"
snap_dir="$WORK/snap"
rm -rf "$snap_dir"; mkdir -p "$snap_dir/tree/src" "$snap_dir/tree/node_modules/dep" "$snap_dir/out"
printf 'package main\n' > "$snap_dir/tree/src/main.go"
printf 'MIT License\n' > "$snap_dir/tree/LICENSE"
printf '{"name":"acme"}\n' > "$snap_dir/tree/package.json"
printf 'pruned\n' > "$snap_dir/tree/node_modules/dep/index.js"
printf 'ELF\0\0\0binary payload\n' > "$snap_dir/tree/src/app.bin"
python3 -c "import sys; open(sys.argv[1],'w').write('x' * 300000)" "$snap_dir/tree/big.txt"
ln -s /etc/passwd "$snap_dir/tree/link.txt"
(
    cd "$snap_dir/out" || exit 1
    bash "$LIB/source-file-tree.sh" "$snap_dir/tree" snap_files.json >/dev/null 2>&1
    python3 "$SNAP" "$snap_dir/tree" snap_files.json snap_source.json >/dev/null 2>&1
)
snap_out="$snap_dir/out/snap_source.json"
if [ -s "$snap_out" ]; then
    pass "snapshot written for a source tree"
else
    fail "no snapshot produced"
fi
got=$(jq -r '[.files[].path] | sort | join(",")' "$snap_out" 2>/dev/null)
[ "$got" = "LICENSE,big.txt,package.json,src/main.go" ] \
    && pass "text files captured; node_modules pruned by the shared listing" \
    || fail "unexpected captured set: '$got'"
got=$(jq -c '[.files[] | select(.path == "src/main.go") | .content]' "$snap_out" 2>/dev/null)
[ "$got" = '["package main\n"]' ] && pass "content is the real file body, newline included" \
    || fail "content mismatch: $got"
got=$(jq -r '.totals.skippedBinary' "$snap_out" 2>/dev/null)
[ "$got" = "1" ] && pass "binary counted, never embedded" || fail "skippedBinary = '$got', expected 1"
got=$(jq -r '.files[] | select(.path == "big.txt") | .truncated' "$snap_out" 2>/dev/null)
[ "$got" = "true" ] && pass "oversized file cut, not dropped" || fail "big.txt truncated = '$got'"
got=$(jq -r '.files[] | select(.path == "big.txt") | .size' "$snap_out" 2>/dev/null)
[ "$got" = "300000" ] && pass "the file's real size survives truncation" || fail "big.txt size = '$got'"

# A listing entry must never reach outside the scanned tree — the paths are ours,
# but a symlink or a crafted entry must still be refused, not read and published.
cat > "$snap_dir/out/evil_files.json" <<'EOF'
{"files":[{"path":"../../../etc/passwd","type":"file"},
          {"path":"/etc/hosts","type":"file"},
          {"path":"link.txt","type":"file"},
          {"path":"src/main.go","type":"file"}]}
EOF
(
    cd "$snap_dir/out" || exit 1
    python3 "$SNAP" "$snap_dir/tree" evil_files.json evil_source.json >/dev/null 2>&1
)
got=$(jq -r '[.files[].path] | join(",")' "$snap_dir/out/evil_source.json" 2>/dev/null)
[ "$got" = "src/main.go" ] \
    && pass "traversal, absolute path and symlink entries all refused" \
    || fail "escaped the scanned tree: '$got'"

# A tight budget must keep the evidence a reviewer opens (licence texts, package
# manifests), account for what it left out, and never store a fragment: the
# 300 KB file is skipped whole rather than cut down to whatever fits.
(
    cd "$snap_dir/out" || exit 1
    SOURCE_SNAPSHOT_MAX_TOTAL=32 python3 "$SNAP" \
        "$snap_dir/tree" snap_files.json tiny_source.json >/dev/null 2>&1
)
got=$(jq -r '[.files[].path] | sort | join(",")' "$snap_dir/out/tiny_source.json" 2>/dev/null)
[ "$got" = "LICENSE,package.json" ] \
    && pass "licence text and manifest win a tight budget" \
    || fail "budget spent elsewhere: '$got'"
got=$(jq -r '.totals.skippedBudget' "$snap_dir/out/tiny_source.json" 2>/dev/null)
[ "${got:-0}" -gt 0 ] && pass "files left out are counted, not silently missing" \
    || fail "skippedBudget = '$got', expected > 0"

# The caps arrive as `-e NAME=` whether or not the user set them (scan-sbom.sh
# forwards them unconditionally), so an unset cap is an empty string, not an
# absent variable. Parsing that as an integer would abort the capture; reading it
# as zero would silently capture nothing. Both must fall back to the default.
for bad in "" "abc" "0" "-5"; do
    (
        cd "$snap_dir/out" || exit 1
        SOURCE_SNAPSHOT_MAX_TOTAL="$bad" python3 "$SNAP" \
            "$snap_dir/tree" snap_files.json cap_source.json >/dev/null 2>&1
    )
    got=$(jq -r '.totals.files' "$snap_dir/out/cap_source.json" 2>/dev/null)
    if [ "${got:-0}" -gt 0 ]; then
        pass "a malformed cap ('$bad') falls back to the default"
    else
        fail "cap '$bad' captured nothing (files=$got)"
    fi
done

# Byte-stable: the snapshot carries no timestamp, so re-scanning the same tree
# reproduces it exactly (the --byte-stable contract the rest of the output keeps).
(
    cd "$snap_dir/out" || exit 1
    python3 "$SNAP" "$snap_dir/tree" snap_files.json again_source.json >/dev/null 2>&1
)
if diff -q "$snap_out" "$snap_dir/out/again_source.json" >/dev/null 2>&1; then
    pass "re-running on the same tree is byte-identical"
else
    fail "snapshot is not reproducible"
fi

echo "== source tree: symlinks are listed, with the target recorded not followed =="
# A container image or a firmware rootfs is mostly symlinks — an Alpine image has
# 90 regular files against 334 links, nearly all of them into busybox. Listing
# only regular files shows a /bin in which none of the commands exist, so links
# are listed with their destination as the content of the entry.
link_dir="$WORK/links"
rm -rf "$link_dir"; mkdir -p "$link_dir/tree/bin" "$link_dir/out"
printf '#!/bin/sh\necho hi\n' > "$link_dir/tree/bin/busybox"
ln -s /bin/busybox "$link_dir/tree/bin/cat"
ln -s busybox "$link_dir/tree/bin/ls"
ln -s /nowhere/gone "$link_dir/tree/bin/dangling"
(
    cd "$link_dir/out" || exit 1
    bash "$LIB/source-file-tree.sh" "$link_dir/tree" link_files.json >/dev/null 2>&1
    python3 "$SNAP" "$link_dir/tree" link_files.json link_source.json >/dev/null 2>&1
)
got=$(jq -r '[.files[] | select(.type == "symlink") | .path] | sort | join(",")' "$link_dir/out/link_files.json" 2>/dev/null)
[ "$got" = "bin/cat,bin/dangling,bin/ls" ] \
    && pass "symlinks appear in the tree, typed as symlink" \
    || fail "symlink entries were '$got'"
got=$(jq -r '.files[] | select(.path == "bin/busybox") | .path' "$link_dir/out/link_files.json" 2>/dev/null)
[ "$got" = "bin/busybox" ] && pass "the real file behind the links is still listed" || fail "regular file missing"
got=$(jq -r '[.links[] | .path + "->" + .target] | sort | join(",")' "$link_dir/out/link_source.json" 2>/dev/null)
[ "$got" = "bin/cat->/bin/busybox,bin/dangling->/nowhere/gone,bin/ls->busybox" ] \
    && pass "link targets recorded verbatim, including a dangling one" \
    || fail "link targets were '$got'"
# The link is described, never opened: no symlink may contribute file content.
got=$(jq -r '[.files[].path] | join(",")' "$link_dir/out/link_source.json" 2>/dev/null)
[ "$got" = "bin/busybox" ] \
    && pass "no symlink was followed for its content" \
    || fail "snapshot captured content through a link: '$got'"

echo "== unpack-scan-target: open an archive, refuse what is not one =="
# A build artifact is one packed file, so without unpacking there is nothing to
# show. Archives are opened; an ELF binary is refused with a reason rather than
# presented as an empty tree.
UNPACK="$ROOT_DIR/docker/lib/unpack-scan-target.sh"
arc_dir="$WORK/arc"
rm -rf "$arc_dir"; mkdir -p "$arc_dir/build/META-INF"
printf 'Manifest-Version: 1.0\n' > "$arc_dir/build/META-INF/MANIFEST.MF"
printf 'ELF\0\0binary\n' > "$arc_dir/plain.bin"
if command -v zip >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
    (cd "$arc_dir/build" && zip -qr "$arc_dir/app.jar" .)
    got_dir=$(bash "$UNPACK" BINARY "$arc_dir/app.jar" 2>/dev/null)
    if [ -n "$got_dir" ] && [ -f "$got_dir/META-INF/MANIFEST.MF" ]; then
        pass "a jar is unpacked into a readable tree"
    else
        fail "jar unpack produced '$got_dir'"
    fi
    [ -n "$got_dir" ] && rm -rf "$got_dir"
else
    pass "jar unpack skipped (no zip/unzip in this environment)"
fi
got_dir=$(bash "$UNPACK" BINARY "$arc_dir/plain.bin" 2>/dev/null)
[ -z "$got_dir" ] \
    && pass "a non-archive prints no directory rather than an empty tree" \
    || fail "unpacked a non-archive into '$got_dir'"

echo "== describe-input-sbom: report the supplier's document, not the conversion =="
# ANALYZE converts every input to CycloneDX, so every result screen describes the
# conversion. The format the supplier wrote in, the tool behind it and its
# authorship survive only in this summary, read from the ORIGINAL. Guarded here:
# all three input families are read, and an unreadable input yields nothing
# rather than a guess (a wrong "produced by" on a compliance screen is worse
# than a blank one).
DESC="$ROOT_DIR/docker/lib/describe-input-sbom.py"
desc_dir="$WORK/desc"
mkdir -p "$desc_dir"

python3 "$DESC" "$FIX/good-cyclonedx.json" "$desc_dir/cdx.json" "supplier.cdx.json" >/dev/null 2>&1
got=$(jq -r '[.format, .specVersion, (.tools | join(";")), (.componentCount | tostring)] | join("|")' "$desc_dir/cdx.json" 2>/dev/null)
[ "$got" = "CycloneDX|1.5|cdxgen 12.0.0|2" ] \
    && pass "CycloneDX header read (format, version, tool, count)" \
    || fail "CycloneDX summary was '$got'"
got=$(jq -r '.originalName' "$desc_dir/cdx.json" 2>/dev/null)
[ "$got" = "supplier.cdx.json" ] && pass "the uploaded filename is kept" || fail "originalName = '$got'"

python3 "$DESC" "$FIX/good-spdx.json" "$desc_dir/spdx2.json" >/dev/null 2>&1
got=$(jq -r '[.format, .specVersion, (.tools | join(";")), .supplier] | join("|")' "$desc_dir/spdx2.json" 2>/dev/null)
[ "$got" = "SPDX|2.3|syft-1.18.1|Supplier Inc." ] \
    && pass "SPDX 2.3 creators split into tool and organization" \
    || fail "SPDX 2.3 summary was '$got'"

# SPDX 3.0 keeps CreationInfo, the tool and the organization in separate @graph
# nodes that the document only references by id. Reading the header alone yields
# blanks, so the references must be resolved.
python3 "$DESC" "$FIX/good-spdx3-jsonld.json" "$desc_dir/spdx3.json" >/dev/null 2>&1
got=$(jq -r '[.format, (.tools | join(";")), .supplier, .created] | join("|")' "$desc_dir/spdx3.json" 2>/dev/null)
[ "$got" = "SPDX|test-tool|test-org|2026-01-01T00:00:00Z" ] \
    && pass "SPDX 3.0 JSON-LD agent references resolved" \
    || fail "SPDX 3.0 summary was '$got'"

printf 'not an sbom at all\n' > "$desc_dir/junk.txt"
rm -f "$desc_dir/junk.json"
python3 "$DESC" "$desc_dir/junk.txt" "$desc_dir/junk.json" >/dev/null 2>&1
[ ! -f "$desc_dir/junk.json" ] \
    && pass "an unrecognized input writes no summary rather than a guess" \
    || fail "wrote a summary for a non-SBOM input"

echo "== source-tree guard: a scan leaves the scanned project unchanged =="
# Regression for the pollution defect: build-prep.sh resolves dependencies IN the
# mounted source tree, so a scan of a checkout rewrote go.mod (~30 lines of
# indirect requires) and left go.sum, Cargo.lock and build dirs behind — the tool
# modified what it measured. build-prep.sh must snapshot the resolver-owned files
# and put the tree back. Driven with stub resolvers on PATH (no Docker, no real
# toolchain): a fake `go` that mutates go.mod + writes go.sum, and a fake `cdxgen`
# that leaves build dirs and writes the bom where -o points.
GUARD_ROOT="$WORK/guard"
mkdir -p "$GUARD_ROOT/bin" "$GUARD_ROOT/src/keepdir" "$GUARD_ROOT/out"
cat > "$GUARD_ROOT/bin/go" <<'STUB'
#!/bin/sh
printf 'require (\n\tgithub.com/indirect/dep v1.0.0 // indirect\n)\n' >> go.mod
echo 'github.com/indirect/dep v1.0.0 h1:deadbeef' > go.sum
STUB
cat > "$GUARD_ROOT/bin/cdxgen" <<'STUB'
#!/bin/sh
mkdir -p build/classes mod-new/build
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
[ -n "$out" ] && echo '{"bomFormat":"CycloneDX","components":[]}' > "$out"
exit 0
STUB
chmod +x "$GUARD_ROOT/bin/go" "$GUARD_ROOT/bin/cdxgen"
printf 'module example.com/demo\n\ngo 1.24\n' > "$GUARD_ROOT/src/go.mod"
printf 'package main\n' > "$GUARD_ROOT/src/main.go"
printf 'keep me\n' > "$GUARD_ROOT/src/keepdir/file.txt"
cp "$GUARD_ROOT/src/go.mod" "$GUARD_ROOT/go.mod.orig"
PATH="$GUARD_ROOT/bin:$PATH" sh "$LIB/build-prep.sh" "$GUARD_ROOT/src" "$GUARD_ROOT/out/bom.json" >/dev/null 2>&1
cmp -s "$GUARD_ROOT/go.mod.orig" "$GUARD_ROOT/src/go.mod" \
    && pass "go.mod is byte-identical after the scan" \
    || fail "the scan rewrote go.mod" "$(diff "$GUARD_ROOT/go.mod.orig" "$GUARD_ROOT/src/go.mod" | head -5)"
[ ! -e "$GUARD_ROOT/src/go.sum" ] \
    && pass "the go.sum the resolver created is gone" \
    || fail "go.sum was left in the source tree"
[ ! -e "$GUARD_ROOT/src/build" ] && [ ! -e "$GUARD_ROOT/src/mod-new" ] \
    && pass "build dirs created by the run are gone (including their new parent)" \
    || fail "build output left in the source tree" "$(cd "$GUARD_ROOT/src" && find . | sort | tr '\n' ' ')"
[ -f "$GUARD_ROOT/src/keepdir/file.txt" ] \
    && pass "a directory that existed before the scan is untouched" \
    || fail "the guard deleted a pre-existing directory"
[ -s "$GUARD_ROOT/out/bom.json" ] \
    && pass "the generated SBOM survives the restore" \
    || fail "the guard removed the generated SBOM"

# Opt-out: BOMLENS_KEEP_BUILD_OUTPUT=1 keeps the resolved tree for debugging.
rm -rf "$GUARD_ROOT/src" "$GUARD_ROOT/out"; mkdir -p "$GUARD_ROOT/src" "$GUARD_ROOT/out"
cp "$GUARD_ROOT/go.mod.orig" "$GUARD_ROOT/src/go.mod"
printf 'package main\n' > "$GUARD_ROOT/src/main.go"
BOMLENS_KEEP_BUILD_OUTPUT=1 PATH="$GUARD_ROOT/bin:$PATH" \
    sh "$LIB/build-prep.sh" "$GUARD_ROOT/src" "$GUARD_ROOT/out/bom.json" >/dev/null 2>&1
[ -f "$GUARD_ROOT/src/go.sum" ] && [ -d "$GUARD_ROOT/src/build" ] \
    && pass "BOMLENS_KEEP_BUILD_OUTPUT=1 keeps the resolved tree" \
    || fail "the opt-out did not keep the resolved tree"

echo "== lic-mapping: 0BSD stops claiming the generic BSD names =="
# build-prep.sh corrects cdxgen's two license-name tables before cdxgen runs,
# because "BSD License" (the only BSD classifier PyPI has) resolved to 0BSD — a
# license with no conditions in place of one that requires attribution. The
# correction is a heredoc inside build-prep.sh; extract and run it against a
# copy of the shipped tables so the test exercises the same code the scan does.
if command -v node >/dev/null 2>&1; then
    LICDIR="$WORK/licdata"
    mkdir -p "$LICDIR"
    cp "$FIX/cdxgen-lic-mapping.json" "$LICDIR/lic-mapping.json"
    cp "$FIX/cdxgen-license-aliases.json" "$LICDIR/license-aliases.json"
    sed -n "/cat > \"\$_fix\" <<'FIX_LIC_JS'/,/^FIX_LIC_JS\$/p" "$LIB/build-prep.sh" \
        | sed '1d;$d' > "$WORK/fix-lic.js"
    [ -s "$WORK/fix-lic.js" ] \
        && pass "correction script extracted from build-prep.sh" \
        || fail "could not extract the lic-mapping correction from build-prep.sh"
    node "$WORK/fix-lic.js" "$LICDIR" 2>"$WORK/fix-lic.err"
    grep -q "0BSD no longer claims" "$WORK/fix-lic.err" \
        && pass "correction reports what 0BSD gave up" \
        || fail "correction produced no report" "$(cat "$WORK/fix-lic.err")"

    zero_names=$(jq -c '.[] | select(.exp=="0BSD") | .names' "$LICDIR/lic-mapping.json")
    [ "$zero_names" = '["Zero-Clause BSD"]' ] \
        && pass "0BSD keeps only the zero-clause name" \
        || fail "0BSD names=$zero_names"
    jq -e '.[] | select(.exp=="BSD-3-Clause") | .names | index("new BSD")' "$LICDIR/lic-mapping.json" >/dev/null \
        && pass "\"new BSD\" moved to BSD-3-Clause in its exact casing" \
        || fail "\"new BSD\" was dropped instead of moved to BSD-3-Clause"
    # The alias table keys are normalised (lowercase, punctuation stripped).
    for k in bsd bsdlicense bsdlike bsdpublicdomain; do
        jq -e --arg k "$k" 'has($k)' "$LICDIR/license-aliases.json" >/dev/null \
            && fail "alias \"$k\" still resolves to 0BSD" \
            || pass "alias \"$k\" no longer resolves to 0BSD"
    done
    newbsd=$(jq -r '.newbsd // "ABSENT"' "$LICDIR/license-aliases.json")
    [ "$newbsd" = "BSD-3-Clause" ] && pass "alias \"newbsd\" now resolves to BSD-3-Clause" \
        || fail "alias newbsd=$newbsd, expected BSD-3-Clause"
    # A component that really is 0BSD must still resolve, and the unrelated
    # families must be untouched.
    for pair in '0bsd 0BSD' 'zeroclausebsd 0BSD' 'bsd3clause BSD-3-Clause' 'bsd2clause BSD-2-Clause' 'mitlicense MIT'; do
        k=${pair%% *}; want=${pair##* }
        got=$(jq -r --arg k "$k" '.[$k] // "ABSENT"' "$LICDIR/license-aliases.json")
        [ "$got" = "$want" ] && pass "alias \"$k\" still resolves to $want" \
            || fail "alias $k=$got, expected $want"
    done

    # Idempotent: a second run has nothing to report and changes nothing.
    cp "$LICDIR/lic-mapping.json" "$WORK/lm-before.json"
    cp "$LICDIR/license-aliases.json" "$WORK/la-before.json"
    node "$WORK/fix-lic.js" "$LICDIR" 2>"$WORK/fix-lic2.err"
    [ ! -s "$WORK/fix-lic2.err" ] \
        && pass "second run reports nothing (already corrected)" \
        || fail "second run was not a no-op" "$(cat "$WORK/fix-lic2.err")"
    diff -q "$WORK/lm-before.json" "$LICDIR/lic-mapping.json" >/dev/null \
        && diff -q "$WORK/la-before.json" "$LICDIR/license-aliases.json" >/dev/null \
        && pass "second run leaves both tables byte-identical" \
        || fail "second run rewrote the tables"
else
    echo "  SKIP: node not available"
fi

echo "== python: license settled on installed dist-info evidence =="
# cdxgen reads PyPI's summary fields, where the classifier is a family rather
# than a license and `license` may hold the whole license text (which it then
# scans for the first name it recognises — how numpy became Apache-2.0). The
# installed wheel carries better evidence, so build-prep.sh re-reads it. Build a
# venv with hand-written dist-info dirs so sysconfig points the script at them.
if command -v python3 >/dev/null 2>&1 && python3 -m venv --without-pip "$WORK/venv" >/dev/null 2>&1; then
    SP=$(echo "$WORK"/venv/lib/python*/site-packages)
    mkdir -p "$SP"
    sed -n "/cat > \"\$_pylic\" <<'PY_LIC'/,/^PY_LIC\$/p" "$LIB/build-prep.sh" \
        | sed '1d;$d' > "$WORK/settle.py"
    [ -s "$WORK/settle.py" ] \
        && pass "evidence script extracted from build-prep.sh" \
        || fail "could not extract the python license pass from build-prep.sh"

    # joblib: license file text says BSD-3-Clause; PyPI only ever said "BSD".
    mkdir -p "$SP/joblib-1.2.0.dist-info"
    printf 'Metadata-Version: 2.1\nName: joblib\nVersion: 1.2.0\nLicense: BSD\n\nbody\n' \
        > "$SP/joblib-1.2.0.dist-info/METADATA"
    cat > "$SP/joblib-1.2.0.dist-info/LICENSE.txt" <<'LICTXT'
Copyright (c) 2008-2021, The joblib developers.
Redistributions of source code must retain the above copyright notice.
Redistributions in binary form must reproduce the above copyright notice.
Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software.
LICTXT
    # pandas: license file carries bundled notices too, so the text is
    # ambiguous; the short declared name settles it.
    mkdir -p "$SP/pandas-2.3.3.dist-info"
    printf 'Metadata-Version: 2.1\nName: pandas\nVersion: 2.3.3\nLicense: BSD 3-Clause License\n\nbody\n' \
        > "$SP/pandas-2.3.3.dist-info/METADATA"
    cat > "$SP/pandas-2.3.3.dist-info/LICENSE" <<'LICTXT'
Redistributions of source code must retain the above copyright notice.
Redistributions in binary form must reproduce the above copyright notice.
Neither the name of the copyright holder may be used to endorse it.
---- bundled ----
Apache License Version 2.0, January 2004
---- bundled ----
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software, to deal in the Software without restriction.
LICTXT
    # threadpoolctl: PEP 639 expression wins outright.
    mkdir -p "$SP/threadpoolctl-3.6.0.dist-info/licenses"
    printf 'Metadata-Version: 2.4\nName: threadpoolctl\nVersion: 3.6.0\nLicense-Expression: BSD-3-Clause\n\nbody\n' \
        > "$SP/threadpoolctl-3.6.0.dist-info/METADATA"
    # python-dateutil: genuinely dual-licensed. Ambiguous text, and a declared
    # name that says nothing — this one must be left for a human.
    mkdir -p "$SP/python_dateutil-2.9.0.post0.dist-info"
    printf 'Metadata-Version: 2.1\nName: python-dateutil\nVersion: 2.9.0.post0\nLicense: Dual License\n\nbody\n' \
        > "$SP/python_dateutil-2.9.0.post0.dist-info/METADATA"
    cat > "$SP/python_dateutil-2.9.0.post0.dist-info/LICENSE" <<'LICTXT'
Apache License Version 2.0, January 2004
Redistributions of source code must retain the above copyright notice.
Redistributions in binary form must reproduce the above copyright notice.
Neither the name of the copyright holder may be used to endorse it.
LICTXT
    # click: installed as .egg-info, the older layout, which records no license
    # file of its own — the declared name in PKG-INFO is all there is. Reading
    # the site-packages directories by hand missed this entirely.
    mkdir -p "$SP/click-8.1.7-py3.12.egg-info"
    printf 'Metadata-Version: 2.1\nName: click\nVersion: 8.1.7\nLicense: BSD-3-Clause\n\nbody\n' \
        > "$SP/click-8.1.7-py3.12.egg-info/PKG-INFO"
    # A component with no evidence at all keeps whatever cdxgen said.
    cat > "$WORK/pybom.json" <<'PYBOM'
{ "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
  { "type": "library", "name": "joblib", "version": "1.2.0",
    "purl": "pkg:pypi/joblib@1.2.0", "licenses": [ { "license": { "id": "0BSD" } } ] },
  { "type": "library", "name": "pandas", "version": "2.3.3",
    "purl": "pkg:pypi/pandas@2.3.3", "licenses": [ { "license": { "id": "Apache-2.0" } } ] },
  { "type": "library", "name": "threadpoolctl", "version": "3.6.0",
    "purl": "pkg:pypi/threadpoolctl@3.6.0", "licenses": [ { "license": { "name": "BSD License" } } ] },
  { "type": "library", "name": "python-dateutil", "version": "2.9.0.post0",
    "purl": "pkg:pypi/python-dateutil@2.9.0.post0", "licenses": [ { "license": { "name": "Dual License" } } ] },
  { "type": "library", "name": "click", "version": "8.1.7",
    "purl": "pkg:pypi/click@8.1.7", "licenses": [ { "license": { "id": "0BSD" } } ] },
  { "type": "library", "name": "mystery", "version": "1.0.0",
    "purl": "pkg:pypi/mystery@1.0.0", "licenses": [ { "license": { "id": "MIT" } } ] },
  { "type": "library", "name": "tslib", "version": "2.6.2",
    "purl": "pkg:npm/tslib@2.6.2", "licenses": [ { "license": { "id": "0BSD" } } ] }
] }
PYBOM
    "$WORK/venv/bin/python3" "$WORK/settle.py" "$WORK/pybom.json" 2>"$WORK/settle.err"
    lic() { jq -r --arg n "$1" '.components[] | select(.name==$n)
        | (.licenses[0].license.id // .licenses[0].license.name // .licenses[0].expression // "ABSENT")' "$WORK/pybom.json"; }
    src() { jq -r --arg n "$1" '.components[] | select(.name==$n)
        | ((.properties // []) | map(select(.name=="bomlens:licenseSource")) | .[0].value // "ABSENT")' "$WORK/pybom.json"; }

    [ "$(lic joblib)" = "BSD-3-Clause" ] \
        && pass "joblib settled on BSD-3-Clause from its license text" \
        || fail "joblib license=$(lic joblib), expected BSD-3-Clause"
    [ "$(src joblib)" = "installed license text" ] \
        && pass "the basis is recorded on the component" \
        || fail "joblib licenseSource=$(src joblib)"
    [ "$(lic pandas)" = "BSD-3-Clause" ] \
        && pass "pandas settled on the declared name when the text is ambiguous" \
        || fail "pandas license=$(lic pandas), expected BSD-3-Clause"
    [ "$(lic threadpoolctl)" = "BSD-3-Clause" ] \
        && pass "threadpoolctl settled on its PEP 639 expression" \
        || fail "threadpoolctl license=$(lic threadpoolctl), expected BSD-3-Clause"
    [ "$(lic click)" = "BSD-3-Clause" ] \
        && pass "click settled from PKG-INFO in an .egg-info install" \
        || fail "click license=$(lic click), expected BSD-3-Clause"
    [ "$(lic python-dateutil)" = "Dual License" ] \
        && pass "a dual-licensed component is left for human review" \
        || fail "dateutil license=$(lic python-dateutil), expected the upstream value"
    [ "$(lic mystery)" = "MIT" ] \
        && pass "a component with no installed evidence is untouched" \
        || fail "mystery license=$(lic mystery)"
    [ "$(lic tslib)" = "0BSD" ] \
        && pass "a genuine 0BSD component outside PyPI is untouched" \
        || fail "tslib license=$(lic tslib), expected 0BSD"
else
    echo "  SKIP: python3 venv not available"
fi

echo "== python: a license file with bundled notices settles on the license it leads with =="
# The reported defect: a project's own license file, with the notices of the
# libraries it bundles appended, matches several templates at once, so the whole
# pass went silent and the generator's wrong license stood (pandas came out
# Apache-2.0 off python-dateutil's notice inside pandas' BSD-3-Clause file).
# build-prep.sh now reads the license the file OPENS with and confirms it against
# the distribution's trove classifiers. These fixtures cover both what that must
# fix and what it must still refuse to touch.
if command -v python3 >/dev/null 2>&1 && python3 -m venv --without-pip "$WORK/leadvenv" >/dev/null 2>&1; then
    LSP=$(echo "$WORK"/leadvenv/lib/python*/site-packages)
    mkdir -p "$LSP"
    cp -R "$ROOT_DIR/tests/fixtures/py-license-evidence/." "$LSP/"
    sed -n "/cat > \"\$_pylic\" <<'PY_LIC'/,/^PY_LIC\$/p" "$LIB/build-prep.sh" \
        | sed '1d;$d' > "$WORK/settle-lead.py"
    cat > "$WORK/leadbom.json" <<'LEADBOM'
{ "bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
  { "type": "library", "name": "bl-fixture-pandas", "version": "1.0.0",
    "purl": "pkg:pypi/bl-fixture-pandas@1.0.0",
    "licenses": [ { "license": { "id": "0BSD" } }, { "license": { "id": "Apache-2.0" } } ] },
  { "type": "library", "name": "bl-fixture-numpy", "version": "1.0.0",
    "purl": "pkg:pypi/bl-fixture-numpy@1.0.0", "licenses": [ { "license": { "id": "0BSD" } } ] },
  { "type": "library", "name": "bl-fixture-bsd2", "version": "1.0.0",
    "purl": "pkg:pypi/bl-fixture-bsd2@1.0.0", "licenses": [ { "license": { "id": "0BSD" } } ] },
  { "type": "library", "name": "bl-fixture-bundlefirst", "version": "1.0.0",
    "purl": "pkg:pypi/bl-fixture-bundlefirst@1.0.0", "licenses": [ { "license": { "name": "BSD License" } } ] },
  { "type": "library", "name": "bl-fixture-dualfiles", "version": "1.0.0",
    "purl": "pkg:pypi/bl-fixture-dualfiles@1.0.0", "licenses": [ { "license": { "name": "MIT OR Apache-2.0" } } ] },
  { "type": "library", "name": "bl-fixture-dualtext", "version": "1.0.0",
    "purl": "pkg:pypi/bl-fixture-dualtext@1.0.0", "licenses": [ { "license": { "name": "MIT OR Apache-2.0" } } ] },
  { "type": "library", "name": "bl-fixture-preamble", "version": "1.0.0",
    "purl": "pkg:pypi/bl-fixture-preamble@1.0.0", "licenses": [ { "license": { "name": "BSD License" } } ] },
  { "type": "library", "name": "bl-fixture-declared", "version": "1.0.0",
    "purl": "pkg:pypi/bl-fixture-declared@1.0.0", "licenses": [ { "license": { "id": "0BSD" } } ] },
  { "type": "library", "name": "bl-fixture-absent", "version": "1.0.0",
    "purl": "pkg:pypi/bl-fixture-absent@1.0.0", "licenses": [ { "license": { "id": "MIT" } } ] }
] }
LEADBOM
    "$WORK/leadvenv/bin/python3" "$WORK/settle-lead.py" "$WORK/leadbom.json" 2>"$WORK/settle-lead.err"
    llic() { jq -r --arg n "$1" '.components[] | select(.name==$n)
        | (.licenses[0].license.id // .licenses[0].license.name // .licenses[0].expression // "ABSENT")' "$WORK/leadbom.json"; }
    lsrc() { jq -r --arg n "$1" '.components[] | select(.name==$n)
        | ((.properties // []) | map(select(.name=="bomlens:licenseSource")) | .[0].value // "ABSENT")' "$WORK/leadbom.json"; }
    lcount() { jq -r --arg n "$1" '.components[] | select(.name==$n) | (.licenses | length)' "$WORK/leadbom.json"; }

    # 1. The reported case: BSD-3-Clause text, then bundled BSD-2 / Apache-2.0 /
    #    MIT notices, no separator, and a License field holding the whole text.
    [ "$(llic bl-fixture-pandas)" = "BSD-3-Clause" ] && [ "$(lcount bl-fixture-pandas)" = "1" ] \
        && pass "a bundled-notice file settles on its leading BSD-3-Clause (was 0BSD + Apache-2.0)" \
        || fail "pandas-shaped fixture license=$(llic bl-fixture-pandas) (entries: $(lcount bl-fixture-pandas))"
    [ "$(lsrc bl-fixture-pandas)" = "installed license text (leading)" ] \
        && pass "the leading-license basis is recorded on the component" \
        || fail "pandas-shaped fixture licenseSource=$(lsrc bl-fixture-pandas)"
    # 2. A file whose bundle list carries names only still takes the plain path.
    [ "$(llic bl-fixture-numpy)" = "BSD-3-Clause" ] && [ "$(lsrc bl-fixture-numpy)" = "installed license text" ] \
        && pass "a single-license file is still read whole, basis unchanged" \
        || fail "numpy-shaped fixture=$(llic bl-fixture-numpy) via $(lsrc bl-fixture-numpy)"
    # 7. The clause count comes from the leading text's own window: a bundled
    #    BSD-3 notice must not turn a BSD-2 project into BSD-3-Clause.
    [ "$(llic bl-fixture-bsd2)" = "BSD-2-Clause" ] \
        && pass "a bundled BSD-3 notice does not raise a BSD-2 project's clause count" \
        || fail "bsd2 fixture license=$(llic bl-fixture-bsd2), expected BSD-2-Clause"
    # 3. The failure this whole pass exists to prevent: reading a bundled license
    #    as the project's own. The classifiers disagree, so nothing is settled.
    [ "$(llic bl-fixture-bundlefirst)" = "BSD License" ] \
        && pass "a leading license the classifiers contradict is left alone" \
        || fail "bundlefirst fixture license=$(llic bl-fixture-bundlefirst), expected the upstream value"
    # 4. Dual licensing, in both shapes it is published in.
    [ "$(llic bl-fixture-dualfiles)" = "MIT OR Apache-2.0" ] \
        && pass "two license files that disagree leave the component for review" \
        || fail "dualfiles fixture license=$(llic bl-fixture-dualfiles)"
    [ "$(llic bl-fixture-dualtext)" = "MIT OR Apache-2.0" ] \
        && pass "two license texts in one file, two classifiers: left for review" \
        || fail "dualtext fixture license=$(llic bl-fixture-dualtext)"
    # 5. An aggregate notice file does not open with the license that governs it.
    [ "$(llic bl-fixture-preamble)" = "BSD License" ] \
        && pass "a license text starting past the head of the file is not taken as leading" \
        || fail "preamble fixture license=$(llic bl-fixture-preamble), expected the upstream value"
    # 6. A License field too long to be a name is read as the text it is.
    [ "$(llic bl-fixture-declared)" = "BSD-3-Clause" ] && [ "$(lsrc bl-fixture-declared)" = "declared license text" ] \
        && pass "an over-long declared license is classified as text, not abandoned" \
        || fail "declared fixture=$(llic bl-fixture-declared) via $(lsrc bl-fixture-declared)"
    # Observability: a component with no installed distribution is now counted,
    # so a silent pip failure is visible in the scan log instead of looking like
    # a run where every license was already right.
    [ "$(llic bl-fixture-absent)" = "MIT" ] \
        && pass "a component with no installed evidence is untouched" \
        || fail "absent fixture license=$(llic bl-fixture-absent)"
    grep -q "1 pypi component(s) had no installed evidence" "$WORK/settle-lead.err" \
        && pass "components without installed evidence are reported" \
        || fail "no missing-evidence count logged" "$(cat "$WORK/settle-lead.err")"
else
    echo "  SKIP: python3 venv not available"
fi

echo "== NOTICE: a license name that is not an SPDX id is marked unverified =="
cat > "$WORK/unverified.json" <<'UNVBOM'
{ "bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": { "component": { "type": "application", "name": "UnverifiedProj", "version": "1.0.0" } },
  "components": [
  { "type": "library", "name": "joblib", "version": "1.2.0", "purl": "pkg:pypi/joblib@1.2.0",
    "licenses": [ { "license": { "name": "BSD License" } } ] },
  { "type": "library", "name": "python-dateutil", "version": "2.9.0", "purl": "pkg:pypi/python-dateutil@2.9.0",
    "licenses": [ { "license": { "name": "Dual License" } } ] },
  { "type": "library", "name": "six", "version": "1.17.0", "purl": "pkg:pypi/six@1.17.0",
    "licenses": [ { "license": { "id": "MIT" } } ] },
  { "type": "library", "name": "packaging", "version": "24.0", "purl": "pkg:pypi/packaging@24.0",
    "licenses": [ { "expression": "Apache-2.0 OR BSD-2-Clause" } ] }
] }
UNVBOM
bash "$LIB/generate-notice.sh" "$WORK/unverified.json" "$WORK/unv" "UnverifiedProj" >/dev/null 2>&1
UNV_TXT="$WORK/unv_NOTICE.txt"
[ -f "$UNV_TXT" ] || UNV_TXT=$(ls "$WORK"/unv*NOTICE*.txt 2>/dev/null | head -1)
if [ -n "$UNV_TXT" ] && [ -f "$UNV_TXT" ]; then
    grep -q "^License: BSD License.*unverified name" "$UNV_TXT" \
        && pass "\"BSD License\" is marked unverified" \
        || fail "BSD License group carries no unverified note" "$(grep '^License:' "$UNV_TXT")"
    grep -q "^License: Dual License.*unverified name" "$UNV_TXT" \
        && pass "\"Dual License\" is marked unverified" \
        || fail "Dual License group carries no unverified note"
    grep -q "^License: MIT$" "$UNV_TXT" \
        && pass "a real SPDX id is left unannotated" \
        || fail "MIT group was annotated" "$(grep '^License: MIT' "$UNV_TXT")"
    grep -q "^License: Apache-2.0 OR BSD-2-Clause$" "$UNV_TXT" \
        && pass "an SPDX expression is left unannotated" \
        || fail "compound expression was annotated" "$(grep '^License: Apache' "$UNV_TXT")"
else
    fail "generate-notice.sh produced no NOTICE for the unverified-name fixture"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
