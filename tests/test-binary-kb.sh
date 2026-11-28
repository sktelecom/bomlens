#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-binary-kb.sh — No-Docker tests for the binary knowledge base layer
# (docker/lib/binarykb.py, identify-binary-kb.py and their wiring).
#
# What these guard:
#   - a component is found from the string literals of its releases, and the version is
#     written only when exactly one release fits (several fitting is reported as candidates,
#     never as the first of them)
#   - the newest release the base has is marked, because a version newer than the base comes
#     back as that release and reading it as exact would hide the difference
#   - a library copied into another component is credited to the component it came from,
#     and a background package's strings are never reported
#   - ELF files of every class and byte order are read, so firmware for MIPS and ARM works
#   - a review decision without a reason, or one whose evidence hash no longer matches, is ignored
#   - the base is opened read-only and a damaged or unknown base does not stop the scan
#   - the pass is wired into scan-firmware.sh and the options into scan-sbom.sh
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

for t in jq python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "[ERROR] $t is required for the binary knowledge base tests"; exit 1; }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------------------
# Fixture: three releases of `alpha`, one of `beta` (which carries a copy of some of alpha's
# code), one background package. Each release adds string literals to the one before it, and 1.1 has
# three that 1.2 dropped: a binary made of release 1.1 alone can then be told from 1.2.
# ---------------------------------------------------------------------------
python3 - "$TMP" <<'PY'
import io, os, sys, tarfile
tmp = sys.argv[1]
def lits(prefix, n):
    return [f'{prefix} message number {i} for the knowledge base test' for i in range(n)]
def c_file(strings):
    return ('\n'.join(f'const char *s{i} = "{s}";' for i, s in enumerate(strings)) + '\n').encode()
def tarball(path, files):
    with tarfile.open(path, 'w:gz') as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
A, B, C, D = lits('alpha core', 40), lits('alpha extra', 30), lits('alpha late', 30), lits('alpha dropped in 1.2', 3)
SHARED = lits('copied helper', 25)
os.makedirs(f'{tmp}/src'); os.makedirs(f'{tmp}/bg')
tarball(f'{tmp}/src/alpha-1.0.tar.gz', {'alpha-1.0/core.c': c_file(A + SHARED)})
tarball(f'{tmp}/src/alpha-1.1.tar.gz', {'alpha-1.1/core.c': c_file(A + SHARED + B + D)})
tarball(f'{tmp}/src/alpha-1.2.tar.gz', {'alpha-1.2/core.c': c_file(A + SHARED + B + C)})
tarball(f'{tmp}/src/beta-2.0.tar.gz', {'beta-2.0/main.c': c_file(lits('beta own', 50) + SHARED)})
tarball(f'{tmp}/bg/gamma-9.0.tar.gz', {'gamma-9.0/g.c': c_file(lits('gamma only', 40) + lits('alpha late', 5))})
with open(f'{tmp}/kb.csv', 'w') as f:
    for v in ('1.2', '1.0', '1.1'):   # out of order on purpose: the build sorts releases
        f.write(f'alpha,{v},{tmp}/src/alpha-{v}.tar.gz\n')
    f.write(f'beta,2.0,{tmp}/src/beta-2.0.tar.gz\n')
def blob(strings): return b'\0'.join(s.encode() for s in strings) + b'\0'
roots = {
  'only-core':   A,                    # fits all three releases
  'release-1.1': A + SHARED + B + D,   # fits exactly 1.1 (D exists only there)
  'newest':      A + SHARED + B + C,   # fits exactly 1.2, the newest the base has
  'beta-only':   lits('beta own', 50) + SHARED,
  'gamma-only':  lits('gamma only', 40),
  'nothing':     ['unrelated text that no release contains, long enough to be a string'],
}
for name, strings in roots.items():
    os.makedirs(f'{tmp}/root-{name}/usr/bin')
    open(f'{tmp}/root-{name}/usr/bin/prog', 'wb').write(blob(strings) + b'\0' * 64)
os.makedirs(f'{tmp}/root-own-lib/usr/lib')
open(f'{tmp}/root-own-lib/usr/lib/libalpha.so.1', 'wb').write(blob(A + SHARED + B + D) + b'\0' * 64)
os.makedirs(f'{tmp}/root-mixed/usr/lib'); os.makedirs(f'{tmp}/root-mixed/usr/bin')
open(f'{tmp}/root-mixed/usr/lib/libalpha.so.1', 'wb').write(blob(A + D) + b'\0' * 64)            # names 1.1, weakly
open(f'{tmp}/root-mixed/usr/bin/mid', 'wb').write(blob(A + SHARED + B) + b'\0' * 64)            # fits 1.1 and 1.2
open(f'{tmp}/root-mixed/usr/bin/top', 'wb').write(blob(A + SHARED + B + C) + b'\0' * 64)        # fits only 1.2
PY

KB="$TMP/kb/kb.sqlite3"; mkdir -p "$TMP/kb"
if python3 "$LIB/binarykb.py" build --kb "$TMP/kb.csv" --bg "$TMP/bg" --release test-1 --out "$KB" 2>"$TMP/build.err"; then
    pass "the knowledge base builds from release tarballs"
else
    fail "the knowledge base did not build" "$(tail -3 "$TMP/build.err")"
fi

ident() {   # ident <root-name> [extra env...] -> JSON on stdout
    local r="$1"; shift
    env FW_BINKB_NONELF=true "$@" python3 "$LIB/identify-binary-kb.py" "$TMP/root-$r" "$KB" 2>"$TMP/ident.err"
}
prop() { jq -r --arg n "$2" '.[] | select(.name == "alpha") | (.properties[]? | select(.name == $n) | .value)' <<<"$1"; }

# ---- versions ---------------------------------------------------------------
out="$(ident release-1.1)"
if [ "$(jq -r '.[] | select(.name == "alpha") | .version' <<<"$out")" = "1.1" ]; then
    pass "a binary carrying only release 1.1 is reported as alpha 1.1"
else fail "release 1.1 was not read as alpha 1.1" "$out"; fi
if [ -z "$(prop "$out" bomlens:versionMayBeNewer)" ]; then
    pass "a release that is not the newest is not marked as possibly newer"
else fail "a middle release was marked as possibly newer"; fi

out="$(ident newest)"
if [ "$(jq -r '.[] | select(.name == "alpha") | has("version")' <<<"$out")" = "false" ] \
   && [ "$(prop "$out" bomlens:versionMayBeNewer)" = "true" ] && [ "$(prop "$out" bomlens:versionCandidates)" = "1.2" ] \
   && [ "$(prop "$out" bomlens:evidenceGrade)" = "presence-only" ]; then
    pass "the newest release the base has is not written as the version: it may be newer, so the supplier is asked"
else fail "the newest release was written as a version" "$out"; fi
out="$(ident newest FW_BINKB_TRUST_NEWEST=true)"
if [ "$(jq -r '.[] | select(.name == "alpha") | .version' <<<"$out")" = "1.2" ] && [ "$(prop "$out" bomlens:versionMayBeNewer)" = "true" ]; then
    pass "FW_BINKB_TRUST_NEWEST=true writes that version, still marked"
else fail "the override did not write the version" "$out"; fi

out="$(ident only-core)"
if [ "$(jq -r '.[] | select(.name == "alpha") | has("version")' <<<"$out")" = "false" ] \
   && [ "$(prop "$out" bomlens:versionCandidates)" = "1.0,1.1,1.2" ] \
   && [ "$(prop "$out" bomlens:evidenceGrade)" = "presence-only" ]; then
    pass "strings every release has give candidates and no version"
else fail "an ambiguous result was given a version or lost its candidates" "$out"; fi

# ---- shared code and background ------------------------------------------------
out="$(ident beta-only)"
if [ "$(jq -r '[.[] | .name] | join(",")' <<<"$out")" = "beta" ]; then
    pass "code copied from another component is credited to the component it came from"
else fail "shared strings pulled in the wrong component" "$out"; fi
out="$(ident gamma-only)"
if [ "$(jq 'length' <<<"$out")" = "0" ]; then
    pass "a background package's strings are never reported"
else fail "a background package was reported" "$out"; fi
out="$(ident nothing)"
if [ "$(jq 'length' <<<"$out")" = "0" ]; then pass "a binary with no known strings reports nothing"
else fail "an unrelated binary reported a component" "$out"; fi

# ---- output shape ------------------------------------------------------------------
out="$(ident release-1.1)"
if jq -e '.[0] | (.["bom-ref"] | startswith("binary-kb:")) and .type == "library"
          and ([.properties[] | select(.name == "bomlens:identifiedBy" and .value == "binary-kb")] | length == 1)
          and ([.properties[] | select(.name == "bomlens:kbRelease" and .value == "test-1")] | length == 1)
          and (.evidence.occurrences | length >= 1) and (has("purl") | not)' <<<"$out" >/dev/null; then
    pass "a result names its pass, the base release and the files it was found in, and invents no purl"
else fail "the component record is malformed" "$out"; fi

if jq -e --arg sha "$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/root-release-1.1/usr/bin/prog")" \
      '.[0] | ([.properties[] | select(.name == "bomlens:kbEvidenceSha256" and .value == $sha)] | length == 1)
            and ([.properties[] | select(.name == "bomlens:kbEvidenceFile" and .value == "usr/bin/prog")] | length == 1)
            and ([.properties[] | select(.name == "bomlens:kbEvidenceStrings") | .value | fromjson | length >= 1] | all)' <<<"$out" >/dev/null; then
    pass "a result carries the hash of its evidence file and the longest strings that matched, for a reviewer to check"
else fail "the evidence file hash or matched strings are missing" "$out"; fi

# ---- static link relation -------------------------------------------------------------
if [ "$(prop "$out" bomlens:linkage)" = "embedded" ] && [ "$(prop "$out" bomlens:embeddedIn)" = "usr/bin/prog" ]; then
    pass "a component found inside a program that is not its own file is reported as embedded in that program"
else fail "the embedded relation is missing" "$out"; fi
own="$(ident own-lib)"
if [ -z "$(prop "$own" bomlens:linkage)" ] && [ -z "$(prop "$own" bomlens:embeddedIn)" ]; then
    pass "a component found in its own library file is not marked as embedded"
else fail "an own library was marked as embedded" "$own"; fi

# ---- constant names --------------------------------------------------------------------
if python3 - "$LIB" "$TMP" <<'PY'
import io, sys, tarfile
sys.path.insert(0, sys.argv[1]); import binarykb
p = sys.argv[2] + '/const.tar.gz'
body = b'const char *a = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY"; const char *b = "unable to get issuer certificate locally";\n'
with tarfile.open(p, 'w:gz') as t:
    i = tarfile.TarInfo('x/a.c'); i.size = len(body); t.addfile(i, io.BytesIO(body))
got = binarykb.source_strings(p)
sys.exit(0 if b'unable to get issuer certificate locally' in got and b'X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY' not in got else 1)
PY
then pass "a literal that is only an upper-case constant name is not stored, a sentence is"
else fail "constant names are stored in the base, or ordinary strings were dropped"; fi

# ---- confidence ---------------------------------------------------------------------
if [ "$(prop "$(ident only-core)" bomlens:kbConfidence)" = "high" ]; then
    pass "a score well above the stored threshold is marked high confidence"
else fail "a strong result was not marked high confidence"; fi
mkdir -p "$TMP/kb-near"
python3 "$LIB/binarykb.py" build --kb "$TMP/kb.csv" --bg "$TMP/bg" --release test-near --rule-score 1500 --out "$TMP/kb-near/kb.sqlite3" 2>/dev/null
near="$(env FW_BINKB_NONELF=true python3 "$LIB/identify-binary-kb.py" "$TMP/root-only-core" "$TMP/kb-near/kb.sqlite3" 2>/dev/null)"
if [ "$(prop "$near" bomlens:kbConfidence)" = "low" ]; then
    pass "a score close to the stored threshold is marked low confidence, for the review page to list first"
else fail "a near-threshold result was not marked low confidence" "$near"; fi

mkdir -p "$TMP/bg-own" "$TMP/kb-own"
cp "$TMP/bg/"* "$TMP/src/alpha-1.1.tar.gz" "$TMP/bg-own/"
python3 "$LIB/binarykb.py" build --kb "$TMP/kb.csv" --bg "$TMP/bg-own" --release test-own --out "$TMP/kb-own/kb.sqlite3" 2>"$TMP/own.err"
own="$(env FW_BINKB_NONELF=true python3 "$LIB/identify-binary-kb.py" "$TMP/root-release-1.1" "$TMP/kb-own/kb.sqlite3" 2>/dev/null)"
if [ "$(jq -r '.[] | select(.name == "alpha") | .version' <<<"$own")" = "1.1" ] && grep -q "skipped: alpha is a component" "$TMP/own.err"; then
    pass "a component's own release given as background is skipped, so the component is still found"
else fail "a component listed as background too was not found" "$own"; fi

mkdir -p "$TMP/wide/src" "$TMP/wide/kb" "$TMP/root-wide/usr/bin"
python3 - "$TMP/wide" "$TMP/root-wide/usr/bin/prog" <<'PY'
import io, sys, tarfile
w, prog = sys.argv[1:3]
core = [f'wide core message number {i} for the knowledge base test' for i in range(40)]
with open(f'{w}/kb.csv', 'w') as kb:
    for r in range(70):   # more releases than a 64-bit version mask holds
        own = [f'wide release {r} only message number {i} for the test' for i in range(3)]
        data = ('\n'.join(f'const char *s{i} = "{s}";' for i, s in enumerate(core + own)) + '\n').encode()
        with tarfile.open(f'{w}/src/wide-1.{r}.tar.gz', 'w:gz') as tf:
            ti = tarfile.TarInfo(f'wide-1.{r}/w.c'); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
        kb.write(f'wide,1.{r},{w}/src/wide-1.{r}.tar.gz\n')
own = [f'wide release 66 only message number {i} for the test' for i in range(3)]
open(prog, 'wb').write(b'\0'.join(s.encode() for s in core + own) + b'\0' * 64)
PY
if python3 "$LIB/binarykb.py" build --kb "$TMP/wide/kb.csv" --release test-wide --out "$TMP/wide/kb/kb.sqlite3" 2>"$TMP/wide.err"; then
    wide="$(env FW_BINKB_NONELF=true python3 "$LIB/identify-binary-kb.py" "$TMP/root-wide" "$TMP/wide/kb/kb.sqlite3" 2>/dev/null)"
    if [ "$(jq -r '.[] | select(.name == "wide") | .version' <<<"$wide")" = "1.66" ]; then
        pass "a component with more than 63 releases builds and its 67th release is read back exactly"
    else fail "a release past the 63rd was not read back" "$wide"; fi
else fail "a component with more than 63 releases did not build" "$(tail -1 "$TMP/wide.err")"; fi
# ---- kernel files -----------------------------------------------------------------------
mkdir -p "$TMP/root-kmod/lib/modules/6.1/kernel" "$TMP/kb-kmod"
cp "$TMP/root-release-1.1/usr/bin/prog" "$TMP/root-kmod/lib/modules/6.1/kernel/drv.ko"
cp "$TMP/root-beta-only/usr/bin/prog" "$TMP/root-kmod/lib/modules/6.1/kernel/other.ko"
kmod="$(ident kmod)"
if [ "$(jq 'length' <<<"$kmod")" = "0" ]; then
    pass "a kernel module is not credited to a user-space component whose strings it carries"
else fail "a kernel module was reported as a user-space component" "$kmod"; fi
python3 "$LIB/binarykb.py" build --kb "$TMP/kb.csv" --bg "$TMP/bg" --kernel-only beta --release test-kmod --out "$TMP/kb-kmod/kb.sqlite3" 2>/dev/null
kmod="$(env FW_BINKB_NONELF=true python3 "$LIB/identify-binary-kb.py" "$TMP/root-kmod" "$TMP/kb-kmod/kb.sqlite3" 2>/dev/null)"
if [ "$(jq -r '[.[].name] | sort | join(",")' <<<"$kmod")" = "beta" ]; then
    pass "a kernel module still reports a kernel-only component"
else fail "a kernel-only component was not reported in a kernel module" "$kmod"; fi

# ---- review decisions -------------------------------------------------------------------
sha="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$TMP/root-release-1.1/usr/bin/prog")"
dec() { printf '%s' "$1" > "$TMP/dec.json"; ident release-1.1 FW_BINARY_KB_DECISIONS="$TMP/dec.json"; }
out="$(dec '[{"component":"alpha","decision":"exclude","reason":"own code, copied the other way","reviewer":"qa"}]')"
if [ "$(jq 'length' <<<"$out")" = "0" ] && grep -q "excluded by review" "$TMP/ident.err"; then
    pass "an exclude decision drops the component and says so"
else fail "exclude did not drop the component" "$out"; fi
out="$(dec '[{"component":"alpha","decision":"exclude","reviewer":"qa"}]')"
if [ "$(jq 'length' <<<"$out")" = "1" ] && grep -q "gives no reason" "$TMP/ident.err"; then
    pass "a decision without a reason is ignored"
else fail "a decision with no reason was applied" "$out"; fi
out="$(dec '[{"component":"alpha","decision":"exclude","reason":"x","evidence_sha256":"deadbeef"}]')"
if [ "$(jq 'length' <<<"$out")" = "1" ]; then pass "a decision whose evidence hash no longer matches is ignored"
else fail "a stale decision was applied" "$out"; fi
out="$(dec "[{\"component\":\"alpha\",\"decision\":\"version\",\"version\":\"1.0.1\",\"reason\":\"banner read\",\"evidence_sha256\":\"$sha\"}]")"
if [ "$(jq -r '.[] | select(.name == "alpha") | .version' <<<"$out")" = "1.0.1" ] \
   && [ "$(prop "$out" bomlens:versionBasis)" = "review" ] && [ -n "$(prop "$out" bomlens:review)" ]; then
    pass "a version decision replaces the version and records the review"
else fail "the version decision was not applied" "$out"; fi
out="$(dec 'not json')"
if [ "$(jq 'length' <<<"$out")" = "1" ]; then pass "an unreadable review file is ignored, not fatal"
else fail "an unreadable review file stopped the pass"; fi

# ---- robustness ------------------------------------------------------------------------------
out="$(python3 "$LIB/identify-binary-kb.py" "$TMP/root-release-1.1" "$TMP/missing" 2>/dev/null)"
if [ "$out" = "[]" ]; then pass "no knowledge base: an empty result, not an error"
else fail "a missing base did not give []" "$out"; fi
echo "not a database" > "$TMP/bad.sqlite3"
out="$(python3 "$LIB/identify-binary-kb.py" "$TMP/root-release-1.1" "$TMP/bad.sqlite3" 2>/dev/null)"
if [ "$out" = "[]" ]; then pass "a damaged base is skipped, the scan goes on"
else fail "a damaged base broke the pass" "$out"; fi
python3 "$LIB/binarykb.py" info "$KB" >"$TMP/info.json" 2>&1
if [ "$(jq -r '.release' "$TMP/info.json")" = "test-1" ] && [ "$(jq -r '.components.alpha.last' "$TMP/info.json")" = "1.2" ]; then
    pass "releases are stored in release order, not in file order (1.2 listed first)"
else fail "info does not show release order" "$(cat "$TMP/info.json")"; fi
# The same inputs give the same base whatever the hash seed: equal file bytes here, and an equal content
# hash that also holds across machines and SQLite versions (the file header records the library version).
PYTHONHASHSEED=7 python3 "$LIB/binarykb.py" build --kb "$TMP/kb.csv" --bg "$TMP/bg" --release test-1 --out "$TMP/kb2/kb.sqlite3" 2>/dev/null
h1="$(python3 "$LIB/binarykb.py" info "$KB" | jq -r .content_sha256)"; h2="$(python3 "$LIB/binarykb.py" info "$TMP/kb2/kb.sqlite3" | jq -r .content_sha256)"
if cmp -s "$KB" "$TMP/kb2/kb.sqlite3" && [ -n "$h1" ] && [ "$h1" = "$h2" ]; then
    pass "two builds from the same inputs give the same file and the same content hash"
else fail "the build is not reproducible" "$h1 vs $h2"; fi
# The thresholds are stored in the base and can be set when it is built.
mkdir -p "$TMP/kb3"
python3 "$LIB/binarykb.py" build --kb "$TMP/kb.csv" --bg "$TMP/bg" --release strict --rule-score 100000 --out "$TMP/kb3/kb.sqlite3" 2>/dev/null
out="$(python3 "$LIB/identify-binary-kb.py" "$TMP/root-release-1.1" "$TMP/kb3/kb.sqlite3" 2>/dev/null; FW_BINKB_NONELF=true python3 "$LIB/identify-binary-kb.py" "$TMP/root-release-1.1" "$TMP/kb3/kb.sqlite3" 2>/dev/null)"
if [ "$(python3 "$LIB/binarykb.py" info "$TMP/kb3/kb.sqlite3" | jq -r .rule.score)" = "100000" ] && [ "$(jq -s 'map(length) | add' <<<"$out")" = "0" ]; then
    pass "a threshold set at build time is stored in the base and applied"
else fail "the stored threshold was not applied" "$out"; fi
# The base is opened read-only: writing through the reader's connection must fail.
if python3 - "$LIB" "$KB" <<'PY' 2>/dev/null
import sys, sqlite3
sys.path.insert(0, sys.argv[1])
import binarykb
kb = binarykb.KnowledgeBase(sys.argv[2])
try:
    kb.con.execute("INSERT INTO meta VALUES ('x','1')")
except sqlite3.OperationalError:
    sys.exit(0)
sys.exit(1)
PY
then pass "the base is opened read-only"
else fail "the base could be written through the reader"; fi

# ---- ELF files of every class and byte order -----------------------------------------------
python3 - "$LIB" "$TMP" <<'PY'
# Build minimal ELF files by hand: class 32/64, little/big endian, one .rodata section holding the strings.
import struct, sys
sys.path.insert(0, sys.argv[1])
tmp = sys.argv[2]
body = open(f'{tmp}/root-release-1.1/usr/bin/prog', 'rb').read()
def elf(path, bits, order):
    e = '<' if order == 'little' else '>'
    shstr = b'\0.rodata\0.shstrtab\0'
    if bits == 64:
        ehsz, shentsize = 64, 64
    else:
        ehsz, shentsize = 52, 40
    off_ro = ehsz; off_str = off_ro + len(body); off_sh = (off_str + len(shstr) + 7) & ~7
    def sh(name, typ, off, size):
        if bits == 64:
            return struct.pack(e + 'IIQQQQIIQQ', name, typ, 0, 0, off, size, 0, 0, 1, 0)
        return struct.pack(e + 'IIIIIIIIII', name, typ, 0, 0, off, size, 0, 0, 1, 0)
    secs = sh(0, 0, 0, 0) + sh(1, 1, off_ro, len(body)) + sh(9, 3, off_str, len(shstr))
    ident = b'\x7fELF' + bytes([1 if bits == 32 else 2, 1 if order == 'little' else 2, 1]) + b'\0' * 9
    if bits == 64:
        hdr = ident + struct.pack(e + 'HHIQQQIHHHHHH', 2, 62, 1, 0, 0, off_sh, 0, ehsz, 0, 0, shentsize, 3, 2)
    else:
        hdr = ident + struct.pack(e + 'HHIIIIIHHHHHH', 2, 8, 1, 0, 0, off_sh, 0, ehsz, 0, 0, shentsize, 3, 2)
    assert len(hdr) == ehsz, len(hdr)
    data = hdr + body + shstr + b'\0' * (off_sh - off_str - len(shstr)) + secs
    import os
    os.makedirs(f'{tmp}/root-elf-{bits}-{order}/bin', exist_ok=True)
    open(path.format(tmp=tmp), 'wb').write(data)
for bits in (32, 64):
    for order in ('little', 'big'):
        elf(f'{{tmp}}/root-elf-{bits}-{order}/bin/prog', bits, order)
PY
for cls in 32-little 32-big 64-little 64-big; do
    out="$(python3 "$LIB/identify-binary-kb.py" "$TMP/root-elf-$cls" "$KB" 2>/dev/null)"
    if [ "$(jq -r '.[] | select(.name == "alpha") | .version' <<<"$out")" = "1.1" ]; then
        pass "an ELF file of class/byte order $cls is read (alpha 1.1)"
    else fail "ELF $cls was not read" "$out"; fi
done
# Only ELF files are read unless asked: the same strings in a text file are not a component.
out="$(python3 "$LIB/identify-binary-kb.py" "$TMP/root-release-1.1" "$KB" 2>/dev/null)"
if [ "$out" = "[]" ]; then pass "a file that is not ELF is not read unless FW_BINKB_NONELF=true"
else fail "a non-ELF file was read by default" "$out"; fi

# ---- review page ---------------------------------------------------------------------------------
REVIEW="$LIB/binary-kb-review.py"
ident release-1.1 > "$TMP/r1.json"; ident only-core > "$TMP/r2.json"
jq -n --slurpfile a "$TMP/r1.json" --slurpfile b "$TMP/r2.json" \
   '{metadata: {component: {name: "device-fw", version: "1.0"}}, components: ($a[0] + $b[0] + [{name: "x</script><img src=x onerror=alert(1)>", properties: [{name: "bomlens:identifiedBy", value: "binary-kb"}]}])}' > "$TMP/bom.json"
if python3 "$REVIEW" "$TMP/bom.json" --lang en > "$TMP/review.html" 2>/dev/null \
   && python3 - "$TMP/review.html" <<'PY'
import json, re, sys
h = open(sys.argv[1]).read()
m = re.search(r'<script id="data" type="application/json">(.*?)</script>', h, re.S)
d = json.loads(m.group(1))
names = [i["name"] for i in d["items"]]
assert d["project"] == "device-fw 1.0", d["project"]
assert len(names) == 3 and names[-1] == "alpha", names   # the ones to decide come first, the one with a single release last
assert d["items"][-1]["version"] == "1.1" and not d["items"][-1]["reasons"]
assert "</script><img" not in h and "innerHTML" not in h
PY
then pass "the review page lists what needs a decision first, escapes hostile names and never uses innerHTML"
else fail "the review page is malformed or unsafe"; fi
if python3 "$REVIEW" "$TMP/bom.json" --lang ko 2>/dev/null | grep -q '바이너리 지식 베이스 검토'; then pass "the review page has a Korean version"
else fail "the Korean review page is missing"; fi
if ! python3 -c 'import re,sys; h=re.sub(r"<script id=\"data\".*?</script>", "", open(sys.argv[1]).read(), flags=re.S); sys.exit(1 if re.search(r"https?://|src=|<link", h) else 0)' "$TMP/review.html"; then fail "the review page references an external resource"
else pass "the review page loads nothing from the network"; fi

# ---- constant tables ---------------------------------------------------------------------------------
# Hand-made ELF files: an unstripped reference with five 1 KiB read-only tables as OBJECT symbols
# (32-bit little endian), and stripped targets of other classes and byte orders carrying the same
# tables with their 4-byte elements reversed on the big-endian ones.
python3 - "$TMP" <<'PY'
import os, random, struct, sys
tmp = sys.argv[1]
rnd = random.Random(5)
tables = [bytes(rnd.randrange(256) for _ in range(1024)) for _ in range(5)]
def swap4(b): return b''.join(b[i:i + 4][::-1] for i in range(0, len(b), 4))
def elf(path, bits, order, tabs, symbols):
    e = '<' if order == 'little' else '>'
    ro = b''.join(tabs)
    shstr = b'\0.rodata\0.symtab\0.strtab\0.shstrtab\0'
    strtab = b'\0' + b''.join(f'tab{i}\0'.encode() for i in range(len(tabs))) if symbols else b'\0'
    syms = b''
    if symbols:
        syms = b'\0' * (16 if bits == 32 else 24)
        off = 0; noff = 1
        for i, t in enumerate(tabs):
            if bits == 32: syms += struct.pack(e + 'IIIBBH', noff, off, len(t), 0x11, 0, 1)
            else: syms += struct.pack(e + 'IBBHQQ', noff, 0x11, 0, 1, off, len(t))
            off += len(t); noff += len(f'tab{i}\0')
    ehsz, shentsize = (52, 40) if bits == 32 else (64, 64)
    o_ro = ehsz; o_sym = o_ro + len(ro); o_str = o_sym + len(syms); o_shs = o_str + len(strtab); o_sh = (o_shs + len(shstr) + 7) & ~7
    def sh(name, typ, off, size, link=0, ent=0):
        if bits == 32: return struct.pack(e + 'IIIIIIIIII', name, typ, 0, 0, off, size, link, 0, 1, ent)
        return struct.pack(e + 'IIQQQQIIQQ', name, typ, 0, 0, off, size, link, 0, 1, ent)
    secs = sh(0, 0, 0, 0) + sh(1, 1, o_ro, len(ro)) + sh(9, 2, o_sym, len(syms), 3, 16 if bits == 32 else 24) + sh(17, 3, o_str, len(strtab)) + sh(25, 3, o_shs, len(shstr))
    ident = b'\x7fELF' + bytes([1 if bits == 32 else 2, 1 if order == 'little' else 2, 1]) + b'\0' * 9
    if bits == 64: hdr = ident + struct.pack(e + 'HHIQQQIHHHHHH', 2, 62, 1, 0, 0, o_sh, 0, ehsz, 0, 0, shentsize, 5, 4)
    else: hdr = ident + struct.pack(e + 'HHIIIIIHHHHHH', 2, 8, 1, 0, 0, o_sh, 0, ehsz, 0, 0, shentsize, 5, 4)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'wb').write(hdr + ro + syms + strtab + shstr + b'\0' * (o_sh - o_shs - len(shstr)) + secs)
elf(f'{tmp}/ref/tabcomp', 32, 'little', tables, True)
open(f'{tmp}/tabs.csv', 'w').write(f'tabcomp,{tmp}/ref/tabcomp\n')
elf(f'{tmp}/root-tab-le32/bin/prog', 32, 'little', tables, False)
elf(f'{tmp}/root-tab-be64/bin/prog', 64, 'big', [swap4(t) for t in tables], False)
elf(f'{tmp}/root-tab-be32-part/bin/prog', 32, 'big', [swap4(t) for t in tables[:3]], False)
elf(f'{tmp}/root-tab-be32-four/bin/prog', 32, 'big', [swap4(t) for t in tables[:4]], False)
open(f'{tmp}/bgfile', 'wb').write(b'header ' + tables[4] + b' trailer')
open(f'{tmp}/bg.txt', 'w').write(f'{tmp}/bgfile\n')
PY
mkdir -p "$TMP/kbt"
python3 "$LIB/binarykb.py" build --kb "$TMP/kb.csv" --bg "$TMP/bg" --ref "$TMP/tabs.csv" --release tab-1 --out "$TMP/kbt/kb.sqlite3" 2>"$TMP/tab.err"
mkdir -p "$TMP/kbt2"
python3 "$LIB/binarykb.py" build --kb "$TMP/kb.csv" --bg "$TMP/bg" --ref "$TMP/tabs.csv" --ref-bg "$TMP/bg.txt" --release tab-2 --out "$TMP/kbt2/kb.sqlite3" 2>"$TMP/tab2.err"
tabident() { python3 "$LIB/identify-binary-kb.py" "$TMP/root-$2" "$1" 2>/dev/null; }
for t in tab-le32 tab-be64; do
    out="$(tabident "$TMP/kbt/kb.sqlite3" $t)"
    if [ "$(jq -r '.[0].name' <<<"$out")" = "tabcomp" ] && [ "$(jq -r '.[0].properties[] | select(.name == "bomlens:kbTables") | .value' <<<"$out")" = "5 tables, 5120 bytes" ]; then
        pass "five constant tables found in $t, reported without a version"
    else fail "tables not found in $t" "$out $(tail -2 "$TMP/tab.err")"; fi
done
out="$(tabident "$TMP/kbt/kb.sqlite3" tab-be32-part)"
if [ "$(jq 'length' <<<"$out")" = "0" ]; then pass "three tables are below the threshold and report nothing"
else fail "three tables were enough" "$out"; fi
out="$(tabident "$TMP/kbt/kb.sqlite3" tab-be32-four)"
if [ "$(jq -r '.[0].name' <<<"$out")" = "tabcomp" ]; then pass "four tables of 4 KiB in total reach the threshold"
else fail "four tables were not enough" "$out"; fi
out="$(tabident "$TMP/kbt2/kb.sqlite3" tab-be32-four)"; out2="$(tabident "$TMP/kbt2/kb.sqlite3" tab-be64)"
if [ "$(jq 'length' <<<"$out")" = "1" ] && [ "$(jq -r '.[0].properties[] | select(.name == "bomlens:kbTables") | .value' <<<"$out2")" = "4 tables, 4096 bytes" ]; then
    pass "a table found in a background file is dropped from the signatures"
else fail "the background table was kept" "$out2 $(grep -c background "$TMP/tab2.err")"; fi

# ---- wiring -------------------------------------------------------------------------------------
if grep -q 'identify-binary-kb.py' "$LIB/scan-firmware.sh" && grep -q -- '--slurpfile g "\$BINKB_COMPS"' "$LIB/scan-firmware.sh" \
   && grep -q '\$a\[0\] + \$b\[0\] + \$c\[0\] + \$d\[0\] + \$f\[0\] + \$e\[0\] + \$g\[0\]' "$LIB/scan-firmware.sh"; then
    pass "scan-firmware.sh runs the pass and merges its result last (that it is never the base is checked on the merge below)"
else fail "the pass is not wired into the merge in scan-firmware.sh"; fi
if grep -q 'FW_BINARY_KB' "$LIB/scan-firmware.sh" && grep -q -- '-e FW_BINARY_KB=' "$ROOT_DIR/scripts/scan-sbom.sh"; then
    pass "scan-sbom.sh forwards --binary-kb to the container"
else fail "--binary-kb is not forwarded"; fi
out="$("$ROOT_DIR/scripts/scan-sbom.sh" --project p --version 1 --target "$TMP" --firmware --binary-kb "$TMP/nope" --generate-only 2>&1 | tail -1)"
case "$out" in *"no knowledge base at"*) pass "--binary-kb with no base is refused up front";; *) fail "--binary-kb with no base was not refused" "$out";; esac
out="$("$ROOT_DIR/scripts/scan-sbom.sh" --project p --version 1 --target "$TMP" --firmware --kb-decisions "$TMP/dec.json" --generate-only 2>&1 | tail -1)"
case "$out" in *"needs --binary-kb"*) pass "--kb-decisions without --binary-kb is refused";; *) fail "--kb-decisions alone was not refused" "$out";; esac
if grep -q 'def cap(name, default)' "$LIB/identify-binary-kb.py"; then
    pass "identify-binary-kb falls back when a cap arrives empty or malformed"
else fail "identify-binary-kb reads its cap with a bare int()"; fi

# ---- defects found in review ----------------------------------------------------------------
# A version newer than the base comes back as the last release of its own series, so the newest of the
# whole base is not enough to mark it.
if python3 - "$LIB" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import binarykb as b
v = ['1.2.11', '1.2.12', '1.3.0']
ok = [b.KnowledgeBase._newest_of_series(v, c) for c in v] == [False, True, True]
sys.exit(0 if ok else 1)
PY
then pass "the last release of a series is marked as possibly newer even when another series follows it"
else fail "the newest-of-series check is wrong"; fi

# Overlapping or oversized section headers cannot expand the bytes read beyond the file.
if python3 - "$LIB" <<'PY'
import struct, sys
sys.path.insert(0, sys.argv[1])
import binarykb as b
body = b'x' * 200000
shstr = b'\0.rodata\0.shstrtab\0'
n = 2000
shoff = 64 + len(body) + len(shstr)
hdr = bytearray(64)
hdr[:4] = b'\x7fELF'; hdr[4] = 2; hdr[5] = 1
struct.pack_into('<Q', hdr, 0x28, shoff); struct.pack_into('<H', hdr, 0x3a, 64)
struct.pack_into('<H', hdr, 0x3c, n + 1); struct.pack_into('<H', hdr, 0x3e, n)
def sh(name, typ, off, size):
    e = bytearray(64); struct.pack_into('<II', e, 0, name, typ); struct.pack_into('<Q', e, 0x18, off); struct.pack_into('<Q', e, 0x20, size); return bytes(e)
secs = b''.join(sh(1, 1, 64, len(body)) for _ in range(n)) + sh(9, 3, 64 + len(body), len(shstr))
data = bytes(hdr) + body + shstr + secs
out, is_elf = b.string_bytes(data)
bad = bytearray(data); struct.pack_into('<H', bad, 0x3c, 65535)
out2, is_elf2 = b.string_bytes(bytes(bad))
sys.exit(0 if is_elf and len(out) <= len(data) and not is_elf2 else 1)
PY
then pass "overlapping sections are read once and a header claiming thousands of sections is not trusted"
else fail "a crafted section table expanded the bytes read"; fi

# Own-file judgement: the name must be the component's, not merely contain it.
if python3 - "$LIB" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location('ibk', sys.argv[1] + '/identify-binary-kb.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
yes = [('zlib', 'usr/lib/libz.so.1'), ('openssl', 'usr/lib/libcrypto.so.1.1'), ('mbedtls', 'lib/libmbedcrypto.so.7'),
       ('iproute2', 'sbin/ip'), ('hostapd', 'usr/sbin/wpad'), ('busybox', 'bin/busybox'), ('alpha', 'usr/lib/libalpha.so.1')]
no = [('zlib', 'usr/lib/libzstd.so.1'), ('ip', 'usr/bin/zip'), ('alpha', 'usr/bin/alphabet'), ('zlib', 'bin/busybox')]
sys.exit(0 if all(m.is_own_file(*x) for x in yes) and not any(m.is_own_file(*x) for x in no) else 1)
PY
then pass "own files are told from hosts by name: libz.so for zlib, wpad for hostapd, but not libzstd for zlib"
else fail "the own-file judgement is wrong"; fi

# Two releases of one component in two files give two components.
mkdir -p "$TMP/root-two/usr/lib" "$TMP/root-two/usr/bin"
cp "$TMP/root-release-1.1/usr/bin/prog" "$TMP/root-two/usr/lib/libalpha.so.1"
cp "$TMP/root-newest/usr/bin/prog" "$TMP/root-two/usr/bin/other"
out="$(ident two FW_BINKB_TRUST_NEWEST=true)"
if [ "$(jq -r '[.[] | select(.name == "alpha") | .version] | sort | join(",")' <<<"$out")" = "1.1,1.2" ]; then
    pass "two releases of one component in two files are two components"
else fail "two releases were merged into one" "$out"; fi

# A file that names one release does not absorb a file that only fits another.
mkdir -p "$TMP/root-named/usr/lib" "$TMP/root-named/usr/bin" "$TMP/root-fits/usr/lib" "$TMP/root-fits/usr/bin"
cp "$TMP/root-release-1.1/usr/bin/prog" "$TMP/root-named/usr/lib/libalpha.so.1"
cp "$TMP/root-newest/usr/bin/prog" "$TMP/root-named/usr/bin/other"
out="$(ident named)"
if [ "$(jq -r '[.[] | select(.name == "alpha") | (.version // ([.properties[] | select(.name == "bomlens:versionRange") | .value][0]))] | sort | join(",")' <<<"$out")" = "1.1,1.2 or later" ]; then
    pass "a release named by one file is kept apart from a file that only fits another release"
else fail "a named release absorbed a file of another release" "$out"; fi
cp "$TMP/root-release-1.1/usr/bin/prog" "$TMP/root-fits/usr/lib/libalpha.so.1"
cp "$TMP/root-only-core/usr/bin/prog" "$TMP/root-fits/usr/bin/other"
out="$(ident fits)"
if [ "$(jq -r '[.[] | select(.name == "alpha") | .version] | join(",")' <<<"$out")" = "1.1" ]; then
    pass "a file that still fits the named release joins it instead of becoming a second component"
else fail "a file that fits the named release was reported apart" "$out"; fi
out="$(ident mixed)"
if [ "$(jq -r '[.[] | select(.name == "alpha") | (.version // ([.properties[] | select(.name == "bomlens:versionRange") | .value][0]))] | sort | join(",")' <<<"$out")" = "1.1,1.2 or later" ] \
   && [ "$(jq '[.[]."bom-ref"] | length == (unique | length)' <<<"$out")" = "true" ]; then
    pass "a version group keeps its version when a stronger file in it only fits, and no two results share a reference"
else fail "a version group lost its version or two results share a reference" "$out"; fi

# The walk is sorted, so the cap keeps the same files on every run.
mkdir -p "$TMP/root-order/a" "$TMP/root-order/b"
cp "$TMP/root-release-1.1/usr/bin/prog" "$TMP/root-order/a/prog"
cp "$TMP/root-beta-only/usr/bin/prog" "$TMP/root-order/b/prog"
out="$(ident order FW_BINKB_MAX_FILES=1)"
if [ "$(jq -r '[.[] | .name] | join(",")' <<<"$out")" = "alpha" ]; then
    pass "the file cap keeps the first files in sorted order"
else fail "the file cap kept files in directory order" "$out"; fi

# The result names the base it came from, and a base that fails midway is reported.
want="$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$KB")"
out="$(ident release-1.1)"
if [ "$(prop "$out" bomlens:kbSha256)" = "$want" ]; then pass "the result carries the hash of the base file"
else fail "the base hash is missing from the result" "$out"; fi
mkdir -p "$TMP/kb4"; cp "$KB" "$TMP/kb4/kb.sqlite3"
python3 - "$TMP/kb4/kb.sqlite3" <<'PY'
import os, sys
p = sys.argv[1]; n = os.path.getsize(p)
with open(p, 'r+b') as f:
    f.seek(4096)
    f.write(os.urandom(max(n - 4096, 0)))
PY
out="$(FW_BINKB_NONELF=true python3 "$LIB/identify-binary-kb.py" "$TMP/root-release-1.1" "$TMP/kb4/kb.sqlite3" 2>"$TMP/dmg.err")"
if jq -e 'type == "array"' <<<"$out" >/dev/null 2>&1 && grep -q "WARN" "$TMP/dmg.err"; then
    pass "a base damaged after the header is reported and the scan goes on"
else fail "a damaged base was not reported" "$(cat "$TMP/dmg.err")"; fi

# A presence-only record whose candidate releases exclude the version found elsewhere is kept by the merge;
# one whose candidates include that version is a repeat and is dropped.
python3 - "$LIB/scan-firmware.sh" "$TMP/merge.jq" <<'PY'
import sys
s = open(sys.argv[1]).read()
k = "--slurpfile g \"$BINKB_COMPS\" '"
open(sys.argv[2], 'w').write(s[s.index(k) + len(k):s.index("' > \"$WORK/merged.json\"")])
PY
echo '[{"name":"openssl","version":"1.1.1","type":"library"},{"name":"zlib","version":"1.2.11","type":"library"}]' > "$TMP/m-a.json"
echo '[]' > "$TMP/m-e.json"
echo '[{"name":"openssl","type":"library","properties":[{"name":"bomlens:evidenceGrade","value":"presence-only"},{"name":"bomlens:versionCandidates","value":"3.0.1,3.0.2"}]},{"name":"zlib","type":"library","properties":[{"name":"bomlens:evidenceGrade","value":"presence-only"},{"name":"bomlens:versionCandidates","value":"1.2.11"}]}]' > "$TMP/m-g.json"
mout="$(jq -n --slurpfile a "$TMP/m-a.json" --slurpfile b "$TMP/m-e.json" --slurpfile c "$TMP/m-e.json" --slurpfile d "$TMP/m-e.json" \
    --slurpfile e "$TMP/m-e.json" --slurpfile f "$TMP/m-e.json" --slurpfile g "$TMP/m-g.json" -f "$TMP/merge.jq" 2>&1)"
if [ "$(jq -r '[.[] | "\(.name)@\(.version // "none")"] | join(",")' <<<"$mout")" = "openssl@none,openssl@1.1.1,zlib@1.2.11" ]; then
    pass "the merge keeps a presence-only record that names other releases and drops one that repeats a version"
else fail "the merge handled presence-only records wrongly" "$mout"; fi

# ---- the base holds no source text -----------------------------------------------------------
# Literals are kept as a hash and a length, tables as one window, a length and a hash, so a base
# can be published without carrying text or bytes from the sources it was built from.
if python3 - "$LIB" "$KB" "$TMP/kbt/kb.sqlite3" "$TMP/tabs.csv" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
import binarykb as b
raw = open(sys.argv[2], 'rb').read() + open(sys.argv[3], 'rb').read()
lits = [b'alpha core message number 1 for the knowledge base test', b'copied helper message number 3', b'gamma only message']
blobs = [blob for line in open(sys.argv[4]) if line.strip() for _, blob in b.rodata_objects(line.strip().split(',', 1)[1])]
sys.exit(0 if blobs and not any(x in raw for x in lits) and not any(blob[:64] in raw for blob in blobs) else 1)
PY
then pass "the base keeps no literal text and no table bytes beyond a 16-byte window"
else fail "source text or table bytes are stored in the base"; fi

# A base of the earlier schema, which kept the literals as text and the tables as bytes, is still read and
# gives the same result. The fixture is built by the schema 1 builder itself (binarykb.py as it was before
# schema 2, kept in tests/fixtures/binary-kb), constant tables included.
OLDB="$ROOT_DIR/tests/fixtures/binary-kb/binarykb-schema1.py"
mkdir -p "$TMP/kb-s1" "$TMP/kbt-s1"
python3 "$OLDB" build --kb "$TMP/kb.csv" --bg "$TMP/bg" --release test-1 --out "$TMP/kb-s1/kb.sqlite3" 2>/dev/null
python3 "$OLDB" build --kb "$TMP/kb.csv" --bg "$TMP/bg" --ref "$TMP/tabs.csv" --release tab-1 --out "$TMP/kbt-s1/kb.sqlite3" 2>/dev/null
cmpview() { jq -c '[.[] | {name, version, s: [.properties[] | select(.name | IN("bomlens:kbScore", "bomlens:kbUniqueStrings", "bomlens:kbEvidenceStrings", "bomlens:versionCandidates", "bomlens:versionRange", "bomlens:kbTables", "bomlens:kbConfidence")) | "\(.name)=\(.value)"]}]'; }
s1="" ; s2=""
for r in release-1.1 only-core newest beta-only; do
    s1="$s1$(FW_BINKB_NONELF=true python3 "$LIB/identify-binary-kb.py" "$TMP/root-$r" "$TMP/kb-s1/kb.sqlite3" 2>/dev/null | cmpview)"
    s2="$s2$(ident $r | cmpview)"
done
for r in tab-le32 tab-be64 tab-be32-four; do
    s1="$s1$(tabident "$TMP/kbt-s1/kb.sqlite3" $r | cmpview)"
    s2="$s2$(tabident "$TMP/kbt/kb.sqlite3" $r | cmpview)"
done
if [ "$(sqlite3 "$TMP/kbt-s1/kb.sqlite3" 'select count(*) from tbl' 2>/dev/null || python3 -c 'import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute("select count(*) from tbl").fetchone()[0])' "$TMP/kbt-s1/kb.sqlite3")" -gt 0 ] \
   && grep -q 'versionCandidates' <<<"$s1" && grep -q 'kbTables' <<<"$s1" && [ "$s1" = "$s2" ]; then
    pass "a base of the earlier schema, tables included, is read and gives the same result"
else fail "the earlier schema reads differently" "$s1 vs $s2"; fi

# Keys that collide: a row is keyed by the hash and the length, so literals that share a hash but not a
# length keep their rows and are still found, and only literals of the same length are dropped.
if python3 - "$LIB" "$TMP" <<'PY' 2>"$TMP/clash.err"
import io, os, sys, tarfile
sys.path.insert(0, sys.argv[1])
import binarykb as b
tmp = sys.argv[2] + '/clash'; os.makedirs(tmp)
b.string_key = lambda s: b'\0' * 8          # every literal gets the same hash
lits = ['x' * n + ' distinct length literal' for n in range(30)] + ['same length literal ' + 'y' * 60 + 'A', 'same length literal ' + 'y' * 60 + 'B']
src = ('\n'.join(f'const char *s{i} = "{s}";' for i, s in enumerate(lits)) + '\n').encode()
with tarfile.open(f'{tmp}/c-1.0.tar.gz', 'w:gz') as tf:
    ti = tarfile.TarInfo('c-1.0/c.c'); ti.size = len(src); tf.addfile(ti, io.BytesIO(src))
open(f'{tmp}/kb.csv', 'w').write(f'clash,1.0,{tmp}/c-1.0.tar.gz\n')
b.main(['build', '--kb', f'{tmp}/kb.csv', '--release', 'clash', '--out', f'{tmp}/kb.sqlite3'])
kb = b.KnowledgeBase(f'{tmp}/kb.sqlite3')
found = kb.owners_of({s.encode() for s in lits})
same = {lits[-1].encode(), lits[-2].encode()}
sys.exit(0 if len(found) == 30 and not (same & set(found)) else 1)
PY
then
    if grep -q 'string key collision, dropped' "$TMP/clash.err"; then
        pass "literals whose hashes collide keep their rows unless their lengths match too, and the drop is reported"
    else fail "a collision was not reported" "$(cat "$TMP/clash.err")"; fi
else fail "colliding keys were handled wrongly" "$(tail -3 "$TMP/clash.err")"; fi

# The release sources and the package URL are kept in the base and the purl reaches the result.
sed 's|^\(alpha,[^,]*,[^,]*\)$|\1,https://example.org/alpha.tar.gz,pkg:generic/alpha|' "$TMP/kb.csv" > "$TMP/kb-purl.csv"
mkdir -p "$TMP/kb-purl"
python3 "$LIB/binarykb.py" build --kb "$TMP/kb-purl.csv" --bg "$TMP/bg" --release test-purl --out "$TMP/kb-purl/kb.sqlite3" 2>/dev/null
pout="$(FW_BINKB_NONELF=true python3 "$LIB/identify-binary-kb.py" "$TMP/root-release-1.1" "$TMP/kb-purl/kb.sqlite3" 2>/dev/null)"
srcs="$(python3 -c 'import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);print(c.execute("select count(*), sum(url != \"\") from src").fetchone())' "$TMP/kb-purl/kb.sqlite3")"
if [ "$(jq -r '.[] | select(.name == "alpha") | .purl' <<<"$pout")" = "pkg:generic/alpha@1.1" ] \
   && [ "$(jq -r '.[] | select(.name == "alpha") | .properties[] | select(.name == "bomlens:purlSource") | .value' <<<"$pout")" = "binary-kb" ] \
   && [ "$(python3 "$LIB/binarykb.py" info "$TMP/kb-purl/kb.sqlite3" | jq -c .purls)" = '{"alpha":"pkg:generic/alpha"}' ] && [ "$srcs" = "(5, 3)" ]; then
    pass "the base keeps each release's tarball hash and URL, and the purl reaches the result with the version"
else fail "sources or purl are wrong" "$srcs $pout"; fi
# A purl the result could not append a version to is refused, and so is a purl in the URL's place.
bad_ok=true
for bad in 'pkg:generic/alpha@1.0' 'pkg:generic/alpha?arch=x86' 'pkg:generic/alpha#src' 'pkg:generic/alpha/'; do
    sed "s|pkg:generic/alpha\$|$bad|" "$TMP/kb-purl.csv" > "$TMP/kb-badpurl.csv"
    if python3 "$LIB/binarykb.py" build --kb "$TMP/kb-badpurl.csv" --release bad --out "$TMP/kb-bad.sqlite3" 2>"$TMP/bad.err" \
       || ! grep -q "must be a package URL without a version, qualifiers or subpath: $bad" "$TMP/bad.err"; then bad_ok=false; fi
done
sed 's|^\(alpha,[^,]*,[^,]*\),.*$|\1,pkg:generic/alpha|' "$TMP/kb-purl.csv" > "$TMP/kb-purl4.csv"
python3 "$LIB/binarykb.py" build --kb "$TMP/kb-purl4.csv" --release bad --out "$TMP/kb-bad4.sqlite3" 2>"$TMP/bad4.err" && bad_ok=false
grep -q 'the fourth field is the tarball URL; give the purl as the fifth' "$TMP/bad4.err" || bad_ok=false
if $bad_ok; then pass "a purl with a version, qualifiers, a subpath or a trailing slash, or one in the URL's field, is refused with the reason"
else fail "a bad purl was accepted or refused without the reason" "$(cat "$TMP/bad.err" "$TMP/bad4.err")"; fi
# Lines that are wrong in other ways are refused with what is wrong, and a missing tarball is named.
T11="$TMP/src/alpha-1.1.tar.gz"
lines_ok=true
while IFS='|' read -r line want; do
    printf '%s\n' "$line" > "$TMP/kb-line.csv"
    if python3 "$LIB/binarykb.py" build --kb "$TMP/kb-line.csv" --release l --out "$TMP/kb-line.sqlite3" 2>"$TMP/line.err" \
       || ! grep -qF "kb-line.csv:1: $want" "$TMP/line.err" || grep -q Traceback "$TMP/line.err"; then
        lines_ok=false; echo "        [$line] $(cat "$TMP/line.err")"
    fi
done <<EOF2
alpha,1.1,$T11,|the line ends with an empty field
alpha,1.1,$T11,pkg:generic/alpha,|the line ends with an empty field
alpha,1.1,$T11,,|the line ends with an empty field
alpha,1.1,$T11,pkg:generic/a,pkg:generic/alpha|two purls
alpha,1.1|expected component,version,tarball[,url[,purl]]
alpha,1.1,$TMP/none.tar.gz|tarball not found: $TMP/none.tar.gz
alpha,1.1,$TMP/none.tar.gz,https://example.org/a.tgz,pkg:generic/alpha|tarball not found: $TMP/none.tar.gz
EOF2
for line in "alpha,1.1,$T11,FILE://localhost/mirror/alpha-1.1.tar.gz" "alpha,1.1,$T11,Ftp://example.org/a.tgz,pkg:generic/alpha"; do
    printf '%s\n' "$line" > "$TMP/kb-line.csv"
    python3 "$LIB/binarykb.py" build --kb "$TMP/kb-line.csv" --release l --out "$TMP/kb-line.sqlite3" 2>"$TMP/line.err" || { lines_ok=false; echo "        [$line] $(cat "$TMP/line.err")"; }
done
if $lines_ok && [ "$(python3 -c 'import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute("select url from src").fetchone()[0])' "$TMP/kb-line.sqlite3")" = "Ftp://example.org/a.tgz" ]; then
    pass "a URL of any scheme in any case is read as the URL; empty trailing fields, two purls, short lines and a missing tarball are refused with the reason"
else fail "a malformed kb.csv line was accepted or refused without the reason"; fi
# A tarball path with a comma reads as it did before the optional fields existed.
mkdir -p "$TMP/com,ma"; cp "$TMP/src/alpha-1.1.tar.gz" "$TMP/com,ma/"
printf 'alpha,1.1,%s\n' "$TMP/com,ma/alpha-1.1.tar.gz" > "$TMP/kb-comma.csv"
printf 'alpha,1.1,%s,https://example.org/a.tar.gz,pkg:generic/alpha\n' "$TMP/com,ma/alpha-1.1.tar.gz" > "$TMP/kb-comma2.csv"
if python3 "$LIB/binarykb.py" build --kb "$TMP/kb-comma.csv" --release c1 --out "$TMP/kb-comma/kb.sqlite3" 2>/dev/null \
   && python3 "$LIB/binarykb.py" build --kb "$TMP/kb-comma2.csv" --release c2 --out "$TMP/kb-comma2/kb.sqlite3" 2>/dev/null \
   && [ "$(python3 "$LIB/binarykb.py" info "$TMP/kb-comma2/kb.sqlite3" | jq -c .purls)" = '{"alpha":"pkg:generic/alpha"}' ]; then
    pass "a tarball path with a comma is read, with and without the URL and purl after it"
else fail "a tarball path with a comma was misread"; fi
# The version in the purl is encoded as container-membership.py encodes it.
if python3 - "$LIB" <<'PY'
import importlib.util, sys
sys.path.insert(0, sys.argv[1])
import binarykb
spec = importlib.util.spec_from_file_location('cm', sys.argv[1] + '/container-membership.py')
cm = importlib.util.module_from_spec(spec); spec.loader.exec_module(cm)
v = '1:2.3+dfsg~1'
want = cm.deb_purl('x', v, ('debian', '12'), '', '').split('@')[1].split('?')[0]
sys.exit(0 if binarykb.purl_version(v) == want == '1%3A2.3%2Bdfsg~1' else 1)
PY
then pass "a version in a base purl is encoded the way container purls encode it"
else fail "the purl version encoding differs from container-membership.py"; fi

# The merge: a base record fills only what the others lack.
# Next to a distribution record with a purl and a CPE, it gives up its purl and its purlSource, so the
# merged component is not offered to the CPE index as a purl BomLens wrote.
echo '[{"bom-ref":"pkg:deb/debian/zlib1g@1.2.11","name":"zlib","version":"1.2.11","type":"library","purl":"pkg:deb/debian/zlib1g@1.2.11","cpe":"cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*"}]' > "$TMP/m-a2.json"
echo '[{"bom-ref":"binary-kb:zlib@1.2.11","name":"zlib","version":"1.2.11","type":"library","purl":"pkg:generic/zlib@1.2.11","properties":[{"name":"bomlens:identifiedBy","value":"binary-kb"},{"name":"bomlens:purlSource","value":"binary-kb"}]}]' > "$TMP/m-g2.json"
mout="$(jq -n --slurpfile a "$TMP/m-a2.json" --slurpfile b "$TMP/m-e.json" --slurpfile c "$TMP/m-e.json" --slurpfile d "$TMP/m-e.json" \
    --slurpfile e "$TMP/m-e.json" --slurpfile f "$TMP/m-e.json" --slurpfile g "$TMP/m-g2.json" -f "$TMP/merge.jq" 2>&1)"
cand="$(jq -r "$(cat "$LIB/vuln-coverage.jq") .[] | vc_cpe_index_candidate" <<<"$mout" 2>&1)"
if [ "$(jq -r 'length' <<<"$mout")" = "1" ] && [ "$(jq -r '.[0].purl' <<<"$mout")" = "pkg:deb/debian/zlib1g@1.2.11" ] \
   && [ "$(jq -r '.[0]["bom-ref"]' <<<"$mout")" = "pkg:deb/debian/zlib1g@1.2.11" ] \
   && [ "$(jq '[.[0].properties[] | select(.name == "bomlens:purlSource")] | length' <<<"$mout")" = "0" ] && [ "$cand" = "false" ]; then
    pass "next to a distribution record the base record gives up its purl and purlSource, and the CPE index is not asked"
else fail "the base record changed the merged distribution record" "$mout $cand"; fi
# Next to an ELF record with a CPE and no purl it is still not the base: the bom-ref, type and name stay
# the ELF record's, and its purl fills the gap with its purlSource.
echo '[{"bom-ref":"elf:usr/lib/libz.so.1","name":"zlib","version":"1.2.11","type":"application","cpe":"cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*","properties":[{"name":"bomlens:identifiedBy","value":"elf-presence"}]}]' > "$TMP/m-c3.json"
mout="$(jq -n --slurpfile a "$TMP/m-e.json" --slurpfile b "$TMP/m-e.json" --slurpfile c "$TMP/m-c3.json" --slurpfile d "$TMP/m-e.json" \
    --slurpfile e "$TMP/m-e.json" --slurpfile f "$TMP/m-e.json" --slurpfile g "$TMP/m-g2.json" -f "$TMP/merge.jq" 2>&1)"
if [ "$(jq -c '[.[] | [.["bom-ref"], .type, .purl, .cpe != null, ([.properties[] | select(.name == "bomlens:purlSource") | .value] | join(","))]]' <<<"$mout")" \
     = '[["elf:usr/lib/libz.so.1","application","pkg:generic/zlib@1.2.11",true,"binary-kb"]]' ]; then
    pass "next to an ELF record the base record is not the base, and its purl fills the gap"
else fail "the base record became the base of the merge" "$mout"; fi

# The version masks are looked up by hash and length too: with every hash the same, a literal still gets
# the releases of its own length and not those of another literal that shares its hash.
if python3 - "$LIB" "$TMP" <<'PY' 2>/dev/null
import io, os, sys, tarfile
sys.path.insert(0, sys.argv[1])
import binarykb as b
tmp = sys.argv[2] + '/clashv'; os.makedirs(tmp)
b.string_key = lambda s: b'\0' * 8
def tb(v, lits):
    src = ('\n'.join(f'const char *s{i} = "{s}";' for i, s in enumerate(lits)) + '\n').encode()
    with tarfile.open(f'{tmp}/c-{v}.tar.gz', 'w:gz') as tf:
        ti = tarfile.TarInfo(f'c-{v}/c.c'); ti.size = len(src); tf.addfile(ti, io.BytesIO(src))
A, B = 'literal only in the first release', 'a longer literal only in the second release'
tb('1.0', [A]); tb('2.0', [B])
open(f'{tmp}/kb.csv', 'w').write(f'clash,1.0,{tmp}/c-1.0.tar.gz\nclash,2.0,{tmp}/c-2.0.tar.gz\n')
b.main(['build', '--kb', f'{tmp}/kb.csv', '--release', 'clashv', '--out', f'{tmp}/kb.sqlite3'])
kb = b.KnowledgeBase(f'{tmp}/kb.sqlite3')
c = next(i for i, (n, _) in kb.comps.items() if n == 'clash')
m = kb._masks(c, [A.encode(), B.encode()])
sys.exit(0 if m == {A.encode(): 1, B.encode(): 2} else 1)
PY
then pass "version masks of literals whose hashes collide stay with their own literal"
else fail "colliding hashes mixed the version masks"; fi

# A version filled from the component-versions file reaches the base purl too.
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"alpha","purl":"pkg:generic/alpha","properties":[{"name":"bomlens:identifiedBy","value":"binary-kb"},{"name":"bomlens:purlSource","value":"binary-kb"},{"name":"bomlens:evidenceGrade","value":"presence-only"}]}]}' > "$TMP/cv.json"
printf 'name,version\nalpha,1.1+b\n' > "$TMP/cv.csv"
python3 "$LIB/component-versions.py" --no-template "$TMP/cv.json" "$TMP/cvp" "$TMP/cv.csv" >/dev/null 2>&1
if [ "$(jq -r '.components[0] | "\(.version) \(.purl)"' "$TMP/cv.json")" = "1.1+b pkg:generic/alpha@1.1%2Bb" ]; then
    pass "a version filled from the component-versions file is written into the base purl"
else fail "the base purl kept no version after the fill" "$(cat "$TMP/cv.json")"; fi
printf '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"alpha","purl":"pkg:generic/alpha@9.9","properties":[{"name":"bomlens:identifiedBy","value":"binary-kb"},{"name":"bomlens:purlSource","value":"binary-kb"}]}]}' > "$TMP/cv2.json"
python3 "$LIB/component-versions.py" --no-template "$TMP/cv2.json" "$TMP/cvp2" "$TMP/cv.csv" >/dev/null 2>&1
if [ "$(jq -r '.components[0] | "\(.version) \(.purl)"' "$TMP/cv2.json")" = "1.1+b pkg:generic/alpha@9.9" ]; then
    pass "a base purl that already has a version is left as it is by the fill"
else fail "the fill rewrote a base purl that had a version" "$(cat "$TMP/cv2.json")"; fi
# A purl stored in a base that the result could not carry is left out with one warning.
cp "$TMP/kb-purl/kb.sqlite3" "$TMP/kb-badstored.sqlite3"
python3 -c 'import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute("update comp set purl = ? where name = ?", ("pkg:generic/alpha?x=1", "alpha"));c.commit()' "$TMP/kb-badstored.sqlite3"
bout="$(FW_BINKB_NONELF=true python3 "$LIB/identify-binary-kb.py" "$TMP/root-release-1.1" "$TMP/kb-badstored.sqlite3" 2>"$TMP/badstored.err")"
if [ "$(jq -r '.[] | select(.name == "alpha") | .purl // "none"' <<<"$bout")" = "none" ] \
   && [ "$(grep -c 'WARN: the base gives alpha a purl that is not a package URL without a version; left out: pkg:generic/alpha?x=1' "$TMP/badstored.err")" = "1" ]; then
    pass "a malformed purl stored in a base is left out with one warning"
else fail "a malformed stored purl was used or not warned about" "$(cat "$TMP/badstored.err")"; fi
echo
echo "binary knowledge base: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
