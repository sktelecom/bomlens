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
if [ "$(jq -r '.[] | select(.name == "alpha") | .version' <<<"$out")" = "1.2" ] \
   && [ "$(prop "$out" bomlens:versionMayBeNewer)" = "true" ]; then
    pass "the newest release the base has is marked bomlens:versionMayBeNewer"
else fail "the newest release was not marked" "$out"; fi

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
    pass "scan-firmware.sh runs the pass and merges its result last, so it never becomes the base record"
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

echo
echo "binary knowledge base: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
