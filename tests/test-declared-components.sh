#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-declared-components.sh: No-Docker checks for the declaration file of a
# source scan (--components, or sbom-declared.cdx.json at the scan target
# root) and docker/lib/apply-declared-components.py, which adds the components
# it lists to the SBOM.
#
# The fixture (tests/fixtures/declared-components) is a C project with two
# programs it builds (declared first-party, with their build outputs in
# bomlens:artifact), a chip vendor's HAL declared third-party with no file,
# and zlib from conan.lock, which the scan finds itself (stage1-bom.json is
# what that scan writes). The build outputs are written here with the first
# bytes of an ELF and a PE executable, so no compiler is needed.
#
# Checked: the declared components reach the SBOM with their hashes, file name
# and executable/archive properties; bomlens:origin is kept; a first-party
# component with no version takes the product's; the graph reaches every
# component from the product; and each refusal rule stops the run with the
# file, the component and the reason. Then the same through entrypoint.sh
# (POSTPROCESS, as test-engine-contract.sh runs it), and the CLI's mount of
# --components files. Last, components a Yocto build declares by recipe
# (bomlens:yocto-recipe, tests/fixtures/yocto-declared): read from SPDX 3.0 in
# the 5.x and 6.x shapes and from the manifests, each refusal, and the same
# through entrypoint.sh (ANALYZE) with the BSI and submission profiles. Needs
# bash 4+, jq, python3.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT_DIR/docker/lib"
FIX="$ROOT_DIR/tests/fixtures/declared-components"
APPLY="$LIB/apply-declared-components.py"
ENTRY="$ROOT_DIR/docker/entrypoint.sh"
SCRIPT="$ROOT_DIR/scripts/scan-sbom.sh"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

command -v jq >/dev/null 2>&1 || { echo "[ERROR] jq is required"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] python3 is required"; exit 1; }
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "[ERROR] bash 4 or later is required (this is $BASH_VERSION)"; exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The first bytes of an ELF64 executable (e_type 2) and of a PE executable.
write_elf() {  # <path> [e_type byte, octal]
    # shellcheck disable=SC2059 # the e_type byte is an octal escape in the format
    printf "\\177ELF\\002\\001\\001\\000\\000\\000\\000\\000\\000\\000\\000\\000\\${2:-002}\\000\\076\\000" > "$1"
    head -c 46 /dev/zero >> "$1"
}
write_pe() {  # <path>
    { printf 'MZ'; head -c 58 /dev/zero; printf '\100\000\000\000PE\000\000'; head -c 60 /dev/zero; } > "$1"
}

# A copy of the fixture project with its two programs "built".
new_project() {  # <name>
    local d="$WORK/$1"
    mkdir -p "$d"
    cp -R "$FIX/project/." "$d/"
    mkdir -p "$d/out/bin"
    write_elf "$d/out/bin/media-daemon"
    write_pe "$d/out/bin/media-ctl.exe"
    printf '%s' "$d"
}

# The stage 1 SBOM after stamp-metadata: the product is MediaSuite 3.1.0.
new_bom() {  # <name>
    jq '.metadata.component.name = "MediaSuite" | .metadata.component.version = "3.1.0"' \
        "$FIX/stage1-bom.json" > "$WORK/$1.bom.json"
    printf '%s' "$WORK/$1.bom.json"
}

# apply <bom> <root> <file>...: runs the step with the labels the CLI would
# pass (the file names), output in <bom>.log; prints the exit code.
apply() {
    local bom="$1" root="$2" labels="" f rc=0
    shift 2
    for f in "$@"; do labels="${labels:+$labels
}$(basename "$f")"; done
    DECLARED_COMPONENTS_LABELS="$labels" python3 -I "$APPLY" "$bom" "$root" "$@" > "$bom.log" 2>&1 || rc=$?
    printf '%s' "$rc"
}

# Components (nested ones included) the dependency graph does not reach from
# metadata.component. Nested file components count as reached through the
# component that holds them.
UNREACHED='
  (.metadata.component["bom-ref"]) as $root
  | (reduce (.dependencies // [])[] as $d ({}; .[$d.ref] = ($d.dependsOn // []))) as $g
  | def walk($seen; $todo):
      if ($todo | length) == 0 then $seen
      elif ($seen | index([$todo[0]])) then walk($seen; $todo[1:])
      else walk($seen + [$todo[0]]; $todo[1:] + ($g[$todo[0]] // [])) end;
    walk([]; [$root]) as $reach
  | [ .components[] | select((.["bom-ref"]) as $r | ($reach | index([$r])) | not) | .name ]'

comp() {  # <bom> <name>: the component, compact
    jq -c --arg n "$2" '[.components[] | select(.name == $n)] | first' "$1"
}
prop() {  # <component json> <property name>
    printf '%s' "$1" | jq -r --arg n "$2" '[.properties[]? | select(.name == $n) | .value] | join(",")'
}

echo "== the declared components are added with what their build outputs say =="
P="$(new_project ok)"
B="$(new_bom ok)"
rc="$(apply "$B" "$P" "$P/sbom-declared.cdx.json")"
[ "$rc" = 0 ] && pass "the declaration is applied" || fail "exit $rc" "$(cat "$B.log")"
D="$(comp "$B" media-daemon)"
C="$(comp "$B" media-ctl)"
H="$(comp "$B" vendor-hal)"
elf512="$(python3 -I -c 'import hashlib,sys; print(hashlib.sha512(open(sys.argv[1],"rb").read()).hexdigest())' "$P/out/bin/media-daemon")"
elf256="$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$P/out/bin/media-daemon")"
[ "$(printf '%s' "$D" | jq -r '[.hashes[] | select(.alg == "SHA-512") | .content] | join(",")')" = "$elf512" ] \
  && [ "$(printf '%s' "$D" | jq -r '[.hashes[] | select(.alg == "SHA-256") | .content] | join(",")')" = "$elf256" ] \
    && pass "the SHA-512 and SHA-256 of out/bin/media-daemon are on its component" \
    || fail "media-daemon hashes" "$D"
[ "$(prop "$D" bsi:component:filename)" = "media-daemon" ] && [ "$(prop "$C" bsi:component:filename)" = "media-ctl.exe" ] \
    && pass "bsi:component:filename is the file name without the path" \
    || fail "file names: $(prop "$D" bsi:component:filename) $(prop "$C" bsi:component:filename)"
[ "$(prop "$D" bsi:component:executable)/$(prop "$D" bsi:component:archive)/$(prop "$D" bsi:component:structured)" = "executable/no archive/unstructured" ] \
  && [ "$(prop "$C" bsi:component:executable)/$(prop "$C" bsi:component:archive)/$(prop "$C" bsi:component:structured)" = "executable/no archive/unstructured" ] \
    && pass "an ELF and a PE executable are executable, not an archive, unstructured" \
    || fail "executable properties" "$D $C"
[ "$(prop "$D" bomlens:declared)" = "true" ] && [ "$(prop "$(comp "$B" zlib)" bomlens:declared)" = "" ] \
    && pass "a declared component carries bomlens:declared = true; a scanned one does not" || fail "declared mark" "$D"
[ "$(prop "$D" bomlens:origin) $(prop "$C" bomlens:origin) $(prop "$H" bomlens:origin)" = "first-party first-party third-party" ] \
    && pass "bomlens:origin is kept as declared" || fail "origins" "$D $H"
[ "$(printf '%s' "$D" | jq -r .version) $(printf '%s' "$C" | jq -r .version)" = "3.1.0 2.0.1" ] \
    && pass "a first-party component with no version takes the product's; a declared one is kept" \
    || fail "versions" "$D $C"
[ "$(printf '%s' "$H" | jq -c '[.version, (.hashes // [] | length), (.properties | length), .supplier.name, .licenses[0].license.id]')" \
    = '["4.2.0",0,2,"Example Chip Vendor","BSD-3-Clause"]' ] \
    && pass "the third-party component with no file is written as declared, with no hashes" \
    || fail "vendor-hal" "$H"
[ "$(printf '%s' "$D" | jq -c '[.supplier.name, .licenses[0].license.name, .type]')" = '["Example Corp","Proprietary","application"]' ] \
    && pass "supplier, licence and type come from the declaration" || fail "declared fields" "$D"
[ "$(jq -r '[.components[] | select(.purl == "pkg:conan/zlib@1.3.1")] | length' "$B")" = 1 ] \
    && pass "the component the scan found (zlib from conan.lock) stays" || fail "zlib missing"
[ "$(jq -c "$UNREACHED" "$B")" = "[]" ] \
    && pass "the dependency graph reaches every component from the product" \
    || fail "not reached from the product: $(jq -c "$UNREACHED" "$B")"
[ "$(jq -c '[.dependencies[] | select(.ref == "pkg:generic/project@latest") | .dependsOn[]] | sort' "$B")" \
    = '["declared:media-ctl@2.0.1","declared:media-daemon@3.1.0","declared:vendor-hal@4.2.0","pkg:conan/zlib@1.3.1"]' ] \
    && pass "with no dependencies in the file, the product depends on each declared component" \
    || fail "product edges" "$(jq -c '.dependencies' "$B")"
grep -q 'added 3 declared component(s) (2 first-party, 1 third-party) from 1 file(s)' "$B.log" \
    && pass "the step says what it added" || fail "summary line" "$(cat "$B.log")"

echo "== applying the same file again gives the same SBOM =="
cp "$B" "$WORK/once.json"
rc="$(apply "$B" "$P" "$P/sbom-declared.cdx.json")"
[ "$rc" = 0 ] && cmp -s "$B" "$WORK/once.json" \
    && pass "a second run replaces what the first added, byte for byte" \
    || fail "second run: exit $rc" "$(diff "$WORK/once.json" "$B" | head -20)"

echo "== a component of the input that carries the mark in any form is removed =="
# Whatever value or count: after the step, every marked component is one it
# wrote, which the conformance check's first-party exemption relies on.
B="$(new_bom mark)"
jq '.components += [
      {"type": "library", "name": "twice", "version": "1", "properties": [{"name": "bomlens:origin", "value": "first-party"},
         {"name": "bomlens:declared", "value": "true"}, {"name": "bomlens:declared", "value": "true"}]},
      {"type": "library", "name": "false-mark", "version": "1", "properties": [{"name": "bomlens:declared", "value": "false"}]},
      {"type": "library", "name": "two-origins", "version": "1", "properties": [{"name": "bomlens:origin", "value": "first-party"},
         {"name": "bomlens:origin", "value": "first-party"}, {"name": "bomlens:declared", "value": "true"}]}]' "$B" > "$B.tmp" && mv "$B.tmp" "$B"
rc="$(apply "$B" "$P" "$P/sbom-declared.cdx.json")"
[ "$rc" = 0 ] && [ "$(jq -c '[.components[].name] | sort' "$B")" = '["media-ctl","media-daemon","vendor-hal","zlib"]' ] \
    && pass "a duplicated, false or doubly-originated mark is removed with its component" \
    || fail "marked input: exit $rc" "$(jq -c '[.components[].name]' "$B")"

echo "== a component with several build outputs =="
P="$(new_project multi)"
B="$(new_bom multi)"
mkdir -p "$P/out/pkg"
write_elf "$P/out/bin/media-plugin.so" 003
( cd "$P/out" && tar cf pkg/media-plugins.tar bin/media-plugin.so )
gzip -c "$P/out/pkg/media-plugins.tar" > "$P/out/pkg/media-plugins.tar.gz"
cat > "$WORK/multi.cdx.json" <<'EOF'
{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
  {"type": "library", "name": "media-plugins", "supplier": {"name": "Example Corp"},
   "properties": [{"name": "bomlens:origin", "value": "first-party"},
                  {"name": "bomlens:artifact", "value": "out/bin/media-plugin.so"},
                  {"name": "bomlens:artifact", "value": "./out/pkg/media-plugins.tar.gz"}]}]}
EOF
rc="$(apply "$B" "$P" "$WORK/multi.cdx.json")"
M="$(comp "$B" media-plugins)"
[ "$rc" = 0 ] && [ "$(printf '%s' "$M" | jq -c '[(.hashes // [] | length), [.properties[].name], [.components[].name]]')" \
    = '[0,["bomlens:origin","bomlens:artifact","bomlens:artifact","bomlens:declared"],["out/bin/media-plugin.so","out/pkg/media-plugins.tar.gz"]]' ] \
    && pass "each output is a nested file component; the declared one carries no hashes of its own" \
    || fail "multi-artifact: exit $rc" "$M $(cat "$B.log")"
[ "$(printf '%s' "$M" | jq -c '[.components[] | [.type, .version, .supplier.name, ([.hashes[].alg] | join("+")),
        ([.properties[] | select(.name | startswith("bsi:")) | .value] | join("|")), .["bom-ref"]]]')" \
    = '[["file","3.1.0","Example Corp","SHA-512+SHA-256","media-plugin.so|executable|no archive|unstructured","declared:media-plugins@3.1.0#out/bin/media-plugin.so"],["file","3.1.0","Example Corp","SHA-512+SHA-256","media-plugins.tar.gz|non-executable|archive|structured","declared:media-plugins@3.1.0#out/pkg/media-plugins.tar.gz"]]' ] \
    && pass "a nested file has its own hashes, file name and properties (a shared object is executable, a .tar.gz a structured archive)" \
    || fail "nested files" "$M"

echo "== the type of a file is read from its first bytes =="
P="$(new_project kinds)"
K="$P/k"; mkdir -p "$K"
printf 'PK\003\004rest' > "$K/a.zip"
printf '\375\067\172\130\132\000rest' > "$K/a.xz"
( cd "$P/out" && tar cf "$K/a.tar" bin )
printf '!<arch>\nrest' > "$K/libx.a"
{ printf '\317\372\355\376'; head -c 28 /dev/zero; } > "$K/macho"
{ printf '\312\376\272\276\000\000\000\002'; head -c 24 /dev/zero; } > "$K/universal"
{ printf '\312\376\272\276\000\000\000\064'; head -c 24 /dev/zero; } > "$K/Main.class"
write_elf "$K/object.o" 001
printf 'just text\n' > "$K/notes.txt"
gzip -c "$K/notes.txt" > "$K/notes.txt.gz"
gzip -c "$K/a.tar" > "$K/a.tar.gz"
python3 -I -c 'import bz2,lzma,sys; d=open(sys.argv[1],"rb").read(); open(sys.argv[2],"wb").write(lzma.compress(d)); open(sys.argv[3],"wb").write(bz2.compress(d))' \
    "$K/a.tar" "$K/a.tar.xz" "$K/a.tar.bz2"
{ printf '070701'; head -c 120 /dev/zero; } > "$K/a.cpio"
{ head -c 32769 /dev/zero; printf 'CD001'; head -c 100 /dev/zero; } > "$K/a.iso"
head -c 4096 /dev/zero > "$K/fw.bin"
# A PE header past the first 512 bytes, and an MZ file with no PE header.
{ printf 'MZ'; head -c 58 /dev/zero; printf '\130\002\000\000'; head -c 536 /dev/zero; printf 'PE\000\000'; head -c 32 /dev/zero; } > "$K/far.exe"
{ printf 'MZ'; head -c 58 /dev/zero; printf '\100\000\000\000NOPE'; head -c 60 /dev/zero; } > "$K/dos.com"
{
    printf '{"bomFormat": "CycloneDX", "components": ['
    sep=""
    for f in a.zip a.xz a.tar libx.a macho universal Main.class object.o notes.txt notes.txt.gz a.tar.gz a.tar.xz a.tar.bz2 a.cpio a.iso fw.bin far.exe dos.com; do
        printf '%s{"type": "file", "name": "%s", "properties": [{"name": "bomlens:origin", "value": "first-party"}, {"name": "bomlens:artifact", "value": "k/%s"}]}' "$sep" "$f" "$f"
        sep=","
    done
    printf ']}'
} > "$WORK/kinds.cdx.json"
B="$(new_bom kinds)"
rc="$(apply "$B" "$P" "$WORK/kinds.cdx.json")"
got="$(jq -r '[.components[] | select(.properties[]?.name == "bsi:component:filename")
              | "\(.name)=\([.properties[] | select(.name | test("^bsi:component:(executable|archive|structured)$")) | .value] | join("/"))"] | join(" ")' "$B")"
want="a.zip=non-executable/archive/structured a.xz=non-executable/archive/unstructured a.tar=non-executable/archive/structured"
want="$want libx.a=non-executable/archive/structured macho=executable/no archive/unstructured universal=executable/no archive/unstructured"
want="$want Main.class=non-executable/no archive/unstructured object.o=non-executable/no archive/unstructured notes.txt=non-executable/no archive/unstructured"
want="$want notes.txt.gz=non-executable/archive/unstructured a.tar.gz=non-executable/archive/structured a.tar.xz=non-executable/archive/structured"
want="$want a.tar.bz2=non-executable/archive/structured a.cpio=non-executable/archive/structured a.iso=non-executable/archive/structured"
want="$want fw.bin=non-executable/no archive/unstructured far.exe=executable/no archive/unstructured dos.com=non-executable/no archive/unstructured"
[ "$rc" = 0 ] && [ "$got" = "$want" ] \
    && pass "file kinds: archives with an index (zip, tar, also compressed, ar, cpio, ISO) are structured; a single compressed stream, executables, firmware images and text are not" \
    || fail "file kinds: exit $rc" "$(printf '%s\n' "$got" | tr ' ' '\n' | diff - <(printf '%s\n' "$want" | tr ' ' '\n'))"
[ "$(jq -r '[.components[] | select(.name == "far.exe" or .name == "dos.com") | .name] | join(" ")' "$B")" = "far.exe dos.com" ] \
    && pass "a PE header is looked for where e_lfanew points, also past the first bytes read" || fail "PE components missing"

echo "== a compressed tar is recognized at full size =="
# A bzip2 block of data that does not compress is close to 1 MB, and nothing
# comes out of it before it is read whole.
P="$(new_project bigkinds)"
python3 -I -c '
import bz2, gzip, io, lzma, os, sys, tarfile
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as t:
    data = os.urandom(1536 * 1024)
    info = tarfile.TarInfo("payload.bin"); info.size = len(data)
    t.addfile(info, io.BytesIO(data))
raw = buf.getvalue()
d = sys.argv[1]
open(d + "/big.tar.bz2", "wb").write(bz2.compress(raw))
open(d + "/big.tar.gz", "wb").write(gzip.compress(raw))
open(d + "/big.tar.xz", "wb").write(lzma.compress(raw))
open(d + "/big.bz2", "wb").write(bz2.compress(os.urandom(1536 * 1024)))
' "$P"
{
    printf '{"bomFormat": "CycloneDX", "components": ['
    sep=""
    for f in big.tar.bz2 big.tar.gz big.tar.xz big.bz2; do
        printf '%s{"type": "file", "name": "%s", "properties": [{"name": "bomlens:origin", "value": "first-party"}, {"name": "bomlens:artifact", "value": "%s"}]}' "$sep" "$f" "$f"
        sep=","
    done
    printf ']}'
} > "$WORK/bigkinds.cdx.json"
B="$(new_bom bigkinds)"
rc="$(apply "$B" "$P" "$WORK/bigkinds.cdx.json")"
got="$(jq -r '[.components[] | select(.properties[]?.name == "bsi:component:filename")
              | "\(.name)=\([.properties[] | select(.name == "bsi:component:structured") | .value] | join(""))"] | join(" ")' "$B")"
[ "$rc" = 0 ] && [ "$got" = "big.tar.bz2=structured big.tar.gz=structured big.tar.xz=structured big.bz2=unstructured" ] \
  && [ "$(wc -c < "$P/big.tar.bz2" | tr -d ' ')" -gt 1048576 ] \
    && pass "a tar of over 1 MB of random data is structured in bzip2, gzip and xz; a bzip2 stream that is not a tar is not" \
    || fail "big compressed tars: exit $rc" "$got"

echo "== a kind the declaration gives itself wins over the one read from the file =="
P="$(new_project override)"
B="$(new_bom override)"
jq '.components[0].properties += [{"name": "bsi:component:structured", "value": "structured"},
                                  {"name": "bsi:component:archive", "value": "archive"}]' \
    "$P/sbom-declared.cdx.json" > "$WORK/override.cdx.json"
rc="$(apply "$B" "$P" "$WORK/override.cdx.json")"
D="$(comp "$B" media-daemon)"
[ "$rc" = 0 ] && [ "$(prop "$D" bsi:component:executable)/$(prop "$D" bsi:component:archive)/$(prop "$D" bsi:component:structured)" = "executable/archive/structured" ] \
    && pass "declared archive and structured values are kept; executable is read from the file" \
    || fail "override: exit $rc" "$D $(cat "$B.log")"

echo "== dependencies written in the declaration file are used =="
P="$(new_project deps)"
B="$(new_bom deps)"
cat > "$WORK/deps.cdx.json" <<'EOF'
{"bomFormat": "CycloneDX", "specVersion": "1.6",
 "components": [
  {"type": "application", "name": "gateway", "bom-ref": "gw",
   "properties": [{"name": "bomlens:origin", "value": "first-party"}]},
  {"type": "library", "name": "rtos", "version": "10.6.2", "bom-ref": "rtos",
   "properties": [{"name": "bomlens:origin", "value": "third-party"}]},
  {"type": "library", "name": "ring-a", "bom-ref": "ra",
   "properties": [{"name": "bomlens:origin", "value": "first-party"}]},
  {"type": "library", "name": "ring-b", "bom-ref": "rb",
   "properties": [{"name": "bomlens:origin", "value": "first-party"}]}],
 "dependencies": [
  {"ref": "gw", "dependsOn": ["rtos", "pkg:conan/zlib@1.3.1"]},
  {"ref": "ra", "dependsOn": ["rb"]},
  {"ref": "rb", "dependsOn": ["ra"]}]}
EOF
rc="$(apply "$B" "$P" "$WORK/deps.cdx.json")"
[ "$rc" = 0 ] && [ "$(jq -c '[.dependencies[] | select(.ref == "pkg:generic/project@latest") | .dependsOn[]]' "$B")" = '["pkg:conan/zlib@1.3.1","gw","ra"]' ] \
  && [ "$(jq -c '[.dependencies[] | select(.ref == "gw") | .dependsOn[]]' "$B")" = '["rtos","pkg:conan/zlib@1.3.1"]' ] \
    && pass "the declared edges are kept; the product depends on what nothing in the file depends on, and on one member of a cycle" \
    || fail "declared dependencies: exit $rc" "$(jq -c .dependencies "$B") $(cat "$B.log")"
[ "$(jq -c "$UNREACHED" "$B")" = "[]" ] && pass "every component is reached from the product" \
    || fail "not reached: $(jq -c "$UNREACHED" "$B")"

echo "== each refusal names the file, the component and the reason =="
# refused <case> <expected message> <declaration file>...: exit 3, the message
# in the log, and the SBOM untouched.
refused() {
    local name="$1" want="$2" rc
    shift 2
    cp "$BASE" "$WORK/$name.bom.json"
    rc="$(apply "$WORK/$name.bom.json" "$P" "$@")"
    if [ "$rc" = 3 ] && grep -qF -- "$want" "$WORK/$name.bom.json.log" && cmp -s "$BASE" "$WORK/$name.bom.json"; then
        pass "$name"
    else
        fail "$name: exit $rc" "$(cat "$WORK/$name.bom.json.log")"
    fi
}
P="$(new_project refuse)"
BASE="$(new_bom refuse)"
DECL="$P/sbom-declared.cdx.json"
variant() {  # <name> <jq filter>: the fixture declaration changed by the filter
    mkdir -p "$WORK/$1"
    jq "$2" "$DECL" > "$WORK/$1/sbom-declared.cdx.json"
    printf '%s' "$WORK/$1/sbom-declared.cdx.json"
}
art='.components[0].properties[1].value'
refused "a bomlens:artifact that was not built" \
    "sbom-declared.cdx.json: component 'media-daemon': bomlens:artifact 'out/bin/not-built' does not exist in the scan target" \
    "$(variant v1 "$art = \"out/bin/not-built\"")"
refused "a path with '..'" \
    "sbom-declared.cdx.json: component 'media-daemon': bomlens:artifact 'out/../../etc/passwd' contains '..'" \
    "$(variant v2 "$art = \"out/../../etc/passwd\"")"
refused "an absolute path" \
    "sbom-declared.cdx.json: component 'media-daemon': bomlens:artifact '/etc/passwd' is an absolute path" \
    "$(variant v3 "$art = \"/etc/passwd\"")"
refused "a Windows drive path" \
    "bomlens:artifact 'C:/build/media-daemon' is an absolute path" \
    "$(variant v3w "$art = \"C:/build/media-daemon\"")"
printf 'outside the project\n' > "$WORK/outside.bin"
ln -s "$WORK/outside.bin" "$P/out/bin/linked-out"
refused "a symbolic link to a file outside the scan target" \
    "sbom-declared.cdx.json: component 'media-daemon': bomlens:artifact 'out/bin/linked-out' leads outside the scan target through a symbolic link" \
    "$(variant v4 "$art = \"out/bin/linked-out\"")"
mkdir -p "$WORK/outside-dir"; write_elf "$WORK/outside-dir/tool"
ln -s "$WORK/outside-dir" "$P/out/linked-dir"
refused "a path through a linked folder outside the scan target" \
    "bomlens:artifact 'out/linked-dir/tool' leads outside the scan target through a symbolic link" \
    "$(variant v4d "$art = \"out/linked-dir/tool\"")"
refused "a component with no bomlens:origin" \
    "sbom-declared.cdx.json: component #3 'vendor-hal': has no bomlens:origin property" \
    "$(variant v5 '.components[2].properties = []')"
refused "a bomlens:origin that is neither first-party nor third-party" \
    "sbom-declared.cdx.json: component #2 'media-ctl': bomlens:origin is 'vendor'; it must be first-party or third-party" \
    "$(variant v6 '.components[1].properties[0].value = "vendor"')"
refused "a third-party component with no version" \
    "sbom-declared.cdx.json: component #3 'vendor-hal': is third-party and has no version" \
    "$(variant v7 'del(.components[2].version)')"
mkdir -p "$WORK/v8"
jq '{bomFormat, specVersion, components: [.components[2]]}' "$DECL" > "$WORK/v8/modules.cdx.json"
refused "the same name and version in two files" \
    "vendor-hal@4.2.0 is declared twice (sbom-declared.cdx.json and modules.cdx.json)" \
    "$DECL" "$WORK/v8/modules.cdx.json"
mkdir -p "$WORK/v9"
printf '{"bomFormat": "CycloneDX", "components": [\n  {"name": "x",\n' > "$WORK/v9/broken.cdx.json"
refused "a file that is not valid JSON" \
    "broken.cdx.json: not valid JSON (line 3" \
    "$WORK/v9/broken.cdx.json"
printf '{"spdxVersion": "SPDX-2.3", "packages": []}\n' > "$WORK/v9/spdx.json"
refused "a JSON file that is not CycloneDX" \
    'spdx.json: not a CycloneDX document (it needs "bomFormat": "CycloneDX")' \
    "$WORK/v9/spdx.json"
printf '{"bomFormat": "CycloneDX", "specVersion": "1.6"}\n' > "$WORK/v9/nocomp.json"
refused "a CycloneDX file with no components array" \
    'nocomp.json: has no "components" array' \
    "$WORK/v9/nocomp.json"
refused "a component type CycloneDX does not define" \
    "component #1 'media-daemon': type 'program' is not a CycloneDX component type" \
    "$(variant v10 '.components[0].type = "program"')"
refused "a bom-ref the scan already uses" \
    "bom-ref 'pkg:conan/zlib@1.3.1' is already used by a component the scan found" \
    "$(variant v11 '.components[2]["bom-ref"] = "pkg:conan/zlib@1.3.1"')"
refused "dependencies that name an unknown component" \
    "dependencies of 'declared:media-ctl@2.0.1' name 'nowhere'" \
    "$(variant v12 '.dependencies = [{"ref": "declared:media-ctl@2.0.1", "dependsOn": ["nowhere"]}]')"
# Every problem is reported in one run, not only the first.
refused "several problems are all reported" \
    "component #3 'vendor-hal': is third-party and has no version" \
    "$(variant v13 "$art = \"/etc/passwd\" | del(.components[2].version)")"
grep -q "is an absolute path" "$WORK/several problems are all reported.bom.json.log" \
    && pass "the first problem is reported with the second" || fail "only one problem reported"

echo "== references stay unique =="
refused "the same build output twice in one component" \
    "component 'media-daemon': lists bomlens:artifact 'out/bin/media-daemon' more than once" \
    "$(variant r1 '.components[0].properties += [{"name": "bomlens:artifact", "value": "./out//bin/media-daemon"}]')"
refused "a file reference that another declared component already uses" \
    "component 'media-daemon': the reference 'md#out/bin/media-ctl.exe' its file out/bin/media-ctl.exe would get is already used" \
    "$(variant r2 '.components[0]["bom-ref"] = "md" | .components[0].properties += [{"name": "bomlens:artifact", "value": "out/bin/media-ctl.exe"}]
                   | .components[1]["bom-ref"] = "md#out/bin/media-ctl.exe"')"
SAVED_BASE="$BASE"
BASE="$WORK/r3.base.json"
jq '.components += [{"type": "file", "name": "x", "bom-ref": "md#out/bin/media-daemon"}]' "$SAVED_BASE" > "$BASE"
refused "a file reference that a scanned component already uses" \
    "the reference 'md#out/bin/media-daemon' its file out/bin/media-daemon would get is already used" \
    "$(variant r3 '.components[0]["bom-ref"] = "md" | .components[0].properties += [{"name": "bomlens:artifact", "value": "out/bin/media-ctl.exe"}]')"
BASE="$SAVED_BASE"

echo "== hashes a declaration gives for a build output are checked against it =="
P="$(new_project givenhash)"
md5="$(python3 -I -c 'import hashlib,sys; print(hashlib.md5(open(sys.argv[1],"rb").read()).hexdigest())' "$P/out/bin/media-daemon")"
sha1="$(python3 -I -c 'import hashlib,sys; print(hashlib.sha1(open(sys.argv[1],"rb").read()).hexdigest())' "$P/out/bin/media-daemon")"
b2="$(python3 -I -c 'import hashlib,sys; print(hashlib.blake2b(open(sys.argv[1],"rb").read(), digest_size=32).hexdigest())' "$P/out/bin/media-daemon")"
jq --arg md5 "$md5" --arg sha1 "$sha1" --arg b2 "$b2" \
    '.components[0].hashes = [{"alg": "MD5", "content": $md5}, {"alg": "SHA-1", "content": ($sha1 | ascii_upcase)}, {"alg": "BLAKE2b-256", "content": $b2}]' \
    "$P/sbom-declared.cdx.json" > "$WORK/givenhash.cdx.json"
B="$(new_bom givenhash)"
rc="$(apply "$B" "$P" "$WORK/givenhash.cdx.json")"
[ "$rc" = 0 ] && [ "$(comp "$B" media-daemon | jq -c '[.hashes[].alg]')" = '["MD5","SHA-1","BLAKE2b-256","SHA-512","SHA-256"]' ] \
    && pass "MD5, SHA-1 (in capitals) and BLAKE2b-256 that match the file are kept with SHA-512 and SHA-256" \
    || fail "matching declared hashes: exit $rc" "$(cat "$B.log")"
P="$(new_project refuse-hash)"
BASE="$(new_bom refuse-hash)"
DECL="$P/sbom-declared.cdx.json"
refused "a declared hash that does not match the file" \
    "component 'media-daemon': the SHA-256 hash it gives does not match" \
    "$(variant h1 '.components[0].hashes = [{"alg": "SHA-256", "content": "0000000000000000000000000000000000000000000000000000000000000000"}]')"
grep -qF "component 'media-daemon': the SHA-256 hash it gives does not match out/bin/media-daemon (the file has " "$WORK/a declared hash that does not match the file.bom.json.log" \
    && pass "the mismatch names the algorithm, the file and the value the file has" || fail "mismatch message" "$(cat "$WORK/a declared hash that does not match the file.bom.json.log")"
refused "a declared hash this step cannot compute" \
    "component 'media-daemon': gives a BLAKE3 hash, which cannot be computed here to check it against out/bin/media-daemon; remove it" \
    "$(variant h2 '.components[0].hashes = [{"alg": "BLAKE3", "content": "0000000000000000000000000000000000000000000000000000000000000000"}]')"
refused "hashes on a component of several files" \
    "component 'media-daemon': gives hashes but has several bomlens:artifact files" \
    "$(variant h3 '.components[0].properties += [{"name": "bomlens:artifact", "value": "out/bin/media-ctl.exe"}]
                   | .components[0].hashes = [{"alg": "MD5", "content": "00000000000000000000000000000000"}]')"
P="$(new_project refuse)"
BASE="$WORK/refuse.bom.json"
DECL="$P/sbom-declared.cdx.json"

echo "== only CycloneDX component fields, in their CycloneDX shape, are taken =="
refused "a field the declaration may not carry" \
    "component #1 'media-daemon': field 'evidence' is not read from a declaration file" \
    "$(variant w1 '.components[0].evidence = {"identity": {"field": "name"}}')"
refused "licenses written as a string" \
    "component #3 'vendor-hal': licenses is not a list of" \
    "$(variant w2 '.components[2].licenses = "MIT"')"
refused "a supplier written as a string" \
    "component #1 'media-daemon': supplier is not an organization" \
    "$(variant w3 '.components[0].supplier = "Example Corp"')"
refused "a hash with an algorithm CycloneDX does not name" \
    "component #3 'vendor-hal': hashes is not a list" \
    "$(variant w4 '.components[2].hashes = [{"alg": "CRC32", "content": "deadbeef"}]')"
refused "an external reference of an unknown type" \
    "component #3 'vendor-hal': externalReferences is not a list" \
    "$(variant w5 '.components[2].externalReferences = [{"url": "https://example.com", "type": "homepage"}]')"
refused "a licence with both an id and a name" \
    "component #3 'vendor-hal': licenses is not a list of" \
    "$(variant w6 '.components[2].licenses = [{"license": {"id": "MIT", "name": "MIT License"}}]')"
refused "an expression mixed with licence objects" \
    "component #3 'vendor-hal': licenses is not a list of" \
    "$(variant w7 '.components[2].licenses = [{"expression": "MIT OR Apache-2.0"}, {"license": {"id": "MIT"}}]')"
refused "a purl that is not a package URL" \
    "component #3 'vendor-hal': purl 'vendor-hal@4.2.0' is not a package URL" \
    "$(variant w8 '.components[2].purl = "vendor-hal@4.2.0"')"
refused "a license id that is not on the SPDX license list" \
    "component #3 'vendor-hal': license id 'Proprietary' is not on the SPDX license list; name it LicenseRef-<name> in a license name ({\"license\": {\"name\": \"LicenseRef-Proprietary\"}})" \
    "$(variant w8a '.components[2].licenses = [{"license": {"id": "Proprietary"}}]')"
refused "a LicenseRef- written as a license id" \
    "license id 'LicenseRef-ExampleCorp' is not on the SPDX license list" \
    "$(variant w8b '.components[2].licenses = [{"license": {"id": "LicenseRef-ExampleCorp"}}]')"
jq '.components[2].licenses = [{"expression": "BSD-3-Clause OR LicenseRef-ExampleCorp"}]
    | .components[1].licenses = [{"license": {"id": "Classpath-exception-2.0"}}, {"license": {"name": "LicenseRef-ExampleCorp"}}]' \
    "$DECL" > "$WORK/w8c.cdx.json"
cp "$BASE" "$WORK/w8c.bom.json"
rc="$(apply "$WORK/w8c.bom.json" "$P" "$WORK/w8c.cdx.json")"
[ "$rc" = 0 ] && pass "SPDX ids on the list, LicenseRef- in a name and in an expression are accepted" \
    || fail "valid licences refused: exit $rc" "$(cat "$WORK/w8c.bom.json.log")"
[ "$(jq '.ids | length' "$LIB/cdx-spdx-ids.json")" -gt 600 ] && jq -e '.ids | index("MIT") and index("Apache-2.0")' "$LIB/cdx-spdx-ids.json" >/dev/null \
    && pass "the SPDX id list from the CycloneDX 1.6 schema is bundled with the step" || fail "cdx-spdx-ids.json is missing or short"
refused "a name with a line break" \
    "holds a control character" \
    "$(variant w9 '.components[1].name = "media\nctl"')"
refused "a name that is only spaces" \
    "sbom-declared.cdx.json: component #2: has no name" \
    "$(variant w10 '.components[1].name = "   "')"
refused "a file kind value BSI does not define" \
    "component #1 'media-daemon': bsi:component:executable must be given once, as 'executable' or 'non-executable'" \
    "$(variant w11 '.components[0].properties += [{"name": "bsi:component:executable", "value": "yes"}]')"
refused "one file kind for a component of several files" \
    "has several bomlens:artifact files, so it cannot give one" \
    "$(variant w12 '.components[0].properties += [{"name": "bomlens:artifact", "value": "out/bin/media-ctl.exe"}, {"name": "bsi:component:structured", "value": "structured"}]')"
mkdir -p "$WORK/w13"
python3 -I -c 'import sys; open(sys.argv[1], "w").write("{\"bomFormat\": \"CycloneDX\", \"components\": [" + "[" * 100000 + "]" * 100000 + "]}")' "$WORK/w13/deep.cdx.json"
# Whether the JSON reader itself gives up on this depth depends on the Python
# version; either way the file is refused with a reason, not a traceback.
cp "$BASE" "$WORK/w13.bom.json"
rc="$(apply "$WORK/w13.bom.json" "$P" "$WORK/w13/deep.cdx.json")"
[ "$rc" = 3 ] && grep -qE "deep.cdx.json: (cannot be read \(RecursionError\)|component #1: is not a JSON object)" "$WORK/w13.bom.json.log" \
  && ! grep -q Traceback "$WORK/w13.bom.json.log" \
    && pass "a file nested too deeply is refused with a reason" \
    || fail "deep file: exit $rc" "$(tail -3 "$WORK/w13.bom.json.log")"
jq '.components[1].name = "  media-ctl  " | .components[0].properties += [{"name": "bomlens:declared", "value": "false"}]' \
    "$DECL" > "$WORK/w14.cdx.json"
cp "$BASE" "$WORK/w14.bom.json"
rc="$(apply "$WORK/w14.bom.json" "$P" "$WORK/w14.cdx.json")"
[ "$rc" = 0 ] && [ "$(comp "$WORK/w14.bom.json" media-ctl | jq -r .name)" = "media-ctl" ] \
  && [ "$(prop "$(comp "$WORK/w14.bom.json" media-daemon)" bomlens:declared)" = "true" ] \
    && pass "a name is trimmed, and a bomlens:declared value in the file is replaced by the step's own" \
    || fail "trim: exit $rc" "$(cat "$WORK/w14.bom.json.log")"

echo "== the SBOM the step adds to =="
jq '.components = "zlib"' "$BASE" > "$WORK/badbom.json"
cp "$WORK/badbom.json" "$WORK/badbom.orig.json"
rc="$(apply "$WORK/badbom.json" "$P" "$DECL")"
[ "$rc" = 1 ] && grep -qF "cannot take declared components: components is not a list of objects" "$WORK/badbom.json.log" \
  && cmp -s "$WORK/badbom.json" "$WORK/badbom.orig.json" \
    && pass "a stage 1 SBOM of the wrong shape is reported, not crashed on" \
    || fail "bad SBOM: exit $rc" "$(cat "$WORK/badbom.json.log")"
# A component the scan wrote with a bomlens:origin of its own (no
# bomlens:declared mark) is not taken for an earlier run's declared one.
jq '.components += [{"type": "library", "name": "scanned-lib", "version": "1",
                     "properties": [{"name": "bomlens:origin", "value": "first-party"}]}]' "$BASE" > "$WORK/keep.json"
rc="$(apply "$WORK/keep.json" "$P" "$DECL")"
[ "$rc" = 0 ] && [ "$(jq '[.components[] | select(.name == "scanned-lib")] | length' "$WORK/keep.json")" = 1 ] \
    && pass "only components this step marked are replaced on a second run" \
    || fail "scanned component with bomlens:origin: exit $rc" "$(jq -c '[.components[].name]' "$WORK/keep.json")"

echo "== a build output that --exclude left out is reported as excluded =="
P="$(new_project excluded)"
rm -rf "$P/out/bin"   # what the scanned copy looks like with --exclude out/bin
BASE="$(new_bom excluded)"
SCAN_EXCLUDE_PATHS="vendor/legacy
./out/bin/" refused "an artifact under an --exclude path" \
    "sbom-declared.cdx.json: component 'media-daemon': bomlens:artifact 'out/bin/media-daemon' is under 'out/bin', which --exclude leaves out of the scan" \
    "$P/sbom-declared.cdx.json"
SCAN_EXCLUDE_PATHS="out/bi" refused "an exclude path that only shares a prefix is not blamed" \
    "bomlens:artifact 'out/bin/media-daemon' does not exist in the scan target" \
    "$P/sbom-declared.cdx.json"
SCAN_EXCLUDE_PATHS="Out/BIN" refused "an exclude path that matches only without regard to case says so" \
    "bomlens:artifact 'out/bin/media-daemon' does not exist in the scan target. It matches --exclude 'Out/BIN' if letter case is ignored, as it is on macOS and Windows" \
    "$P/sbom-declared.cdx.json"
SCAN_EXCLUDE_PATHS="Out/BIN
out/bin" refused "an exact --exclude match wins over one that ignores case" \
    "bomlens:artifact 'out/bin/media-daemon' is under 'out/bin', which --exclude leaves out of the scan" \
    "$P/sbom-declared.cdx.json"
DECLARED_COMPONENTS_DEFAULT=1 refused "a missing build output in the default file points to --no-components" \
    "this file was read because it is at the scan target root, so pass --no-components to scan without it" \
    "$P/sbom-declared.cdx.json"
refused "a file given with --components does not mention --no-components" \
    "does not exist in the scan target; build it before the scan, or fix the path" \
    "$P/sbom-declared.cdx.json"
grep -q -- "--no-components" "$WORK/a file given with --components does not mention --no-components.bom.json.log" \
    && fail "--no-components suggested for a file given with --components" \
    || pass "the --no-components hint is only for the default file"

echo "== the conformance report counts a component of several files by its files =="
bash "$LIB/validate-sbom.sh" "$WORK/multi.bom.json" "$WORK/multi" x >/dev/null 2>&1
[ "$(jq -c '[.checks[] | select(.id == "component-filename" or .id == "file-properties" or .id == "hash-algorithm") | "\(.id)=\(.detail)"]' "$WORK/multi_conformance.json" 2>/dev/null)" \
    = '["hash-algorithm=50% (1/2)","component-filename=50% (1/2)","file-properties=50% (1/2)"]' ] \
    && pass "media-plugins, whose two files carry SHA-512, a file name and the three kinds, counts as having them; zlib does not" \
    || fail "BSI tallies" "$(jq -c '[.checks[] | select(.id == "component-filename" or .id == "file-properties" or .id == "hash-algorithm") | {id, detail}]' "$WORK/multi_conformance.json" 2>&1)"
jq '(.components[] | select(.name == "media-plugins") | .components[1].properties) |= map(select(.name != "bsi:component:filename"))' \
    "$WORK/multi.bom.json" > "$WORK/multi-gap.json"
bash "$LIB/validate-sbom.sh" "$WORK/multi-gap.json" "$WORK/multi-gap" x >/dev/null 2>&1
[ "$(jq -r '.checks[] | select(.id == "component-filename") | .detail' "$WORK/multi-gap_conformance.json" 2>/dev/null)" = "0% (0/2)" ] \
    && pass "one file without a file name leaves the component without one" \
    || fail "partial children" "$(jq -c '.checks[] | select(.id == "component-filename")' "$WORK/multi-gap_conformance.json" 2>&1)"
[ "$(jq -r '.checks[] | select(.id == "hash") | .detail' "$WORK/multi_conformance.json" 2>/dev/null)" = "50% (1/2)" ] \
    && pass "the hash coverage row counts media-plugins by the hashes of its files" \
    || fail "hash row" "$(jq -c '.checks[] | select(.id == "hash")' "$WORK/multi_conformance.json" 2>&1)"
cisa_missing() {  # <conformance.json> <check id>
    jq -c --arg id "$2" '[.checks[] | select(.id == $id) | .missing] | first' "$1" 2>/dev/null
}
[ "$(cisa_missing "$WORK/multi_conformance.json" cisa-component-hash-value)" = '["MediaSuite","zlib"]' ] \
  && [ "$(cisa_missing "$WORK/multi_conformance.json" cisa-component-identifiers)" = '["MediaSuite"]' ] \
    && pass "the CISA hash value and identifier rows count media-plugins by its files (the product and zlib have no hash)" \
    || fail "CISA rows" "$(jq -c '[.checks[] | select(.id | startswith("cisa-component-h") or . == "cisa-component-identifiers") | {id, status, missing}]' "$WORK/multi_conformance.json" 2>&1)"
jq '(.components[] | select(.name == "media-plugins") | .components[0].hashes) = []' "$WORK/multi.bom.json" > "$WORK/multi-nohash.json"
bash "$LIB/validate-sbom.sh" "$WORK/multi-nohash.json" "$WORK/multi-nohash" x >/dev/null 2>&1
[ "$(cisa_missing "$WORK/multi-nohash_conformance.json" cisa-component-hash-value)" = '["MediaSuite","zlib","media-plugins"]' ] \
  && [ "$(jq -r '.checks[] | select(.id == "hash") | .detail' "$WORK/multi-nohash_conformance.json")" = "0% (0/2)" ] \
    && pass "a file without a hash leaves its component without one in both rows" \
    || fail "partial child hashes" "$(cisa_missing "$WORK/multi-nohash_conformance.json" cisa-component-hash-value)"

echo "== build outputs on distribution references, declared licences concluded =="
# BSI TR-03183-2 section 8 puts the SHA-512 of the deployable file on an
# externalReferences entry of type distribution, and gives the distribution
# licence as "concluded".
dist_of() {  # <bom> <name>: the distribution references of a component, compact
    jq -c --arg n "$2" '[.components[] | select(.name == $n) | (.externalReferences // [])[] | select(.type == "distribution")]' "$1"
}
d512="$(jq -r '.components[] | select(.name == "media-daemon") | .hashes[] | select(.alg == "SHA-512") | .content' "$WORK/ok.bom.json")"
[ "$(dist_of "$WORK/ok.bom.json" media-daemon)" = "[{\"type\":\"distribution\",\"url\":\"out/bin/media-daemon\",\"hashes\":[{\"alg\":\"SHA-512\",\"content\":\"$d512\"}]}]" ] \
  && [ "$(jq -r '.components[] | select(.name == "media-daemon") | [.hashes[].alg] | join("+")' "$WORK/ok.bom.json")" = "SHA-512+SHA-256" ] \
  && [ "$(dist_of "$WORK/ok.bom.json" vendor-hal)" = "[]" ] \
    && pass "a build output is named on a distribution reference by its path, with its SHA-512; the component keeps its hashes" \
    || fail "distribution reference" "$(dist_of "$WORK/ok.bom.json" media-daemon) $(dist_of "$WORK/ok.bom.json" vendor-hal)"
[ "$(jq -c '[.components[] | select(.name == "media-plugins") | .components[] | .externalReferences[0] | [.url, (.hashes | map(.alg) | join("+"))]]' "$WORK/multi.bom.json")" \
    = '[["out/bin/media-plugin.so","SHA-512"],["out/pkg/media-plugins.tar.gz","SHA-512"]]' ] \
  && [ "$(dist_of "$WORK/multi.bom.json" media-plugins)" = "[]" ] \
    && pass "with several build outputs, each nested file has its own distribution reference" \
    || fail "nested distribution references" "$(jq -c '.components[] | select(.name == "media-plugins")' "$WORK/multi.bom.json")"
[ "$(jq -c '[.components[] | select(.name == "media-daemon" or .name == "vendor-hal") | .licenses[0].license.acknowledgement]' "$WORK/ok.bom.json")" = '["concluded","concluded"]' ] \
    && pass "a declared licence with no acknowledgement is marked concluded" \
    || fail "concluded licences" "$(jq -c '[.components[] | .licenses]' "$WORK/ok.bom.json")"
DP="$(new_project distu)"
B="$(new_bom distu)"
rc="$(apply "$B" "$DP" "$(variant du1 '.components[0].properties += [{"name": "bomlens:distribution-url", "value": "https://downloads.example.com/media-daemon"}]
    | .components[2].properties += [{"name": "bomlens:distribution-url", "value": "firmware/hal.bin"}]
    | .components[2].licenses[0].license.acknowledgement = "declared"
    | .components[1].licenses = [{"expression": "LicenseRef-ExampleCorp-Proprietary"}]')")"
[ "$rc" = 0 ] && [ "$(dist_of "$B" media-daemon | jq -r '.[0].url + " " + (.[0].hashes | length | tostring)')" = "https://downloads.example.com/media-daemon 1" ] \
  && [ "$(dist_of "$B" vendor-hal)" = '[{"type":"distribution","url":"firmware/hal.bin"}]' ] \
  && [ "$(jq -c '[.components[] | select(.name == "vendor-hal" or .name == "media-ctl") | .licenses[0] | (.license.acknowledgement // .acknowledgement)]' "$B")" = '["concluded","declared"]' ] \
    && pass "bomlens:distribution-url names the reference (with no build output, without a hash); an acknowledgement the declaration gives is kept" \
    || fail "distribution-url: exit $rc" "$(dist_of "$B" media-daemon) $(dist_of "$B" vendor-hal) $(cat "$B.log")"
refused "a distribution URL with another scheme" \
    "sbom-declared.cdx.json: component #1 'media-daemon': bomlens:distribution-url 'file:///etc/passwd' is neither an http(s) URL nor a relative path" \
    "$(variant du2 '.components[0].properties += [{"name": "bomlens:distribution-url", "value": "file:///etc/passwd"}]')"
refused "a distribution path that leaves the delivery" \
    "bomlens:distribution-url 'out/../../x' is neither an http(s) URL nor a relative path" \
    "$(variant du3 '.components[0].properties += [{"name": "bomlens:distribution-url", "value": "out/../../x"}]')"
refused "a distribution URL with a control character" \
    "bomlens:distribution-url 'https://e.example/a\\nb' is neither" \
    "$(variant du4 '.components[0].properties += [{"name": "bomlens:distribution-url", "value": "https://e.example/a\nb"}]')"
# A colon in the first segment of a path is put behind "./", so the
# reference does not read as a scheme; a percent escape already written is
# kept, other characters are encoded; a '%' that starts no escape is refused.
CP="$(new_project colon)"
mkdir -p "$CP/build:1"
write_elf "$CP/build:1/tool bin"
B="$(new_bom colon)"
rc="$(apply "$B" "$CP" "$(variant du6 '.components[0].properties[1].value = "build:1/tool bin"
    | .components[1].properties += [{"name": "bomlens:distribution-url", "value": "dl/media%20ctl.exe"}]')")"
[ "$rc" = 0 ] && [ "$(dist_of "$B" media-daemon | jq -r '.[0].url')" = "./build:1/tool%20bin" ] \
  && [ "$(dist_of "$B" media-ctl | jq -r '.[0].url')" = "dl/media%20ctl.exe" ] \
    && pass "a path with a colon in its first segment is written as ./build:1/tool%20bin; an escape the declaration wrote is kept" \
    || fail "path references: exit $rc" "$(dist_of "$B" media-daemon) $(dist_of "$B" media-ctl) $(cat "$B.log")"
refused "a distribution path with a stray percent sign" \
    "bomlens:distribution-url 'dl/100%' is neither" \
    "$(variant du7 '.components[0].properties += [{"name": "bomlens:distribution-url", "value": "dl/100%"}]')"
refused "two distribution URLs" \
    "component #1 'media-daemon': has bomlens:distribution-url more than once" \
    "$(variant du5 '.components[0].properties += [{"name": "bomlens:distribution-url", "value": "a"}, {"name": "bomlens:distribution-url", "value": "b"}]')"

echo "== the bsi-tr-03183-2 profile on the fixture =="
# As declared, the fixture's components give their licence as a name
# ("Proprietary") rather than an SPDX identifier or LicenseRef-, the HAL's
# supplier has no URL, the SBOM names no creator, and the product has no
# supplier or licence: those rows fail, by component. The stage 1 SBOM states
# no graph completeness, so that row warns. The file rows pass on what the
# build outputs gave.
bsi_rows() {  # <conformance.json>: id=status:missing, one per bsi-* row
    jq -r '.checks[] | select(.id | startswith("bsi-")) | "\(.id)=\(.status):\(.missing | join(","))"' "$1" 2>/dev/null
}
CONFORMANCE_PROFILE=bsi-tr-03183-2 bash "$LIB/validate-sbom.sh" "$WORK/ok.bom.json" "$WORK/bsi-ok" x >/dev/null 2>&1
want_bsi='bsi-sbom-creator=fail:
bsi-dependency-graph=warn:
bsi-dependency-entries=pass:
bsi-primary-component=fail:MediaSuite@3.1.0: creator, concluded licence
bsi-primary-component-file=warn:
bsi-declared-creator=fail:vendor-hal@4.2.0
bsi-declared-name-version=pass:
bsi-declared-license=fail:media-daemon@3.1.0,media-ctl@2.0.1
bsi-declared-filename=pass:
bsi-declared-sha512=pass:
bsi-declared-file-properties=pass:
bsi-declared-without-file=warn:vendor-hal@4.2.0
bsi-scanned-components=warn:zlib@1.3.1: creator, filename, SHA-512, file properties, concluded licence'
[ "$(bsi_rows "$WORK/bsi-ok_conformance.json")" = "$want_bsi" ] \
    && pass "bsi-tr-03183-2 names, row by row, which declared component misses what; zlib is advisory" \
    || fail "bsi rows on the fixture" "$(bsi_rows "$WORK/bsi-ok_conformance.json")"
# The fixture passing the profile, once its declarations carry the BSI
# fields, is checked through entrypoint.sh below.
# skt-submission, in a scan where the declaration step ran: the two
# first-party programs carry a supplier and SHA-512, so they need no purl and
# are listed as exempted; the third-party HAL does. Without that step in the
# scan (or under --analyze) nothing is exempted.
DECLARED_COMPONENTS_APPLIED=1 MODE=SOURCE CONFORMANCE_PROFILE=skt-submission bash "$LIB/validate-sbom.sh" "$WORK/ok.bom.json" "$WORK/skt-ok" x >/dev/null 2>&1
CONFORMANCE_PROFILE=skt-submission bash "$LIB/validate-sbom.sh" "$WORK/ok.bom.json" "$WORK/skt-no" x >/dev/null 2>&1
[ "$(jq -c '.checks[] | select(.id == "purl") | [.status, .missing]' "$WORK/skt-ok_conformance.json" 2>/dev/null)" = '["fail",["vendor-hal"]]' ] \
  && [ "$(jq -c '.checks[] | select(.id == "first-party-exempt") | .missing' "$WORK/skt-ok_conformance.json" 2>/dev/null)" = '["media-daemon@3.1.0","media-ctl@2.0.1"]' ] \
  && [ "$(jq -c '.checks[] | select(.id == "purl") | .missing' "$WORK/skt-no_conformance.json" 2>/dev/null)" = '["media-daemon","media-ctl","vendor-hal"]' ] \
    && pass "skt-submission asks a purl of the third-party HAL only, and lists the exempted programs, in a scan that applied the declaration" \
    || fail "skt-submission on the fixture" "$(jq -c '[.checks[] | select(.id == "purl" or .id == "first-party-exempt")]' "$WORK/skt-ok_conformance.json" "$WORK/skt-no_conformance.json" 2>&1)"

echo "== SPDX 2.3 export keeps the declared components' checksums and files =="
if command -v syft >/dev/null 2>&1; then
    bash "$LIB/convert-to-spdx.sh" "$WORK/ok.bom.json" "$WORK/ok.spdx.json" --stable >/dev/null 2>&1
    bash "$LIB/convert-to-spdx.sh" "$WORK/multi.bom.json" "$WORK/multi.spdx.json" --stable >/dev/null 2>&1
    elf512="$(jq -r '.components[] | select(.name == "media-daemon") | .hashes[] | select(.alg == "SHA-512") | .content' "$WORK/ok.bom.json")"
    [ "$(jq -c --arg h "$elf512" '[.packages[] | select(.name == "media-daemon") | [([.checksums[].algorithm] | sort), (.checksums[] | select(.algorithm == "SHA512") | .checksumValue == $h), .packageFileName]]' "$WORK/ok.spdx.json")" \
        = '[[["SHA256","SHA512"],true,"media-daemon"]]' ] \
        && pass "a declared component's package has its SHA512 and SHA256 and file name" \
        || fail "SPDX checksums" "$(jq -c '[.packages[] | {name, checksums, packageFileName}]' "$WORK/ok.spdx.json")"
    [ "$(jq -c '[.packages[] | select(.name == "vendor-hal") | has("checksums")]' "$WORK/ok.spdx.json")" = '[false]' ] \
        && pass "a declared component without a build output gets no checksums" || fail "vendor-hal checksums"
    [ "$(jq -c '(.packages[] | select(.name == "media-plugins") | .SPDXID) as $p
               | [.relationships[] | select(.spdxElementId == $p and .relationshipType == "CONTAINS") | .relatedSpdxElement] as $kids
               | [.packages[] | select(.SPDXID as $i | $kids | index($i)) | [.name, .primaryPackagePurpose, ([.checksums[].algorithm] | sort), .packageFileName, .filesAnalyzed]]' "$WORK/multi.spdx.json")" \
        = '[["out/bin/media-plugin.so","FILE",["SHA256","SHA512"],"media-plugin.so",false],["out/pkg/media-plugins.tar.gz","FILE",["SHA256","SHA512"],"media-plugins.tar.gz",false]]' ] \
        && pass "each file of a multi-file component is a FILE package with checksums that the component CONTAINS" \
        || fail "SPDX nested files" "$(jq -c '[.packages[] | {SPDXID, name, checksums}] , .relationships' "$WORK/multi.spdx.json")"
    # SPDX 2.3 rules the export must keep: unique SPDXIDs, every relationship
    # end defined, and the fields a package requires.
    for f in ok multi; do
        [ "$(jq -r '
            ([.packages[].SPDXID] | (length == (unique | length))) as $uniq
            | ([.packages[].SPDXID] + ["SPDXRef-DOCUMENT"]) as $ids
            | ([.relationships[] | .spdxElementId, .relatedSpdxElement] | all(. as $r | $ids | index($r))) as $ends
            | ([.packages[] | has("SPDXID") and has("name") and has("downloadLocation")] | all) as $req
            | ([.packages[].checksums[]? | (.algorithm | IN("SHA1","SHA224","SHA256","SHA384","SHA512","MD5")) and (.checksumValue | test("^[0-9a-f]+$"))] | all) as $sums
            | $uniq and $ends and $req and $sums' "$WORK/$f.spdx.json")" = true ] \
            && pass "$f: the SPDX file keeps unique ids, defined relationship ends and valid checksums" \
            || fail "$f: SPDX structure"
    done
    # The conformance check of the SPDX file counts packages the way the
    # CycloneDX check counts components: the FILE packages are not packages of
    # their own, and media-plugins has checksums through them.
    bash "$LIB/validate-sbom.sh" "$WORK/multi.spdx.json" "$WORK/multi-spdx" x >/dev/null 2>&1
    spdx_total="$(jq '[.packages[] | select((.primaryPackagePurpose // "") != "FILE")] | length' "$WORK/multi.spdx.json")"
    spdx_summed="$(jq '[.packages[] | select((.primaryPackagePurpose // "") != "FILE") | select((.checksums // []) | length > 0)] | length' "$WORK/multi.spdx.json")"
    [ "$(jq -r '.checks[] | select(.id == "name-version") | .detail' "$WORK/multi-spdx_conformance.json" 2>/dev/null | cut -d/ -f2)" = "$spdx_total" ] \
        && pass "the SPDX conformance check leaves the FILE packages out of the package count ($spdx_total)" \
        || fail "SPDX package count" "$(jq -c '[.checks[] | select(.id == "name-version" or .id == "hash") | {id, detail}]' "$WORK/multi-spdx_conformance.json" 2>&1)"
    [ "$(jq -r '.checks[] | select(.id == "hash") | .detail' "$WORK/multi-spdx_conformance.json" 2>/dev/null)" \
        = "$(( (spdx_summed + 1) * 100 / spdx_total ))% ($((spdx_summed + 1))/$spdx_total)" ] \
        && pass "the SPDX hash row counts media-plugins through the checksums of the files it contains" \
        || fail "SPDX hash row" "$(jq -c '.checks[] | select(.id == "hash")' "$WORK/multi-spdx_conformance.json" 2>&1) summed=$spdx_summed total=$spdx_total"
    if command -v pyspdxtools >/dev/null 2>&1; then
        pyspdxtools -i "$WORK/multi.spdx.json" >/dev/null 2>&1 && pyspdxtools -i "$WORK/ok.spdx.json" >/dev/null 2>&1 \
            && pass "pyspdxtools validates both SPDX 2.3 files" || fail "pyspdxtools rejects an SPDX file" "$(pyspdxtools -i "$WORK/multi.spdx.json" 2>&1 | tail -5)"
    fi
else
    echo "  SKIP: syft is not installed (the post-process CI job installs it)"
fi

echo "== NOTICE: third-party only =="
N="$WORK/notice"; mkdir -p "$N"
( cd "$N" && bash "$LIB/generate-notice.sh" "$WORK/ok.bom.json" "$N/ms" MediaSuite > "$N/log" 2>&1 )
if [ -f "$N/ms_NOTICE.txt" ] && [ -f "$N/ms_NOTICE.html" ]; then
    ! grep -q 'media-daemon\|media-ctl' "$N/ms_NOTICE.txt" "$N/ms_NOTICE.html" \
      && grep -q 'vendor-hal@4.2.0' "$N/ms_NOTICE.txt" && grep -q 'zlib@1.3.1' "$N/ms_NOTICE.txt" \
        && pass "first-party components are left out of the NOTICE; the declared third-party one and zlib are in it" \
        || fail "NOTICE content" "$(grep -n 'media\|vendor\|zlib' "$N/ms_NOTICE.txt")"
    grep -q 'Total components: 2 ' "$N/ms_NOTICE.txt" && ! grep -q 'Proprietary' "$N/ms_NOTICE.txt" \
        && pass "the NOTICE counts only what it lists, and the first-party licence is not in it" \
        || fail "NOTICE header" "$(grep -n 'Total\|Proprietary' "$N/ms_NOTICE.txt")"
    [ "$(jq '[.components[] | select(any(.properties[]?; .name == "bomlens:origin" and .value == "first-party"))] | length' "$WORK/ok.bom.json")" = 2 ] \
        && pass "the first-party components stay in the SBOM" || fail "first-party components missing from the SBOM"
else
    fail "generate-notice.sh wrote no NOTICE" "$(cat "$N/log")"
fi

echo "== through entrypoint.sh (POSTPROCESS, as a CLI source scan runs it) =="
mkdir -p "$WORK/bin"
cat > "$WORK/bin/trivy" <<'EOF'
#!/bin/bash
[ "${1:-}" = "version" ] && { echo '{"Version":"0.0.0-stub"}'; exit 0; }
exit 1
EOF
chmod +x "$WORK/bin/trivy"
# run_entry <name> <project> [VAR=value ...]: prints the exit code; the output
# folder is $WORK/<name>.out.
run_entry() {
    local name="$1" src="$2" out="$WORK/$1.out" rc=0
    shift 2
    mkdir -p "$out"
    jq '.metadata.component.name = "project" | .metadata.component.version = "latest"' "${RUN_ENTRY_INPUT:-$FIX/stage1-bom.json}" > "$out/MediaSuite_3.1.0_bom.json"
    ( cd "$out" && env PATH="$WORK/bin:$PATH" MODE=POSTPROCESS PROJECT_NAME=MediaSuite PROJECT_VERSION=3.1.0 \
        HOST_OUTPUT_DIR="$out" BOMLENS_LIBDIR="$LIB" BOMLENS_RUN_INPUT=MediaSuite_3.1.0_bom.json SOURCE_ROOT="$src" \
        UPLOAD_ENABLED=false GENERATE_SECURITY=false GENERATE_NOTICE=false DEEP_CVE=false SECURITY_ENRICH=false \
        ENRICH_EOL=false ENRICH_MALICIOUS=false ENRICH_STALENESS=false LICENSE_REGISTRY=false "$@" bash "$ENTRY" ) > "$out.log" 2>&1 || rc=$?
    printf '%s' "$rc"
}
step() {  # <output folder>: the declared-components step of the manifest
    jq -c '[.steps[] | select(.id == "declared-components") | {status, reason, counts}] | first' "$1/bomlens-result.json" 2>/dev/null
}
P="$(new_project entry-default)"
rc="$(run_entry e1 "$P")"
O="$WORK/e1.out"
F="$O/MediaSuite_3.1.0_bom.json"
[ "$rc" = 0 ] && [ "$(step "$O")" = '{"status":"ok","reason":null,"counts":{"components":3}}' ] \
    && pass "sbom-declared.cdx.json at the scan target root is read when no file is given" \
    || fail "default file: exit $rc, step $(step "$O")" "$(tail -5 "$O.log")"
D="$(comp "$F" media-daemon)"
[ "$(printf '%s' "$D" | jq -c '[.version, ([.hashes[].alg] | sort), ([.properties[] | select(.name | startswith("bsi:")) | .value])]')" \
    = '["3.1.0",["SHA-256","SHA-512"],["media-daemon","executable","no archive","unstructured"]]' ] \
    && pass "the declared fields survive normalize and the rest of the pipeline" \
    || fail "final SBOM component" "$D"
[ "$(jq -c "$UNREACHED" "$F")" = "[]" ] && pass "the final SBOM's graph reaches every component from the product" \
    || fail "not reached in the final SBOM: $(jq -c "$UNREACHED" "$F")"
[ "$(jq -r '.metadata.component.name + "@" + .metadata.component.version' "$F")" = "MediaSuite@3.1.0" ] \
    && pass "the product is the stamped one" || fail "product $(jq -c .metadata.component "$F")"
[ "$(jq -c '.checks[] | select(.id == "first-party-exempt") | .missing | sort' "$O/MediaSuite_3.1.0_conformance.json" 2>/dev/null)" = '["media-ctl@2.0.1","media-daemon@3.1.0"]' ] \
    && pass "the conformance check of the scan lists the two first-party programs as exempt from the PURL rows" \
    || fail "exemption through the pipeline" "$(jq -c '[.checks[] | select(.id == "purl" or .id == "first-party-exempt")]' "$O/MediaSuite_3.1.0_conformance.json" 2>&1)"

# DECLARED_COMPONENTS_APPLIED in the caller's environment is not taken: with
# no declaration read, a stage 1 SBOM that already carries marked first-party
# components (as one a declaration step wrote, or one forged to look so) gets
# no exemption.
jq --argjson h "$(jq -c '[.components[] | select(.name == "media-daemon") | .hashes] | first' "$WORK/ok.bom.json")" \
   '.components += [{"type": "application", "name": "forged", "version": "1", "bom-ref": "forged",
       "supplier": {"name": "X", "url": ["https://x.example"]}, "hashes": $h,
       "properties": [{"name": "bomlens:origin", "value": "first-party"}, {"name": "bomlens:declared", "value": "true"}]}]
    | .dependencies[0].dependsOn += ["forged"] | .dependencies += [{"ref": "forged", "dependsOn": []}]' \
    "$FIX/stage1-bom.json" > "$WORK/forged-stage1.json"
P="$(new_project entry-forged)"
rc="$(RUN_ENTRY_INPUT="$WORK/forged-stage1.json" run_entry e6 "$P" DECLARED_COMPONENTS_SKIP=1 DECLARED_COMPONENTS_APPLIED=1)"
C6="$WORK/e6.out/MediaSuite_3.1.0_conformance.json"
[ "$rc" = 0 ] && ! jq -e 'any(.checks[]; .id == "first-party-exempt")' "$C6" >/dev/null \
  && jq -e '.checks[] | select(.id == "purl") | .missing | index("forged") != null' "$C6" >/dev/null \
    && pass "DECLARED_COMPONENTS_APPLIED from the caller is ignored: a forged first-party component still needs a purl" \
    || fail "forged exemption: exit $rc" "$(jq -c '[.checks[] | select(.id == "purl" or .id == "first-party-exempt")]' "$C6" 2>&1)"

# bsi-tr-03183-2 through the pipeline: with the licences as LicenseRef-, a URL
# for the HAL's supplier, and --sbom-author, --supplier and --license given as
# a CLI scan passes them, the fixture passes on every required BSI row. The
# compositions entry the pipeline writes names the product's dependencies.
P="$(new_project entry-bsi)"
jq '.components[0].licenses = [{"license": {"name": "LicenseRef-ExampleCorp-Proprietary"}}]
    | .components[1].licenses = [{"license": {"name": "LicenseRef-ExampleCorp-Proprietary"}}]
    | .components[2].supplier.url = ["https://chip.example.com"]' \
    "$FIX/project/sbom-declared.cdx.json" > "$P/sbom-declared.cdx.json"
rc="$(run_entry e5 "$P" CONFORMANCE_PROFILE=bsi-tr-03183-2 SBOM_AUTHOR="Example Corp <sbom@example.com>" \
    PRODUCT_SUPPLIER="Example Corp <https://example.com>" PROJECT_LICENSE=Apache-2.0)"
O="$WORK/e5.out"
F="$O/MediaSuite_3.1.0_bom.json"
C5="$O/MediaSuite_3.1.0_conformance.json"
[ "$rc" = 0 ] && [ "$(jq -r .result "$C5" 2>/dev/null)" = pass ] \
  && [ "$(jq -r '[.checks[] | select(.id | startswith("bsi-")) | select(.required) | .status] | unique | join(",")' "$C5")" = pass ] \
  && [ "$(jq -cS '[.metadata.component.supplier, .metadata.supplier, .metadata.component.licenses]' "$F")" \
       = '[{"name":"Example Corp","url":["https://example.com"]},null,[{"license":{"acknowledgement":"concluded","id":"Apache-2.0"}}]]' ] \
  && [ "$(jq -c '.compositions[0].dependencies == ([.dependencies[].ref] | unique)' "$F")" = true ] \
    && pass "the fixture passes bsi-tr-03183-2 through the pipeline with --supplier, --sbom-author and --license" \
    || fail "bsi through the pipeline: exit $rc" "$(jq -c '[.result, (.checks[] | select(.required and .status != "pass") | [.id, .detail, .missing])]' "$C5" 2>&1) $(jq -c '[.metadata.component["bom-ref"], .metadata.supplier, .metadata.component.licenses, .compositions]' "$F" 2>&1)"

cat > "$WORK/given.cdx.json" <<'EOF'
{"bomFormat": "CycloneDX", "components": [{"type": "firmware", "name": "dsp-blob", "version": "7",
  "properties": [{"name": "bomlens:origin", "value": "third-party"}]}]}
EOF
rc="$(run_entry e2 "$P" DECLARED_COMPONENTS_FILES="$WORK/given.cdx.json" DECLARED_COMPONENTS_LABELS="modules/given.cdx.json")"
F="$WORK/e2.out/MediaSuite_3.1.0_bom.json"
[ "$rc" = 0 ] && [ "$(jq -c '[.components[] | select(any(.properties[]?; .name == "bomlens:origin")) | .name]' "$F")" = '["dsp-blob"]' ] \
    && pass "a file given with --components is read instead of the one at the root" \
    || fail "given file: exit $rc" "$(jq -c '[.components[].name]' "$F") $(tail -5 "$WORK/e2.out.log")"

P="$(new_project entry-refused)"
rm "$P/out/bin/media-ctl.exe"
rc="$(run_entry e3 "$P")"
O="$WORK/e3.out"
[ "$rc" = 1 ] && [ "$(step "$O" | jq -r .status)" = failed ] \
  && grep -qF "[declared-components] ERROR: sbom-declared.cdx.json (at the scan target root): component 'media-ctl': bomlens:artifact 'out/bin/media-ctl.exe' does not exist" "$O.log" \
  && grep -qF "[ERROR] the declared components were refused" "$O.log" \
  && [ "$(jq -r '.steps[] | select(.id == "declared-components") | .detail' "$O/bomlens-result.json")" != "null" ] \
    && pass "a refused declaration stops the run with exit 1, the reason in the log and in the manifest" \
    || fail "refused run: exit $rc, step $(step "$O")" "$(tail -8 "$O.log")"
[ ! -f "$O/MediaSuite_3.1.0_conformance.json" ] && pass "nothing after the refusal runs (no conformance report)" \
    || fail "the run went on after the refusal"
[ ! -f "$O/MediaSuite_3.1.0_bom.json" ] && [ -s "$O/MediaSuite_3.1.0_bom.refused.json" ] \
  && grep -qF "kept as MediaSuite_3.1.0_bom.refused.json, not as MediaSuite_3.1.0_bom.json" "$O.log" \
    && pass "the incomplete SBOM is renamed to _bom.refused.json, so nothing can take it for the result" \
    || fail "refused SBOM name" "$(ls "$O")"
grep -qF "pass --no-components to scan without it" "$O.log" \
    && pass "the refusal of the default file points to --no-components" || fail "no --no-components hint" "$(grep ERROR "$O.log")"
rc="$(run_entry e3 "$P" DECLARED_COMPONENTS_SKIP=1)"
[ "$rc" = 0 ] && [ "$(step "$O")" = "null" ] && [ -s "$O/MediaSuite_3.1.0_bom.json" ] && [ ! -f "$O/MediaSuite_3.1.0_bom.refused.json" ] \
  && grep -qF -- "--no-components: sbom-declared.cdx.json at the scan target root is not read" "$O.log" \
    && pass "--no-components leaves the default file unread, and the next run sweeps the refused SBOM away" \
    || fail "--no-components: exit $rc, step $(step "$O")" "$(ls "$O"; tail -5 "$O.log")"

P="$(new_project entry-none)"
rm "$P/sbom-declared.cdx.json"
rc="$(run_entry e4 "$P")"
[ "$rc" = 0 ] && [ "$(step "$WORK/e4.out")" = "null" ] \
    && pass "with no declaration file the step is not recorded and the run is unchanged" \
    || fail "no file: exit $rc, step $(step "$WORK/e4.out")" "$(tail -5 "$WORK/e4.out.log")"

P="$(new_project entry-link)"
rm "$P/sbom-declared.cdx.json"
cp "$FIX/project/sbom-declared.cdx.json" "$WORK/outside-declared.cdx.json"
ln -s "$WORK/outside-declared.cdx.json" "$P/sbom-declared.cdx.json"
rc="$(run_entry e7 "$P")"
[ "$rc" = 1 ] && grep -qF "sbom-declared.cdx.json (at the scan target root): leads outside the scan target through a symbolic link" "$WORK/e7.out.log" \
    && pass "a default file that links out of the scan target is refused" \
    || fail "linked default file: exit $rc" "$(tail -5 "$WORK/e7.out.log")"

echo "== scan-sbom.sh: --components files reach the container =="
extract_fn() {
    awk -v fn="$1" '
        $0 ~ "^" fn "\\(\\) \\{" { inside = 1 }
        inside { print }
        inside && $0 == "}" { exit }
    ' "$SCRIPT"
}
body="$(extract_fn components_run)"
if [ -z "$body" ]; then
    fail "could not lift components_run out of scan-sbom.sh"
else
    eval "$body"
    hostpath() { printf '%s' "$1"; }
    NO_COMPONENTS="false"
    mkdir -p "$WORK/cli dir"
    printf '{}' > "$WORK/cli dir/a b.cdx.json"
    printf '{}' > "$WORK/second.cdx.json"
    COMPONENTS_FILES=("$WORK/cli dir/a b.cdx.json" "$WORK/second.cdx.json")
    # The string is expanded inside an eval'd docker command line; eval it the
    # same way and look at the words it becomes.
    eval "set -- $(components_run)"
    want=(-v "$WORK/cli dir/a b.cdx.json:/components-in/0.cdx.json:ro" -v "$WORK/second.cdx.json:/components-in/1.cdx.json:ro"
          -e "DECLARED_COMPONENTS_FILES=/components-in/0.cdx.json /components-in/1.cdx.json" -e DECLARED_COMPONENTS_LABELS)
    [ "$*" = "${want[*]}" ] && [ "$#" = "${#want[@]}" ] \
        && pass "each file is mounted read-only at a fixed path; the user's names travel by variable name only" \
        || fail "components_run gave $# words: $*"
    # shellcheck disable=SC2034 # read by components_run, lifted above
    COMPONENTS_FILES=()
    [ -z "$(components_run)" ] && pass "no --components, no mount" || fail "mount without --components"
    # shellcheck disable=SC2034 # read by components_run, lifted above
    NO_COMPONENTS="true"
    [ "$(components_run)" = " -e DECLARED_COMPONENTS_SKIP=1" ] && pass "--no-components reaches the container as DECLARED_COMPONENTS_SKIP=1" \
        || fail "--no-components gave '$(components_run)'"
fi
out="$(bash "$SCRIPT" --project x --version 1 --components 2>&1)"; rc=$?
[ "$rc" = 1 ] && [ "$out" = "[ERROR] --components requires a file, e.g. --components sbom-declared.cdx.json" ] \
    && pass "--components as the last argument says it needs a file" || fail "--components last: exit $rc" "$out"
out="$(bash "$SCRIPT" --project x --version 1 --no-components --components "$FIX/project/sbom-declared.cdx.json" --target "$WORK/no-such-dir" 2>&1)"; rc=$?
[ "$rc" = 1 ] && printf '%s' "$out" | grep -qF "[ERROR] --no-components cannot be combined with --components" \
    && pass "--no-components and --components together are refused" || fail "--no-components with --components: exit $rc" "$out"
grep -q '^  --no-components ' "$SCRIPT" && pass "--no-components is in the help" || fail "--no-components missing from the help"
# An earlier run's _bom.refused.json is removed with the earlier SBOM, before
# stage 1, so the check after stage 2 reads only this run's refusal.
rm_line="$(grep -n '^rm -f "${OUTPUT_HOST_DIR}/${OUTPUT_FILE%_bom.json}_bom.refused.json"$' "$SCRIPT" | cut -d: -f1)"
stage1_line="$(grep -n '^# Stage 1: produce SBOM' "$SCRIPT" | cut -d: -f1)"
check_line="$(grep -n '_bom.refused.json" \]; then' "$SCRIPT" | cut -d: -f1)"
[ -n "$rm_line" ] && [ -n "$stage1_line" ] && [ -n "$check_line" ] && [ "$rm_line" -lt "$stage1_line" ] && [ "$stage1_line" -lt "$check_line" ] \
    && pass "a stale _bom.refused.json is removed before stage 1 and checked only after stage 2" \
    || fail "stale refused SBOM: rm at '$rm_line', stage 1 at '$stage1_line', check at '$check_line'"
body="$(extract_fn exclude_run)"
if [ -z "$body" ]; then
    fail "could not lift exclude_run out of scan-sbom.sh"
else
    eval "$body"
    [ "$(SCAN_EXCLUDE_PATHS="" exclude_run)" = "" ] && [ "$(SCAN_EXCLUDE_PATHS="out/bin" exclude_run)" = " -e SCAN_EXCLUDE_PATHS" ] \
        && pass "the --exclude paths reach the container by variable name, only when there are some" \
        || fail "exclude_run gave '$(SCAN_EXCLUDE_PATHS="out/bin" exclude_run)'"
fi
grep -q '(components_run)$(exclude_run)' "$SCRIPT" && grep -q '^    export SCAN_EXCLUDE_PATHS' "$SCRIPT" \
    && pass "the post-process container gets the --exclude paths" || fail "exclude_run is not used"
grep -q '^            COMPONENTS_FILES+=("$2"); shift ;;' "$SCRIPT" && grep -q '^  --components <file>' "$SCRIPT" \
    && pass "--components is parsed (repeatable) and in the help" || fail "--components parsing or help missing"
grep -q '(components_run)' "$SCRIPT" && pass "the post-process container gets the mounts" || fail "components_run is not used"

echo "== Yocto: components declared by recipe (bomlens:yocto-recipe) =="
# tests/fixtures/yocto-declared: one image in the SPDX 3.0 shape of 5.x
# (build_Build hasOutput) and of 6.x (specification recipe generates, with
# SHA-512 file hashes as 6.1 writes them), and the manifests of a build with
# no SPDX. The image installs busybox (two packages), zlib (libz1), the
# in-house recipe media-daemon (LICENSE = "CLOSED", two packages) and a chip
# vendor's binary recipe vendor-dsp (one package, vendor-dsp-firmware).
YFIX="$ROOT_DIR/tests/fixtures/yocto-declared"
YDECL="$YFIX/sbom-declared.cdx.json"
# yocto_read <name> <5x|6x|manifests>: the reader's SBOM in $WORK/<name>.bom.json,
# and for SPDX the file list in $WORK/<name>.files.json.
yocto_read() {
    case "$2" in
        manifests) YOCTO_FILES_OUT="$WORK/$1.files.json" python3 -I "$LIB/parse-yocto-manifests.py" "$YFIX/build-manifests" "$WORK/$1.bom.json" "$WORK/$1" >/dev/null 2>&1 ;;
        *) YOCTO_FILES_OUT="$WORK/$1.files.json" python3 -I "$LIB/parse-yocto-spdx.py" "$YFIX/spdx3-$2-image.json" "$WORK/$1.bom.json" "$WORK/$1" >/dev/null 2>&1 ;;
    esac
}
# yocto_apply <name> <file>...: the step as entrypoint.sh runs it for a Yocto build.
yocto_apply() {
    local name="$1" rc=0
    shift
    DECLARED_COMPONENTS_YOCTO=1 DECLARED_COMPONENTS_YOCTO_FILES="$( [ -f "$WORK/$name.files.json" ] && printf '%s' "$WORK/$name.files.json")" \
        DECLARED_COMPONENTS_LABELS="$(basename "$1")" python3 -I "$APPLY" "$WORK/$name.bom.json" "$YFIX" "$@" > "$WORK/$name.log" 2>&1 || rc=$?
    printf '%s' "$rc"
}
# One line per package: name|type|origin|recipe|supplier|licence|own hashes|files|file hash algs
YPKGS='[.components[] | select(.name | test("^(busybox|busybox-syslog|libz1|media-daemon|media-daemon-cli|vendor-dsp-firmware)$"))
        | [.name, .type, ([.properties[] | select(.name == "bomlens:origin") | .value] | join(",")),
           ([.properties[] | select(.name == "bomlens:yocto-recipe") | .value] | join(",")),
           (.supplier.name // ""), ((.licenses // [])[0] | ((.license.name // .license.id // .expression // "") + "/" + (.license.acknowledgement // .acknowledgement // ""))),
           ((.hashes // []) | length | tostring), ((.components // []) | length | tostring),
           ([(.components // [])[] | [.hashes[].alg] | join("+")] | unique | join(","))] | join("|")] | join("\n")'

for shape in 5x 6x; do
    yocto_read "y$shape" "$shape"
    before="$(jq '.components | length' "$WORK/y$shape.bom.json")"
    rc="$(yocto_apply "y$shape" "$YDECL")"
    [ "$rc" = 0 ] && [ "$(jq '.components | length' "$WORK/y$shape.bom.json")" = "$before" ] \
        && grep -qF "recipe 'media-daemon' (first-party): declared on 2 package(s): media-daemon, media-daemon-cli; 3 file(s) with their hashes" "$WORK/y$shape.log" \
        && pass "$shape: the declaration goes on the packages already in the SBOM, adding none" \
        || fail "$shape apply: exit $rc" "$(cat "$WORK/y$shape.log")"
    want_algs="SHA-256"; [ "$shape" = 6x ] && want_algs="SHA-256+SHA-512"
    got="$(jq -r "$YPKGS" "$WORK/y$shape.bom.json")"
    # The packages of busybox and zlib are not declared: they keep the
    # licence the build gave them.
    ywant="busybox|library||||GPL-2.0-only/|0|0|
busybox-syslog|library||||GPL-2.0-only/|0|0|
libz1|library||||Zlib/|0|0|
media-daemon|application|first-party|media-daemon|Example Corp|LicenseRef-ExampleCorp-Proprietary/concluded|0|2|$want_algs
media-daemon-cli|application|first-party|media-daemon|Example Corp|LicenseRef-ExampleCorp-Proprietary/concluded|0|1|$want_algs
vendor-dsp-firmware|firmware|third-party|vendor-dsp|Example Chip Vendor|LicenseRef-Vendor-Binary/concluded|0|1|$want_algs"
    [ "$got" = "$ywant" ] && pass "$shape: every package of each declared recipe gets the type, origin, recipe, supplier and concluded licence; the files the build hashed are nested, with no package hash made up" \
        || fail "$shape packages" "got:
$got"
    D="$(comp "$WORK/y$shape.bom.json" media-daemon)"
    sha="$(python3 -I -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' usr/bin/media-daemon)"
    [ "$(printf '%s' "$D" | jq -r '.components[] | select(.name == "usr/bin/media-daemon") | [.type, .version, (.hashes[] | select(.alg == "SHA-256") | .content), ([.properties[] | select(.name == "bsi:component:filename") | .value] | join(",")), .supplier.name, .["bom-ref"]] | join("|")')" \
        = "file|3.1.0|$sha|media-daemon|Example Corp|urn:pkg:media-daemon#usr/bin/media-daemon" ] \
      && [ "$(prop "$D" bomlens:declared)" = "true" ] && [ "$(printf '%s' "$D" | jq -r .version)" = "3.1.0" ] \
        && pass "$shape: a nested file carries the hash, file name and version the build recorded; the package keeps its version and is marked" \
        || fail "$shape media-daemon" "$D"
done
[ "$(jq -r '.components[] | select(.name == "media-daemon") | .purl' "$WORK/y6x.bom.json")" = "pkg:yocto/meta-example/media-daemon@3.1.0" ] \
    && pass "6x: the package keeps the purl the build wrote" || fail "6x purl" "$(comp "$WORK/y6x.bom.json" media-daemon)"
# The manifests list no files: the declaration still goes on the packages.
yocto_read ym manifests
rc="$(yocto_apply ym "$YDECL")"
[ "$rc" = 0 ] && [ "$(jq -r "$YPKGS" "$WORK/ym.bom.json" | grep -c '|0|0|$')" = 6 ] \
  && [ "$(jq -r '[.components[] | select(any(.properties[]?; .name == "bomlens:origin")) | .name] | join(",")' "$WORK/ym.bom.json")" = "media-daemon,media-daemon-cli,vendor-dsp-firmware" ] \
    && pass "manifests: the packages of each declared recipe (from license.manifest) are declared, with no files to nest" \
    || fail "manifests apply: exit $rc" "$(cat "$WORK/ym.log"; jq -r "$YPKGS" "$WORK/ym.bom.json")"
# busybox is a package named after its recipe, which the readers do not repeat
# in bomlens:yocto:recipe; a recipe declaration still finds it.
cat > "$WORK/ybb.cdx.json" <<'EOF'
{"bomFormat": "CycloneDX", "components": [{"type": "library", "name": "busybox", "version": "1.36.1",
  "supplier": {"name": "BusyBox", "url": ["https://busybox.net"]},
  "properties": [{"name": "bomlens:origin", "value": "third-party"}, {"name": "bomlens:yocto-recipe", "value": "busybox"}]}]}
EOF
yocto_read ybb 5x
rc="$(yocto_apply ybb "$WORK/ybb.cdx.json")"
[ "$rc" = 0 ] && [ "$(jq -r '[.components[] | select(any(.properties[]?; .name == "bomlens:yocto-recipe")) | .name] | join(",")' "$WORK/ybb.bom.json")" = "busybox,busybox-syslog" ] \
  && [ "$(jq -r '.components[] | select(.name == "busybox") | .licenses[0].license.id' "$WORK/ybb.bom.json")" = "GPL-2.0-only" ] \
    && pass "a recipe named like its package matches it, and a declaration with no licence keeps the build's" \
    || fail "busybox by name: exit $rc" "$(cat "$WORK/ybb.log")"
# The SBOM the 5.x reader wrote is unchanged except for the declared packages.
yocto_read y5plain 5x
[ "$(jq -c '[.components[] | select(.name | test("^(busybox|busybox-syslog|libz1)$"))]' "$WORK/y5plain.bom.json")" \
    = "$(jq -c '[.components[] | select(.name | test("^(busybox|busybox-syslog|libz1)$"))]' "$WORK/y5x.bom.json")" ] \
  && [ "$(jq -c .dependencies "$WORK/y5plain.bom.json")" = "$(jq -c .dependencies "$WORK/y5x.bom.json")" ] \
  && [ "$(jq -c .metadata "$WORK/y5plain.bom.json")" = "$(jq -c .metadata "$WORK/y5x.bom.json")" ] \
    && pass "packages not declared, the dependencies and the metadata stay as the reader wrote them" \
    || fail "untouched parts changed"
python3 -I "$LIB/parse-yocto-spdx.py" "$YFIX/spdx3-6x-image.json" "$WORK/y6nofiles.bom.json" >/dev/null 2>&1
YOCTO_FILES_OUT="$WORK/y6again.files.json" python3 -I "$LIB/parse-yocto-spdx.py" "$YFIX/spdx3-6x-image.json" "$WORK/y6again.bom.json" >/dev/null 2>&1
cmp -s "$WORK/y6nofiles.bom.json" "$WORK/y6again.bom.json" \
  && [ "$(jq -r '.files | keys | length' "$WORK/y6again.files.json")" = 6 ] \
  && ! jq -e '.files[][] | select(.name == "media-daemon.c")' "$WORK/y6again.files.json" >/dev/null \
    && pass "YOCTO_FILES_OUT lists the files of each installed package (not the recipe's sources) and leaves the SBOM as it was" \
    || fail "file list" "$(jq -c '.files | keys' "$WORK/y6again.files.json" 2>&1)"
# SPDX_PACKAGE_SUPPLIER_name:pn-vendor-dsp gives the package a suppliedBy,
# read as its supplier; a declaration without a supplier leaves it.
cat > "$WORK/ysup.cdx.json" <<'EOF'
{"bomFormat": "CycloneDX", "components": [{"type": "firmware", "name": "vendor-dsp",
  "properties": [{"name": "bomlens:origin", "value": "third-party"}, {"name": "bomlens:yocto-recipe", "value": "vendor-dsp"}]}]}
EOF
yocto_read ysup 6x
[ "$(jq -c '[.components[] | select(.supplier) | [.name, .supplier.name]]' "$WORK/ysup.bom.json")" = '[["vendor-dsp-firmware","Example Chip Vendor"]]' ] \
  && [ "$(yocto_apply ysup "$WORK/ysup.cdx.json")" = 0 ] \
  && [ "$(jq -r '.components[] | select(.name == "vendor-dsp-firmware") | .supplier.name + "|" + .type' "$WORK/ysup.bom.json")" = "Example Chip Vendor|firmware" ] \
    && pass "the supplier the build wrote (suppliedBy) is read, and kept when the declaration gives none" \
    || fail "build supplier" "$(comp "$WORK/ysup.bom.json" vendor-dsp-firmware)"

echo "== Yocto: each refusal names the recipe =="
# yrefuse <name> <declaration json> [env...]: exit code of the step on a fresh 6.x read
yrefuse() {
    local name="$1" json="$2"
    shift 2
    printf '%s\n' "$json" > "$WORK/$name.cdx.json"
    yocto_read "$name" 6x
    env "$@" bash -c 'rc=0; DECLARED_COMPONENTS_YOCTO="${DECLARED_COMPONENTS_YOCTO-1}" DECLARED_COMPONENTS_YOCTO_FILES="$3" DECLARED_COMPONENTS_LABELS="$(basename "$2")" python3 -I "$4" "$1" "$5" "$2" > "$1.log" 2>&1 || rc=$?; printf "%s" "$rc"' \
        _ "$WORK/$name.bom.json" "$WORK/$name.cdx.json" "$WORK/$name.files.json" "$APPLY" "$YFIX"
}
yerr() { grep -F "[declared-components] ERROR: " "$WORK/$1.bom.json.log" | head -1; }
YC='{"bomFormat": "CycloneDX", "components": [{"type": "application", "name": "x", "supplier": {"name": "E"}, "properties": [{"name": "bomlens:origin", "value": "first-party"}'
rc="$(yrefuse yr1 "$YC, {\"name\": \"bomlens:yocto-recipe\", \"value\": \"no-such-recipe\"}]}]}")"
[ "$rc" = 3 ] && [ "$(yerr yr1)" = "[declared-components] ERROR: yr1.cdx.json: component 'x': recipe 'no-such-recipe' (bomlens:yocto-recipe) built no package installed in this image. Give the recipe name (PN) of a package the image installs, or remove the component" ] \
  && cmp -s "$WORK/yr1.bom.json" "$WORK/y6nofiles.bom.json" \
    && pass "a recipe that installed no package is refused by name, and the SBOM is left as it was" \
    || fail "missing recipe: exit $rc" "$(yerr yr1)"
rc="$(yrefuse yr2 "$YC, {\"name\": \"bomlens:yocto-recipe\", \"value\": \"libz1\"}]}]}")"
[ "$rc" = 3 ] && yerr yr2 | grep -qF "recipe 'libz1' (bomlens:yocto-recipe) built no package installed in this image; the package named 'libz1' comes from recipe 'zlib'." \
    && pass "a package name given for the recipe is refused with the recipe it comes from" || fail "package name as recipe: exit $rc" "$(yerr yr2)"
rc="$(yrefuse yr3 "$YC, {\"name\": \"bomlens:yocto-recipe\", \"value\": \"media-daemon\"}, {\"name\": \"bomlens:artifact\", \"value\": \"out/x\"}]}]}")"
[ "$rc" = 3 ] && grep -qF "component #1 'x': names both bomlens:artifact and bomlens:yocto-recipe" "$WORK/yr3.bom.json.log" \
    && pass "bomlens:artifact and bomlens:yocto-recipe together are refused" || fail "both: exit $rc" "$(yerr yr3)"
rc="$(yrefuse yr4 "$YC, {\"name\": \"bomlens:yocto-recipe\", \"value\": \"media-daemon\"}]}]}" DECLARED_COMPONENTS_YOCTO=0)"
[ "$rc" = 3 ] && grep -qF "component #1 'x': bomlens:yocto-recipe applies to a Yocto build scan only" "$WORK/yr4.bom.json.log" \
    && pass "a recipe declaration outside a Yocto build is refused" || fail "recipe in a source scan: exit $rc" "$(yerr yr4)"
rc="$(yrefuse yr5 "$YC, {\"name\": \"bomlens:artifact\", \"value\": \"out/x\"}]}]}")"
[ "$rc" = 3 ] && grep -qF "component #1 'x': bomlens:artifact names a file of a build output folder, which a Yocto build scan does not read; name the recipe that installs it in bomlens:yocto-recipe instead" "$WORK/yr5.bom.json.log" \
    && pass "bomlens:artifact in a Yocto build is refused, pointing to bomlens:yocto-recipe" || fail "artifact in yocto: exit $rc" "$(yerr yr5)"
rc="$(yrefuse yr6 "$(printf '%s' "$YC" | sed 's/"name": "x"/"name": "x", "version": "9.9"/'), {\"name\": \"bomlens:yocto-recipe\", \"value\": \"media-daemon\"}]}]}")"
[ "$rc" = 3 ] && grep -qF "component 'x': version '9.9' is not the one the build recorded for recipe 'media-daemon' (3.1.0)" "$WORK/yr6.bom.json.log" \
    && pass "a version other than the build's is refused" || fail "version: exit $rc" "$(yerr yr6)"
rc="$(yrefuse yr7 "$(printf '%s' "$YC" | sed 's/"name": "x"/"name": "x", "purl": "pkg:generic\/x@1", "hashes": [{"alg": "SHA-256", "content": "'"$(printf 'a%.0s' $(seq 1 64))"'"}]/'), {\"name\": \"bomlens:yocto-recipe\", \"value\": \"media-daemon\"}, {\"name\": \"bsi:component:executable\", \"value\": \"executable\"}]}]}")"
[ "$rc" = 3 ] && grep -qF "component #1 'x': hashes is taken from the Yocto build for the packages of recipe 'media-daemon'; remove it" "$WORK/yr7.bom.json.log" \
  && grep -qF "component #1 'x': purl is taken from the Yocto build" "$WORK/yr7.bom.json.log" \
  && grep -qF "component #1 'x': bsi:component:executable describes one file, and recipe 'media-daemon' installs packages of files; remove it" "$WORK/yr7.bom.json.log" \
    && pass "fields the build decides (hashes, purl) and one-file properties are refused on a recipe declaration" || fail "build fields: exit $rc" "$(cat "$WORK/yr7.bom.json.log")"
rc="$(yrefuse yr8 "$YC, {\"name\": \"bomlens:yocto-recipe\", \"value\": \"media-daemon\"}]}, {\"type\": \"application\", \"name\": \"y\", \"properties\": [{\"name\": \"bomlens:origin\", \"value\": \"first-party\"}, {\"name\": \"bomlens:yocto-recipe\", \"value\": \"media-daemon\"}]}]}")"
[ "$rc" = 3 ] && grep -qF "recipe 'media-daemon' is declared twice (yr8.cdx.json and yr8.cdx.json); keep it in one place" "$WORK/yr8.bom.json.log" \
    && pass "a recipe declared twice is refused" || fail "twice: exit $rc" "$(yerr yr8)"
rc="$(yrefuse yr9 "$YC, {\"name\": \"bomlens:yocto-recipe\", \"value\": \"../x\"}]}]}")"
[ "$rc" = 3 ] && grep -qF "component #1 'x': bomlens:yocto-recipe '../x' is not a recipe name" "$WORK/yr9.bom.json.log" \
    && pass "a recipe value that is not a recipe name is refused" || fail "recipe name: exit $rc" "$(yerr yr9)"
# A component with no recipe and no build output (a blob the image loads at
# run time) is added in a Yocto build as anywhere else.
rc="$(yrefuse yr10 '{"bomFormat": "CycloneDX", "components": [{"type": "firmware", "name": "modem-blob", "version": "5", "supplier": {"name": "M"}, "properties": [{"name": "bomlens:origin", "value": "third-party"}]}]}')"
[ "$rc" = 0 ] && [ "$(jq -r '[.components[] | select(.name == "modem-blob")] | length' "$WORK/yr10.bom.json")" = 1 ] \
  && [ "$(jq -r '.metadata.component["bom-ref"] as $r | [.dependencies[] | select(.ref == $r) | .dependsOn[]] | index("declared:modem-blob@5") != null' "$WORK/yr10.bom.json")" = true ] \
    && pass "a component with neither a recipe nor a file is added to a Yocto build's SBOM and linked from the image" \
    || fail "blob in yocto: exit $rc" "$(cat "$WORK/yr10.bom.json.log")"

echo "== Yocto: through entrypoint.sh (ANALYZE, as a build directory scan runs it) =="
# run_yocto <name> <5x|6x|manifests> [VAR=value ...]: prints the exit code;
# the output folder is $WORK/<name>.out.
run_yocto() {
    local name="$1" shape="$2" out="$WORK/$1.out" rc=0 input
    shift 2
    mkdir -p "$out"
    if [ "$shape" = manifests ]; then input="YOCTO_BUILD_DIR=$YFIX/build-manifests"; else input="ANALYZE_SBOM=$YFIX/spdx3-$shape-image.json"; fi
    ( cd "$out" && env PATH="$WORK/bin:$PATH" MODE=ANALYZE PROJECT_NAME=ExampleImage PROJECT_VERSION=1.0 \
        HOST_OUTPUT_DIR="$out" BOMLENS_LIBDIR="$LIB" "$input" YOCTO_FROM_BUILD=true \
        UPLOAD_ENABLED=false GENERATE_SECURITY=false GENERATE_NOTICE=false DEEP_CVE=false SECURITY_ENRICH=false \
        ENRICH_EOL=false ENRICH_MALICIOUS=false ENRICH_STALENESS=false LICENSE_REGISTRY=false "$@" bash "$ENTRY" ) > "$out.log" 2>&1 || rc=$?
    printf '%s' "$rc"
}
# What a supplier passes for BSI TR-03183-2: --sbom-author, --supplier, --license.
YBSI=(CONFORMANCE_PROFILE=bsi-tr-03183-2 SBOM_AUTHOR="Example Corp <sbom@example.com>"
      PRODUCT_SUPPLIER="Example Corp <https://example.com>" PROJECT_LICENSE=LicenseRef-ExampleCorp-Proprietary)
for shape in 5x 6x manifests; do
    rc="$(run_yocto "ye$shape" "$shape" DECLARED_COMPONENTS_FILES="$YDECL" DECLARED_COMPONENTS_LABELS=sbom-declared.cdx.json "${YBSI[@]}")"
    O="$WORK/ye$shape.out"
    F="$O/ExampleImage_1.0_bom.json"
    [ "$rc" = 0 ] && [ "$(step "$O")" = '{"status":"ok","reason":null,"counts":{"components":3}}' ] \
      && [ "$(jq -r '[.components[] | select(any(.properties[]?; .name == "bomlens:yocto-recipe")) | .name] | sort | join(",")' "$F")" = "media-daemon,media-daemon-cli,vendor-dsp-firmware" ] \
        && pass "$shape: the declared-components step runs for a Yocto build and its packages reach the final SBOM" \
        || fail "$shape through entrypoint: exit $rc, step $(step "$O")" "$(grep -E 'ERROR|declared' "$O.log" | head -5)"
    cp "$F" "$WORK/yocto-final-$shape.json" 2>/dev/null
done
# The BSI rows for the declared packages. 6.1 hashes every file with SHA-512;
# the 5.x document has SHA-256 only and the manifests list no files, which the
# report says are not in the source SBOM. No Yocto record gives the file
# properties.
ybsi() {  # <shape> <row id>: status|missing
    jq -r --arg id "$2" '.checks[] | select(.id == $id) | "\(.status)|\(.missing | sort | join(";"))"' "$WORK/ye$1.out/ExampleImage_1.0_conformance.json" 2>/dev/null
}
NOSRC3="media-daemon-cli@3.1.0 (not in the source SBOM);media-daemon@3.1.0 (not in the source SBOM);vendor-dsp-firmware@7.2 (not in the source SBOM)"
[ "$(ybsi 6x bsi-declared-sha512)" = "pass|" ] && [ "$(ybsi 6x bsi-declared-filename)" = "pass|" ] \
  && [ "$(ybsi 6x bsi-declared-file-properties)" = "warn|$NOSRC3" ] \
  && [ "$(ybsi 6x bsi-declared-creator)" = "pass|" ] && [ "$(ybsi 6x bsi-declared-license)" = "pass|" ] && [ "$(ybsi 6x bsi-declared-name-version)" = "pass|" ] \
    && pass "6x: SHA-512 and file names come from the build's file hashes; file properties are not in the source SBOM" \
    || fail "6x bsi rows" "$(jq -c '[.checks[] | select(.id | startswith("bsi-declared")) | [.id, .status, .missing]]' "$WORK/ye6x.out/ExampleImage_1.0_conformance.json" 2>&1)"
[ "$(ybsi 5x bsi-declared-sha512)" = "warn|$NOSRC3" ] && [ "$(ybsi 5x bsi-declared-filename)" = "pass|" ] \
  && [ "$(ybsi manifests bsi-declared-sha512)" = "warn|$NOSRC3" ] && [ "$(ybsi manifests bsi-declared-filename)" = "warn|$NOSRC3" ] \
    && pass "5x and manifests: the SHA-512 (and with no file list the file name) is reported as not in the source SBOM, a warning" \
    || fail "5x/manifests bsi rows" "$(ybsi 5x bsi-declared-sha512) / $(ybsi manifests bsi-declared-filename)"
for shape in 5x 6x manifests; do
    [ "$(jq -r '[.checks[] | select(.id | startswith("bsi-declared")) | select(.status == "fail") | .id] | join(",")' "$WORK/ye$shape.out/ExampleImage_1.0_conformance.json")" = "" ] \
        && pass "$shape: no declared-component BSI row fails" \
        || fail "$shape failing declared rows" "$(jq -c '[.checks[] | select(.id | startswith("bsi-declared")) | select(.status == "fail") | [.id, .missing]]' "$WORK/ye$shape.out/ExampleImage_1.0_conformance.json")"
done

echo "== Yocto: an SBOM read from a build directory is stamped as a generated one =="
# YOCTO_FROM_BUILD (the CLI and the web server set it only for a document or
# manifests found in a build directory): the SBOM is this scan's, so its
# document metadata and image root are completed, and with --sbom-author,
# --supplier and --license every required BSI row passes.
for shape in 6x manifests; do
    C="$WORK/ye$shape.out/ExampleImage_1.0_conformance.json"
    [ "$(jq -r .result "$C")" = pass ] \
      && [ "$(jq -r '[.checks[] | select(.required and .status == "fail") | .id] | join(",")' "$C")" = "" ] \
      && [ "$(jq -r '[.checks[] | select(.id == "bsi-sbom-creator" or .id == "bsi-dependency-graph" or .id == "bsi-primary-component") | .status] | join(",")' "$C")" = "pass,pass,pass" ] \
        && pass "$shape: bsi-tr-03183-2 passes, with the SBOM creator, the dependency graph and the primary component met" \
        || fail "$shape bsi result" "$(jq -c '[.result, (.checks[] | select(.required and .status != "pass") | [.id, .status, .detail])]' "$C")"
done
F="$WORK/ye6x.out/ExampleImage_1.0_bom.json"
[ "$(jq -c '.metadata | [.component["bom-ref"], .component.name, .component.version, .component.supplier.url[0], .component.licenses[0].license.name, .component.licenses[0].license.acknowledgement, .authors[0].email, .lifecycles[0].phase, ([.tools.components[].name] | index("BomLens") != null), .timestamp]' "$F")" \
    = '["yocto-image:example-image@1.0","example-image","1.0","https://example.com","LicenseRef-ExampleCorp-Proprietary","concluded","sbom@example.com","build",true,"2026-10-01T00:00:00Z"]' ] \
    && pass "6x: the image keeps its name and gets a bom-ref, the --version, --supplier and --license (concluded); the document gets the author, BomLens and the build phase, and keeps the build's creation time" \
    || fail "6x stamped metadata" "$(jq -c .metadata "$F")"
[ "$(jq -c '.metadata.component["bom-ref"] as $r | [.dependencies[] | select(.ref == $r) | .dependsOn | sort] | first' "$F")" = "$(jq -c '[.components[]["bom-ref"]] | sort' "$F")" ] \
  && [ "$(jq -c "$UNREACHED" "$F")" = "[]" ] \
    && pass "6x: the image depends on every installed package, so the graph reaches them all" \
    || fail "6x root edges" "$(jq -c '.dependencies' "$F")"
FM="$WORK/yemanifests.out/ExampleImage_1.0_bom.json"
[ "$(jq -r '.metadata.timestamp // "" | test("^20[0-9][0-9]-")' "$FM")" = true ] && [ "$(jq -c "$UNREACHED" "$FM")" = "[]" ] \
    && pass "manifests: a timestamp is written (the manifests carry none) and the graph reaches every package" \
    || fail "manifests stamped" "$(jq -c '[.metadata.timestamp, .metadata.component]' "$FM")"
# The same document passed with --analyze on its own is someone else's SBOM:
# none of it is stamped, whatever options are given.
rc="$(run_yocto yerecv 6x YOCTO_FROM_BUILD=false "${YBSI[@]}")"
FR="$WORK/yerecv.out/ExampleImage_1.0_bom.json"
[ "$rc" = 0 ] && [ "$(jq -c '.metadata | [.component["bom-ref"], .component.version, .component.supplier, .component.licenses, .authors, .lifecycles, ([(.tools.components // [])[].name] | index("BomLens"))]' "$FR")" = '[null,null,null,null,null,null,null]' ] \
  && [ "$(jq -r '.metadata.component as $m | [.dependencies[]? | select(.ref == ($m["bom-ref"] // "-"))] | length' "$FR")" = 0 ] \
  && ! grep -qF "[yocto-root]" "$WORK/yerecv.out.log" && ! grep -qF "[docmeta]" "$WORK/yerecv.out.log" \
    && pass "a Yocto document passed with --analyze (not from a build directory) is not stamped" \
    || fail "received document: exit $rc" "$(jq -c .metadata "$FR" 2>&1; grep -E 'yocto-root|docmeta' "$WORK/yerecv.out.log")"
# skt-submission: the first-party exemption from the PURL rows needs a
# supplier and a SHA-512, which a 6.1 build gives every file; on 5.x the
# in-house packages keep needing a purl, and the vendor's never get it.
for shape in 5x 6x; do
    run_yocto "ys$shape" "$shape" DECLARED_COMPONENTS_FILES="$YDECL" CONFORMANCE_PROFILE=skt-submission >/dev/null
done
YS6="$WORK/ys6x.out/ExampleImage_1.0_conformance.json"
YS5="$WORK/ys5x.out/ExampleImage_1.0_conformance.json"
[ "$(jq -c '.checks[] | select(.id == "first-party-exempt") | .missing | sort' "$YS6" 2>/dev/null)" = '["media-daemon-cli@3.1.0","media-daemon@3.1.0"]' ] \
  && ! jq -e 'any(.checks[]; .id == "first-party-exempt")' "$YS5" >/dev/null \
  && jq -e '[.checks[] | select(.id == "purl") | .missing[]] | index("media-daemon") != null' "$YS5" >/dev/null \
    && pass "skt-submission: 6.1 file SHA-512s exempt the in-house packages from the PURL rows; 5.x (SHA-256 only) leaves them needing a purl" \
    || fail "submission exemption" "$(jq -c '[.checks[] | select(.id == "purl" or .id == "first-party-exempt") | [.id, .missing]]' "$YS6" "$YS5" 2>&1)"

printf '%s\n' '{"bomFormat": "CycloneDX", "components": [{"type": "application", "name": "x", "properties": [{"name": "bomlens:origin", "value": "first-party"}, {"name": "bomlens:yocto-recipe", "value": "no-such-recipe"}]}]}' > "$WORK/ymiss.cdx.json"
rc="$(run_yocto yemiss 6x DECLARED_COMPONENTS_FILES="$WORK/ymiss.cdx.json" DECLARED_COMPONENTS_LABELS=layers/meta-example/sbom-declared.cdx.json)"
O="$WORK/yemiss.out"
[ "$rc" = 1 ] && [ "$(step "$O" | jq -r .status)" = failed ] \
  && grep -qF "[declared-components] ERROR: layers/meta-example/sbom-declared.cdx.json: component 'x': recipe 'no-such-recipe' (bomlens:yocto-recipe) built no package installed in this image" "$O.log" \
  && [ ! -f "$O/ExampleImage_1.0_bom.json" ] && [ -s "$O/ExampleImage_1.0_bom.refused.json" ] && [ ! -f "$O/ExampleImage_1.0_conformance.json" ] \
    && pass "a recipe the image does not install stops the Yocto scan (exit 1), naming the recipe, with the SBOM kept as _bom.refused.json" \
    || fail "missing recipe through entrypoint: exit $rc, step $(step "$O")" "$(tail -6 "$O.log"; ls "$O")"
rc="$(run_yocto yeplain 6x)"
[ "$rc" = 0 ] && [ "$(step "$WORK/yeplain.out")" = "null" ] \
    && pass "a Yocto build without --components runs no declaration step" || fail "no files: exit $rc" "$(tail -5 "$WORK/yeplain.out.log")"
# --components changes the SBOM, so a received one (--analyze, with no build
# directory: YOCTO_FROM_BUILD unset) is refused, a Yocto document included.
rc="$(run_yocto yerecvc 6x YOCTO_FROM_BUILD=false DECLARED_COMPONENTS_FILES="$YDECL")"
[ "$rc" = 1 ] && grep -qF "[ERROR] --components applies to a source scan and a Yocto build directory; spdx3-6x-image.json was passed with --analyze, and a received SBOM is not changed." "$WORK/yerecvc.out.log" \
  && [ ! -f "$WORK/yerecvc.out/ExampleImage_1.0_bom.json" ] \
    && pass "--components with a Yocto document passed with --analyze on its own is refused, and no SBOM is written" \
    || fail "received Yocto document with --components: exit $rc" "$(tail -4 "$WORK/yerecvc.out.log")"
mkdir -p "$WORK/yenot.out"
rc=0
( cd "$WORK/yenot.out" && env PATH="$WORK/bin:$PATH" MODE=ANALYZE PROJECT_NAME=Supplier PROJECT_VERSION=1 HOST_OUTPUT_DIR="$WORK/yenot.out" \
    BOMLENS_LIBDIR="$LIB" ANALYZE_SBOM="$ROOT_DIR/tests/fixtures/good-cyclonedx.json" UPLOAD_ENABLED=false GENERATE_SECURITY=false GENERATE_NOTICE=false \
    DEEP_CVE=false SECURITY_ENRICH=false ENRICH_EOL=false ENRICH_MALICIOUS=false ENRICH_STALENESS=false LICENSE_REGISTRY=false \
    DECLARED_COMPONENTS_FILES="$YDECL" bash "$ENTRY" ) > "$WORK/yenot.out.log" 2>&1 || rc=$?
[ "$rc" = 1 ] && grep -qF "[ERROR] --components applies to a source scan and a Yocto build directory; good-cyclonedx.json was passed with --analyze, and a received SBOM is not changed." "$WORK/yenot.out.log" \
    && pass "--components with any other received SBOM is refused" \
    || fail "non-Yocto analyze: exit $rc" "$(tail -4 "$WORK/yenot.out.log")"
# A build directory whose document no Yocto reader could read (the generic
# converter took it) has no packages to declare on.
mkdir -p "$WORK/yenot2.out"
rc=0
( cd "$WORK/yenot2.out" && env PATH="$WORK/bin:$PATH" MODE=ANALYZE PROJECT_NAME=Supplier PROJECT_VERSION=1 HOST_OUTPUT_DIR="$WORK/yenot2.out" \
    BOMLENS_LIBDIR="$LIB" ANALYZE_SBOM="$ROOT_DIR/tests/fixtures/good-cyclonedx.json" YOCTO_FROM_BUILD=true UPLOAD_ENABLED=false GENERATE_SECURITY=false GENERATE_NOTICE=false \
    DEEP_CVE=false SECURITY_ENRICH=false ENRICH_EOL=false ENRICH_MALICIOUS=false ENRICH_STALENESS=false LICENSE_REGISTRY=false \
    DECLARED_COMPONENTS_FILES="$YDECL" bash "$ENTRY" ) > "$WORK/yenot2.out.log" 2>&1 || rc=$?
[ "$rc" = 1 ] && grep -qF "[ERROR] --components applies to a source scan and a Yocto build directory; good-cyclonedx.json is not an SBOM a Yocto build wrote." "$WORK/yenot2.out.log" \
    && pass "--components with a build directory whose document is not a Yocto one is refused" \
    || fail "non-Yocto build document: exit $rc" "$(tail -4 "$WORK/yenot2.out.log")"
# The CLI refuses it before starting a container (needs a Docker engine to get
# that far).
cli_out="$(bash "$SCRIPT" --project x --version 1 --analyze "$YFIX/spdx3-6x-image.json" --components "$YDECL" 2>&1)"; cli_rc=$?
if printf '%s' "$cli_out" | grep -qF "Cannot reach the Docker engine"; then
    echo "  SKIP: scan-sbom.sh --analyze with --components (no Docker engine)"
else
    [ "$cli_rc" = 1 ] && printf '%s' "$cli_out" | grep -qF "[ERROR] --components cannot be used with --analyze: the SBOM passed there is received, and is not changed." \
        && pass "scan-sbom.sh refuses --components with --analyze" || fail "CLI --analyze with --components: exit $cli_rc" "$(printf '%s' "$cli_out" | tail -3)"
fi
# A --license CycloneDX has no field for is refused before the scan starts,
# with the helper the container uses.
cli_out="$(bash "$SCRIPT" --project x --version 1 --license "Proprietary" --target "$WORK/no-such-dir" 2>&1)"; cli_rc=$?
if printf '%s' "$cli_out" | grep -qF "Cannot reach the Docker engine"; then
    echo "  SKIP: scan-sbom.sh --license with free text (no Docker engine)"
else
    [ "$cli_rc" = 1 ] && printf '%s' "$cli_out" | grep -qF "[license] ERROR: the licence 'Proprietary' is not an SPDX license id" \
        && pass "scan-sbom.sh refuses a free-text --license before scanning" || fail "CLI free-text --license: exit $cli_rc" "$(printf '%s' "$cli_out" | tail -3)"
fi
# The image root of a Yocto build uses the same helper.
yocto_read yroot 6x
yroot_rc=0
PROJECT_LICENSE="Proprietary" bash "$LIB/stamp-yocto-root.sh" "$WORK/yroot.bom.json" > "$WORK/yroot.log" 2>&1 || yroot_rc=$?
PROJECT_LICENSE="mit or apache-2.0" PROJECT_VERSION=1 bash "$LIB/stamp-yocto-root.sh" "$WORK/yroot.bom.json" >/dev/null 2>&1
[ "$yroot_rc" = 1 ] && grep -qF "LicenseRef-Proprietary" "$WORK/yroot.log" \
  && [ "$(jq -c '.metadata.component.licenses' "$WORK/yroot.bom.json")" = '[{"expression":"mit OR apache-2.0","acknowledgement":"concluded"}]' ] \
    && pass "stamp-yocto-root.sh refuses a free-text --license and writes an expression as one" \
    || fail "yocto root licence: exit $yroot_rc" "$(cat "$WORK/yroot.log"; jq -c .metadata.component "$WORK/yroot.bom.json")"

echo "== Yocto: properties only the readers write cannot be declared =="
# bomlens:identifiedBy and the other reader properties are what mark a
# component as a package the build recorded; a declaration that carries one is
# refused in any scan, so it cannot pass a component of its own off as one.
P="$(new_project spoof)"
B="$(new_bom spoof)"
jq '.components[0].properties += [{"name": "bomlens:identifiedBy", "value": "yocto-spdx"}]' "$FIX/project/sbom-declared.cdx.json" > "$WORK/spoof.cdx.json"
rc="$(apply "$B" "$P" "$WORK/spoof.cdx.json")"
[ "$rc" = 3 ] && grep -qF "component #1 'media-daemon': bomlens:identifiedBy is written by the scan, not by a declaration; remove it" "$B.log" \
    && pass "a source declaration that claims bomlens:identifiedBy is refused" || fail "identifiedBy spoof: exit $rc" "$(cat "$B.log")"
rc="$(yrefuse yr11 "$YC, {\"name\": \"bomlens:yocto-recipe\", \"value\": \"media-daemon\"}, {\"name\": \"bomlens:layer\", \"value\": \"yocto\"}, {\"name\": \"bomlens:yocto:recipe\", \"value\": \"media-daemon\"}]}]}")"
[ "$rc" = 3 ] && grep -qF "component #1 'x': bomlens:layer is written by the scan, not by a declaration; remove it" "$WORK/yr11.bom.json.log" \
  && grep -qF "component #1 'x': bomlens:yocto:recipe is written by the scan, not by a declaration; remove it" "$WORK/yr11.bom.json.log" \
    && pass "a recipe declaration that carries bomlens:layer or bomlens:yocto:recipe is refused" || fail "reader props: exit $rc" "$(yerr yr11)"

echo "== Yocto: a package is matched only by the recipe the build recorded =="
# A plain declaration with the name of an installed package is refused: that
# package is declared by its recipe.
rc="$(yrefuse yr12 '{"bomFormat": "CycloneDX", "components": [{"type": "library", "name": "libz1", "version": "1.3.1", "supplier": {"name": "Z"}, "properties": [{"name": "bomlens:origin", "value": "third-party"}]}]}')"
[ "$rc" = 3 ] && grep -qF "yr12.cdx.json: component 'libz1': a package of that name is installed in the image by recipe 'zlib'; declare it by its recipe (bomlens:yocto-recipe = zlib) rather than adding it again" "$WORK/yr12.bom.json.log" \
    && pass "a plain declaration named like an installed package is refused, pointing to its recipe" || fail "duplicate name: exit $rc" "$(yerr yr12)"
# A package whose recipe the build did not record is not matched by its name.
yocto_read yunk 6x
jq '.components += [{"bom-ref": "urn:pkg:mystery", "type": "library", "name": "mystery", "version": "1",
      "properties": [{"name": "bomlens:layer", "value": "yocto"}, {"name": "bomlens:identifiedBy", "value": "yocto-spdx"}]}]' \
    "$WORK/yunk.bom.json" > "$WORK/yunk.tmp" && mv "$WORK/yunk.tmp" "$WORK/yunk.bom.json"
printf '%s\n' "$YC, {\"name\": \"bomlens:yocto-recipe\", \"value\": \"mystery\"}]}]}" > "$WORK/yunk.cdx.json"
rc="$(yocto_apply yunk "$WORK/yunk.cdx.json")"
[ "$rc" = 3 ] && grep -qF "component 'x': the build did not record which recipe built the installed package 'mystery', so recipe 'mystery' (bomlens:yocto-recipe) cannot be matched to it" "$WORK/yunk.log" \
    && pass "a package whose recipe the build did not record is not matched by name, and the refusal names it" \
    || fail "unknown recipe: exit $rc" "$(cat "$WORK/yunk.log")"
# The multilib and SDK variants of a recipe are recipes of their own: a
# declaration of zlib is not put on lib32-zlib's packages, and says so.
yocto_read yml 6x
jq '.components += [{"bom-ref": "urn:pkg:lib32-libz1", "type": "library", "name": "lib32-libz1", "version": "1.3.1",
      "properties": [{"name": "bomlens:identifiedBy", "value": "yocto-spdx"}, {"name": "bomlens:yocto:recipe", "value": "lib32-zlib"}]}]' \
    "$WORK/yml.bom.json" > "$WORK/yml.tmp" && mv "$WORK/yml.tmp" "$WORK/yml.bom.json"
printf '%s\n' '{"bomFormat": "CycloneDX", "components": [{"type": "library", "name": "zlib", "supplier": {"name": "Z"}, "properties": [{"name": "bomlens:origin", "value": "third-party"}, {"name": "bomlens:yocto-recipe", "value": "zlib"}]}]}' > "$WORK/yml.cdx.json"
rc="$(yocto_apply yml "$WORK/yml.cdx.json")"
[ "$rc" = 0 ] && grep -qF "WARN: yml.cdx.json: component 'zlib': recipe 'lib32-zlib' also installed packages in this image; a declaration of 'zlib' does not cover them, so declare that recipe separately" "$WORK/yml.log" \
  && [ "$(jq -r '[.components[] | select(any(.properties[]?; .name == "bomlens:yocto-recipe")) | .name] | join(",")' "$WORK/yml.bom.json")" = "libz1" ] \
    && pass "a lib32- variant of a declared recipe is not covered, and a warning names it" \
    || fail "multilib: exit $rc" "$(cat "$WORK/yml.log")"

echo "== Yocto: file hashes the build wrote are taken only when they are hex digests of their algorithm =="
jq '(."@graph"[] | select(.spdxId == "urn:file:media-daemon:1") | .verifiedUsing) =
      [{"type": "Hash", "algorithm": "sha256", "hashValue": ("0x" + ("a" * 62))},
       {"type": "Hash", "algorithm": "sha512", "hashValue": ("a" * 64)}]
    | (."@graph"[] | select(.spdxId == "urn:file:media-daemon:2") | .verifiedUsing) =
      [{"type": "Hash", "algorithm": "sha256", "hashValue": ("z" * 64)},
       {"type": "Hash", "algorithm": "sha1", "hashValue": ("A" * 40)}]' "$YFIX/spdx3-6x-image.json" > "$WORK/yhex.spdx.json"
YOCTO_FILES_OUT="$WORK/yhex.files.json" python3 -I "$LIB/parse-yocto-spdx.py" "$WORK/yhex.spdx.json" "$WORK/yhex.bom.json" >/dev/null 2>&1
[ "$(jq -c '[.files["urn:pkg:media-daemon"][] | [.name, [.hashes[] | .alg + ":" + (.content | length | tostring)]]]' "$WORK/yhex.files.json")" \
    = '[["usr/bin/media-daemon",[]],["etc/media-daemon.conf",["SHA-1:40"]]]' ] \
  && [ "$(jq -r '.files["urn:pkg:media-daemon"][1].hashes[0].content' "$WORK/yhex.files.json")" = "$(printf 'a%.0s' $(seq 1 40))" ] \
    && pass "a 0x prefix, a non-hex digit or a length other than the algorithm's drops the hash; a valid one is kept in lower case" \
    || fail "hex digests" "$(jq -c '.files["urn:pkg:media-daemon"]' "$WORK/yhex.files.json")"

if [ "${BOMLENS_CDX_SCHEMA:-}" = "1" ] || command -v cyclonedx >/dev/null 2>&1 || [ -n "${CYCLONEDX_CLI:-}" ]; then
    mkdir -p "$WORK/cdx"
    cp "$WORK/y5x.bom.json" "$WORK/cdx/yocto-5x.json"
    cp "$WORK/y6x.bom.json" "$WORK/cdx/yocto-6x.json"
    cp "$WORK/ym.bom.json" "$WORK/cdx/yocto-manifests.json"
    for shape in 5x 6x manifests; do
        cp "$WORK/yocto-final-$shape.json" "$WORK/cdx/yocto-final-$shape.json"
    done
    cp "$WORK/ok.bom.json" "$WORK/cdx/declared.json"
    cp "$WORK/multi.bom.json" "$WORK/cdx/multi.json"
    cp "$WORK/deps.bom.json" "$WORK/cdx/deps.json"
    cp "$WORK/distu.bom.json" "$WORK/cdx/distu.json"
    cp "$WORK/colon.bom.json" "$WORK/cdx/colon.json"
    cp "$WORK/e5.out/MediaSuite_3.1.0_bom.json" "$WORK/cdx/bsi-final.json"
    cp "$WORK/e1.out/MediaSuite_3.1.0_bom.json" "$WORK/cdx/final.json"
    if cdxout=$(bash "$ROOT_DIR/scripts/check-cdx-schema.sh" "$WORK"/cdx/*.json 2>&1); then
        pass "SBOMs with declared components validate against the CycloneDX 1.6 schema"
    else
        fail "an SBOM with declared components fails the CycloneDX schema" "$cdxout"
    fi
else
    echo "  SKIP: CycloneDX CLI not available (set BOMLENS_CDX_SCHEMA=1 to download the pinned one)"
fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[ "$FAIL" -eq 0 ]
