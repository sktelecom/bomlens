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
# --components files. Needs bash 4+, jq and python3.
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
[ "$(prop "$D" bsi:component:executable)/$(prop "$D" bsi:component:archive)" = "executable/no archive" ] \
  && [ "$(prop "$C" bsi:component:executable)/$(prop "$C" bsi:component:archive)" = "executable/no archive" ] \
    && pass "an ELF and a PE executable are marked executable and not an archive" \
    || fail "executable properties" "$D $C"
[ -z "$(prop "$D" bsi:component:structured)" ] && pass "bsi:component:structured is not written" || fail "structured written"
[ "$(prop "$D" bomlens:origin) $(prop "$C" bomlens:origin) $(prop "$H" bomlens:origin)" = "first-party first-party third-party" ] \
    && pass "bomlens:origin is kept as declared" || fail "origins" "$D $H"
[ "$(printf '%s' "$D" | jq -r .version) $(printf '%s' "$C" | jq -r .version)" = "3.1.0 2.0.1" ] \
    && pass "a first-party component with no version takes the product's; a declared one is kept" \
    || fail "versions" "$D $C"
[ "$(printf '%s' "$H" | jq -c '[.version, (.hashes // [] | length), (.properties | length), .supplier.name, .licenses[0].license.id]')" \
    = '["4.2.0",0,1,"Example Chip Vendor","BSD-3-Clause"]' ] \
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
    = '[0,["bomlens:origin","bomlens:artifact","bomlens:artifact"],["out/bin/media-plugin.so","out/pkg/media-plugins.tar.gz"]]' ] \
    && pass "each output is a nested file component; the declared one carries no hashes of its own" \
    || fail "multi-artifact: exit $rc" "$M $(cat "$B.log")"
[ "$(printf '%s' "$M" | jq -c '[.components[] | [.type, .version, .supplier.name, ([.hashes[].alg] | join("+")),
        ([.properties[] | select(.name | startswith("bsi:")) | .value] | join("|")), .["bom-ref"]]]')" \
    = '[["file","3.1.0","Example Corp","SHA-512+SHA-256","media-plugin.so|executable|no archive","declared:media-plugins@3.1.0#out/bin/media-plugin.so"],["file","3.1.0","Example Corp","SHA-512+SHA-256","media-plugins.tar.gz|non-executable|archive","declared:media-plugins@3.1.0#out/pkg/media-plugins.tar.gz"]]' ] \
    && pass "a nested file has its own hashes, file name and properties (a shared object is executable, a .tar.gz an archive)" \
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
{
    printf '{"bomFormat": "CycloneDX", "components": ['
    sep=""
    for f in a.zip a.xz a.tar libx.a macho universal Main.class object.o notes.txt; do
        printf '%s{"type": "file", "name": "%s", "properties": [{"name": "bomlens:origin", "value": "first-party"}, {"name": "bomlens:artifact", "value": "k/%s"}]}' "$sep" "$f" "$f"
        sep=","
    done
    printf ']}'
} > "$WORK/kinds.cdx.json"
B="$(new_bom kinds)"
rc="$(apply "$B" "$P" "$WORK/kinds.cdx.json")"
got="$(jq -r '[.components[] | select(.properties[]?.name == "bsi:component:filename")
              | "\(.name)=\([.properties[] | select(.name == "bsi:component:executable" or .name == "bsi:component:archive") | .value] | join("/"))"] | join(" ")' "$B")"
want="a.zip=non-executable/archive a.xz=non-executable/archive a.tar=non-executable/archive libx.a=non-executable/archive macho=executable/no archive universal=executable/no archive Main.class=non-executable/no archive object.o=non-executable/no archive notes.txt=non-executable/no archive"
[ "$rc" = 0 ] && [ "$got" = "$want" ] \
    && pass "zip, xz, tar and ar are archives; Mach-O (also universal) is executable; a Java class, an object file and text are neither" \
    || fail "file kinds: exit $rc" "$got"

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
    jq '.metadata.component.name = "project" | .metadata.component.version = "latest"' "$FIX/stage1-bom.json" > "$out/MediaSuite_3.1.0_bom.json"
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
    = '["3.1.0",["SHA-256","SHA-512"],["media-daemon","executable","no archive"]]' ] \
    && pass "the declared fields survive normalize and the rest of the pipeline" \
    || fail "final SBOM component" "$D"
[ "$(jq -c "$UNREACHED" "$F")" = "[]" ] && pass "the final SBOM's graph reaches every component from the product" \
    || fail "not reached in the final SBOM: $(jq -c "$UNREACHED" "$F")"
[ "$(jq -r '.metadata.component.name + "@" + .metadata.component.version' "$F")" = "MediaSuite@3.1.0" ] \
    && pass "the product is the stamped one" || fail "product $(jq -c .metadata.component "$F")"

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
rc="$(run_entry e5 "$P")"
[ "$rc" = 1 ] && grep -qF "sbom-declared.cdx.json (at the scan target root): leads outside the scan target through a symbolic link" "$WORK/e5.out.log" \
    && pass "a default file that links out of the scan target is refused" \
    || fail "linked default file: exit $rc" "$(tail -5 "$WORK/e5.out.log")"

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
fi
grep -q '^        --components) COMPONENTS_FILES+=' "$SCRIPT" && grep -q '^  --components <file>' "$SCRIPT" \
    && pass "--components is parsed (repeatable) and in the help" || fail "--components parsing or help missing"
grep -q '(components_run)' "$SCRIPT" && pass "the post-process container gets the mounts" || fail "components_run is not used"

if [ "${BOMLENS_CDX_SCHEMA:-}" = "1" ] || command -v cyclonedx >/dev/null 2>&1 || [ -n "${CYCLONEDX_CLI:-}" ]; then
    mkdir -p "$WORK/cdx"
    cp "$WORK/ok.bom.json" "$WORK/cdx/declared.json"
    cp "$WORK/multi.bom.json" "$WORK/cdx/multi.json"
    cp "$WORK/deps.bom.json" "$WORK/cdx/deps.json"
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
