#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-firmware-unpack.sh — No-Docker unit tests for the firmware unpack and
# component-merge stage of scan-firmware.sh.
#
# The defects these guard:
#   - cve-bin-tool writes one placeholder component named after the directory it
#     scanned, whether or not it identified anything. Shipping it turned "found
#     nothing" into "found one component", which reads as a result.
#   - the failure message named the whole unpacker chain regardless of which
#     tools were installed, sending people after a format problem when the tool
#     simply was not in the image.
#   - Windows installers (NSIS) went unextracted even though 7z, which reads
#     them, was already in the image.
#
# The merge filter is lifted out of the shipping script rather than
# re-implemented, from its `name() {` line to the first line that is exactly `}`.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/docker/lib/scan-firmware.sh"
FIX="$ROOT_DIR/tests/fixtures"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is required for firmware unpack unit tests"; exit 1
fi

body="$(awk '
    /^comps_of\(\) \{/ { inside = 1 }
    inside { print }
    inside && $0 == "}" { exit }
' "$SCRIPT")"
if [ -z "$body" ]; then
    echo "[ERROR] could not lift comps_of out of scan-firmware.sh (was it renamed?)"; exit 1
fi
eval "$body"

echo "== an identification that found nothing reports nothing =="

n=$(comps_of "$FIX/cvebintool-placeholder-only.json" | jq 'length')
if [ "$n" = "0" ]; then
    pass "a scan with only the cve-bin-tool placeholder yields no components"
else
    fail "the placeholder survived into the component list" "got $n component(s)"
fi

echo "== real identifications are kept, and their names cleaned =="

got="$(comps_of "$FIX/cvebintool-identified.json")"
n=$(printf '%s' "$got" | jq 'length')
if [ "$n" = "4" ]; then
    pass "the placeholder is dropped and the real components are kept"
else
    fail "unexpected component count" "expected 4, got $n: $got"
fi

# The second pass names its output `<image>.extracted/`, so the same file arrives
# both as `bin/openssl` and as `sqfs.img.extracted/bin/openssl`. Strip both that
# marker and unblob's `_extract/`, or the two survive as separate components with
# different dedupe keys.
same=$(printf '%s' "$got" | jq '[.[] | select(.name == "bin/openssl")] | length')
if [ "$same" = "2" ]; then
    pass "the second pass's own directory name is stripped too"
else
    fail "an .extracted/ prefix survived into a component name" \
         "both entries should reduce to bin/openssl; got $same of 2"
fi

if printf '%s' "$got" | jq -e 'any(.[]; .name == "openssl" and .version == "1.1.1v")' >/dev/null; then
    pass "an identified library keeps its name and version"
else
    fail "openssl 1.1.1v missing from the merged components" "$got"
fi

# cve-bin-tool names a file it cannot attribute by its full path on disk, which
# at that point is the throwaway unpack directory. Only the path inside the
# firmware is meaningful to anyone reading the delivered SBOM.
if printf '%s' "$got" | jq -e 'any(.[]; .name == "usr/bin/busybox")' >/dev/null; then
    pass "an unattributed binary is named by its path inside the firmware"
else
    fail "the scanning machine's temp path leaked into the component name" "$got"
fi

if printf '%s' "$got" | jq -e 'any(.[]; .name | startswith("CVEBINTOOL"))' >/dev/null; then
    fail "a CVEBINTOOL placeholder is still present"
else
    pass "no CVEBINTOOL placeholder in the merged output"
fi

echo "== the unpacker chain reaches Windows installer formats =="

# 7z reads NSIS and Inno Setup installers, which unblob does not unpack. It is
# already in the image, so its absence from the chain was the whole reason a
# supplier's product installer produced an empty SBOM.
if grep -q 'command -v 7z' "$SCRIPT"; then
    pass "7z is part of the unpacker fallback chain"
else
    fail "7z is missing from the unpacker fallback chain"
fi

# The chain must stay ordered: format-aware unpackers first, 7z last, because 7z
# will also carve fragments out of files it does not really understand.
unblob_at=$(grep -n 'command -v unblob' "$SCRIPT" | head -1 | cut -d: -f1)
sevenzip_at=$(grep -n 'command -v 7z' "$SCRIPT" | head -1 | cut -d: -f1)
if [ -n "$unblob_at" ] && [ -n "$sevenzip_at" ] && [ "$unblob_at" -lt "$sevenzip_at" ]; then
    pass "7z runs only after the format-aware unpackers"
else
    fail "7z is not ordered after unblob" "unblob at ${unblob_at:-?}, 7z at ${sevenzip_at:-?}"
fi

echo "== the failure message names only what was actually run =="

# Naming a tool that is not installed sends the reader after a format problem
# that does not exist.
if grep -q 'tried: ' "$SCRIPT"; then
    pass "the message reports the unpackers that ran"
else
    fail "the message does not report which unpackers ran"
fi

for absent in BANG bang-scanner; do
    if grep -q "no unpacker produced files.*$absent" "$SCRIPT"; then
        fail "the failure message still names $absent, which the image does not install"
    else
        pass "the failure message does not claim $absent was tried"
    fi
done

echo "== a carved-but-unopened filesystem image is opened on a second pass =="

# unblob carves a squashfs out of a firmware blob but cannot always extract it,
# and that carve counts as "unblob produced files" — so the fallback chain is
# skipped and the pipeline catalogs one opaque blob. Measured on an OpenWrt
# rootfs: 1 component before the second pass, 199 after. The checks below guard
# the two ways this silently regresses.
if grep -q 'extract_carved_filesystems' "$SCRIPT"; then
    pass "the carved-filesystem pass exists"
else
    fail "the carved-filesystem pass is gone"
fi

# The whole point is that it runs even though unblob reported success. Gating it
# on `unpacked = 0` would restore the defect while leaving the function in place.
carve_line=$(grep -n 'while \[ "\$carve_round"' "$SCRIPT" | head -1 | cut -d: -f1)
if [ -n "$carve_line" ]; then
    guard=$(sed -n "${carve_line}p" "$SCRIPT")
    case "$guard" in
        *'unpacked'*) fail "the carved-filesystem pass is gated on the unpack result" "$guard" ;;
        *) pass "the carved-filesystem pass runs regardless of the unpack result" ;;
    esac
else
    fail "could not find the carved-filesystem loop"
fi

# Nested images need more than one pass, but an unbounded loop on a crafted image
# would never end.
if sed -n "${carve_line:-1}p" "$SCRIPT" | grep -qE '\-lt [0-9]+'; then
    pass "the retry loop is bounded"
else
    fail "the retry loop has no bound"
fi

# When the extractor is missing the function must report "no progress", or the
# caller loops doing nothing and marks the firmware as unpacked.
if awk '/^extract_carved_filesystems\(\) \{/,/^}/' "$SCRIPT" \
   | grep -q 'command -v unsquashfs .* || return 1'; then
    pass "a missing extractor reports no progress"
else
    fail "a missing extractor does not report no progress" \
         "the caller would mark the firmware unpacked and skip the warning"
fi

echo "== an empty result says why it is empty =="

# Seven vendor firmware images were scanned; three returned zero components, for
# three different reasons — encrypted payload, a squashfs variant the bundled
# extractor rejects, and a tree that unpacked but matched no signature. Reporting
# all three as a bare "components=0" leaves the reader unable to tell a clean scan
# from a failed one, and only one of the three is theirs to act on.
if grep -q 'no components identified' "$SCRIPT"; then
    pass "an empty result is called out"
else
    fail "an empty result is reported as a bare component count"
fi

# The distinguishing input is the list of images that were found but not opened.
# Drop the recording and every empty result collapses to the same generic message.
if awk '/^extract_carved_filesystems\(\) \{/,/^}/' "$SCRIPT" | grep -q 'CARVED_UNOPENED='; then
    pass "images that could not be opened are recorded, not just skipped"
else
    fail "an unopenable filesystem image is skipped without a trace" \
         "every empty result would then report the same generic cause"
fi

# The reason must come from the extractor, not from a guess. Guessing once shipped
# a message telling readers to find sasquatch when unsquashfs was actually refusing
# to write an SELinux attribute — a one-flag problem, sent in the wrong direction.
if grep -q '2>"\$err"' "$SCRIPT"; then
    pass "the extractor's own error output is captured"
else
    fail "the extractor's error output is discarded" \
         "the cause can then only be guessed at"
fi

if awk '/^extract_carved_filesystems\(\) \{/,/^}/' "$SCRIPT" | grep -q 'reason='; then
    pass "the recorded entry carries the reason, not just the path"
else
    fail "no reason is recorded alongside the unopenable image"
fi

# unsquashfs restores extended attributes by default and treats a refused
# security.selinux write as fatal, aborting mid-extraction. Both call sites must
# turn that off or a standard squashfs comes out empty.
# Every extractor invocation, including the one that runs the tool through a
# variable, has to pass the flag — a new call site without it aborts the same way.
calls=$(grep -cE '_tmo (unsquashfs|sasquatch|"\$tool")' "$SCRIPT")
noxattr=$(grep -cE '_tmo (unsquashfs|sasquatch|"\$tool") -no-xattrs' "$SCRIPT")
if [ "$noxattr" -ge 1 ] && [ "$noxattr" -eq "$calls" ]; then
    pass "every extractor call disables extended-attribute restore ($noxattr/$calls)"
else
    fail "an extractor call still restores extended attributes" \
         "$noxattr of $calls calls pass -no-xattrs; the others abort on SELinux writes"
fi

# Three branches, so the reader gets a cause rather than a catch-all.
branches=$(sed -n '/no components identified/,/^fi$/p' "$SCRIPT" | grep -cE '^\s*(if|elif)')
if [ "${branches:-0}" -ge 3 ]; then
    pass "the diagnostic distinguishes at least three causes"
else
    fail "the diagnostic does not distinguish the known causes" "found $branches branch(es)"
fi

echo "== a byte-swapped squashfs is still recognized as one =="

# `file` calls a vendor image with swapped magic plain "data". A Zyxel switch keeps
# its whole system in such an image, so trusting `file` meant walking past a 3.9 MB
# root filesystem and cataloguing the boot initramfs instead — 1 component against
# the 17 the vendor declares in its own notice.
fn="$(awk '/^is_squashfs_image\(\) \{/,/^}/' "$SCRIPT")"
if [ -n "$fn" ]; then
    pass "squashfs detection is a dedicated check"
else
    fail "is_squashfs_image is gone"
fi

if awk '/^extract_carved_filesystems\(\) \{/,/^}/' "$SCRIPT" | grep -q 'file -b'; then
    fail "the carve pass decides from \`file\` output again" \
         "a swapped-magic image reports as \"data\" and would be walked past"
else
    pass "the carve pass does not depend on \`file\` output"
fi

# All four arrangements: both endiannesses, each with and without 16-bit word swap.
for magic in 68737173 73717368 73687371 71736873; do
    if printf '%s' "$fn" | grep -q "$magic"; then
        pass "magic $magic accepted"
    else
        fail "magic $magic not accepted" "one of the four squashfs arrangements is missing"
    fi
done

echo "== the two passes' records of one component are merged, not both shipped =="

# syft's binary classifier and cve-bin-tool describe the same component
# differently: `application` with a purl against `library` with a CPE and none.
# Keyed on `.purl // name@version` those landed in different groups and both
# shipped. Measured on the vendor firmware corpus: busybox, curl and openssl were
# duplicated on every image that yielded components.
#
# The filter is lifted out of the shipping script rather than re-implemented.
# The invocation spans several lines (one --slurpfile each) before the quote that
# opens the filter, so skip forward to that quote rather than assuming line one.
merge_filter="$(awk '
    /^jq -n --slurpfile a "\$WORK\/pkg-comps.json"/ { inside = 1; next }
    inside && !started { if ($0 ~ /'"'"'$/) started = 1; next }
    started && /^'"'"' > "\$WORK\/merged.json"$/ { exit }
    started { print }
' "$SCRIPT")"
if [ -z "$merge_filter" ]; then
    echo "[ERROR] could not lift the merge filter out of scan-firmware.sh (was it renamed?)"; exit 1
fi

merged="$(jq -n --slurpfile a "$FIX/merge-pkg-comps.json" \
                --slurpfile b "$FIX/merge-bin-comps.json" \
                --slurpfile c <(echo '[]') --slurpfile d <(echo '[]') "$merge_filter")"

n=$(printf '%s' "$merged" | jq '[.[] | select(.name == "openssl" and .version == "1.0.2h")] | length')
if [ "$n" = "1" ]; then
    pass "one component described by both passes is reported once"
else
    fail "the same component is still reported twice" "openssl 1.0.2h appears $n time(s)"
fi

# The purl is what the CVE step matches on, so it has to survive the merge; the
# CPE and the other pass's file location are what a reader checks the claim with.
one="$(printf '%s' "$merged" | jq '[.[] | select(.name == "openssl" and .version == "1.0.2h")][0]')"
if printf '%s' "$one" | jq -e '.purl == "pkg:generic/openssl@1.0.2h" and (.cpe | length) > 0' >/dev/null; then
    pass "the merged record keeps the purl and the CPE"
else
    fail "the merged record lost the purl or the CPE" "$one"
fi

locs=$(printf '%s' "$one" | jq '[.evidence.occurrences[]?.location] | length')
if [ "$locs" = "1" ]; then
    pass "the location only one pass recorded is carried over"
else
    fail "an occurrence was dropped or duplicated" "got $locs location(s): $one"
fi

# Two versions of the same component at the same path are two findings, not one.
if printf '%s' "$merged" | jq -e 'any(.[]; .name == "openssl" and .version == "1.0.2r")' >/dev/null; then
    pass "a different version of the same component stays separate"
else
    fail "a distinct version was merged away"
fi

# enrich-os-context.py looks for exactly `operating-system` to give Trivy its OS
# context. Folding syft's distro record into the busybox binary would remove it.
os_n=$(printf '%s' "$merged" | jq '[.[] | select(.type == "operating-system")] | length')
if [ "$os_n" = "1" ]; then
    pass "the distro record survives the merge"
else
    fail "the operating-system component was merged away" \
         "Trivy loses its OS context; got $os_n"
fi

# `file` entries are the file listing, not components.
if printf '%s' "$merged" | jq -e 'any(.[]; .type == "file" and .name == "bin/openssl")' >/dev/null; then
    pass "file entries are left alone"
else
    fail "a file entry was merged into a component"
fi

# Left alone is not the same as passed through untouched. The two extraction
# passes hold the same rootfs twice, so one file arrives as two identical `file`
# entries; excluding them from the merge without deduping them ships both.
fn=$(printf '%s' "$merged" | jq '[.[] | select(.type == "file" and .name == "bin/openssl")] | length')
if [ "$fn" = "1" ]; then
    pass "an identical file entry from both extraction passes is reported once"
else
    fail "the same file is reported $fn time(s)" \
         "types excluded from the merge still have to be deduped among themselves"
fi

# Same name and version, two different purls: nothing here can tell whether those
# are one component or two, so they stay separate.
z=$(printf '%s' "$merged" | jq '[.[] | select(.name == "zlib")] | length')
if [ "$z" = "2" ]; then
    pass "two different purls under one name and version are not merged"
else
    fail "entries with different purls were merged" "expected 2 zlib entries, got $z"
fi

echo "== a component with no version left is still reported, and marked as such =="

# Signature identification only reports what it can read a version out of, so a
# component whose version string did not survive is missing from the SBOM
# entirely. On a Zyxel switch that is net-snmp, libradius and libtacplus — three
# of the seventeen the vendor declares in its own notice.
with_presence="$(jq -n --slurpfile a "$FIX/merge-pkg-comps.json" \
                       --slurpfile b "$FIX/merge-bin-comps.json" \
                       --slurpfile c "$FIX/elf-presence-comps.json" \
                       --slurpfile d <(echo '[]') "$merge_filter")"

if printf '%s' "$with_presence" | jq -e 'any(.[]; .name == "net-snmp")' >/dev/null; then
    pass "a component only the ELF structure proves is carried into the SBOM"
else
    fail "the presence-only component was dropped" "$with_presence"
fi

# It has to be marked. Without the grade it is an ordinary row with an empty
# version field, and a reader takes "0 vulnerabilities" as covering it.
if printf '%s' "$with_presence" | jq -e '
      [.[] | select(.name == "net-snmp")][0]
      | any(.properties[]?; .name == "bomlens:evidenceGrade" and .value == "presence-only")
   ' >/dev/null; then
    pass "the presence-only grade survives the merge"
else
    fail "the evidence grade was lost" "nothing downstream can then tell the two apart"
fi

# No version means no purl and no CPE. Attaching either would let a matcher pair
# the component with some other release's advisories.
if printf '%s' "$with_presence" | jq -e '
      [.[] | select(.name == "net-snmp")][0]
      | (has("version") | not) and (has("purl") | not) and (has("cpe") | not)
   ' >/dev/null; then
    pass "a presence-only component carries no version, purl or CPE"
else
    fail "a presence-only component carries an identifier" \
         "a versionless component with an identifier can be matched to the wrong advisory"
fi

# The evidence is the point: a reader has to be able to check the claim.
if printf '%s' "$with_presence" | jq -e '
      [.[] | select(.name == "net-snmp")][0].evidence.occurrences | length > 0
   ' >/dev/null; then
    pass "the file that proves it is recorded"
else
    fail "no evidence recorded for a presence-only component"
fi

# openssl is in the ELF list too, but cve-bin-tool read 1.0.2h out of a binary.
# Reporting both lists openssl twice, once without a version, which reads as two
# findings when it is one component described twice.
n=$(printf '%s' "$with_presence" | jq '[.[] | select(.name == "openssl")] | length')
if [ "$n" = "2" ]; then
    pass "a presence-only judgement yields to the versioned ones for the same component"
else
    fail "presence-only openssl was kept alongside the versioned findings" \
         "expected the two versioned entries (1.0.2h, 1.0.2r), got $n"
fi

if printf '%s' "$with_presence" | jq -e '
      any(.[]; .name == "openssl"
          and any(.properties[]?; .name == "bomlens:evidenceGrade"))' >/dev/null; then
    fail "the versioned openssl was marked presence-only"
else
    pass "the versioned entries keep their grade"
fi

echo "== the ELF reader is wired in and its dependency is declared =="

# A NEEDED entry with no library file behind it is a link-time name a vendor is
# free to reuse, and it leaves a reader nothing to check. MikroTik RouterOS lists
# `libubox.so` beside its own libumsg, liburadius, libucrypto and libuc++ — its
# own `libu*` family, not OpenWrt's libubox — and it was reported as ubox with an
# empty evidence list until the file was made a requirement.
if grep -q 'if not e\["files"\]' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "a NEEDED entry with no library file behind it is not reported"
else
    fail "a bare NEEDED entry can still produce a component" \
         "the claim would carry no evidence a reader can check"
fi


if [ -x "$ROOT_DIR/docker/lib/identify-elf-presence.py" ] || \
   [ -f "$ROOT_DIR/docker/lib/identify-elf-presence.py" ]; then
    pass "the ELF presence reader ships in lib/"
else
    fail "identify-elf-presence.py is missing"
fi

# readelf prints what it finds, and what it finds is attacker-supplied. A symbol
# name or section string that is not valid UTF-8 made the decode raise, and the
# exception escaped the whole pass — so one stray byte anywhere in a rootfs cost
# every judgement in the image, not just the file it came from. Measured on a
# switch OS image of some 38,000 files: the pass died and reported nothing.
if grep -qE 'text=True, *errors="replace"|errors="replace", *text=True' \
     "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "undecodable bytes in the reader's input do not abort the pass"
else
    fail "the ELF reader decodes strictly" \
         "one non-UTF-8 byte anywhere in the rootfs loses every judgement"
fi

# The behaviour, not just the flag: a stream carrying a byte that is not valid
# UTF-8 must be read to the end rather than raising partway.
if command -v python3 >/dev/null 2>&1; then
    if python3 - <<'PY'
import subprocess, sys, tempfile, os
fd, p = tempfile.mkstemp()
os.write(fd, b"File: x\nsym \xff\xfe bad\nFile: y\n")
os.close(fd)
try:
    proc = subprocess.Popen(["cat", p], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, errors="replace")
    n = sum(1 for _ in proc.stdout)
    proc.wait()
    sys.exit(0 if n == 3 else 1)
except UnicodeDecodeError:
    sys.exit(1)
finally:
    os.unlink(p)
PY
    then
        pass "a stream with an undecodable byte is read to the end"
    else
        fail "reading stopped at the undecodable byte"
    fi
fi

# readelf had been arriving as another package's dependency. That is how a
# runtime file goes missing from a release without any build step failing.
if grep -qE '^\s+lzop zstd lz4 liblzo2-2 zlib1g binutils' "$ROOT_DIR/docker/Dockerfile"; then
    pass "binutils is installed by name, not inherited"
else
    fail "binutils is not named in the firmware install list" \
         "readelf would then be present only by luck"
fi

if grep -q 'readelf --version' "$ROOT_DIR/docker/Dockerfile"; then
    pass "the build fails if readelf is not runnable"
else
    fail "no build gate on readelf"
fi

# A string search would report busybox's help text mentioning "readline" as
# evidence that readline is linked in. The reader must work off the dynamic
# section instead.
if grep -qE '"readelf".*"-d"' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "evidence comes from the ELF dynamic section, not from strings"
else
    fail "the reader does not read the dynamic section"
fi

# The digits in a SONAME are an ABI number. libcrypto.so.1.0.0 is not OpenSSL
# 1.0.0, and a wrong version draws another component's CVEs.
if grep -qE '"[^"]*":\s*"[^"]*[0-9]+\.[0-9]+' "$ROOT_DIR/docker/lib/elf-soname-map.json" \
   | grep -v '_comment'; then
    fail "the SONAME map carries a version" "filename digits are ABI numbers, not versions"
else
    pass "the SONAME map maps names only, never versions"
fi

echo "== a version cve-bin-tool's checkers do not match is still read =="

# Its checkers want a fixed string and regex per component: a three-digit
# requirement drops `FFmpeg version 4.1`, a CLI-only marker drops a library build.
with_verstr="$(jq -n --slurpfile a "$FIX/merge-pkg-comps.json" \
                     --slurpfile b "$FIX/merge-bin-comps.json" \
                     --slurpfile c "$FIX/elf-presence-comps.json" \
                     --slurpfile d "$FIX/version-string-comps.json" "$merge_filter")"

if printf '%s' "$with_verstr" | jq -e '
      any(.[]; .name == "net-tools" and .version == "1.60")' >/dev/null; then
    pass "a version string form the checkers miss reaches the SBOM"
else
    fail "the version-string judgement was dropped" "$with_verstr"
fi

# The string it was read from, or the claim cannot be checked.
if printf '%s' "$with_verstr" | jq -e '
      [.[] | select(.name == "net-tools")][0]
      | any(.properties[]?; .name == "bomlens:versionEvidence" and (.value | length) > 0)
   ' >/dev/null; then
    pass "the matched string is recorded as evidence"
else
    fail "no evidence string recorded for a version-string judgement"
fi

# net-tools has no product anywhere in the NVD CPE index, and five unrelated
# products are called hydra. Attaching a CPE would hand the component another
# project's advisories, so the table leaves it off and the SBOM says so.
if printf '%s' "$with_verstr" | jq -e '
      [.[] | select(.name == "net-tools")][0]
      | (has("cpe") | not)
        and any(.properties[]?; .name == "bomlens:cpeUnmapped" and .value == "true")
   ' >/dev/null; then
    pass "a component with no safe identifier carries none, and is marked"
else
    fail "an unmapped component was given an identifier or left unmarked"
fi

# The presence-only uclibc from the ELF pass and the versioned one from here are
# one component. The versioned judgement wins.
n=$(printf '%s' "$with_verstr" | jq '[.[] | select(.name == "uclibc")] | length')
if [ "$n" = "1" ]; then
    pass "a version found here supersedes the presence-only judgement"
else
    fail "uclibc is reported $n time(s)" "the presence-only entry should have yielded"
fi

# The two passes do not always spell a component the same way. A library is read
# from its SONAME, so the structural pass calls it what the file is called, while
# a signature checker calls it what the project is called. Measured on an Extreme
# EXOS image: `expat` from the ELF pass stood beside `libexpat 2.5.0`, and `zstd`
# beside `zstandard 1.5.2` — the versionless judgement surviving is exactly what
# the rule above exists to prevent, and comparing the names as written missed it.
forms_in="$(jq -n '[
  {type:"library", name:"expat",
   properties:[{name:"bomlens:evidenceGrade", value:"presence-only"}]},
  {type:"library", name:"zstd",
   properties:[{name:"bomlens:evidenceGrade", value:"presence-only"}]},
  {type:"library", name:"openssl",
   properties:[{name:"bomlens:evidenceGrade", value:"presence-only"}]}
]')"
forms_versioned="$(jq -n '[
  {type:"library", name:"libexpat", version:"2.5.0"},
  {type:"library", name:"zstandard", version:"1.5.2"},
  {type:"library", name:"busybox", version:"1.35.0"}
]')"
forms_out="$(jq -n --slurpfile a <(echo "$forms_versioned") \
                   --slurpfile b <(echo "$forms_in") \
                   --slurpfile c <(echo '[]') --slurpfile d <(echo '[]') "$merge_filter")"

for pair in expat:libexpat zstd:zstandard; do
    bare="${pair%%:*}"; full="${pair#*:}"
    n=$(printf '%s' "$forms_out" | jq --arg n "$bare" '[.[] | select(.name == $n)] | length')
    if [ "$n" = "0" ]; then
        pass "a presence-only $bare yields to the versioned $full"
    else
        fail "$bare survived beside $full" "the same component is reported twice"
    fi
done

# The versioned entries themselves must not be touched by the comparison.
if printf '%s' "$forms_out" | jq -e '
      ([.[] | select(.name == "libexpat" and .version == "2.5.0")] | length) == 1
      and ([.[] | select(.name == "zstandard" and .version == "1.5.2")] | length) == 1' >/dev/null; then
    pass "the versioned entries keep the names their producers gave them"
else
    fail "a versioned entry was renamed or dropped"
fi

# Written too loosely this would swallow a genuine presence-only finding. openssl
# is present only without a version here, and nothing versioned matches it.
if printf '%s' "$forms_out" | jq -e '
      [.[] | select(.name == "openssl")] | length == 1' >/dev/null; then
    pass "a presence-only component with no versioned counterpart survives"
else
    fail "a presence-only component was dropped with nothing to yield to"
fi

if printf '%s' "$with_verstr" | jq -e '
      [.[] | select(.name == "uclibc")][0] | .version == "0.9.28"' >/dev/null; then
    pass "the surviving uclibc is the versioned one"
else
    fail "the versionless uclibc won over the versioned one"
fi

echo "== a program is also evidence of the component that ships it =="

# The plan had these eight down as statically linked or in the bootloader, with
# neither a string nor a filename to go on. Four of them are standalone binaries
# sitting in /bin under their own names. The name a program is installed under is
# often not its component: brctl ships in bridge-utils, chat and pppd in ppp,
# hostapd_cli in hostapd, ip and tc in iproute2.
PTBL="$ROOT_DIR/docker/lib/elf-program-map.json"
if [ -f "$PTBL" ] && jq -e 'to_entries | map(select(.key | startswith("_") | not)) | length > 0' \
     "$PTBL" >/dev/null 2>&1; then
    pass "the program-name map ships and has entries"
else
    fail "elf-program-map.json is missing or empty"
fi

for pair in brctl:bridge-utils pppd:ppp hostapd_cli:hostapd ip:iproute2; do
    k="${pair%%:*}"; v="${pair#*:}"
    got=$(jq -r --arg k "$k" '.[$k] // "MISSING"' "$PTBL")
    if [ "$got" = "$v" ]; then
        pass "$k maps to $v, not to itself"
    else
        fail "$k maps to '$got'" "the installed name is not always the component"
    fi
done

# No versions here either: nothing about an installed filename gives one.
if jq -e 'to_entries | map(select(.key | startswith("_") | not))
          | all(.value | type == "string" and (test("[0-9]+\\.[0-9]") | not))' \
     "$PTBL" >/dev/null 2>&1; then
    pass "the program map carries names only, never versions"
else
    fail "the program map carries a version"
fi

# Only under bin/ or sbin/, so a data file sharing a name cannot stand in for the
# program — `ip`, `tc` and `chat` are ordinary words.
if grep -q 'parts\[-2\] in ("bin", "sbin")' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "only executables under bin/ or sbin/ are matched by name"
else
    fail "any file matching a program name would be counted"
fi

# An image that installs /bin/telnetd as a copy of busybox is carrying busybox,
# which is already identified with a version.
if grep -q 'BusyBox v' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "a busybox copy under an applet name is not reported as that component"
else
    fail "a busybox applet copy would be reported as a separate component"
fi

echo "== a component linked into another binary is read from its symbols =="

# The Zyxel notice declares ncurses, readline and quagga; all three are inside
# one 400 KB executable with no version string left for any of them, so neither
# a signature checker nor a version-string pass can see them. The binary exports
# its dynamic symbols, and those name the components.
STBL="$ROOT_DIR/docker/lib/elf-symbol-map.json"
if [ -f "$STBL" ] && jq -e 'to_entries | map(select(.key | startswith("_") | not)) | length > 0' \
     "$STBL" >/dev/null 2>&1; then
    pass "the symbol map ships and has entries"
else
    fail "elf-symbol-map.json is missing or empty"
fi

# One shared name is a coincidence. The threshold is what makes a match evidence,
# and it also has to be reachable — a min above the number of symbols listed
# would mean the entry can never fire.
if jq -e 'to_entries | map(select(.key | startswith("_") | not))
          | all((.value.symbols | length) >= 3
                and .value.min >= 2
                and .value.min <= (.value.symbols | length))' "$STBL" >/dev/null 2>&1; then
    pass "every entry needs several symbols to agree, and can reach its own threshold"
else
    fail "an entry matches on too few symbols, or on a threshold it cannot reach"
fi

# The public API is what a compatible reimplementation also provides: libedit
# exports readline's rl_* entry points, and tgetent/tputs/tparm belong to every
# termcap there has ever been. Matching on those would report GNU readline for a
# BSD library. The internals do not travel.
for banned in rl_initialize readline add_history tgetent tputs tparm setupterm; do
    if jq -e --arg s "$banned" '[.[] | select(type == "object") | .symbols[]?] | any(. == $s)' \
         "$STBL" >/dev/null 2>&1; then
        fail "the symbol map matches on $banned" \
             "a compatible reimplementation exports it too"
    else
        pass "the symbol map does not match on the shared name $banned"
    fi
done

# Same rule as the other two maps: presence, never a version, and no identifier
# for anything downstream to match against an advisory.
if jq -e 'to_entries | map(select(.key | startswith("_") | not))
          | all(.value | has("purl") == false and has("cpe") == false
                and has("version") == false)' "$STBL" >/dev/null 2>&1; then
    pass "the symbol map carries no version and no identifier"
else
    fail "the symbol map carries a version or an identifier"
fi

# -W or the long names come back as `rl_completion_qu[...]` and every symbol
# worth matching on is silently missed.
if grep -q '"readelf", "-W"' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "symbol names are read unabbreviated"
else
    fail "readelf is called without -W" "long symbol names would be truncated"
fi

# Which symbols matched has to reach the SBOM. A count cannot be checked by
# anyone; the names and the file they were found in can.
if grep -q 'bomlens:elfSymbols' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "the matched symbols are recorded as evidence"
else
    fail "a symbol judgement lands with no evidence to check"
fi

echo "== a fork that kept its parent's symbols is told apart by the file =="

# FRRouting forked from quagga in 2017 and kept its symbol names, its command
# library and much of its wording — an FRR zebra still writes /var/tmp/quagga —
# so nothing in the dynamic symbol table separates them. A Zyxel XGS1210-12
# carries both and its vendor notice declares both: bin/cli has the quagga
# markers and no FRR marker, bin/zebra has FRRouting three times and neither
# quagga marker. Reporting the family name for both would have lost frr.
if jq -e '.quagga.variants.candidates | length >= 2' "$STBL" >/dev/null 2>&1; then
    pass "the symbol map records the members of a shared-symbol family"
else
    fail "quagga has no variants entry" "an FRR image would be reported as quagga"
fi

# Each member needs markers of its own and a record of where they were seen.
if jq -e '.quagga.variants.candidates
          | all((.name | length) > 0 and (.markers | length) >= 1
                and (.where | length) > 0)' "$STBL" >/dev/null 2>&1; then
    pass "every member carries its own markers and where they were seen"
else
    fail "a variant member has no marker, no name, or no recorded sighting"
fi

# The two marker sets must not overlap, or no file could ever be decided.
if jq -e '[.quagga.variants.candidates[].markers[]] as $all
          | ($all | length) == ($all | unique | length)' "$STBL" >/dev/null 2>&1; then
    pass "the members do not share a marker"
else
    fail "two members claim the same marker" "no file could be decided"
fi

# A file matching both, or neither, is not something these markers settle. It
# keeps the family name rather than picking a member at random.
if jq -e '.quagga.variants | has("default")' "$STBL" >/dev/null 2>&1; then
    pass "an undecided file falls back to the family name"
else
    fail "the variants entry has no default" "an undecided file would name a member anyway"
fi

if grep -q 'if len(names) == 1' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "a member is named only when exactly one of them matches"
else
    fail "the variant rule does not require a single match"
fi

echo "== a SONAME that names a slot is settled by the file in it =="

# `libc` says something is the C library, not which one, so elf-soname-map.json
# leaves it out. Three projects fill that slot across the seven vendor images and
# their licences differ — musl is MIT, glibc and uClibc LGPL — so a notice saying
# `libc` has not answered the question a notice exists to answer. The library
# writes its own name inside: MikroTik and Ubiquiti carry `musl libc`, D-Link
# `GNU C Library`.
ATBL="$ROOT_DIR/docker/lib/elf-ambiguous-soname-map.json"
if [ -f "$ATBL" ] && jq -e 'to_entries | map(select(.key | startswith("_") | not)) | length > 0' \
     "$ATBL" >/dev/null 2>&1; then
    pass "the slot map ships and has entries"
else
    fail "elf-ambiguous-soname-map.json is missing or empty"
fi

# Every candidate needs a marker to match on and a record of where it was seen.
if jq -e 'to_entries | map(select(.key | startswith("_") | not))
          | all((.value.candidates | length) >= 2
                and all(.value.candidates[];
                        (.name | length) > 0 and (.marker | length) > 0
                        and (.where | length) > 0))' "$ATBL" >/dev/null 2>&1; then
    pass "every candidate carries a marker and where it was seen"
else
    fail "a candidate has no marker, no name, or no recorded sighting"
fi

# Same rule as the other maps: presence, never a version or an identifier.
if jq -e '[.. | objects | select(has("marker"))]
          | all(has("version") == false and has("purl") == false and has("cpe") == false)' \
     "$ATBL" >/dev/null 2>&1; then
    pass "the slot map carries no version and no identifier"
else
    fail "the slot map carries a version or an identifier"
fi

# uClibc is left out on purpose. Its filename already carries the upstream
# version, which version-string-map.json reads, and the marker would not settle
# the identity anyway: uclibc ended at 0.9.33 and uclibc-ng picks up at 1.0, both
# writing `uClibc`. Adding it would trade a correct answer for an ambiguous one.
if jq -e '[.. | objects | select(has("marker")) | .marker] | any(test("uclibc"; "i"))' \
     "$ATBL" >/dev/null 2>&1; then
    fail "uClibc was added as a slot candidate" \
         "the filename rule already names it, and the marker cannot separate uclibc from uclibc-ng"
else
    pass "uClibc is left to the filename rule that can name its version"
fi

# One marker or nothing. Two mean the file is not what the SONAME said, none mean
# the slot holds something unlisted, and neither is a basis for naming anything.
if grep -q 'len(hit) == 1' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "a slot is named only when exactly one candidate matches"
else
    fail "the slot rule does not require a single match" \
         "an ambiguous file would be reported as one of its candidates"
fi

# Only listed slots are ever read for content. Without that gate this becomes the
# open string search the script exists to avoid.
if grep -q 'cands = slot_rules.get(key)' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "only a listed slot SONAME has its file read"
else
    fail "file content is read for SONAMEs that are not listed slots"
fi

# The marker and its file have to reach the SBOM, or the judgement cannot be checked.
if grep -q 'bomlens:elfSlotMarker' "$ROOT_DIR/docker/lib/identify-elf-presence.py"; then
    pass "the matched marker is recorded as evidence"
else
    fail "a slot judgement lands with no evidence to check"
fi

echo "== the version-string table is closed, and its CPEs are checked =="

TBL="$ROOT_DIR/docker/lib/version-string-map.json"
if [ -f "$TBL" ] && jq -e '(.entries | length) > 0' "$TBL" >/dev/null 2>&1; then
    pass "the version-string table ships and has entries"
else
    fail "version-string-map.json is missing or empty"
fi

# Every entry needs its own anchored pattern. An open `<name> <version>` sweep of
# a rootfs returns XMP namespaces, HTTP/1.1, netmasks and IP addresses by the
# hundred — measured on the corpus before the table was written.
if jq -e 'all(.entries[]; (.pattern | length) > 0 and (.pattern | test("\\(")))' \
     "$TBL" >/dev/null 2>&1; then
    pass "every entry carries its own capturing pattern"
    # A prerelease is not the release. 0.18-pre1 precedes 0.18, so trimming the
    # suffix would claim a version the image does not carry — and quietly line the
    # component up against the wrong advisories.
    if command -v python3 >/dev/null 2>&1 && python3 - "$TBL" <<'PY'
import json, re, sys
t = json.load(open(sys.argv[1]))
e = next((x for x in t["entries"] if x["name"] == "netkit-ftp"), None)
if not e:
    sys.exit(1)
m = re.search(e["pattern"], "$NetKit: netkit-ftp-0.18-pre1 $")
sys.exit(0 if m and m.group(1) == "0.18-pre1" else 1)
PY
    then
        pass "a prerelease version is read whole, not trimmed to the release"
    else
        fail "the netkit-ftp pattern does not capture 0.18-pre1 intact"
    fi
else
    fail "an entry has no pattern, or no capture group for the version"
fi

# The reason a CPE is or is not attached has to be written down, or the next
# person adding an entry guesses.
if jq -e 'all(.entries[]; (.why | length) > 0 and (.where | length) > 0)' \
     "$TBL" >/dev/null 2>&1; then
    pass "every entry records why its CPE decision was made and where it was seen"
else
    fail "an entry is missing its why/where note"
fi

if [ -f "$ROOT_DIR/docker/check-version-string-map.py" ] \
   && grep -q 'check-version-string-map.py' "$ROOT_DIR/docker/Dockerfile"; then
    pass "the build checks every CPE in the table against the bundled index"
else
    fail "no build gate ties the table's CPEs to the index they are matched against"
fi

# A version-shaped token inside a cross-toolchain path describes how the firmware
# was built, not what it ships. A D-Link image records
# `crosstools-arm-gcc-5.5-linux-4.1-glibc-2.26` in binaries that run against uClibc.
if grep -q 'TOOLCHAIN = re.compile' "$ROOT_DIR/docker/lib/identify-version-strings.py"; then
    pass "matches inside cross-toolchain paths are ignored"
else
    fail "a build-toolchain path can still be read as a shipped component"
fi

echo "== the vendor squashfs variant has an extractor =="

if grep -q 'sasquatch' "$ROOT_DIR/docker/Dockerfile"; then
    pass "sasquatch is installed into the firmware image"
else
    fail "sasquatch is not installed" "byte-swapped and LZMA squashfs stay unreadable"
fi

# Standard tool first: nothing is lost by trying it, and its error is the more
# useful one to report when both fail.
order=$(awk '/^opened_squashfs\(\) \{/,/^}/' "$SCRIPT" | grep -oE 'unsquashfs sasquatch|sasquatch unsquashfs' | head -1)
if [ "$order" = "unsquashfs sasquatch" ]; then
    pass "the standard extractor is tried before the patched one"
else
    fail "extractor order is wrong or missing" "got: ${order:-none}"
fi

echo "== the rootfs is the shallowest one, not whichever the filesystem lists first =="

# Lifted from the shipping script for the same reason comps_of is: a copy here
# would keep passing after the real one changed.
#
# pick_shallowest is fed a list rather than left to search a directory, which is
# what makes these checks worth running. Handed a real tree, the old rule
# ("take the first line") returns the right answer whenever the filesystem
# happens to list the root first — it does on macOS — so a directory fixture
# would pass against the defect it is meant to catch. Feeding the deep candidate
# first fails the old rule on every platform.
rootfs_body="$(awk '
    /^pick_shallowest\(\) \{/ { inside = 1 }
    inside { print }
    inside && $0 == "}" { exit }
' "$SCRIPT")"
if [ -z "$rootfs_body" ]; then
    fail "could not lift pick_shallowest out of scan-firmware.sh" "was it renamed?"
else
    eval "$rootfs_body"

    # A MikroTik RouterOS image in miniature: bundled sub-packages that carry
    # bin, etc and lib exactly as the real root does. Nothing but depth tells
    # them apart, and a bundle came first on the scanner's filesystem, which
    # cost the whole image's components.
    got=$(printf '%s\n' \
        /x/bndl/ppp/nova/etc /x/bndl/wifi/nova/etc /x/bndl/hotspot/nova/etc /x/etc \
        | pick_shallowest)
    if [ "$got" = "/x/etc" ]; then
        pass "the root's own etc wins over a bundle listed before it"
    else
        fail "a bundled sub-package was taken for the rootfs" "got ${got:-nothing}"
    fi

    # Order of arrival must not matter at all; the same set has one answer.
    got=$(printf '%s\n' /x/etc /x/bndl/ppp/nova/etc | pick_shallowest)
    if [ "$got" = "/x/etc" ]; then
        pass "the same set gives the same answer whichever order it arrives in"
    else
        fail "the choice depends on input order" "got ${got:-nothing}"
    fi

    # Ties have to resolve somewhere, and the path is the only ordering left.
    got=$(printf '%s\n' /x/zzz/etc /x/aaa/etc | pick_shallowest)
    if [ "$got" = "/x/aaa/etc" ]; then
        pass "equally deep candidates resolve by path"
    else
        fail "a tie between equally deep candidates is unresolved" "got ${got:-nothing}"
    fi

    # No candidates is a real case (a carved partition with no rootfs); the
    # caller falls back to the whole tree only when this says nothing.
    if [ -z "$(printf '' | pick_shallowest)" ]; then
        pass "no candidates yields nothing to fall back from"
    else
        fail "an empty candidate list still named a rootfs"
    fi

    # The search half has to actually reach the choosing half.
    if awk '/^shallowest_etc\(\) \{/,/^}/' "$SCRIPT" | grep -q 'pick_shallowest'; then
        pass "the etc search feeds its candidates through the choice"
    else
        fail "shallowest_etc no longer uses pick_shallowest" \
             "the tested rule is not the one that runs"
    fi
fi

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
