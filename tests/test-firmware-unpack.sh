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
                --slurpfile c <(echo '[]') --slurpfile d <(echo '[]') \
                --slurpfile e <(echo '[]') --slurpfile f <(echo '[]') "$merge_filter")"

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

# A purl written from a container layer's own os-release is shorter than the one
# syft writes for the same package in the rootfs, because the architecture is not
# in the SBOM to copy. Counted as a second purl it would split every package
# installed in both the rootfs and a container into one component per container:
# measured on one switch OS, 5,619 entries where 192 belonged.
store_merge="$(jq -n \
    --slurpfile a "$FIX/merge-pkg-comps.json" \
    --slurpfile b <(echo '[]') --slurpfile c <(echo '[]') --slurpfile d <(echo '[]') \
    --slurpfile e '/dev/stdin' --slurpfile f <(echo '[]') "$merge_filter" <<'EOF'
[{"type":"library","name":"openssl","version":"1.0.2h",
  "purl":"pkg:deb/debian/openssl@1.0.2h?distro=debian-13",
  "properties":[{"name":"bomlens:purlSource","value":"container-store-distro"},
                {"name":"bomlens:container:image","value":"app-one@1.0"}]},
 {"type":"library","name":"openssl","version":"1.0.2h",
  "purl":"pkg:deb/debian/openssl@1.0.2h?distro=debian-13",
  "properties":[{"name":"bomlens:purlSource","value":"container-store-distro"},
                {"name":"bomlens:container:image","value":"app-two@2.0"}]},
 {"type":"library","name":"only-in-container","version":"1.0",
  "purl":"pkg:deb/debian/only-in-container@1.0?distro=debian-13",
  "properties":[{"name":"bomlens:purlSource","value":"container-store-distro"},
                {"name":"bomlens:container:image","value":"app-one@1.0"}]},
 {"type":"library","name":"only-in-container","version":"1.0",
  "purl":"pkg:deb/debian/only-in-container@1.0?distro=debian-13",
  "properties":[{"name":"bomlens:purlSource","value":"container-store-distro"},
                {"name":"bomlens:container:image","value":"app-two@2.0"}]}]
EOF
)"
n=$(printf '%s' "$store_merge" | jq '[.[] | select(.name == "openssl" and .version == "1.0.2h")] | length')
if [ "$n" = "1" ]; then
    pass "a package in the rootfs and in containers stays one component"
else
    fail "a package was split once per container" "openssl 1.0.2h appears $n time(s)"
fi

# The rootfs is the filesystem the device boots, so its record stays the base of
# the group and the identifier read off the rootfs is the one that ships.
got="$(printf '%s' "$store_merge" | jq -r '
    [.[] | select(.name == "openssl" and .version == "1.0.2h")][0].purl')"
if [ "$got" = "pkg:generic/openssl@1.0.2h" ]; then
    pass "the merged record keeps syft's purl over the synthesized one"
else
    fail "the synthesized purl displaced syft's" "got $got"
fi

# Every container the package was found in still has to be readable off it.
imgs=$(printf '%s' "$store_merge" | jq '[.[] | select(.name == "openssl")
    | .properties[]? | select(.name == "bomlens:container:image")] | length')
if [ "$imgs" = "2" ]; then
    pass "the merged record still names every container the package is in"
else
    fail "a container membership was lost in the merge" "got $imgs of 2"
fi

# A package that only exists inside containers keeps the purl written for it —
# that identifier is the only thing the vulnerability step can match on.
n=$(printf '%s' "$store_merge" | jq '[.[] | select(.name == "only-in-container")] | length')
got="$(printf '%s' "$store_merge" | jq -r '[.[] | select(.name == "only-in-container")][0].purl')"
if [ "$n" = "1" ] && [ "$got" = "pkg:deb/debian/only-in-container@1.0?distro=debian-13" ]; then
    pass "a package found only in containers is reported once, with its purl"
else
    fail "a container-only package lost its identifier or was duplicated" \
         "$n entr(y/ies), purl $got"
fi

echo "== a component with no version left is still reported, and marked as such =="

# Signature identification only reports what it can read a version out of, so a
# component whose version string did not survive is missing from the SBOM
# entirely. On a Zyxel switch that is net-snmp, libradius and libtacplus — three
# of the seventeen the vendor declares in its own notice.
with_presence="$(jq -n --slurpfile a "$FIX/merge-pkg-comps.json" \
                       --slurpfile b "$FIX/merge-bin-comps.json" \
                       --slurpfile c "$FIX/elf-presence-comps.json" \
                       --slurpfile d <(echo '[]') \
                       --slurpfile e <(echo '[]') --slurpfile f <(echo '[]') "$merge_filter")"

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

echo "== a cap the warning tells you to raise can actually be raised =="

# Both identification passes bound how many files they read, and both say so when
# they stop: "raise FW_VERSTR_MAX_FILES to cover the rest." That advice was false
# — scan-sbom.sh forwarded the presentation caps to the container and not these
# two, so the variable a reader set on the command line never arrived and the pass
# stopped in the same place as before. Measured on a switch OS image of some
# 38,000 files, where the version-string pass covered barely half of them.
for v in FW_VERSTR_MAX_FILES FW_VERSTR_MAX_BYTES FW_ELF_MAX_FILES \
         FW_KERNEL_MAX_FILES FW_KERNEL_MAX_BYTES FW_KERNEL_MAX_VERSIONS \
         FW_EXTRA_ROOTS FW_MAX_EXTRA_ROOTS; do
    if grep -q -- "-e $v=" "$ROOT_DIR/scripts/scan-sbom.sh"; then
        pass "$v reaches the container"
    else
        fail "$v is never forwarded" \
             "the warning naming it tells the reader to do something that does nothing"
    fi
done

# Those variables are forwarded as `-e NAME=` whether or not anyone set one, so an
# unset cap arrives as an empty string. A bare int("") raises, which would abort
# the pass on every scan rather than fall back to the default.
for f in identify-version-strings identify-elf-presence identify-kernel-version; do
    if grep -q 'def cap(name, default)' "$ROOT_DIR/docker/lib/$f.py"; then
        pass "$f falls back when a cap arrives empty or malformed"
    else
        fail "$f reads its cap with a bare int()" \
             "an unset cap arrives as an empty string and would abort the pass"
    fi
done

# And the helper has to behave: empty and zero fall back, a real value is used.
cap_probe="$ROOT_DIR/tests/fixtures/cap-probe.py"
if [ -f "$cap_probe" ] && command -v python3 >/dev/null 2>&1; then
    if python3 "$cap_probe" "$ROOT_DIR/docker/lib/identify-version-strings.py" >/dev/null 2>&1; then
        pass "an empty or zero cap falls back, a real one is honoured"
    else
        fail "the cap helper does not behave as documented"
    fi
    if python3 "$cap_probe" "$ROOT_DIR/docker/lib/identify-kernel-version.py" >/dev/null 2>&1; then
        pass "identify-kernel-version's cap helper behaves the same way"
    else
        fail "identify-kernel-version's cap helper does not behave as documented"
    fi
fi

echo "== a version-string pattern reads its own stamp and nothing that resembles it =="

# The table is closed precisely because a loose pattern reads version-shaped text
# everywhere. Two sample files hold the strings a media player's codec plugins
# actually carry, and ten that look like them but are something else: a text
# editor of the same name, a columnar file format of the same name, a two-digit
# form the binary builds its string from, a format name without the vendor stamp.
# Both halves have to hold — reading none of the real four is as wrong as reading
# any of the ten.
verstr_dir="$ROOT_DIR/tests/fixtures/verstr-samples"
if [ -d "$verstr_dir" ] && command -v python3 >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    verstr_out="$(python3 "$ROOT_DIR/docker/lib/identify-version-strings.py" \
                  "$verstr_dir" "$ROOT_DIR/docker/lib/version-string-map.json" 2>/dev/null)"
    for want in "libkate 0.4.1" "libtheora 1.1" "schroedinger 1.0.11" "orc 0.4.33"; do
        nm="${want% *}"; ver="${want#* }"
        if printf '%s' "$verstr_out" | jq -e --arg n "$nm" --arg v "$ver" \
            'any(.[]; .name == $n and .version == $v)' >/dev/null 2>&1; then
            pass "$nm is read from its own stamp as $ver"
        else
            fail "$nm $ver was not read from the sample stamp" "$verstr_out"
        fi
    done
    # Every judgement must come from the file holding real stamps. A hit in the
    # look-alike file means a pattern reaches text that is not a version stamp.
    if printf '%s' "$verstr_out" | jq -e \
        'all(.[]; .evidence.occurrences[0].location | test("codec-plugin"))' >/dev/null 2>&1; then
        pass "nothing is read out of the look-alike strings"
    else
        fail "a pattern matched text that only resembles a version stamp" "$verstr_out"
    fi
    # The theora entry is the one carrying a CPE, and a wrong one hands a codec
    # another project's advisories. xiph:theora is checked against the bundled
    # index at build time; here we only hold it to the vendor it was verified as.
    if printf '%s' "$verstr_out" | jq -e \
        'any(.[]; .name == "libtheora" and ((.cpe // "") | test("^cpe:2.3:a:xiph:theora:")))' \
        >/dev/null 2>&1; then
        pass "libtheora carries the xiph CPE and not another project's"
    else
        fail "libtheora lost its CPE or carries the wrong vendor" "$verstr_out"
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
                     --slurpfile d "$FIX/version-string-comps.json" \
                     --slurpfile e <(echo '[]') --slurpfile f <(echo '[]') "$merge_filter")"

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
                   --slurpfile c <(echo '[]') --slurpfile d <(echo '[]') \
                   --slurpfile e <(echo '[]') --slurpfile f <(echo '[]') "$merge_filter")"

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

echo "== the kernel is read from wherever in the image it sits =="

# Every pass above reads only inside the rootfs. Two firmware images measured
# this session both boot a kernel that sits outside it: an install ISO whose
# boot catalog and install payload are sibling top-level trees, and an image
# where the kernel is an intermediate decompression stage unblob unpacks
# *through* on the way down to the rootfs rather than a file inside it. In
# both a rootfs-scoped search never reads the file naming the kernel version.
if command -v python3 >/dev/null 2>&1; then
    KTREE="$(mktemp -d)"

    mkdir -p "$KTREE/boot_extract/mod_extract" \
             "$KTREE/a_extract" "$KTREE/b_extract" \
             "$KTREE/lookalike" "$KTREE/rootfs/lib/modules/5.10.177"

    python3 - "$KTREE" <<'PY'
import sys
root = sys.argv[1]
# The kernel image's own boot banner. The byte before "Linux version" is a NUL
# here, as it is in a real gzip-uncompressed vmlinux -- never a newline, which
# is what cve-bin-tool's own pattern (built for pre-extracted strings, not raw
# bytes) anchors on instead.
open(f"{root}/boot_extract/vmlinux.uncompressed", "wb").write(
    b"\x00\x00garbage\x00Linux version 5.10.177 (b@h) (gcc 8.4) "
    b"#1 SMP Tue Apr 4 01:02:03 UTC 2023\x00more")
# A loadable module's vermagic -- the strongest signature, and it should win
# over the banner above even though both are present in this tree.
open(f"{root}/boot_extract/mod_extract/drv.ko", "wb").write(
    b"ELF\x00...\x00vermagic=5.10.177 SMP mod_unload \x00...")
# Two files that collide under identify-version-strings.py's marker-stripping
# dedupe (both reduce to "lzma.uncompressed") but sit under different
# branches. Only one carries a kernel string; both must still be read.
open(f"{root}/a_extract/lzma.uncompressed", "wb").write(
    b"junk\x00Linux version 4.4.153 (foo) (gcc 7) #1 Mon Jan 1 00:00:00 UTC 2024\x00pad")
open(f"{root}/b_extract/lzma.uncompressed", "wb").write(
    b"completely unrelated content, no kernel here at all")
# Text that resembles both patterns but must not match: a missing "vermagic="
# prefix, a missing "Linux version " prefix, and prose mentioning a version
# without the trailing "#<n> <weekday>" the real banner always carries.
open(f"{root}/lookalike/notes.txt", "wb").write(
    b"Requires Linux version 2.6 or later.\n2.6.32 #1 SMP\nvermagic\nHTTP/1.1 200 OK\n")
PY

    kernel_out="$(python3 "$ROOT_DIR/docker/lib/identify-kernel-version.py" \
                  "$KTREE" "$KTREE/rootfs" 2>/dev/null)"

    if printf '%s' "$kernel_out" | jq -e \
        'any(.[]; .name == "linux_kernel" and .version == "5.10.177")' >/dev/null 2>&1; then
        pass "the kernel is identified from a file outside the rootfs entirely"
    else
        fail "the kernel signature outside the rootfs was not read" "$kernel_out"
    fi

    if printf '%s' "$kernel_out" | jq -e \
        'any(.[]; .name == "linux_kernel" and .version == "5.10.177")
         and (any(.[]; .properties[]? | .name == "bomlens:identifiedBy" and .value == "kernel-signature"))' \
        >/dev/null 2>&1; then
        pass "a vermagic hit outranks a banner hit for the same tree"
    else
        fail "the wrong evidence grade won" "$kernel_out"
    fi

    if printf '%s' "$kernel_out" | jq -e \
        '[.[] | select(.name == "linux_kernel")] | length == 1' >/dev/null 2>&1; then
        pass "only the strongest-grade version is reported when a stronger one exists"
    else
        fail "more than one kernel version was reported" "$kernel_out"
    fi

    # cpe:/a:, not cpe:/o: -- firmware-cpe-match.py's parser only reads part
    # `a` out of either CPE form, and this is the form cve-bin-tool's own
    # scan output and the Dockerfile's kernel smoke test both use.
    if printf '%s' "$kernel_out" | jq -e \
        'any(.[]; .cpe == "cpe:/a:linux:linux_kernel:5.10.177")' >/dev/null 2>&1; then
        pass "the kernel's cpe uses part a, matching what firmware-cpe-match.py parses"
    else
        fail "the kernel's cpe is not cpe:/a:linux:linux_kernel:<version>" "$kernel_out"
    fi

    # Drop the vermagic file and confirm the banner-only fallback still works,
    # picks the version with an actual file behind it (not the empty b_extract
    # file), and reads no evidence from the lookalikes.
    rm -rf "$KTREE/boot_extract"
    fallback_out="$(python3 "$ROOT_DIR/docker/lib/identify-kernel-version.py" \
                     "$KTREE" "$KTREE/rootfs" 2>/dev/null)"
    if printf '%s' "$fallback_out" | jq -e \
        'any(.[]; .name == "linux_kernel" and .version == "4.4.153")' >/dev/null 2>&1; then
        pass "falls back to the banner signature when no vermagic is present"
    else
        fail "the banner-only fallback did not read the kernel version" "$fallback_out"
    fi
    if printf '%s' "$fallback_out" | jq -e \
        'all(.[]; .evidence.occurrences[0].location | test("lzma.uncompressed|drv.ko|vmlinux.uncompressed"))
         and (all(.[]; .evidence.occurrences[0].location | test("notes.txt") | not))' \
        >/dev/null 2>&1; then
        pass "nothing is read out of the version-shaped lookalike text"
    else
        fail "a pattern matched text that only resembles a kernel signature" "$fallback_out"
    fi

    # The two identically-named files after marker-stripping (a_extract and
    # b_extract's "lzma.uncompressed") are the exact collision
    # identify-version-strings.py's dedupe would hit -- this pass must not
    # reuse that dedupe, or reading either file becomes a coin flip on walk
    # order. Confirmed above (4.4.153 was read from a_extract); this checks
    # the evidence points at the right one, not b_extract's unrelated content.
    if printf '%s' "$fallback_out" | jq -e \
        '[.[] | select(.name == "linux_kernel")][0].evidence.occurrences[0].location
         == "lzma.uncompressed"' >/dev/null 2>&1; then
        pass "a marker-stripped name collision does not hide the kernel-bearing file"
    else
        fail "the path-collision regression guard failed" "$fallback_out"
    fi

    # choose() is importable and its answer must not depend on the order
    # candidates arrive in -- the same property pick_shallowest's own test
    # checks for rootfs selection, for the same MikroTik-shaped reason.
    order_out="$(python3 - "$ROOT_DIR/docker/lib/identify-kernel-version.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("ikv", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

forward = [
    ("banner", "4.4.153", "a", "Linux version 4.4.153 ..."),
    ("banner", "4.4.153", "b", "Linux version 4.4.153 ..."),
    ("banner", "3.10.20", "c", "Linux version 3.10.20 ..."),
]
reversed_ = list(reversed(forward))
r1 = m.choose(forward)
r2 = m.choose(reversed_)
print("OK" if r1 == r2 and r1[0][0] == "4.4.153" else f"MISMATCH {r1} {r2}")
PY
)"
    if [ "$order_out" = "OK" ]; then
        pass "choose() picks the same answer regardless of candidate order"
    else
        fail "choose() is order-dependent" "$order_out"
    fi

    # The hard-won part: identification alone is not the fix, matching
    # against the index is. A synthetic index with one linux_kernel row
    # proves the component this pass emits actually reaches a CVE through
    # firmware-cpe-match.py unmodified -- this is the check that would have
    # caught shipping cpe:/o: instead of cpe:/a:.
    if command -v sqlite3 >/dev/null 2>&1; then
        KIDX="$(mktemp -u).sqlite"
        sqlite3 "$KIDX" "CREATE TABLE cpe_match (vendor TEXT NOT NULL, product TEXT NOT NULL,
            exact_version TEXT, version_start TEXT, vs_incl INTEGER, version_end TEXT,
            ve_incl INTEGER, cve_id TEXT NOT NULL, severity TEXT, cvss_version TEXT, cvss_score REAL);
            INSERT INTO cpe_match VALUES ('linux','linux_kernel',NULL,'4.4.0',1,'4.4.180',0,
            'CVE-TEST-KERNEL','HIGH','3',7.5);"
        ksbom="$(mktemp -u).json"
        jq -n --argjson comps "$fallback_out" '{components: $comps}' > "$ksbom"
        match_out="$(python3 "$ROOT_DIR/docker/lib/firmware-cpe-match.py" "$ksbom" "$KIDX" 2>/dev/null)"
        rm -f "$KIDX" "$ksbom"
        if printf '%s' "$match_out" | jq -e \
            'any(.[]; .cve_number == "CVE-TEST-KERNEL")' >/dev/null 2>&1; then
            pass "the emitted component reaches a CVE through the real matcher unmodified"
        else
            fail "the kernel component did not reach a CVE through firmware-cpe-match.py" "$match_out"
        fi
    fi

    rm -rf "$KTREE"
fi

# Wiring guard: the whole point is reading $EXTRACT, not $ROOTFS. If this pass
# is ever called with the rootfs like every other identification step, this
# fix silently stops doing anything on exactly the images that motivated it.
if grep -q 'identify-kernel-version.py" "\$EXTRACT" "\$ROOTFS"' "$ROOT_DIR/docker/lib/scan-firmware.sh"; then
    pass "the kernel pass is wired to the whole extraction, not the rootfs"
else
    fail "identify-kernel-version.py is not called with \$EXTRACT" \
         "the fix only works if this pass sees outside the rootfs"
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

echo "== a filesystem sitting beside the rootfs is found, and one inside it is not =="

# The defect: the scan read one filesystem per image. A switch image that ships
# its root filesystem and a container image store as siblings had the store's
# contents — every daemon the switch runs — missing from the SBOM entirely.
#
# Both halves of the rule are checked, because both can be got wrong in a way that
# still looks right. Recognising the store by the archive's name would pass on the
# one vendor whose archive is called dockerfs.tar.gz and no others; and offering up
# a store that lives *under* the rootfs would scan the same files twice, since the
# package catalogers already match their evidence files at any depth.
lift_fn() {
    awk -v fn="$1" '
        $0 ~ "^" fn "\\(\\) \\{" { inside = 1 }
        inside { print }
        inside && $0 == "}" { exit }
    ' "$SCRIPT"
}
roots_body="$(lift_fn docker_data_dirs)
$(lift_fn package_db_roots)
$(lift_fn language_package_roots)
$(lift_fn extra_scan_roots)"
if ! printf '%s' "$roots_body" | grep -q 'extra_scan_roots()'; then
    fail "could not lift the extra-root search out of scan-firmware.sh" "was it renamed?"
else
    eval "$roots_body"

    TREE="$(mktemp -d)"
    # A SONiC installer in miniature: the root filesystem and the container image
    # store are siblings, neither inside the other. The store's directory is
    # deliberately not named after any archive, so only the image index can
    # identify it.
    mkdir -p "$TREE/fs.zip_extract/fs.squashfs_extract/etc"
    mkdir -p "$TREE/fs.zip_extract/blob_extract/gzip.uncompressed_extract/image/overlay2"
    mkdir -p "$TREE/fs.zip_extract/blob_extract/gzip.uncompressed_extract/overlay2/aaa/diff/etc"
    echo '{"Repositories":{"docker-lldp":{}}}' \
        > "$TREE/fs.zip_extract/blob_extract/gzip.uncompressed_extract/image/overlay2/repositories.json"

    # Read by the two functions lifted out of the shipping script above. The
    # linter cannot follow a use through the eval that defined them.
    # shellcheck disable=SC2034
    EXTRACT="$TREE"
    # shellcheck disable=SC2034
    ROOTFS="$TREE/fs.zip_extract/fs.squashfs_extract"
    want="$TREE/fs.zip_extract/blob_extract/gzip.uncompressed_extract	container-store"
    got="$(extra_scan_roots)"
    if [ "$got" = "$want" ]; then
        pass "the container image store beside the rootfs is offered for cataloging"
    else
        fail "the sibling container image store was not found" "got ${got:-nothing}"
    fi

    # Same tree, plus a store where an ordinary Linux install keeps it. syft reads
    # that one already as part of the rootfs, so offering it again is duplicate
    # work — and this is the case that decides whether every other firmware in the
    # corpus keeps the output it has today.
    mkdir -p "$TREE/fs.zip_extract/fs.squashfs_extract/var/lib/docker/image/overlay2"
    mkdir -p "$TREE/fs.zip_extract/fs.squashfs_extract/var/lib/docker/overlay2/bbb/diff"
    echo '{"Repositories":{}}' \
        > "$TREE/fs.zip_extract/fs.squashfs_extract/var/lib/docker/image/overlay2/repositories.json"
    got="$(extra_scan_roots)"
    if [ "$got" = "$want" ]; then
        pass "a store inside the rootfs is left to the rootfs scan"
    else
        fail "a store under the rootfs was offered for a second scan" "got ${got:-nothing}"
    fi

    # An index with no layer directory beside it describes nothing readable.
    rm -rf "$TREE/fs.zip_extract/blob_extract/gzip.uncompressed_extract/overlay2"
    got="$(extra_scan_roots)"
    if [ -z "$got" ]; then
        pass "an image index with no layer directory yields nothing to scan"
    else
        fail "a store with no layer directory was still offered" "got $got"
    fi

    # An image carrying no containers at all must come out exactly as before.
    rm -rf "$TREE/fs.zip_extract/blob_extract" \
           "$TREE/fs.zip_extract/fs.squashfs_extract/var"
    got="$(extra_scan_roots)"
    if [ -z "$got" ]; then
        pass "an image with no container store adds no roots"
    else
        fail "an extra root appeared on an image with no container store" "got $got"
    fi

    # A second filesystem beside the rootfs, identified by the record of what is
    # installed in it rather than by a container index. One vendor ships its root
    # filesystem and a second install as siblings; without this the second one is
    # absent from the SBOM the same way the container store was.
    mkdir -p "$TREE/fs.zip_extract/second_extract/var/lib/dpkg"
    : > "$TREE/fs.zip_extract/second_extract/var/lib/dpkg/status"
    got="$(extra_scan_roots)"
    if [ "$got" = "$TREE/fs.zip_extract/second_extract	package-db" ]; then
        pass "a filesystem with its own package database is offered for cataloging"
    else
        fail "the sibling filesystem was not found by its package database" "got ${got:-nothing}"
    fi

    # The same rootfs has a package database too, and it is already read.
    mkdir -p "$TREE/fs.zip_extract/fs.squashfs_extract/var/lib/dpkg"
    : > "$TREE/fs.zip_extract/fs.squashfs_extract/var/lib/dpkg/status"
    got="$(extra_scan_roots)"
    if [ "$got" = "$TREE/fs.zip_extract/second_extract	package-db" ]; then
        pass "the rootfs is not offered to itself for a second scan"
    else
        fail "the rootfs was offered as an extra root" "got ${got:-nothing}"
    fi

    # Language packages recorded per package instead of in a system database. This
    # is the measured case: an interpreter's library set beside the rootfs, whose
    # packages the vendor declares and the scan did not report.
    SP="$TREE/fs.zip_extract/tools_extract/lib/python3.10/site-packages"
    mkdir -p "$SP/flask-2.3.3.dist-info"
    got="$(extra_scan_roots | grep -c 'language-packages')"
    if [ "$got" = "1" ]; then
        pass "an installed set of language packages beside the rootfs is offered"
    else
        fail "the sibling language packages were not found" "matched $got"
    fi
    # Metadata outside an interpreter's own directory is not a library set, and
    # opening any directory that holds a *.dist-info would scan arbitrary trees.
    mkdir -p "$TREE/fs.zip_extract/docs_extract/notes-1.0.dist-info"
    if [ "$(extra_scan_roots | grep -c 'language-packages')" = "1" ]; then
        pass "metadata outside an interpreter directory is left alone"
    else
        fail "a directory holding metadata was opened without being a library set"
    fi

    # A tree inside one already offered must not be read twice. Every Debian layer
    # in a container store carries its own package database, so without this the
    # store is read once as a store and again once per layer.
    mkdir -p "$TREE/fs.zip_extract/second_extract/rootfs/var/lib/dpkg"
    : > "$TREE/fs.zip_extract/second_extract/rootfs/var/lib/dpkg/status"
    if [ "$(extra_scan_roots | grep -c 'package-db')" = "1" ]; then
        pass "a tree inside one already offered is not offered again"
    else
        fail "a nested tree was offered on top of the tree containing it" \
             "$(extra_scan_roots)"
    fi
    rm -rf "$TREE"
fi

# The cap has to be visible when it fires. A silently truncated read reports the
# same way a complete one does, and the reader has no way to tell them apart.
if grep -q 'FW_MAX_EXTRA_ROOTS is ' "$SCRIPT" \
   && grep -q 'were found and NOT read' "$SCRIPT"; then
    pass "reaching the extra-root cap is reported, not silent"
else
    fail "the extra-root cap does not say when it truncated the scan"
fi

echo "== each component says which container image it came from =="

# The membership is the point. A library present somewhere in a switch image and
# the same library present in the routing daemon's container are different facts,
# and the vendor's own declaration records the second one, a scope per component.
#
# The fixture is a store in miniature, built so that the one indirection this can
# get wrong is load-bearing: an image config names its layers by diff_id, the
# directory the files sit in is named by cache-id, and only layerdb joins the two.
# The two strings here share nothing, so an implementation that matched diff_ids
# against the paths syft recorded would attribute nothing at all.
MEMBER="$ROOT_DIR/docker/lib/container-membership.py"
if [ ! -f "$MEMBER" ]; then
    fail "container-membership.py is missing" "the store's components cannot be attributed"
elif ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"
else
    STORE="$(mktemp -d)"
    IMG="$STORE/image/overlay2"
    mkdir -p "$IMG/imagedb/content/sha256" "$IMG/layerdb/sha256"
    A=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    B=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    # Two images over three layers: one base they share, one of their own each.
    cat > "$IMG/repositories.json" <<EOF
{"Repositories": {
  "app-one": {"app-one:1.0": "sha256:$A", "app-one:latest": "sha256:$A"},
  "app-two": {"app-two:2.0": "sha256:$B", "app-two:latest": "sha256:$B"}}}
EOF
    echo '{"rootfs":{"diff_ids":["sha256:d1","sha256:d2"]}}' \
        > "$IMG/imagedb/content/sha256/$A"
    echo '{"rootfs":{"diff_ids":["sha256:d1","sha256:d3"]}}' \
        > "$IMG/imagedb/content/sha256/$B"
    n=0
    for pair in d1:LAYERBASE d2:LAYERONE d3:LAYERTWO; do
        n=$((n + 1))
        mkdir -p "$IMG/layerdb/sha256/chain$n" "$STORE/overlay2/${pair#*:}/diff"
        printf 'sha256:%s\n' "${pair%%:*}" > "$IMG/layerdb/sha256/chain$n/diff"
        printf '%s\n' "${pair#*:}" > "$IMG/layerdb/sha256/chain$n/cache-id"
    done

    # A syft run over that store: one package in the shared base and one in each
    # image's own layer. Paths are relative to the store, the way syft records
    # them when pointed at a directory.
    cat > "$STORE/store.cdx.json" <<'EOF'
{"bomFormat":"CycloneDX","components":[
 {"type":"library","name":"shared-lib","version":"1.0","properties":[
   {"name":"syft:location:0:path","value":"/overlay2/LAYERBASE/diff/usr/lib/libshared.so"}]},
 {"type":"library","name":"one-only","version":"2.0","properties":[
   {"name":"syft:location:0:path","value":"/overlay2/LAYERONE/diff/usr/bin/one"}]},
 {"type":"library","name":"two-only","version":"3.0","properties":[
   {"name":"syft:location:0:path","value":"/overlay2/LAYERTWO/diff/usr/bin/two"}]},
 {"type":"library","name":"nowhere","version":"4.0","properties":[
   {"name":"syft:location:0:path","value":"/engine-id"}]}]}
EOF
    out="$(python3 "$MEMBER" "$STORE" "$STORE/store.cdx.json" 2>/dev/null)"

    imgs_of() {
        printf '%s' "$out" | jq -r --arg n "$1" '
            [.components[] | select(.name == $n)
             | .properties[]? | select(.name == "bomlens:container:image") | .value]
            | sort | join(",")'
    }

    if [ "$(imgs_of shared-lib)" = "app-one@1.0,app-two@2.0" ]; then
        pass "a package in a shared base layer belongs to every image built on it"
    else
        fail "a shared base layer's package was attributed to the wrong set" \
             "got: $(imgs_of shared-lib)"
    fi

    if [ "$(imgs_of one-only)" = "app-one@1.0" ] \
       && [ "$(imgs_of two-only)" = "app-two@2.0" ]; then
        pass "a package in one image's own layer belongs to that image alone"
    else
        fail "a package was attributed to an image that does not carry its layer" \
             "one-only: $(imgs_of one-only); two-only: $(imgs_of two-only)"
    fi

    # Nothing outside a layer may be attributed. A file at the store's root
    # belongs to the store, not to any image built from it.
    if [ -z "$(imgs_of nowhere)" ]; then
        pass "a file that is not in a layer is attributed to no image"
    else
        fail "a file outside every layer was given an image" "got: $(imgs_of nowhere)"
    fi

    # The layer is what makes the membership checkable: it names the directory the
    # files were read out of, so a reader can go and look.
    got="$(printf '%s' "$out" | jq -r '
        [.components[] | select(.name == "shared-lib")
         | .properties[]? | select(.name == "bomlens:container:layer") | .value] | join(",")')"
    if [ "$got" = "LAYERBASE" ]; then
        pass "the layer a component was read from is recorded as evidence"
    else
        fail "the layer behind a membership is not recorded" "got: ${got:-nothing}"
    fi

    # The images themselves, at the version the vendor uses. A store tags each
    # image twice, with the build's version and as `latest`; a purl reading
    # @latest says nothing and would not match any declaration.
    got="$(printf '%s' "$out" | jq -r '
        [.components[] | select(.type == "container") | .purl] | sort | join(",")')"
    if [ "$got" = "pkg:oci/app-one@1.0,pkg:oci/app-two@2.0" ]; then
        pass "each image is a component at its real version, not at latest"
    else
        fail "the container components are missing or versioned as latest" "got: ${got:-none}"
    fi

    # Attribution is an addition, never a filter: every component that arrived
    # still has to leave.
    if [ "$(printf '%s' "$out" | jq '[.components[] | select(.type != "container")] | length')" = "4" ]; then
        pass "no component is dropped on the way through"
    else
        fail "a component was lost during attribution" \
             "got $(printf '%s' "$out" | jq '[.components[] | select(.type != "container")] | length') of 4"
    fi

    # One repository name can hold two images. Reporting the repository as one
    # component would name one version, hide the other, and hand the hidden
    # image's layer to the one that was kept.
    C=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    python3 - "$IMG" "$A" "$C" <<'EOF'
import json, sys
img, a, c = sys.argv[1], sys.argv[2], sys.argv[3]
index = json.load(open(img + "/repositories.json"))
index["Repositories"]["app-one"]["app-one:1.1"] = "sha256:" + c
json.dump(index, open(img + "/repositories.json", "w"))
json.dump({"rootfs": {"diff_ids": ["sha256:d1", "sha256:d3"]}},
          open(img + "/imagedb/content/sha256/" + c, "w"))
EOF
    two="$(python3 "$MEMBER" "$STORE" "$STORE/store.cdx.json" 2>/dev/null)"
    got="$(printf '%s' "$two" | jq -r '
        [.components[] | select(.type == "container") | .purl] | sort | join(",")')"
    if [ "$got" = "pkg:oci/app-one@1.0,pkg:oci/app-one@1.1,pkg:oci/app-two@2.0" ]; then
        pass "a repository holding two images yields two components"
    else
        fail "two images under one repository name were collapsed into one" "got: $got"
    fi
    got="$(printf '%s' "$two" | jq -r '
        [.components[] | select(.name == "two-only")
         | .properties[]? | select(.name == "bomlens:container:image") | .value]
        | sort | join(",")')"
    if [ "$got" = "app-one@1.1,app-two@2.0" ]; then
        pass "the second image under that name gets its own layer's components"
    else
        fail "the second image's layer was attributed to the wrong image" "got: $got"
    fi

    # A store that is only partly there is the normal case for a firmware
    # extraction, and it must cost the memberships, not the components.
    rm -rf "$IMG/layerdb"
    part="$(python3 "$MEMBER" "$STORE" "$STORE/store.cdx.json" 2>/dev/null)"
    n_comp="$(printf '%s' "$part" | jq '[.components[] | select(.type != "container")] | length')"
    n_img="$(printf '%s' "$part" | jq '[.components[] | select(any(.properties[]?;
                 .name == "bomlens:container:image"))] | length')"
    if [ "$n_comp" = "4" ] && [ "$n_img" = "0" ]; then
        pass "a store missing its layer index loses the memberships, not the components"
    else
        fail "an incomplete store did not degrade cleanly" \
             "components $n_comp of 4, attributed $n_img (expected 0)"
    fi

    # And a directory that is not a store at all leaves the document alone.
    rm -rf "$STORE/image"
    plain="$(python3 "$MEMBER" "$STORE" "$STORE/store.cdx.json" 2>/dev/null)"
    if [ "$(printf '%s' "$plain" | jq '[.components[] | select(.type == "container")] | length')" = "0" ] \
       && [ "$(printf '%s' "$plain" | jq '.components | length')" = "4" ]; then
        pass "a directory that is not a container store is handed back untouched"
    else
        fail "a non-store directory was treated as one"
    fi
    rm -rf "$STORE"
fi

# The scan must not lose the store's components when attribution fails, and the
# only way to guarantee that is to keep the original until the new file is known
# good.
if awk '/container-membership.py/,/^        fi$/' "$SCRIPT" | grep -q 'attributed.json'; then
    pass "attribution replaces the store's SBOM only after it is checked"
else
    fail "attribution writes over the store's SBOM in place" \
         "a failure there would drop every component the store contributed"
fi

echo "== a deb read out of a layer gets the purl its distribution decides =="

# syft writes a deb's purl only when it knows the distribution, and it looks for
# that in /etc/os-release at the root of what it was pointed at. A store keeps
# each image's files under <driver>/<cache-id>/diff/, so every deb read out of one
# arrives with no purl — and the vulnerability step keys on the purl, so those
# packages are matched against nothing. Measured on one switch OS: 192 packages
# with no purl; with the purl written from the layer's own os-release, the scan
# reports 1,000 advisories it did not report before.
if [ ! -f "$MEMBER" ]; then
    fail "container-membership.py is missing" "layer debs cannot be identified"
elif ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"
else
    STORE="$(mktemp -d)"
    IMG="$STORE/image/overlay2"
    mkdir -p "$IMG/imagedb/content/sha256" "$IMG/layerdb/sha256"
    ONE=1111111111111111111111111111111111111111111111111111111111111111
    TWO=2222222222222222222222222222222222222222222222222222222222222222
    THREE=3333333333333333333333333333333333333333333333333333333333333333
    cat > "$IMG/repositories.json" <<EOF
{"Repositories": {
  "deb-one":  {"deb-one:1.0": "sha256:$ONE"},
  "deb-two":  {"deb-two:2.0": "sha256:$TWO"},
  "nodistro": {"nodistro:3.0": "sha256:$THREE"}}}
EOF
    echo '{"rootfs":{"diff_ids":["sha256:e1","sha256:e2"]}}' \
        > "$IMG/imagedb/content/sha256/$ONE"
    echo '{"rootfs":{"diff_ids":["sha256:e3","sha256:e4"]}}' \
        > "$IMG/imagedb/content/sha256/$TWO"
    echo '{"rootfs":{"diff_ids":["sha256:e5"]}}' \
        > "$IMG/imagedb/content/sha256/$THREE"
    n=0
    for pair in e1:BASEONE e2:APPONE e3:BASETWO e4:APPTWO e5:PLAIN; do
        n=$((n + 1))
        mkdir -p "$IMG/layerdb/sha256/link$n" "$STORE/overlay2/${pair#*:}/diff/etc"
        printf 'sha256:%s\n' "${pair%%:*}" > "$IMG/layerdb/sha256/link$n/diff"
        printf '%s\n' "${pair#*:}" > "$IMG/layerdb/sha256/link$n/cache-id"
    done
    # Two images on two Debian releases, and one that does not say what it runs.
    printf 'ID=debian\nVERSION_ID="13"\n' > "$STORE/overlay2/BASEONE/diff/etc/os-release"
    printf 'ID=debian\nVERSION_ID="14"\n' > "$STORE/overlay2/BASETWO/diff/etc/os-release"

    cat > "$STORE/store.cdx.json" <<'EOF'
{"bomFormat":"CycloneDX","components":[
 {"type":"library","name":"bash","version":"5.2.37-2+b9","properties":[
   {"name":"syft:package:type","value":"deb"},
   {"name":"syft:location:0:path","value":"/overlay2/APPONE/diff/var/lib/dpkg/status"}]},
 {"type":"library","name":"libssl3","version":"3.0.15-1","properties":[
   {"name":"syft:package:type","value":"deb"},
   {"name":"syft:metadata:source","value":"openssl"},
   {"name":"syft:metadata:sourceVersion","value":"3.0.15"},
   {"name":"syft:location:0:path","value":"/overlay2/APPONE/diff/var/lib/dpkg/status"}]},
 {"type":"library","name":"curl","version":"8.0","purl":"pkg:deb/debian/curl@8.0?arch=amd64",
  "properties":[
   {"name":"syft:package:type","value":"deb"},
   {"name":"syft:location:0:path","value":"/overlay2/APPONE/diff/var/lib/dpkg/status"}]},
 {"type":"library","name":"pylib","version":"1.0","properties":[
   {"name":"syft:package:type","value":"python"},
   {"name":"syft:location:0:path","value":"/overlay2/APPONE/diff/usr/lib/x.dist-info/METADATA"}]},
 {"type":"library","name":"shared","version":"1.0","properties":[
   {"name":"syft:package:type","value":"deb"},
   {"name":"syft:location:0:path","value":"/overlay2/APPONE/diff/var/lib/dpkg/status"},
   {"name":"syft:location:1:path","value":"/overlay2/APPTWO/diff/var/lib/dpkg/status"}]},
 {"type":"library","name":"plain","version":"1.0","properties":[
   {"name":"syft:package:type","value":"deb"},
   {"name":"syft:location:0:path","value":"/overlay2/PLAIN/diff/var/lib/dpkg/status"}]}]}
EOF
    out="$(python3 "$MEMBER" "$STORE" "$STORE/store.cdx.json" 2>/dev/null)"
    purl_of() {
        printf '%s' "$out" | jq -r --arg n "$1" \
            '.components[] | select(.name == $n) | .purl // "(none)"'
    }

    if [ "$(purl_of bash)" = "pkg:deb/debian/bash@5.2.37-2%2Bb9?distro=debian-13" ]; then
        pass "a deb with no purl gets one from the os-release in its image's layers"
    else
        fail "the layer's distribution was not turned into a purl" "got $(purl_of bash)"
    fi

    # Trivy matches a distribution advisory on the SOURCE package (libssl3 is
    # fixed by an openssl advisory) and the normalize stage reads that out of the
    # `upstream` qualifier, so a purl without it identifies the wrong thing.
    if [ "$(purl_of libssl3)" = "pkg:deb/debian/libssl3@3.0.15-1?distro=debian-13&upstream=openssl%403.0.15" ]; then
        pass "the source package syft recorded travels in the purl's upstream qualifier"
    else
        fail "the source package is missing from the synthesized purl" "got $(purl_of libssl3)"
    fi

    # An identifier syft wrote is evidence; one written here is a reading of the
    # store. Overwriting the first with the second would lose the architecture and
    # move the component to a different purl than the rootfs scan gives it.
    if [ "$(purl_of curl)" = "pkg:deb/debian/curl@8.0?arch=amd64" ]; then
        pass "a purl syft already wrote is left alone"
    else
        fail "an existing purl was overwritten" "got $(purl_of curl)"
    fi

    # Only deb packages are decided by the distribution. A Python package in the
    # same layer is identified by its own metadata, wherever it is installed.
    if [ "$(purl_of pylib)" = "(none)" ]; then
        pass "a package that is not a deb is not given a distribution's purl"
    else
        fail "a non-deb component was identified as one" "got $(purl_of pylib)"
    fi

    # The same package in two images on different releases: the store says it is
    # in both and nothing there says which build this copy is.
    if [ "$(purl_of shared)" = "(none)" ]; then
        pass "a package spanning two distributions is left unidentified"
    else
        fail "a package was assigned one of two possible distributions" "got $(purl_of shared)"
    fi

    # An image that never says what it runs yields no purl, rather than borrowing
    # the distribution of some other image in the same store.
    if [ "$(purl_of plain)" = "(none)" ]; then
        pass "an image with no os-release does not borrow another image's distribution"
    else
        fail "a distribution was borrowed from an unrelated image" "got $(purl_of plain)"
    fi

    # os-release is allowed to live in /usr/lib, and a layer above the base
    # replaces the one below it the way the running container would see it.
    mkdir -p "$STORE/overlay2/APPONE/diff/usr/lib"
    printf 'ID=debian\nVERSION_ID="13.5"\n' \
        > "$STORE/overlay2/APPONE/diff/usr/lib/os-release"
    out="$(python3 "$MEMBER" "$STORE" "$STORE/store.cdx.json" 2>/dev/null)"
    if [ "$(purl_of bash)" = "pkg:deb/debian/bash@5.2.37-2%2Bb9?distro=debian-13.5" ]; then
        pass "a higher layer's os-release wins, and /usr/lib is read as well as /etc"
    else
        fail "the upper layer's os-release was not read" "got $(purl_of bash)"
    fi
    rm -rf "$STORE"
fi

echo "== the bundled CPE index is still offered what was identified from a layer =="

# The index answers a different question from the distribution advisories, and
# the two disagree. Writing a purl for a container's deb moved it onto the purl
# path and out of this one, which cost four CVEs on a switch OS — `snmp` and
# `pkgconf` were reported by the index alone. Components are offered to both;
# whatever both find is deduplicated on (component, CVE) further downstream.
cpe_in_filter="$(awk '
    /^    jq -n --slurpfile c "\$WORK\/merged.json" / { inside = 1; sub(/^[^\x27]*\x27/, ""); }
    inside { print }
    inside && /cpe-in.json/ { exit }
' "$SCRIPT" | sed "s|\x27 > \"\$WORK/cpe-in.json\"||")"
if [ -z "$cpe_in_filter" ]; then
    fail "could not lift the CPE index input filter out of scan-firmware.sh" "was it renamed?"
else
    offered="$(jq -n --slurpfile c /dev/stdin "$cpe_in_filter" <<'EOF' | jq -r '[.components[].name] | sort | join(",")'
[{"name":"no-purl","version":"1.0","cpe":"cpe:2.3:a:x:no-purl:1.0:*:*:*:*:*:*:*"},
 {"name":"generic","version":"1.0","purl":"pkg:generic/generic@1.0"},
 {"name":"real-purl","version":"1.0","purl":"pkg:deb/debian/real-purl@1.0?arch=amd64&distro=debian-13"},
 {"name":"from-layer","version":"1.0","purl":"pkg:deb/debian/from-layer@1.0?distro=debian-13",
  "properties":[{"name":"bomlens:purlSource","value":"container-store-distro"}]}]
EOF
)"
    if [ "$offered" = "from-layer,generic,no-purl" ]; then
        pass "a purl written from a layer keeps the component on the CPE index path"
    else
        fail "the CPE index input no longer holds what it needs" "offered: ${offered:-nothing}"
    fi
fi

echo "== an app package's own record of its libraries is read =="

# An app written in Kotlin or Java alone carries no package database and no
# native library, so every other identification pass reads nothing out of it.
# Measured on one app: 964 files unpacked, 0 components — while the package
# carried a list of 55 libraries the whole time, one file each under META-INF.
ANDROID="$ROOT_DIR/docker/lib/identify-android-libraries.py"
if [ ! -f "$ANDROID" ]; then
    fail "identify-android-libraries.py is missing" "an app package yields nothing"
elif ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"
else
    APP="$(mktemp -d)"
    mkdir -p "$APP/META-INF" "$APP/assets/META-INF" "$APP/res"
    printf '1.8.0\n' > "$APP/META-INF/androidx.activity_activity-ktx.version"
    printf '1.7.0'   > "$APP/META-INF/androidx.appcompat_appcompat.version"
    # Gradle writes its own task description here when a build never resolves the
    # value. Shipping that as a version is worse than leaving the library out.
    printf "task ':arch:core:core-runtime:writeVersionFile' property 'version'\n" \
        > "$APP/META-INF/androidx.arch.core_core-runtime.version"
    # No `_`, so there is no artifact to name.
    printf '2.0\n' > "$APP/META-INF/nogroup.version"
    # Same file name, somewhere that is not the record Gradle writes.
    printf '9.9\n' > "$APP/res/androidx.fake_fake.version"
    out="$(python3 "$ANDROID" "$APP" 2>/dev/null)"

    got="$(printf '%s' "$out" | jq -r '[.[] | .purl] | sort | join(",")')"
    want="pkg:maven/androidx.activity/activity-ktx@1.8.0,pkg:maven/androidx.appcompat/appcompat@1.7.0"
    if [ "$got" = "$want" ]; then
        pass "each declared library becomes a component at its Maven coordinate"
    else
        fail "the package's own library list was not read" "got: ${got:-nothing}"
    fi

    if printf '%s' "$out" | jq -e 'any(.[]; .version | test("task|property")) | not' >/dev/null; then
        pass "a file holding prose instead of a version yields no component"
    else
        fail "a Gradle task description was shipped as a version"
    fi

    if printf '%s' "$out" | jq -e 'any(.[]; .name == "nogroup") | not' >/dev/null; then
        pass "a version file that names no artifact is left alone"
    else
        fail "a file with no artifact in its name became a component"
    fi

    # The evidence is the directory, not the file name: `META-INF` is where the
    # build records what it put in, and a file of the same name elsewhere is not
    # that record.
    if printf '%s' "$out" | jq -e 'any(.[]; .name == "fake") | not' >/dev/null; then
        pass "a version file outside META-INF is not read as a declaration"
    else
        fail "a file outside the build's own record was read as one"
    fi

    # The coordinate is the identifier the vulnerability step keys on, so the
    # group has to survive the split at the first underscore.
    got="$(printf '%s' "$out" | jq -r '[.[] | select(.name == "activity-ktx") | .group][0]')"
    if [ "$got" = "androidx.activity" ]; then
        pass "the group and the artifact are split at the right underscore"
    else
        fail "the Maven coordinate was split wrong" "group came out as $got"
    fi

    # A nested app package (an app inside an installer, an app's own bundle) keeps
    # its record in a META-INF of its own, wherever it lands in the tree.
    mkdir -p "$APP/inner/base/META-INF"
    printf '1.6.8\n' > "$APP/inner/base/META-INF/androidx.compose.runtime_runtime.version"
    if [ "$(python3 "$ANDROID" "$APP" 2>/dev/null | jq 'length')" = "3" ]; then
        pass "a record nested deeper in the tree is read too"
    else
        fail "only the top-level META-INF was read"
    fi
    rm -rf "$APP"
fi

echo "== an iOS package's frameworks are read from what each one states =="

# An iOS package has no package database and its binaries are Mach-O, which the
# ELF reader does not open, so nothing above finds anything in one. What it does
# carry is a bundle per shipped framework, each stating its name and version.
# Measured on four packages: a supplier's app ships CocoaLumberjack 3.0.0 and two
# more frameworks, and three public apps ship OpenSSL at an exact version — all
# previously reported as nothing.
IOS="$ROOT_DIR/docker/lib/identify-ios-frameworks.py"
if [ ! -f "$IOS" ]; then
    fail "identify-ios-frameworks.py is missing" "an iOS package yields nothing"
elif ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"
else
    IPA="$(mktemp -d)"
    APPDIR="$IPA/Payload/Demo.app"
    mkdir -p "$APPDIR/Frameworks"
    plist() {
        # $1 = destination directory, rest = key/value pairs
        local dest="$1"; shift
        {
            printf '<?xml version="1.0" encoding="UTF-8"?>\n'
            printf '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            printf '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            printf '<plist version="1.0"><dict>\n'
            while [ "$#" -ge 2 ]; do
                printf '  <key>%s</key><string>%s</string>\n' "$1" "$2"
                shift 2
            done
            printf '</dict></plist>\n'
        } > "$dest/Info.plist"
    }
    plist "$APPDIR" CFBundleIdentifier com.example.demo CFBundleShortVersionString 1.0
    mkdir -p "$APPDIR/Frameworks/OpenSSL.framework"
    plist "$APPDIR/Frameworks/OpenSSL.framework" \
        CFBundleName OpenSSL CFBundleIdentifier com.github.krzyzanowskim.OpenSSL \
        CFBundleShortVersionString 3.3.3001
    # A bundle can be named one thing and hold another, so the directory name is
    # the fallback and not the answer.
    mkdir -p "$APPDIR/Frameworks/CydiaSubstrate.framework"
    plist "$APPDIR/Frameworks/CydiaSubstrate.framework" \
        CFBundleName ElleKit CFBundleIdentifier libellekit.dylib \
        CFBundleShortVersionString 1.1.3
    # Swift Package Manager puts a build hash in the name, in the bundle as well
    # as in the directory. It identifies one build, not a component.
    mkdir -p "$APPDIR/Frameworks/KeychainAccess_2B8FF55066FFBF8C_PackageProduct.framework"
    plist "$APPDIR/Frameworks/KeychainAccess_2B8FF55066FFBF8C_PackageProduct.framework" \
        CFBundleName KeychainAccess_2B8FF55066FFBF8C_PackageProduct \
        CFBundleIdentifier keychainaccess.KeychainAccess CFBundleShortVersionString 1.0
    # The app's own code, split into a framework rather than brought in.
    mkdir -p "$APPDIR/Frameworks/DemoCore.framework"
    plist "$APPDIR/Frameworks/DemoCore.framework" \
        CFBundleName DemoCore CFBundleIdentifier com.example.demo.DemoCore \
        CFBundleShortVersionString 1.0
    # States no version at all.
    mkdir -p "$APPDIR/Frameworks/Silent.framework"
    plist "$APPDIR/Frameworks/Silent.framework" CFBundleName Silent
    out="$(python3 "$IOS" "$IPA" 2>/dev/null)"
    ios_names="$(printf '%s' "$out" | jq -r '[.[] | "\(.name)@\(.version)"] | sort | join(",")')"

    if [ "$ios_names" = "DemoCore@1.0,ElleKit@1.1.3,KeychainAccess@1.0,OpenSSL@3.3.3001" ]; then
        pass "each shipped framework becomes a component at the version it states"
    else
        fail "the package's frameworks were not read as stated" "got: ${ios_names:-nothing}"
    fi

    # `CydiaSubstrate.framework` holding ElleKit is the measured case.
    if printf '%s' "$out" | jq -e 'any(.[]; .name == "ElleKit")' >/dev/null; then
        pass "the name comes from the bundle, not from the directory it sits in"
    else
        fail "a framework was named after its directory"
    fi

    # The hash identifies one build. Keeping it would make the same library a new
    # component on every rebuild.
    if printf '%s' "$out" | jq -e 'any(.[]; .name == "KeychainAccess")' >/dev/null; then
        pass "a Swift Package Manager build hash is not part of the name"
    else
        fail "the build hash stayed in the component name"
    fi

    # Marked, not dropped: the rule reads a hand-written identifier and one of the
    # four packages measured spells it without the separator, so it misses there.
    owned="$(printf '%s' "$out" | jq -r '[.[] | select(any(.properties[];
        .name == "bomlens:appOwnedFramework")) | .name] | join(",")')"
    if [ "$owned" = "DemoCore" ]; then
        pass "a framework that is the app's own code is marked, and still reported"
    else
        fail "the app-owned mark is wrong" "marked: ${owned:-none}"
    fi

    # A framework in the package that states no version is a different answer from
    # a framework that is not there, so the count is said out loud.
    if python3 "$IOS" "$IPA" 2>&1 >/dev/null | grep -q "1 framework(s) stated no version"; then
        pass "a framework that states no version is reported as left out"
    else
        fail "a framework with no version was dropped silently"
    fi

    # An app extension carries its own frameworks, and they ship in the package
    # just the same.
    mkdir -p "$APPDIR/PlugIns/Share.appex/Frameworks/Alamofire.framework"
    plist "$APPDIR/PlugIns/Share.appex/Frameworks/Alamofire.framework" \
        CFBundleName Alamofire CFBundleIdentifier org.alamofire.Alamofire \
        CFBundleShortVersionString 5.9.1
    if python3 "$IOS" "$IPA" 2>/dev/null | jq -e 'any(.[]; .name == "Alamofire")' >/dev/null; then
        pass "a framework under an app extension is read too"
    else
        fail "only the top-level Frameworks directory was read"
    fi
    rm -rf "$IPA"
fi

echo "== the dependency graph survives the merge instead of being dropped =="

# syft reads what each package depends on out of the package database and writes
# it beside the components. The merge took component arrays only, so the graph
# never reached the SBOM and the conformance report reported "0 edges" as a
# required failure — which read as a limit of reading an unpacked image and was
# in fact this. Measured on one root filesystem: 8,158 components, 317 of them
# with a dependency recorded.
CARRY="$ROOT_DIR/docker/lib/carry-dependencies.py"
if [ ! -f "$CARRY" ]; then
    fail "carry-dependencies.py is missing" "the SBOM ships without a dependency graph"
elif ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not available"
else
    DEPW="$(mktemp -d)"
    cat > "$DEPW/merged.json" <<'EOF'
[{"bom-ref":"kept","type":"library","name":"openssl","version":"3.0.1"},
 {"bom-ref":"survivor","type":"library","name":"zlib","version":"1.3"},
 {"bom-ref":"lonely","type":"library","name":"solo","version":"1.0"}]
EOF
    # What a pass produced before the merge: one reference that survives as it is,
    # one whose record was merged into another, and one whose component is gone.
    cat > "$DEPW/src.json" <<'EOF'
{"components":[
  {"bom-ref":"kept","type":"library","name":"openssl","version":"3.0.1"},
  {"bom-ref":"merged-away","type":"library","name":"zlib","version":"1.3"},
  {"bom-ref":"dropped","type":"library","name":"gone","version":"9.9"}],
 "dependencies":[
  {"ref":"kept","dependsOn":["merged-away","dropped"]},
  {"ref":"dropped","dependsOn":["kept"]},
  {"ref":"merged-away","dependsOn":[]}]}
EOF
    out="$(python3 "$CARRY" "$DEPW/merged.json" "$DEPW/src.json" 2>/dev/null)"

    got="$(printf '%s' "$out" | jq -r '[.[] | "\(.ref)->\(.dependsOn | join("+"))"] | sort | join(",")')"
    if [ "$got" = "kept->survivor" ]; then
        pass "a reference is followed to the record that survived the merge"
    else
        fail "the graph was not carried across correctly" "got: ${got:-nothing}"
    fi

    # A reference to a component that is not in the SBOM makes the document
    # invalid for a reader that resolves them — worse than a missing edge.
    if printf '%s' "$out" | jq -e 'all(.[]; all(.dependsOn[]; . != "dropped"))' >/dev/null \
       && printf '%s' "$out" | jq -e 'all(.[]; .ref != "dropped")' >/dev/null; then
        pass "an edge whose endpoint did not survive is dropped, not left dangling"
    else
        fail "a dangling reference reached the dependency graph"
    fi

    # Two records that turned out to be one must not become a self-loop.
    cat > "$DEPW/self.json" <<'EOF'
{"components":[
  {"bom-ref":"one","type":"library","name":"openssl","version":"3.0.1"},
  {"bom-ref":"two","type":"library","name":"openssl","version":"3.0.1"}],
 "dependencies":[{"ref":"one","dependsOn":["two"]}]}
EOF
    if [ "$(python3 "$CARRY" "$DEPW/merged.json" "$DEPW/self.json" 2>/dev/null | jq 'length')" = "0" ]; then
        pass "two records of one component do not become a dependency on itself"
    else
        fail "the merge produced a self-referencing edge"
    fi

    # More than one pass contributes, and an edge named by both is one edge.
    cat > "$DEPW/second.json" <<'EOF'
{"components":[{"bom-ref":"kept","type":"library","name":"openssl","version":"3.0.1"},
               {"bom-ref":"survivor","type":"library","name":"zlib","version":"1.3"}],
 "dependencies":[{"ref":"kept","dependsOn":["survivor"]}]}
EOF
    n=$(python3 "$CARRY" "$DEPW/merged.json" "$DEPW/src.json" "$DEPW/second.json" 2>/dev/null \
        | jq '[.[].dependsOn[]] | length')
    if [ "$n" = "1" ]; then
        pass "the same edge from two passes is reported once"
    else
        fail "an edge was duplicated across passes" "got $n"
    fi
    rm -rf "$DEPW"
fi

# The graph has to reach the document, not just be computed.
if grep -q 'dependencies: \$deps\[0\]' "$SCRIPT"; then
    pass "the SBOM carries the dependency graph it computed"
else
    fail "the computed dependency graph is not written to the SBOM" \
         "the conformance report would keep reporting 0 edges"
fi

echo "== a version is compared as a number, and an uncomparable one matches nothing =="

# The CPE index records version bounds as plain numbers, while projects write
# releases with prefixes (the Go toolchain's `go1.25.6`, a Go module's `v0.37.0`).
# A bound holds only when both sides can be compared as versions.
if command -v python3 >/dev/null 2>&1; then
    if python3 - "$ROOT_DIR/docker/lib/firmware-cpe-match.py" <<'CPEPY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("m", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# A prefixed version compares as the number it is.
assert m.vcmp("go1.25.6", "1.25.6") == 0, m.vcmp("go1.25.6", "1.25.6")
assert m.vcmp("v0.37.0", "0.37.0") == 0
assert m.vcmp("go1.24.0", "1.25.0") < 0
assert m.vcmp("v1.2.0", "1.1.9") > 0

# A bounded range rejects a version above it, prefix or not.
assert m.in_range("go1.25.6", None, "1.20.0", 1, "1.24.0", 0) is False
assert m.in_range("go1.22.0", None, "1.20.0", 1, "1.24.0", 0) is True
assert m.in_range("v0.99.0", None, None, None, "0.40.0", 0) is False

# Only `go`/`v` immediately before a digit are dropped. A version is not a
# free-text field: stripping more would match releases that are genuinely
# different.
assert m._strip_version_prefix("vendor-1.0") == "vendor-1.0"
assert m._strip_version_prefix("golang1.2") == "golang1.2"
assert m._strip_version_prefix("v1.0") == "1.0"
assert m._strip_version_prefix("go1.0") == "1.0"
assert m._strip_version_prefix(None) is None

# An advisory with no bounds at all still means every version, which is NVD's
# own way of saying so and must not be broken by the above.
assert m.in_range("1.0", None, None, None, None, None) is True

# A value that is not a version matches nothing. UNKNOWN is what this pipeline
# writes when no version was recovered.
assert m.usable_version("UNKNOWN") is False
assert m.usable_version("unknown") is False
assert m.usable_version("-") is False
assert m.usable_version("") is False
assert m.usable_version(None) is False
assert m.in_range("UNKNOWN", None, "1.0", 1, "2.0", 0) is False
assert m.in_range("UNKNOWN", None, None, None, None, None) is False

# Real release forms stay usable: letter suffixes and Debian epochs included.
for v in ("1.0.2h", "2:9.1.1230-2", "1.7.1", "4.9.2-1", "0.11.0"):
    assert m.usable_version(v), v
CPEPY
    then
        pass "a prefixed version compares as its number, and a bounded range still bounds"
    else
        fail "version prefix handling is wrong (see assertion above)"
    fi
else
    echo "  SKIP: python3 not available"
fi

# The matching runs over the merged component set, so a component named by any
# pass is offered to it.
if awk '/^# ④.6 CPE -> CVE matching/,/^fi$/' "$SCRIPT" | grep -q 'merged.json'; then
    pass "CPE matching reads the merged component set"
else
    fail "CPE matching does not read the merged set"
fi

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
