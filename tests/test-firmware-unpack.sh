#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
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
merge_filter="$(awk '
    /^jq -n --slurpfile a "\$WORK\/pkg-comps.json"/ { inside = 1; next }
    inside && /^'"'"' > "\$WORK\/merged.json"$/ { exit }
    inside { print }
' "$SCRIPT")"
if [ -z "$merge_filter" ]; then
    echo "[ERROR] could not lift the merge filter out of scan-firmware.sh (was it renamed?)"; exit 1
fi

merged="$(jq -n --slurpfile a "$FIX/merge-pkg-comps.json" \
                --slurpfile b "$FIX/merge-bin-comps.json" "$merge_filter")"

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

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
