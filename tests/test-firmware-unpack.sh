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
if [ "$n" = "2" ]; then
    pass "the placeholder is dropped and both real components are kept"
else
    fail "unexpected component count" "expected 2, got $n: $got"
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

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
