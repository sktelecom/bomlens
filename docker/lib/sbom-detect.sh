#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# sbom-detect.sh — shared supplier-SBOM input helpers, sourced by
# convert-to-cdx.sh and validate-sbom.sh so both accept the same encodings.
# Definitions only: no `set -e`, no top-level work. Bash only (BASH_SOURCE).

# normalize_sbom_encoding <infile> [workdir]
#   A supplier SBOM saved as UTF-16 (common from Windows tooling, with or without
#   a BOM) or with a UTF-8 BOM is rejected downstream because jq and grep assume
#   UTF-8, so a valid SBOM reads as "unknown format" and is dropped silently.
#   Detect those from the leading bytes and write a UTF-8 copy under <workdir>. As
#   a last resort, when the body still does not parse and a stray non-JSON
#   preamble sits before the first '{', drop that preamble. Nothing is mutated in
#   place: the path to use (the rewritten copy, or the original when no change was
#   needed) is printed on stdout. Diagnostics go to stderr.
#
#   A CycloneDX XML document is also rewritten here, as CycloneDX JSON, so the
#   validator and the converter both read one format (cdx-xml-to-json.py keeps the
#   hashes and the root component that `syft convert` drops). Anything else that
#   is XML is left alone and named by the caller.
normalize_sbom_encoding() {
    _sd_in="$1"
    _sd_workdir="${2:-$(dirname "$1")}"
    _sd_out="$_sd_workdir/.sbom-utf8.$$"
    _sd_path="$_sd_in"

    # Leading 4 bytes decide the encoding: a UTF-16/UTF-8 BOM, or — for BOM-less
    # UTF-16, which Windows tools often emit — the tell-tale NUL byte pattern of
    # ASCII-range JSON ("{\0\"\0" for LE, "\0{\0\"" for BE).
    read -r _b0 _b1 _b2 _b3 <<EOF
$(od -An -tx1 -N4 "$_sd_in" 2>/dev/null)
EOF
    _sd_enc=""
    case "$_b0$_b1" in
        fffe|feff) _sd_enc="UTF-16" ;;                          # BOM: iconv autodetects endianness
    esac
    if [ -z "$_sd_enc" ] && [ "$_b0" = ef ] && [ "$_b1" = bb ] && [ "$_b2" = bf ]; then
        _sd_enc="UTF-8-BOM"
    fi
    if [ -z "$_sd_enc" ]; then
        if [ "$_b1" = 00 ] && [ "$_b3" = 00 ] && [ "$_b0" != 00 ]; then
            _sd_enc="UTF-16LE"
        elif [ "$_b0" = 00 ] && [ "$_b2" = 00 ] && [ "$_b1" != 00 ]; then
            _sd_enc="UTF-16BE"
        fi
    fi

    case "$_sd_enc" in
        UTF-16|UTF-16LE|UTF-16BE)
            if iconv -f "$_sd_enc" -t UTF-8 "$_sd_in" > "$_sd_out" 2>/dev/null && [ -s "$_sd_out" ]; then
                echo "[detect] normalized $_sd_enc input to UTF-8" >&2
                _sd_path="$_sd_out"
            fi
            ;;
        UTF-8-BOM)
            if tail -c +4 "$_sd_in" > "$_sd_out" 2>/dev/null && [ -s "$_sd_out" ]; then
                echo "[detect] stripped UTF-8 BOM" >&2
                _sd_path="$_sd_out"
            fi
            ;;
    esac

    # Still not valid JSON and not SPDX Tag-Value, but a '{' exists past a stray
    # preamble (some tools prepend non-JSON bytes): drop everything before the
    # first '{'. Conservative — kept only if the result then parses as JSON.
    if ! jq -e . "$_sd_path" >/dev/null 2>&1 && ! grep -q '^SPDXVersion:' "$_sd_path" 2>/dev/null; then
        _sd_off=$(LC_ALL=C grep -aob '{' "$_sd_path" 2>/dev/null | head -1 | cut -d: -f1)
        if [ -n "$_sd_off" ] && [ "$_sd_off" -gt 0 ] 2>/dev/null; then
            _sd_strip="$_sd_workdir/.sbom-strip.$$"
            if tail -c +"$((_sd_off + 1))" "$_sd_path" > "$_sd_strip" 2>/dev/null \
               && jq -e . "$_sd_strip" >/dev/null 2>&1; then
                echo "[detect] dropped stray non-JSON preamble before first '{'" >&2
                _sd_path="$_sd_strip"
            fi
        fi
    fi

    # CycloneDX XML: the namespace is looked for in the decoded head, so UTF-16
    # (converted above, or BOM-less) is found the same way as UTF-8.
    if ! jq -e . "$_sd_path" >/dev/null 2>&1 \
       && { LC_ALL=C head -c 4096 "$_sd_path" 2>/dev/null | tr -d '\000' | grep -aq 'cyclonedx.org/schema/bom'; } \
       && command -v python3 >/dev/null 2>&1; then
        _sd_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        # Keyed by content, so the validator and the converter, which both call
        # this on the same input, convert it once.
        _sd_key=$(cksum < "$_sd_path" | cut -d' ' -f1,2 | tr ' ' '-')
        _sd_xml="$_sd_workdir/.sbom-xml.$_sd_key.json"
        if [ -s "$_sd_xml" ] && jq -e '.bomFormat == "CycloneDX"' "$_sd_xml" >/dev/null 2>&1; then
            _sd_path="$_sd_xml"
        elif [ -f "$_sd_lib/cdx-xml-to-json.py" ] \
             && python3 "$_sd_lib/cdx-xml-to-json.py" "$_sd_path" "$_sd_xml.tmp" >&2 \
             && [ -s "$_sd_xml.tmp" ] && mv "$_sd_xml.tmp" "$_sd_xml"; then
            echo "[detect] read CycloneDX XML and converted it to JSON" >&2
            _sd_path="$_sd_xml"
        fi
    fi

    printf '%s' "$_sd_path"
}
