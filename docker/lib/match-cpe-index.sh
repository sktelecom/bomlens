#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# match-cpe-index.sh - match the SBOM's CPEs against the bundled NVD CPE index.
#
# Usage: match-cpe-index.sh <sbom.json> <out_prefix>
#   writes <out_prefix>_security_cvebintool.json when at least one CVE matched
#   prints  {"offered":N,"components":N,"cves":N} on stdout (the step's counts)
#
# Exit status: 0 matched (zero CVEs included), 3 no index in this image,
# 4 turned off (CVE_BIN_TOOL_MODE=components-only), 1 the match failed.
#
# Trivy matches by purl and operating-system context and never reads
# component.cpe. A component with no purl, a `pkg:generic` one, an opkg one or
# one that points at a source repository (a binary syft's classifier named, a library
# the firmware signature checkers found, an OS component such as busybox) is
# reached by nothing else. Run by entrypoint.sh for FIRMWARE, ROOTFS and BINARY,
# and for a Yocto SPDX 2.2 archive, after every CPE enrichment step, so a CPE
# added from cpe-name-map.json is matched too.
#
# The rows go into the sidecar scan-security.sh merges into _security.json,
# keyed on (package, CVE), so a CVE Trivy also reports is counted once. The
# file keeps its historical name; the engine contract lists it as the
# `cve-bin-tool` engine's result.
set -e

# Exit 3 means only "no index in this image" (the pipeline records it as
# skipped). Any other way out with 3, such as a jq compile error under set -e,
# is reported as a failure.
NO_INDEX=false
WORK=""
on_exit() {
    _rc=$?
    if [ -n "$WORK" ]; then rm -rf "$WORK"; fi
    if [ "$_rc" = 3 ] && [ "$NO_INDEX" != true ]; then
        echo "[cpe-index] the CPE match failed (exit 3 from a command, not a missing index)." >&2
        exit 1
    fi
    exit "$_rc"
}
trap on_exit EXIT

SBOM="$1"
OUT_PREFIX="$2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ] || [ -z "$OUT_PREFIX" ]; then
    echo "[cpe-index] usage: match-cpe-index.sh <sbom.json> <out_prefix>" >&2
    exit 1
fi

SIDE="${OUT_PREFIX}_security_cvebintool.json"
# A sidecar from an earlier run in the same folder is not this run's.
rm -f "$SIDE"

if [ "${CVE_BIN_TOOL_MODE:-auto}" = "components-only" ]; then
    echo "[cpe-index] CVE_BIN_TOOL_MODE=components-only: CVE matching is turned off." >&2
    exit 4
fi
# The index is built at image-build time by docker/build-cpe-index.py.
CPE_INDEX="${FW_CPE_INDEX:-${CVE_BIN_TOOL_HOME:-/opt/cve-bin-tool-home}/cpe_match.sqlite}"
if [ ! -f "$CPE_INDEX" ]; then
    echo "[cpe-index] no CPE index at $CPE_INDEX; components with no package purl are not matched." >&2
    echo "[cpe-index] Use an image built with the index (the default build; --build-arg SBOM_CPE_INDEX=true)." >&2
    NO_INDEX=true
    exit 3
fi
if ! command -v python3 >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    echo "[cpe-index] python3 and jq are required to match the CPE index." >&2
    exit 1
fi
if [ ! -f "$SCRIPT_DIR/vuln-coverage.jq" ] || [ ! -f "$SCRIPT_DIR/firmware-cpe-match.py" ]; then
    echo "[cpe-index] vuln-coverage.jq or firmware-cpe-match.py is missing beside $0; the image is incomplete." >&2
    exit 1
fi

WORK="$(mktemp -d)"

# A purl synthesized from a container layer's os-release stays offered here
# (vc_cpe_index_candidate). It was written to reach the distribution advisories,
# which is a different question from what this index answers, and the two
# disagree: measured on one switch OS, giving `snmp` and `pkgconf` a purl and
# taking them out of this pass cost four CVEs that nothing else reported.
if ! jq "$(cat "$SCRIPT_DIR/vuln-coverage.jq")"'
    {components: [ (.components // [])[] | recurse(.components[]?)
                   | select(vc_cpe_index_candidate) ]}' "$SBOM" > "$WORK/cpe-in.json" 2>"$WORK/err"; then
    echo "[cpe-index] could not read the components to match: $(head -c 300 "$WORK/err")" >&2
    exit 1
fi
OFFERED="$(jq '.components | length' "$WORK/cpe-in.json")"

if ! python3 "$SCRIPT_DIR/firmware-cpe-match.py" "$WORK/cpe-in.json" "$CPE_INDEX" \
        > "$WORK/rows.json" 2>"$WORK/err" \
   || ! jq -e 'type == "array"' "$WORK/rows.json" >/dev/null 2>&1; then
    echo "[cpe-index] the CPE match failed: $(head -c 300 "$WORK/err")" >&2
    exit 1
fi

# The Trivy-shaped contract scan-security.sh and the web layer read:
# { Results: [ { Target, Vulnerabilities: [ { VulnerabilityID, PkgName,
# InstalledVersion, Severity, CVSS, PrimaryURL } ] } ] }. NVD severity is upper
# case already; a score becomes CVSS V<n>Score. Identical (CVE, package,
# version) rows are kept once.
if ! jq '
  [ .[]? | select((.cve_number // "") | test("^CVE-")) | {
      VulnerabilityID: .cve_number,
      PkgName: (.product // ""),
      InstalledVersion: (.version // ""),
      Severity: ((.severity // "UNKNOWN") | ascii_upcase),
      PrimaryURL: ("https://nvd.nist.gov/vuln/detail/" + .cve_number),
      CVSS: ( (.score // null) as $s
              | if ($s != null and ($s|tostring|test("^[0-9.]+$")) and (($s|tonumber) > 0))
                then { "cve-bin-tool": { ("V" + ((.cvss_version // "3")|tostring) + "Score"): ($s|tonumber) } }
                else {} end ),
      source: "cve-bin-tool"
    } ]
  | unique_by([.VulnerabilityID, .PkgName, .InstalledVersion])
' "$WORK/rows.json" > "$WORK/vulns.json" 2>"$WORK/err"; then
    echo "[cpe-index] could not shape the matched CVEs: $(head -c 300 "$WORK/err")" >&2
    exit 1
fi

NCVE="$(jq 'length' "$WORK/vulns.json")"
NCOMP="$(jq '[.[] | [.PkgName, .InstalledVersion]] | unique | length' "$WORK/vulns.json")"
if [ "${NCVE:-0}" -gt 0 ]; then
    jq '{ Results: [ { Target: "CPE index (NVD)", Class: "firmware", Vulnerabilities: . } ] }' \
        "$WORK/vulns.json" > "$SIDE"
fi
# Required NVD attribution: the bundled index is derived from NVD data.
echo "[cpe-index] This product uses NVD data but is not endorsed or certified by the NVD." >&2
echo "[cpe-index] ${OFFERED} component(s) with no package purl offered; ${NCVE} CVE(s) matched on ${NCOMP} of them." >&2
jq -nc --argjson o "$OFFERED" --argjson c "$NCOMP" --argjson v "$NCVE" \
    '{offered: $o, components: $c, cves: $v}'
