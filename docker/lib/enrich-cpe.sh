#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# enrich-cpe.sh — attach a normalized cpe:2.3 AND a confirmed SPDX license to
# whitelisted components so the NOTICE / license distribution are not blank for
# famous OSS and the CPE identifier is correct for SBOM consumers that key on it.
#
# Usage: enrich-cpe.sh <sbom.json>
#
# NOTE ON CVE MATCHING: `trivy sbom` matches components by PURL (and, for distro
# packages, by an operating-system component — see enrich-os-context.py), NOT by
# `component.cpe`. A CPE attached here is therefore not a Trivy input on its own
# and does not by itself produce findings; measurements confirmed a CPE-only
# component (e.g. openssl@1.0.1f) yields 0 Trivy findings (issue #458). Distro CVE
# matching comes from the synthesized OS component; firmware binaries with no
# usable PURL are covered by the cve-bin-tool sidecar (scan-security.sh). The CPE
# is retained here for correctness and for downstream consumers that read it.
#
# Why: firmware / image / rootfs SBOMs carry no license for famous OSS, and their
# CPEs (where present) carry distro-suffixed versions. Fixed here for WHITELISTED
# component names only (cpe-name-map.json):
#
#   (a) No cpe at all. A component with name+version but no purl/cpe carries no
#       usable identifier. We synthesize
#         cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
#       so the SBOM records a correct, NVD-shaped CPE for that component.
#
#   (b) A cpe whose VERSION carries a distro package-revision suffix. syft labels
#       OpenWRT/Buildroot/Alpine packages with versions like `1.30.1-5`, `2.80-15`
#       or `1.36.1-r2` (upstream version + a distro rebuild count). NVD's CPE
#       version is the bare upstream `1.30.1` / `2.80` / `1.36.1`. For whitelisted
#       names we rewrite the cpe's version to the upstream prefix (revision suffix
#       stripped) AND, when vendor/product disagree with our curated map, correct
#       them — so the recorded CPE is the NVD-canonical identifier.
#
#   (c) No license. syft reads name+version from opkg/dpkg entries but not the
#       license metadata, so famous OSS (busybox, dropbear, dnsmasq, ...) arrive
#       license-null. For a whitelisted name that carries a confirmed `spdx_license`
#       AND only when the component has no license yet, we fill CycloneDX
#       licenses[] from the curated SPDX id/expression. A pre-existing license
#       (e.g. one syft did populate) is NEVER overwritten — syft is trusted.
#
# Accuracy first: a name->CPE guess (or a version rewrite, or a license) for an
# UNKNOWN component invents false-positives (a wrong vuln or a wrong license is
# worse than an empty result), so ONLY whitelisted names are touched, and only
# licenses confirmed against the upstream project are listed in the map. Versions
# that are not CPE-safe are left as-is.
#
# Generic by design: applies to any CycloneDX SBOM (FIRMWARE, IMAGE, ROOTFS, ...).
set -e

SBOM="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[cpe] SBOM file not found: $SBOM" >&2
    exit 1
fi
if ! jq empty "$SBOM" 2>/dev/null; then
    echo "[cpe] WARN: $SBOM is not valid JSON; skipping CPE enrichment" >&2
    exit 0
fi

MAP_FILE="$SCRIPT_DIR/cpe-name-map.json"
if [ ! -f "$MAP_FILE" ]; then
    echo "[cpe] WARN: cpe-name-map.json not found; skipping CPE enrichment" >&2
    exit 0
fi
# Drop the documentation key(s) so the lookup map holds only real entries.
CMAP=$(jq 'with_entries(select(.key | startswith("_") | not))' "$MAP_FILE" 2>/dev/null || echo '{}')

TMP="$(mktemp)"
# CPE-safe version guard: a ':' (cpe field separator), space, or wildcard (*/?) in
# the version would shift or break the 13-field cpe:2.3 grammar and could make
# Trivy reject the whole SBOM. Same guard as normalize-sbom.sh's vendored fix.
#
# upstream_ver: strip a SINGLE trailing distro package-revision segment so the
# CPE version matches NVD. OpenWRT/Buildroot append `-<rebuild>` and OpenWRT/Alpine
# an `-r<rebuild>` to the upstream version (1.30.1-5 -> 1.30.1, 2.80-15 -> 2.80,
# 1.36.1-r2 -> 1.36.1). We only strip `-<digits>` or `-r<digits>` at the very end
# (a conservative rule): any other non-numeric suffix (e.g. -rc1, -beta) is a real
# upstream qualifier and is kept. Applied to whitelisted names only.
# has_license: true when the component already carries any usable license entry
# (an id, a name, or an SPDX expression). We only fill a license when this is
# false, so syft-populated licenses are never overwritten.
#
# spdx_licenses(s): a confirmed SPDX expression containing " OR "/" AND " (a dual
# or multi-license) becomes a single {expression:...} entry; a bare id becomes
# {license:{id:...}}. Matches CycloneDX licenses[] shape used downstream.
if jq --argjson cmap "$CMAP" '
  def safe_ver(v): (v // "") | test("^[A-Za-z0-9][A-Za-z0-9_.+-]*$");
  def upstream_ver(v): (v // "") | sub("-r?[0-9]+$"; "");
  def has_license: ((.licenses // []) | type=="array")
    and ((.licenses // []) | any(
      ((.license.id // "") != "") or
      ((.license.name // "") != "") or
      ((.expression // "") != "")));
  def spdx_licenses($s):
    if ($s | test(" OR | AND "))
    then [ { expression: $s } ]
    else [ { license: { id: $s } } ] end;

  # A producer that identified the component can also have decided that no
  # identifier is safe for it, and says so with bomlens:cpeUnmapped. Matching on
  # the name here would overrule that from further away with less information.
  # Measured: a firmware carries uClibc 1.0.22, which is uClibc-ng, and the name
  # map turns any component called uclibc into uclibc:uclibc, which would hand it
  # the advisories of a different project.
  # (No apostrophes in this block: the whole jq program is single-quoted here.)
  def cpe_withheld: any((.properties // [])[];
                        .name == "bomlens:cpeUnmapped" and .value == "true");

  # A Linux kernel module is not a product, and the CPE syft gives it is built
  # out of the module name: 8021q.ko becomes cpe:2.3:a:8021q:8021q:1.8, and the
  # 1.8 is the modules own modinfo field rather than a release of anything. Most
  # of those names match nothing in the index, which is why this has cost nothing
  # so far, but the collisions are real. A MikroTik image carries a wireguard
  # module at 1.0.0 and wireguard:wireguard is in the index with rows at 0.5.3;
  # only the version kept them apart. This project does not attach an identifier
  # it cannot justify, and there is no reason to keep one either.
  #
  # The module itself is kept. It is a real file, its licence is real, and the
  # kernel it belongs to is reported separately with its own version. What goes
  # is the guess about its identity, marked the way a producer marks one so
  # nothing downstream puts it back.
  def kernel_module: any((.properties // [])[];
                         .name == "syft:package:type" and .value == "linux-kernel-module");

  (.components) |= (if type=="array" then map(
    (if kernel_module and ((.cpe // "") != "")
     then del(.cpe)
          | .properties = (((.properties // [])
              | map(select(.name != "bomlens:cpeUnmapped" and .name != "bomlens:cpeSource")))
              + [{name:"bomlens:cpeUnmapped", value:"true"},
                 {name:"bomlens:cpeSource", value:"withheld-kernel-module"}])
     else . end)
    | (((.name // "") | ascii_downcase)) as $n
    | ($cmap[$n]) as $m
    # (a)+(b) CPE enrichment for whitelisted names with a CPE-safe version.
    | (if ($m != null) and (safe_ver(.version)) and (cpe_withheld | not)
      then
        (upstream_ver(.version)) as $uv
        | ("cpe:2.3:a:" + $m.cpe_vendor + ":" + $m.cpe_product + ":" + $uv + ":*:*:*:*:*:*:*") as $cpe
        | (if (.cpe == $cpe) then .   # idempotent: already our cpe
           else
             . + { cpe: $cpe }
             | .properties = (((.properties // []) | map(select(.name != "bomlens:cpeSource")))
                 + [{name:"bomlens:cpeSource", value:"name-map"}])
           end)
      else . end)
    # (c) License enrichment: only a whitelisted name with a confirmed spdx_license
    # AND no existing license. Idempotent via bomlens:licenseSource=name-map.
    | (if ($m != null) and (($m.spdx_license // "") != "") and (has_license | not)
      then
        .licenses = spdx_licenses($m.spdx_license)
        | .properties = (((.properties // []) | map(select(.name != "bomlens:licenseSource")))
            + [{name:"bomlens:licenseSource", value:"name-map"}])
      else . end)
  ) else . end)
' "$SBOM" > "$TMP" 2>/dev/null; then
    N=$(jq '[.components[]? | select((.properties // []) | any(
             .name=="bomlens:cpeSource" and .value != "withheld-kernel-module"))] | length' "$TMP" 2>/dev/null || echo 0)
    L=$(jq '[.components[]? | select((.properties // []) | any(.name=="bomlens:licenseSource"))] | length' "$TMP" 2>/dev/null || echo 0)
    K=$(jq '[.components[]? | select((.properties // []) | any(
             .name=="bomlens:cpeSource" and .value=="withheld-kernel-module"))] | length' "$TMP" 2>/dev/null || echo 0)
    mv "$TMP" "$SBOM"
    echo "[cpe] set/normalized a whitelisted cpe:2.3 on ${N} component(s) for CVE matching."
    echo "[cpe] filled a confirmed SPDX license on ${L} previously license-null whitelisted component(s)."
    if [ "${K:-0}" -gt 0 ]; then
        echo "[cpe] withheld a name-derived cpe from ${K} Linux kernel module(s); the module name is not a product and the kernel is reported separately."
    fi
else
    rm -f "$TMP"
    echo "[cpe] WARN: CPE enrichment jq failed; leaving SBOM unchanged" >&2
fi
