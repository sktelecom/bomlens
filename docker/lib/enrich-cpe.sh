#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# enrich-cpe.sh — attach a cpe:2.3 AND a confirmed SPDX license to whitelisted
# components so Trivy can match CVEs by CPE (Plan 1) and the NOTICE / license
# distribution are not blank for famous OSS.
#
# Usage: enrich-cpe.sh <sbom.json>
#
# Why: firmware / image / rootfs SBOMs match few/no CVEs in Trivy and carry no
# license for famous OSS, fixed here for WHITELISTED component names only
# (cpe-name-map.json):
#
#   (a) No cpe at all. A component with name+version but no purl/cpe is invisible
#       to Trivy's matchers. We synthesize
#         cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
#       so the CPE matcher can find its CVEs.
#
#   (b) A cpe whose VERSION carries a distro package-revision suffix. syft labels
#       OpenWRT/Buildroot packages with versions like `1.30.1-5` or `2.80-15`
#       (upstream version + a distro rebuild count). NVD's CPE version is the bare
#       upstream `1.30.1` / `2.80`, so Trivy's CPE compare misses and the report is
#       empty even though the cpe vendor/product are right. For whitelisted names
#       we rewrite the cpe's version to the upstream prefix (revision suffix
#       stripped) AND, when vendor/product disagree with our curated map, correct
#       them — so the famous-OSS CVEs actually match.
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
# CPE version matches NVD. OpenWRT/Buildroot append `-<rebuild>` to the upstream
# version (1.30.1-5 -> 1.30.1, 2.80-15 -> 2.80). We only strip `-<digits>` at the
# very end (a conservative rule): a non-numeric suffix (e.g. -rc1, -beta) is a
# real upstream qualifier and is kept. Applied to whitelisted names only.
# has_license: true when the component already carries any usable license entry
# (an id, a name, or an SPDX expression). We only fill a license when this is
# false, so syft-populated licenses are never overwritten.
#
# spdx_licenses(s): a confirmed SPDX expression containing " OR "/" AND " (a dual
# or multi-license) becomes a single {expression:...} entry; a bare id becomes
# {license:{id:...}}. Matches CycloneDX licenses[] shape used downstream.
if jq --argjson cmap "$CMAP" '
  def safe_ver(v): (v // "") | test("^[A-Za-z0-9][A-Za-z0-9_.+-]*$");
  def upstream_ver(v): (v // "") | sub("-[0-9]+$"; "");
  def has_license: ((.licenses // []) | type=="array")
    and ((.licenses // []) | any(
      ((.license.id // "") != "") or
      ((.license.name // "") != "") or
      ((.expression // "") != "")));
  def spdx_licenses($s):
    if ($s | test(" OR | AND "))
    then [ { expression: $s } ]
    else [ { license: { id: $s } } ] end;

  (.components) |= (if type=="array" then map(
    (((.name // "") | ascii_downcase)) as $n
    | ($cmap[$n]) as $m
    # (a)+(b) CPE enrichment for whitelisted names with a CPE-safe version.
    | (if ($m != null) and (safe_ver(.version))
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
    N=$(jq '[.components[]? | select((.properties // []) | any(.name=="bomlens:cpeSource"))] | length' "$TMP" 2>/dev/null || echo 0)
    L=$(jq '[.components[]? | select((.properties // []) | any(.name=="bomlens:licenseSource"))] | length' "$TMP" 2>/dev/null || echo 0)
    mv "$TMP" "$SBOM"
    echo "[cpe] set/normalized a whitelisted cpe:2.3 on ${N} component(s) for CVE matching."
    echo "[cpe] filled a confirmed SPDX license on ${L} previously license-null whitelisted component(s)."
else
    rm -f "$TMP"
    echo "[cpe] WARN: CPE enrichment jq failed; leaving SBOM unchanged" >&2
fi
