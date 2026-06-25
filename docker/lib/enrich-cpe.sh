#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# enrich-cpe.sh — attach a cpe:2.3 to whitelisted components so Trivy can match
# CVEs by CPE (Plan 1).
#
# Usage: enrich-cpe.sh <sbom.json>
#
# Why: firmware / image / rootfs SBOMs match few/no CVEs in Trivy for two reasons,
# both fixed here for WHITELISTED component names only (cpe-name-map.json):
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
# Accuracy first: a name->CPE guess (or a version rewrite) for an UNKNOWN
# component invents false-positive CVEs (worse than an empty result), so ONLY
# whitelisted names are touched. Versions that are not CPE-safe are left as-is.
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
if jq --argjson cmap "$CMAP" '
  def safe_ver(v): (v // "") | test("^[A-Za-z0-9][A-Za-z0-9_.+-]*$");
  def upstream_ver(v): (v // "") | sub("-[0-9]+$"; "");

  (.components) |= (if type=="array" then map(
    (((.name // "") | ascii_downcase)) as $n
    | ($cmap[$n]) as $m
    | if ($m != null) and (safe_ver(.version))
      then
        (upstream_ver(.version)) as $uv
        | ("cpe:2.3:a:" + $m.cpe_vendor + ":" + $m.cpe_product + ":" + $uv + ":*:*:*:*:*:*:*") as $cpe
        | (if (.cpe == $cpe) then .   # idempotent: already our cpe
           else
             . + { cpe: $cpe }
             | .properties = (((.properties // []) | map(select(.name != "bomlens:cpeSource")))
                 + [{name:"bomlens:cpeSource", value:"name-map"}])
           end)
      else . end
  ) else . end)
' "$SBOM" > "$TMP" 2>/dev/null; then
    N=$(jq '[.components[]? | select((.properties // []) | any(.name=="bomlens:cpeSource"))] | length' "$TMP" 2>/dev/null || echo 0)
    mv "$TMP" "$SBOM"
    echo "[cpe] set/normalized a whitelisted cpe:2.3 on ${N} component(s) for CVE matching."
else
    rm -f "$TMP"
    echo "[cpe] WARN: CPE enrichment jq failed; leaving SBOM unchanged" >&2
fi
