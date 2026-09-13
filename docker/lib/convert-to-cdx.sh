#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# convert-to-cdx.sh — normalize a supplier SBOM to CycloneDX JSON so the rest of
# the pipeline (normalize/notice/security) has a single input format.
#
# Usage: convert-to-cdx.sh <input_sbom> <output_cyclonedx.json>
#   - CycloneDX input        -> copied as-is
#   - SPDX (JSON/Tag-Value)  -> `syft convert` to cyclonedx-json
#   - syft failure on SPDX-JSON -> jq fallback (.packages[] -> .components[],
#     preserving name/version/purl/license) so license analysis still works.
#   - XML (CycloneDX / SPDX RDF) -> refused by name: convert to JSON and retry.
#
# See docs/supplier-sbom-analysis.md §5. normalize-sbom.sh / generate-notice.sh
# need NO SPDX branch because everything downstream sees CycloneDX.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=docker/lib/cdx-version.sh
. "$SCRIPT_DIR/cdx-version.sh"

INPUT="$1"
OUTPUT="$2"

if [ -z "$INPUT" ] || [ ! -f "$INPUT" ]; then
    echo "[convert] input SBOM not found: $INPUT" >&2
    exit 1
fi
if [ -z "$OUTPUT" ]; then
    echo "[convert] output path required (usage: convert-to-cdx.sh <input> <output.json>)" >&2
    exit 1
fi

# Normalize input encoding (UTF-16/BOM/stray preamble) so jq and syft see UTF-8.
# shellcheck source=docker/lib/sbom-detect.sh
. "$(dirname "$0")/sbom-detect.sh"
INPUT="$(normalize_sbom_encoding "$INPUT" "$(dirname "$OUTPUT")")"

# --------------------------------------------------------
# Format detection (same rules as validate-sbom.sh).
# --------------------------------------------------------
FORMAT="unknown"
if jq -e '.bomFormat=="CycloneDX" and (.specVersion!=null)' "$INPUT" >/dev/null 2>&1; then
    FORMAT="CycloneDX"
elif jq -e '.spdxVersion!=null' "$INPUT" >/dev/null 2>&1; then
    FORMAT="SPDX-JSON"
elif jq -e '(.["@context"]? // "" | tostring | test("spdx.org/rdf/3")) or (.["@graph"]? != null)' "$INPUT" >/dev/null 2>&1; then
    # SPDX 3.0 is JSON-LD (@context/@graph) with no top-level .spdxVersion; syft
    # convert reads it the same as SPDX-JSON.
    FORMAT="SPDX-3.0"
elif grep -q '^SPDXVersion:' "$INPUT" 2>/dev/null; then
    FORMAT="SPDX-TagValue"
elif head -c 4096 "$INPUT" 2>/dev/null | grep -qi -e '^[[:space:]]*<?xml' -e '<bom[ >]' -e '<rdf:RDF'; then
    # CycloneDX XML and SPDX RDF/XML are recognized only to say so: they fall
    # through to a named error instead of "unrecognized format", which sent
    # users looking for a corrupted file rather than a format conversion.
    FORMAT="unsupported-xml"
fi

# --------------------------------------------------------
# jq fallback: SPDX-JSON -> minimal CycloneDX (license-preserving).
# --------------------------------------------------------
spdx_json_to_cdx() {
    jq --arg spec "$CDX_SPEC_VERSION" '{
      bomFormat: "CycloneDX",
      specVersion: $spec,
      version: 1,
      metadata: {
        timestamp: (.creationInfo.created // "1970-01-01T00:00:00Z"),
        component: { type: "application", name: (.name // "supplier-sbom") }
      },
      components: [ .packages[]? | {
        type: "library",
        name: .name,
        version: (.versionInfo // ""),
        purl: ( [ .externalRefs[]? | select(.referenceType=="purl") | .referenceLocator ] | first ),
        licenses: (
          [ (.licenseConcluded // empty), (.licenseDeclared // empty) ]
          | map(select(. != null and . != "" and . != "NOASSERTION"))
          | unique | map({ license: { id: . } })
        )
      } | with_entries(select(.value != null and .value != "" and .value != [])) ]
    }' "$INPUT" > "$OUTPUT"
}

case "$FORMAT" in
    CycloneDX)
        echo "[convert] input is CycloneDX; copying as-is."
        cp "$INPUT" "$OUTPUT"
        ;;
    SPDX-JSON|SPDX-TagValue|SPDX-3.0)
        echo "[convert] input is $FORMAT; converting to CycloneDX..."
        if command -v syft >/dev/null 2>&1 && syft convert "$INPUT" -o "cyclonedx-json@$CDX_SPEC_VERSION=$OUTPUT" >/dev/null 2>&1 \
           && [ -s "$OUTPUT" ] && jq -e '.bomFormat=="CycloneDX"' "$OUTPUT" >/dev/null 2>&1; then
            echo "[convert] syft convert succeeded."
        elif [ "$FORMAT" = "SPDX-JSON" ]; then
            echo "[convert] WARN: syft convert unavailable/failed; using jq fallback (license-preserving)." >&2
            spdx_json_to_cdx
        else
            # SPDX 3.0 JSON-LD and Tag-Value have no jq fallback (the 2.x .packages[]
            # shape does not apply); syft is required.
            echo "[convert] ERROR: cannot convert $FORMAT without syft." >&2
            exit 1
        fi
        ;;
    unsupported-xml)
        echo "[convert] ERROR: XML SBOMs are not supported yet: $INPUT" >&2
        echo "[convert]        This looks like CycloneDX or SPDX in XML. Convert it to JSON and retry, e.g." >&2
        echo "[convert]          cyclonedx convert --input-file bom.xml --output-file bom.json" >&2
        echo "[convert]        or export JSON from the tool that produced it." >&2
        exit 1
        ;;
    *)
        echo "[convert] ERROR: unrecognized SBOM format (not CycloneDX or SPDX): $INPUT" >&2
        exit 1
        ;;
esac

if [ ! -s "$OUTPUT" ] || ! jq -e '.bomFormat=="CycloneDX"' "$OUTPUT" >/dev/null 2>&1; then
    echo "[convert] ERROR: produced output is not valid CycloneDX: $OUTPUT" >&2
    exit 1
fi

NCOMP=$(jq '[.components[]?]|length' "$OUTPUT" 2>/dev/null || echo 0)

# A conversion that returns a valid-but-empty CycloneDX is worse than a failure:
# every later step succeeds, and the report says "no components, no vulnerabilities"
# — which reads as a clean bill of health rather than a broken read. Catch it by
# comparing against the package count in the ORIGINAL document. An input that
# genuinely declares no packages still converts to an empty SBOM without error.
SRC_PKGS=0
case "$FORMAT" in
    SPDX-JSON)
        SRC_PKGS=$(jq '[.packages[]?] | length' "$INPUT" 2>/dev/null || echo 0) ;;
    SPDX-3.0)
        SRC_PKGS=$(jq '[.["@graph"][]? | select(.type == "software_Package")] | length' \
            "$INPUT" 2>/dev/null || echo 0) ;;
esac
if [ "${SRC_PKGS:-0}" -gt 0 ] && [ "${NCOMP:-0}" -eq 0 ]; then
    echo "[convert] ERROR: the input declares $SRC_PKGS package(s) but the conversion produced none." >&2
    echo "[convert]        The SBOM was read but its contents were not understood; not continuing with an empty result." >&2
    exit 1
fi

echo "[convert] CycloneDX ready: $OUTPUT (components=$NCOMP)"
