#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
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
#
# See docs/supplier-sbom-analysis.md §5. normalize-sbom.sh / generate-notice.sh
# need NO SPDX branch because everything downstream sees CycloneDX.
set -e

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

# --------------------------------------------------------
# Format detection (same rules as validate-sbom.sh).
# --------------------------------------------------------
FORMAT="unknown"
if jq -e '.bomFormat=="CycloneDX" and (.specVersion!=null)' "$INPUT" >/dev/null 2>&1; then
    FORMAT="CycloneDX"
elif jq -e '.spdxVersion!=null' "$INPUT" >/dev/null 2>&1; then
    FORMAT="SPDX-JSON"
elif grep -q '^SPDXVersion:' "$INPUT" 2>/dev/null; then
    FORMAT="SPDX-TagValue"
fi

# --------------------------------------------------------
# jq fallback: SPDX-JSON -> minimal CycloneDX (license-preserving).
# --------------------------------------------------------
spdx_json_to_cdx() {
    jq '{
      bomFormat: "CycloneDX",
      specVersion: "1.6",
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
    SPDX-JSON|SPDX-TagValue)
        echo "[convert] input is $FORMAT; converting to CycloneDX..."
        if command -v syft >/dev/null 2>&1 && syft convert "$INPUT" -o cyclonedx-json@1.6="$OUTPUT" >/dev/null 2>&1 \
           && [ -s "$OUTPUT" ] && jq -e '.bomFormat=="CycloneDX"' "$OUTPUT" >/dev/null 2>&1; then
            echo "[convert] syft convert succeeded."
        elif [ "$FORMAT" = "SPDX-JSON" ]; then
            echo "[convert] WARN: syft convert unavailable/failed; using jq fallback (license-preserving)." >&2
            spdx_json_to_cdx
        else
            echo "[convert] ERROR: cannot convert SPDX Tag-Value without syft." >&2
            exit 1
        fi
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
echo "[convert] CycloneDX ready: $OUTPUT (components=$NCOMP)"
