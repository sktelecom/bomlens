#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# stamp-document-metadata.sh — record who generated this SBOM, with what, and at
# which point in the software lifecycle.
#
# Usage: stamp-document-metadata.sh <sbom.json> <scan_mode>
#
# These are document-level facts about the SBOM itself, not about the software it
# describes, which is why they live here rather than in stamp-metadata.sh (that
# one owns the root component's identity and runs for three modes only). The 2026
# SBOM minimum elements name all three as data fields an SBOM should carry:
# SBOM Generation Context, SBOM Author, SBOM Tool Name and SBOM Tool Version.
#
# Not called for ANALYZE. That mode converts a supplier's own SBOM, and the
# supplier authored the data — stamping our name onto the conversion would claim
# authorship of a document we only reformatted. MERGE is different and IS stamped:
# merge-sbom.sh writes a new document, and it already records itself as the tool
# that produced it.
set -e

SBOM="$1"
MODE="$2"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[docmeta] SBOM file not found: $SBOM" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "[docmeta] ERROR: jq not available; cannot stamp document metadata. This is a build defect — rebuild the image with jq." >&2
    exit 1
fi

if ! jq empty "$SBOM" 2>/dev/null; then
    echo "[docmeta] ERROR: $SBOM is not valid JSON; cannot stamp document metadata." >&2
    exit 1
fi

# Generation context: the lifecycle phase the SBOM describes, which decides what
# the component data can even mean. The minimum elements give the mapping in their
# own words — an SBOM generated from source code is "before build", and one a
# binary analysis tool generates is "after build". Our modes divide exactly along
# that line, so no user input is needed. CycloneDX spells the two phases
# `pre-build` and `post-build`.
#
# cdxgen writes `build` on a source scan and we overwrite it. That value is the
# generator's default, not a reading of this scan, and leaving it would make the
# source path the one mode that disagrees with every other about what phase its
# own output describes.
#
# MERGE gets no phase. It combines SBOMs that were generated at whatever phase
# each input was, and the merged document cannot honestly claim a single one.
LIFECYCLE=""
case "$MODE" in
    SOURCE|POSTPROCESS)                 LIFECYCLE="pre-build" ;;
    ROOTFS|IMAGE|BINARY|FIRMWARE|AIBOM) LIFECYCLE="post-build" ;;
    MERGE)                              LIFECYCLE="" ;;
    *)
        echo "[docmeta] WARN: no lifecycle phase defined for MODE=$MODE; leaving it unset." >&2
        ;;
esac

# SBOM Author: the entity operating the tool, which is not something this
# container can discover — only the person or organisation running the scan knows
# it. Written when SBOM_AUTHOR says so and left absent otherwise.
#
# An absent author is not the same as an unknown one, and neither is a wrong one:
# cdxgen fills metadata.authors with its own publisher, which by definition is not
# whoever ran the scan, so that default is dropped rather than passed off as an
# answer.
SBOM_AUTHOR="${SBOM_AUTHOR:-}"

# SBOM Tool Version. BOMLENS_VERSION is baked in at image build time; a local
# build without it reports the version as unknown, which is what the minimum
# elements ask for when no version identifier is available.
TOOL_VERSION="${BOMLENS_VERSION:-}"
[ -n "$TOOL_VERSION" ] || TOOL_VERSION="unknown"

TMP="$(mktemp)"
if jq --arg lifecycle "$LIFECYCLE" \
      --arg author "$SBOM_AUTHOR" \
      --arg toolver "$TOOL_VERSION" '
    # A tool entry with no version tells the reader nothing about which build
    # produced the SBOM, so an absent one is stated as unknown rather than left
    # out. Both shapes of metadata.tools are in play: CycloneDX 1.5 replaced the
    # flat array with {components,services} and our scanners emit both.
    def fill_tool_versions:
      if (.metadata.tools | type) == "array"
        then .metadata.tools |= map(if ((.version // "") == "") then .version = "unknown" else . end)
      elif (.metadata.tools | type) == "object"
        then .metadata.tools.components |=
               (if type == "array" then map(if ((.version // "") == "") then .version = "unknown" else . end) else . end)
      else . end;
    def has_bomlens:
      ((.metadata.tools // {}) | tostring | contains("\"BomLens\""));
    def add_bomlens($t):
      if has_bomlens then .
      elif (.metadata.tools | type) == "array" then .metadata.tools += [$t]
      elif (.metadata.tools | type) == "object" then .metadata.tools.components = (((.metadata.tools.components // []) + [$t]))
      else .metadata.tools = {components: [$t]} end;

      fill_tool_versions
    # The tool the minimum elements ask about is the one the SBOM author ran, and
    # that is this one: the scanners below produced the raw inventory, but the
    # document being delivered is the one this pipeline normalized, enriched and
    # named. Their entries stay — the question is which tools were involved, not
    # which single tool gets the credit.
    | add_bomlens({type: "application", publisher: "SK Telecom", name: "BomLens", version: $toolver})
    | (if $lifecycle != "" then .metadata.lifecycles = [{phase: $lifecycle}] else . end)
    | (if $author != ""
       then .metadata.authors = [{name: $author}]
       else (.metadata) |= del(.authors) end)
    ' "$SBOM" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$SBOM"
else
    rm -f "$TMP"
    echo "[docmeta] ERROR: could not stamp document metadata (jq transform failed): $SBOM" >&2
    exit 1
fi

echo "[docmeta] tool=BomLens@${TOOL_VERSION}${LIFECYCLE:+, lifecycle=$LIFECYCLE}${SBOM_AUTHOR:+, author=$SBOM_AUTHOR}: $SBOM"
[ -n "$SBOM_AUTHOR" ] || echo "[docmeta] no SBOM author declared (set SBOM_AUTHOR or pass --sbom-author to name the entity that generated this SBOM)"
