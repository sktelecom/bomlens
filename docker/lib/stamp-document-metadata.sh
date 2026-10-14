#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# stamp-document-metadata.sh — record who generated this SBOM, with what, at which
# point in the software lifecycle, and what exactly was scanned.
#
# Usage: stamp-document-metadata.sh <sbom.json> <scan_mode> [<scanned_artifact>]
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
ARTIFACT="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=docker/lib/cdx-version.sh
. "$SCRIPT_DIR/cdx-version.sh"

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
#
# DATASET gets no phase either, for a different reason: it describes a published
# research dataset read from Figshare, not software moving through a build. Neither
# pre-build nor post-build is true of it, so leaving the field absent is the honest
# answer rather than a gap to warn about.
# AIDECLARE describes a model from its publisher's declaration, before it is
# published or built into anything: CycloneDX's `design` phase.
LIFECYCLE=""
case "$MODE" in
    SOURCE|POSTPROCESS)                 LIFECYCLE="pre-build" ;;
    ROOTFS|IMAGE|BINARY|FIRMWARE|AIBOM|MODELFILE) LIFECYCLE="post-build" ;;
    MERGE|DATASET)                      LIFECYCLE="" ;;
    AIDECLARE)                          LIFECYCLE="design" ;;
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

# AIDECLARE is the one mode where the person running it has already said who
# writes the document: the declaration's document.createdBy. With no
# SBOM_AUTHOR, those names become the SBOM author, and
# bomlens:sbom-author-source=declaration records where they came from so a
# reader (and the SPDX 3.0.1 conversion) can tell them from a --sbom-author
# value. An explicit SBOM_AUTHOR still wins. A scanned model given a
# declaration (AIBOM with --ai-declare) is not covered: its CycloneDX file keeps
# to what the scan read.
AUTHORS_JSON="[]"
AUTHOR_SOURCE=""
if [ -n "$SBOM_AUTHOR" ]; then
    AUTHORS_JSON=$(jq -cn --arg a "$SBOM_AUTHOR" '[{name: $a}]')
elif [ "$MODE" = "AIDECLARE" ] && [ -n "${AI_DECLARATION_FILE:-}" ] && [ -f "$AI_DECLARATION_FILE" ]; then
    _declared=$(jq -c '[(.document.createdBy // [])[]? | objects | .name | strings
                        | gsub("^\\s+|\\s+$"; "") | select(length > 0) | {name: .}]
                       | reduce .[] as $a ([]; if any(.[]; .name == $a.name) then . else . + [$a] end)' \
                   "$AI_DECLARATION_FILE" 2>/dev/null || true)
    if [ -n "$_declared" ] && [ "$_declared" != "[]" ]; then
        AUTHORS_JSON="$_declared"
        AUTHOR_SOURCE="declaration"
    fi
fi

# SBOM Tool Version. BOMLENS_VERSION is baked in at image build time; a local
# build without it reports the version as unknown, which is what the minimum
# elements ask for when no version identifier is available.
TOOL_VERSION="${BOMLENS_VERSION:-}"
[ -n "$TOOL_VERSION" ] || TOOL_VERSION="unknown"

# Why a minimum-element field is empty when it is empty. The guidance asks the
# author to say which of two things an absence means: the author does not know the
# value, or the author knows it and is holding it back. A scan only ever produces
# the first. It reads what it can reach and writes what it read; it has no second
# set of findings to withhold, and there is no switch here that would drop one.
#
# Stated once for the document rather than once per empty field. The claim is the
# same for every one of them, and repeating it across the components of a firmware
# image would add thousands of properties saying nothing new. A reader who wants
# to know why a particular license is missing gets the same answer either way.
UNDECLARED_POLICY="unknown-to-author"

# The hash of the thing that was actually scanned, recorded on the component the
# SBOM is about. The minimum elements define this field over an executable
# component artifact, and for a binary or a firmware image that artifact is one
# file — the one named on the command line. A recipient can hash their copy and
# tell whether it is the copy this SBOM describes.
#
# Only for scans whose target IS a file. A source tree has no artifact yet, a
# container image is layers rather than a file, and an installed OS package is a
# set of files spread across a root filesystem with no single one to hash. Making
# something up for those would put a value in a field the guidance defines as the
# hash of an artifact; where no artifact is in reach it says to record that the
# value is unknown, which the undeclared-fields statement above already does.
ARTIFACT_SHA256=""
if [ -n "$ARTIFACT" ] && [ -f "$ARTIFACT" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        ARTIFACT_SHA256=$(sha256sum "$ARTIFACT" 2>/dev/null | cut -d" " -f1)
    elif command -v shasum >/dev/null 2>&1; then
        ARTIFACT_SHA256=$(shasum -a 256 "$ARTIFACT" 2>/dev/null | cut -d" " -f1)
    fi
    if [ -z "$ARTIFACT_SHA256" ]; then
        echo "[docmeta] WARN: could not hash $ARTIFACT; the target component will carry no hash." >&2
    fi
fi

# The CycloneDX version asked for (cdx-version.sh). The generators write it
# themselves, but some documents arrive at an older version (a producer that
# writes a fixed 1.6, an SBOM given to POSTPROCESS or kept as a merge root), so
# a 1.4, 1.5 or 1.6 document is raised to 1.7 here when 1.7 was asked for,
# $schema included. Those versions only gained fields up to 1.7 (the older
# metadata.tools array is still accepted), so the content is valid as it
# stands. 1.3 and older are left as they are: they predate the shapes this
# pipeline writes into metadata. Never lowered: an AI SBOM is 1.7 whatever was
# asked for.
TMP="$(mktemp)"
if jq --arg lifecycle "$LIFECYCLE" \
      --arg spec "$CDX_SPEC_VERSION" \
      --argjson authors "$AUTHORS_JSON" \
      --arg authorsource "$AUTHOR_SOURCE" \
      --arg toolver "$TOOL_VERSION" \
      --arg undeclared "$UNDECLARED_POLICY" \
      --arg artifactsha "$ARTIFACT_SHA256" '
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
      # The older flat array (CycloneDX 1.4 and before) takes a tool, which has
      # vendor where a component has publisher, and no type.
      elif (.metadata.tools | type) == "array" then .metadata.tools += [{vendor: $t.publisher, name: $t.name, version: $t.version}]
      elif (.metadata.tools | type) == "object" then .metadata.tools.components = (((.metadata.tools.components // []) + [$t]))
      else .metadata.tools = {components: [$t]} end;

      fill_tool_versions
    | (if $spec == "1.7" and ((.specVersion // "") | IN("1.4", "1.5", "1.6"))
       then .specVersion = "1.7"
            | (if has("$schema") then ."$schema" = "http://cyclonedx.org/schema/bom-1.7.schema.json" else . end)
       else . end)
    # The tool the minimum elements ask about is the one the SBOM author ran, and
    # that is this one: the scanners below produced the raw inventory, but the
    # document being delivered is the one this pipeline normalized, enriched and
    # named. Their entries stay — the question is which tools were involved, not
    # which single tool gets the credit.
    | add_bomlens({type: "application", publisher: "SK Telecom", name: "BomLens", version: $toolver})
    | (if $lifecycle != "" then .metadata.lifecycles = [{phase: $lifecycle}] else . end)
    | (if ($authors | length) > 0
       then .metadata.authors = $authors
       else (.metadata) |= del(.authors) end)
    # An existing hash is left alone: a scanner that already recorded one was
    # looking at the same artifact and may have used a different algorithm.
    | (if $artifactsha != "" and (((.metadata.component.hashes // []) | length) == 0)
       then .metadata.component.hashes = [{alg: "SHA-256", content: $artifactsha}]
       else . end)
    | (.metadata.properties) = (((.metadata.properties // [])
        | map(select((.name // "") != "bomlens:undeclared-fields"
                     and (.name // "") != "bomlens:sbom-author-source")))
        + [{name: "bomlens:undeclared-fields", value: $undeclared}]
        + (if $authorsource != "" then [{name: "bomlens:sbom-author-source", value: $authorsource}] else [] end))
    ' "$SBOM" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$SBOM"
else
    rm -f "$TMP"
    echo "[docmeta] ERROR: could not stamp document metadata (jq transform failed): $SBOM" >&2
    exit 1
fi

echo "[docmeta] tool=BomLens@${TOOL_VERSION}${LIFECYCLE:+, lifecycle=$LIFECYCLE}${SBOM_AUTHOR:+, author=$SBOM_AUTHOR}${ARTIFACT_SHA256:+, sha256=${ARTIFACT_SHA256%"${ARTIFACT_SHA256#????????}"}…}: $SBOM"
if [ "$AUTHOR_SOURCE" = "declaration" ]; then
    echo "[docmeta] SBOM author taken from the declaration's document.createdBy: $(printf '%s' "$AUTHORS_JSON" | jq -r 'map(.name) | join(", ")') (set SBOM_AUTHOR or pass --sbom-author to name someone else)"
elif [ -z "$SBOM_AUTHOR" ]; then
    echo "[docmeta] no SBOM author declared (set SBOM_AUTHOR or pass --sbom-author to name the entity that generated this SBOM)"
fi
