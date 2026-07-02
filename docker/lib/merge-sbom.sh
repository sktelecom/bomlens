#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# merge-sbom.sh — merge several CycloneDX SBOMs into one.
#
# Usage: merge-sbom.sh <output.json> <project_name> <project_version> <in1> <in2> [...]
#   produces <output.json> (CycloneDX 1.6) whose root component is the project,
#   with every input's components flattened and deduped by purl.
#
# Built for layered server SBOMs: an OS rootfs layer, an application layer, and a
# static-link layer are each scanned separately, then merged here so the
# downstream pipeline (notice/security/risk-report) sees one component set.
#
# Each component keeps a `bomlens:layer` property naming the source layer (the
# input's root component name, or layer-<index>), so provenance survives the
# merge. Dedup keeps the first occurrence, so the first layer listed wins.
#
# The per-layer `dependencies` graphs are merged too (edges unioned by ref), so
# the merged BOM keeps transitive-dependency information — required by the SKT
# conformance check. bom-refs rarely collide across ecosystems; identical refs
# have their dependsOn lists unioned.
#
# Root preservation (AI path): by default the output is a fresh CycloneDX 1.6
# document with a new root component. When MERGE_ROOT_FROM points at one of the
# input files, the output instead keeps THAT input's specVersion and
# metadata.component (root) — so an ML-BOM (1.7, carrying a machine-learning-model
# root with a modelCard) can absorb an application's software components without
# being downgraded to 1.6 or losing its modelCard. Only the component/dependency
# sets are merged; the preserved root's own components are included via the normal
# input flattening below (pass the ML-BOM as an input too).
set -e

OUTPUT="$1"
NAME="$2"
VERSION="$3"
shift 3 2>/dev/null || true

if [ -z "$OUTPUT" ] || [ -z "$NAME" ] || [ -z "$VERSION" ]; then
    echo "[merge] usage: merge-sbom.sh <output.json> <name> <version> <in1> <in2> [...]" >&2
    exit 1
fi
if [ "$#" -lt 2 ]; then
    echo "[merge] need at least 2 input SBOMs to merge (got $#)." >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "[merge] ERROR: jq not installed in this image." >&2
    exit 1
fi

GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Optional base SBOM whose specVersion + root metadata.component are preserved
# (AI path: keep the ML-BOM's 1.7 spec and modelCard). Ignored if unset, missing,
# or not valid JSON — the merge then falls back to a fresh 1.6 root. The preserved
# root's name/version are OVERRIDDEN with the caller's NAME/VERSION: generators
# name their root after ephemeral job ids (the OWASP AIBOM Generator emits
# "job-<timestamp>"), and the caller-supplied identity is the contract every merge
# mode guarantees. The root object goes through a FILE + --slurpfile, not --argjson
# argv (same ARG_MAX rule as the components below — a root modelCard can exceed
# Linux's 128 KiB per-argument limit and abort the merge under set -e).
MERGE_ROOT_FROM="${MERGE_ROOT_FROM:-}"
PRESERVE_SPEC=""
ROOT_META_FILE="$WORK/root-meta.json"
echo "null" > "$ROOT_META_FILE"
if [ -n "$MERGE_ROOT_FROM" ] && [ -s "$MERGE_ROOT_FROM" ] && jq empty "$MERGE_ROOT_FROM" >/dev/null 2>&1; then
    PRESERVE_SPEC=$(jq -r '.specVersion // empty' "$MERGE_ROOT_FROM" 2>/dev/null)
    jq -c --arg name "$NAME" --arg version "$VERSION" \
        '.metadata.component // null | if . == null then null else . + {name: $name, version: $version} end' \
        "$MERGE_ROOT_FROM" > "$ROOT_META_FILE" 2>/dev/null || echo "null" > "$ROOT_META_FILE"
    if [ -n "$PRESERVE_SPEC" ] && [ "$(cat "$ROOT_META_FILE")" != "null" ]; then
        echo "[merge] preserving root from $MERGE_ROOT_FROM (specVersion=$PRESERVE_SPEC, modelCard kept, named $NAME@$VERSION)"
    else
        PRESERVE_SPEC=""
        echo "null" > "$ROOT_META_FILE"
        echo "[merge] WARN: MERGE_ROOT_FROM has no specVersion/metadata.component; using fresh 1.6 root." >&2
    fi
fi

# Collect each input's components into a temp file, tagging each with its source
# layer. Drop components without a real name (syft's empty "os:unknown" noise). A
# malformed input is skipped with a warning rather than aborting the whole merge.
# Components are passed between jq steps via FILES, not argv — a real server SBOM
# has hundreds/thousands of components and `--argjson <big-json>` overflows
# ARG_MAX ("Argument list too long").
i=0
valid=0
for f in "$@"; do
    if [ ! -s "$f" ] || ! jq empty "$f" >/dev/null 2>&1; then
        echo "[merge] WARN: skipping missing or invalid SBOM: $f" >&2
        i=$((i + 1))
        continue
    fi
    LAYER=$(jq -r '.metadata.component.name // empty' "$f" 2>/dev/null)
    [ -n "$LAYER" ] || LAYER="layer-$i"
    jq -c --arg L "$LAYER" '
        [ .components[]?
          | select((.name // "") != "")
          | .properties = ((.properties // []) + [{name: "bomlens:layer", value: $L}]) ]' \
        "$f" > "$WORK/comps-$i.json"
    # Keep each layer's dependency graph so the merged BOM retains transitive
    # edges (a mandatory SKT conformance check; dropping them fails it).
    jq -c '[ .dependencies[]? ]' "$f" > "$WORK/deps-$i.json"
    valid=$((valid + 1))
    i=$((i + 1))
done

if [ "$valid" -eq 0 ]; then
    echo "[merge] ERROR: no valid CycloneDX inputs to merge." >&2
    exit 1
fi

# Merge all per-layer component files, dedupe by purl (fallback name@version).
# `jq -s` slurps each file as one array element; `add` concatenates them.
jq -s '
    add
    | group_by(.purl // ((.name // "") + "@" + (.version // "")))
    | map(.[0])
    | sort_by(.purl // ((.name // "") + "@" + (.version // "")))
' "$WORK"/comps-*.json > "$WORK/merged.json"

NTOTAL=$(jq 'length' "$WORK/merged.json")

# Merge the per-layer dependency graphs. Edges are preserved so the merged BOM
# keeps transitive-dependency information. bom-refs rarely collide across
# ecosystems (pkg:rpm vs pkg:npm …); when the same ref appears in more than one
# layer, its dependsOn lists are unioned. Entries with no edges are dropped.
jq -s '
    add
    | group_by(.ref)
    | map({ ref: .[0].ref, dependsOn: ([ .[].dependsOn[]? ] | unique) })
    | map(select((.ref != null) and ((.dependsOn | length) > 0)))
' "$WORK"/deps-*.json > "$WORK/deps.json"

NEDGES=$(jq '[.[].dependsOn[]?] | length' "$WORK/deps.json")

# --slurpfile reads the merged components/dependencies AND the preserved root from
# files (ARG_MAX safe — see the comment at the collection loop). When a base root
# is preserved, keep its specVersion and metadata.component (incl. any modelCard,
# renamed to the caller's NAME/VERSION above); otherwise emit a fresh CycloneDX
# 1.6 root. The preserved root's own component is not re-added as a plain
# component — it stays the metadata.component — so the merged component set is
# deduped as usual.
jq -n \
    --slurpfile comps "$WORK/merged.json" \
    --slurpfile deps "$WORK/deps.json" \
    --slurpfile meta "$ROOT_META_FILE" \
    --arg name "$NAME" \
    --arg version "$VERSION" \
    --arg ts "$GEN_AT" \
    --arg spec "${PRESERVE_SPEC:-1.6}" '
{
  bomFormat: "CycloneDX",
  specVersion: $spec,
  version: 1,
  metadata: {
    timestamp: $ts,
    tools: { components: [ { type: "application", name: "bomlens-merge" } ] },
    component: ($meta[0] // { type: "application", name: $name, version: $version })
  },
  components: $comps[0],
  dependencies: $deps[0]
}' > "$OUTPUT"

echo "[merge] SBOM written: $OUTPUT (components=${NTOTAL}, dependency edges=${NEDGES}, from ${valid} layer(s))"
