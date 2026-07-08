#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# identify-cocoapods.sh — extract CocoaPods dependencies from Podfile.lock via syft.
#
# Usage: identify-cocoapods.sh <source_dir> <output_sbom.json> <version>
#   produces <output_sbom.json> (CycloneDX 1.6) whose components are the pods pinned in
#   the project's Podfile.lock, as pkg:cocoapods/<name>@<version>.
#
# Why this exists: cdxgen's CocoaPods cataloger shells out to the `pod` CLI, which the
# slim swift language image does not bundle, so a CocoaPods iOS project comes back with
# zero components. syft parses Podfile.lock directly — no `pod`, no network — and emits
# the full transitive set CocoaPods already resolved into the lockfile. This step fills
# that gap in POSTPROCESS (where syft is present and the source tree is mounted); the
# caller reconciles against the main scan and merges, so CVE/notice generation picks the
# pods up.
#
# Completeness: Podfile.lock's PODS section is the resolved graph — every pod, direct and
# transitive, with a pinned version. syft returns that full set (verified). It does not
# emit dependency edges; edge reconstruction from the nested PODS lists is a follow-up.
#
# Best-effort: a missing tool, no Podfile.lock, or a syft failure degrades to an empty
# components array rather than aborting — the caller always gets a valid SBOM.
set -e

SRC="$1"
OUTPUT="$2"
VERSION="${3:-unknown}"
SELFDIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
    echo "[cocoapods] source directory not found: $SRC" >&2
    exit 1
fi
if [ -z "$OUTPUT" ]; then
    echo "[cocoapods] output path is required (usage: identify-cocoapods.sh <src> <out.json> <version>)" >&2
    exit 1
fi

GEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Always emit a valid (possibly empty) CycloneDX envelope so the caller never sees a
# missing/half file. $1 = status recorded on metadata.properties: "matched" (pods found),
# "no-match" (Podfile.lock parsed, nothing to add), "unavailable" (syft/parse failed).
write_empty() {
    local status="${1:-no-match}"
    jq -n --arg version "$VERSION" --arg ts "$GEN_AT" --arg status "$status" '
    {
      bomFormat: "CycloneDX", specVersion: "1.6", version: 1,
      metadata: {
        timestamp: $ts,
        tools: { components: [ { type: "application", name: "syft" } ] },
        component: { type: "application", name: "cocoapods", version: $version },
        properties: [ { name: "bomlens:cocoapods:status", value: $status } ]
      },
      components: []
    }' > "$OUTPUT"
}

if ! command -v jq >/dev/null 2>&1; then
    echo "[cocoapods] ERROR: jq not installed in this image." >&2
    exit 1
fi
if ! command -v syft >/dev/null 2>&1; then
    echo "[cocoapods] syft not installed in this image; skipping CocoaPods identification." >&2
    write_empty "unavailable"
    exit 0
fi

# Only the project-level Podfile.lock carries the resolved graph. The copy CocoaPods
# writes under Pods/ is named Manifest.lock, so a plain -name Podfile.lock already skips
# it; guard on the Pods/ path anyway in case a project vendors one.
LOCKS=$(find "$SRC" -type f -name Podfile.lock -not -path '*/Pods/*' 2>/dev/null || true)
if [ -z "$LOCKS" ]; then
    echo "[cocoapods] no Podfile.lock found under $SRC; nothing to identify." >&2
    write_empty "no-match"
    exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NDJSON="$WORK/comps.ndjson"
: > "$NDJSON"

# Run syft in the directory of each Podfile.lock and keep only pkg:cocoapods components
# (a lockfile-scoped scan still catalogs any sibling manifests; cdxgen already owns those,
# so we drop them here and reconcile the rest in the caller). syft parses Podfile.lock
# offline — no `pod`, no network.
while IFS= read -r lock; do
    [ -n "$lock" ] || continue
    dir=$(dirname "$lock")
    echo "[cocoapods] syft: parsing ${lock#"$SRC"/} (offline; no pod)..." >&2
    if ! syft "dir:$dir" -o cyclonedx-json@1.6 > "$WORK/syft.json" 2>/dev/null; then
        echo "[cocoapods] WARN: syft failed on $dir; skipping." >&2
        continue
    fi
    jq -c '.components[]? | select((.purl // "") | startswith("pkg:cocoapods/"))' \
        "$WORK/syft.json" >> "$NDJSON" 2>/dev/null || true
done <<EOF
$LOCKS
EOF

# Assemble components: dedupe by purl, keep name/version/licenses, tag provenance so the
# UI and downstream steps can tell these apart from the package-manager scan. bom-ref is
# set to the purl so the dependency edges below (and the merge in entrypoint.sh) link to
# these exact components.
COMPS_FILE="$WORK/comps.json"
jq -s '
    [ .[]
      | { "bom-ref": (.purl // ((.name // "") + "@" + (.version // ""))),
          type: (.type // "library"),
          name: .name,
          version: (.version // ""),
          purl: (.purl // null),
          licenses: (.licenses // []),
          properties: ( [
              { name: "bomlens:layer",        value: "cocoapods" },
              { name: "bomlens:identifiedBy", value: "syft" }
            ] ) }
      | select((.name // "") != "")
    ]
    | unique_by(.purl // ((.name // "") + "@" + (.version // "")))
    | sort_by(.purl // ((.name // "") + "@" + (.version // "")))
' "$NDJSON" > "$COMPS_FILE" 2>/dev/null || true
if [ ! -s "$COMPS_FILE" ] || ! jq -e 'type=="array"' "$COMPS_FILE" >/dev/null 2>&1; then
    echo '[]' > "$COMPS_FILE"
fi

NCOMP=$(jq 'length' "$COMPS_FILE" 2>/dev/null || echo 0)
if [ "${NCOMP:-0}" -gt 0 ]; then STATUS="matched"; else STATUS="no-match"; fi

# Dependency graph. syft emits components but no edges; rebuild them from Podfile.lock's
# nested PODS lists (each pod's indented children are its sub-dependencies), keyed by the
# component bom-refs (= purls) so merge-sbom.sh unions them into the final graph. Names
# are mapped to refs via the syft component set — never reconstructed — so a ref always
# matches an emitted component. Best-effort: any parse issue leaves dependencies empty.
NAME2REF="$WORK/name2ref.json"
jq 'map({ (.name): (."bom-ref") }) | add // {}' "$COMPS_FILE" > "$NAME2REF" 2>/dev/null || echo '{}' > "$NAME2REF"
DEPS_NDJSON="$WORK/deps.ndjson"
: > "$DEPS_NDJSON"
if command -v python3 >/dev/null 2>&1; then
    while IFS= read -r lock; do
        [ -n "$lock" ] || continue
        python3 "$SELFDIR/parse-podfile-lock.py" "$lock" "$NAME2REF" >> "$DEPS_NDJSON" 2>/dev/null || true
    done <<EOF
$LOCKS
EOF
fi

DEPS_FILE="$WORK/deps.json"
# Union edges across lockfiles by ref; drop empties. `jq -s` slurps the newline-delimited
# edge objects into one array (do NOT `add` — that would merge the objects, not the list).
jq -s '
    group_by(.ref)
    | map({ ref: .[0].ref, dependsOn: ([ .[].dependsOn[]? ] | unique) })
    | map(select((.ref != null) and ((.dependsOn | length) > 0)))
' "$DEPS_NDJSON" > "$DEPS_FILE" 2>/dev/null || echo '[]' > "$DEPS_FILE"
if [ ! -s "$DEPS_FILE" ] || ! jq -e 'type=="array"' "$DEPS_FILE" >/dev/null 2>&1; then
    echo '[]' > "$DEPS_FILE"
fi
NEDGES=$(jq '[.[].dependsOn[]?] | length' "$DEPS_FILE" 2>/dev/null || echo 0)

jq -n \
    --slurpfile comps "$COMPS_FILE" \
    --slurpfile deps "$DEPS_FILE" \
    --arg version "$VERSION" \
    --arg ts "$GEN_AT" \
    --arg status "$STATUS" '
{
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  version: 1,
  metadata: {
    timestamp: $ts,
    tools: { components: [ { type: "application", name: "syft" } ] },
    component: { type: "application", name: "cocoapods", version: $version },
    properties: [ { name: "bomlens:cocoapods:status", value: $status } ]
  },
  components: $comps[0],
  dependencies: $deps[0]
}' > "$OUTPUT"

echo "[cocoapods] SBOM written: $OUTPUT (cocoapods components=${NCOMP}, dependency edges=${NEDGES})"
