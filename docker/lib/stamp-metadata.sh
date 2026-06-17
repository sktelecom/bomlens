#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# stamp-metadata.sh — set a CycloneDX SBOM's root component to the caller's
# project identity.
#
# Usage: stamp-metadata.sh <sbom.json> <project_name> <project_version>
#
# cdxgen fills metadata.component from the source manifest (pkg:pypi/app@latest)
# or, when it cannot resolve a name, from the scanned directory — which on the
# web UI path is the temp upload dir (/host-output/.uploads/<token>/extracted/
# <lang>), leaking an internal path and breaking reproducibility. Overwrite the
# root component name/version with the caller's --project/--version and drop the
# now-stale purl (optional in CycloneDX) since it encoded the old coordinates.
#
# Called for cdxgen-backed modes (SOURCE/POSTPROCESS) and for ROOTFS, where syft
# names the root component after the scan path (/target) — meaningless and leaking
# the mount path, the same problem described above. IMAGE/BINARY/FIRMWARE/ANALYZE
# carry their own meaningful root component and should not call this.
set -e

SBOM="$1"
NAME="$2"
VERSION="$3"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[stamp] SBOM file not found: $SBOM" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "[stamp] WARN: jq not available; leaving metadata.component as-is" >&2
    exit 0
fi

if ! jq empty "$SBOM" 2>/dev/null; then
    echo "[stamp] WARN: $SBOM is not valid JSON; skipping" >&2
    exit 0
fi

TMP="$(mktemp)"
if jq --arg n "$NAME" --arg v "$VERSION" \
    '.metadata.component.name = $n
     | .metadata.component.version = $v
     | (.metadata.component) |= del(.purl)' \
    "$SBOM" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$SBOM"
    echo "[stamp] metadata.component set to ${NAME}@${VERSION}: $SBOM"
else
    rm -f "$TMP"
    echo "[stamp] WARN: could not stamp metadata.component (leaving cdxgen values)." >&2
fi
