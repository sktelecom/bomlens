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

# jq is mandatory in the post-process image. A missing jq is a build defect, not a
# runtime condition to tolerate — failing closed keeps a mis-named SBOM (which would
# collide in Black Duck on the codelocation name) from being delivered.
if ! command -v jq >/dev/null 2>&1; then
    echo "[stamp] ERROR: jq not available; cannot stamp metadata.component. This is a build defect — rebuild the image with jq." >&2
    exit 1
fi

if ! jq empty "$SBOM" 2>/dev/null; then
    echo "[stamp] ERROR: $SBOM is not valid JSON; cannot stamp metadata.component." >&2
    exit 1
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
    echo "[stamp] ERROR: could not stamp metadata.component (jq transform failed): $SBOM" >&2
    exit 1
fi

# Final net (engine-agnostic): confirm the root component now carries the caller's
# project name and is not a generic placeholder. cdxgen/syft default the root name
# to the scan path (src/app/target) when they cannot resolve one; such a name
# becomes a non-unique Black Duck codelocation and blocks unrelated imports. We
# reach here only after a successful stamp, so a mismatch means the write silently
# did not take — and src/app means the caller itself passed a colliding name.
ACTUAL="$(jq -r '.metadata.component.name // ""' "$SBOM" 2>/dev/null)"
if [ "$ACTUAL" != "$NAME" ]; then
    echo "[stamp] ERROR: metadata.component.name is '${ACTUAL}', expected '${NAME}' — stamp did not take." >&2
    exit 1
fi
case "$ACTUAL" in
    src|app)
        echo "[stamp] ERROR: metadata.component.name is the generic placeholder '${ACTUAL}', which collides across submissions. Pass a distinct --project name." >&2
        exit 1
        ;;
esac
