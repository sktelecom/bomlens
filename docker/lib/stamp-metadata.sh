#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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
#
# Also records the project's OUTBOUND license from $PROJECT_LICENSE, when set. A
# source scan cannot infer it: cdxgen leaves metadata.component.licenses empty for
# maven and gradle trees (only npm fills it, from package.json), so without a
# declaration the license-conflict check has nothing to compare dependencies
# against. Given with --license, it is the licence the product is distributed
# under: it replaces the root licence the generator read and is written with
# "acknowledgement": "concluded", as BSI TR-03183-2 gives the distribution
# licence. Read from the project manifest by entrypoint.sh
# (PROJECT_LICENSE_FROM_MANIFEST=1), it only fills an empty value, as "declared".
# An SPDX list id goes in license.id, a LicenseRef- in license.name and a
# compound expression in expression, the fields CycloneDX takes them in.
# The modes that carry a supplier's own root component (ANALYZE/MERGE) do not
# call this file at all, so a received SBOM's declaration can never be overwritten.
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
# collide on the codelocation name in some SBOM import platforms) from being delivered.
if ! command -v jq >/dev/null 2>&1; then
    echo "[stamp] ERROR: jq not available; cannot stamp metadata.component. This is a build defect — rebuild the image with jq." >&2
    exit 1
fi

if ! jq empty "$SBOM" 2>/dev/null; then
    echo "[stamp] ERROR: $SBOM is not valid JSON; cannot stamp metadata.component." >&2
    exit 1
fi

TMP="$(mktemp)"
if jq --arg n "$NAME" --arg v "$VERSION" --arg lic "${PROJECT_LICENSE:-}" --arg manifest "${PROJECT_LICENSE_FROM_MANIFEST:-}" \
    '.metadata.component.name = $n
     | .metadata.component.version = $v
     | (.metadata.component) |= del(.purl)
     # CycloneDX requires a component type. cdxgen writes no metadata.component
     # at all for a tree with no dependencies, so the root built above would
     # otherwise carry only a name and version and fail schema validation.
     | (if ((.metadata.component.type // "") == "") then .metadata.component.type = "application" else . end)
     # Given with --license, it is the licence the user states the product
     # is distributed under: it replaces what the generator read and is
     # marked concluded. Read from the manifest instead (entrypoint.sh sets
     # PROJECT_LICENSE_FROM_MANIFEST=1), it only fills an empty value and is
     # what the project declares.
     # CycloneDX takes only an SPDX list id in license.id: a compound
     # expression goes in expression, and a LicenseRef- (a licence the
     # SPDX list does not hold, such as a closed product licence) in name.
     | def lic_entry($ack):
         if ($lic | test(" (AND|OR|WITH) ")) then {expression: $lic, acknowledgement: $ack}
         elif ($lic | startswith("LicenseRef-")) then {license: {name: $lic, acknowledgement: $ack}}
         else {license: {id: $lic, acknowledgement: $ack}} end;
       (if $lic == "" then .
        elif $manifest != "1" then .metadata.component.licenses = [lic_entry("concluded")]
        elif (((.metadata.component.licenses // []) | length) == 0)
        then .metadata.component.licenses = [lic_entry("declared")]
        else . end)' \
    "$SBOM" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$SBOM"
    echo "[stamp] metadata.component set to ${NAME}@${VERSION}: $SBOM"
    if [ -n "${PROJECT_LICENSE:-}" ]; then
        if jq -e '((.metadata.component.licenses // [])[0] | (.license.id // .license.name // .expression // "")) == $ENV.PROJECT_LICENSE' "$SBOM" >/dev/null 2>&1; then
            echo "[stamp] outbound license declared: ${PROJECT_LICENSE} (drives the license-conflict check)"
        else
            echo "[stamp] outbound license read from the manifest (${PROJECT_LICENSE}) not applied: the SBOM already names one; pass --license to replace it"
        fi
    fi
else
    rm -f "$TMP"
    echo "[stamp] ERROR: could not stamp metadata.component (jq transform failed): $SBOM" >&2
    exit 1
fi

# Final net (engine-agnostic): confirm the root component now carries the caller's
# project name and is not a generic placeholder. cdxgen/syft default the root name
# to the scan path (src/app/target) when they cannot resolve one; such a name
# becomes a non-unique codelocation in some SBOM import platforms and blocks unrelated imports. We
# reach here only after a successful stamp, so a mismatch means the write silently
# did not take — and src/app means the caller itself passed a colliding name.
# The collision happens on upload only: with UPLOAD_ENABLED=false (an execution
# plan's caller keeps the SBOM for itself, and may well call a project "app")
# the name is used as given, with a warning.
ACTUAL="$(jq -r '.metadata.component.name // ""' "$SBOM" 2>/dev/null)"
if [ "$ACTUAL" != "$NAME" ]; then
    echo "[stamp] ERROR: metadata.component.name is '${ACTUAL}', expected '${NAME}' — stamp did not take." >&2
    exit 1
fi
case "$ACTUAL" in
    src|app)
        if [ "${UPLOAD_ENABLED:-true}" = "false" ]; then
            echo "[stamp] WARN: the project name '${ACTUAL}' is also the name scanners give a project they cannot name; an SBOM import platform may confuse it with others. Kept, since nothing is uploaded." >&2
        else
            echo "[stamp] ERROR: metadata.component.name is the generic placeholder '${ACTUAL}', which collides across submissions. Pass a distinct --project name." >&2
            exit 1
        fi
        ;;
esac
