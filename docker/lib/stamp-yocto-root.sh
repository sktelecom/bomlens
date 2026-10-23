#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# stamp-yocto-root.sh: make the image the root of an SBOM read from a Yocto
# build directory.
#
# Usage: stamp-yocto-root.sh <sbom.json>
#
# The Yocto readers (parse-yocto-spdx.py, parse-yocto-manifests.py) write the
# image as metadata.component with no bom-ref and no edge to what it installs,
# and bitbake writes the image package with no version. Read from a build
# directory the user pointed at (entrypoint.sh: YOCTO_SBOM and
# YOCTO_FROM_BUILD), the SBOM is the one this scan generates, so its root is
# completed the way a generated scan's is:
#
#   - a bom-ref, when it has none (yocto-image:<name>@<version>, made unique
#     against the references already in the SBOM);
#   - the version --version gives (PROJECT_VERSION), when it has none; the
#     image name the build wrote is kept;
#   - the licence --license gives (PROJECT_LICENSE), marked "concluded", as
#     stamp-metadata.sh records it for a source scan (an expression or a
#     LicenseRef- in the CycloneDX field that takes it);
#   - a dependencies entry in which the image depends on every installed
#     package (every top-level component), kept with what the entry already
#     lists;
#   - a timestamp, when the reader found none (the manifests carry none); the
#     creation time of the build's SPDX document is kept.
#
# Not called for a document passed with --analyze on its own: that is someone
# else's SBOM, converted, and its root stays as they wrote it.
set -e

SBOM="$1"

if [ -z "$SBOM" ] || [ ! -f "$SBOM" ]; then
    echo "[yocto-root] SBOM file not found: $SBOM" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "[yocto-root] ERROR: jq not available; cannot complete the image root. This is a build defect: rebuild the image with jq." >&2
    exit 1
fi

TMP="$(mktemp)"
if jq --arg name "${PROJECT_NAME:-}" --arg v "${PROJECT_VERSION:-}" --arg lic "${PROJECT_LICENSE:-}" \
      --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
    .metadata = (.metadata // {})
    | .metadata.component = (.metadata.component // {})
    | (if ((.metadata.component.type // "") == "") then .metadata.component.type = "operating-system" else . end)
    | (if ((.metadata.component.name // "") == "") then .metadata.component.name = $name else . end)
    | (if (((.metadata.component.version // "") | tostring) == "") and $v != "" then .metadata.component.version = $v else . end)
    # CycloneDX takes only an SPDX list id in license.id: an expression goes
    # in expression, and a LicenseRef- (a closed product licence) in name.
    | (if $lic == "" then .
       elif ($lic | test(" (AND|OR|WITH) ")) then .metadata.component.licenses = [{expression: $lic, acknowledgement: "concluded"}]
       elif ($lic | startswith("LicenseRef-")) then .metadata.component.licenses = [{license: {name: $lic, acknowledgement: "concluded"}}]
       else .metadata.component.licenses = [{license: {id: $lic, acknowledgement: "concluded"}}] end)
    | ([.components[]? | .["bom-ref"]? | strings] + [(.dependencies // [])[]? | .ref? | strings]) as $used
    | (if ((.metadata.component["bom-ref"] // "") == "")
       then ("yocto-image:" + .metadata.component.name + "@" + ((.metadata.component.version // "") | tostring)) as $base
            | .metadata.component["bom-ref"] = (if ($used | index($base)) == null then $base else $base + "#image" end)
       else . end)
    | .metadata.component["bom-ref"] as $root
    | ([.components[]? | .["bom-ref"]? | strings | select(. != $root)]) as $installed
    | .dependencies = ((.dependencies // [])
        | if any(.[]; .ref == $root) then . else . + [{ref: $root, dependsOn: []}] end
        | map(if .ref == $root
              then .dependsOn = (reduce $installed[] as $p ((.dependsOn // []); if index([$p]) == null then . + [$p] else . end))
              else . end))
    | (if ((.metadata.timestamp // "") == "") then .metadata.timestamp = $now else . end)' \
    "$SBOM" > "$TMP" 2>/dev/null; then
    mv "$TMP" "$SBOM"
else
    rm -f "$TMP"
    echo "[yocto-root] ERROR: could not complete the image root (jq transform failed): $SBOM" >&2
    exit 1
fi
echo "[yocto-root] image root $(jq -r '.metadata.component["bom-ref"]' "$SBOM") depends on $(jq -r --arg r "$(jq -r '.metadata.component["bom-ref"]' "$SBOM")" '[.dependencies[] | select(.ref == $r) | .dependsOn[]] | length' "$SBOM") installed component(s)${PROJECT_LICENSE:+, licence $PROJECT_LICENSE (concluded)}"
