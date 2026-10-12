#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# update-cdxgen-digests.sh - refresh docker/lib/cdxgen-images.json for the
# cdxgen image tag in docker/lib/source-detect.sh (CDXGEN_TAG). Reads each
# image's multi-platform index digest from ghcr.io; nothing is pulled. Run it
# after bumping CDXGEN_TAG, and commit the result with the bump.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAP="$ROOT/docker/lib/cdxgen-images.json"
TAG="$(sed -n 's/^CDXGEN_TAG="${CDXGEN_TAG:-\([^}]*\)}".*/\1/p' "$ROOT/docker/lib/source-detect.sh")"
[ -n "$TAG" ] || { echo "could not read CDXGEN_TAG from source-detect.sh" >&2; exit 1; }
ACCEPT='application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
jq --arg tag "$TAG" '.tag = $tag' "$MAP" > "$tmp"
for img in $(jq -r '.digests | keys[]' "$MAP"); do
    repo="${img#ghcr.io/}"
    tok="$(curl -sf "https://ghcr.io/token?scope=repository:${repo}:pull" | jq -r .token)"
    digest="$(curl -sfI -H "Authorization: Bearer $tok" -H "Accept: $ACCEPT" \
        "https://ghcr.io/v2/${repo}/manifests/${TAG}" | tr -d '\r' \
        | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')"
    case "$digest" in sha256:*) ;; *) echo "no digest for $img:$TAG" >&2; exit 1 ;; esac
    jq --arg i "$img" --arg d "$digest" '.digests[$i] = $d' "$tmp" > "$tmp.n" && mv "$tmp.n" "$tmp"
    echo "$img:$TAG -> $digest"
done
mv "$tmp" "$MAP"
trap - EXIT
