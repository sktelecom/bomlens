#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# image-digest.sh <syft source json> <image reference> <socket: true|false>
#
# The digest of the image syft read in IMAGE mode, so the later reads of the
# same reference (Trivy's license scan, the file view) take exactly that image
# even when the tag moves meanwhile. <syft source json> is syft's `source`
# object (its syft-json model, written by entrypoint.sh through a template
# output); <socket> says whether the Docker socket was mounted.
#
# Where syft read the image: the scheme says it when there is one. A plain
# name with no socket is a registry read. With the socket syft tries the
# daemon first and falls back to the registry, and its record does not name
# the provider, so it is told from the record: a Docker Hub repository digest
# written in full (index.docker.io/..., docker.io/...) is only written by the
# registry read, and tags are only listed by the daemon read. When neither
# shows, the source is unknown and the repository digest is used, which names
# the same content in the daemon and in the registry.
#
# Prints one JSON object on stdout:
#   reference         the reference as given
#   source            registry, daemon, unknown, archive or other
#   digest            registry: the manifest digest of the image read (one
#                     platform); daemon or unknown: the repository digest for
#                     this repository (for a multi-platform image, the index);
#                     null for an archive, or when it cannot be resolved or the
#                     name cannot be pinned
#   index_digest      registry only, when the reference resolved through an
#                     image index (manifest list) whose digest differs
#   platform          os/architecture[/variant], or null
#   pinned_reference  the reference to read the same image by
#                     (<scheme><repository>@<digest>), or null to keep the
#                     reference as given
# Every digest matches ^sha256:[0-9a-f]{64}$ and the repository a plain image
# name before it is put in pinned_reference. Never fails: anything it cannot
# read gives a null digest.
set -uo pipefail

SRC_JSON="${1:-}"; REF="${2:-}"; SOCKET="${3:-false}"

scheme=""; name="$REF"; source=""
case "$REF" in
    docker-archive:*|oci-archive:*|oci-dir:*|dir:*|file:*|singularity:*) source=archive ;;
    registry:*) scheme="registry:"; name="${REF#registry:}"; source=registry ;;
    docker:*) scheme="docker:"; name="${REF#docker:}"; source=daemon ;;
    podman:*) scheme="podman:"; name="${REF#podman:}"; source=daemon ;;
    # syft's containerd: scheme has no Trivy counterpart: not pinned.
    containerd:*) source=other ;;
esac
# A plain name: registry with no socket; with it, decided from syft's record.
if [ -z "$source" ]; then
    if [ "$SOCKET" = true ]; then source=plain-socket; else source=registry; fi
fi

# The repository: the name less any @digest, then less a :tag on its last
# path segment (a registry port stays).
repo="${name%%@*}"
last="${repo##*/}"
case "$last" in *:*) repo="${repo%:*}" ;; esac
repo_ok=false
[[ "$repo" =~ ^[A-Za-z0-9][A-Za-z0-9._/:-]*$ ]] && [[ "$repo" != *//* ]] && repo_ok=true

meta='{}'
if [ -n "$SRC_JSON" ] && [ -f "$SRC_JSON" ]; then
    meta="$(jq -c '(.metadata // {}) | if type == "object" then . else {} end' "$SRC_JSON" 2>/dev/null)" || meta='{}'
    [ -n "$meta" ] || meta='{}'
fi

jq -nc --arg ref "$REF" --arg source "$source" --arg scheme "$scheme" --arg repo "$repo" \
    --argjson repo_ok "$repo_ok" --argjson m "$meta" '
    def dig: if type == "string" and test("^sha256:[0-9a-f]{64}$") then . else null end;
    def norm: sub("^(index\\.)?docker\\.io/"; "") | sub("^library/"; "");
    def part: if type == "string" and test("^[a-z0-9][a-z0-9._-]*$") then . else null end;
    # repoDigests entries are <repository>@<digest>.
    ([$m.repoDigests[]? | strings | select(contains("@"))
      | {repo: (split("@")[0]), digest: (split("@")[1] | dig)} | select(.digest != null)]) as $rd
    | (if $source != "plain-socket" then $source
       elif any($rd[]; .repo | test("^(index\\.)?docker\\.io/")) then "registry"
       elif (($m.tags // []) | type) == "array" and (($m.tags // []) | length) > 0 then "daemon"
       else "unknown" end) as $source
    | (if ($source == "registry" or $source == "daemon" or $source == "unknown") and ($repo_ok | not) then null
       elif $source == "registry" then ($m.manifestDigest | dig)
       elif $source == "daemon" or $source == "unknown" then
         ([$rd[] | select((.repo | norm) == ($repo | norm)) | .digest] | first)
       else null end) as $digest
    | (if $source == "registry" and $digest != null then
         ([$rd[].digest | select(. != $digest)] | first)
       else null end) as $index
    # The variant is architectureVariant in the syft record, else in the image config.
    | ($m.architectureVariant // (try ($m.config | @base64d | fromjson | .variant) catch null)) as $variant
    | ([($m.os | part), ($m.architecture | part)] | if all(. != null) then
         (. + [($variant | part)] | map(select(. != null)) | join("/")) else null end) as $platform
    | {reference: $ref, source: $source, digest: $digest}
      + (if $index != null then {index_digest: $index} else {} end)
      + {platform: $platform,
         pinned_reference: (if $digest != null and ($source == "registry" or $source == "daemon" or $source == "unknown")
                            then "\($scheme)\($repo)@\($digest)" else null end)}'
