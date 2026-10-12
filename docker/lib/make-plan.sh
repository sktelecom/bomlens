#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# make-plan.sh - the execution plan for a source scan (MODE=PLAN).
#
# Usage: make-plan.sh <source-dir> <output-dir> <output-file>
#
# A program that runs BomLens as its scan engine runs a source scan in two
# containers, the same two the CLI runs: stage 1 resolves the dependencies in
# a cdxgen language image, stage 2 is this image in POSTPROCESS mode. This
# script decides everything about them that BomLens decides (which image, at
# which digest, with which arguments, mounts and environment) and writes it to
# <output-dir>/bomlens-plan.json; the caller only runs what it says. The files
# stage 1 needs from this image (build-prep.sh, identify-conda.py) are copied
# to <output-dir>/bomlens-plan/ so the caller can mount them. The format is
# schemas/engine-plan-1.json, documented in docs/reference/engine-contract.md.
#
# The source is only read. Stage 1 must mount it writable: the dependency
# resolvers write lock files there, and build-prep.sh puts the tree back as it
# was when it finishes.

set -euo pipefail

SRC="${1:?source dir}"
OUTDIR="${2:?output dir}"
OUTFILE="${3:?output file name}"
LIBDIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=docker/lib/source-detect.sh
. "$LIBDIR/source-detect.sh"
# shellcheck source=docker/lib/cdx-version.sh
. "$LIBDIR/cdx-version.sh"

# The plan follows the same engine contract as the result manifest: one
# version, kept in engine-result.sh (ENGINE_CONTRACT_VERSION).
PLAN_CONTRACT_VERSION="$(sed -n 's/^ENGINE_CONTRACT_VERSION="\(.*\)"$/\1/p' "$LIBDIR/engine-result.sh")"
[ -n "$PLAN_CONTRACT_VERSION" ] || { echo "[plan] engine contract version not found in engine-result.sh" >&2; exit 1; }
# An earlier plan, and an earlier run's stage 1 outputs, are not this scan's:
# stage 2 cannot tell a fresh SBOM from a leftover one at the same name, so
# they go before stage 1 runs (the CLI does the same).
rm -f "$OUTDIR/bomlens-plan.json" "$OUTDIR/$OUTFILE" "$OUTDIR/${OUTFILE%_bom.json}_conda.cdx.json"
[ -d "$SRC" ] || { echo "[plan] source dir not found: $SRC" >&2; exit 1; }
# An empty source is usually a mount that did not reach the container (a
# path the Docker VM cannot see is replaced by an empty directory).
if [ -z "$(ls -A "$SRC" 2>/dev/null)" ]; then
    echo "[plan] source dir is empty: $SRC" >&2
    exit 1
fi
mkdir -p "$OUTDIR/bomlens-plan"
cp "$LIBDIR/build-prep.sh" "$OUTDIR/bomlens-plan/build-prep.sh"
cp "$LIBDIR/identify-conda.py" "$OUTDIR/bomlens-plan/identify-conda.py"

# Byte-stable output asks for no network license lookup in stage 1, as the CLI
# sets it. GOTOOLCHAIN reaches build-prep.sh as HOST_GOTOOLCHAIN (inside the
# cdxgen image GOTOOLCHAIN is always set), and only a toolchain name is kept.
fetch="${FETCH_LICENSE:-true}"
[ "${BYTE_STABLE:-false}" = "true" ] && fetch="false"
gotoolchain="${GOTOOLCHAIN:-}"
case "$gotoolchain" in *[!A-Za-z0-9.+_-]*) gotoolchain="" ;; esac

lang="$(detect_lang "$SRC")"
status="ok"; reason=""; detail=""
image=""; digest=""
case "$lang" in
    android)
        # The Android SDK image is built by the user, not published (see the
        # Android section of docs/reference/ecosystems.md), so there is no
        # image to name here.
        status="unsupported"; reason="android-sdk-image"
        detail="Android needs a locally built SDK image (${ANDROID_IMAGE_PREFIX}$(android_api "$SRC")); it is not published"
        ;;
    *)
        image="$(img_for_lang "$lang")"
        # Digests are recorded by the published name; a mirror serves the
        # same image under its own prefix.
        _canon="${image%:*}"; _canon="ghcr.io/cdxgen/${_canon#"$CDXGEN_IMAGE_PREFIX"}"
        digest="$(jq -r --arg i "$_canon" --arg t "${image##*:}" \
            'if .tag == $t then (.digests[$i] // "") else "" end' "$LIBDIR/cdxgen-images.json" 2>/dev/null || true)"
        if [ -z "$digest" ]; then
            status="unsupported"; reason="no-pinned-digest"
            detail="no digest recorded for $image in cdxgen-images.json"
        fi
        ;;
esac

jq -n \
    --arg cv "$PLAN_CONTRACT_VERSION" --arg ev "${BOMLENS_VERSION:-}" \
    --arg img2 "${BOMLENS_IMAGE_REF:-}" --arg dig2 "${BOMLENS_IMAGE_DIGEST:-}" \
    --arg status "$status" --arg reason "$reason" --arg detail "$detail" \
    --arg lang "$lang" \
    --arg img1 "$image" --arg dig1 "$digest" \
    --arg outfile "$OUTFILE" --arg spec "$CDX_SPEC_VERSION" \
    --arg fetch "$fetch" --arg gotc "$gotoolchain" \
    --arg pname "${PROJECT_NAME:-}" --arg pver "${PROJECT_VERSION:-}" \
    --arg prepenv "$BUILD_PREP_ENV_NAMES $PROXY_ENV_NAMES" --arg netenv "$STAGE2_NETWORK_ENV_NAMES" '
    def nn: if . == "" then null else . end;
    {
      contract: {name: "bomlens-engine-plan", version: $cv},
      engine: {version: ($ev | nn), image: ($img2 | nn), image_digest: ($dig2 | nn)},
      input: {kind: "source", detected_ecosystem: $lang},
      status: $status,
      reason: ($reason | nn),
      detail: ($detail | nn),
      output_file: $outfile,
      stages: (if $status != "ok" then [] else [
        {
          id: "generate",
          stage: 1,
          image: $img1,
          image_digest: $dig1,
          user: "0:0",
          entrypoint: ["sh"],
          args: ["/tmp/build-prep.sh", "/app", ("/out/" + $outfile), $spec],
          workdir: null,
          mounts: [
            {role: "source", target: "/app", mode: "rw"},
            {role: "output", target: "/out", mode: "rw"},
            {role: "plan-file", source: "bomlens-plan/build-prep.sh", target: "/tmp/build-prep.sh", mode: "ro"},
            {role: "plan-file", source: "bomlens-plan/identify-conda.py", target: "/tmp/identify-conda.py", mode: "ro"},
            {role: "guard-state", target: "/bomlens-state", mode: "rw", optional: true},
            {role: "cache-maven", target: "/root/.m2", mode: "rw", optional: true},
            {role: "cache-gradle", target: "/root/.gradle", mode: "rw", optional: true}
          ],
          on_kill: "If stage 1 is killed before it finishes, it cannot put the source back. With the guard-state mount and BOMLENS_GUARD_ID, run the same image and arguments again with BOMLENS_GUARD_RESTORE_ONLY=1 to restore it",
          env: ({
            HOME: "/tmp/sbomhome",
            MAVEN_OPTS: "-Dmaven.repo.local=/tmp/sbomhome/.m2",
            FETCH_LICENSE: $fetch,
            PROJECT_NAME: $pname,
            PROJECT_VERSION: $pver
          } + (if $gotc != "" then {HOST_GOTOOLCHAIN: $gotc} else {} end)),
          env_passthrough: (($prepenv | split(" ") | map(select(. != ""))) + ["GOPROXY", "GOSUMDB", "HOST_UID", "HOST_GID"]),
          env_from_caller: {
            BOMLENS_GUARD_ID: "a unique id for this scan, used with the guard-state mount"
          },
          network: {required: true, purpose: "package registries the project resolves from (npm, PyPI, Maven Central, crates.io, the Go module proxy, ...)"},
          resources: {memory_min: "4g"},
          on_exit: "Run stage 2 whatever the exit code; pass it as BOMLENS_STAGE1_EXIT, and the container log as bomlens-stage1.log in the output folder"
        },
        {
          id: "postprocess",
          stage: 2,
          image: ($img2 | nn),
          image_digest: ($dig2 | nn),
          user: null,
          entrypoint: null,
          args: [],
          workdir: "/host-output",
          mounts: [
            {role: "source", target: "/src", mode: "ro"},
            {role: "output", target: "/host-output", mode: "rw"},
            {role: "trivy-db", target: "/trivy-db", mode: "ro", optional: true}
          ],
          env: {
            MODE: "POSTPROCESS",
            SECURITY_ENRICH: "false",
            BOMLENS_RUN_INPUT: $outfile,
            HOST_OUTPUT_DIR: "/host-output",
            PROJECT_NAME: $pname,
            PROJECT_VERSION: $pver,
            UPLOAD_ENABLED: "false"
          },
          env_passthrough: (["HOST_UID", "HOST_GID", "BOMLENS_INCLUDE_NON_SHIPPED", "SRC_TREE_EXCLUDE"] + ($netenv | split(" ") | map(select(. != "")))),
          env_from_stage1: {
            BOMLENS_STAGE1_EXIT: "the stage 1 exit code",
            BOMLENS_STAGE1_OOM: "true when the stage 1 container was killed for memory",
            BOMLENS_STAGE1_LOG: "bomlens-stage1.log (stage 1 output, saved in the output folder)"
          },
          network: {required: false, purpose: "the Trivy database download when no trivy-db mount holds one, and options that look things up online (--license-registry, --resolve-purl, EPSS/KEV, staleness)"}
        }
      ] end)
    }' > "$OUTDIR/bomlens-plan.json"

if [[ "${HOST_UID:-}" =~ ^[0-9]+$ ]] && [[ "${HOST_GID:-}" =~ ^[0-9]+$ ]]; then
    chown -R "$HOST_UID:$HOST_GID" "$OUTDIR/bomlens-plan" "$OUTDIR/bomlens-plan.json" 2>/dev/null || true
fi
echo "[plan] $status: $lang${image:+ -> $image@$digest}${detail:+ ($detail)}"
# Exit 0 for ok, 3 for unsupported: the plan is written either way, and a
# caller that only checks the code still sees that there is nothing to run.
[ "$status" = "ok" ] || exit 3
