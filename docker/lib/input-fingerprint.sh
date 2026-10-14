#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# input-fingerprint.sh - the input fingerprint of a source scan's stage 1.
#
# Stage 1 (build-prep.sh and cdxgen in a language image) reads the whole source
# tree. When no file in it changed (.git/ aside), and stage 1 ran from the same
# images, files and settings, a caller that kept the SBOM from an earlier stage
# 1 (exit code 0) may use it again and skip stage 1; stage 2 always runs. The
# fingerprint is a sha256 over all of that, with whether the result is
# reproducible at all (a resolver that asks the registry again is not) and why
# not. input-fingerprint.py does the work; this file gathers what it is given
# on each path.
#
# Sourced after source-detect.sh by make-plan.sh (the execution plan) and by
# entrypoint.sh (the result manifest of a POSTPROCESS run). Documented in the
# input fingerprint section of docs/reference/engine-contract.md.
#
# Left out: absolute paths, time, scan id, proxies, registry addresses and
# credentials (PROXY_ENV_NAMES, GOPROXY, GOSUMDB, TRIVY_*), CDXGEN_IMAGE_PREFIX
# (a mirror serves the same digest) and HOST_UID/HOST_GID. SRC_TREE_EXCLUDE is
# not an input either: stage 1 never sees it.

_FP_LIBDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# A fingerprint that says nothing can be reused, for when it cannot be made.
INPUT_FINGERPRINT_UNAVAILABLE='{"algorithm":"bomlens-input-1","sha256":null,"reusable":false,"reasons":["unhashable-input"],"components":[]}'

# cdxgen_pinned_digest <image> <libdir>: the digest cdxgen-images.json records
# for a cdxgen image, or nothing. Digests are recorded by the published name; a
# mirror serves the same image under its own prefix (CDXGEN_IMAGE_PREFIX).
cdxgen_pinned_digest() {
    local image="$1" libdir="$2" canon
    [ -n "$image" ] || return 0
    canon="${image%:*}"; canon="ghcr.io/cdxgen/${canon#"$CDXGEN_IMAGE_PREFIX"}"
    jq -r --arg i "$canon" --arg t "${image##*:}" \
        'if .tag == $t then (.digests[$i] // "") else "" end' "$libdir/cdxgen-images.json" 2>/dev/null || true
}

# _fp_run <src> <ecosystem> <unsupported> <stage1-missing-reason> <fetch>
#         <gotoolchain> <spec> [input-fingerprint.py options...]
# The settings stage 1 reads: the ones given, and the build-prep options from
# this environment.
_fp_run() {
    local src="$1" lang="$2" unsupported="$3" missing="$4" fetch="$5" gotc="$6" spec="$7" n
    shift 7
    local -a args=(--src "$src" --ecosystem "$lang" --manifest-re "$NON_SHIPPED_MANIFEST_RE"
        --stage1-missing-reason "$missing"
        --setting "PROJECT_NAME=${PROJECT_NAME:-}" --setting "PROJECT_VERSION=${PROJECT_VERSION:-}"
        --setting "FETCH_LICENSE=$fetch" --setting "HOST_GOTOOLCHAIN=$gotc" --setting "CDX_SPEC_VERSION=$spec")
    if non_shipped_enabled; then args+=(--non-shipped-dirs "$NON_SHIPPED_DIRS"); fi
    for n in $BUILD_PREP_ENV_NAMES; do args+=(--setting "$n=${!n:-}"); done
    if [ "$unsupported" = "true" ]; then args+=(--unsupported); fi
    command -v python3 >/dev/null 2>&1 || return 1
    # BOMLENS_FINGERPRINT_TIMEOUT bounds the walk inside the script; this
    # bounds the whole computation, the checks included, at 30 seconds more.
    # A run that is stopped prints nothing, and the caller then records the
    # not-reusable INPUT_FINGERPRINT_UNAVAILABLE.
    local limit="${BOMLENS_FINGERPRINT_TIMEOUT:-300}"
    case "$limit" in ''|*[!0-9]*|0) limit=300 ;; esac
    if command -v timeout >/dev/null 2>&1; then
        timeout "$((limit + 30))" python3 "$_FP_LIBDIR/input-fingerprint.py" "${args[@]}" "$@"
    else
        python3 "$_FP_LIBDIR/input-fingerprint.py" "${args[@]}" "$@"
    fi
}

# input_fingerprint_plan <src> <ecosystem> <stage1-digest> <unsupported>
#                        <fetch> <gotoolchain> <spec> <plan-files-dir>
# The plan's fingerprint. The files stage 1 runs from this image are hashed as
# copied into bomlens-plan/, and make-plan.sh, which sets stage 1's arguments
# and environment, as it is in this image.
input_fingerprint_plan() {
    _fp_run "$1" "$2" "$4" plan-unsupported "$5" "$6" "$7" \
        --image "stage1=$3" --image "bomlens=${BOMLENS_IMAGE_DIGEST:-}" \
        --engine-file "build-prep.sh=$8/build-prep.sh" --engine-file "identify-conda.py=$8/identify-conda.py" \
        --engine-file "make-plan.sh=$_FP_LIBDIR/make-plan.sh"
}

# input_fingerprint_for_run <plan> <output-file> <src> <output-dir>
# For the result manifest of a POSTPROCESS run: {"fingerprint": ..., "plan_mismatch":
# true|false|null}. Always computed again from the source with this image's
# code, never taken from a file in the output folder.
#   - After an execution plan (bomlens-plan.json there, written for this SBOM):
#     stage 1's image digest, settings and spec version come from the plan (or
#     BOMLENS_STAGE1_DIGEST), its files from the bomlens-plan/ copies. When the
#     result differs from the plan's own value, plan_mismatch is true.
#   - Otherwise (the CLI's stage 2): what the CLI says it ran, in
#     BOMLENS_STAGE1_DIGEST (the image's RepoDigest), BOMLENS_STAGE1_PREP_SHA256,
#     BOMLENS_STAGE1_CONDA_SHA256, BOMLENS_STAGE1_CLI_SHA256 (scan-sbom.sh, which
#     sets stage 1's arguments there) and BOMLENS_STAGE1_SPEC_VERSION, with the
#     run's own output folder inside the source left out of the tree
#     (BOMLENS_FINGERPRINT_EXCLUDE; that makes the result not reusable, since
#     stage 1 may have read an earlier run's files there). Anything missing
#     makes the result not reusable too.
# Prints nothing when there is no source to read.
input_fingerprint_for_run() {
    local plan="$1" outfile="$2" src="$3" outdir="$4" lang plan_fp="" fp mismatch=null
    local dig fetch gotc spec bdig unsup
    [ -d "$src" ] || return 0
    lang="$(detect_lang "$src")"
    if [ -f "$plan" ]; then
        plan_fp="$(jq -c --arg f "$outfile" 'select(.output_file == $f)
            | (([.stages[]? | select(.id == "generate") | .input_fingerprint] | first) // .input_fingerprint // {})' "$plan" 2>/dev/null || true)"
    fi
    if [ -n "$plan_fp" ]; then
        dig="${BOMLENS_STAGE1_DIGEST:-$(jq -r '[.stages[]? | select(.id == "generate") | .image_digest] | first // ""' "$plan")}"
        bdig="${BOMLENS_IMAGE_DIGEST:-$(jq -r '.engine.image_digest // ""' "$plan")}"
        unsup="$(jq -r 'if .status == "ok" then "false" else "true" end' "$plan")"
        fetch="$(jq -r '[.stages[]? | select(.id == "generate") | .env.FETCH_LICENSE] | first // empty' "$plan")"
        if [ -z "$fetch" ]; then
            fetch="${FETCH_LICENSE:-true}"; [ "${BYTE_STABLE:-false}" = "true" ] && fetch="false"
        fi
        gotc="$(jq -r '[.stages[]? | select(.id == "generate") | .env.HOST_GOTOOLCHAIN] | first // ""' "$plan")"
        spec="$(jq -r '[.stages[]? | select(.id == "generate") | .args[3]] | first // empty' "$plan")"
        fp="$(BOMLENS_IMAGE_DIGEST="$bdig" input_fingerprint_plan "$src" "$lang" "$dig" "$unsup" \
            "$fetch" "$gotc" "${spec:-$CDX_SPEC_VERSION}" "$outdir/bomlens-plan")" || fp=""
        [ -n "$fp" ] || fp="$INPUT_FINGERPRINT_UNAVAILABLE"
        mismatch="$(jq -n --argjson a "$plan_fp" --argjson b "$fp" \
            '([$a.sha256, $a.reasons, $a.components] != [$b.sha256, $b.reasons, $b.components])' 2>/dev/null || echo true)"
    else
        fetch="${FETCH_LICENSE:-true}"; [ "${BYTE_STABLE:-false}" = "true" ] && fetch="false"
        gotc="${HOST_GOTOOLCHAIN:-}"
        case "$gotc" in *[!A-Za-z0-9.+_-]*) gotc="" ;; esac
        fp="$(_fp_run "$src" "$lang" false unknown-stage1-image "$fetch" "$gotc" "${BOMLENS_STAGE1_SPEC_VERSION:-}" \
            --image "stage1=${BOMLENS_STAGE1_DIGEST:-}" --image "bomlens=${BOMLENS_IMAGE_DIGEST:-}" \
            --engine-sha "build-prep.sh=${BOMLENS_STAGE1_PREP_SHA256:-}" \
            --engine-sha "identify-conda.py=${BOMLENS_STAGE1_CONDA_SHA256:-}" \
            --engine-sha "scan-sbom.sh=${BOMLENS_STAGE1_CLI_SHA256:-}" \
            --exclude-dir "${BOMLENS_FINGERPRINT_EXCLUDE:-}")" || fp=""
        [ -n "$fp" ] || fp="$INPUT_FINGERPRINT_UNAVAILABLE"
    fi
    jq -nc --argjson fp "$fp" --argjson m "$mismatch" '{fingerprint: $fp, plan_mismatch: $m}'
}
