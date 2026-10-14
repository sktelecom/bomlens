#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# pipeline-step.sh — observability helpers for best-effort post-process steps.
#
# Several post-process steps (normalize, CPE/AIBOM enrichment, conformance,
# vendored-OSS suggestion) must never abort a scan — a valid SBOM is always
# emitted — which is why they used to end in `... || true`. But a bare `|| true`
# hid real failures: a broken step silently produced a slightly wrong SBOM with
# no trace. run_optional_step keeps the "never abort" guarantee while logging the
# failure and recording it on the SBOM, so the failure is observable.
#
# Sourced by docker/entrypoint.sh and, for mark_document_status specifically,
# by enrich-eol.sh / enrich-malicious.sh directly (they run as their own `bash
# script.sh` process, not sourced into entrypoint.sh's shell, so each sources
# this file itself). Unit-tested by tests/test-postprocess.sh.

# Stamp a single-valued document-level status property, replacing any existing
# entry of the same name rather than appending — so re-running the same check,
# or re-scanning an SBOM that already carries this scanner's own stamp (a
# supplier-submitted BomLens SBOM re-processed with --analyze), does not
# accumulate duplicates. Distinct from mark_pipeline_warning below, whose
# entries intentionally form a list (one failed step co-exists with another).
mark_document_status() {
    local file="$1" name="$2" value="$3" tmp
    [ -n "$file" ] && [ -f "$file" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    tmp="${file}.docstatus.tmp"
    if jq --arg n "$name" --arg v "$value" \
        '(.metadata.properties) = (((.metadata.properties // [])
            | map(select(.name != $n))) + [{name:$n, value:$v}])' \
        "$file" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
    fi
}

# Record that a best-effort post-process step failed. Distinct from the
# bomlens:sbom-tool-degraded signal (a shallow syft *generation* fallback); this
# marks that an enrichment/normalize/conformance *step* did not complete, so a
# reader knows the SBOM is valid but that step's output may be missing.
mark_pipeline_warning() {
    local file="$1" step="$2" tmp
    [ -n "$file" ] && [ -f "$file" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    tmp="${file}.pipewarn.tmp"
    if jq --arg s "$step" \
        '(.metadata.properties) = ((.metadata.properties // []) + [{name:"bomlens:pipeline-step-failed", value:$s}])' \
        "$file" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
    fi
}

# Run a best-effort post-process step. On failure, log a WARN and stamp the
# SBOM ($OUTPUT_FILE, set by the caller) so the failure is observable, then
# return 0 so the run continues with a valid SBOM.
# When the run keeps a result manifest (engine-result.sh), the step's outcome
# and time span are recorded there too.
run_optional_step() {
    local label="$1"; shift
    local _started=""
    declare -F er_record >/dev/null && _started="$(er_now)"
    declare -F er_event >/dev/null && er_event step.start "$label"
    if "$@"; then
        [ -n "$_started" ] && er_record "$label" ok "" "" "$_started"
        return 0
    fi
    echo "[WARN] post-process step '$label' failed; continuing with a valid SBOM, but this step's output may be missing or incomplete." >&2
    mark_pipeline_warning "${OUTPUT_FILE:-}" "$label"
    [ -n "$_started" ] && er_record "$label" failed failed "" "$_started"
    return 0
}

# Print "arm64" and return 0 when this container is an amd64 image run under
# user-mode emulation on an arm64 host (uname says x86_64, but the kernel's
# /proc/cpuinfo describes ARM cores); return 1 otherwise. Go programs such as
# syft can crash at random there, in the garbage collector. BOMLENS_UNAME_M and
# BOMLENS_CPUINFO_FILE stand in for uname and /proc/cpuinfo in tests.
emulated_host_arch() {
    local m cpuinfo="${BOMLENS_CPUINFO_FILE:-/proc/cpuinfo}"
    m="${BOMLENS_UNAME_M:-$(uname -m 2>/dev/null)}"
    case "$m" in x86_64|amd64|i?86) ;; *) return 1 ;; esac
    [ -r "$cpuinfo" ] || return 1
    if grep -q '^CPU implementer' "$cpuinfo" 2>/dev/null; then
        echo arm64
        return 0
    fi
    return 1
}
