#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
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
# Sourced by docker/entrypoint.sh; unit-tested by tests/test-postprocess.sh.

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
run_optional_step() {
    local label="$1"; shift
    if "$@"; then
        return 0
    fi
    echo "[WARN] post-process step '$label' failed; continuing with a valid SBOM, but this step's output may be missing or incomplete." >&2
    mark_pipeline_warning "${OUTPUT_FILE:-}" "$label"
    return 0
}
