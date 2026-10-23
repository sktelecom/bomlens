#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# ========================================================
# Post-processing entrypoint (2-stage architecture)
#
# Source-code SBOM generation (CLI) is done by scan-sbom.sh via cdxgen language
# images. THIS image (post-processor) handles:
#   - UI          : local web UI
#   - SOURCE      : syft dir scan of a source tree (web UI source/zip/git path)
#   - IMAGE/BINARY/ROOTFS : syft scan -> SBOM
#   - FIRMWARE    : unpack firmware -> syft + cve-bin-tool -> SBOM (opt-in image)
#   - MODELFILE   : read one AI model file's own header -> ML-BOM (offline)
#   - AIDECLARE   : an AI model described from the publisher's declaration alone
#   - ANALYZE     : validate + convert a supplier SBOM -> conformance + risk report
#   - MERGE       : combine several CycloneDX SBOMs (layered server delivery)
#   - DIFF        : compare two already-generated AI-model SBOMs (drift report)
#   - POSTPROCESS : consume an already-generated SBOM
# then runs the common pipeline: normalize -> notice -> security -> sign.
# ========================================================

SCAN_MODE="${MODE:-POSTPROCESS}"
# BOMLENS_LIBDIR lets tests/test-engine-contract.sh run this script from a
# checkout against the repository's docker/lib, without building the image.
LIBDIR="${BOMLENS_LIBDIR:-/usr/local/lib/sbom}"
# Any user (a Kubernetes job's runAsUser) with a read-only root: such a user
# has no home of its own, so HOME is / or a folder it cannot write, while the
# tools keep their caches under it (scancode; Trivy's database when no
# trivy-db mount holds one). A home it cannot write becomes a fresh folder in
# the temporary directory, unless something is mounted under it (a cache the
# caller provides, such as ~/.cache/trivy): then HOME stays, and only
# scancode's cache folder, which must be creatable, moves.
if ! { [ -n "${HOME:-}" ] && [ -d "$HOME" ] && [ -w "$HOME" ]; }; then
    if _bomlens_tmp="$(mktemp -d "${TMPDIR:-/tmp}/bomlens-home.XXXXXX" 2>/dev/null)"; then
        if [ -n "${HOME:-}" ] && [ "$HOME" != "/" ] && grep -q " ${HOME%/}/" /proc/mounts 2>/dev/null; then
            export SCANCODE_CACHE="${SCANCODE_CACHE:-$_bomlens_tmp}"
        else
            export HOME="$_bomlens_tmp"
        fi
    else
        echo "[WARN] no writable home folder and no writable ${TMPDIR:-/tmp}: tools that keep a cache (scancode, Trivy) may fail. Mount a writable ${TMPDIR:-/tmp}." >&2
    fi
fi

# The cache folder a host shares between scans (SBOM_TRIVY_CACHE) is meant to
# hold the vulnerability database. Trivy's per-scan layer cache goes to memory
# there: a second scan opening the same cache file at the same time failed with
# "cache may be in use by another process" and left its report incomplete. The
# database is opened read-only, so scans run side by side.
if [ "${TRIVY_CACHE_DIR:-}" = "/trivy-cache" ] && [ -z "${TRIVY_CACHE_BACKEND:-}" ]; then
    export TRIVY_CACHE_BACKEND=memory
fi

# --- UI mode: hand off to the web server, no project metadata needed ---
if [ "$SCAN_MODE" = "UI" ]; then
    echo "[INFO] Starting BomLens Web UI on port ${UI_PORT:-8080}..."
    exec python3 /usr/local/lib/sbom-web/server.py
fi

# Result manifest (bomlens-result.json) for a program that runs this image as
# its scan engine: each step is recorded as it runs, and the manifest is written
# on exit, also when the run stops early (a missing PROJECT_NAME included).
# The trap keeps the exit code: er_finish runs with errexit off, and the code
# is passed to exit again. INT and TERM exit with their own codes so the EXIT
# trap sees 130/143 and records the run as cancelled; generate_sbom_cdxgen
# replaces these two while its sibling container runs, then restores them.
# shellcheck source=docker/lib/engine-result.sh
. "$LIBDIR/engine-result.sh"
er_init
trap er_exit_trap EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- DIFF mode: compare two already-generated SBOMs, no project metadata or
# common pipeline needed — it reads two files and writes one report. Kept out
# of the shared PROJECT_NAME/VERSION pipeline below entirely: unlike MERGE (a
# generator that produces a new SBOM under --project/--version), this produces
# no SBOM at all, so there is nothing for normalize/notice/security/sign to do.
if [ "$SCAN_MODE" = "DIFF" ]; then
    if [ -z "$DIFF_OLD" ] || [ -z "$DIFF_NEW" ]; then
        echo "[ERROR] DIFF_OLD and DIFF_NEW are required for DIFF mode."
        exit 1
    fi
    OUT="/host-output/${DIFF_OUT_NAME:-model-diff.json}"
    python3 "$LIBDIR/diff-ai-model.py" "$DIFF_OLD" "$DIFF_NEW" "$OUT"
    exit $?
fi

if [ -z "$PROJECT_NAME" ] || [ -z "$PROJECT_VERSION" ]; then
    echo "[ERROR] PROJECT_NAME and PROJECT_VERSION are required."
    exit 1
fi

SAFE_PROJECT=$(echo "${PROJECT_NAME}" | sed 's/[^a-zA-Z0-9.-]/_/g' | sed 's/__*/_/g' | sed 's/^_//; s/_$//')
SAFE_VERSION=$(echo "${PROJECT_VERSION}" | sed 's/[^a-zA-Z0-9.-]/_/g' | sed 's/__*/_/g' | sed 's/^_//; s/_$//')
OUTPUT_FILE="${SAFE_PROJECT}_${SAFE_VERSION}_bom.json"
OUT_PREFIX="${SAFE_PROJECT}_${SAFE_VERSION}"

# --- PLAN mode: the execution plan of a source scan (bomlens-plan.json) for a
# program that runs the two stages itself; nothing is scanned here. See
# make-plan.sh.
if [ "$SCAN_MODE" = "PLAN" ]; then
    er_phase plan
    _plan_rc=0
    bash "$LIBDIR/make-plan.sh" "${SOURCE_ROOT:-/src}" "${HOST_OUTPUT_DIR:-.}" "$OUTPUT_FILE" || _plan_rc=$?
    ARTIFACTS=("bomlens-plan.json")
    case "$_plan_rc" in
        0) er_record plan ok "" "" "$ER_PHASE_STARTED"; er_phase_end; exit 0 ;;
        3) _plan_reason="$(jq -r '.reason // empty' "${HOST_OUTPUT_DIR:-.}/bomlens-plan.json" 2>/dev/null)"
           er_record plan skipped "$([ "$_plan_reason" = "android-sdk-image" ] && echo not_installed || echo unavailable)" \
               "$(jq -r '.detail // empty' "${HOST_OUTPUT_DIR:-.}/bomlens-plan.json" 2>/dev/null)" "$ER_PHASE_STARTED"
           # Not a failure: the plan says why there is nothing to run, and
           # the skipped step leaves the run succeeded_degraded.
           er_phase_end; exit 0 ;;
        *) exit "$_plan_rc" ;;
    esac
fi

# --component-versions: read the supplier's file before anything in the output
# folder is removed. The template a scan writes is the file a supplier fills in
# and passes back, so the input can be that very file. It is then neither
# removed by the sweep below nor rewritten by this run: it holds the versions
# the next scan needs as well.
CV_INPUT_IS_TEMPLATE=false
if [ -n "${COMPONENT_VERSIONS_FILE:-}" ] && [ -f "$COMPONENT_VERSIONS_FILE" ]; then
    _cv_copy="$(mktemp)"
    if cp "$COMPONENT_VERSIONS_FILE" "$_cv_copy" 2>/dev/null; then
        if [ -n "$HOST_OUTPUT_DIR" ] && command -v cmp >/dev/null 2>&1 \
           && cmp -s "$_cv_copy" "$HOST_OUTPUT_DIR/${OUT_PREFIX}_component-versions.template.csv"; then
            CV_INPUT_IS_TEMPLATE=true
        fi
        COMPONENT_VERSIONS_FILE="$_cv_copy"
    else
        rm -f "$_cv_copy"
    fi
    unset _cv_copy
fi

# Stale-artifact cleanup. A re-scan of the same project/version reuses this
# folder (mkdir -p, never recreated: scan-sbom.sh and server.py's
# claim_run_id both do this) and sync_artifacts below only ever copies, never
# deletes, so a suffix this run's own mode/options do not produce would
# otherwise survive from an earlier run here and be mistaken for this run's
# own output: a CLI re-scan's folder listing, and the web UI's results list
# and download-all (both just read whatever is on disk right now) would all
# still show it. Every image (base, firmware, aibom, deep-cve) runs this same
# entrypoint, and the web UI's sibling-container paths and --analyze both
# reach here too, so this one place covers all of them.
#
# Only a file matching THIS run's prefix and a suffix this pipeline is known
# to produce is removed; anything else the user placed in the folder (a
# README, an unrelated file) is left alone. --timestamp / ?timestamp=true
# give each run its own folder, so there is nothing to clean there. Run
# before anything below writes a new artifact, so if this run itself fails
# partway through, what is left in the folder is only what THIS run produced
# so far, never a stale mix with the previous run's leftovers.
#
# The suffix list mirrors scripts/check-artifact-registry-sync.sh's REGISTRY
# exactly (that script cross-checks this array against it); update both when
# a producer script starts writing a new one.
KNOWN_ARTIFACT_SUFFIXES=(
    _bom.json _bom.json.sig _bom.spdx.json _bom.spdx.json.sig
    _NOTICE.txt _NOTICE.html _NOTICE.pdf
    _security.json _security.md _security.html
    _conformance.json _conformance.md _conformance.html _conformance.result _summary.result
    _risk-report.md _risk-report.html
    _scancode.json _files.json _source.json _input.json
    _yocto_vex.json _security_epss.json _vendored.cdx.json _gate.result
    _ai-profile.json _ai-profile.md _vex.cdx.json
    _bom.spdx3.json _bom.spdx3.json.sig _spdx3-check.json _spdx3-check.md _ai-declaration.template.json
    _modelica.cdx.json _cocoapods.cdx.json _conda.cdx.json
    _security_cvebintool.json _security_grype.json _security_yocto.json
    _security_trivy.json _component-versions.template.csv
    _reachability.cdx.json _bom.refused.json
)
# Only a caller that knows about this cleanup runs it at all. An old
# scan-sbom.sh or server.py (built before this existed) sends neither signal
# below, so its calls fall through to the pre-cleanup behavior (nothing
# removed) instead of this new sweep mistaking ITS stage 1's just-written
# $OUTPUT_FILE for a previous run's leftover -- that mistake is exactly what
# broke a 2-stage CLI SOURCE scan started by an old scan-sbom.sh against a new
# image: BOMLENS_RUN_INPUT (below) only protects one filename, it does not
# gate whether the sweep runs at all, so a caller that never sends it still
# had everything else it just produced swept away.
#
# BOMLENS_RUN_INPUT itself is the signal for the 2-stage CLI SOURCE path (a
# current scan-sbom.sh always sets it there, see below); every other path
# (single-container CLI modes, the web UI in-process and sibling-container
# paths) has no stage-1 filename to name, so a current caller sends
# BOMLENS_ARTIFACT_CLEANUP=1 instead.
if [ -n "${BOMLENS_RUN_INPUT:-}" ] || [ "${BOMLENS_ARTIFACT_CLEANUP:-}" = "1" ]; then
    # A CLI SOURCE scan writes $OUTPUT_FILE in two containers: stage 1 (cdxgen,
    # on the host) first, this one (POSTPROCESS) second. scan-sbom.sh removes any
    # leftover from an earlier run at this filename before stage 1 starts, so by
    # the time this runs, that same filename is either absent or is stage 1's own
    # fresh output for THIS run -- never a stale one. Deleting it here anyway
    # would be exactly the bug that pre-deletion exists to prevent, so
    # scan-sbom.sh names it (BOMLENS_RUN_INPUT) and it is skipped below. Only a
    # plain filename (no path separator, no leading dot) is honored; anything
    # else is ignored rather than trusted, since a malformed value here should
    # degrade to "skip nothing", not to a path escape.
    _run_input=""
    # A licence scan the caller ran first and that finished (0, or 6 with
    # errors on some files) wrote this run's _scancode.json; any other code
    # leaves the file to be removed with the rest.
    _dl_handed_rc=""
    case "${BOMLENS_DEEP_LICENSE_RC:-}" in 0|6) _dl_handed_rc=1 ;; esac
    if [ -n "${BOMLENS_RUN_INPUT:-}" ] && printf '%s' "$BOMLENS_RUN_INPUT" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
        _run_input="$BOMLENS_RUN_INPUT"
    fi
    if [ -n "$HOST_OUTPUT_DIR" ] && [ -d "$HOST_OUTPUT_DIR" ]; then
        _cleaned=()
        for _suf in "${KNOWN_ARTIFACT_SUFFIXES[@]}"; do
            _f="$HOST_OUTPUT_DIR/${OUT_PREFIX}${_suf}"
            [ -n "$_run_input" ] && [ "$(basename "$_f")" = "$_run_input" ] && continue
            # Stage 1 also leaves the conda sidecar (build-prep.sh parses
            # environment.yml there and drops cdxgen's python cataloger when it
            # does); it is this run's input too, and scan-sbom.sh clears an old
            # one before stage 1 for the same reason as the SBOM itself.
            [ -n "$_run_input" ] && [ "$_suf" = "_conda.cdx.json" ] && continue
            # The licence scan ran before this container, in the deep-license
            # image (see the deep-license step below), and finished: its
            # result is this run's, written by the caller after its own
            # cleanup.
            [ -n "$_dl_handed_rc" ] && [ "$_suf" = "_scancode.json" ] && continue
            [ "${CV_INPUT_IS_TEMPLATE:-false}" = true ] && [ "$_suf" = "_component-versions.template.csv" ] && continue
            if [ -f "$_f" ]; then
                rm -f "$_f"
                _cleaned+=("$(basename "$_f")")
            fi
        done
        if [ "${#_cleaned[@]}" -gt 0 ]; then
            echo "[INFO] cleaned ${#_cleaned[@]} stale artifact(s) from a previous scan of the same project/version: ${_cleaned[*]}"
        fi
        unset _cleaned _suf _f
    fi
    unset _run_input _dl_handed_rc
fi

# Report language for the human-facing conformance + AI-profile reports. Only
# en (default) or ko; the report generators read REPORT_LANG directly, so export
# a normalized value here for both of them. Anything else falls back to English
# and never aborts the run.
case "${REPORT_LANG:-en}" in ko) REPORT_LANG="ko" ;; *) REPORT_LANG="en" ;; esac
export REPORT_LANG

er_phase generate

# Shared language detection + cdxgen image selection (also used by the CLI).
# shellcheck source=docker/lib/source-detect.sh
. "$LIBDIR/source-detect.sh"

# self_container_id: THIS container's own id, for --volumes-from. Docker bind-mounts
# /etc/hostname, /etc/hosts and /etc/resolv.conf from /var/lib/docker/containers/<id>/,
# so the full id appears in /proc/self/mountinfo regardless of cgroup version; fall back
# to $HOSTNAME (the short id, unless a launcher set --hostname — ours do not).
self_container_id() {
    local id
    id=$(sed -n 's|.*/containers/\([0-9a-f]\{64\}\)/.*|\1|p' /proc/self/mountinfo 2>/dev/null | head -1)
    [ -n "$id" ] || id="${HOSTNAME:-}"
    echo "$id"
}

# How long a cancel gives the cdxgen sibling (below) to stop gracefully before
# the docker engine's own SIGKILL fallback takes over. server.py sets the same
# value as the env var when it launches this script, so both sides of a cancel
# (this trap, and server.py's own escalation from proc.terminate() to a hard
# kill) share one number.
BOMLENS_CANCEL_GRACE="${BOMLENS_CANCEL_GRACE:-30}"

# SIBLING_CID: the cdxgen sibling container id while generate_sbom_cdxgen is
# waiting on it, empty otherwise. Read by stop_sibling (below), called from
# the INT/TERM trap generate_sbom_cdxgen sets while it runs.
SIBLING_CID=""
stop_sibling() {
    [ -n "$SIBLING_CID" ] || return 0
    docker stop -t "$BOMLENS_CANCEL_GRACE" "$SIBLING_CID" >/dev/null 2>&1 || true
}

# REACH_TOOLS_DIR: the folder holding the govulncheck copy handed to the
# sibling (--reachability), while it runs. REACHABILITY_NONCE: the nonce that
# sibling was given, read by the reachability step (reachability.sh).
REACH_TOOLS_DIR=""
REACHABILITY_NONCE="${REACHABILITY_NONCE:-}"
remove_reach_tools() {
    [ -n "$REACH_TOOLS_DIR" ] || return 0
    rm -rf -- "$REACH_TOOLS_DIR" 2>/dev/null
    REACH_TOOLS_DIR=""
}

# Host-persistent guard state: mirrors scripts/scan-sbom.sh's
# setup_guard_state for the web UI's SOURCE scans. Whoever launched this
# container (scan-sbom.sh --ui, the desktop app) mounts a host directory at
# GUARD_STATE_DIR; --volumes-from "$self" below already carries that mount
# into the cdxgen sibling, so only the env var needs adding there.
#
# Scope: only a stable, repeatedly-scanned host path. SOURCE_ROOT_HOST is
# empty for a ZIP upload or git clone (a fresh temp dir every scan, so there
# is no "next scan of the same tree" to hand a stale record to) — the same
# scope scan-sbom.sh's CLI path uses.
guard_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum 2>/dev/null | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 2>/dev/null | awk '{print $1}'
    else
        return 1
    fi
}
#   $1 = this container's id (for --volumes-from, sees the same mounts the
#        real sibling would)
#   $2 = build-prep.sh's own content (already read once by the caller)
#   $3 = scanned tree, this container's path
#   $4 = the name the caller is about to give the real sibling container
#   $5 = the cdxgen image the caller is about to run (recorded for cleanup)
GUARD_STATE_DIR="/bomlens-state"
GUARD_ID=""

# write_prep_file: place build-prep.sh's content ($1) in a file the cdxgen
# sibling can run by path, and print that path. build-prep.sh has grown past
# the kernel's single-argument limit (MAX_ARG_STRLEN, 128KiB on Linux --
# Docker Desktop's Linux VM, Colima and GitHub Actions runners all enforce
# it), so injecting it as `sh -c "$prep"` now fails with "argument list too
# long" once the script crosses that line. GUARD_STATE_DIR is a host-
# persistent directory both launch paths (scan-sbom.sh --ui, the desktop app)
# always mount into this container and carry to the sibling via
# --volumes-from, so a file written here is visible to the sibling at the
# same path -- the same trick --volumes-from already does for the scanned
# tree. Prints nothing when that mount is missing; callers fall back to the
# old -c injection (defensive only, both launch paths always provide it).
write_prep_file() {
    [ -d "$GUARD_STATE_DIR" ] || return 1
    mkdir -p "$GUARD_STATE_DIR/prep" 2>/dev/null || return 1
    local f="$GUARD_STATE_DIR/prep/prep-$$.sh"
    printf '%s' "$1" > "$f" 2>/dev/null || return 1
    echo "$f"
}
setup_guard_state() {
    local self="$1" prep="$2" src="$3" next_owner="$4" next_image="$5"
    [ -n "${SOURCE_ROOT_HOST:-}" ] || return 0
    [ -d "$GUARD_STATE_DIR" ] || return 0
    local key owner_file owner ps_out ps_rc recorded_path recorded_image cleanup_image self_image
    key=$(printf '%s' "$SOURCE_ROOT_HOST" | guard_hash) || return 0
    [ -n "$key" ] || return 0
    owner_file="$GUARD_STATE_DIR/$key/owner"
    if [ -f "$owner_file" ]; then
        owner=$(cat "$owner_file" 2>/dev/null)
        recorded_path=$(cat "$GUARD_STATE_DIR/$key/path" 2>/dev/null)
        if [ -z "$owner" ] || [ "$recorded_path" != "$SOURCE_ROOT_HOST" ] || ! command -v docker >/dev/null 2>&1; then
            echo "[WARN] found a leftover-cleanup record for this folder that does not match it (or cannot be confirmed); leaving it in place."
            return 0
        fi
        ps_out=$(docker ps --filter "name=^${owner}\$" --format '{{.Names}}' 2>/dev/null)
        ps_rc=$?
        if [ "$ps_rc" -ne 0 ]; then
            echo "[WARN] could not confirm whether a previous scan of this folder ($owner) is still running; leaving its leftovers in place this time."
            return 0
        fi
        if [ -n "$ps_out" ]; then
            echo "[WARN] a previous scan of this folder ($owner) appears to still be running; not touching its leftovers."
            return 0
        fi
        recorded_image=$(cat "$GUARD_STATE_DIR/$key/image" 2>/dev/null)
        cleanup_image=""
        if [ -n "$recorded_image" ] && docker image inspect "$recorded_image" >/dev/null 2>&1; then
            cleanup_image="$recorded_image"
        else
            self_image=$(docker inspect -f '{{.Config.Image}}' "$self" 2>/dev/null)
            if [ -n "$self_image" ] && docker image inspect "$self_image" >/dev/null 2>&1; then
                cleanup_image="$self_image"
            fi
        fi
        if [ -z "$cleanup_image" ]; then
            echo "[WARN] no locally available image to clean up a previous interrupted scan's leftovers with; leaving them in place."
            return 0
        fi
        echo "[INFO] cleaning up build artifacts a previous, interrupted scan of this folder left behind..."
        local cleanup_prep_file; cleanup_prep_file=$(write_prep_file "$prep")
        if [ -n "$cleanup_prep_file" ]; then
            docker run --rm -u 0:0 \
                --volumes-from "$self" \
                -e BOMLENS_GUARD_RESTORE_ONLY=1 -e "BOMLENS_GUARD_ID=$key" \
                --entrypoint sh "$cleanup_image" \
                "$cleanup_prep_file" "$src" >/dev/null 2>&1 || true
            rm -f "$cleanup_prep_file"
        else
            docker run --rm -u 0:0 \
                --volumes-from "$self" \
                -e BOMLENS_GUARD_RESTORE_ONLY=1 -e "BOMLENS_GUARD_ID=$key" \
                --entrypoint sh "$cleanup_image" \
                -c "$prep" _ "$src" >/dev/null 2>&1 || true
        fi
    fi
    mkdir -p "$GUARD_STATE_DIR/$key" 2>/dev/null || return 0
    printf '%s\n' "$next_owner" > "$GUARD_STATE_DIR/$key/owner" 2>/dev/null || return 0
    printf '%s\n' "$SOURCE_ROOT_HOST" > "$GUARD_STATE_DIR/$key/path" 2>/dev/null || return 0
    printf '%s\n' "$next_image" > "$GUARD_STATE_DIR/$key/image" 2>/dev/null || return 0
    GUARD_ID="$key"
}

# generate_sbom_cdxgen: run a cdxgen language image as a SIBLING container (via the
# mounted host Docker socket) so a web-UI source scan resolves transitive deps,
# matching the CLI. The sibling reaches the scanned tree by inheriting THIS container's
# mounts (--volumes-from), NOT by a host path. Passing a host path was the Windows UI
# defect: SOURCE_ROOT_HOST is a drive path (C:/…) there, and the in-container Linux
# docker CLI cannot consume a drive letter — the ':' splits the -v spec ("invalid mode")
# so cdxgen never ran and the scan silently fell back to syft. --volumes-from replays the
# daemon's already-resolved mount, so the source appears at the SAME container path on
# every host OS. build-prep.sh is injected inline (it lives only inside THIS image, not on
# the host). cdxgen writes the bom straight into the working dir when that dir is on a
# shared mount, so the scanned tree stays untouched (see bom_path below).
#   $1 = scanned tree, this container's path (also the sibling's, via --volumes-from)
#   $2 = output bom filename (relative)
generate_sbom_cdxgen() {
    local src="$1" out="$2"
    local lang img api rc=0 self
    CDXGEN_FAIL_REASON=""
    self=$(self_container_id)
    if [ -z "$self" ]; then
        CDXGEN_FAIL_REASON="cdxgen-unavailable"
        echo "[WARN] cdxgen sibling: could not determine this container's id for --volumes-from."
        return 1
    fi
    lang=$(detect_lang "$src")
    warn_low_engine_memory_for "$lang" "$src"
    if [ "$lang" = "android" ]; then
        api=$(android_api "$src")
        img="${ANDROID_IMAGE_PREFIX}${api}:latest"
        echo "[INFO] Android source (compileSdk=$api) -> $img"
        # Not a published image — the Android SDK inside it is not open source
        # and its terms bar redistribution, so it is built where it is used.
        if ! docker image inspect "$img" >/dev/null 2>&1; then
            echo "[ERROR] Android SDK image not found: $img"
            echo "        Build it on the host once, then re-run:"
            echo "          docker build --build-arg ANDROID_API=$api$([ "$CDXGEN_IMAGE_PREFIX" = "ghcr.io/cdxgen/" ] || printf ' --build-arg CDXGEN_IMAGE_PREFIX=%s' "$CDXGEN_IMAGE_PREFIX") -t $img docker/android"
            echo "        (accepting https://developer.android.com/studio/terms), or set"
            echo "        ANDROID_IMAGE_PREFIX to an image built elsewhere."
            return 1
        fi
    else
        img=$(img_for_lang "$lang")
        echo "[INFO] Language: $lang -> $img"
    fi
    local prep; prep=$(cat "$LIBDIR/build-prep.sh")
    # Where cdxgen writes the bom. Our working dir is the right place — a scan
    # must not drop files into the project it analyzes — but the sibling only
    # sees that dir if it sits on a mount we inherited via --volumes-from, so
    # confirm it against /proc/self/mountinfo (field 5 is the mount point; "/"
    # is this container's own layer and is NOT shared). If it is not shared we
    # fall back to writing inside the tree and move the file out below, which is
    # what this always did.
    local outdir bom_path
    outdir=$(pwd)
    if awk -v d="$outdir" '$5 != "/" && ($5 == d || index(d, $5 "/") == 1) { found = 1 } END { exit !found }' \
           /proc/self/mountinfo 2>/dev/null; then
        bom_path="$outdir/$out"
    else
        bom_path="$src/$out"
    fi
    # Capture the sibling output for diagnosis while still streaming it live, so
    # an out-of-disk extraction failure can be reported specifically (rather than
    # a bare rc=125) and recorded for the UI. --rm is dropped in favor of an
    # explicit --cidfile + docker rm below: an out-of-memory kill (rc=137) needs
    # `docker inspect`'s own OOMKilled flag to confirm, which --rm's automatic
    # cleanup would remove before we could read it — guessing from rc=137 alone
    # would misreport a plain `kill -9` or an OOM on a different process in the
    # same container as memory exhaustion.
    #
    # Run in the background and wait explicitly, instead of foreground, so a
    # cancel (server.py's proc.terminate()) is handled the moment it arrives:
    # a shell only acts on a trap once it regains control, and while blocked on
    # a foreground command that does not happen until the command finishes on
    # its own (measured). `wait` returns as soon as the signal
    # arrives, so the trap below can stop the sibling right away instead of
    # leaving it to run to completion unsupervised.
    local logf cidf rcf; logf=$(mktemp); cidf=$(mktemp); rcf=$(mktemp); rm -f "$cidf"
    local prep_env; read -ra prep_env <<< "$(build_prep_env_args)"
    local sibling_name="bomlens-sib-$$"
    setup_guard_state "$self" "$prep" "$src" "$sibling_name" "$img"
    local guard_env=()
    [ -n "$GUARD_ID" ] && guard_env=(-e "BOMLENS_GUARD_ID=$GUARD_ID")
    # See write_prep_file above: run build-prep.sh by path when the guard-state
    # mount is there (the normal case), fall back to the old -c injection
    # otherwise (works as long as build-prep.sh stays under the kernel's
    # 128KiB single-argument limit).
    local prep_file; prep_file=$(write_prep_file "$prep")
    # --reachability on Go: the sibling has the Go toolchain this image lacks,
    # so govulncheck runs there (build-prep.sh). The binary is copied into a
    # new folder of its own under the guard-state mount, which the sibling
    # shares through --volumes-from and which is not the run folder, and the
    # folder is removed once the sibling has finished or the scan is
    # cancelled. Stage 1 writes the nonce beside its output; the reachability
    # step below reads only output that carries it.
    local reach_env=()
    REACH_TOOLS_DIR=""; REACHABILITY_NONCE=""
    if [ "${REACHABILITY:-false}" = "true" ] && [ "$lang" = "go" ] && [ "$bom_path" = "$outdir/$out" ] \
       && command -v govulncheck >/dev/null 2>&1; then
        if [ -d "$GUARD_STATE_DIR" ] && mkdir -p "$GUARD_STATE_DIR/tools" 2>/dev/null; then
            # A copy left by a scan that was killed outright (no trap ran).
            find "$GUARD_STATE_DIR/tools" -maxdepth 1 -name 'govulncheck.*' -mmin +1440 -exec rm -rf {} + 2>/dev/null || true
            REACH_TOOLS_DIR=$(mktemp -d "$GUARD_STATE_DIR/tools/govulncheck.XXXXXX" 2>/dev/null) || REACH_TOOLS_DIR=""
        fi
        if [ -n "$REACH_TOOLS_DIR" ] && chmod 755 "$REACH_TOOLS_DIR" \
           && cp "$(command -v govulncheck)" "$REACH_TOOLS_DIR/govulncheck" 2>/dev/null \
           && chmod 755 "$REACH_TOOLS_DIR/govulncheck"; then
            REACHABILITY_NONCE=$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
            [ -n "$REACHABILITY_NONCE" ] || REACHABILITY_NONCE="$$${RANDOM}${RANDOM}$(date +%s)"
            reach_env=(-e BOMLENS_REACHABILITY=true -e "BOMLENS_GOVULNCHECK=$REACH_TOOLS_DIR/govulncheck"
                       -e "BOMLENS_REACHABILITY_NONCE=$REACHABILITY_NONCE")
        else
            echo "[WARN] --reachability: no folder outside the run folder to hand govulncheck to the cdxgen container (the launcher mounts none at $GUARD_STATE_DIR); the Go call analysis is skipped."
            remove_reach_tools
        fi
    fi
    ( if [ -n "$prep_file" ]; then
        docker run -u 0:0 \
            --name "$sibling_name" \
            --cidfile "$cidf" \
            --volumes-from "$self" \
            -e HOME=/tmp/sbomhome \
            -e "MAVEN_OPTS=-Duser.home=/tmp/sbomhome -Dmaven.repo.local=/tmp/sbomhome/.m2/repository" \
            -e GOPATH=/tmp/sbomhome/go -e GOMODCACHE=/tmp/sbomhome/go/pkg/mod -e GOCACHE=/tmp/sbomhome/go-build \
            -e FETCH_LICENSE="$FETCH_LICENSE" \
            -e PROJECT_NAME="$PROJECT_NAME" \
            -e PROJECT_VERSION="$PROJECT_VERSION" \
            -e HOST_GOTOOLCHAIN="${GOTOOLCHAIN:-}" -e GOPROXY -e GOSUMDB \
            "${prep_env[@]}" \
            "${guard_env[@]}" \
            "${reach_env[@]}" \
            --entrypoint sh "$img" \
            "$prep_file" "$src" "$bom_path" "$CDX_SPEC_VERSION"
      else
        docker run -u 0:0 \
            --name "$sibling_name" \
            --cidfile "$cidf" \
            --volumes-from "$self" \
            -e HOME=/tmp/sbomhome \
            -e "MAVEN_OPTS=-Duser.home=/tmp/sbomhome -Dmaven.repo.local=/tmp/sbomhome/.m2/repository" \
            -e GOPATH=/tmp/sbomhome/go -e GOMODCACHE=/tmp/sbomhome/go/pkg/mod -e GOCACHE=/tmp/sbomhome/go-build \
            -e FETCH_LICENSE="$FETCH_LICENSE" \
            -e PROJECT_NAME="$PROJECT_NAME" \
            -e PROJECT_VERSION="$PROJECT_VERSION" \
            -e HOST_GOTOOLCHAIN="${GOTOOLCHAIN:-}" -e GOPROXY -e GOSUMDB \
            "${prep_env[@]}" \
            "${guard_env[@]}" \
            "${reach_env[@]}" \
            --entrypoint sh "$img" \
            -c "$prep" _ "$src" "$bom_path" "$CDX_SPEC_VERSION"
      fi; echo $? > "$rcf" ) 2>&1 | tee "$logf" &
    local pipe_pid=$!
    # The cidfile appears as soon as the container is created, well before it
    # finishes, so a cancel arriving during the run still has a container id
    # to stop.
    local cid="" _n=0
    while [ -z "$cid" ] && [ "$_n" -lt 50 ] && kill -0 "$pipe_pid" 2>/dev/null; do
        [ -s "$cidf" ] && cid=$(cat "$cidf")
        [ -n "$cid" ] || { sleep 0.1; _n=$((_n + 1)); }
    done
    SIBLING_CID="$cid"
    trap 'stop_sibling; remove_reach_tools; exit 130' INT
    trap 'stop_sibling; remove_reach_tools; exit 143' TERM
    wait "$pipe_pid" || true
    trap 'exit 130' INT
    trap 'exit 143' TERM
    rc=$(cat "$rcf" 2>/dev/null || echo 1)
    rm -f "$rcf"
    remove_reach_tools
    SIBLING_CID=""
    if [ "$rc" -ne 0 ]; then
        if [ -n "$cid" ] && [ "$(docker inspect -f '{{.State.OOMKilled}}' "$cid" 2>/dev/null)" = "true" ]; then
            CDXGEN_FAIL_REASON="oom"
            echo "[WARN] cdxgen was killed for running out of memory (rc=$rc). Give the Docker engine more memory — Docker Desktop: Settings > Resources; Colima: 'colima start --memory N' — and re-scan for full transitive dependencies."
        elif grep -qi "no space left on device" "$logf"; then
            CDXGEN_FAIL_REASON="disk-space"
            echo "[WARN] cdxgen failed: Docker is out of disk space (rc=$rc). Free space (e.g. 'docker system prune') and re-scan for full transitive dependencies."
        elif grep -qEi "temporary failure in name resolution|could not resolve host|network is unreachable|connection timed out|connect timed out|no route to host|ENOTFOUND|ETIMEDOUT" "$logf"; then
            # Build tools resolve the real dependency tree by reaching Maven
            # Central / npmjs / PyPI etc. from inside the sibling container;
            # a proxy, firewall or offline host breaks that even though the
            # scan's own network access (cloning the repo) already worked.
            CDXGEN_FAIL_REASON="network"
            echo "[WARN] cdxgen couldn't reach the network while resolving dependencies (rc=$rc). Check proxy/firewall access to the package registries from the Docker engine and re-scan for full transitive dependencies."
        else
            # Not a resource/network failure this container could see: cdxgen
            # ran and exited non-zero on its own, most often an internal
            # exception or its own schema validator rejecting the document
            # (raw Node stack trace or validation errors, both in $logf only).
            CDXGEN_FAIL_REASON="cdxgen-crash"
            echo "[WARN] cdxgen failed processing the dependency data (rc=$rc)."
        fi
        [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1
        rm -f "$logf" "$cidf" "$prep_file"
        return 1
    fi
    [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1
    rm -f "$logf" "$cidf" "$prep_file"
    if [ "$bom_path" != "$outdir/$out" ] && [ -f "$bom_path" ]; then
        mv "$bom_path" "$outdir/$out"
    fi
    if [ ! -f "$outdir/$out" ]; then
        CDXGEN_FAIL_REASON="cdxgen-unavailable"
        echo "[WARN] cdxgen produced no SBOM at $bom_path."; return 1
    fi
    return 0
}

# Declare how complete this SBOM's dependency graph is, in CycloneDX's own
# compositions.aggregate field (one document-level entry whose dependencies
# names the primary component's bom-ref, when it has one; assemblies stay
# empty). `complete` is used only when there is POSITIVE evidence
# the graph is whole, never merely because nothing failed: an unresolved leaf
# (e.g. one Maven coordinate cdxgen could not fetch) leaves no trace in the
# SBOM or in any log, so "no failure seen" cannot mean "complete" (measured).
#
# SOURCE/POSTPROCESS: build-prep.sh already stamped bomlens:prep-step-applied
# (a label per ecosystem lock step it ran or found already committed, success
# or failure) and bomlens:pipeline-step-failed (labels that failed) onto this
# same file -- read those instead of re-deriving anything here, since the
# source tree itself is not mounted in POSTPROCESS. Maven has no such label at
# all (no pre-resolve step, and its own cdxgen success signals do not tell
# resolved apart from degraded, measured), so it can never satisfy the
# lock-evidence condition below and stays `unknown`.
#
# IMAGE/ROOTFS/FIRMWARE/BINARY: syft only reads a package database, so success
# alone is never positive evidence of a complete graph (it does not see
# inter-package or static-linked dependencies) -- these stay `unknown` unless a
# failure signal is present, then `incomplete`.
#
# AIBOM/MODELFILE/DATASET/AIDECLARE/MERGE: no signal this design defines a value for --
# fixed `unknown`. ANALYZE with no compositions of its own is the same
# (`unknown`); ANALYZE that already carries a supplier's own compositions is
# never reached here at all (the early return below).
mark_compositions_aggregate() {
    local file="$1" aggregate="" info degraded lock_ok components edges tmp
    [ -f "$file" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    # A supplier's own declaration (ANALYZE) is never overwritten.
    if jq -e '(.compositions // []) | length > 0' "$file" >/dev/null 2>&1; then
        return 0
    fi
    case "$SCAN_MODE" in
        SOURCE|POSTPROCESS)
            info=$(jq -r --arg labels "npm-production-set pip-install go-mod-tidy cargo-lockfile bundle-lock swift-package-resolve gradle-dependencies android-release-classpath composer-install composer-lock-committed dotnet-lock-committed" '
                ($labels | split(" ")) as $known
                | (.metadata.properties // []) as $props
                | ([$props[] | select(.name=="bomlens:prep-step-applied") | .value]) as $applied
                | ([$props[] | select(.name=="bomlens:pipeline-step-failed") | .value]) as $failed
                # A Poetry project converted only in part (ranges and table
                # entries left out) is missing dependencies by construction,
                # and so is one whose pins could not be resolved further.
                | ((($props | map(select(.name=="bomlens:sbom-tool-degraded")) | length) > 0)
                   or ($applied | index("poetry-requirements-partial") != null)
                   or ($failed | index("poetry-graph") != null)) as $degraded
                | (([$known[] | select(. as $l | ($applied|index($l)) and (($failed|index($l))|not))] | length) > 0) as $lock_ok
                | ((.components // []) | length) as $components
                | ([(.dependencies // [])[]?.dependsOn[]?] | length) as $edges
                | "\($degraded) \($lock_ok) \($components) \($edges)"
            ' "$file" 2>/dev/null)
            read -r degraded lock_ok components edges <<< "$info"
            if [ "$degraded" = "true" ]; then
                aggregate="incomplete"
            elif [ "$lock_ok" = "true" ] && [ "${components:-0}" -ge 2 ] && [ "${edges:-0}" -ge 1 ]; then
                aggregate="complete"
            else
                aggregate="unknown"
            fi
            ;;
        IMAGE|ROOTFS|FIRMWARE|BINARY)
            if jq -e '(.metadata.properties // []) | any(.name=="bomlens:pipeline-step-failed" and (.value=="firmware-packages" or .value=="firmware-extra-roots"))' "$file" >/dev/null 2>&1; then
                aggregate="incomplete"
            else
                aggregate="unknown"
            fi
            ;;
        AIBOM|MODELFILE|DATASET|AIDECLARE|MERGE|ANALYZE)
            aggregate="unknown"
            ;;
        *)
            return 0
            ;;
    esac
    [ -n "$aggregate" ] || return 0
    tmp="${file}.compositions.tmp"
    # The entry names the graph its aggregate is about: the dependencies of the
    # primary component (compositions[].dependencies), so a reader such as a
    # BSI TR-03183-2 check sees the completeness stated for the dependency
    # graph rather than for an unnamed set. The aggregate value is unchanged.
    if jq --arg agg "$aggregate" '
        ((.metadata.component["bom-ref"] // "") | if type == "string" then . else "" end) as $root
        | .compositions = [{aggregate: $agg} + (if $root != "" then {dependencies: [$root]} else {} end)]' \
        "$file" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
    fi
}

# Observability helpers for best-effort post-process steps (run_optional_step /
# mark_pipeline_warning): a failed enrichment/normalize/conformance step is now
# logged and recorded on the SBOM instead of being swallowed by `... || true`.
# shellcheck source=docker/lib/pipeline-step.sh
. "$LIBDIR/pipeline-step.sh"
# shellcheck source=docker/lib/cdx-version.sh
. "$LIBDIR/cdx-version.sh"

# Modes whose SBOM describes an AI asset rather than a software project: the
# model-card path (AIBOM, from a HuggingFace id), the model-file path
# (MODELFILE, from the file itself), the dataset path (DATASET, from a
# published research item) and the declaration path (AIDECLARE, from what the
# publisher states). They share the AI post-processing — risk assessment,
# G7 conformance, the AI profile — and skip the package-oriented enrichments,
# which have no purl, no CPE and no release cycle to match on.
case "$SCAN_MODE" in
    AIBOM|MODELFILE|DATASET|AIDECLARE) AI_MODEL_SCAN=true ;;
    *) AI_MODEL_SCAN=false ;;
esac

echo "=========================================="
echo " BomLens (post-process)"
echo " Mode: $SCAN_MODE"
echo " Project: $PROJECT_NAME ($PROJECT_VERSION)"
echo "=========================================="

# ========================================================
# Produce / locate the SBOM
# ========================================================
# Every syft invocation below pins its CycloneDX output to @$CDX_SPEC_VERSION.
# syft >= 1.28 defaults to emitting CycloneDX 1.7, but the rest of this
# pipeline standardizes on the version cdx-version.sh names (1.6, or 1.7 when
# CYCLONEDX_SPEC_VERSION asks for it): cdxgen is run with --spec-version
# "$CDX_SPEC_VERSION", convert-to-cdx.sh writes it, and the docs promise it.
# The selector keeps syft output aligned with cdxgen.
# Whether the SBOM was read from a Yocto build's own records (ANALYZE: the
# SPDX reader or the manifest reader). Those components have the same need as a
# firmware scan's: no package purl a vulnerability or license database
# resolves, so the upstream purl step below runs for them too.
# YOCTO_CPE_MATCH: the CPE index step as well, for an SPDX 2.2 archive only. Its
# CPEs (Yocto's CVE_PRODUCT) are all it gives for vulnerabilities. An SPDX 3.0
# document records which CVEs each recipe patched or is not affected by, and
# the manifest reader takes cve-check's own verdicts; matching their CPEs again
# would report as open what Yocto already judged.
YOCTO_SBOM=false
YOCTO_CPE_MATCH=false
# The document came out of a Yocto build directory the user pointed at, not from
# a supplier: the SBOM this scan writes is the one to submit, so it is the one
# checked for conformance (below), not the build's own document. YOCTO_FROM_BUILD
# is set by scan-sbom.sh and server.py when they found the document in the build.
YOCTO_FROM_BUILD="${YOCTO_FROM_BUILD:-false}"
[ -n "${YOCTO_BUILD_DIR:-}" ] && YOCTO_FROM_BUILD=true
case "$SCAN_MODE" in
    SOURCE)
        # Local web UI source scan (current dir / extracted ZIP / cloned git repo).
        # Preferred path: run a cdxgen language image as a sibling container so
        # transitive dependencies resolve, matching the CLI. This needs the host
        # Docker socket and a docker CLI in this image. SOURCE_ROOT_HOST (set by the
        # web server) is required only as the signal that the scanned tree is under a
        # mount this container owns — the sibling inherits that mount via --volumes-from
        # rather than re-mounting a host path, so its VALUE is no longer used. When the
        # socket/CLI/signal is missing we fall back to syft, which parses package
        # manifests (package.json/go.mod/pom.xml/Gemfile/…) without building — direct deps.
        SRC_ROOT="${SOURCE_ROOT:-/src}"
        if [ ! -d "$SRC_ROOT" ]; then echo "[ERROR] source dir not found: $SRC_ROOT"; exit 1; fi
        if [ -z "$(ls -A "$SRC_ROOT" 2>/dev/null)" ]; then echo "[ERROR] source dir is empty: $SRC_ROOT"; exit 1; fi
        # The syft fallback leaves out the same non-shipped trees as the cdxgen
        # path (see NON_SHIPPED_DIRS in source-detect.sh).
        read -ra SYFT_EXCLUDE <<< "$(non_shipped_syft_args)"
        # Static detection first, as the CLI does (scan-sbom.sh --detection): a lock
        # file that covers the whole tree is read as it is, with no language image
        # and no docker socket. This is also what lets the image run as a CI job
        # container, where there is no Docker to start a sibling in. DETECTION=build
        # keeps the old order; the registry license lookup that fills the licenses
        # a lock file lacks is switched on with it, so a reproducible (BYTE_STABLE)
        # or no-license-fetch run builds instead.
        _static_why=""
        case "${DETECTION:-auto}" in
            static) _static_why="requested" ;;
            auto)
                if [ "${BYTE_STABLE:-false}" != "true" ] && [ "${FETCH_LICENSE:-true}" != "false" ] \
                   && static_detection_check "$SRC_ROOT" "$(detect_lang "$SRC_ROOT")"; then
                    _static_why="$STATIC_DETECTION_WHY"
                fi ;;
        esac
        _static_ok=false
        if [ -n "$_static_why" ]; then
            echo "[1/2] static: source dir $SRC_ROOT ($_static_why, no build)"
            if generate_sbom_static "$SRC_ROOT" "$OUTPUT_FILE"; then
                _static_ok=true
                mark_sbom_detection "$OUTPUT_FILE" static "$_static_why"
                mark_sbom_excluded "$OUTPUT_FILE" "$SRC_ROOT"
                [ "${BYTE_STABLE:-false}" = "true" ] || [ "${FETCH_LICENSE:-true}" = "false" ] || LICENSE_REGISTRY=true
            else
                rm -f "$OUTPUT_FILE"
                echo "[WARN] static detection could not read the lock file; continuing without it."
            fi
        fi
        if [ "$_static_ok" = "true" ]; then
            :
        elif [ -S /var/run/docker.sock ] && command -v docker >/dev/null 2>&1 && [ -n "$SOURCE_ROOT_HOST" ]; then
            # Best-effort low-disk warning: cdxgen pulls/extracts a language image
            # via the host Docker, which fails if space is tight. We only see this
            # container's view of the disk (on Docker Desktop it shares the VM
            # volume), so this is a hint, not a guarantee — the reliable signal is
            # the out-of-disk detection inside generate_sbom_cdxgen.
            avail_mb=$(df -Pk "$SRC_ROOT" 2>/dev/null | awk 'NR==2 {print int($4/1024)}')
            if [ -n "$avail_mb" ] && [ "$avail_mb" -lt 2048 ]; then
                echo "[WARN] Low disk space (~${avail_mb} MB) — cdxgen may fail to pull its language image; consider 'docker system prune'."
            fi
            echo "[1/2] cdxgen: source dir $SRC_ROOT (transitive resolution)"
            if ! generate_sbom_cdxgen "$SRC_ROOT" "$OUTPUT_FILE"; then
                echo "[WARN] cdxgen path failed; falling back to syft (direct deps only)."
                syft "dir:$SRC_ROOT" "${SYFT_EXCLUDE[@]}" -o "cyclonedx-json@$CDX_SPEC_VERSION" > "$OUTPUT_FILE" 2>/dev/null \
                    || { echo "[ERROR] syft source scan failed."; exit 1; }
                apply_node_fallback_quality_gate "$OUTPUT_FILE" "$SRC_ROOT" 2 || exit 1
                mark_sbom_degraded "$OUTPUT_FILE" "${CDXGEN_FAIL_REASON:-cdxgen-unavailable}"
                mark_sbom_excluded "$OUTPUT_FILE" "$SRC_ROOT"
            fi
        else
            echo "[1/2] syft: source dir $SRC_ROOT (manifest-only; docker.sock/CLI/host-path unavailable)"
            syft "dir:$SRC_ROOT" "${SYFT_EXCLUDE[@]}" -o "cyclonedx-json@$CDX_SPEC_VERSION" > "$OUTPUT_FILE" 2>/dev/null \
                || { echo "[ERROR] syft source scan failed."; exit 1; }
            apply_node_fallback_quality_gate "$OUTPUT_FILE" "$SRC_ROOT" 2 || exit 1
            mark_sbom_degraded "$OUTPUT_FILE" "cdxgen-unavailable"
            mark_sbom_excluded "$OUTPUT_FILE" "$SRC_ROOT"
        fi
        # Normalize the root component type for a source scan. cdxgen sets
        # application/library/framework, but a syft `dir:` (fallback / no-Docker)
        # sets "file", which mislabels the scan as a generic "SBOM" in the UI. A
        # source tree is an application-style root, so coerce non-source types
        # here while keeping cdxgen's own choice.
        if command -v jq >/dev/null 2>&1 && [ -f "$OUTPUT_FILE" ]; then
            case "$(jq -r '.metadata.component.type // ""' "$OUTPUT_FILE" 2>/dev/null)" in
                application|library|framework) ;;
                *)
                    if jq '.metadata.component.type = "application"' "$OUTPUT_FILE" \
                        > "$OUTPUT_FILE.rt" 2>/dev/null; then
                        mv "$OUTPUT_FILE.rt" "$OUTPUT_FILE"
                    else
                        rm -f "$OUTPUT_FILE.rt"
                    fi
                    ;;
            esac
        fi
        ;;

    IMAGE)
        if [ -z "$TARGET_IMAGE" ]; then echo "[ERROR] TARGET_IMAGE required for IMAGE mode."; exit 1; fi
        # syft, Trivy and docker would read a name starting with - as an option.
        case "$TARGET_IMAGE" in
            -*) echo "[ERROR] TARGET_IMAGE '$TARGET_IMAGE' starts with '-': an image name cannot, and the scan tools would read it as an option. Give the image reference itself, for example alpine:3.20."; exit 1 ;;
        esac
        # With the Docker socket mounted syft reads the image from the daemon;
        # without it, straight from the registry (no daemon needed, as in a
        # Kubernetes job), or from an archive named with its scheme
        # (docker-archive:, oci-archive:, oci-dir:). A private registry takes
        # SYFT_REGISTRY_AUTH_* or a docker config file (DOCKER_CONFIG).
        if [ -S /var/run/docker.sock ]; then
            echo "[1/2] syft: Docker image $TARGET_IMAGE"
        else
            echo "[1/2] syft: image $TARGET_IMAGE (no Docker socket: read from the registry or the archive)"
        fi
        IMAGE_SYFT_LOG=$(mktemp)
        # syft's source record (its syft-json `source`, through a template so
        # the file catalogue is not written twice) gives the digest it read.
        # It is an extra: when it cannot be written, the scan goes on with the
        # digest unresolved.
        IMAGE_SOURCE_TMPL="$(mktemp 2>/dev/null)" || IMAGE_SOURCE_TMPL=""
        IMAGE_SOURCE_JSON="$(mktemp 2>/dev/null)" || IMAGE_SOURCE_JSON=""
        _img_extra=()
        if [ -n "$IMAGE_SOURCE_TMPL" ] && [ -n "$IMAGE_SOURCE_JSON" ] \
            && printf '%s' '{{ toJson .source }}' > "$IMAGE_SOURCE_TMPL" 2>/dev/null; then
            _img_extra=(-o "template=$IMAGE_SOURCE_JSON" -t "$IMAGE_SOURCE_TMPL")
        else
            echo "[WARN] no temporary file for syft's source record, so the image digest is not resolved: later reads use the reference as given." >&2
            rm -f ${IMAGE_SOURCE_TMPL:+"$IMAGE_SOURCE_TMPL"} ${IMAGE_SOURCE_JSON:+"$IMAGE_SOURCE_JSON"}
            IMAGE_SOURCE_TMPL=""; IMAGE_SOURCE_JSON=""
        fi
        _img_rc=0
        syft "$TARGET_IMAGE" -o "cyclonedx-json@$CDX_SPEC_VERSION" "${_img_extra[@]}" \
            > "$OUTPUT_FILE" 2>"$IMAGE_SYFT_LOG" || _img_rc=$?
        if [ "$_img_rc" -ne 0 ] && [ "${#_img_extra[@]}" -gt 0 ]; then
            # syft writes the SBOM before the template: a complete SBOM means
            # only the source record failed. Otherwise read once more without it.
            if jq -e '.bomFormat == "CycloneDX" and (.components | type) == "array"' "$OUTPUT_FILE" >/dev/null 2>&1; then
                _img_rc=0
            else
                _img_rc=0
                syft "$TARGET_IMAGE" -o "cyclonedx-json@$CDX_SPEC_VERSION" \
                    > "$OUTPUT_FILE" 2>"$IMAGE_SYFT_LOG" || _img_rc=$?
            fi
            if [ "$_img_rc" -eq 0 ]; then
                echo "[WARN] syft could not write its source record, so the image digest is not resolved: later reads use the reference as given." >&2
                rm -f "$IMAGE_SOURCE_JSON"; IMAGE_SOURCE_JSON=""
            fi
        fi
        if [ "$_img_rc" -ne 0 ]; then
            case "$TARGET_IMAGE" in
                docker-archive:*|oci-archive:*|oci-dir:*)
                    echo "[ERROR] syft could not read the image archive $TARGET_IMAGE: check that the path is mounted into the container and holds an image in that format." ;;
                *)
                    echo "[ERROR] syft could not read the image $TARGET_IMAGE: it does not exist, or the registry needs credentials (SYFT_REGISTRY_AUTH_USERNAME and SYFT_REGISTRY_AUTH_PASSWORD, or a docker config file in DOCKER_CONFIG). With the CLI, pulling it first (docker pull) also works." ;;
            esac
            [ -s "$IMAGE_SYFT_LOG" ] && tail -5 "$IMAGE_SYFT_LOG" >&2
            rm -f "$IMAGE_SYFT_LOG" ${IMAGE_SOURCE_TMPL:+"$IMAGE_SOURCE_TMPL"} ${IMAGE_SOURCE_JSON:+"$IMAGE_SOURCE_JSON"}
            exit 1
        fi
        rm -f "$IMAGE_SYFT_LOG"
        # Pin the later reads of this image (Trivy's license scan, the file
        # view) to the digest syft read, so a tag that moves meanwhile cannot
        # give them another image. An archive is read as it is. With no digest
        # the reference is read as given, and the manifest records it as null.
        _img_socket=false; [ -S /var/run/docker.sock ] && _img_socket=true
        ER_INPUT_IMAGE="$(bash "$LIBDIR/image-digest.sh" "$IMAGE_SOURCE_JSON" "$TARGET_IMAGE" "$_img_socket" 2>/dev/null)" || ER_INPUT_IMAGE=""
        rm -f ${IMAGE_SOURCE_TMPL:+"$IMAGE_SOURCE_TMPL"} ${IMAGE_SOURCE_JSON:+"$IMAGE_SOURCE_JSON"}
        IMAGE_READ_TARGET="$TARGET_IMAGE"
        _img_json="${ER_INPUT_IMAGE:-"{}"}"
        _img_pinned="$(jq -r '.pinned_reference // empty' <<<"$_img_json" 2>/dev/null)" || _img_pinned=""
        case "$(jq -r '.source // empty' <<<"$_img_json" 2>/dev/null)" in
            registry|daemon|unknown)
                if [ -n "$_img_pinned" ]; then
                    IMAGE_READ_TARGET="$_img_pinned"
                    echo "[1/2] image digest: $(jq -r '.digest + (if .platform then " (" + .platform + ")" else "" end)' <<<"$ER_INPUT_IMAGE"); later reads use $IMAGE_READ_TARGET"
                elif [ -n "$IMAGE_SOURCE_JSON" ]; then
                    echo "[WARN] could not resolve the digest of $TARGET_IMAGE (no repository digest for this name, as for an image built locally, or a name that is not a plain image name): later reads use the reference as given." >&2
                fi ;;
        esac
        export ER_INPUT_IMAGE
        ;;

    BINARY)
        if [ -z "$TARGET_FILE" ] || [ ! -f "$TARGET_FILE" ]; then echo "[ERROR] TARGET_FILE not found: $TARGET_FILE"; exit 1; fi
        echo "[1/2] syft: binary $TARGET_FILE"
        # syft's own messages (an update check that cannot reach the network,
        # for one) go to a log, not into the SBOM it writes on standard output.
        BINARY_SYFT_LOG=$(mktemp)
        if ! syft "file:$TARGET_FILE" -o "cyclonedx-json@$CDX_SPEC_VERSION" > "$OUTPUT_FILE" 2>"$BINARY_SYFT_LOG"; then
            echo "[WARN] syft binary scan failed; emitting minimal SBOM."
            [ -s "$BINARY_SYFT_LOG" ] && tail -5 "$BINARY_SYFT_LOG" >&2
            FILE_INFO=$(file "$TARGET_FILE")
            cat > "$OUTPUT_FILE" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "$CDX_SPEC_VERSION",
  "version": 1,
  "metadata": { "component": { "type": "file", "name": "$(basename "$TARGET_FILE")", "version": "$PROJECT_VERSION", "description": "$FILE_INFO" } },
  "components": []
}
EOF
        fi
        rm -f "$BINARY_SYFT_LOG"
        ;;

    ROOTFS)
        if [ -z "$TARGET_DIR" ] || [ ! -d "$TARGET_DIR" ]; then echo "[ERROR] TARGET_DIR not found: $TARGET_DIR"; exit 1; fi
        echo "[1/2] syft: RootFS $TARGET_DIR"
        # Skip pseudo filesystems: a live host / mounted via `--ui --mount /`
        # brings /proc, /sys, /dev and /run along (docker bind mounts recurse
        # into submounts), and walking them is slow and can error out. They
        # never hold packages, so excluding them is safe for extracted
        # rootfs trees too.
        # Capture stderr to a temp file instead of discarding it: on failure the
        # cause (permission denied, unreadable path, ...) is otherwise invisible.
        # It must stay off stdout, which carries the SBOM JSON on success.
        ROOTFS_SYFT_LOG=$(mktemp)
        if ! syft "dir:$TARGET_DIR" -o "cyclonedx-json@$CDX_SPEC_VERSION" \
                --exclude './proc/**' --exclude './sys/**' \
                --exclude './dev/**' --exclude './run/**' \
                > "$OUTPUT_FILE" 2>"$ROOTFS_SYFT_LOG"; then
            echo "[ERROR] syft directory scan failed."
            [ -s "$ROOTFS_SYFT_LOG" ] && cat "$ROOTFS_SYFT_LOG" >&2
            rm -f "$ROOTFS_SYFT_LOG"
            exit 1
        fi
        rm -f "$ROOTFS_SYFT_LOG"
        ;;

    FIRMWARE)
        # TARGET_FILE may name a folder: a tree already unpacked, such as a root
        # filesystem with no package database (scan-firmware.sh copies it).
        if [ -z "$TARGET_FILE" ] || { [ ! -f "$TARGET_FILE" ] && [ ! -d "$TARGET_FILE" ]; }; then echo "[ERROR] TARGET_FILE not found: $TARGET_FILE"; exit 1; fi
        echo "[1/2] firmware: unpack + identify $TARGET_FILE"
        # scan-firmware.sh is best-effort (always emits a valid SBOM); the empty-file
        # guard below still catches a hard failure.
        # OUT_PREFIX names the file tree and snapshot it writes. Firmware
        # binaries carry a CPE but no package purl, so Trivy alone matches
        # nothing; their CVEs come from match-cpe-index.sh, run below once every
        # CPE enrichment step has run.
        bash "$LIBDIR/scan-firmware.sh" "$TARGET_FILE" "$OUTPUT_FILE" "$PROJECT_VERSION" "$OUT_PREFIX"
        ;;

    AIBOM)
        # AI model SBOM: the OWASP AIBOM Generator (opt-in bomlens-aibom image)
        # reads the HuggingFace model card and emits CycloneDX 1.7. The common
        # post-processing runs on it unchanged (normalize keeps the 1.7 specVersion
        # and the modelCard; notice/risk cover the model & dataset licenses). It
        # sets its own metadata.component, so no stamp pass is needed below.
        #
        # MODEL_ID is the only variable read here by name. HF_TOKEN, when the
        # caller passes one in, is consumed implicitly by huggingface_hub inside
        # the generator and the enrich step — it looks unused from this file, but
        # removing it from the environment would break private/gated models.
        if [ -z "$MODEL_ID" ]; then echo "[ERROR] MODEL_ID required for AIBOM mode."; exit 1; fi
        echo "[1/2] aibom: generate AI SBOM for $MODEL_ID"
        bash "$LIBDIR/scan-aibom.sh" "$MODEL_ID" "$OUTPUT_FILE" "$PROJECT_VERSION"
        # Enrich the generated ML-BOM before normalize/validate: LFS SHA-256
        # hashes and openness signals from the HuggingFace API, plus model
        # pedigree/performance metrics harvested from cdxgen -t ai when present.
        # Best-effort — a missing network or tool just leaves those fields unfilled,
        # and the G7 conformance step then reports them honestly as not present.
        run_optional_step enrich-aibom bash "$LIBDIR/enrich-aibom.sh" "$OUTPUT_FILE" "$MODEL_ID"
        # --verify-weights (opt-in, off by default): download only the
        # pickle-format weight files (.bin/.pt/.pth/.ckpt) and run the same
        # local picklescan verification MODE=MODELFILE runs, instead of only
        # trusting the Hub's own scan. Real network + disk cost, unlike the
        # metadata-only enrich-aibom.sh step above, which is why it needs an
        # explicit opt-in. Best-effort: a network failure or missing
        # huggingface_hub degrades to "not verified" rather than failing the scan.
        if [ "${VERIFY_MODEL_WEIGHTS:-false}" = "true" ]; then
            run_optional_step verify-weights python3 "$LIBDIR/verify-model-weights.py" \
                "$OUTPUT_FILE" "$MODEL_ID"
        fi
        ;;

    DATASET)
        # A published research dataset, from a Figshare item reference. The fields
        # an SBOM wants are fields there rather than prose in a model card, and the
        # public item endpoint needs no account, so this is one stdlib script in the
        # base image: no generator, no opt-in image, and it works for whoever can
        # reach the API. It writes its own metadata.component, like AIBOM.
        # A HuggingFace dataset (hf:<owner>/<name>, as scan-sbom.sh and the web
        # UI normalize it) is read the way a model scan reads each dataset its
        # card names, sources included, by the same module.
        if [ -z "$DATASET_REF" ]; then echo "[ERROR] DATASET_REF required for DATASET mode."; exit 1; fi
        case "$DATASET_REF" in
            hf:*)
                echo "[1/2] huggingface: describe dataset ${DATASET_REF#hf:}"
                python3 "$LIBDIR/scan-hf-dataset.py" "$DATASET_REF" "$OUTPUT_FILE" "$PROJECT_VERSION" ;;
            *)
                echo "[1/2] figshare: describe $DATASET_REF"
                python3 "$LIBDIR/scan-figshare.py" "$DATASET_REF" "$OUTPUT_FILE" "$PROJECT_VERSION" ;;
        esac
        ;;

    MODELFILE)
        # AI model SBOM built from a model FILE rather than a HuggingFace id: the
        # file's own header is the only source. No network, no generator image —
        # identify-model-file.py is stdlib-only and ships in the base image, so
        # this path works air-gapped and on a model that was never published.
        #
        # What it can fill depends on the format (GGUF carries a name, a license
        # and an architecture; safetensors usually carries only tensor shapes),
        # and a field the file does not declare is left empty rather than
        # guessed. A file it cannot identify is refused (exit 3) instead of
        # becoming a model component nobody could read.
        if [ -z "$TARGET_FILE" ] || [ ! -f "$TARGET_FILE" ]; then echo "[ERROR] TARGET_FILE not found: $TARGET_FILE"; exit 1; fi
        echo "[1/2] modelfile: read $(basename "$TARGET_FILE")"
        if ! python3 "$LIBDIR/identify-model-file.py" \
                "$TARGET_FILE" "$OUTPUT_FILE" "$PROJECT_VERSION" "$PROJECT_NAME"; then
            echo "[ERROR] could not identify the model file: $(basename "$TARGET_FILE")"
            exit 1
        fi
        # Does loading this file run code? pickle weights do, and no Hub scan
        # result exists for a file that was never published, so the answer has
        # to be produced here. Best-effort: a failure leaves the property unset
        # and the risk assessment then has no security axis at all, which reads
        # as "not scanned" rather than as safe.
        run_optional_step model-security python3 "$LIBDIR/scan-model-file-security.py" \
            "$OUTPUT_FILE" "$TARGET_FILE"
        ;;

    AIDECLARE)
        # A model with no hub repository and no file to read yet: the
        # publisher's declaration is the input. declare-ai-model.py writes the
        # model component and reads only what the declaration points at on the
        # hub (its base models' lineage, its datasets and their sources), so the
        # assessment and G7 run as for any AI scan. The declared values
        # themselves go into the SPDX 3.0.1 document below, not into this SBOM.
        if [ -z "${AI_DECLARATION_FILE:-}" ] || [ ! -f "$AI_DECLARATION_FILE" ]; then
            echo "[ERROR] AI_DECLARATION_FILE required for AIDECLARE mode."; exit 1
        fi
        echo "[1/2] declaration: describe $PROJECT_NAME $PROJECT_VERSION"
        if ! python3 "$LIBDIR/declare-ai-model.py" "$AI_DECLARATION_FILE" "$OUTPUT_FILE" \
                "$PROJECT_NAME" "$PROJECT_VERSION"; then
            echo "[ERROR] The AI declaration could not be read (reason above). Fix the file and run again."
            exit 1
        fi
        ;;

    MERGE)
        # Combine several already-generated CycloneDX SBOMs into one (e.g. a
        # server's OS rootfs layer + application layer + static-link layer).
        # MERGE_FILES is a space-separated list of container paths (read-only
        # mounts set up by scan-sbom.sh). merge-sbom.sh writes its own root
        # component from PROJECT_NAME/VERSION, so no stamp pass is needed below.
        if [ -z "$MERGE_FILES" ]; then echo "[ERROR] MERGE_FILES required for MERGE mode."; exit 1; fi
        echo "[1/2] Merging layered SBOMs -> $OUTPUT_FILE"
        # shellcheck disable=SC2086
        if ! bash "$LIBDIR/merge-sbom.sh" "$OUTPUT_FILE" "$PROJECT_NAME" "$PROJECT_VERSION" $MERGE_FILES; then
            echo "[ERROR] SBOM merge failed."; exit 1
        fi
        ;;

    POSTPROCESS)
        # SBOM was already generated by a cdxgen language image (scan-sbom.sh,
        # or a caller that ran stage 1 from the execution plan).
        echo "[1/2] Post-processing existing SBOM: $OUTPUT_FILE"
        # The input fingerprint of stage 1, for the result manifest's generate
        # step (input-fingerprint.sh): computed again from the source with
        # this image's code, and compared with the plan's when this run
        # follows one. Read before the fallback below; it never stops the run.
        # shellcheck source=docker/lib/input-fingerprint.sh
        . "$LIBDIR/input-fingerprint.sh"
        ER_INPUT_FINGERPRINT="$(input_fingerprint_for_run "${HOST_OUTPUT_DIR:-.}/bomlens-plan.json" "$OUTPUT_FILE" \
            "${SOURCE_ROOT:-/src}" "${HOST_OUTPUT_DIR:-.}" 2>/dev/null)" || ER_INPUT_FINGERPRINT=""
        # A stage 1 that exited 0 can still have come out short: a step that
        # failed inside build-prep.sh, or the generator's own fallback, is only
        # recorded in the SBOM. Read before stage 2 adds its own records. The
        # label of a post-process step is left out: a reused SBOM carries the
        # post-process record of the run that left it, not of stage 1.
        ER_STAGE1_DEGRADED=false
        if [ -s "$OUTPUT_FILE" ] && jq -e --arg pp "$ER_POSTPROCESS_STEPS" "$ER_JQ_POSTPROCESS"'
               any(.metadata.properties[]?; (.name == "bomlens:pipeline-step-failed" and ((.value | strings | er_postprocess) | not))
                   or .name == "bomlens:sbom-tool-degraded")' \
               "$OUTPUT_FILE" >/dev/null 2>&1; then
            ER_STAGE1_DEGRADED=true
        fi
        # Static detection (scan-sbom.sh --detection static, or auto when a lock
        # file covers the tree): the CLI skipped stage 1 and this step reads the
        # lock file itself. A failure ends the run, and the CLI then builds.
        if [ "${BOMLENS_DETECTION:-}" = "static" ] && [ ! -s "$OUTPUT_FILE" ]; then
            echo "[1/2] static: source dir ${SOURCE_ROOT:-/src} (lock file, no build)"
            if ! generate_sbom_static "${SOURCE_ROOT:-/src}" "$OUTPUT_FILE"; then
                echo "[ERROR] static detection failed (the lock file could not be read into an SBOM)."
                exit 3
            fi
            mark_sbom_detection "$OUTPUT_FILE" static "${BOMLENS_DETECTION_WHY:-}"
            mark_sbom_excluded "$OUTPUT_FILE" "${SOURCE_ROOT:-/src}"
        fi
        # A caller that ran stage 1 from the execution plan passes its exit
        # code. When stage 1 failed or left no SBOM, the manifest-only syft
        # scan takes its place, the same fallback the CLI runs, and the SBOM
        # carries the reason (bomlens:sbom-tool-degraded).
        if [ -n "${BOMLENS_STAGE1_EXIT:-}" ] && { [ "$BOMLENS_STAGE1_EXIT" != "0" ] || [ ! -s "$OUTPUT_FILE" ]; }; then
            _s1_log="${BOMLENS_STAGE1_LOG:-}"
            case "$_s1_log" in ''|*/*|.*) _s1_log="" ;; esac
            # A caller that already classified the failure (the CLI does, with
            # the same stage1_fail_reason) passes the reason itself. One that
            # never ran stage 1 (an unsupported plan) passes cdxgen-unavailable,
            # or exit code 127.
            case "${BOMLENS_STAGE1_REASON:-}" in
                oom|disk-space|network|cdxgen-crash|cdxgen-unavailable) _s1_reason="$BOMLENS_STAGE1_REASON" ;;
                *) _s1_reason="$(stage1_fail_reason "${BOMLENS_STAGE1_OOM:-}" "${_s1_log:+$HOST_OUTPUT_DIR/$_s1_log}" "$BOMLENS_STAGE1_EXIT")" ;;
            esac
            # The CLI prints its own guidance for this, before and after.
            [ -n "${_BOMLENS_CLI_FALLBACK:-}" ] || \
                echo "[WARN] stage 1 (cdxgen) did not produce an SBOM (exit ${BOMLENS_STAGE1_EXIT}, ${_s1_reason}); falling back to a manifest-only scan (direct dependencies only)."
            rm -f "$OUTPUT_FILE"
            read -ra _s1_exclude <<< "$(non_shipped_syft_args)"
            if ! syft "dir:${SOURCE_ROOT:-/src}" "${_s1_exclude[@]}" -o "cyclonedx-json@$CDX_SPEC_VERSION" > "$OUTPUT_FILE" 2>/dev/null \
               || ! apply_node_fallback_quality_gate "$OUTPUT_FILE" "${SOURCE_ROOT:-/src}" 2; then
                rm -f "$OUTPUT_FILE"
                [ -n "${_BOMLENS_CLI_FALLBACK:-}" ] || \
                    echo "[ERROR] SBOM generation failed (stage 1), and the manifest-only fallback also failed or was discarded."
                exit 1
            fi
            mark_sbom_degraded "$OUTPUT_FILE" "$_s1_reason"
            mark_sbom_excluded "$OUTPUT_FILE" "${SOURCE_ROOT:-/src}"
        fi
        if [ ! -s "$OUTPUT_FILE" ]; then
            echo "[ERROR] SBOM not found for post-processing: $OUTPUT_FILE"
            echo "        (stage 1 — cdxgen language image — may have failed)"
            exit 1
        fi
        ;;

    ANALYZE)
        # A Yocto build directory that published no SPDX document at all. There is
        # no supplier document to validate or convert here — the build's own
        # records (the image package manifest, license.manifest, cve-check) are
        # read into the same CycloneDX the SPDX path produces, and the rest of the
        # pipeline continues unchanged. Set by scan-sbom.sh / server.py only after
        # they have established the folder is a build directory with no SBOM.
        if [ -n "${YOCTO_BUILD_DIR:-}" ] && [ -z "$ANALYZE_SBOM" ]; then
            if [ ! -d "$YOCTO_BUILD_DIR" ]; then
                echo "[ERROR] YOCTO_BUILD_DIR not found: $YOCTO_BUILD_DIR"; exit 1
            fi
            echo "[1/2] Reading the Yocto build's own records (no SPDX in this build)..."
            if ! python3 "$LIBDIR/parse-yocto-manifests.py" \
                    "$YOCTO_BUILD_DIR" "$OUTPUT_FILE" "$OUT_PREFIX"; then
                echo "[ERROR] this build directory holds no image package manifest to read."
                exit 1
            fi
            YOCTO_SBOM=true
        else
        # Supplier-submitted SBOM (CycloneDX or SPDX). Validate the ORIGINAL for
        # conformance, then convert to CycloneDX so the common pipeline is reused.
        if [ -z "$ANALYZE_SBOM" ] || [ ! -f "$ANALYZE_SBOM" ]; then
            echo "[ERROR] ANALYZE_SBOM not found: $ANALYZE_SBOM"; exit 1
        fi
        # An SPDX 2.x archive is not a document: it is a bundle of them, and the
        # image document inside is an index listing one package. Measuring either
        # against the submission criteria would report an unparseable or almost
        # empty SBOM for something we read 36 packages out of, so the archive is
        # not judged; the SBOM read out of it is, below (YOCTO_FROM_BUILD).
        case "$ANALYZE_SBOM" in
            *.spdx.tar.zst) YOCTO_ARCHIVE=true ;;
            *)              YOCTO_ARCHIVE=false ;;
        esac
        if [ "$YOCTO_ARCHIVE" = "false" ]; then
        # Ask a package repository whether each identifier names something that
        # exists. Opt-in (PURL_RESOLVE=true) because it is the only step here
        # that needs the network, and it runs BEFORE the conformance check so
        # the report can carry its answer on an advisory row. The submitted
        # document is not touched; the answer lands in a sidecar.
        if [ "${PURL_RESOLVE:-false}" = "true" ]; then
            echo "[analyze] Looking up each PURL in its package repository..."
            run_optional_step resolve-purl python3 "$LIBDIR/resolve-purl.py" \
                "$ANALYZE_SBOM" "$OUT_PREFIX"
        fi
        if [ "$YOCTO_FROM_BUILD" != "true" ]; then
        echo "[1/2] Validating supplier SBOM (conformance, original input)..."
        # Conformance never aborts the pipeline (best-effort report).
        run_optional_step conformance bash "$LIBDIR/validate-sbom.sh" "$ANALYZE_SBOM" "$OUT_PREFIX" "$PROJECT_NAME"
        fi
        # Describe the document the supplier actually sent, before conversion
        # rewrites it: the format and version it was written in, the tool that
        # produced it, when, and on whose authority. The result screens otherwise
        # only ever describe the CycloneDX conversion. Best-effort.
        run_optional_step describe-input python3 "$LIBDIR/describe-input-sbom.py" \
            "$ANALYZE_SBOM" "${OUT_PREFIX}_input.json" "$(basename "$ANALYZE_SBOM")"
        fi
        echo "[1/2] Converting supplier SBOM to CycloneDX..."
        # Yocto SPDX 3.0 takes a dedicated path. syft converts these documents but
        # drops every vulnerability and lists source FILES as components (measured:
        # 1000 components, 872 of them files, 0 vulnerabilities — against 35 installed
        # packages and 3188 vulnerabilities actually in the document). The parser
        # reads the installed set and the VEX judgements Yocto recorded at build time.
        # rc=3 means "not a Yocto document" and is the normal path for every other
        # supplier SBOM; any other non-zero rc is a real failure that still falls back
        # so a parser bug cannot block a scan.
        YOCTO_RC=3
        if command -v python3 >/dev/null 2>&1 && [ -f "$LIBDIR/parse-yocto-spdx.py" ]; then
            YOCTO_RC=0
            python3 "$LIBDIR/parse-yocto-spdx.py" "$ANALYZE_SBOM" "$OUTPUT_FILE" "$OUT_PREFIX" \
                || YOCTO_RC=$?
        fi
        if [ "$YOCTO_RC" != 0 ] && [ "$YOCTO_ARCHIVE" = "true" ]; then
            # An archive is never CycloneDX or SPDX text, so the generic converter
            # has nothing to try; it would only report an unrecognized format and
            # bury the reason the archive could not be read (zstd missing, or a
            # bundle with no image document in it).
            echo "[ERROR] could not read the Yocto SPDX archive: $(basename "$ANALYZE_SBOM")"
            echo "        See the [yocto-spdx] message above for what stopped it."
            exit 1
        fi
        if [ "$YOCTO_RC" = 0 ]; then
            YOCTO_SBOM=true
            [ "$YOCTO_ARCHIVE" = "true" ] && YOCTO_CPE_MATCH=true
        fi
        if [ "$YOCTO_RC" != 0 ]; then
            [ "$YOCTO_RC" = 3 ] || echo "[analyze] WARN: Yocto SPDX parser failed (rc=$YOCTO_RC); using the generic converter." >&2
            if ! bash "$LIBDIR/convert-to-cdx.sh" "$ANALYZE_SBOM" "$OUTPUT_FILE"; then
                echo "[ERROR] could not convert supplier SBOM to CycloneDX."; exit 1
            fi
        fi
        fi
        ;;

    *)
        echo "[ERROR] Unknown MODE: $SCAN_MODE (expected SOURCE/IMAGE/BINARY/ROOTFS/FIRMWARE/AIBOM/MODELFILE/DATASET/AIDECLARE/ANALYZE/MERGE/POSTPROCESS/UI/DIFF)"
        exit 1
        ;;
esac

# The JSON copy of a CycloneDX XML input (sbom-detect.sh) is scratch, not a result.
rm -f "$(dirname "$OUTPUT_FILE")"/.sbom-xml.*.json* "$(dirname "$OUT_PREFIX")"/.sbom-xml.*.json* 2>/dev/null || true
if [ ! -s "$OUTPUT_FILE" ]; then echo "[ERROR] SBOM file is empty: $OUTPUT_FILE"; exit 1; fi
echo "[INFO] SBOM ready: $OUTPUT_FILE"
_gen_count="$(jq '[.components[]?] | length' "$OUTPUT_FILE" 2>/dev/null || echo 0)"
_gen_degraded="$(jq -r '[.metadata.properties[]? | select(.name == "bomlens:sbom-tool-degraded") | .value] | first // empty' "$OUTPUT_FILE" 2>/dev/null)"
# A Poetry project with no poetry.lock is scanned from its exact pins only
# (build-prep.sh); when it also has ranged or table dependencies those are not
# in the SBOM, which is a partial result and is recorded as one.
_gen_poetry_partial=""; _gen_poetry_graph_failed=""
case "$SCAN_MODE" in SOURCE|POSTPROCESS)
_gen_poetry_partial="$(jq -r 'any(.metadata.properties[]?; .name == "bomlens:prep-step-applied" and .value == "poetry-requirements-partial")' "$OUTPUT_FILE" 2>/dev/null)"
# The pins' own dependencies are resolved by a second cdxgen run
# (poetry-graph); when it failed (no network, for one) they are missing too.
_gen_poetry_graph_failed="$(jq -r 'any(.metadata.properties[]?; .name == "bomlens:pipeline-step-failed" and .value == "poetry-graph")' "$OUTPUT_FILE" 2>/dev/null)"
;; esac
# A package cdxgen saw but could not name (build-prep.sh drops it): said in
# generate's detail and counted as unresolved, whatever the status.
_gen_unnamed="$(jq -r '[.metadata.properties[]? | select(.name == "bomlens:unnamed-packages-dropped") | .value] | first // empty' "$OUTPUT_FILE" 2>/dev/null)"
case "$_gen_unnamed" in ''|*[!0-9]*) _gen_unnamed="" ;; esac
_gen_counts="{\"components\":${_gen_count:-0}${_gen_unnamed:+,\"unresolved\":$_gen_unnamed}}"
_gen_unnamed_detail="${_gen_unnamed:+$_gen_unnamed package(s) cdxgen could not name were left out (pkg:pypi/unknown@latest)}"
if [ -n "$_gen_degraded" ]; then
    er_record generate degraded fallback "$_gen_degraded" "$ER_PHASE_STARTED" "" "$_gen_counts"
elif [ "$_gen_poetry_partial" = "true" ] || [ "$_gen_poetry_graph_failed" = "true" ]; then
    _gen_poetry_detail="Poetry project with no poetry.lock:"
    [ "$_gen_poetry_partial" = "true" ] && _gen_poetry_detail="$_gen_poetry_detail only exact pins resolved, ranged and table dependencies are missing;"
    [ "$_gen_poetry_graph_failed" = "true" ] && _gen_poetry_detail="$_gen_poetry_detail the dependencies of the pins could not be resolved (poetry-graph failed);"
    _gen_poetry_detail="${_gen_poetry_detail%;}"
    er_record generate degraded fallback "$_gen_poetry_detail${_gen_unnamed_detail:+; $_gen_unnamed_detail}" "$ER_PHASE_STARTED" "" "$_gen_counts"
else
    er_record generate ok "" "${_gen_unnamed_detail}" "$ER_PHASE_STARTED" "" "$_gen_counts"
fi
er_phase_end

# Debian packages of an image or a root filesystem take their licenses from
# Trivy, which reads the copyright files syft leaves as a hash
# (os-licenses.sh). Recorded as its own step, after generate. BOMLENS_OS_LICENSES=false turns it off (the second read
# of the image costs time); any hash is then still dropped. When Trivy cannot
# read the target, the hashes are dropped and the step is degraded.
case "$SCAN_MODE" in
    IMAGE|ROOTFS)
        _osl_target="${IMAGE_READ_TARGET:-${TARGET_IMAGE:-}}"; [ "$SCAN_MODE" = ROOTFS ] && _osl_target="$TARGET_DIR"
        _osl_started="$(er_now)"; _osl_rc=0
        if [ "${BOMLENS_OS_LICENSES:-true}" = "false" ]; then
            bash "$LIBDIR/os-licenses.sh" "$OUTPUT_FILE" "$SCAN_MODE" "$_osl_target" >/dev/null || true
            er_record os-licenses disabled
        else
            _osl_out="$(bash "$LIBDIR/os-licenses.sh" "$OUTPUT_FILE" "$SCAN_MODE" "$_osl_target")" || _osl_rc=$?
            _osl_counts="$(printf '%s' "$_osl_out" | awk 'NF==2 {printf "{\"replaced\":%d,\"hashes_dropped\":%d}", $1, $2}')"
            case "$_osl_rc" in
                0)
                    [ -n "$_osl_counts" ] && echo "[os-licenses] $(printf '%s' "$_osl_out" | awk '{print $1" Debian package(s) from Trivy, "$2" with a file hash cleaned"}')"
                    er_record os-licenses ok "" "" "$_osl_started" "" "$_osl_counts" ;;
                1)
                    echo "[WARN] Debian package licenses: Trivy could not read the target; syft's licenses are kept, less any file hash." >&2
                    er_record os-licenses degraded unavailable "Trivy's license scan could not read the target" "$_osl_started" "" "$_osl_counts" ;;
                3)
                    echo "[WARN] Debian package licenses: Trivy is not installed; syft's licenses are kept, less any file hash." >&2
                    er_record os-licenses skipped not_installed "" "$_osl_started" "" "$_osl_counts" ;;
                4)
                    echo "[WARN] Debian package licenses: Trivy read the target but gave no Debian package a license; syft's are kept, less any file hash." >&2
                    er_record os-licenses degraded unavailable "Trivy gave no Debian package a license" "$_osl_started" "" "$_osl_counts" ;;
                *)
                    echo "[WARN] Debian package licenses: the step failed; the SBOM is left as syft wrote it." >&2
                    er_record os-licenses failed failed "" "$_osl_started" ;;
            esac
        fi ;;
esac

# Warn (don't fail) when the SBOM has no components. A genuine no-dependency
# project can legitimately be empty, but more often this means the scan saw
# nothing — a missing lockfile or an empty/unshared source mount.
if command -v jq >/dev/null 2>&1; then
    COMP_COUNT=$(jq '[.components[]?] | length' "$OUTPUT_FILE" 2>/dev/null || echo 0)
    if [ "${COMP_COUNT:-0}" -eq 0 ]; then
        echo "[WARN] SBOM has 0 components — the scan may have found nothing (missing lockfile or empty source)."
        # The npm production set was resolved, so the project declares no
        # runtime dependencies; its development-only ones are left out.
        if jq -e '(.metadata.properties // []) | any(.name == "bomlens:prep-step-applied" and .value == "npm-production-set")' "$OUTPUT_FILE" >/dev/null 2>&1; then
            echo "       The lock file was read: this project has no runtime dependencies, and its development-only dependencies are left out."
            echo "       Set BOMLENS_NODE_FULL_GRAPH=1 to list them as well."
        fi
        # A directory --target that is not itself a root filesystem but
        # has one a level or two below it (a delivery folder wrapping the
        # actual rootfs) is a common way this ends up empty -- cdxgen has
        # nothing to read there. scan-sbom.sh already found this on the host
        # (nested_rootfs_hint) and names it here only now that the scan is
        # confirmed empty, not on sight of the folder alone: a source repo
        # that happens to hold a rootfs-shaped fixture, but still resolves
        # real components, must never see this note. Validated the same way
        # as BOMLENS_RUN_INPUT: an unexpected character degrades to no note,
        # never to an unsafe value echoed verbatim.
        if [ -n "${NESTED_ROOTFS_HINT:-}" ] \
           && printf '%s' "$NESTED_ROOTFS_HINT" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._/ -]*$' \
           && ! printf '%s' "$NESTED_ROOTFS_HINT" | grep -q '\.\.'; then
            echo "       $NESTED_ROOTFS_HINT (inside the scanned folder) looks like a root filesystem."
            echo "       If that folder is the actual delivery, re-run with --target pointed at it directly."
        fi
    fi
fi

# ========================================================
# Source-tree enrichment (vendored OSS, CocoaPods) below only applies to a real
# source scan: the CLI source scan (MODE=POSTPROCESS, tree at /src) or the web-UI
# source scan (MODE=SOURCE, SOURCE_ROOT). Every other mode (ANALYZE/MERGE/IMAGE/
# BINARY/ROOTFS/FIRMWARE/AIBOM) may still have an unrelated tree mounted at /src —
# the web UI mounts its host dir there for EVERY mode, so an ANALYZE of a supplier
# SBOM would otherwise scan the server's own working tree and merge stray
# components into the result. Gate both steps on the source-scan modes, mirroring
# the source-file-tree gate below (case "$SCAN_MODE").
case "$SCAN_MODE" in
    SOURCE|POSTPROCESS) SOURCE_SCAN=true ;;
    *) SOURCE_SCAN=false ;;
esac

# ========================================================
# Vendored open source (opt-in, SCANOSS) — only meaningful for a source tree.
# Runs for both the CLI source scan (MODE=POSTPROCESS, tree mounted at /src) and
# the web-UI source scan (SOURCE mode, SOURCE_ROOT). When enabled, identify the
# open source copied straight into the sources and merge it into the SBOM before
# stamping/normalizing, so the PURL->CPE fix and the security scan pick it up.
# When disabled, suggest-vendored.sh decides whether to nudge the user (C/C++,
# no package manager, near-empty scan) — off-by-default discovery.
# ========================================================
VENDORED_SRC="${SOURCE_ROOT:-/src}"
if [ "$SOURCE_SCAN" = "true" ] && [ "${IDENTIFY_VENDORED:-false}" = "true" ] && [ -d "$VENDORED_SRC" ]; then
    echo "[INFO] Identifying vendored open source (SCANOSS)..."
    VEND_SBOM="${OUT_PREFIX}_vendored.cdx.json"
    _vend_started="$(er_now)"
    _vend_status=failed
    if bash "$LIBDIR/identify-vendored.sh" "$VENDORED_SRC" "$VEND_SBOM" "$PROJECT_VERSION"; then
        _vend_status=ok
        VEND_N=$(jq '[.components[]?] | length' "$VEND_SBOM" 2>/dev/null || echo 0)
        # Reconcile against the package-manager scan before merging: drop vendored
        # matches whose name a cdxgen/syft component already carries (see
        # reconcile-vendored.sh). Prevents duplicate pkg:github components / false
        # CVEs when this option is enabled on a normal managed project.
        if [ "${VEND_N:-0}" -gt 0 ]; then
            DROPPED_N=$(bash "$LIBDIR/reconcile-vendored.sh" "$OUTPUT_FILE" "$VEND_SBOM")
            [ "${DROPPED_N:-0}" -gt 0 ] && echo "[INFO] vendored: reconciled ${DROPPED_N} match(es) already covered by the package-manager scan."
            VEND_N=$(jq '[.components[]?] | length' "$VEND_SBOM" 2>/dev/null || echo 0)
        fi
        if [ "${VEND_N:-0}" -gt 0 ]; then
            echo "[INFO] vendored components identified: $VEND_N — merging into SBOM."
            if bash "$LIBDIR/merge-sbom.sh" "${OUTPUT_FILE}.merged" "$PROJECT_NAME" "$PROJECT_VERSION" "$OUTPUT_FILE" "$VEND_SBOM"; then
                mv "${OUTPUT_FILE}.merged" "$OUTPUT_FILE"
            else
                echo "[WARN] merge of vendored components failed; keeping the original SBOM." >&2
                _vend_status=failed
                rm -f "${OUTPUT_FILE}.merged"
            fi
        else
            echo "[INFO] no new vendored open source to add (after reconciliation)."
        fi
    fi
    er_record vendored "$_vend_status" "$([ "$_vend_status" = failed ] && echo failed)" "" "$_vend_started"
elif [ "$SOURCE_SCAN" = "true" ] && [ "${IDENTIFY_VENDORED:-false}" = "true" ]; then
    er_record vendored skipped no_input "no source tree at $VENDORED_SRC"
elif [ "$SOURCE_SCAN" = "true" ]; then
    er_record vendored disabled
    if [ -d "$VENDORED_SRC" ]; then
        run_optional_step suggest-vendored bash "$LIBDIR/suggest-vendored.sh" "$OUTPUT_FILE" "$VENDORED_SRC"
    fi
fi

# ========================================================
# CocoaPods (iOS) — cdxgen's swift language image has no `pod` CLI, so a CocoaPods
# project comes back with zero components. syft parses Podfile.lock offline (no `pod`,
# no network); fill the gap here for the CLI source scan (/src) and the web-UI source
# scan (SOURCE_ROOT), and merge before normalize/security so CVE/notice generation picks
# the pods up. No-op when the main scan already carries pkg:cocoapods components (e.g. a
# future pod-capable image), so this never double-counts.
# ========================================================
COCOA_SRC="${SOURCE_ROOT:-/src}"
if [ "$SOURCE_SCAN" = "true" ] && [ -d "$COCOA_SRC" ] \
   && find "$COCOA_SRC" -type f -name Podfile.lock -not -path '*/Pods/*' 2>/dev/null | grep -q .; then
    HAS_COCOA=$(jq '[.components[]? | select((.purl // "") | startswith("pkg:cocoapods/"))] | length' "$OUTPUT_FILE" 2>/dev/null || echo 0)
    if [ "${HAS_COCOA:-0}" -eq 0 ]; then
        echo "[INFO] Identifying CocoaPods dependencies from Podfile.lock (syft)..."
        COCOA_SBOM="${OUT_PREFIX}_cocoapods.cdx.json"
        _cocoa_started="$(er_now)"
        _cocoa_status=failed
        if bash "$LIBDIR/identify-cocoapods.sh" "$COCOA_SRC" "$COCOA_SBOM" "$PROJECT_VERSION"; then
            _cocoa_status=ok
            COCOA_N=$(jq '[.components[]?] | length' "$COCOA_SBOM" 2>/dev/null || echo 0)
            if [ "${COCOA_N:-0}" -gt 0 ]; then
                echo "[INFO] CocoaPods components identified: $COCOA_N — merging into SBOM."
                if bash "$LIBDIR/merge-sbom.sh" "${OUTPUT_FILE}.merged" "$PROJECT_NAME" "$PROJECT_VERSION" "$OUTPUT_FILE" "$COCOA_SBOM"; then
                    mv "${OUTPUT_FILE}.merged" "$OUTPUT_FILE"
                else
                    echo "[WARN] merge of CocoaPods components failed; keeping the original SBOM." >&2
                    _cocoa_status=failed
                    rm -f "${OUTPUT_FILE}.merged"
                fi
            fi
        fi
        er_record cocoapods "$_cocoa_status" "$([ "$_cocoa_status" = failed ] && echo failed)" "" "$_cocoa_started"
    fi
fi

# ========================================================
# conda environment.yml dependencies. identify-conda.py already ran in
# build-prep.sh (stage 1, before cdxgen), not here: whether cdxgen's python
# cataloger gets excluded has to be decided before cdxgen runs, and only when
# the parse actually produced something (see identify-conda.py's own header
# and build-prep.sh's own conda block for why). This step reads that already-
# written sidecar and merges it in -- the same /out directory both stages
# mount, so it is still here to read. Re-parsing environment.yml a second
# time would only ever reproduce the same result, since nothing about the
# source tree changes between the two stages. No-op when the main scan
# already carries a pkg:layer=conda component, so this never double-counts.
# ========================================================
CONDA_SBOM="${OUT_PREFIX}_conda.cdx.json"
if [ -f "$CONDA_SBOM" ]; then
    HAS_CONDA=$(jq '[.components[]? | select(.properties[]? | select(.name=="bomlens:layer" and .value=="conda"))] | length' "$OUTPUT_FILE" 2>/dev/null || echo 0)
    if [ "${HAS_CONDA:-0}" -eq 0 ]; then
        CONDA_N=$(jq '[.components[]?] | length' "$CONDA_SBOM" 2>/dev/null || echo 0)
        if [ "${CONDA_N:-0}" -gt 0 ]; then
            echo "[INFO] conda environment.yml dependencies identified: $CONDA_N, merging into SBOM."
            if bash "$LIBDIR/merge-sbom.sh" "${OUTPUT_FILE}.merged" "$PROJECT_NAME" "$PROJECT_VERSION" "$OUTPUT_FILE" "$CONDA_SBOM"; then
                mv "${OUTPUT_FILE}.merged" "$OUTPUT_FILE"
            else
                echo "[WARN] merge of conda components failed; keeping the original SBOM." >&2
                rm -f "${OUTPUT_FILE}.merged"
            fi
        fi
    fi
fi

# ========================================================
# Modelica (.mo) library dependencies — cdxgen has no Modelica cataloger, so a
# Modelica project (OpenModelica/Dymola sources) scans to zero components even
# though the file itself already states what it depends on: a package's
# annotation(uses(...)) block names each external library with its version.
# identify-modelica.py parses that structurally, the same way identify-
# cocoapods.sh parses Podfile.lock, for the CLI source scan (/src) and the
# web-UI source scan (SOURCE_ROOT). No-op when the main scan already carries
# a pkg:layer=modelica component, so this never double-counts.
# ========================================================
MODELICA_SRC="${SOURCE_ROOT:-/src}"
if [ "$SOURCE_SCAN" = "true" ] && [ -d "$MODELICA_SRC" ] \
   && find "$MODELICA_SRC" -type f -name '*.mo' 2>/dev/null | grep -q .; then
    HAS_MODELICA=$(jq '[.components[]? | select(.properties[]? | select(.name=="bomlens:layer" and .value=="modelica"))] | length' "$OUTPUT_FILE" 2>/dev/null || echo 0)
    if [ "${HAS_MODELICA:-0}" -eq 0 ]; then
        echo "[INFO] Identifying Modelica library dependencies (uses() annotation)..."
        MODELICA_SBOM="${OUT_PREFIX}_modelica.cdx.json"
        if command -v python3 >/dev/null 2>&1 \
           && python3 "$LIBDIR/identify-modelica.py" "$MODELICA_SRC" "$MODELICA_SBOM" "$PROJECT_VERSION"; then
            MODELICA_N=$(jq '[.components[]?] | length' "$MODELICA_SBOM" 2>/dev/null || echo 0)
            if [ "${MODELICA_N:-0}" -gt 0 ]; then
                echo "[INFO] Modelica library dependencies identified: $MODELICA_N — merging into SBOM."
                if bash "$LIBDIR/merge-sbom.sh" "${OUTPUT_FILE}.merged" "$PROJECT_NAME" "$PROJECT_VERSION" "$OUTPUT_FILE" "$MODELICA_SBOM"; then
                    mv "${OUTPUT_FILE}.merged" "$OUTPUT_FILE"
                else
                    echo "[WARN] merge of Modelica components failed; keeping the original SBOM." >&2
                    rm -f "${OUTPUT_FILE}.merged"
                fi
            fi
        fi
    fi
fi

# ========================================================
# A source tree that declares dependencies (a manifest or lock file that lists
# some, outside the non-shipped folders) yet ends with no component did not get
# scanned the way it asked: a Poetry project with no lock file is the measured
# case. Decided here, after every step that can still add components
# (vendored, CocoaPods, conda, Modelica), on the final count. It reads the same
# as a project with nothing to declare unless it is said, so it is recorded on
# the SBOM (bomlens:sbom-empty-with-manifests) and in the result manifest.
# ========================================================
if [ "$SOURCE_SCAN" = "true" ] && [ -d "${SOURCE_ROOT:-/src}" ] \
   && [ "$(jq '[.components[]?] | length' "$OUTPUT_FILE" 2>/dev/null || echo 1)" = "0" ]; then
    _empty_manifests="$(source_manifests "${SOURCE_ROOT:-/src}" 5)"
    if [ -n "$_empty_manifests" ]; then
        echo "[WARN] the source declares dependencies ($_empty_manifests) but the SBOM has no components; the scan did not resolve them."
        mark_document_status "$OUTPUT_FILE" "bomlens:sbom-empty-with-manifests" "$_empty_manifests"
        # The resolver steps that failed, which are most often why (a Gradle
        # or pip step that could not run), from the SBOM build-prep stamped.
        _empty_failed="$(jq -r '[.metadata.properties[]? | select(.name == "bomlens:pipeline-step-failed") | .value] | unique | join(", ")' "$OUTPUT_FILE" 2>/dev/null)"
        er_record generate degraded no_components "manifests found: $_empty_manifests${_empty_failed:+; steps that failed: $_empty_failed}" "" "" "{\"components\":0}"
    fi
fi

# ========================================================
# Common pipeline: normalize / deep-license / notice / security / sign
# ========================================================
ARTIFACTS=("$OUTPUT_FILE")

# Copy every artifact accumulated in ARTIFACTS so far to HOST_OUTPUT_DIR.
# Called after each pipeline stage below (not just once at the very end): a
# scan can run for minutes (cdxgen, Trivy, an AI-model pull), and a kill,
# an OOM, or a real power loss during any of them used to discard even a
# fully-finished BOM, because nothing reached the host mount until the last
# line of this script ran. Idempotent — re-copying an unchanged file is a
# harmless no-op, and re-copying a file this stage just rewrote in place
# (stamp/normalize/enrich all edit "$OUTPUT_FILE") picks up the latest content.
sync_artifacts() {
    if [ -n "$HOST_OUTPUT_DIR" ] && [ -d "$HOST_OUTPUT_DIR" ]; then
        for art in "${ARTIFACTS[@]}"; do
            [ -f "$art" ] || continue
            dest="$HOST_OUTPUT_DIR/$(basename "$art")"
            if [ "$art" -ef "$dest" ]; then
                : # already the host path (e.g. POSTPROCESS writing in place)
            elif cp "$art" "$HOST_OUTPUT_DIR/" 2>/dev/null; then
                echo "[SUCCESS] copied: $dest"
            else
                echo "[WARN] copy failed for $art (available in container at: $art)"
                continue
            fi
            if [[ "${HOST_UID:-}" =~ ^[0-9]+$ ]] && [[ "${HOST_GID:-}" =~ ^[0-9]+$ ]]; then
                chown "${HOST_UID}:${HOST_GID}" "$dest" 2>/dev/null || true
            fi
        done
    elif [ -z "${_WARNED_NO_HOST_OUTPUT:-}" ]; then
        echo "[WARN] HOST_OUTPUT_DIR not set/accessible. Artifacts at: $(pwd)"
        _WARNED_NO_HOST_OUTPUT=1
    fi
}
sync_artifacts

# Stamp the BOM's root component with the caller's --project/--version. ROOTFS is
# stamped too: syft names a `dir:` scan's root component after the scan path
# (/target), which is meaningless and leaks the container mount path — the same
# leak stamp-metadata.sh fixes for cdxgen. IMAGE/BINARY/FIRMWARE/ANALYZE/MERGE keep
# their own meaningful root (an image/file basename, a supplier's own identifier we
# must preserve, or — for MERGE — the project root merge-sbom.sh already wrote).
# See stamp-metadata.sh for the rationale.
case "$SCAN_MODE" in
    SOURCE|POSTPROCESS|ROOTFS)
        # Outbound licence: what the project itself ships under, which decides
        # whether the licence-conflict check runs at all. cdxgen fills this from
        # package.json for npm and leaves it empty everywhere else, so a Maven
        # project with a perfectly good <licenses> block in its pom.xml used to be
        # told no outbound licence was declared — the user had to repeat it with
        # --license. Read the manifest here instead. An explicit --license still
        # wins, and a manifest we cannot read confidently yields nothing, which
        # leaves the check off rather than inventing a licence to compare against.
        if [ -z "${PROJECT_LICENSE:-}" ] && command -v python3 >/dev/null 2>&1; then
            _lic_src="${SOURCE_ROOT:-/src}"
            [ -d "$_lic_src" ] || _lic_src=""
            if [ -n "$_lic_src" ]; then
                _detected="$(python3 "$LIBDIR/detect-project-license.py" "$_lic_src" 2>/dev/null || true)"
                if [ -n "$_detected" ]; then
                    PROJECT_LICENSE="$_detected"
                    export PROJECT_LICENSE
                    echo "[license] outbound license read from the project manifest: $PROJECT_LICENSE"
                fi
            fi
        fi
        # No `|| true`: a stamp failure means the SBOM still carries a leaked/placeholder
        # root name (e.g. src@latest), which collides in some SBOM import platforms. Fail closed under
        # set -e so a mis-named SBOM is never normalized, signed, or uploaded.
        er_phase stamp-metadata
        bash "$LIBDIR/stamp-metadata.sh" "$OUTPUT_FILE" "$PROJECT_NAME" "$PROJECT_VERSION"
        # A name scanners also give a project they cannot name, kept because
        # nothing is uploaded: the run is complete, so ok, with the warning.
        case "$PROJECT_NAME" in
            src|app) er_record stamp-metadata ok "" "the project name '$PROJECT_NAME' is also the name scanners give a project they cannot name; kept, since nothing is uploaded" "$ER_PHASE_STARTED" ;;
            *) er_record stamp-metadata ok "" "" "$ER_PHASE_STARTED" ;;
        esac
        er_phase_end
        ;;
esac

# Components a declaration file lists: what a source scan cannot find, such as
# the supplier's own build outputs and third-party parts added by hand. The
# files come from --components (DECLARED_COMPONENTS_FILES, space-separated
# container paths, with the names the user gave them in
# DECLARED_COMPONENTS_LABELS); without it, sbom-declared.cdx.json at the scan
# target root is read when it exists. After stamp-metadata, so a first-party
# component with no version takes the product's, and before normalize, so what
# is added is normalized with the rest. A refused file (exit 3) stops the run
# here with the reasons, before the SBOM is normalized, signed or uploaded:
# an SBOM without the declared components is not the one that was asked for,
# so the SBOM written so far is renamed to _bom.refused.json, where a CI step
# that picks up _bom.json cannot take it for the result. --no-components
# (DECLARED_COMPONENTS_SKIP=1) leaves the default file unread.
# Recorded only when there is a file to read.
#
# DECLARED_COMPONENTS_APPLIED=1 tells the conformance check that the
# components marked bomlens:declared were written by this step in this run,
# which the first-party exemption from the PURL rows relies on
# (validate-sbom.sh). It is never taken from the caller's environment.
unset DECLARED_COMPONENTS_APPLIED
case "$SCAN_MODE" in
    SOURCE|POSTPROCESS)
        _dc_root="${SOURCE_ROOT:-/src}"
        _dc_files=()
        _dc_default=0
        if [ -n "${DECLARED_COMPONENTS_FILES:-}" ]; then
            read -r -a _dc_files <<< "$DECLARED_COMPONENTS_FILES"
        elif [ "${DECLARED_COMPONENTS_SKIP:-}" = "1" ]; then
            [ -f "$_dc_root/sbom-declared.cdx.json" ] \
                && echo "[INFO] --no-components: sbom-declared.cdx.json at the scan target root is not read."
        elif [ -f "$_dc_root/sbom-declared.cdx.json" ]; then
            _dc_files=("$_dc_root/sbom-declared.cdx.json")
            _dc_default=1
            DECLARED_COMPONENTS_LABELS="sbom-declared.cdx.json (at the scan target root)"
        fi
        if [ "${#_dc_files[@]}" -gt 0 ]; then
            er_phase declared-components
            _dc_rc=0
            _dc_err="$(mktemp)"
            DECLARED_COMPONENTS_LABELS="${DECLARED_COMPONENTS_LABELS:-}" DECLARED_COMPONENTS_DEFAULT="$_dc_default" \
                python3 "$LIBDIR/apply-declared-components.py" "$OUTPUT_FILE" "$_dc_root" "${_dc_files[@]}" 2> "$_dc_err" || _dc_rc=$?
            cat "$_dc_err" >&2
            if [ "$_dc_rc" -eq 0 ]; then
                _dc_count="$(jq '[.components[]? | select(any(.properties[]?; .name == "bomlens:declared" and .value == "true"))] | length' "$OUTPUT_FILE" 2>/dev/null || echo 0)"
                er_record declared-components ok "" "" "$ER_PHASE_STARTED" "" "{\"components\":${_dc_count:-0}}"
                er_phase_end
                export DECLARED_COMPONENTS_APPLIED=1
            else
                _dc_first="$(sed -n 's/^\[declared-components\] ERROR: //p' "$_dc_err" | head -n 1)"
                er_record declared-components failed failed "${_dc_first:-the declaration could not be applied}" "$ER_PHASE_STARTED"
                er_phase_end
                rm -f "$_dc_err"
                _dc_refused="${OUT_PREFIX}_bom.refused.json"
                mv -f "$OUTPUT_FILE" "$_dc_refused" 2>/dev/null || true
                # The copy already synced to the host (an output folder that
                # is not this one) is renamed there too.
                if [ -n "${HOST_OUTPUT_DIR:-}" ] && [ -f "$HOST_OUTPUT_DIR/$OUTPUT_FILE" ]; then
                    mv -f "$HOST_OUTPUT_DIR/$OUTPUT_FILE" "$HOST_OUTPUT_DIR/$_dc_refused" 2>/dev/null || true
                fi
                ARTIFACTS=("$_dc_refused")
                sync_artifacts
                if [ "$_dc_rc" -eq 3 ]; then
                    echo "[ERROR] the declared components were refused (reasons above), so the SBOM is not complete. Fix the declaration file and scan again."
                else
                    echo "[ERROR] the declared components could not be added to the SBOM (see above)."
                fi
                echo "[ERROR] The SBOM without them is kept as $_dc_refused, not as $OUTPUT_FILE."
                exit 1
            fi
            rm -f "$_dc_err"
        fi
        unset _dc_root _dc_files _dc_rc _dc_err _dc_count _dc_first _dc_default
        ;;
esac

# ========================================================
# Record who generated this SBOM, with what, and at which lifecycle phase — the
# document-level fields the 2026 SBOM minimum elements ask every SBOM to carry.
# See stamp-document-metadata.sh for what each one means and why ANALYZE is the
# one mode left out (it converts a supplier's document; we did not author it).
#
# Listed mode by mode rather than as "everything except ANALYZE": a mode added
# later that also takes a supplier's SBOM as input would otherwise be stamped by
# default and quietly claim authorship of it. The script warns about a mode it has
# no phase for, so a new scan mode shows up in the log instead of passing silently.
# ========================================================
#
# The scanned artifact is passed where the target IS a file, so its hash lands on
# the component the SBOM is about. BINARY, FIRMWARE and MODELFILE are the three
# such modes; the others scan a tree, an image or an existing document, none of
# which is one file.
case "$SCAN_MODE" in
    BINARY|FIRMWARE|MODELFILE)
        # A firmware folder is not one file, so it has no hash to stamp.
        if [ -f "$TARGET_FILE" ]; then
            run_optional_step docmeta bash "$LIBDIR/stamp-document-metadata.sh" "$OUTPUT_FILE" "$SCAN_MODE" "$TARGET_FILE"
        else
            run_optional_step docmeta bash "$LIBDIR/stamp-document-metadata.sh" "$OUTPUT_FILE" "$SCAN_MODE"
        fi
        ;;
    SOURCE|POSTPROCESS|ROOTFS|IMAGE|AIBOM|DATASET|AIDECLARE|MERGE)
        run_optional_step docmeta bash "$LIBDIR/stamp-document-metadata.sh" "$OUTPUT_FILE" "$SCAN_MODE"
        ;;
esac

# Versions the scan could not read. A firmware, root filesystem or binary scan
# can prove a component is there without finding its version. The supplier's
# file (--component-versions, CSV name,version[,reason]) fills those in, keeps
# a version read from the delivered files when the file disagrees, adds the
# names the scan did not find as supplier-declared components, and records the
# reason a supplier gives for a component it has no version for. Every
# such scan also writes the components still missing a version as a template
# in the same format. Before normalize, so what is added is normalized too;
# the placeholder versions normalize removes (UNKNOWN) count as missing here.
# A refused file (exit 3) fails the step, and the run exits 1 at the end, after
# every file is written, with the reason: the versions the user supplied were
# not applied.
CV_REFUSED=""
case "$SCAN_MODE" in
    FIRMWARE|ROOTFS|BINARY)
        # Which kind of scan wrote this SBOM, stated rather than left to be
        # guessed from the tools listed: a reviewer's --analyze run reads it
        # (validate-sbom.sh, submission profile).
        if jq --arg m "$SCAN_MODE" '.metadata.properties = ([(.metadata.properties // [])[] | select(.name? != "bomlens:scanMode")]
                                    + [{name: "bomlens:scanMode", value: $m}])' "$OUTPUT_FILE" > "$OUTPUT_FILE.mode.tmp" 2>/dev/null; then
            mv "$OUTPUT_FILE.mode.tmp" "$OUTPUT_FILE"
        else
            rm -f "$OUTPUT_FILE.mode.tmp"
        fi
        _cv_args=("$OUTPUT_FILE" "$OUT_PREFIX")
        [ "$CV_INPUT_IS_TEMPLATE" = true ] && _cv_args=(--no-template "${_cv_args[@]}")
        if [ -n "${COMPONENT_VERSIONS_FILE:-}" ]; then
            if [ -f "$COMPONENT_VERSIONS_FILE" ]; then
                _cv_args+=("$COMPONENT_VERSIONS_FILE")
            else
                echo "[WARN] --component-versions skipped: the file is not visible inside the container ($COMPONENT_VERSIONS_FILE). If it is a symbolic link, pass the real file." >&2
            fi
        fi
        if [ -f "$LIBDIR/component-versions.py" ]; then
            _cv_started="$(er_now)"
            er_event step.start component-versions
            _cv_err="$(mktemp)"
            _cv_rc=0
            python3 "$LIBDIR/component-versions.py" "${_cv_args[@]}" 2> "$_cv_err" || _cv_rc=$?
            cat "$_cv_err" >&2
            if [ "$_cv_rc" -eq 0 ]; then
                er_record component-versions ok "" "" "$_cv_started"
            else
                if [ "$_cv_rc" -eq 3 ]; then
                    CV_REFUSED="$(sed -n 's/^\[component-versions\] ERROR: the --component-versions file was refused: //p' "$_cv_err" | head -n 1)"
                    [ -n "$CV_REFUSED" ] || CV_REFUSED="the file was refused"
                else
                    echo "[WARN] post-process step 'component-versions' failed; continuing with a valid SBOM, but this step's output may be missing or incomplete." >&2
                fi
                mark_pipeline_warning "$OUTPUT_FILE" component-versions
                er_record component-versions failed failed "${CV_REFUSED:+the --component-versions file was refused: $CV_REFUSED}" "$_cv_started"
            fi
            rm -f "$_cv_err"
        fi
        [ "$CV_INPUT_IS_TEMPLATE" != true ] && [ -f "${OUT_PREFIX}_component-versions.template.csv" ] \
            && ARTIFACTS+=("${OUT_PREFIX}_component-versions.template.csv")
        ;;
esac
# A Yocto build's SBOM says so too, for the same reviewer. It has every version
# from the build records, so no template is written for it.
CONFORMANCE_MODE="$SCAN_MODE"
if [ "$YOCTO_SBOM" = true ] && [ "$YOCTO_FROM_BUILD" = true ]; then
    CONFORMANCE_MODE=YOCTO
    if jq '.metadata.properties = ([(.metadata.properties // [])[] | select(.name? != "bomlens:scanMode")]
                                   + [{name: "bomlens:scanMode", value: "YOCTO"}])' "$OUTPUT_FILE" > "$OUTPUT_FILE.mode.tmp" 2>/dev/null; then
        mv "$OUTPUT_FILE.mode.tmp" "$OUTPUT_FILE"
    else
        rm -f "$OUTPUT_FILE.mode.tmp"
    fi
fi

if [ "${BYTE_STABLE:-false}" = "true" ]; then
    run_optional_step normalize bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE" --stable
else
    run_optional_step normalize bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE"
fi

# Registry licences (opt-in, network): fill a component that has no licence,
# and check a single strong-copyleft or non-commercial licence against the
# registry, replacing it when the registry says otherwise. After normalize, so
# a licence written as free text has its SPDX id by now and is checked too;
# when anything changed, normalize runs again to classify what was written. A
# supplier's own SBOM (ANALYZE) only has missing licences filled: its declared
# ones are never overwritten. The counts go to the result manifest; a lookup
# that failed or ran out of time leaves the step degraded, since those
# components were not checked.
if [ "${LICENSE_REGISTRY:-false}" = "true" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    echo "[INFO] Looking up licences in the package registries (deps.dev)..."
    _lr_started="$(er_now)"
    _lr_rc=0
    _lr_args=()
    [ "$SCAN_MODE" = "ANALYZE" ] && _lr_args=(--fill-only)
    _lr_counts="$(python3 "$LIBDIR/enrich-license-registry.py" "${_lr_args[@]}" "$OUTPUT_FILE")" || _lr_rc=$?
    if [ "$_lr_rc" -ne 0 ] || ! printf '%s' "$_lr_counts" | jq -e 'type == "object"' >/dev/null 2>&1; then
        mark_pipeline_warning "$OUTPUT_FILE" license-registry
        er_record license-registry failed failed "" "$_lr_started"
    else
        if printf '%s' "$_lr_counts" | jq -e '(.budget_reached // 0) > 0' >/dev/null; then
            er_record license-registry degraded budget_exhausted "" "$_lr_started" "" "$_lr_counts"
        elif printf '%s' "$_lr_counts" | jq -e '(.lookup_failed // 0) > 0' >/dev/null; then
            er_record license-registry degraded unavailable "" "$_lr_started" "" "$_lr_counts"
        else
            er_record license-registry ok "" "" "$_lr_started" "" "$_lr_counts"
        fi
        if printf '%s' "$_lr_counts" | jq -e '(.filled // 0) + (.superseded // 0) > 0' >/dev/null; then
            if [ "${BYTE_STABLE:-false}" = "true" ]; then
                run_optional_step normalize bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE" --stable
            else
                run_optional_step normalize bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE"
            fi
        fi
    fi
elif [ "$AI_MODEL_SCAN" != "true" ]; then
    er_record license-registry disabled
fi

# The component/dependency graph is final as of the normalize pass above; every
# step below this point only enriches metadata (CPE, EOL, risk, ...) and must
# not change compositions.aggregate's answer, so this runs once, here.
mark_compositions_aggregate "$OUTPUT_FILE"

# CPE enrichment: firmware/image/rootfs components often arrive with name+version
# but no purl/cpe. enrich-cpe.sh attaches (or version-normalizes) a cpe:2.3 for
# WHITELISTED component names only (closed list, no guessing) and fills confirmed
# SPDX licenses. The CPE keeps the SBOM identifier correct for consumers that read
# it; note that `trivy sbom` matches by PURL and OS-context, NOT by component.cpe
# (issue #458), so distro CVE matching comes from the OS component synthesized just
# below and, for firmware/rootfs/binary, from match-cpe-index.sh before the security
# scan. Skipped for AI SBOMs and
# disabled with ENRICH_CPE=false. Generic across modes; best-effort (|| true).
if [ "${ENRICH_CPE:-true}" != "false" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-cpe bash "$LIBDIR/enrich-cpe.sh" "$OUTPUT_FILE"
elif [ "$AI_MODEL_SCAN" != "true" ]; then
    er_record enrich-cpe disabled
fi

# Upstream repository purl: a component a firmware, root filesystem or binary
# scan identified has no purl, a pkg:generic one, or an opkg one, none of which
# a tool that looks components up by purl can resolve. upstream-purl.py sets
# the purl of the project's source repository at the release tag
# (pkg:github/<owner>/<repo>@<tag>, pkg:sourceforge, pkg:gnu) from a closed,
# checked table (upstream-purl-map.json); a name not in it is left alone. The
# version, CPE and evidence stay, so the CVE matching that ran on them keeps
# its result. After enrich-cpe, so a CPE it added can identify the project too.
# A Yocto build's records (YOCTO_SBOM) get the same step. Disable with
# ENRICH_UPSTREAM_PURL=false.
_upstream_mode="$SCAN_MODE"
[ "$YOCTO_SBOM" = true ] && _upstream_mode=YOCTO
case "$_upstream_mode" in
    FIRMWARE|ROOTFS|BINARY|YOCTO)
        if [ "${ENRICH_UPSTREAM_PURL:-true}" != "false" ]; then
            run_optional_step upstream-purl python3 "$LIBDIR/upstream-purl.py" "$OUTPUT_FILE"
        else
            er_record upstream-purl disabled
        fi
        ;;
esac

# OS-context enrichment: a supplier SBOM can list every rpm/deb/apk package yet
# omit the operating-system component Trivy needs to pick a distro advisory DB.
# Without it an SBOM full of pkg:rpm/centos/... (or pkg:deb/..., pkg:apk/...)
# returns ZERO findings despite valid PURLs. enrich-os-context.py infers (distro,
# version) from the dominant distro PURL and appends one operating-system component
# (or normalizes an existing "8.10" -> "8" so RHEL-like matching works): rpm and
# debian by major, ubuntu by major.minor, alpine by its release id. Skipped for AI
# SBOMs and with ENRICH_OS_CONTEXT=false; a no-op when the SBOM has no recognizable
# distro packages (an unsupported distro like OpenWRT, or deb/apk PURLs with no
# distro= version). Runs before the security scan; best-effort, never aborts.
if [ "${ENRICH_OS_CONTEXT:-true}" != "false" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-os-context python3 "$LIBDIR/enrich-os-context.py" "$OUTPUT_FILE"
elif [ "$AI_MODEL_SCAN" != "true" ]; then
    er_record enrich-os-context disabled
fi

# Distro supplier enrichment: an rpm/deb/apk component carries `publisher` but
# never `supplier` (verified: deb/apk hold an individual maintainer there,
# different per package; rpm already holds the distro project, but that is a
# different CycloneDX field with a different meaning, so it does not excuse
# leaving `supplier` empty). enrich-distro-supplier.py reads the
# operating-system component enrich-os-context.py just synthesized (or left
# in place) and fills `supplier` with that distro's project name, for the
# distros this file has a confirmed name for. Runs right after OS-context
# enrichment, since it depends on that component. Skipped for AI SBOMs and
# with ENRICH_DISTRO_SUPPLIER=false; a no-op when there is no single
# unambiguous operating-system component, or its distro has no confirmed
# supplier name yet. Best-effort, never aborts.
if [ "${ENRICH_DISTRO_SUPPLIER:-true}" != "false" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-distro-supplier python3 "$LIBDIR/enrich-distro-supplier.py" "$OUTPUT_FILE"
elif [ "$AI_MODEL_SCAN" != "true" ]; then
    er_record enrich-distro-supplier disabled
fi

# Maven CPE enrichment: maven libraries carry a PURL but no CPE, so a CPE-aware
# engine cannot reach their NVD-only CVEs (older Apache libs like pdfbox 1.8.7 /
# tomcat 7.0.50, matched in NVD by cpe:2.3:a:apache:pdfbox, absent from the GitHub
# Security Advisory data Trivy/OSV use for maven). enrich-maven-cpe.py derives an
# NVD-matchable cpe:2.3 from the groupId — a curated map for well-known groups
# (spring, jackson, ...) plus a conservative org.apache.* rule; anything it cannot
# map safely gets no CPE (no guessing). Skipped for AI SBOMs and with
# ENRICH_MAVEN_CPE=false; a no-op when the SBOM has no maven components.
if [ "${ENRICH_MAVEN_CPE:-true}" != "false" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-maven-cpe python3 "$LIBDIR/enrich-maven-cpe.py" "$OUTPUT_FILE"
elif [ "$AI_MODEL_SCAN" != "true" ]; then
    er_record enrich-maven-cpe disabled
fi

# GitHub-coordinate CPE enrichment: a component identified only by its source
# repository (pkg:github/<owner>/<repo>@<version> — large C/C++ projects with no
# package-manager ecosystem, e.g. a browser engine or a header-only library) has
# no purl an ecosystem vulnerability source can match, and Trivy does not
# recognize pkg:github/ at all, so these silently score zero findings.
# enrich-github-cpe.py attaches an NVD-matchable cpe:2.3 for a short, hand-
# verified owner/repo -> vendor:product map only (e.g. chromium/chromium ->
# google:chrome); anything not in the map gets no CPE, since a repo's own name
# rarely matches NVD's vendor:product and guessing would inject wrong CVEs.
# Skipped for AI SBOMs and with ENRICH_GITHUB_CPE=false; a no-op when the SBOM
# has no pkg:github/ component in the map.
if [ "${ENRICH_GITHUB_CPE:-true}" != "false" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-github-cpe python3 "$LIBDIR/enrich-github-cpe.py" "$OUTPUT_FILE"
elif [ "$AI_MODEL_SCAN" != "true" ]; then
    er_record enrich-github-cpe disabled
fi

# Interpreter CPE enrichment: a language interpreter distributed AS a package
# under conda or NuGet (e.g. a conda environment pinning `python`, or a NuGet
# package bundling CPython) carries a pkg:conda/ or pkg:nuget/ purl that Trivy
# parses fine, but neither ecosystem's advisory feed carries CVEs for a package
# named "python" -- CPython's CVEs live in NVD, keyed by cpe:2.3:a:python:python.
# enrich-interpreter-cpe.py attaches that CPE for a short, hand-verified
# (purl type, name) -> vendor:product map only; anything not in the map gets no
# CPE (no guessing from the purl name). Skipped for AI SBOMs and with
# ENRICH_INTERPRETER_CPE=false; a no-op when the SBOM has no matching component.
if [ "${ENRICH_INTERPRETER_CPE:-true}" != "false" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-interpreter-cpe python3 "$LIBDIR/enrich-interpreter-cpe.py" "$OUTPUT_FILE"
elif [ "$AI_MODEL_SCAN" != "true" ]; then
    er_record enrich-interpreter-cpe disabled
fi

# EOL enrichment: flag components whose release cycle is past its published
# end-of-life, fully OFFLINE from a bundled endoflife.date snapshot (no network,
# works air-gapped). Answers "is this still maintained?" — a supply-chain risk
# separate from CVEs. Matches by PURL against a curated whitelist (eol-purl-map.json);
# unmapped components are left untouched (implicitly unknown), never guessed.
# Skipped for AI SBOMs (no runtime/framework components) and with ENRICH_EOL=false
# (e.g. an image built without the dataset). Best-effort; never aborts the scan.
if [ "${ENRICH_EOL:-true}" != "false" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-eol bash "$LIBDIR/enrich-eol.sh" "$OUTPUT_FILE"
elif [ "$AI_MODEL_SCAN" != "true" ]; then
    er_record enrich-eol disabled
fi

# Malicious-package check: flag components that are known-malicious packages
# (typosquats, hijacked accounts, install-time payloads), fully OFFLINE from a
# bundled OSV snapshot. A different question from "does this have a CVE?", and a
# different response — removal and credential rotation rather than an upgrade —
# so it is reported as its own signal. Matches by PURL only; a name match would
# be exactly wrong here, since these packages are named to resemble real ones.
# Runs for every mode: an AI SBOM's dependencies can be malicious too. Disable
# with ENRICH_MALICIOUS=false. Best-effort; never aborts the scan.
if [ "${ENRICH_MALICIOUS:-true}" != "false" ]; then
    run_optional_step enrich-malicious bash "$LIBDIR/enrich-malicious.sh" "$OUTPUT_FILE"
else
    er_record enrich-malicious disabled
fi

# Staleness enrichment (OPT-IN, default off): query deps.dev for absolute version
# currency (newest version, how many releases behind, last-release date). Unlike
# EOL this makes one network call per package, so it trades the scan's offline
# determinism for freshness and is only run when STALENESS_ENRICH=true. Best-effort
# and bounded (per-request timeout + wall-clock budget); never aborts the scan.
if [ "${STALENESS_ENRICH:-false}" = "true" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-staleness python3 "$LIBDIR/enrich-staleness.py" "$OUTPUT_FILE"
elif [ "$AI_MODEL_SCAN" != "true" ]; then
    er_record enrich-staleness disabled
fi

# AI model risk assessment: stamp every model/dataset component with a
# bomlens:assessment:* verdict (ok / conditional / caution / review) from the
# curated license-terms registry (ai-risk-knowledge.json). Offline, pure
# post-processing after normalize (SPDX ids in place); an unknown license falls
# to review, never to a guess, and the reports that print the verdict carry the
# registry's not-legal-advice disclaimer. Self-gates on the presence of a
# machine-learning-model component, so ANALYZE of a plain SBOM is a no-op.
if [ "$AI_MODEL_SCAN" = "true" ] || [ "$SCAN_MODE" = "ANALYZE" ]; then
    # Sources the publisher named by hub id are read from the hub first, so the
    # assessment judges them with the dataset (the SPDX 3.0.1 block below
    # records them as declared). The same declaration that block applies.
    DECL_FOR_SOURCES="${AI_DECLARATION_FILE:-}"
    if [ -z "$DECL_FOR_SOURCES" ] && [ -n "${HOST_OUTPUT_DIR:-}" ]; then
        DECL_FOR_SOURCES="$HOST_OUTPUT_DIR/${OUT_PREFIX}_ai-declaration.json"
    fi
    if [ "$AI_MODEL_SCAN" = "true" ] && [ -n "$DECL_FOR_SOURCES" ] && [ -f "$DECL_FOR_SOURCES" ]; then
        run_optional_step declared-sources python3 "$LIBDIR/apply-declared-sources.py" "$OUTPUT_FILE" "$DECL_FOR_SOURCES"
        # The service the model runs in (services[], with its dependencies and
        # standard claims) and the model's declared input and output kinds,
        # training compute and adversarial testing, each marked as the
        # publisher's declaration. Before the G7 checks, which read them.
        run_optional_step declared-service python3 "$LIBDIR/apply-declared-service.py" "$OUTPUT_FILE" "$DECL_FOR_SOURCES"
    fi
    run_optional_step assess-ai-risk bash "$LIBDIR/assess-ai-risk.sh" "$OUTPUT_FILE"
fi

# Conformance check on the generated SBOM. For AI SBOM modes this is the G7
# minimum-element checklist (validate-sbom.sh detects the machine-learning-model
# component and appends those checks — model id/license/card/integrity, datasets,
# openness, all advisory). For the other generation modes it is the same SKT
# submission format check ANALYZE already runs on a supplied SBOM, so a scan's
# own output can be self-checked before submission instead of requiring a
# separate --analyze pass. Best-effort (exit 0); the resulting _conformance.*
# files are collected by the [ -f ] guard in the risk-report block below.
case "$SCAN_MODE" in
    SOURCE|POSTPROCESS|ROOTFS|IMAGE|BINARY|FIRMWARE|MERGE) CONFORMANCE_GEN_MODE=true ;;
    *) CONFORMANCE_GEN_MODE=false ;;
esac
if [ "$AI_MODEL_SCAN" = "true" ]; then
    echo "[2/2] ai: G7 minimum-element conformance"
    run_optional_step conformance bash "$LIBDIR/validate-sbom.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"
elif [ "$CONFORMANCE_GEN_MODE" = "true" ]; then
    run_optional_step conformance bash "$LIBDIR/validate-sbom.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"
elif [ "$YOCTO_FROM_BUILD" = "true" ] && [ ! -f "${OUT_PREFIX}_conformance.json" ]; then
    # A Yocto build directory: the SBOM read from the build is what the supplier
    # submits. Judged as a firmware SBOM is (MODE=YOCTO): it records the packages
    # installed, not a dependency graph.
    MODE="$CONFORMANCE_MODE" run_optional_step conformance bash "$LIBDIR/validate-sbom.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"
fi
# --no-report skips the block that collects the conformance sidecars below, but the
# CLI's closing summary still needs its facts on the host.
if [ "${GENERATE_REPORT:-false}" != "true" ] && [ -f "${OUT_PREFIX}_summary.result" ]; then
    ARTIFACTS+=("${OUT_PREFIX}_summary.result")
fi

# Deep license detection (scancode, opt-in). Only meaningful for source trees.
DEEP_SRC="${SOURCE_ROOT:-/src}"
# BOMLENS_DEEP_LICENSE_RC: the caller already ran deep-license.sh in the
# deep-license image and wrote ${OUT_PREFIX}_scancode.json, because this stage
# runs on the deep-cve image (grype, no scancode); the value is its exit code,
# recorded here as if it had run in this container.
# BOMLENS_DEEP_LICENSE_STARTED and _ENDED, when given, are when it ran.
_dl_handed=""
[[ "${BOMLENS_DEEP_LICENSE_RC:-}" =~ ^[0-9]{1,3}$ ]] && _dl_handed=1
if [ "$SOURCE_SCAN" = "true" ] && [ "${DEEP_LICENSE:-false}" = "true" ] && { [ -d "$DEEP_SRC" ] || [ -n "$_dl_handed" ]; }; then
    _dl_started="$(er_now)"
    _dl_ended=""
    _dl_rc=0
    if [ -n "$_dl_handed" ]; then
        _dl_rc="$BOMLENS_DEEP_LICENSE_RC"
        _dl_ts='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
        [[ "${BOMLENS_DEEP_LICENSE_STARTED:-}" =~ $_dl_ts ]] && _dl_started="$BOMLENS_DEEP_LICENSE_STARTED"
        [[ "${BOMLENS_DEEP_LICENSE_ENDED:-}" =~ $_dl_ts ]] && _dl_ended="$BOMLENS_DEEP_LICENSE_ENDED"
        echo "[INFO] scancode deep license detection ran before this stage, in the deep-license image (exit code $_dl_rc)."
        case "$_dl_rc" in 0|6) [ -f "${OUT_PREFIX}_scancode.json" ] || _dl_rc=1 ;; esac
    else
        echo "[INFO] Running scancode deep license detection..."
        # This run's own output folder, when it sits inside the scanned tree (a
        # CLI scan of the current folder), is not the project's source.
        DEEP_LICENSE_EXCLUDE="${SRC_TREE_EXCLUDE:-} $OUT_PREFIX" \
            bash "$LIBDIR/deep-license.sh" "$DEEP_SRC" "${OUT_PREFIX}_scancode.json" || _dl_rc=$?
    fi
    case "$_dl_rc" in
        0)
            ARTIFACTS+=("${OUT_PREFIX}_scancode.json")
            er_record deep-license ok "" "" "$_dl_started" "$_dl_ended" ;;
        6)
            ARTIFACTS+=("${OUT_PREFIX}_scancode.json")
            er_record deep-license degraded failed "scancode reported errors on some files" "$_dl_started" "$_dl_ended" ;;
        3)
            # Say why scancode is missing: the CLI ran this step here because
            # the scancode image could not be pulled, the image the caller
            # handed the scan to had none, or this is the deep-cve image (grype,
            # no scancode), which a caller that does not run the licence scan
            # first leaves without it.
            if [ -n "${BOMLENS_DEEP_LICENSE_FALLBACK:-}" ]; then
                echo "[WARN] --deep-license: the scancode image ${BOMLENS_DEEP_LICENSE_FALLBACK} was not available, so the licence scan did not run."
                er_record deep-license skipped fallback "the scancode image was not available: ${BOMLENS_DEEP_LICENSE_FALLBACK}" "$_dl_started" "$_dl_ended"
            elif [ -n "$_dl_handed" ]; then
                echo "[WARN] --deep-license: scancode was not in the image the licence scan ran on, so it did not run."
                er_record deep-license skipped not_installed "scancode was not in the image the licence scan ran on" "$_dl_started" "$_dl_ended"
            elif command -v grype >/dev/null 2>&1; then
                echo "[WARN] --deep-license: this stage runs on the deep-cve image, which has grype but not scancode, so the licence scan did not run. Run it in the bomlens-deep-license image before this stage and pass its exit code as BOMLENS_DEEP_LICENSE_RC (the CLI does this with --deep-cve)."
                er_record deep-license skipped not_installed "scancode is not in this image: the deep-cve image has grype only" "$_dl_started" "$_dl_ended"
            else
                echo "[WARN] --deep-license requested but scancode not in image (use the bomlens-deep-license image, or rebuild with --build-arg SBOM_DEEP_LICENSE=true)."
                er_record deep-license skipped not_installed "scancode is not in this image" "$_dl_started" "$_dl_ended"
            fi ;;
        4)
            er_record deep-license skipped too_large "more than ${DEEP_LICENSE_MAX_FILES:-20000} source files" "$_dl_started" "$_dl_ended" ;;
        5)
            er_record deep-license failed timeout "stopped after ${DEEP_LICENSE_TIMEOUT:-600}s" "$_dl_started" "$_dl_ended" ;;
        *)
            echo "[WARN] scancode run failed."
            er_record deep-license failed failed "" "$_dl_started" "$_dl_ended" ;;
    esac
elif [ "$SOURCE_SCAN" = "true" ] && [ "${DEEP_LICENSE:-false}" = "true" ]; then
    er_record deep-license skipped no_input "no source tree at $DEEP_SRC"
elif [ "$SOURCE_SCAN" = "true" ]; then
    er_record deep-license disabled
elif [ "${DEEP_LICENSE:-false}" = "true" ]; then
    er_record deep-license skipped no_input "not a source scan"
fi

# Where this mode's scanned files sit on disk. SOURCE (web UI) and POSTPROCESS
# (the CLI source scan, which mounts the scanned tree at /src) both look at a
# source tree; ROOTFS looks at the extracted image directory. FIRMWARE handles
# itself inside scan-firmware.sh, because its extracted rootfs is a temp dir
# removed before we get here. AIBOM/ANALYZE/MERGE have no files at all.
SRC_TREE_DIR=""
UNPACKED_DIR=""
case "$SCAN_MODE" in
    SOURCE) SRC_TREE_DIR="${SOURCE_ROOT:-/src}" ;;
    POSTPROCESS) [ "$SOURCE_SCAN" = "true" ] && SRC_TREE_DIR="${SOURCE_ROOT:-/src}" ;;
    ROOTFS) SRC_TREE_DIR="$TARGET_DIR" ;;
    IMAGE|BINARY)
        # A container image is layers, and a build artifact is one packed file:
        # neither has a directory to walk, so the scan alone can say what is
        # INSIDE them but never show it. Unpack a readable copy to a temp dir,
        # build the tree and snapshot from it, and delete it below — the same
        # shape scan-firmware.sh already uses for its extraction. Best-effort:
        # an ELF binary or a missing docker socket prints nothing and the file
        # views are simply absent.
        UNPACK_TARGET="${IMAGE_READ_TARGET:-$TARGET_IMAGE}"
        [ "$SCAN_MODE" = "BINARY" ] && UNPACK_TARGET="$TARGET_FILE"
        # stdout is the directory (empty when it could not unpack); stderr is the
        # reason, and belongs in the scan log where the user reads it.
        UNPACKED_DIR="$(bash "$LIBDIR/unpack-scan-target.sh" "$SCAN_MODE" "$UNPACK_TARGET")"
        SRC_TREE_DIR="$UNPACKED_DIR"
        ;;
esac
[ -n "$SRC_TREE_DIR" ] && [ -d "$SRC_TREE_DIR" ] || SRC_TREE_DIR=""

# Source file tree (${OUT_PREFIX}_files.json): a ScanCode-shaped inventory so the
# web UI's source-tree view works WITHOUT the opt-in ScanCode deep-license scan —
# structure only, no licenses. When ScanCode already produced a _scancode.json,
# that one wins (it carries licenses), so we skip this fallback. Best-effort:
# never aborts.
#
# A "current folder" scan writes this run's own output subfolder
# (${OUT_PREFIX}/) inside the very directory being scanned, so it is a real
# child of SRC_TREE_DIR by the time this runs: earlier steps already wrote
# into it. Two different launch shapes hit this, detected two different ways:
#   - CLI, no --output-dir: OUTPUT_HOST_DIR ends up NESTED under SCAN_INPUT_DIR
#     (a subfolder, not the same directory), so scan-sbom.sh knows both as
#     plain host strings and sets SRC_TREE_EXCLUDE itself when that is the case.
#   - Web UI, Current folder target: /src and /host-output are two bind mounts
#     of the IDENTICAL host directory (server.py launches with
#     `-v $(pwd):/src -v $(pwd):/host-output`), which two different container
#     paths can't reveal. So when the host did not already set
#     SRC_TREE_EXCLUDE, fall back to comparing device+inode, which is exactly
#     the same location in that shape (and reliably different in the CLI's
#     nested one, where this fallback correctly finds nothing to do).
if [ -z "${SRC_TREE_EXCLUDE:-}" ] && [ -n "$SRC_TREE_DIR" ] && [ -d /host-output ]; then
    src_dev_ino="$(stat -c '%d:%i' "$SRC_TREE_DIR" 2>/dev/null)"
    out_dev_ino="$(stat -c '%d:%i' /host-output 2>/dev/null)"
    if [ -n "$src_dev_ino" ] && [ "$src_dev_ino" = "$out_dev_ino" ]; then
        SRC_TREE_EXCLUDE="$OUT_PREFIX"
    fi
fi
if [ ! -f "${OUT_PREFIX}_scancode.json" ] && [ -n "$SRC_TREE_DIR" ]; then
    run_optional_step source-file-tree bash "$LIBDIR/source-file-tree.sh" "$SRC_TREE_DIR" "${OUT_PREFIX}_files.json" "${SRC_TREE_EXCLUDE:-}"
fi

# Whether the tree pinned the versions its SBOM reports. Source scans only: an
# image or a firmware carries what is installed, so there is nothing resolved at
# scan time to warn about. The CLI reaches this file as POSTPROCESS with
# SOURCE_SCAN set, the web UI as SOURCE — both are the same scan and both need
# the answer. Best-effort: an unjudgeable tree records nothing.
if [ -n "$SRC_TREE_DIR" ] && { [ "$SCAN_MODE" = "SOURCE" ] \
   || { [ "$SCAN_MODE" = "POSTPROCESS" ] && [ "${SOURCE_SCAN:-false}" = "true" ]; }; }; then
    bash "$LIBDIR/detect-version-pinning.sh" "$SRC_TREE_DIR" "$OUTPUT_FILE" || true
fi
# Collect the file tree if any source-having mode produced one (the modes above,
# or FIRMWARE from scan-firmware.sh).
[ -f "${OUT_PREFIX}_files.json" ] && ARTIFACTS+=("${OUT_PREFIX}_files.json")

# Source snapshot (${OUT_PREFIX}_source.json): the CONTENT behind that tree, so
# the UI can show what was scanned and not only what was found. Takes the file
# list just written (either artifact — both carry the same ScanCode `files[]`
# shape) so the exclusions live in one place. The scanned tree is gone once the
# container exits, which is why the content is captured now. FIRMWARE again does
# its own inside scan-firmware.sh. Best-effort: never aborts.
if [ -n "$SRC_TREE_DIR" ]; then
    SRC_LIST=""
    [ -f "${OUT_PREFIX}_files.json" ] && SRC_LIST="${OUT_PREFIX}_files.json"
    [ -f "${OUT_PREFIX}_scancode.json" ] && SRC_LIST="${OUT_PREFIX}_scancode.json"
    if [ -n "$SRC_LIST" ]; then
        run_optional_step source-snapshot python3 "$LIBDIR/source-snapshot.py" \
            "$SRC_TREE_DIR" "$SRC_LIST" "${OUT_PREFIX}_source.json"
    fi
fi
[ -f "${OUT_PREFIX}_source.json" ] && ARTIFACTS+=("${OUT_PREFIX}_source.json")
# The unpacked copy of an image / build artifact has served its purpose once the
# tree and the snapshot are written. It can be gigabytes, so it goes now rather
# than at container exit.
if [ -n "$UNPACKED_DIR" ] && [ -d "$UNPACKED_DIR" ]; then
    rm -rf "$UNPACKED_DIR"
fi
# Supplier-SBOM header summary (ANALYZE, written before the conversion above).
[ -f "${OUT_PREFIX}_input.json" ] && ARTIFACTS+=("${OUT_PREFIX}_input.json")
# Yocto VEX judgement counts (parse-yocto-spdx.py). Shipped as an artifact because
# the numbers it carries — how many CVEs the build already patched — are not
# recoverable from the CycloneDX or the security report, which list only what is
# still unresolved.
[ -f "${OUT_PREFIX}_yocto_vex.json" ] && ARTIFACTS+=("${OUT_PREFIX}_yocto_vex.json")

# The BOM is fully enriched at this point (stamp/normalize/CPE/EOL/malicious/
# vendored all done) and NOTICE/security below can each run for a while —
# sync now so an interruption in either still leaves a complete, usable BOM.
sync_artifacts

if [ "${GENERATE_NOTICE:-false}" != "true" ]; then
    er_record generate-notice disabled
fi
if [ "${GENERATE_NOTICE:-false}" = "true" ]; then
    run_optional_step generate-notice bash "$LIBDIR/generate-notice.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"
    [ -f "${OUT_PREFIX}_NOTICE.txt" ] && ARTIFACTS+=("${OUT_PREFIX}_NOTICE.txt")
    [ -f "${OUT_PREFIX}_NOTICE.html" ] && ARTIFACTS+=("${OUT_PREFIX}_NOTICE.html")
    # PDF is produced only when a renderer is in the image (SBOM_PDF=true).
    [ -f "${OUT_PREFIX}_NOTICE.pdf" ] && ARTIFACTS+=("${OUT_PREFIX}_NOTICE.pdf")
    sync_artifacts
fi

if [ "${GENERATE_SECURITY:-false}" != "true" ]; then
    er_record scan-security disabled
fi
# A Trivy database mounted at /trivy-db (the plan's trivy-db mount, read-only):
# Trivy reads it as it is, with no update, no download and no write, so the
# scan runs with no network and a read-only root. A mount with no database in
# it fails the step with that reason rather than a download error, and a
# database older than BOMLENS_TRIVY_DB_MAX_AGE_DAYS (7) days degrades it.
TRIVY_DB_MOUNT="/trivy-db"
_trivy_db_ready=true; _trivy_db_age=""
if [ "${GENERATE_SECURITY:-false}" = "true" ] && [ -d "$TRIVY_DB_MOUNT" ]; then
    if [ -f "$TRIVY_DB_MOUNT/db/trivy.db" ]; then
        export TRIVY_CACHE_DIR="$TRIVY_DB_MOUNT" TRIVY_SKIP_DB_UPDATE=true TRIVY_SKIP_JAVA_DB_UPDATE=true TRIVY_OFFLINE_SCAN=true
        _trivy_db_age="$(jq -r '(.UpdatedAt // empty) | sub("\\.[0-9]+"; "") | ((now - fromdateiso8601) / 86400 | floor)' "$TRIVY_DB_MOUNT/db/metadata.json" 2>/dev/null || true)"
        echo "[security] Trivy database: $TRIVY_DB_MOUNT (read as it is, no update${_trivy_db_age:+; $_trivy_db_age day(s) old})"
    else
        _trivy_db_ready=false
        echo "[WARN] security scan skipped: $TRIVY_DB_MOUNT is mounted but holds no Trivy database (db/trivy.db)." >&2
        mark_pipeline_warning "$OUTPUT_FILE" scan-security
        er_record scan-security failed failed "no Trivy database in the trivy-db mount ($TRIVY_DB_MOUNT/db/trivy.db)"
    fi
fi
# CPE index match (FIRMWARE, ROOTFS, BINARY, and a Yocto SPDX 2.2 archive):
# components with no package purl
# but a CPE (a binary syft's classifier named, a library a signature checker
# found, a CPE enrich-cpe.sh added from cpe-name-map.json) are matched against
# the bundled NVD index, since Trivy never reads component.cpe. Runs here, after
# every CPE enrichment step, and writes the sidecar scan-security.sh merges.
# scan-security.sh is told whether it ran, so it can name the components no
# check reached.
BOMLENS_CPE_INDEX_MATCHED=false
_cpe_mode="$SCAN_MODE"
[ "$YOCTO_CPE_MATCH" = true ] && _cpe_mode=YOCTO
case "$_cpe_mode" in FIRMWARE|ROOTFS|BINARY|YOCTO)
    if [ "${GENERATE_SECURITY:-false}" != "true" ]; then
        er_record match-cpe disabled
    else
        _mc_started="$(er_now)"; er_event step.start match-cpe
        _mc_rc=0
        _mc_counts="$(bash "$LIBDIR/match-cpe-index.sh" "$OUTPUT_FILE" "$OUT_PREFIX")" || _mc_rc=$?
        case "$_mc_rc" in
            0) BOMLENS_CPE_INDEX_MATCHED=true
               er_record match-cpe ok "" "" "$_mc_started" "" "$_mc_counts" ;;
            3) er_record match-cpe skipped not_installed "no CPE index in this image" "$_mc_started" ;;
            4) er_record match-cpe disabled "" "CVE_BIN_TOOL_MODE=components-only" "$_mc_started" ;;
            *) echo "[WARN] post-process step 'match-cpe' failed; CVEs of components with no package purl are not reported." >&2
               mark_pipeline_warning "$OUTPUT_FILE" match-cpe
               er_record match-cpe failed failed "" "$_mc_started" ;;
        esac
    fi ;;
esac
export BOMLENS_CPE_INDEX_MATCHED
# Go reachability (--reachability, opt-in): govulncheck judges whether the code
# each Go advisory lives in is reached, from the source's call graph (run in
# stage 1, which has the Go toolchain) or from a Go executable's symbols. The
# judgements go into a CycloneDX VEX (_reachability.cdx.json); scan-security.sh
# then marks the matching findings and counts the unreachable ones apart. Off,
# this does nothing but record the step as disabled. The Go vulnerability
# database is read over the network; without it the step is skipped.
REACHABILITY_DOC=""
_rch_mode=""
case "$SCAN_MODE" in
    SOURCE|POSTPROCESS) _rch_mode=source ;;
    BINARY) _rch_mode=binary ;;
esac
if [ -n "$_rch_mode" ]; then
    if [ "${REACHABILITY:-false}" != "true" ]; then
        rm -f "${OUT_PREFIX}_govulncheck_stage1.json" "${OUT_PREFIX}_govulncheck_stage1.err" "${OUT_PREFIX}_govulncheck_stage1.rc"
        er_record reachability disabled
    else
        _rch_started="$(er_now)"; er_event step.start reachability
        _rch_rc=0
        _rch_out="$(REACHABILITY_NONCE="$REACHABILITY_NONCE" bash "$LIBDIR/reachability.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$_rch_mode" "${TARGET_FILE:-}")" || _rch_rc=$?
        _rch_detail="$(jq -r '.detail // empty' <<<"$_rch_out" 2>/dev/null)" || _rch_detail=""
        case "$_rch_rc" in
            0) REACHABILITY_DOC="${OUT_PREFIX}_reachability.cdx.json"
               ARTIFACTS+=("$REACHABILITY_DOC")
               echo "[reachability] $(jq -r '"\(.exploitable) reached, \(.not_affected) not reached"' <<<"$_rch_out" 2>/dev/null) (govulncheck, $_rch_mode): $REACHABILITY_DOC"
               er_record reachability ok "" "" "$_rch_started" "" \
                   "$(jq -c '{exploitable, not_affected, components}' <<<"$_rch_out" 2>/dev/null)" ;;
            4) REACHABILITY_DOC="${OUT_PREFIX}_reachability.cdx.json"
               ARTIFACTS+=("$REACHABILITY_DOC")
               echo "[WARN] --reachability: ${_rch_detail}; its components get no judgement from it." >&2
               er_record reachability degraded unavailable "$_rch_detail" "$_rch_started" "" \
                   "$(jq -c '{exploitable, not_affected, components}' <<<"$_rch_out" 2>/dev/null)" ;;
            3) echo "[WARN] --reachability skipped: ${_rch_detail}. Allow access to vuln.go.dev and run again." >&2
               er_record reachability skipped unavailable "$_rch_detail" "$_rch_started" ;;
            10) echo "[WARN] --reachability skipped: govulncheck is not in this image. Refresh it (docker pull) and run again." >&2
                er_record reachability skipped not_installed "$_rch_detail" "$_rch_started" ;;
            11) echo "[reachability] nothing to judge: ${_rch_detail}."
                er_record reachability skipped no_input "$_rch_detail" "$_rch_started" ;;
            12) echo "[WARN] --reachability skipped: ${_rch_detail}." >&2
                er_record reachability skipped too_large "$_rch_detail" "$_rch_started" ;;
            *) echo "[WARN] post-process step 'reachability' failed: ${_rch_detail:-see the log above}." >&2
               mark_pipeline_warning "$OUTPUT_FILE" reachability
               er_record reachability failed failed "$_rch_detail" "$_rch_started" ;;
        esac
        sync_artifacts
    fi
fi
export REACHABILITY_DOC
if [ "${GENERATE_SECURITY:-false}" = "true" ] && [ "$_trivy_db_ready" = true ]; then
    run_optional_step scan-security bash "$LIBDIR/scan-security.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"
    _trivy_db_max="${BOMLENS_TRIVY_DB_MAX_AGE_DAYS:-7}"
    case "$_trivy_db_max" in ''|*[!0-9]*) _trivy_db_max=7 ;; esac
    if [[ "$_trivy_db_age" =~ ^[0-9]+$ ]] && [ "$_trivy_db_age" -gt "$_trivy_db_max" ] \
       && jq -e 'has("Results") and (.ScanError | not)' "${OUT_PREFIX}_security.json" >/dev/null 2>&1; then
        echo "[WARN] the Trivy database in $TRIVY_DB_MOUNT is $_trivy_db_age days old; vulnerabilities published since are not reported." >&2
        er_record scan-security degraded unavailable "the Trivy database is $_trivy_db_age days old (over $_trivy_db_max)"
    fi
    [ -f "${OUT_PREFIX}_security.json" ] && ARTIFACTS+=("${OUT_PREFIX}_security.json")
    [ -f "${OUT_PREFIX}_security_trivy.json" ] && ARTIFACTS+=("${OUT_PREFIX}_security_trivy.json")
    [ -f "${OUT_PREFIX}_security.md" ] && ARTIFACTS+=("${OUT_PREFIX}_security.md")
    [ -f "${OUT_PREFIX}_security.html" ] && ARTIFACTS+=("${OUT_PREFIX}_security.html")
    sync_artifacts
fi
# Deep CVE matching (--deep-cve): scan-security.sh runs grype's CPE matcher
# when grype is in this image (the deep-cve image) and DEEP_CVE is not false.
# Asked for with no grype here, it is skipped: fallback when the CLI ran this
# stage without the deep-cve image (see BOMLENS_DEEP_CVE_FALLBACK below).
# A firmware or AI model scan has no package purls for grype to match: the
# step is disabled there whatever was asked, as it is without --security.
case "$SCAN_MODE" in
    FIRMWARE|AIBOM|MODELFILE|DATASET|AIDECLARE)
        if [ "${DEEP_CVE:-}" = "true" ]; then
            er_record deep-cve disabled "" "grype CPE matching does not apply to a $SCAN_MODE scan"
        else
            er_record deep-cve disabled
        fi ;;
    *) if [ "${GENERATE_SECURITY:-false}" != "true" ]; then
           er_record deep-cve disabled
       elif [ "${DEEP_CVE:-}" = "false" ] || { [ "${DEEP_CVE:-}" != "true" ] && ! command -v grype >/dev/null 2>&1; }; then
           er_record deep-cve disabled
       elif ! command -v grype >/dev/null 2>&1; then
           # BOMLENS_DEEP_CVE_FALLBACK: why the CLI ran this stage without
           # the deep-cve image (it could not be pulled, or no deep-cve image
           # of the scanner image's own build is known).
           if [ -n "${BOMLENS_DEEP_CVE_FALLBACK:-}" ]; then
               er_record deep-cve skipped fallback "${BOMLENS_DEEP_CVE_FALLBACK}"
           else
               er_record deep-cve skipped not_installed "grype is not in this image"
           fi
       elif [ "$_trivy_db_ready" != true ]; then
           er_record deep-cve skipped no_input "the security scan did not run"
       elif [ -f "${OUT_PREFIX}_security_grype.json" ]; then
           er_record deep-cve ok
       else
           er_record deep-cve failed failed "grype did not write its result"
       fi ;;
esac

# A supplier's CycloneDX VEX (--vex): keep the statements that apply to this
# SBOM in ${OUT_PREFIX}_vex_imported.json. The SBOM and the security report are
# left as they are. An explicit request the document cannot satisfy is said
# plainly and does not stop the scan: the SBOM is already complete. A document
# with nothing that applies leaves an earlier received file as it was, as the
# web UI's import does.
if [ -n "${VEX_FILE:-}" ]; then
    vex_out="${OUT_PREFIX}_vex_imported.json"
    if [ ! -f "$VEX_FILE" ]; then
        echo "[WARN] --vex skipped: the document is not visible inside the container ($VEX_FILE). If it is a symbolic link, pass the real file." >&2
    elif [ ! -f "$LIBDIR/import-vex.py" ]; then
        echo "[WARN] --vex skipped: this scanner image predates --vex. Refresh it (docker pull) and run again." >&2
    else
        vex_tmp="${vex_out}.tmp.$$"
        vex_rc=0
        vex_json="$(python3 "$LIBDIR/import-vex.py" "$OUTPUT_FILE" "$VEX_FILE" "$vex_tmp" 2>/dev/null)" || vex_rc=$?
        case "$vex_rc" in
            0)
                if [ "$(printf '%s' "$vex_json" | jq -r '.imported')" = "0" ]; then
                    echo "[WARN] --vex: no statement in the document applies to a component of this SBOM ($(printf '%s' "$vex_json" | jq -r '.unmatched') name components it does not contain, $(printf '%s' "$vex_json" | jq -r '.ignored') ignored); nothing was saved." >&2
                elif mv "$vex_tmp" "$vex_out"; then
                    ARTIFACTS+=("$vex_out")
                    echo "[vex] $(printf '%s' "$vex_json" | jq -r '"\(.imported) statement(s) apply to this SBOM, \(.unmatched) name a component it does not contain, \(.ignored) ignored"') -> $(basename "$vex_out")"
                else
                    echo "[WARN] --vex: could not save $(basename "$vex_out") in the output folder." >&2
                fi
                ;;
            3)
                echo "[WARN] --vex skipped: the document describes $(printf '%s' "$vex_json" | jq -r '.vexProduct'), but this scan is $(printf '%s' "$vex_json" | jq -r '.scanProduct'). Use the VEX for this product and version." >&2
                ;;
            4)
                echo "[WARN] --vex skipped: the document holds too many statements to import." >&2
                ;;
            *)
                echo "[WARN] --vex skipped: the file is not a readable CycloneDX VEX document (JSON with bomFormat CycloneDX and a vulnerabilities list)." >&2
                ;;
        esac
        rm -f "$vex_tmp"
    fi
    sync_artifacts
fi

# --fail-on: judge the requested conditions now that the security report and the
# SBOM enrichments (malicious-package, license conflict) are final. The verdict
# goes to a small sidecar the CLI turns into an exit code; if this step cannot run
# there is no sidecar, and the CLI reports that rather than passing.
if [ -n "${FAIL_ON:-}" ]; then
    bash "$LIBDIR/evaluate-gate.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$FAIL_ON" \
        || echo "[WARN] --fail-on: the conditions could not be evaluated." >&2
    [ -f "${OUT_PREFIX}_gate.result" ] && ARTIFACTS+=("${OUT_PREFIX}_gate.result")
    sync_artifacts
fi

# Risk report (오픈소스위험분석보고서): always for ANALYZE, and for every other
# mode when GENERATE_REPORT=true (the CLI/UI default, opt-out via --no-report).
# It re-aggregates the notice + security artifacts already produced above.
# Conformance artifacts now exist in every generation mode (ANALYZE, the AI SBOM
# modes, and SOURCE/POSTPROCESS/ROOTFS/IMAGE/BINARY/FIRMWARE/MERGE); the [ -f ]
# guard only matters for the remaining modes (UI/DIFF), where generate-risk-report.sh
# drops the 포맷 검증 section accordingly.
# Placed before SPDX export/signing below: on failure, run_optional_step stamps
# $OUTPUT_FILE, and a stamp written after cosign has already signed it would
# invalidate that signature (the .sig would no longer verify against the
# now-different file).
if [ "$SCAN_MODE" = "ANALYZE" ] || [ "${GENERATE_REPORT:-false}" = "true" ]; then
    # "result" is the bare pass/fail sidecar --fail-on-conformance reads; it
    # never appears in server.py's ARTIFACT_SUFFIXES (not human-facing), only
    # in ARTIFACTS here so it actually reaches HOST_OUTPUT_DIR.
    for ext in json md html result; do
        [ -f "${OUT_PREFIX}_conformance.${ext}" ] && ARTIFACTS+=("${OUT_PREFIX}_conformance.${ext}")
    done
    # Facts for the CLI's closing summary (written by validate-sbom.sh; not
    # human-facing, so it is not in server.py's ARTIFACT_SUFFIXES either).
    [ -f "${OUT_PREFIX}_summary.result" ] && ARTIFACTS+=("${OUT_PREFIX}_summary.result")
    run_optional_step generate-risk-report bash "$LIBDIR/generate-risk-report.sh" "$OUT_PREFIX" "$PROJECT_NAME" "$SCAN_MODE"
    [ -f "${OUT_PREFIX}_risk-report.md" ] && ARTIFACTS+=("${OUT_PREFIX}_risk-report.md")
    [ -f "${OUT_PREFIX}_risk-report.html" ] && ARTIFACTS+=("${OUT_PREFIX}_risk-report.html")
fi

# SBOM body size cap: a scan run against --target (not through the web UI's
# upload) never passes through docker/web/server.py's MAX_BYTES["sbom"] check,
# and the UI's own /results and download paths read a generated SBOM off disk
# with no size gate of their own -- so nothing has ever refused an oversized
# document produced this way, and a browser tab fetching + parsing one in full
# is a real memory/hang risk. This reuses MAX_BYTES["sbom"]'s already-measured
# 100 MB figure as a consistent budget for one document rather than inventing
# a second number; the two are not wired together, so a legitimate change to
# one is not expected to move the other in lockstep. Placed after every
# enrichment step and before SPDX export/signing below, for the same reason
# generate-risk-report is: a stamp written after cosign has already signed
# would invalidate that signature. Oversized is stamped, not truncated or
# rejected -- a cut CycloneDX component list is a worse blind spot than a
# large file, and the scan already succeeded.
SBOM_SIZE_CAP="${SBOM_SIZE_CAP_BYTES:-$((100 * 1024 * 1024))}"   # 100 MB default; override for testing
# The `| tr` here is deliberate, not incidental: under `set -e`, a bare
# `wc -c < "$OUTPUT_FILE"` failing would abort the whole scan at its last
# step, so the pipeline's exit status is `tr`'s (always 0) instead -- an
# unreadable/missing OUTPUT_FILE just yields an empty $SBOM_BYTES, guarded
# below. SBOM_SIZE_CAP_BYTES is a test-only override (never documented for
# end users); a non-numeric value here would make the -gt comparison print
# "integer expression expected" and skip the cap rather than fail the scan.
SBOM_BYTES="$(wc -c < "$OUTPUT_FILE" 2>/dev/null | tr -d '[:space:]')"
if [ -n "$SBOM_BYTES" ] && [ "$SBOM_BYTES" -gt "$SBOM_SIZE_CAP" ]; then
    echo "[WARN] SBOM is $SBOM_BYTES bytes, over the $SBOM_SIZE_CAP-byte budget the web UI expects."
    mark_document_status "$OUTPUT_FILE" "bomlens:sbom-oversized" "${SBOM_BYTES} bytes"
fi

# SPDX export (opt-in): convert the FINISHED CycloneDX BOM to SPDX 2.3 JSON as an
# additional artifact. Runs after every enrichment (so the SPDX reflects the final
# BOM) and before signing (so an enabled --sign covers it too). CycloneDX remains
# the working/upload format — Trivy, notice and Dependency-Track all consume it.
SPDX_FILE="${OUT_PREFIX}_bom.spdx.json"
if [ "${GENERATE_SPDX:-false}" = "true" ]; then
    SPDX_ARGS=("$OUTPUT_FILE" "$SPDX_FILE")
    [ "${BYTE_STABLE:-false}" = "true" ] && SPDX_ARGS+=(--stable)
    if bash "$LIBDIR/convert-to-spdx.sh" "${SPDX_ARGS[@]}"; then
        ARTIFACTS+=("$SPDX_FILE")
    else
        echo "[WARN] SPDX export failed; the CycloneDX SBOM and other artifacts are unaffected."
    fi
fi

# SPDX 3.0.1 AI document (AI scans, on unless GENERATE_SPDX3=false): the
# finished CycloneDX BOM written with the AI and Dataset profiles, plus a check
# saying which fields came from the scan, which from the publisher's declaration,
# and which required ones are still open. The declaration is the file given with
# --ai-declare, or else the one a previous run or the web UI left in the output
# folder. A refused declaration is reported and the document is written without
# it, as a draft. Like the SPDX 2.3 export, a failure here leaves the CycloneDX
# SBOM and everything else untouched. Before signing, so --sign covers it.
SPDX3_FILE="${OUT_PREFIX}_bom.spdx3.json"
if [ "$AI_MODEL_SCAN" = "true" ] && [ "${GENERATE_SPDX3:-true}" != "false" ]; then
    SPDX3_DECL=""
    if [ -n "${AI_DECLARATION_FILE:-}" ]; then
        if [ -f "$AI_DECLARATION_FILE" ]; then
            SPDX3_DECL="$AI_DECLARATION_FILE"
        else
            echo "[WARN] --ai-declare: the declaration is not visible inside the container ($AI_DECLARATION_FILE). If it is a symbolic link, pass the real file." >&2
        fi
    elif [ -n "$HOST_OUTPUT_DIR" ] && [ -f "$HOST_OUTPUT_DIR/${OUT_PREFIX}_ai-declaration.json" ]; then
        SPDX3_DECL="$HOST_OUTPUT_DIR/${OUT_PREFIX}_ai-declaration.json"
        echo "[INFO] SPDX 3.0.1: applying the declaration kept in the output folder (${OUT_PREFIX}_ai-declaration.json)."
    fi
    # --prefix= keeps a prefix that begins with "-" from reading as an option.
    SPDX3_ARGS=(convert --bom "$OUTPUT_FILE" --out-dir . "--prefix=$OUT_PREFIX")
    [ "${BYTE_STABLE:-false}" = "true" ] && SPDX3_ARGS+=(--stable)
    spdx3_rc=0
    if [ -n "$SPDX3_DECL" ]; then
        # With --declaration-fallback a refused declaration still gives the
        # document (exit 2), and the check records the refusal for the web UI.
        python3 "$LIBDIR/convert-to-spdx3-ai.py" "${SPDX3_ARGS[@]}" --declaration "$SPDX3_DECL" \
            --declaration-fallback || spdx3_rc=$?
        if [ "$spdx3_rc" -eq 2 ] && [ "$SCAN_MODE" = "AIDECLARE" ]; then
            # Here the declaration is the input, not a supplement: without it
            # the result is a model with a name and nothing else.
            echo "[ERROR] The AI declaration was refused (reasons above). Fix the file and run again." >&2
            exit 1
        fi
        if [ "$spdx3_rc" -eq 2 ]; then
            echo "[ERROR] The AI declaration was refused (reasons above). The SPDX 3.0.1 document is written without it, as a draft. Fix the file and run again." >&2
            SPDX3_DECL=""
            spdx3_rc=0
        fi
    else
        python3 "$LIBDIR/convert-to-spdx3-ai.py" "${SPDX3_ARGS[@]}" || spdx3_rc=$?
    fi
    if [ "$spdx3_rc" -eq 0 ] && [ -f "$SPDX3_FILE" ]; then
        ARTIFACTS+=("$SPDX3_FILE" "${OUT_PREFIX}_spdx3-check.json" "${OUT_PREFIX}_spdx3-check.md")
        # The empty declaration for this scan: the fields a person fills, for
        # the datasets and base models this scan found. Edit it and pass it
        # back with --ai-declare.
        if python3 "$LIBDIR/convert-to-spdx3-ai.py" template --bom "$OUTPUT_FILE" --out-dir . \
               "--prefix=$OUT_PREFIX" 2>/dev/null; then
            ARTIFACTS+=("${OUT_PREFIX}_ai-declaration.template.json")
        fi
        # Keep an accepted --ai-declare file with the results, so a re-scan and
        # the web UI start from it. A file already in the output folder is
        # that same file and is left where it is.
        if [ -n "${AI_DECLARATION_FILE:-}" ] && [ "$SPDX3_DECL" = "$AI_DECLARATION_FILE" ]; then
            cp "$AI_DECLARATION_FILE" "${OUT_PREFIX}_ai-declaration.json" \
                && ARTIFACTS+=("${OUT_PREFIX}_ai-declaration.json")
        fi
    else
        echo "[WARN] SPDX 3.0.1 AI document failed; the CycloneDX SBOM and other artifacts are unaffected."
    fi
fi

if [ "${SIGN_SBOM:-false}" = "true" ]; then
    if command -v cosign >/dev/null 2>&1 && [ -n "${COSIGN_KEY:-}" ]; then
        echo "[INFO] Signing SBOM with cosign..."
        _sign_started="$(er_now)"
        SIGN_FAILED=0
        # COSIGN_SIGN_FLAGS keeps the detached `.sig` next to the SBOM and keeps
        # the signature local. cosign 3 defaults to the Sigstore bundle format and
        # to resolving a signing config, both of which reject --output-signature
        # and --tlog-upload=false; the two opt-outs restore the documented
        # artifact. They are accepted by cosign 2 as well, so the command works
        # on either pinned version. cosign marks them deprecated, so the bundle
        # format is where this has to move once a plain detached signature is no
        # longer offered.
        COSIGN_SIGN_FLAGS=(--yes --use-signing-config=false --tlog-upload=false --new-bundle-format=false)
        if cosign sign-blob "${COSIGN_SIGN_FLAGS[@]}" --key "$COSIGN_KEY" \
               --output-signature "${OUTPUT_FILE}.sig" "$OUTPUT_FILE"; then
            ARTIFACTS+=("${OUTPUT_FILE}.sig")
        else
            echo "[ERROR] cosign could not sign the SBOM (check COSIGN_KEY / COSIGN_PASSWORD)."; SIGN_FAILED=1
        fi
        if [ -f "$SPDX_FILE" ]; then
            if cosign sign-blob "${COSIGN_SIGN_FLAGS[@]}" --key "$COSIGN_KEY" \
                   --output-signature "${SPDX_FILE}.sig" "$SPDX_FILE"; then
                ARTIFACTS+=("${SPDX_FILE}.sig")
            else
                echo "[ERROR] cosign could not sign the SPDX SBOM."; SIGN_FAILED=1
            fi
        fi
        # A draft is signed too: the signature says this file came from this
        # scan, not that the document is complete.
        if [ -f "$SPDX3_FILE" ]; then
            if cosign sign-blob "${COSIGN_SIGN_FLAGS[@]}" --key "$COSIGN_KEY" \
                   --output-signature "${SPDX3_FILE}.sig" "$SPDX3_FILE"; then
                ARTIFACTS+=("${SPDX3_FILE}.sig")
            else
                echo "[ERROR] cosign could not sign the SPDX 3.0.1 AI document."; SIGN_FAILED=1
            fi
        fi
        # The conformance sidecar files (generated earlier, before signing could
        # run at all) still say the SBOM author signature element is missing.
        # That was true then, but the signing outcome above is the fact that
        # actually matters now. Re-run validate-sbom.sh so the report reflects
        # it: the script only ever reads $OUTPUT_FILE and writes the
        # ${OUT_PREFIX}_conformance.* sidecar files, so re-running it after
        # signing cannot touch the just-signed SBOM, which would invalidate the
        # signature. Unlike run_optional_step, whose failure path stamps
        # $OUTPUT_FILE, this call is unwrapped so a failure here cannot do that
        # either. Skipped when this mode never produced a conformance report.
        if [ -f "${OUT_PREFIX}_conformance.json" ]; then
            MODE="$CONFORMANCE_MODE" SIGN_FAILED="$SIGN_FAILED" bash "$LIBDIR/validate-sbom.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME" \
                || echo "[WARN] could not refresh the conformance check report's signature status after signing." >&2
        fi
        # A requested signature that was not produced is a failure on a
        # supply-chain tool. Do not exit 0 leaving the user to believe their
        # SBOM is signed when no .sig exists.
        if [ "$SIGN_FAILED" != "0" ]; then
            er_record sign failed failed "" "$_sign_started"
            echo "[ERROR] --sign was requested but a signature could not be produced. The SBOM and other artifacts were still written."
            # The refreshed conformance report above only lives in the container;
            # the next sync_artifacts pass (near the end of this script) is what
            # copies it to the host, and exit below skips straight past that.
            # Run it here too so a supplier reading the failure still gets the
            # accurate report, not the pre-signing snapshot. Re-copying files
            # this run already sent to the host (the SBOM, NOTICE, ...) is a
            # harmless no-op (see sync_artifacts's own comment).
            sync_artifacts
            exit 1
        fi
        er_record sign ok "" "" "$_sign_started"
    elif ! command -v cosign >/dev/null 2>&1; then
        echo "[WARN] --sign requested but cosign/COSIGN_KEY unavailable; skipping."
        er_record sign skipped not_installed "cosign is not in this image"
    else
        echo "[WARN] --sign requested but cosign/COSIGN_KEY unavailable; skipping."
        er_record sign skipped no_input "COSIGN_KEY is not set"
    fi
else
    er_record sign disabled
fi

# AI compliance profile (AI SBOMs only): a governance one-pager that re-aggregates
# the G7 conformance status, the regulatory crosswalk and the license-review flags
# — no new scan. generate-ai-profile.sh self-gates on the presence of G7 checks in
# the conformance report, so it is a clean no-op for a plain (non-AI) SBOM; we wire
# it only for the modes that can carry a machine-learning-model component.
if [ "$AI_MODEL_SCAN" = "true" ] || [ "$SCAN_MODE" = "ANALYZE" ]; then
    if bash "$LIBDIR/generate-ai-profile.sh" "$OUT_PREFIX" "$PROJECT_NAME"; then
        for ext in json md; do
            [ -f "${OUT_PREFIX}_ai-profile.${ext}" ] && ARTIFACTS+=("${OUT_PREFIX}_ai-profile.${ext}")
        done
    fi
fi

# ========================================================
# Copy artifacts to host output (always) — final pass. sync_artifacts already
# ran after the BOM was fully enriched and after NOTICE/security, so this
# call's real job is the tail end: SPDX, signatures, conformance, risk-report
# and the AI profile.
# ========================================================
sync_artifacts

# A refused --component-versions file: everything above is written, without
# the versions it held. Said last so it is the line the user reads, and a
# non-zero exit, since the user asked for those versions and did not get them.
if [ -n "$CV_REFUSED" ]; then
    echo "[ERROR] --component-versions: the file was refused, so none of its versions were applied: ${CV_REFUSED}" >&2
    echo "[ERROR]   The SBOM and the other files were written without them. Fix the file (CSV: name,version[,reason]) and run the scan again." >&2
    exit 1
fi

# ========================================================
# Upload handling (optional — Dependency-Track or TRUSCA)
# ========================================================
# UPLOAD_TARGET selects the wire contract:
#   dependency-track (default) — POST /api/v1/bom, X-Api-Key, autoCreate
#   trusca                     — POST /v1/projects/{id}/sbom-ingest, Bearer token.
#                                TRUSCA's native ingest is NOT Dependency-Track
#                                compatible (different path/auth/fields), so it
#                                needs a distinct uploader mode.
if [ "${UPLOAD_ENABLED:-true}" = "false" ]; then
    echo "[INFO] Generate-only mode. Done."
    exit 0
fi

# curl exits non-zero when the request never completes — connection refused, DNS
# failure, timeout. Under `set -e` that ended the run with curl's own exit code
# and no explanation, so a closed upload server looked like a failed scan even
# though every artifact had already been written. Report what happened, say the
# artifacts are fine, and exit 1 like the HTTP-rejected path does.
report_unreachable_upload() {
    local rc="$1" url="$2"
    [ "$rc" -eq 0 ] && return 0
    echo "[ERROR] Upload to $url did not complete (curl exit $rc: no response)."
    echo "[INFO] The artifacts listed above are complete and were saved."
    echo "[INFO] Use --generate-only to skip the upload, or set API_URL to a server that is up."
    exit 1
}

if [ "${UPLOAD_TARGET:-dependency-track}" = "trusca" ]; then
    echo "[2/2] Uploading to TRUSCA..."
    if [ -z "$API_URL" ] || [ -z "$API_KEY" ] || [ -z "${TRUSCA_PROJECT_ID:-}" ]; then
        echo "[ERROR] TRUSCA upload needs API_URL, API_KEY (Bearer token), and TRUSCA_PROJECT_ID."; exit 1
    fi
    # The ingest endpoint accepts the already-generated CycloneDX SBOM and runs
    # the back half of TRUSCA's scan pipeline (components + trivy + findings).
    CURL_RC=0
    RESPONSE=$(curl -s -w "\n%{http_code}" --connect-timeout 10 -X POST "$API_URL/v1/projects/$TRUSCA_PROJECT_ID/sbom-ingest" \
        -H "Authorization: Bearer $API_KEY" \
        -F "sbom=@$OUTPUT_FILE" \
        -F "ref=${TRUSCA_REF:-main}" \
        -F "release=${TRUSCA_RELEASE:-$PROJECT_VERSION}") || CURL_RC=$?
    report_unreachable_upload "$CURL_RC" "$API_URL"
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    # A successful ingest is accepted asynchronously (202 + queued scan id). We
    # confirm acceptance and print the scan id; tracking to completion is done
    # in the TRUSCA UI (GET /v1/scans/{id}).
    if [ "$HTTP_CODE" = "202" ]; then
        SCAN_ID=$(echo "$BODY" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        echo "[SUCCESS] Accepted by TRUSCA (HTTP 202). scan id: ${SCAN_ID:-unknown}"
        [ -n "$SCAN_ID" ] && echo "[INFO] Track status: $API_URL/v1/scans/$SCAN_ID"
    else
        echo "[ERROR] TRUSCA ingest failed (HTTP $HTTP_CODE)"; echo "Response: $BODY"; exit 1
    fi
    exit 0
fi

echo "[2/2] Uploading to Dependency Track..."
if [ -z "$API_KEY" ] || [ -z "$API_URL" ]; then
    echo "[ERROR] API_KEY and API_URL are required for upload."; exit 1
fi
DT_VERSION_JSON=""
if ! DT_VERSION_JSON="$(curl -s --max-time 5 "$API_URL/api/version" 2>/dev/null)"; then
    echo "[WARN] Cannot reach Dependency Track at $API_URL."
fi
# The server's version, when /api/version gives one in the x.y.z form.
DT_VERSION="$(printf '%s' "$DT_VERSION_JSON" | jq -r '.version // empty' 2>/dev/null \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
dt_upload() {
    CURL_RC=0
    RESPONSE=$(curl -s -w "\n%{http_code}" --connect-timeout 10 -X POST "$API_URL/api/v1/bom" \
        -H "Content-Type: multipart/form-data" \
        -H "X-Api-Key: $API_KEY" \
        -F "autoCreate=true" \
        -F "projectName=$PROJECT_NAME" \
        -F "projectVersion=$PROJECT_VERSION" \
        -F "bom=@$1") || CURL_RC=$?
    report_unreachable_upload "$CURL_RC" "$API_URL"
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
}
dt_upload "$OUTPUT_FILE"
# Dependency-Track reads CycloneDX 1.7 from 4.14.4 and 5.1.0 on; an older
# server refuses a 1.7 BOM (a scan that asked for 1.7, and AI model and dataset SBOMs)
# as invalid. When /api/version names such a server, or names no version at
# all, a 400 is answered once more with a 1.6 copy (cdx-copy-as-1.6.sh, which
# also rewrites what 1.6 does not allow), and the delivered SBOM keeps its
# version. A server that reads 1.7 gets no second try: its 400 is about
# something else.
dt_reads_17() {
    # 0: reads 1.7; 1: does not; 2: the version is not known.
    [ -n "$DT_VERSION" ] || return 2
    local major minor patch
    major="${DT_VERSION%%.*}"
    minor="${DT_VERSION#*.}"; minor="${minor%%.*}"
    patch="${DT_VERSION#*.*.}"; patch="${patch%%[!0-9]*}"
    [ -n "$patch" ] || patch=0
    if [ "$major" -lt 4 ]; then return 1; fi
    if [ "$major" -eq 4 ]; then
        if [ "$minor" -lt 14 ] || { [ "$minor" -eq 14 ] && [ "$patch" -lt 4 ]; }; then return 1; fi
        return 0
    fi
    if [ "$major" -eq 5 ] && [ "$minor" -eq 0 ]; then return 1; fi
    return 0
}
if [ "$HTTP_CODE" = "400" ] && [ "$(jq -r '.specVersion // ""' "$OUTPUT_FILE" 2>/dev/null)" = "1.7" ]; then
    DT_READS_17=0
    dt_reads_17 || DT_READS_17=$?
    if [ "$DT_READS_17" = 0 ]; then
        echo "[WARN] Dependency-Track $DT_VERSION reads CycloneDX 1.7, so the refusal (HTTP 400) is not about the version; the SBOM is not sent again."
    else
        DT_COPY="$(mktemp)"
        if bash "$LIBDIR/cdx-copy-as-1.6.sh" "$OUTPUT_FILE" "$DT_COPY" 2>/dev/null; then
            if [ "$DT_READS_17" = 1 ]; then
                echo "[WARN] Dependency-Track $DT_VERSION refused the CycloneDX 1.7 SBOM (HTTP 400); it reads 1.7 from 4.14.4 and 5.1.0 on. Sending a CycloneDX 1.6 copy instead (delivered SBOM unchanged)."
            else
                echo "[WARN] Dependency-Track refused the CycloneDX 1.7 SBOM (HTTP 400) and its version is not known; servers before 4.14.4 and 5.1.0 do not read 1.7. Sending a CycloneDX 1.6 copy once (delivered SBOM unchanged)."
            fi
            DT_FIRST_BODY="$BODY"
            dt_upload "$DT_COPY"
            if ! { [[ "$HTTP_CODE" =~ ^[0-9]+$ ]] && [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; }; then
                echo "[ERROR] The CycloneDX 1.6 copy was refused too (HTTP $HTTP_CODE)."
                echo "Response to the 1.7 SBOM: $DT_FIRST_BODY"
            fi
        fi
        rm -f "$DT_COPY"
    fi
fi
# A response that is not a status line at all (proxy banner, truncated body)
# would make the numeric comparison below abort the script instead of reporting.
if ! [[ "$HTTP_CODE" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] Upload to $API_URL returned no status code."; echo "Response: $BODY"; exit 1
fi
if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ] && echo "$BODY" | grep -q "token"; then
    echo "[SUCCESS] Upload complete!"
else
    echo "[ERROR] Upload failed (HTTP $HTTP_CODE)"; echo "Response: $BODY"; exit 1
fi
