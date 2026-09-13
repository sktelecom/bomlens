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
#   - ANALYZE     : validate + convert a supplier SBOM -> conformance + risk report
#   - MERGE       : combine several CycloneDX SBOMs (layered server delivery)
#   - DIFF        : compare two already-generated AI-model SBOMs (drift report)
#   - POSTPROCESS : consume an already-generated SBOM
# then runs the common pipeline: normalize -> notice -> security -> sign.
# ========================================================

SCAN_MODE="${MODE:-POSTPROCESS}"
LIBDIR="/usr/local/lib/sbom"

# --- UI mode: hand off to the web server, no project metadata needed ---
if [ "$SCAN_MODE" = "UI" ]; then
    echo "[INFO] Starting BomLens Web UI on port ${UI_PORT:-8080}..."
    exec python3 /usr/local/lib/sbom-web/server.py
fi

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

# Report language for the human-facing conformance + AI-profile reports. Only
# en (default) or ko; the report generators read REPORT_LANG directly, so export
# a normalized value here for both of them. Anything else falls back to English
# and never aborts the run.
case "${REPORT_LANG:-en}" in ko) REPORT_LANG="ko" ;; *) REPORT_LANG="en" ;; esac
export REPORT_LANG

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
    if [ "$lang" = "android" ]; then
        api=$(android_api "$src")
        img="${ANDROID_IMAGE_PREFIX}${api}:latest"
        echo "[INFO] Android source (compileSdk=$api) -> $img"
        # Not a published image — the Android SDK inside it is not open source
        # and its terms bar redistribution, so it is built where it is used.
        if ! docker image inspect "$img" >/dev/null 2>&1; then
            echo "[ERROR] Android SDK image not found: $img"
            echo "        Build it on the host once, then re-run:"
            echo "          docker build --build-arg ANDROID_API=$api -t $img docker/android"
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
    local logf cidf; logf=$(mktemp); cidf=$(mktemp); rm -f "$cidf"
    local prep_env; read -ra prep_env <<< "$(build_prep_env_args)"
    docker run -u 0:0 \
        --cidfile "$cidf" \
        --volumes-from "$self" \
        -e HOME=/tmp/sbomhome \
        -e MAVEN_OPTS=-Dmaven.repo.local=/tmp/sbomhome/.m2 \
        -e FETCH_LICENSE="$FETCH_LICENSE" \
        -e PROJECT_NAME="$PROJECT_NAME" \
        -e PROJECT_VERSION="$PROJECT_VERSION" \
        -e HOST_GOTOOLCHAIN="${GOTOOLCHAIN:-}" -e GOPROXY -e GOSUMDB \
        "${prep_env[@]}" \
        --entrypoint sh "$img" \
        -c "$prep" _ "$src" "$bom_path" "$CDX_SPEC_VERSION" 2>&1 | tee "$logf"
    rc=${PIPESTATUS[0]}
    local cid=""
    [ -s "$cidf" ] && cid=$(cat "$cidf")
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
            CDXGEN_FAIL_REASON="cdxgen-unavailable"
            echo "[WARN] cdxgen sibling container failed (rc=$rc)."
        fi
        [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1
        rm -f "$logf" "$cidf"
        return 1
    fi
    [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1
    rm -f "$logf" "$cidf"
    if [ "$bom_path" != "$outdir/$out" ] && [ -f "$bom_path" ]; then
        mv "$bom_path" "$outdir/$out"
    fi
    if [ ! -f "$outdir/$out" ]; then
        CDXGEN_FAIL_REASON="cdxgen-unavailable"
        echo "[WARN] cdxgen produced no SBOM at $bom_path."; return 1
    fi
    return 0
}

# Record that the SBOM came from the shallow syft fallback (direct deps only),
# with the reason, so the web UI can explain why the dependency graph is thin.
# Mirrors the other bomlens:* metadata signals the server reads (survives
# stamp/normalize like bomlens:suggest-identify-vendored does).
mark_sbom_degraded() {
    local file="$1" reason="$2" tmp
    [ -f "$file" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    tmp="${file}.degraded.tmp"
    if jq --arg r "$reason" \
        '(.metadata.properties) = ((.metadata.properties // []) + [{name:"bomlens:sbom-tool-degraded", value:$r}])' \
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
# (MODELFILE, from the file itself) and the dataset path (DATASET, from a
# published research item). They share the AI post-processing — risk assessment,
# G7 conformance, the AI profile — and skip the package-oriented enrichments,
# which have no purl, no CPE and no release cycle to match on.
case "$SCAN_MODE" in
    AIBOM|MODELFILE|DATASET) AI_MODEL_SCAN=true ;;
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
# pipeline standardizes on the version cdx-version.sh names (cdxgen is run
# with --spec-version "$CDX_SPEC_VERSION"; convert-to-cdx.sh writes it; the
# docs promise it) and the bundled Trivy 0.70 cannot decode 1.7 ("invalid
# specification version"), which would silently empty the security report.
# The selector keeps syft output aligned with cdxgen and readable by Trivy.
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
        if [ -S /var/run/docker.sock ] && command -v docker >/dev/null 2>&1 && [ -n "$SOURCE_ROOT_HOST" ]; then
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
                syft "dir:$SRC_ROOT" -o "cyclonedx-json@$CDX_SPEC_VERSION" > "$OUTPUT_FILE" 2>/dev/null \
                    || { echo "[ERROR] syft source scan failed."; exit 1; }
                mark_sbom_degraded "$OUTPUT_FILE" "${CDXGEN_FAIL_REASON:-cdxgen-unavailable}"
            fi
        else
            echo "[1/2] syft: source dir $SRC_ROOT (manifest-only; docker.sock/CLI/host-path unavailable)"
            syft "dir:$SRC_ROOT" -o "cyclonedx-json@$CDX_SPEC_VERSION" > "$OUTPUT_FILE" 2>/dev/null \
                || { echo "[ERROR] syft source scan failed."; exit 1; }
            mark_sbom_degraded "$OUTPUT_FILE" "cdxgen-unavailable"
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
        if [ ! -S /var/run/docker.sock ]; then
            echo "[ERROR] Docker socket not mounted: -v /var/run/docker.sock:/var/run/docker.sock"; exit 1
        fi
        echo "[1/2] syft: Docker image $TARGET_IMAGE"
        if ! syft "$TARGET_IMAGE" -o "cyclonedx-json@$CDX_SPEC_VERSION" > "$OUTPUT_FILE" 2>/dev/null; then
            echo "[ERROR] syft failed (image missing or inaccessible)."; exit 1
        fi
        ;;

    BINARY)
        if [ -z "$TARGET_FILE" ] || [ ! -f "$TARGET_FILE" ]; then echo "[ERROR] TARGET_FILE not found: $TARGET_FILE"; exit 1; fi
        echo "[1/2] syft: binary $TARGET_FILE"
        if ! syft "file:$TARGET_FILE" -o "cyclonedx-json@$CDX_SPEC_VERSION" > "$OUTPUT_FILE" 2>&1; then
            echo "[WARN] syft binary scan failed; emitting minimal SBOM."
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
        if [ -z "$TARGET_FILE" ] || [ ! -f "$TARGET_FILE" ]; then echo "[ERROR] TARGET_FILE not found: $TARGET_FILE"; exit 1; fi
        echo "[1/2] firmware: unpack + identify $TARGET_FILE"
        # scan-firmware.sh is best-effort (always emits a valid SBOM); the empty-file
        # guard below still catches a hard failure.
        # OUT_PREFIX lets scan-firmware.sh drop a Trivy-shaped cve-bin-tool CVE
        # sidecar (${OUT_PREFIX}_security_cvebintool.json) that scan-security.sh
        # merges into the security report — firmware binaries carry no purl/CPE,
        # so Trivy alone matches nothing; cve-bin-tool matches by version signature.
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
        if [ -z "$DATASET_REF" ]; then echo "[ERROR] DATASET_REF required for DATASET mode."; exit 1; fi
        echo "[1/2] figshare: describe $DATASET_REF"
        python3 "$LIBDIR/scan-figshare.py" "$DATASET_REF" "$OUTPUT_FILE" "$PROJECT_VERSION"
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
        # SBOM was already generated by a cdxgen language image (scan-sbom.sh).
        echo "[1/2] Post-processing existing SBOM: $OUTPUT_FILE"
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
            # No conformance report: conformance measures a document someone sent
            # us against the submission criteria, and there is no document here.
        else
        # Supplier-submitted SBOM (CycloneDX or SPDX). Validate the ORIGINAL for
        # conformance, then convert to CycloneDX so the common pipeline is reused.
        if [ -z "$ANALYZE_SBOM" ] || [ ! -f "$ANALYZE_SBOM" ]; then
            echo "[ERROR] ANALYZE_SBOM not found: $ANALYZE_SBOM"; exit 1
        fi
        # An SPDX 2.x archive is not a document: it is a bundle of them, and the
        # image document inside is an index listing one package. Measuring either
        # against the submission criteria would report an unparseable or almost
        # empty SBOM for something we read 36 packages out of, so conformance is
        # skipped here for the same reason the manifest path skips it — there is
        # no submitted document to judge.
        case "$ANALYZE_SBOM" in
            *.spdx.tar.zst) YOCTO_ARCHIVE=true ;;
            *)              YOCTO_ARCHIVE=false ;;
        esac
        if [ "$YOCTO_ARCHIVE" = "false" ]; then
        echo "[1/2] Validating supplier SBOM (conformance, original input)..."
        # Conformance never aborts the pipeline (best-effort report).
        run_optional_step conformance bash "$LIBDIR/validate-sbom.sh" "$ANALYZE_SBOM" "$OUT_PREFIX" "$PROJECT_NAME"
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
        if [ "$YOCTO_RC" != 0 ]; then
            [ "$YOCTO_RC" = 3 ] || echo "[analyze] WARN: Yocto SPDX parser failed (rc=$YOCTO_RC); using the generic converter." >&2
            if ! bash "$LIBDIR/convert-to-cdx.sh" "$ANALYZE_SBOM" "$OUTPUT_FILE"; then
                echo "[ERROR] could not convert supplier SBOM to CycloneDX."; exit 1
            fi
        fi
        fi
        ;;

    *)
        echo "[ERROR] Unknown MODE: $SCAN_MODE (expected SOURCE/IMAGE/BINARY/ROOTFS/FIRMWARE/AIBOM/MODELFILE/DATASET/ANALYZE/MERGE/POSTPROCESS/UI/DIFF)"
        exit 1
        ;;
esac

if [ ! -s "$OUTPUT_FILE" ]; then echo "[ERROR] SBOM file is empty: $OUTPUT_FILE"; exit 1; fi
echo "[INFO] SBOM ready: $OUTPUT_FILE"

# Warn (don't fail) when the SBOM has no components. A genuine no-dependency
# project can legitimately be empty, but more often this means the scan saw
# nothing — a missing lockfile or an empty/unshared source mount.
if command -v jq >/dev/null 2>&1; then
    COMP_COUNT=$(jq '[.components[]?] | length' "$OUTPUT_FILE" 2>/dev/null || echo 0)
    if [ "${COMP_COUNT:-0}" -eq 0 ]; then
        echo "[WARN] SBOM has 0 components — the scan may have found nothing (missing lockfile or empty source)."
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
    if bash "$LIBDIR/identify-vendored.sh" "$VENDORED_SRC" "$VEND_SBOM" "$PROJECT_VERSION"; then
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
                rm -f "${OUTPUT_FILE}.merged"
            fi
        else
            echo "[INFO] no new vendored open source to add (after reconciliation)."
        fi
    fi
elif [ "$SOURCE_SCAN" = "true" ] && [ -d "$VENDORED_SRC" ]; then
    run_optional_step suggest-vendored bash "$LIBDIR/suggest-vendored.sh" "$OUTPUT_FILE" "$VENDORED_SRC"
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
        if bash "$LIBDIR/identify-cocoapods.sh" "$COCOA_SRC" "$COCOA_SBOM" "$PROJECT_VERSION"; then
            COCOA_N=$(jq '[.components[]?] | length' "$COCOA_SBOM" 2>/dev/null || echo 0)
            if [ "${COCOA_N:-0}" -gt 0 ]; then
                echo "[INFO] CocoaPods components identified: $COCOA_N — merging into SBOM."
                if bash "$LIBDIR/merge-sbom.sh" "${OUTPUT_FILE}.merged" "$PROJECT_NAME" "$PROJECT_VERSION" "$OUTPUT_FILE" "$COCOA_SBOM"; then
                    mv "${OUTPUT_FILE}.merged" "$OUTPUT_FILE"
                else
                    echo "[WARN] merge of CocoaPods components failed; keeping the original SBOM." >&2
                    rm -f "${OUTPUT_FILE}.merged"
                fi
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
        bash "$LIBDIR/stamp-metadata.sh" "$OUTPUT_FILE" "$PROJECT_NAME" "$PROJECT_VERSION"
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
        run_optional_step docmeta bash "$LIBDIR/stamp-document-metadata.sh" "$OUTPUT_FILE" "$SCAN_MODE" "$TARGET_FILE"
        ;;
    SOURCE|POSTPROCESS|ROOTFS|IMAGE|AIBOM|DATASET|MERGE)
        run_optional_step docmeta bash "$LIBDIR/stamp-document-metadata.sh" "$OUTPUT_FILE" "$SCAN_MODE"
        ;;
esac

if [ "${BYTE_STABLE:-false}" = "true" ]; then
    run_optional_step normalize bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE" --stable
else
    run_optional_step normalize bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE"
fi

# CPE enrichment: firmware/image/rootfs components often arrive with name+version
# but no purl/cpe. enrich-cpe.sh attaches (or version-normalizes) a cpe:2.3 for
# WHITELISTED component names only (closed list, no guessing) and fills confirmed
# SPDX licenses. The CPE keeps the SBOM identifier correct for consumers that read
# it; note that `trivy sbom` matches by PURL and OS-context, NOT by component.cpe
# (issue #458), so distro CVE matching comes from the OS component synthesized just
# below and, for firmware, from the cve-bin-tool sidecar. Skipped for AI SBOMs and
# disabled with ENRICH_CPE=false. Generic across modes; best-effort (|| true).
if [ "${ENRICH_CPE:-true}" != "false" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-cpe bash "$LIBDIR/enrich-cpe.sh" "$OUTPUT_FILE"
fi

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
fi

# Staleness enrichment (OPT-IN, default off): query deps.dev for absolute version
# currency (newest version, how many releases behind, last-release date). Unlike
# EOL this makes one network call per package, so it trades the scan's offline
# determinism for freshness and is only run when STALENESS_ENRICH=true. Best-effort
# and bounded (per-request timeout + wall-clock budget); never aborts the scan.
if [ "${STALENESS_ENRICH:-false}" = "true" ] && [ "$AI_MODEL_SCAN" != "true" ]; then
    run_optional_step enrich-staleness python3 "$LIBDIR/enrich-staleness.py" "$OUTPUT_FILE"
fi

# AI model risk assessment: stamp every model/dataset component with a
# bomlens:assessment:* verdict (ok / conditional / caution / review) from the
# curated license-terms registry (ai-risk-knowledge.json). Offline, pure
# post-processing after normalize (SPDX ids in place); an unknown license falls
# to review, never to a guess, and the reports that print the verdict carry the
# registry's not-legal-advice disclaimer. Self-gates on the presence of a
# machine-learning-model component, so ANALYZE of a plain SBOM is a no-op.
if [ "$AI_MODEL_SCAN" = "true" ] || [ "$SCAN_MODE" = "ANALYZE" ]; then
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
fi

# Deep license detection (scancode, opt-in). Only meaningful for source trees.
if [ "${DEEP_LICENSE:-false}" = "true" ] && [ -d /src ]; then
    if command -v scancode >/dev/null 2>&1; then
        echo "[INFO] Running scancode deep license detection..."
        if scancode --license --json-pp /tmp/scancode.json /src >/dev/null 2>&1; then
            cp /tmp/scancode.json "${OUT_PREFIX}_scancode.json"
            ARTIFACTS+=("${OUT_PREFIX}_scancode.json")
        else
            echo "[WARN] scancode run failed."
        fi
    else
        echo "[WARN] --deep-license requested but scancode not in image (rebuild with --build-arg SBOM_DEEP_LICENSE=true)."
    fi
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
        UNPACK_TARGET="$TARGET_IMAGE"
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

if [ "${GENERATE_NOTICE:-false}" = "true" ]; then
    run_optional_step generate-notice bash "$LIBDIR/generate-notice.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"
    [ -f "${OUT_PREFIX}_NOTICE.txt" ] && ARTIFACTS+=("${OUT_PREFIX}_NOTICE.txt")
    [ -f "${OUT_PREFIX}_NOTICE.html" ] && ARTIFACTS+=("${OUT_PREFIX}_NOTICE.html")
    # PDF is produced only when a renderer is in the image (SBOM_PDF=true).
    [ -f "${OUT_PREFIX}_NOTICE.pdf" ] && ARTIFACTS+=("${OUT_PREFIX}_NOTICE.pdf")
    sync_artifacts
fi

if [ "${GENERATE_SECURITY:-false}" = "true" ]; then
    run_optional_step scan-security bash "$LIBDIR/scan-security.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"
    [ -f "${OUT_PREFIX}_security.json" ] && ARTIFACTS+=("${OUT_PREFIX}_security.json")
    [ -f "${OUT_PREFIX}_security.md" ] && ARTIFACTS+=("${OUT_PREFIX}_security.md")
    [ -f "${OUT_PREFIX}_security.html" ] && ARTIFACTS+=("${OUT_PREFIX}_security.html")
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
    for ext in json md html; do
        [ -f "${OUT_PREFIX}_conformance.${ext}" ] && ARTIFACTS+=("${OUT_PREFIX}_conformance.${ext}")
    done
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

if [ "${SIGN_SBOM:-false}" = "true" ]; then
    if command -v cosign >/dev/null 2>&1 && [ -n "${COSIGN_KEY:-}" ]; then
        echo "[INFO] Signing SBOM with cosign..."
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
            SIGN_FAILED="$SIGN_FAILED" bash "$LIBDIR/validate-sbom.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME" \
                || echo "[WARN] could not refresh the conformance report's signature status after signing." >&2
        fi
        # A requested signature that was not produced is a failure on a
        # supply-chain tool. Do not exit 0 leaving the user to believe their
        # SBOM is signed when no .sig exists.
        if [ "$SIGN_FAILED" != "0" ]; then
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
    else
        echo "[WARN] --sign requested but cosign/COSIGN_KEY unavailable; skipping."
    fi
fi

# AI compliance profile (AI SBOMs only): a governance one-pager that re-aggregates
# the G7 conformance status, the regulatory crosswalk and the license-review flags
# — no new scan. generate-ai-profile.sh self-gates on the presence of G7 checks in
# the conformance report, so it is a clean no-op for a plain (non-AI) SBOM; we wire
# it only for the modes that can carry a machine-learning-model component.
if [ "$AI_MODEL_SCAN" = "true" ] || [ "$SCAN_MODE" = "ANALYZE" ]; then
    if bash "$LIBDIR/generate-ai-profile.sh" "$OUT_PREFIX" "$PROJECT_NAME"; then
        for ext in json md html; do
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
if ! curl -s --max-time 5 "$API_URL/api/version" > /dev/null 2>&1; then
    echo "[WARN] Cannot reach Dependency Track at $API_URL."
fi
CURL_RC=0
RESPONSE=$(curl -s -w "\n%{http_code}" --connect-timeout 10 -X POST "$API_URL/api/v1/bom" \
    -H "Content-Type: multipart/form-data" \
    -H "X-Api-Key: $API_KEY" \
    -F "autoCreate=true" \
    -F "projectName=$PROJECT_NAME" \
    -F "projectVersion=$PROJECT_VERSION" \
    -F "bom=@$OUTPUT_FILE") || CURL_RC=$?
report_unreachable_upload "$CURL_RC" "$API_URL"
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
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
