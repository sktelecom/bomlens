#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
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
#   - ANALYZE     : validate + convert a supplier SBOM -> conformance + risk report
#   - MERGE       : combine several CycloneDX SBOMs (layered server delivery)
#   - POSTPROCESS : consume an already-generated SBOM
# then runs the common pipeline: normalize -> notice -> security -> sign.
# ========================================================

SCAN_MODE="${MODE:-POSTPROCESS}"

# --- UI mode: hand off to the web server, no project metadata needed ---
if [ "$SCAN_MODE" = "UI" ]; then
    echo "[INFO] Starting BomLens Web UI on port ${UI_PORT:-8080}..."
    exec python3 /usr/local/lib/sbom-web/server.py
fi

if [ -z "$PROJECT_NAME" ] || [ -z "$PROJECT_VERSION" ]; then
    echo "[ERROR] PROJECT_NAME and PROJECT_VERSION are required."
    exit 1
fi

SAFE_PROJECT=$(echo "${PROJECT_NAME}" | sed 's/[^a-zA-Z0-9.-]/_/g' | sed 's/__*/_/g' | sed 's/^_//; s/_$//')
SAFE_VERSION=$(echo "${PROJECT_VERSION}" | sed 's/[^a-zA-Z0-9.-]/_/g' | sed 's/__*/_/g' | sed 's/^_//; s/_$//')
OUTPUT_FILE="${SAFE_PROJECT}_${SAFE_VERSION}_bom.json"
OUT_PREFIX="${SAFE_PROJECT}_${SAFE_VERSION}"
LIBDIR="/usr/local/lib/sbom"

# Shared language detection + cdxgen image selection (also used by the CLI).
# shellcheck source=docker/lib/source-detect.sh
. "$LIBDIR/source-detect.sh"

# generate_sbom_cdxgen: run a cdxgen language image as a SIBLING container (via the
# mounted host Docker socket) so a web-UI source scan resolves transitive deps,
# matching the CLI. The sibling is launched by the HOST daemon, which can only
# bind-mount HOST paths — so we mount the scanned tree by its host path
# ($src_host) and inject build-prep.sh inline (it lives only inside THIS image,
# not on the host, so it cannot be bind-mounted). cdxgen writes the bom into the
# scanned tree; we move it into the working dir for the common pipeline.
#   $1 = scanned tree, this container's path   (for detect_lang / reading output)
#   $2 = scanned tree, host path               (for the sibling bind-mount)
#   $3 = output bom filename (relative)
generate_sbom_cdxgen() {
    local src_container="$1" src_host="$2" out="$3"
    local lang img api rc=0
    lang=$(detect_lang "$src_container")
    if [ "$lang" = "android" ]; then
        api=$(android_api "$src_container")
        img="${ANDROID_IMAGE_PREFIX}${api}:latest"
        echo "[INFO] Android source (compileSdk=$api) -> $img"
    else
        img=$(img_for_lang "$lang")
        echo "[INFO] Language: $lang -> $img"
    fi
    local prep; prep=$(cat "$LIBDIR/build-prep.sh")
    docker run --rm -u 0:0 \
        -v "$src_host":/app \
        -e HOME=/tmp/sbomhome \
        -e MAVEN_OPTS=-Dmaven.repo.local=/tmp/sbomhome/.m2 \
        -e FETCH_LICENSE="$FETCH_LICENSE" \
        -e PROJECT_NAME="$PROJECT_NAME" \
        -e PROJECT_VERSION="$PROJECT_VERSION" \
        --entrypoint sh "$img" \
        -c "$prep" _ /app "/app/$out" 1.6 || rc=$?
    [ "$rc" -eq 0 ] || { echo "[WARN] cdxgen sibling container failed (rc=$rc)."; return 1; }
    if [ -f "$src_container/$out" ]; then
        mv "$src_container/$out" "./$out"
    else
        echo "[WARN] cdxgen produced no SBOM at $src_container/$out."; return 1
    fi
    return 0
}

echo "=========================================="
echo " BomLens (post-process)"
echo " Mode: $SCAN_MODE"
echo " Project: $PROJECT_NAME ($PROJECT_VERSION)"
echo "=========================================="

# ========================================================
# Produce / locate the SBOM
# ========================================================
case "$SCAN_MODE" in
    SOURCE)
        # Local web UI source scan (current dir / extracted ZIP / cloned git repo).
        # Preferred path: run a cdxgen language image as a sibling container so
        # transitive dependencies resolve, matching the CLI. This needs the host
        # Docker socket, a docker CLI in this image, and the HOST path of the
        # scanned tree (SOURCE_ROOT_HOST, supplied by the web server). When any is
        # missing we fall back to syft, which parses package manifests
        # (package.json/go.mod/pom.xml/Gemfile/…) without building — direct deps only.
        SRC_ROOT="${SOURCE_ROOT:-/src}"
        if [ ! -d "$SRC_ROOT" ]; then echo "[ERROR] source dir not found: $SRC_ROOT"; exit 1; fi
        if [ -z "$(ls -A "$SRC_ROOT" 2>/dev/null)" ]; then echo "[ERROR] source dir is empty: $SRC_ROOT"; exit 1; fi
        if [ -S /var/run/docker.sock ] && command -v docker >/dev/null 2>&1 && [ -n "$SOURCE_ROOT_HOST" ]; then
            echo "[1/2] cdxgen: source dir $SRC_ROOT (transitive resolution)"
            if ! generate_sbom_cdxgen "$SRC_ROOT" "$SOURCE_ROOT_HOST" "$OUTPUT_FILE"; then
                echo "[WARN] cdxgen path failed; falling back to syft (direct deps only)."
                syft "dir:$SRC_ROOT" -o cyclonedx-json > "$OUTPUT_FILE" 2>/dev/null \
                    || { echo "[ERROR] syft source scan failed."; exit 1; }
            fi
        else
            echo "[1/2] syft: source dir $SRC_ROOT (manifest-only; docker.sock/CLI/host-path unavailable)"
            syft "dir:$SRC_ROOT" -o cyclonedx-json > "$OUTPUT_FILE" 2>/dev/null \
                || { echo "[ERROR] syft source scan failed."; exit 1; }
        fi
        ;;

    IMAGE)
        if [ -z "$TARGET_IMAGE" ]; then echo "[ERROR] TARGET_IMAGE required for IMAGE mode."; exit 1; fi
        if [ ! -S /var/run/docker.sock ]; then
            echo "[ERROR] Docker socket not mounted: -v /var/run/docker.sock:/var/run/docker.sock"; exit 1
        fi
        echo "[1/2] syft: Docker image $TARGET_IMAGE"
        if ! syft "$TARGET_IMAGE" -o cyclonedx-json > "$OUTPUT_FILE" 2>/dev/null; then
            echo "[ERROR] syft failed (image missing or inaccessible)."; exit 1
        fi
        ;;

    BINARY)
        if [ -z "$TARGET_FILE" ] || [ ! -f "$TARGET_FILE" ]; then echo "[ERROR] TARGET_FILE not found: $TARGET_FILE"; exit 1; fi
        echo "[1/2] syft: binary $TARGET_FILE"
        if ! syft "file:$TARGET_FILE" -o cyclonedx-json > "$OUTPUT_FILE" 2>&1; then
            echo "[WARN] syft binary scan failed; emitting minimal SBOM."
            FILE_INFO=$(file "$TARGET_FILE")
            cat > "$OUTPUT_FILE" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
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
        if ! syft "dir:$TARGET_DIR" -o cyclonedx-json > "$OUTPUT_FILE" 2>/dev/null; then
            echo "[ERROR] syft directory scan failed."; exit 1
        fi
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
        if [ -z "$MODEL_ID" ]; then echo "[ERROR] MODEL_ID required for AIBOM mode."; exit 1; fi
        echo "[1/2] aibom: generate AI SBOM for $MODEL_ID"
        bash "$LIBDIR/scan-aibom.sh" "$MODEL_ID" "$OUTPUT_FILE" "$PROJECT_VERSION"
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
        # Supplier-submitted SBOM (CycloneDX or SPDX). Validate the ORIGINAL for
        # conformance, then convert to CycloneDX so the common pipeline is reused.
        if [ -z "$ANALYZE_SBOM" ] || [ ! -f "$ANALYZE_SBOM" ]; then
            echo "[ERROR] ANALYZE_SBOM not found: $ANALYZE_SBOM"; exit 1
        fi
        echo "[1/2] Validating supplier SBOM (conformance, original input)..."
        # Conformance never aborts the pipeline (best-effort report).
        bash "$LIBDIR/validate-sbom.sh" "$ANALYZE_SBOM" "$OUT_PREFIX" "$PROJECT_NAME" || true
        echo "[1/2] Converting supplier SBOM to CycloneDX..."
        if ! bash "$LIBDIR/convert-to-cdx.sh" "$ANALYZE_SBOM" "$OUTPUT_FILE"; then
            echo "[ERROR] could not convert supplier SBOM to CycloneDX."; exit 1
        fi
        ;;

    *)
        echo "[ERROR] Unknown MODE: $SCAN_MODE (expected SOURCE/IMAGE/BINARY/ROOTFS/FIRMWARE/AIBOM/ANALYZE/MERGE/POSTPROCESS/UI)"
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
# Vendored open source (opt-in, SCANOSS) — only meaningful for a source tree.
# Runs for both the CLI source scan (MODE=POSTPROCESS, tree mounted at /src) and
# the web-UI source scan (SOURCE mode, SOURCE_ROOT). When enabled, identify the
# open source copied straight into the sources and merge it into the SBOM before
# stamping/normalizing, so the PURL->CPE fix and the security scan pick it up.
# When disabled, suggest-vendored.sh decides whether to nudge the user (C/C++,
# no package manager, near-empty scan) — off-by-default discovery.
# ========================================================
VENDORED_SRC="${SOURCE_ROOT:-/src}"
if [ "${IDENTIFY_VENDORED:-false}" = "true" ] && [ -d "$VENDORED_SRC" ]; then
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
elif [ -d "$VENDORED_SRC" ]; then
    bash "$LIBDIR/suggest-vendored.sh" "$OUTPUT_FILE" "$VENDORED_SRC" || true
fi

# ========================================================
# Common pipeline: normalize / deep-license / notice / security / sign
# ========================================================
ARTIFACTS=("$OUTPUT_FILE")

# Stamp the BOM's root component with the caller's --project/--version. ROOTFS is
# stamped too: syft names a `dir:` scan's root component after the scan path
# (/target), which is meaningless and leaks the container mount path — the same
# leak stamp-metadata.sh fixes for cdxgen. IMAGE/BINARY/FIRMWARE/ANALYZE/MERGE keep
# their own meaningful root (an image/file basename, a supplier's own identifier we
# must preserve, or — for MERGE — the project root merge-sbom.sh already wrote).
# See stamp-metadata.sh for the rationale.
case "$SCAN_MODE" in
    SOURCE|POSTPROCESS|ROOTFS)
        # No `|| true`: a stamp failure means the SBOM still carries a leaked/placeholder
        # root name (e.g. src@latest), which collides in Black Duck. Fail closed under
        # set -e so a mis-named SBOM is never normalized, signed, or uploaded.
        bash "$LIBDIR/stamp-metadata.sh" "$OUTPUT_FILE" "$PROJECT_NAME" "$PROJECT_VERSION"
        ;;
esac

if [ "${BYTE_STABLE:-false}" = "true" ]; then
    bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE" --stable || true
else
    bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE" || true
fi

# CPE enrichment (Plan 1): firmware/image/rootfs components often arrive with
# name+version but no purl/cpe, so Trivy matches no CVEs. enrich-cpe.sh attaches a
# cpe:2.3 to WHITELISTED component names only (closed list, no guessing) so Trivy
# can match by CPE. Skipped for AI SBOMs (no OS/library components to match) and
# disabled with ENRICH_CPE=false. Generic across modes; best-effort (|| true).
if [ "${ENRICH_CPE:-true}" != "false" ] && [ "$SCAN_MODE" != "AIBOM" ]; then
    bash "$LIBDIR/enrich-cpe.sh" "$OUTPUT_FILE" || true
fi

# AI SBOM: G7 minimum-element conformance on the generated SBOM. validate-sbom.sh
# detects the machine-learning-model component and appends the G7 checks (model
# id/license/card/integrity, datasets, openness — all advisory). Best-effort
# (exit 0); the resulting _conformance.* files are collected by the [ -f ] guard
# in the risk-report block below.
if [ "$SCAN_MODE" = "AIBOM" ]; then
    echo "[2/2] aibom: G7 minimum-element conformance"
    bash "$LIBDIR/validate-sbom.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME" || true
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

if [ "${GENERATE_NOTICE:-false}" = "true" ]; then
    if bash "$LIBDIR/generate-notice.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"; then
        ARTIFACTS+=("${OUT_PREFIX}_NOTICE.txt" "${OUT_PREFIX}_NOTICE.html")
        # PDF is produced only when a renderer is in the image (SBOM_PDF=true).
        [ -f "${OUT_PREFIX}_NOTICE.pdf" ] && ARTIFACTS+=("${OUT_PREFIX}_NOTICE.pdf")
    fi
fi

if [ "${GENERATE_SECURITY:-false}" = "true" ]; then
    if bash "$LIBDIR/scan-security.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"; then
        ARTIFACTS+=("${OUT_PREFIX}_security.json" "${OUT_PREFIX}_security.md" "${OUT_PREFIX}_security.html")
    fi
fi

if [ "${SIGN_SBOM:-false}" = "true" ]; then
    if command -v cosign >/dev/null 2>&1 && [ -n "${COSIGN_KEY:-}" ]; then
        echo "[INFO] Signing SBOM with cosign..."
        if cosign sign-blob --yes --tlog-upload=false --key "$COSIGN_KEY" \
               --output-signature "${OUTPUT_FILE}.sig" "$OUTPUT_FILE"; then
            ARTIFACTS+=("${OUTPUT_FILE}.sig")
        fi
    else
        echo "[WARN] --sign requested but cosign/COSIGN_KEY unavailable; skipping."
    fi
fi

# Risk report (오픈소스위험분석보고서): always for ANALYZE, and for every other
# mode when GENERATE_REPORT=true (the CLI/UI default, opt-out via --no-report).
# It re-aggregates the notice + security artifacts already produced above.
# Conformance artifacts exist in ANALYZE and AIBOM; the [ -f ] guard skips them
# in other modes, and generate-risk-report.sh drops the 포맷 검증 section accordingly.
if [ "$SCAN_MODE" = "ANALYZE" ] || [ "${GENERATE_REPORT:-false}" = "true" ]; then
    for ext in json md html; do
        [ -f "${OUT_PREFIX}_conformance.${ext}" ] && ARTIFACTS+=("${OUT_PREFIX}_conformance.${ext}")
    done
    if bash "$LIBDIR/generate-risk-report.sh" "$OUT_PREFIX" "$PROJECT_NAME"; then
        ARTIFACTS+=("${OUT_PREFIX}_risk-report.md" "${OUT_PREFIX}_risk-report.html")
    fi
fi

# ========================================================
# Copy artifacts to host output (always)
# ========================================================
if [ -n "$HOST_OUTPUT_DIR" ] && [ -d "$HOST_OUTPUT_DIR" ]; then
    for art in "${ARTIFACTS[@]}"; do
        [ -f "$art" ] || continue
        dest="$HOST_OUTPUT_DIR/$(basename "$art")"
        if [ "$art" -ef "$dest" ]; then
            echo "[SUCCESS] saved (in-place): $art"
        elif cp "$art" "$HOST_OUTPUT_DIR/" 2>/dev/null; then
            echo "[SUCCESS] copied: $dest"
        else
            echo "[WARN] copy failed for $art (available in container at: $art)"
            continue
        fi
        # Hand ownership back to the calling user so Linux hosts/CI runners can
        # read the artifacts (the container runs as root). No-op/ignored on macOS.
        if [[ "${HOST_UID:-}" =~ ^[0-9]+$ ]] && [[ "${HOST_GID:-}" =~ ^[0-9]+$ ]]; then
            chown "${HOST_UID}:${HOST_GID}" "$dest" 2>/dev/null || true
        fi
    done
else
    echo "[WARN] HOST_OUTPUT_DIR not set/accessible. Artifacts at: $(pwd)"
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

if [ "${UPLOAD_TARGET:-dependency-track}" = "trusca" ]; then
    echo "[2/2] Uploading to TRUSCA..."
    if [ -z "$API_URL" ] || [ -z "$API_KEY" ] || [ -z "${TRUSCA_PROJECT_ID:-}" ]; then
        echo "[ERROR] TRUSCA upload needs API_URL, API_KEY (Bearer token), and TRUSCA_PROJECT_ID."; exit 1
    fi
    # The ingest endpoint accepts the already-generated CycloneDX SBOM and runs
    # the back half of TRUSCA's scan pipeline (components + trivy + findings).
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/v1/projects/$TRUSCA_PROJECT_ID/sbom-ingest" \
        -H "Authorization: Bearer $API_KEY" \
        -F "sbom=@$OUTPUT_FILE" \
        -F "ref=${TRUSCA_REF:-main}" \
        -F "release=${TRUSCA_RELEASE:-$PROJECT_VERSION}")
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
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API_URL/api/v1/bom" \
    -H "Content-Type: multipart/form-data" \
    -H "X-Api-Key: $API_KEY" \
    -F "autoCreate=true" \
    -F "projectName=$PROJECT_NAME" \
    -F "projectVersion=$PROJECT_VERSION" \
    -F "bom=@$OUTPUT_FILE")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')
if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ] && echo "$BODY" | grep -q "token"; then
    echo "[SUCCESS] Upload complete!"
else
    echo "[ERROR] Upload failed (HTTP $HTTP_CODE)"; echo "Response: $BODY"; exit 1
fi
