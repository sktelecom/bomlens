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
#   - POSTPROCESS : consume an already-generated SBOM
# then runs the common pipeline: normalize -> notice -> security -> sign.
# ========================================================

SCAN_MODE="${MODE:-POSTPROCESS}"

# --- UI mode: hand off to the web server, no project metadata needed ---
if [ "$SCAN_MODE" = "UI" ]; then
    echo "[INFO] Starting SBOM Tools Web UI on port ${UI_PORT:-8080}..."
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

echo "=========================================="
echo " SKT SBOM Scanner (post-process)"
echo " Mode: $SCAN_MODE"
echo " Project: $PROJECT_NAME ($PROJECT_VERSION)"
echo "=========================================="

# ========================================================
# Produce / locate the SBOM
# ========================================================
case "$SCAN_MODE" in
    SOURCE)
        # Local web UI source scan (current dir / extracted ZIP / cloned git repo).
        # The CLI source path uses cdxgen language images on the HOST (scan-sbom.sh)
        # for deeper transitive resolution; inside this image we have syft (no
        # language toolchains, no docker CLI), so we scan the tree like ROOTFS.
        # syft detects package manifests (package.json/go.mod/pom.xml/Gemfile/…)
        # without building. SOURCE_ROOT lets the UI point at an extracted/cloned dir.
        SRC_ROOT="${SOURCE_ROOT:-/src}"
        if [ ! -d "$SRC_ROOT" ]; then echo "[ERROR] source dir not found: $SRC_ROOT"; exit 1; fi
        if [ -z "$(ls -A "$SRC_ROOT" 2>/dev/null)" ]; then echo "[ERROR] source dir is empty: $SRC_ROOT"; exit 1; fi
        echo "[1/2] syft: source dir $SRC_ROOT"
        if ! syft "dir:$SRC_ROOT" -o cyclonedx-json > "$OUTPUT_FILE" 2>/dev/null; then
            echo "[ERROR] syft source scan failed."; exit 1
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
        bash "$LIBDIR/scan-firmware.sh" "$TARGET_FILE" "$OUTPUT_FILE" "$PROJECT_VERSION"
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
        echo "[ERROR] Unknown MODE: $SCAN_MODE (expected SOURCE/IMAGE/BINARY/ROOTFS/FIRMWARE/ANALYZE/POSTPROCESS/UI)"
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
# Common pipeline: normalize / deep-license / notice / security / sign
# ========================================================
ARTIFACTS=("$OUTPUT_FILE")

if [ "${BYTE_STABLE:-false}" = "true" ]; then
    bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE" --stable || true
else
    bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE" || true
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
# Conformance artifacts only exist in ANALYZE; the [ -f ] guard skips them
# elsewhere, and generate-risk-report.sh drops the 포맷 검증 section accordingly.
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
# Upload handling (optional Dependency-Track)
# ========================================================
if [ "${UPLOAD_ENABLED:-true}" = "false" ]; then
    echo "[INFO] Generate-only mode. Done."
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
