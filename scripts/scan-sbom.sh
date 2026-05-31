#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# ========================================================
# SBOM Scan Orchestrator (2-stage architecture)
#
#   Stage 1 (SBOM): source -> cdxgen language image (+ build-prep) OR
#                   Android -> self-built sbom-scanner-android-sdk<API> OR
#                   mixed   -> cdxgen all-in-one
#   Stage 2 (post): post-process image -> normalize/notice/security/sign
#   image/binary/rootfs: post-process image (syft) does both stages in one.
# ========================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_PREP="$REPO_DIR/docker/lib/build-prep.sh"

POSTPROCESS_IMAGE="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/sbom-scanner:latest}"
FIRMWARE_IMAGE="${SBOM_FIRMWARE_IMAGE:-ghcr.io/sktelecom/sbom-scanner-firmware:latest}"  # opt-in (unblob/cve-bin-tool)
CDXGEN_TAG="${CDXGEN_TAG:-v12}"                                  # cdxgen language image tag
CDXGEN_ALLINONE="${CDXGEN_ALLINONE:-ghcr.io/cyclonedx/cdxgen:v12.5.0}"
ANDROID_IMAGE_PREFIX="${ANDROID_IMAGE_PREFIX:-ghcr.io/sktelecom/sbom-scanner-android-sdk}"
ANDROID_API_DEFAULT="${ANDROID_API_DEFAULT:-34}"

SERVER_URL="http://host.docker.internal:8081"
DEFAULT_API_KEY="${API_KEY:-odt_YOUR_REAL_API_KEY_HERE}"

GENERATE_ONLY="false"; TARGET=""; PROJECT_NAME=""; PROJECT_VERSION=""
GENERATE_NOTICE="false"; GENERATE_SECURITY="false"; DEEP_LICENSE="false"
SIGN_SBOM="false"; BYTE_STABLE="false"; UI_MODE="false"; UI_PORT="${UI_PORT:-8080}"
FORCE_FIRMWARE="false"

# ========================================================
# Parse arguments
# ========================================================
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --project) PROJECT_NAME="$2"; shift ;;
        --version) PROJECT_VERSION="$2"; shift ;;
        --target) TARGET="$2"; shift ;;
        --generate-only) GENERATE_ONLY="true" ;;
        --notice) GENERATE_NOTICE="true" ;;
        --security) GENERATE_SECURITY="true" ;;
        --all) GENERATE_NOTICE="true"; GENERATE_SECURITY="true" ;;
        --deep-license) DEEP_LICENSE="true" ;;
        --sign) SIGN_SBOM="true" ;;
        --byte-stable) BYTE_STABLE="true" ;;
        --firmware) FORCE_FIRMWARE="true" ;;
        --ui) UI_MODE="true" ;;
        --help)
            cat << EOF
Usage: $0 --project <name> --version <ver> [OPTIONS]

Options:
  --project <name>       Project name (required)
  --version <ver>        Version (required)
  --target <target>      Not set: source (current dir) | image name | file | directory
  --firmware             Force firmware mode for --target file (opt-in image)
  --generate-only        Save locally without uploading
  --notice               Open-source NOTICE (txt+html)
  --security             Trivy security report (json+md+html)
  --all                  --notice --security
  --deep-license         scancode deep license (opt-in image)
  --byte-stable          Deterministic SBOM output
  --sign                 cosign sign (requires COSIGN_KEY)
  --ui                   Launch local web UI
  --help                 Show this help

Architecture: source SBOM generation uses cdxgen's per-language images
(on-demand); this tool orchestrates + post-processes. See docs/direction-study.md.
EOF
            exit 0 ;;
        *) echo "[ERROR] Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ========================================================
# Docker checks
# ========================================================
docker_check() {
    command -v docker &>/dev/null || { echo "[ERROR] Docker not installed."; echo "  https://www.docker.com/products/docker-desktop/"; exit 1; }
    docker info >/dev/null 2>&1 || { echo "[ERROR] Docker daemon not running. Start Docker Desktop and retry."; exit 1; }
}

# ========================================================
# Web UI mode
# ========================================================
if [ "$UI_MODE" = "true" ]; then
    docker_check
    echo "=========================================="
    echo "  SBOM Tools Web UI — http://localhost:${UI_PORT}  (Ctrl+C to stop)"
    echo "=========================================="
    ( sleep 2; (command -v open >/dev/null 2>&1 && open "http://localhost:${UI_PORT}") \
        || (command -v xdg-open >/dev/null 2>&1 && xdg-open "http://localhost:${UI_PORT}") ) >/dev/null 2>&1 &
    exec docker run --rm -it -p "${UI_PORT}:8080" \
        -v "$(pwd)":/src -v "$(pwd)":/host-output \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -e MODE=UI -e UI_PORT=8080 "$POSTPROCESS_IMAGE"
fi

# ========================================================
# Validate
# ========================================================
[ -n "$PROJECT_NAME" ] && [ -n "$PROJECT_VERSION" ] || { echo "[ERROR] --project and --version are required ($0 --help)."; exit 1; }
docker_check

SAFE_PROJECT=$(echo "$PROJECT_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g')
SAFE_VERSION=$(echo "$PROJECT_VERSION" | sed 's/[^a-zA-Z0-9._-]/_/g')
OUTPUT_FILE="${SAFE_PROJECT}_${SAFE_VERSION}_bom.json"
SOURCE_DIR="$(pwd)"
UPLOAD_VAR="true"; [ "$GENERATE_ONLY" = "true" ] && UPLOAD_VAR="false"

# Common -e flags for the post-process image
pp_env() {
    printf ' -e GENERATE_NOTICE=%s -e GENERATE_SECURITY=%s -e DEEP_LICENSE=%s -e SIGN_SBOM=%s -e BYTE_STABLE=%s -e UPLOAD_ENABLED=%s -e PROJECT_NAME=%q -e PROJECT_VERSION=%q -e HOST_OUTPUT_DIR=/host-output -e API_KEY=%q -e API_URL=%q' \
        "$GENERATE_NOTICE" "$GENERATE_SECURITY" "$DEEP_LICENSE" "$SIGN_SBOM" "$BYTE_STABLE" "$UPLOAD_VAR" "$PROJECT_NAME" "$PROJECT_VERSION" "$DEFAULT_API_KEY" "$SERVER_URL"
}

# ========================================================
# Detect target type
# ========================================================
# Recognize a firmware blob by extension, or (if `file` is on the host) by magic.
is_firmware() {
    local f="$1" lower magic
    lower=$(printf '%s' "$f" | tr '[:upper:]' '[:lower:]')
    case "$lower" in
        *.bin|*.img|*.squashfs|*.sqsh|*.ubi|*.ubifs|*.trx|*.chk|*.fw|*.rom|*.dlf) return 0 ;;
    esac
    if command -v file >/dev/null 2>&1; then
        magic=$(file -b "$f" 2>/dev/null)
        case "$magic" in
            *Squashfs*|*"UBI image"*|*"u-boot legacy uImage"*|*JFFS2*|*cramfs*|*"filesystem data"*) return 0 ;;
        esac
    fi
    return 1
}

MODE="SOURCE"
if [ -n "$TARGET" ]; then
    if [ -f "$TARGET" ]; then
        if [ "$FORCE_FIRMWARE" = "true" ] || is_firmware "$TARGET"; then MODE="FIRMWARE"; else MODE="BINARY"; fi
    elif [ -d "$TARGET" ]; then MODE="ROOTFS";
    else MODE="IMAGE"; fi
elif [ "$FORCE_FIRMWARE" = "true" ]; then
    echo "[ERROR] --firmware requires '--target <firmware-file>'."; exit 1
fi

if [ "$FORCE_FIRMWARE" = "true" ] && [ "$MODE" != "FIRMWARE" ]; then
    echo "[ERROR] --firmware expects a file target, but '$TARGET' is not a regular file."; exit 1
fi

# ========================================================
# Language detection (source)
# ========================================================
detect_lang() {
    local d="$1" langs=""
    # Android: build.gradle with android plugin, or AndroidManifest.xml
    if grep -rqsE "com\.android\.(application|library)|namespace +['\"]" "$d"/build.gradle "$d"/build.gradle.kts "$d"/app/build.gradle "$d"/app/build.gradle.kts 2>/dev/null \
       || find "$d" -maxdepth 3 -name AndroidManifest.xml 2>/dev/null | grep -q .; then
        echo "android"; return
    fi
    # iOS / Swift: SPM (Package.swift), CocoaPods (Podfile), or Xcode project
    if [ -f "$d/Package.swift" ] || [ -f "$d/Podfile" ] || [ -f "$d/Podfile.lock" ] \
       || ls "$d"/*.xcodeproj >/dev/null 2>&1 || ls "$d"/*.xcworkspace >/dev/null 2>&1; then
        echo "swift"; return
    fi
    [ -f "$d/Cargo.toml" ] && langs="$langs rust"
    [ -f "$d/go.mod" ] && langs="$langs go"
    [ -f "$d/Gemfile" ] && langs="$langs ruby"
    { [ -f "$d/pom.xml" ] || ls "$d"/*.gradle "$d"/*.gradle.kts >/dev/null 2>&1; } && langs="$langs java"
    { [ -f "$d/requirements.txt" ] || [ -f "$d/pyproject.toml" ]; } && langs="$langs python"
    [ -f "$d/package.json" ] && langs="$langs node"
    [ -f "$d/composer.json" ] && langs="$langs php"
    ls "$d"/*.csproj "$d"/*.sln >/dev/null 2>&1 && langs="$langs dotnet"
    # shellcheck disable=SC2086
    set -- $langs
    if [ "$#" -eq 1 ]; then echo "$1"; elif [ "$#" -eq 0 ]; then echo "unknown"; else echo "mixed"; fi
}

img_for_lang() {
    case "$1" in
        rust)   echo "ghcr.io/cyclonedx/cdxgen-debian-rust:$CDXGEN_TAG" ;;
        go)     echo "ghcr.io/cyclonedx/cdxgen-debian-golang124:$CDXGEN_TAG" ;;
        ruby)   echo "ghcr.io/cyclonedx/cdxgen-debian-ruby34:$CDXGEN_TAG" ;;
        java)   echo "ghcr.io/cyclonedx/cdxgen-temurin-java21:$CDXGEN_TAG" ;;
        python) echo "ghcr.io/cyclonedx/cdxgen-python312:$CDXGEN_TAG" ;;
        node)   echo "ghcr.io/cyclonedx/cdxgen-node20:$CDXGEN_TAG" ;;
        php)    echo "ghcr.io/cyclonedx/cdxgen-debian-php84:$CDXGEN_TAG" ;;
        dotnet) echo "ghcr.io/cyclonedx/cdxgen-debian-dotnet9:$CDXGEN_TAG" ;;
        swift)  echo "ghcr.io/cyclonedx/cdxgen-debian-swift:$CDXGEN_TAG" ;;
        *)      echo "$CDXGEN_ALLINONE" ;;   # mixed / unknown
    esac
}

android_api() {
    local d="$1" api
    api=$(grep -rhoE "compileSdk(Version)?[ =]+[0-9]+" "$d"/build.gradle "$d"/build.gradle.kts "$d"/app/build.gradle "$d"/app/build.gradle.kts 2>/dev/null \
          | grep -oE "[0-9]+" | head -1)
    echo "${api:-$ANDROID_API_DEFAULT}"
}

echo "=========================================="
echo "  SBOM Analysis — Mode: $MODE — $PROJECT_NAME ($PROJECT_VERSION)"
[ -n "$TARGET" ] && echo "  Target: $TARGET"
echo "=========================================="

# ========================================================
# Stage 1: produce SBOM
# ========================================================
if [ "$MODE" = "SOURCE" ]; then
    [ -n "$(ls -A "$SOURCE_DIR" 2>/dev/null)" ] || { echo "[ERROR] current directory is empty"; exit 1; }
    LANG_DET=$(detect_lang "$SOURCE_DIR")
    if [ "$LANG_DET" = "android" ]; then
        API=$(android_api "$SOURCE_DIR")
        CDX_IMG="${ANDROID_IMAGE_PREFIX}${API}:latest"
        echo "[INFO] Android source detected (compileSdk=$API) -> $CDX_IMG"
    else
        CDX_IMG=$(img_for_lang "$LANG_DET")
        echo "[INFO] Language: $LANG_DET -> $CDX_IMG"
        if [ "$LANG_DET" = "swift" ]; then
            echo "[WARN] iOS/Swift: CocoaPods(Podfile.lock) resolves fully; SPM is augmented via 'swift package resolve'."
            echo "[WARN]   iOS-platform (UIKit) and Xcode-driven dependencies require macOS and are NOT resolved in this Linux container."
        fi
    fi
    echo "[1/2] Generating SBOM (cdxgen)..."
    CACHE_MOUNTS=""
    [ -d "$HOME/.gradle" ] && CACHE_MOUNTS="$CACHE_MOUNTS -v \"$HOME/.gradle\":/root/.gradle"
    [ -d "$HOME/.m2" ] && CACHE_MOUNTS="$CACHE_MOUNTS -v \"$HOME/.m2\":/root/.m2"
    # HOME=/tmp/sbomhome: writable for both root and non-root (cyclonedx) images,
    # so maven/cargo/etc. caches resolve regardless of the base image's user.
    eval docker run --rm \
        -v "\"$SOURCE_DIR\"":/app \
        -v "\"$BUILD_PREP\"":/tmp/build-prep.sh:ro \
        $CACHE_MOUNTS \
        -e HOME=/tmp/sbomhome \
        -e MAVEN_OPTS=-Dmaven.repo.local=/tmp/sbomhome/.m2 \
        --entrypoint sh "\"$CDX_IMG\"" \
        -c "'sh /tmp/build-prep.sh /app \"/app/$OUTPUT_FILE\" 1.6'" \
        || { echo "[ERROR] SBOM generation failed (stage 1)"; exit 1; }

    echo "[2/2] Post-processing..."
    eval docker run --rm \
        -v "\"$SOURCE_DIR\"":/src -v "\"$SOURCE_DIR\"":/host-output \
        --add-host=host.docker.internal:host-gateway \
        -e MODE=POSTPROCESS $(pp_env) \
        "\"$POSTPROCESS_IMAGE\""
else
    # image / binary / rootfs / firmware: scanner image runs syft + pipeline in one shot.
    # Firmware needs the heavier opt-in image (unblob/cve-bin-tool); others use the base image.
    VOL=""; ENVV=""; RUN_IMAGE="$POSTPROCESS_IMAGE"
    case "$MODE" in
        IMAGE)  VOL="-v \"$SOURCE_DIR\":/host-output -v /var/run/docker.sock:/var/run/docker.sock"; ENVV="-e TARGET_IMAGE=\"$TARGET\"" ;;
        BINARY) FD="$(cd "$(dirname "$TARGET")" && pwd)"; FN="$(basename "$TARGET")"; VOL="-v \"$FD\":/target -v \"$SOURCE_DIR\":/host-output"; ENVV="-e TARGET_FILE=\"/target/$FN\"" ;;
        ROOTFS) TD="$(cd "$TARGET" && pwd)"; VOL="-v \"$TD\":/target -v \"$SOURCE_DIR\":/host-output"; ENVV="-e TARGET_DIR=/target" ;;
        FIRMWARE) FD="$(cd "$(dirname "$TARGET")" && pwd)"; FN="$(basename "$TARGET")"; VOL="-v \"$FD\":/target -v \"$SOURCE_DIR\":/host-output"; ENVV="-e TARGET_FILE=\"/target/$FN\""; RUN_IMAGE="$FIRMWARE_IMAGE" ;;
    esac
    eval docker run --rm $VOL \
        --add-host=host.docker.internal:host-gateway \
        -e MODE="$MODE" $ENVV $(pp_env) \
        "\"$RUN_IMAGE\""
fi

echo "=========================================="
echo "  Analysis Complete!"
if [ "$GENERATE_ONLY" = "true" ]; then
    echo "  SBOM: ${OUTPUT_FILE}"
    [ "$GENERATE_NOTICE" = "true" ]   && echo "  Notice:   ${SAFE_PROJECT}_${SAFE_VERSION}_NOTICE.{txt,html}"
    [ "$GENERATE_SECURITY" = "true" ] && echo "  Security: ${SAFE_PROJECT}_${SAFE_VERSION}_security.{json,md,html}"
fi
echo "=========================================="
