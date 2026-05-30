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
# SBOM Scan Script
# ========================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_IMAGE="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/sbom-scanner:latest}"
SERVER_URL="http://host.docker.internal:8081"
DEFAULT_API_KEY="${API_KEY:-odt_YOUR_REAL_API_KEY_HERE}"

GENERATE_ONLY="false"
TARGET=""
PROJECT_NAME=""
PROJECT_VERSION=""
GENERATE_NOTICE="false"
GENERATE_SECURITY="false"
DEEP_LICENSE="false"
SIGN_SBOM="false"
BYTE_STABLE="false"
UI_MODE="false"
UI_PORT="${UI_PORT:-8080}"

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
        --ui) UI_MODE="true" ;;
        --help)
            cat << EOF
Usage: $0 --project <name> --version <ver> [OPTIONS]

Options:
  --project <name>       Project name (required)
  --version <ver>        Version (required)
  --target <target>      Analysis target:
                         - Not specified: Current directory source code
                         - Image name (e.g., nginx:latest): Docker image
                         - File path (e.g., firmware.bin): Binary file
                         - Directory (e.g., ./rootfs/): RootFS directory
  --generate-only        Save locally without uploading
  --notice               Also generate open-source NOTICE (txt + html)
  --security             Also generate Trivy security report (json + md + html)
  --all                  Shorthand for --notice --security
  --deep-license         Deep 1st-party license detection via scancode (opt-in, heavy)
  --byte-stable          Deterministic SBOM output (pinned timestamp, sorted components)
  --sign                 Sign the SBOM with cosign (requires COSIGN_KEY)
  --ui                   Launch the local web UI (browser) instead of scanning
  --help                 Show this help message

Environment Variables:
  SBOM_SCANNER_IMAGE     Docker image to use (default: latest)
                         Examples:
                           ghcr.io/sktelecom/sbom-scanner:latest (default)
                           ghcr.io/sktelecom/sbom-scanner:v1
                           ghcr.io/sktelecom/sbom-scanner:v1.0.0

Examples:
  # Scan source code (current directory)
  $0 --project MyApp --version 1.0.0 --generate-only

  # Scan Docker image
  $0 --project MyImage --version 1.0 --target nginx:latest --generate-only

  # Scan binary file
  $0 --project RouterOS --version 2.0 --target firmware.bin --generate-only

  # Scan RootFS directory
  $0 --project DeviceOS --version 1.0 --target ./rootfs/ --generate-only
EOF
            exit 0
            ;;
        *) echo "[ERROR] Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# ========================================================
# Web UI mode (launch browser-based wrapper, no scan args needed)
# ========================================================
if [ "$UI_MODE" = "true" ]; then
    if ! command -v docker &> /dev/null; then
        echo "[ERROR] Docker is not installed or not in PATH"
        echo "  Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
        exit 1
    fi
    if ! docker info > /dev/null 2>&1; then
        echo "[ERROR] Docker daemon is not running. Please start Docker Desktop and retry."
        echo "  Download: https://www.docker.com/products/docker-desktop/"
        exit 1
    fi
    echo "=========================================="
    echo "  SBOM Tools Web UI"
    echo "  URL: http://localhost:${UI_PORT}"
    echo "  (Ctrl+C to stop)"
    echo "=========================================="
    # Best-effort browser open (after the server has a moment to start)
    ( sleep 2
      if command -v open >/dev/null 2>&1; then open "http://localhost:${UI_PORT}"
      elif command -v xdg-open >/dev/null 2>&1; then xdg-open "http://localhost:${UI_PORT}"
      fi ) >/dev/null 2>&1 &
    exec docker run --rm -it \
        -p "${UI_PORT}:8080" \
        -v "$(pwd)":/src \
        -v "$(pwd)":/host-output \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -e MODE=UI \
        -e UI_PORT=8080 \
        "$DOCKER_IMAGE"
fi

# ========================================================
# Validate input
# ========================================================
if [ -z "$PROJECT_NAME" ] || [ -z "$PROJECT_VERSION" ]; then
    echo "[ERROR] --project and --version are required."
    echo "Run '$0 --help' for usage."
    exit 1
fi

# ========================================================
# Auto-detect target type
# ========================================================
MODE="SOURCE"
TARGET_IMAGE=""
TARGET_FILE=""
TARGET_DIR=""
SOURCE_DIR="$(pwd)"

if [ -n "$TARGET" ]; then
    # Check filesystem first (file/directory priority)
    if [ -f "$TARGET" ]; then
        MODE="BINARY"
        TARGET_FILE="$(cd "$(dirname "$TARGET")" && pwd)/$(basename "$TARGET")"
        echo "[INFO] Detected binary file: $TARGET_FILE"
    elif [ -d "$TARGET" ]; then
        MODE="ROOTFS"
        TARGET_DIR="$(cd "$TARGET" && pwd)"
        echo "[INFO] Detected directory: $TARGET_DIR"
    else
        MODE="IMAGE"
        TARGET_IMAGE="$TARGET"
        echo "[INFO] Detected Docker image: $TARGET_IMAGE"
    fi
fi

# ========================================================
# Verify Docker environment
# ========================================================
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed or not in PATH"
    exit 1
fi

if ! docker info > /dev/null 2>&1; then
    echo "[ERROR] Docker daemon is not running"
    echo "Please start Docker and try again"
    exit 1
fi

# ========================================================
# Configure volume mounts and environment variables
# ========================================================
CACHE_MOUNTS=""
VOLUME_MOUNTS=""
ENV_VARS=""

if [ "$MODE" = "SOURCE" ]; then
    VOLUME_MOUNTS="-v \"$SOURCE_DIR\":/src -v \"$SOURCE_DIR\":/host-output"
    
    # Mount build caches if they exist
    if [ -d "$HOME/.gradle" ]; then
        CACHE_MOUNTS="$CACHE_MOUNTS -v \"$HOME/.gradle\":/root/.gradle"
    fi
    if [ -d "$HOME/.m2" ]; then
        CACHE_MOUNTS="$CACHE_MOUNTS -v \"$HOME/.m2\":/root/.m2"
    fi
fi

if [ "$MODE" = "IMAGE" ]; then
    VOLUME_MOUNTS="-v \"$SOURCE_DIR\":/host-output -v /var/run/docker.sock:/var/run/docker.sock"
    ENV_VARS="$ENV_VARS -e TARGET_IMAGE=\"$TARGET_IMAGE\""
fi

if [ "$MODE" = "BINARY" ]; then
    FILE_DIR="$(dirname "$TARGET_FILE")"
    FILE_NAME="$(basename "$TARGET_FILE")"
    VOLUME_MOUNTS="-v \"$FILE_DIR\":/target -v \"$SOURCE_DIR\":/host-output"
    ENV_VARS="$ENV_VARS -e TARGET_FILE=\"/target/$FILE_NAME\""
fi

if [ "$MODE" = "ROOTFS" ]; then
    VOLUME_MOUNTS="-v \"$TARGET_DIR\":/target -v \"$SOURCE_DIR\":/host-output"
    ENV_VARS="$ENV_VARS -e TARGET_DIR=\"/target\""
fi

# Common environment variables
if [ "$GENERATE_ONLY" = "true" ]; then
    UPLOAD_VAR="false"
else
    UPLOAD_VAR="true"
fi

# ========================================================
# Run Docker container
# ========================================================
echo "=========================================="
echo "  Starting SBOM Analysis"
echo "  Mode: $MODE"
echo "  Project: $PROJECT_NAME ($PROJECT_VERSION)"
if [ -n "$TARGET" ]; then
    echo "  Target: $TARGET"
fi
echo "=========================================="

eval docker run --rm \
    $VOLUME_MOUNTS \
    $CACHE_MOUNTS \
    --add-host=host.docker.internal:host-gateway \
    -e MODE=\"$MODE\" \
    $ENV_VARS \
    -e UPLOAD_ENABLED=\"$UPLOAD_VAR\" \
    -e GENERATE_NOTICE=\"$GENERATE_NOTICE\" \
    -e GENERATE_SECURITY=\"$GENERATE_SECURITY\" \
    -e DEEP_LICENSE=\"$DEEP_LICENSE\" \
    -e SIGN_SBOM=\"$SIGN_SBOM\" \
    -e BYTE_STABLE=\"$BYTE_STABLE\" \
    -e HOST_OUTPUT_DIR=\"/host-output\" \
    -e PROJECT_NAME=\"$PROJECT_NAME\" \
    -e PROJECT_VERSION=\"$PROJECT_VERSION\" \
    -e API_KEY=\"$DEFAULT_API_KEY\" \
    -e API_URL=\"$SERVER_URL\" \
    \"$DOCKER_IMAGE\"

if [ $? -ne 0 ]; then
    echo "[ERROR] Scan failed. Check logs above."
    exit 1
fi

echo "=========================================="
echo "  Analysis Complete!"
if [ "$GENERATE_ONLY" = "true" ]; then
    SAFE_PROJECT=$(echo "$PROJECT_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g')
    SAFE_VERSION=$(echo "$PROJECT_VERSION" | sed 's/[^a-zA-Z0-9._-]/_/g')
    echo "  SBOM saved: ${SAFE_PROJECT}_${SAFE_VERSION}_bom.json"
    [ "$GENERATE_NOTICE" = "true" ]   && echo "  Notice:     ${SAFE_PROJECT}_${SAFE_VERSION}_NOTICE.{txt,html}"
    [ "$GENERATE_SECURITY" = "true" ] && echo "  Security:   ${SAFE_PROJECT}_${SAFE_VERSION}_security.{json,md,html}"
fi
echo "=========================================="
