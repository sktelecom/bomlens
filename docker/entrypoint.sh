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
# Exception Handling and Environment Validation
# ========================================================

# Auto-configure JAVA_HOME
if [ -z "$JAVA_HOME" ]; then
    JAVA_BIN=$(readlink -f $(which java 2>/dev/null) 2>/dev/null || echo "")
    if [ -n "$JAVA_BIN" ]; then
        export JAVA_HOME=$(dirname $(dirname "$JAVA_BIN"))
        export PATH="$JAVA_HOME/bin:$PATH"
        echo "[INFO] JAVA_HOME detected: $JAVA_HOME"
    else
        echo "[WARN] Java not found. Java projects may fail."
    fi
else
    echo "[INFO] JAVA_HOME already set: $JAVA_HOME"
fi

# Verify JAVA_HOME is valid
if [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    echo "[INFO] Java verified: $($JAVA_HOME/bin/java -version 2>&1 | head -n 1)"
else
    echo "[WARN] JAVA_HOME is set but java binary not found at: $JAVA_HOME/bin/java"
fi

# Validate required environment variables
SCAN_MODE="${MODE:-SOURCE}"

# UI mode needs no project metadata — hand off to the web server immediately.
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

echo "=========================================="
echo " SKT SBOM Scanner"
echo " Mode: $SCAN_MODE"
echo " Project: $PROJECT_NAME ($PROJECT_VERSION)"
echo "=========================================="

export GRADLE_OPTS="-Dorg.gradle.daemon=false"

# ========================================================
# Execute by mode
# ========================================================
case "$SCAN_MODE" in
    IMAGE)
        # Docker image analysis
        if [ -z "$TARGET_IMAGE" ]; then
            echo "[ERROR] TARGET_IMAGE is required for IMAGE mode."
            exit 1
        fi
        
        # Check Docker socket
        if [ ! -S /var/run/docker.sock ]; then
            echo "[ERROR] Docker socket not found. Please mount: -v /var/run/docker.sock:/var/run/docker.sock"
            exit 1
        fi
        
        echo "[1/2] Analyzing Docker Image: $TARGET_IMAGE"
        if ! syft "$TARGET_IMAGE" -o cyclonedx-json > "$OUTPUT_FILE" 2>/dev/null; then
            echo "[ERROR] Syft failed. Image may be non-existent or inaccessible."
            exit 1
        fi
        ;;
        
    BINARY)
        # Binary file analysis
        if [ -z "$TARGET_FILE" ]; then
            echo "[ERROR] TARGET_FILE is required for BINARY mode."
            exit 1
        fi
        
        if [ ! -f "$TARGET_FILE" ]; then
            echo "[ERROR] Target file not found: $TARGET_FILE"
            exit 1
        fi
        
        echo "[1/2] Analyzing Binary File: $TARGET_FILE"
        if ! syft "file:$TARGET_FILE" -o cyclonedx-json > "$OUTPUT_FILE" 2>&1; then
            echo "[WARN] Standard binary analysis failed. Trying alternative method..."
            # Extract basic binary information
            FILE_INFO=$(file "$TARGET_FILE")
            cat > "$OUTPUT_FILE" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "component": {
      "type": "file",
      "name": "$(basename $TARGET_FILE)",
      "version": "$PROJECT_VERSION",
      "description": "$FILE_INFO"
    }
  },
  "components": []
}
EOF
        fi
        ;;
        
    ROOTFS)
        # RootFS directory analysis
        if [ -z "$TARGET_DIR" ]; then
            echo "[ERROR] TARGET_DIR is required for ROOTFS mode."
            exit 1
        fi
        
        if [ ! -d "$TARGET_DIR" ]; then
            echo "[ERROR] Target directory not found: $TARGET_DIR"
            exit 1
        fi
        
        echo "[1/2] Analyzing RootFS Directory: $TARGET_DIR"
        if ! syft "dir:$TARGET_DIR" -o cyclonedx-json > "$OUTPUT_FILE" 2>/dev/null; then
            echo "[ERROR] Syft failed to analyze directory."
            exit 1
        fi
        ;;
        
    SOURCE|*)
        # Source code analysis
        echo "[1/2] Analyzing Source Code..."
        
        # Check working directory
        if [ ! "$(ls -A /src)" ]; then
            echo "[ERROR] /src directory is empty. Please mount your source code: -v \$(pwd):/src"
            exit 1
        fi
        
        # Handle Python 2.x requirements.txt
        if [ -f "requirements.txt" ] && command -v python2 >/dev/null 2>&1; then
            # Detect Python 2.x project
            if head -n 5 requirements.txt | grep -qiE 'python_version.*2\.|==.*py2'; then
                echo "[INFO] Detected Python 2.x project. Installing dependencies..."
                if python2 -m pip install --user -r requirements.txt 2>&1 | grep -i error || true; then
                    echo "[WARN] Some Python 2 dependencies failed to install."
                fi
            fi
        fi
        
        # Handle Python 3.x requirements.txt
        if [ -f "requirements.txt" ]; then
            echo "[INFO] Found requirements.txt. Installing Python 3 dependencies..."
            if python3 -m venv /tmp/venv 2>/dev/null && source /tmp/venv/bin/activate; then
                pip install --quiet -r requirements.txt 2>&1 | grep -i error || true
            else
                echo "[WARN] Python venv creation failed. Continuing without Python dependencies."
            fi
        fi
        
        # Handle Ruby Gemfile
        if [ -f "Gemfile" ] && command -v bundle >/dev/null 2>&1; then
            echo "[INFO] Found Gemfile. Installing Ruby dependencies..."
            bundle install --quiet 2>&1 | grep -i error || true
        fi
        
        # Handle PHP composer.json
        if [ -f "composer.json" ] && command -v composer >/dev/null 2>&1; then
            echo "[INFO] Found composer.json. Installing PHP dependencies..."
            composer install --quiet --no-interaction 2>&1 | grep -i error || true
        fi
        
        # Handle Java Maven pom.xml
        if [ -f "pom.xml" ] && command -v mvn >/dev/null 2>&1; then
            echo "[INFO] Found pom.xml. Downloading Maven dependencies..."
            mvn dependency:resolve dependency:resolve-plugins -q 2>&1 | grep -iE 'error|failure' || true
        fi
        
        # Handle Java Gradle build.gradle
        if [ -f "build.gradle" ] || [ -f "build.gradle.kts" ]; then
            if [ -x "./gradlew" ]; then
                echo "[INFO] Found Gradle project. Downloading dependencies..."
                ./gradlew dependencies --quiet 2>&1 | grep -iE 'error|failure' || true
            elif command -v gradle >/dev/null 2>&1; then
                echo "[INFO] Found Gradle project. Downloading dependencies..."
                gradle dependencies --quiet 2>&1 | grep -iE 'error|failure' || true
            fi
        fi
        
        # Handle Rust Cargo.toml
        if [ -f "Cargo.toml" ] && command -v cargo >/dev/null 2>&1; then
            echo "[INFO] Found Cargo.toml. Generating Cargo.lock..."
            . "$HOME/.cargo/env"
            cargo generate-lockfile 2>&1 | grep -i error || true
        fi

        # Handle Python Poetry (pyproject.toml + poetry.lock)
        if [ -f "pyproject.toml" ] && grep -q "\[tool.poetry\]" pyproject.toml 2>/dev/null && command -v poetry >/dev/null 2>&1; then
            echo "[INFO] Found Poetry project. Resolving dependencies..."
            poetry lock --no-interaction 2>&1 | grep -iE 'error' || true
        fi

        # Handle Go modules (go.mod)
        if [ -f "go.mod" ] && command -v go >/dev/null 2>&1; then
            echo "[INFO] Found go.mod. Downloading Go modules..."
            go mod download 2>&1 | grep -iE 'error' || true
        fi

        # Handle .NET (*.csproj / *.sln)
        if { ls ./*.csproj >/dev/null 2>&1 || ls ./*.sln >/dev/null 2>&1; } && command -v dotnet >/dev/null 2>&1; then
            echo "[INFO] Found .NET project. Restoring NuGet packages..."
            dotnet restore 2>&1 | grep -iE 'error' || true
        fi

        # Handle Node.js yarn / pnpm lockfiles (npm handled natively by cdxgen)
        if [ -f "yarn.lock" ] && command -v yarn >/dev/null 2>&1; then
            echo "[INFO] Found yarn.lock. Installing dependencies..."
            yarn install --silent 2>&1 | grep -iE 'error' || true
        elif [ -f "pnpm-lock.yaml" ] && command -v pnpm >/dev/null 2>&1; then
            echo "[INFO] Found pnpm-lock.yaml. Installing dependencies..."
            pnpm install --silent 2>&1 | grep -iE 'error' || true
        fi

        export NODE_OPTIONS="--max-old-space-size=8192"
        
        # Grant execution permissions
        [ -f "./gradlew" ] && chmod +x ./gradlew 2>/dev/null || true
        [ -f "./mvnw" ] && chmod +x ./mvnw 2>/dev/null || true
        
        # Run cdxgen (CycloneDX 1.6)
        if ! cdxgen -r --spec-version 1.6 -o "$OUTPUT_FILE" . 2>&1 | tee /tmp/cdxgen.log; then
            echo "[ERROR] cdxgen failed. Check /tmp/cdxgen.log for details."
            cat /tmp/cdxgen.log
            exit 1
        fi
        ;;
esac

# ========================================================
# SBOM Validation
# ========================================================
if [ ! -s "$OUTPUT_FILE" ]; then
    echo "[ERROR] SBOM file is empty or not generated."
    exit 1
fi

echo "[INFO] SBOM generated: $OUTPUT_FILE"

# ========================================================
# Post-processing: normalize, deep-license, notice, security, sign
# ========================================================
OUT_PREFIX="${SAFE_PROJECT}_${SAFE_VERSION}"
LIBDIR="/usr/local/lib/sbom"
ARTIFACTS=("$OUTPUT_FILE")

# Deterministic / byte-stable output
if [ "${BYTE_STABLE:-false}" = "true" ]; then
    bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE" --stable || true
else
    bash "$LIBDIR/normalize-sbom.sh" "$OUTPUT_FILE" || true
fi

# Deep license detection (scancode, opt-in, SOURCE only)
if [ "${DEEP_LICENSE:-false}" = "true" ] && [ "$SCAN_MODE" = "SOURCE" ]; then
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

# Open-source notice (Text + HTML)
if [ "${GENERATE_NOTICE:-false}" = "true" ]; then
    if bash "$LIBDIR/generate-notice.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"; then
        ARTIFACTS+=("${OUT_PREFIX}_NOTICE.txt" "${OUT_PREFIX}_NOTICE.html")
    fi
fi

# Security report (Trivy: JSON + Markdown + HTML)
if [ "${GENERATE_SECURITY:-false}" = "true" ]; then
    if bash "$LIBDIR/scan-security.sh" "$OUTPUT_FILE" "$OUT_PREFIX" "$PROJECT_NAME"; then
        ARTIFACTS+=("${OUT_PREFIX}_security.json" "${OUT_PREFIX}_security.md" "${OUT_PREFIX}_security.html")
    fi
fi

# Optional cosign signing (opt-in; cosign install is roadmap Phase 5)
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

# ========================================================
# Copy all artifacts to host output (always)
# ========================================================
if [ -n "$HOST_OUTPUT_DIR" ] && [ -d "$HOST_OUTPUT_DIR" ]; then
    for art in "${ARTIFACTS[@]}"; do
        [ -f "$art" ] || continue
        if [ "$art" -ef "$HOST_OUTPUT_DIR/$(basename "$art")" ]; then
            echo "[SUCCESS] saved (in-place): $art"
        elif cp "$art" "$HOST_OUTPUT_DIR/" 2>/dev/null; then
            echo "[SUCCESS] copied: $HOST_OUTPUT_DIR/$(basename "$art")"
        else
            echo "[WARN] copy failed for $art (available in container at: $art)"
        fi
    done
else
    echo "[WARN] HOST_OUTPUT_DIR not set/accessible. Artifacts at: $(pwd)"
fi

# ========================================================
# Upload Handling
# ========================================================
if [ "${UPLOAD_ENABLED:-true}" = "false" ]; then
    echo "[INFO] Generate-only mode. Done."
    exit 0
fi

# Upload to Dependency Track
echo "[2/2] Uploading to Dependency Track..."

if [ -z "$API_KEY" ] || [ -z "$API_URL" ]; then
    echo "[ERROR] API_KEY and API_URL are required for upload."
    exit 1
fi

# Server connectivity test
if ! curl -s --max-time 5 "$API_URL/api/version" > /dev/null 2>&1; then
    echo "[WARN] Cannot reach Dependency Track at $API_URL. Check network/firewall."
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
    echo "[ERROR] Upload failed (HTTP $HTTP_CODE)"
    echo "Response: $BODY"
    exit 1
fi