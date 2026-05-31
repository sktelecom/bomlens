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
FORCE_FIRMWARE="false"; ANALYZE_SBOM=""
GIT_URL=""; GIT_REF=""; NO_REPORT="false"; GENERATE_REPORT="false"
INGEST_SOURCE="false"; SCAN_INPUT_DIR=""; CLEANUP_DIRS=()

# ========================================================
# Parse arguments
# ========================================================
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --project) PROJECT_NAME="$2"; shift ;;
        --version) PROJECT_VERSION="$2"; shift ;;
        --target) TARGET="$2"; shift ;;
        --analyze|--sbom) ANALYZE_SBOM="$2"; shift ;;
        --git) GIT_URL="$2"; shift ;;
        --branch|--ref) GIT_REF="$2"; shift ;;
        --no-report) NO_REPORT="true" ;;
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
  --target <target>      Not set: source (current dir) | image name | file |
                         directory | .zip/.tar.gz archive (auto-extracted)
  --git <url>            Clone a git/GitHub URL (shallow) and scan as source.
                         Private repos: set GIT_TOKEN env. Mutually exclusive
                         with --target/--analyze/--firmware.
  --branch <ref>         Branch, tag, or commit for --git (default: repo default)
  --firmware             Force firmware mode for --target file (opt-in image)
  --analyze <sbom>       Validate + analyze a supplier SBOM (alias: --sbom).
                         CycloneDX or SPDX; mutually exclusive with --target.
  --generate-only        Save locally without uploading
  --notice               Open-source NOTICE (txt+html)
  --security             Trivy security report (json+md+html)
  --all                  --notice --security
  --no-report            Skip the 오픈소스위험분석보고서 (risk-report). By default
                         the risk report (+notice+security) is generated in
                         every mode; --no-report opts out.
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
        -e MODE=UI -e UI_PORT=8080 -e SBOM_UI_HOST_DIR="$(pwd)" "$POSTPROCESS_IMAGE"
fi

# ========================================================
# Validate
# ========================================================
[ -n "$PROJECT_NAME" ] && [ -n "$PROJECT_VERSION" ] || { echo "[ERROR] --project and --version are required ($0 --help)."; exit 1; }
docker_check

SAFE_PROJECT=$(echo "$PROJECT_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g')
SAFE_VERSION=$(echo "$PROJECT_VERSION" | sed 's/[^a-zA-Z0-9._-]/_/g')
OUTPUT_FILE="${SAFE_PROJECT}_${SAFE_VERSION}_bom.json"
SOURCE_DIR="$(pwd)"          # host-output anchor: artifacts land where the user ran the tool
SCAN_INPUT_DIR="$SOURCE_DIR" # what cdxgen scans (overridden by git clone / zip extract)
UPLOAD_VAR="true"; [ "$GENERATE_ONLY" = "true" ] && UPLOAD_VAR="false"

# Temp dirs (git clone / archive extract) are cleaned on any exit.
cleanup() { local d; for d in "${CLEANUP_DIRS[@]}"; do [ -n "$d" ] && rm -rf -- "$d"; done; }
trap cleanup EXIT INT TERM

# Common -e flags for the post-process image.
# HOST_UID/HOST_GID let the (root) container chown artifacts back to the calling
# user, so Linux hosts/CI runners can read them (macOS Docker maps UIDs already).
pp_env() {
    printf ' -e GENERATE_NOTICE=%s -e GENERATE_SECURITY=%s -e GENERATE_REPORT=%s -e DEEP_LICENSE=%s -e SIGN_SBOM=%s -e BYTE_STABLE=%s -e UPLOAD_ENABLED=%s -e PROJECT_NAME=%q -e PROJECT_VERSION=%q -e HOST_OUTPUT_DIR=/host-output -e HOST_UID=%s -e HOST_GID=%s -e API_KEY=%q -e API_URL=%q' \
        "$GENERATE_NOTICE" "$GENERATE_SECURITY" "$GENERATE_REPORT" "$DEEP_LICENSE" "$SIGN_SBOM" "$BYTE_STABLE" "$UPLOAD_VAR" "$PROJECT_NAME" "$PROJECT_VERSION" "$(id -u)" "$(id -g)" "$DEFAULT_API_KEY" "$SERVER_URL"
}

# cosign key mount + env, only when --sign is set with a real key. The private
# key dir is mounted READ-ONLY and the password comes from the host env — never
# hardcoded (CLAUDE.md security). Without this the container's COSIGN_KEY is
# unset and entrypoint.sh skips signing, so `--sign` produced no .sig.
cosign_run() {
    [ "$SIGN_SBOM" = "true" ] && [ -n "${COSIGN_KEY:-}" ] && [ -f "$COSIGN_KEY" ] || return 0
    local d f
    d="$(cd "$(dirname "$COSIGN_KEY")" && pwd)"; f="$(basename "$COSIGN_KEY")"
    printf ' -v %q:/cosign:ro -e COSIGN_KEY=%q -e COSIGN_PASSWORD=%q' "$d" "/cosign/$f" "${COSIGN_PASSWORD:-}"
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

# A git/GitHub URL we are willing to clone. Strict allowlist (anti-injection):
# only http(s)/git/ssh/file schemes, no whitespace, no '..', no leading '-' .
is_git_url() {
    case "$1" in
        -*) return 1 ;;
        *..*) return 1 ;;
        *" "*|*$'\t'*) return 1 ;;
    esac
    [[ "$1" =~ ^(https?://|git@|ssh://git@|file://)[A-Za-z0-9._~:@/+-]+$ ]]
}

# A source archive we auto-extract and scan as SOURCE.
is_archive() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        *.zip|*.tar.gz|*.tgz|*.tar.bz2|*.tar.xz|*.tar) return 0 ;;
        *) return 1 ;;
    esac
}

# Pick the scan root inside an extracted/cloned temp dir: if it contains exactly
# one subdirectory (and no top-level files), descend into it (GitHub tarballs/zips
# wrap everything in a single `repo-main/` folder).
flatten_single_dir() {
    local d="$1" entries
    # shellcheck disable=SC2012
    entries=$(ls -A "$d" 2>/dev/null)
    if [ "$(printf '%s\n' "$entries" | grep -c .)" = "1" ] && [ -d "$d/$entries" ]; then
        printf '%s' "$d/$entries"
    else
        printf '%s' "$d"
    fi
}

ingest_git() {
    local url="$1" tmp args
    is_git_url "$url" || { echo "[ERROR] unsafe or unsupported git URL: $url"; exit 1; }
    command -v git >/dev/null 2>&1 || { echo "[ERROR] git not installed (required for --git)."; exit 1; }
    # Clone under the pwd (already shared with Docker Desktop) rather than $TMPDIR,
    # which on macOS is /var/folders and is NOT mounted into the cdxgen container.
    tmp=$(mktemp -d "$SOURCE_DIR/.sbom-git.XXXXXX") || { echo "[ERROR] mktemp failed"; exit 1; }
    CLEANUP_DIRS+=("$tmp")
    # Inject a token for private https repos into a LOCAL var only (never logged).
    local clone_url="$url"
    if [ -n "${GIT_TOKEN:-}" ]; then
        case "$url" in
            https://*) clone_url="https://x-access-token:${GIT_TOKEN}@${url#https://}" ;;
        esac
    fi
    echo "[INFO] Cloning $url (shallow)..."
    args=(clone --depth 1 --single-branch)
    [ -n "$GIT_REF" ] && args+=(--branch "$GIT_REF")
    # `--` stops option parsing so a hostile URL can't smuggle git options.
    if ! GIT_TERMINAL_PROMPT=0 git "${args[@]}" -- "$clone_url" "$tmp/repo" 2>/tmp/sbom-git-err; then
        echo "[ERROR] git clone failed for $url"; sed 's/x-access-token:[^@]*@/x-access-token:***@/g' /tmp/sbom-git-err 2>/dev/null; rm -f /tmp/sbom-git-err; exit 1
    fi
    rm -f /tmp/sbom-git-err
    SCAN_INPUT_DIR=$(flatten_single_dir "$tmp/repo")
    INGEST_SOURCE="true"
}

ingest_archive() {
    local arc="$1" tmp lower
    [ -f "$arc" ] || { echo "[ERROR] archive not found: $arc"; exit 1; }
    # Extract under the pwd (shared with Docker Desktop), not $TMPDIR (/var/folders
    # on macOS is not mounted into the cdxgen container).
    tmp=$(mktemp -d "$SOURCE_DIR/.sbom-arc.XXXXXX") || { echo "[ERROR] mktemp failed"; exit 1; }
    CLEANUP_DIRS+=("$tmp")
    lower=$(printf '%s' "$arc" | tr '[:upper:]' '[:lower:]')
    echo "[INFO] Extracting archive $arc..."
    case "$lower" in
        *.zip)
            # zip-slip guard: reject absolute or parent-traversal entries before extracting.
            if command -v unzip >/dev/null 2>&1; then
                if unzip -l "$arc" 2>/dev/null | awk '{print $4}' | grep -qE '(^/|(^|/)\.\.(/|$))'; then
                    echo "[ERROR] unsafe path in archive (zip-slip)"; exit 1
                fi
                unzip -q -d "$tmp" -- "$arc" || { echo "[ERROR] unzip failed"; exit 1; }
            else
                # bsdtar (Git Bash on Windows) extracts .zip and rejects traversal.
                tar -tf "$arc" 2>/dev/null | grep -qE '(^/|(^|/)\.\.(/|$))' && { echo "[ERROR] unsafe path in archive"; exit 1; }
                tar -C "$tmp" -xf "$arc" || { echo "[ERROR] tar (zip) extract failed"; exit 1; }
            fi
            ;;
        *)
            tar -tf "$arc" 2>/dev/null | grep -qE '(^/|(^|/)\.\.(/|$))' && { echo "[ERROR] unsafe path in archive"; exit 1; }
            tar -C "$tmp" --no-same-owner -xf "$arc" || { echo "[ERROR] tar extract failed"; exit 1; }
            ;;
    esac
    SCAN_INPUT_DIR=$(flatten_single_dir "$tmp")
    INGEST_SOURCE="true"
}

# --------------------------------------------------------
# Ingestion: git URL (--git or a URL-shaped --target) / source archive.
# Produces a local SCAN_INPUT_DIR and forces SOURCE mode below.
# --------------------------------------------------------
# Allow a git URL passed positionally via --target.
if [ -z "$GIT_URL" ] && [ -n "$TARGET" ] && is_git_url "$TARGET"; then
    GIT_URL="$TARGET"; TARGET=""
fi
if [ -n "$GIT_URL" ]; then
    [ -z "$TARGET" ]      || { echo "[ERROR] --git is mutually exclusive with --target."; exit 1; }
    [ -z "$ANALYZE_SBOM" ] || { echo "[ERROR] --git is mutually exclusive with --analyze."; exit 1; }
    [ "$FORCE_FIRMWARE" = "true" ] && { echo "[ERROR] --git cannot be combined with --firmware."; exit 1; }
    ingest_git "$GIT_URL"
elif [ -n "$TARGET" ] && [ -f "$TARGET" ] && is_archive "$TARGET"; then
    [ "$FORCE_FIRMWARE" = "true" ] && { echo "[ERROR] --firmware cannot be combined with a source archive."; exit 1; }
    ingest_archive "$TARGET"
fi

MODE="SOURCE"
if [ "$INGEST_SOURCE" = "true" ]; then
    # A git clone / extracted archive is always scanned as SOURCE (the temp dir
    # would otherwise be detected as ROOTFS below).
    MODE="SOURCE"
elif [ -n "$ANALYZE_SBOM" ]; then
    # Supplier SBOM analysis takes precedence; it does not use --target.
    [ -z "$TARGET" ] || { echo "[ERROR] --analyze/--sbom is mutually exclusive with --target."; exit 1; }
    [ "$FORCE_FIRMWARE" = "true" ] && { echo "[ERROR] --firmware cannot be combined with --analyze."; exit 1; }
    [ -f "$ANALYZE_SBOM" ] || { echo "[ERROR] --analyze SBOM file not found: $ANALYZE_SBOM"; exit 1; }
    MODE="ANALYZE"
    # The risk report needs both license and vulnerability data, so enable them.
    GENERATE_NOTICE="true"; GENERATE_SECURITY="true"
elif [ -n "$TARGET" ]; then
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

# Unified 오픈소스위험분석보고서 (risk-report) is on by default in every mode.
# It aggregates license (NOTICE) + vulnerability (security), so both are forced
# on unless the user opts out with --no-report. ANALYZE already enabled them.
if [ "$NO_REPORT" != "true" ]; then
    GENERATE_REPORT="true"; GENERATE_NOTICE="true"; GENERATE_SECURITY="true"
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
    # Separate single-pattern globs: `ls a.gradle *.gradle.kts` exits non-zero when
    # one variant is absent, which would mis-skip gradle-only / kts-only projects.
    { [ -f "$d/pom.xml" ] || ls "$d"/*.gradle >/dev/null 2>&1 || ls "$d"/*.gradle.kts >/dev/null 2>&1; } && langs="$langs java"
    { [ -f "$d/requirements.txt" ] || [ -f "$d/pyproject.toml" ]; } && langs="$langs python"
    [ -f "$d/package.json" ] && langs="$langs node"
    [ -f "$d/composer.json" ] && langs="$langs php"
    { ls "$d"/*.csproj >/dev/null 2>&1 || ls "$d"/*.sln >/dev/null 2>&1; } && langs="$langs dotnet"
    # C/C++ with a package manager (Conan / vcpkg). cdxgen's all-in-one image
    # resolves these; raw CMake/Make C/C++ has no manifest and stays "unknown".
    { [ -f "$d/conanfile.txt" ] || [ -f "$d/conanfile.py" ] || [ -f "$d/vcpkg.json" ]; } && langs="$langs cpp"
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
[ -n "$GIT_URL" ] && echo "  Git:    $GIT_URL${GIT_REF:+ (ref: $GIT_REF)}"
echo "=========================================="

# ========================================================
# Stage 1: produce SBOM
# ========================================================
if [ "$MODE" = "SOURCE" ]; then
    # SCAN_INPUT_DIR = the tree we scan (current dir, or a cloned/extracted temp
    # dir). SOURCE_DIR ($(pwd)) stays the host-output anchor so artifacts land
    # where the user ran the tool, even for --git/zip ingestion.
    [ -n "$(ls -A "$SCAN_INPUT_DIR" 2>/dev/null)" ] || { echo "[ERROR] source directory is empty: $SCAN_INPUT_DIR"; exit 1; }
    LANG_DET=$(detect_lang "$SCAN_INPUT_DIR")
    if [ "$LANG_DET" = "android" ]; then
        API=$(android_api "$SCAN_INPUT_DIR")
        CDX_IMG="${ANDROID_IMAGE_PREFIX}${API}:latest"
        echo "[INFO] Android source detected (compileSdk=$API) -> $CDX_IMG"
    else
        CDX_IMG=$(img_for_lang "$LANG_DET")
        echo "[INFO] Language: $LANG_DET -> $CDX_IMG"
        if [ "$LANG_DET" = "swift" ]; then
            echo "[WARN] iOS/Swift: CocoaPods(Podfile.lock) resolves fully; SPM is augmented via 'swift package resolve'."
            echo "[WARN]   iOS-platform (UIKit) and Xcode-driven dependencies require macOS and are NOT resolved in this Linux container."
        fi
        if [ "$LANG_DET" = "cpp" ]; then
            echo "[WARN] C/C++: dependencies resolve only via a package manager (Conan/vcpkg)."
            echo "[WARN]   Raw CMake/Make sources yield a sparse SBOM; add --deep-license for 1st-party license headers."
        fi
        if [ "$LANG_DET" = "unknown" ]; then
            echo "[WARN] No package manifest detected; using cdxgen all-in-one (results may be sparse)."
        fi
    fi
    echo "[1/2] Generating SBOM (cdxgen)..."
    CACHE_MOUNTS=""
    [ -d "$HOME/.gradle" ] && CACHE_MOUNTS="$CACHE_MOUNTS -v \"$HOME/.gradle\":/root/.gradle"
    [ -d "$HOME/.m2" ] && CACHE_MOUNTS="$CACHE_MOUNTS -v \"$HOME/.m2\":/root/.m2"
    # HOME=/tmp/sbomhome: writable for both root and non-root (cyclonedx) images,
    # so maven/cargo/etc. caches resolve regardless of the base image's user.
    # -u 0:0: the all-in-one fallback image runs as a non-root user and could not
    # write the host-owned /app on Linux (EACCES). Per-language images are already
    # root (no-op); the resulting bom is chown'd back to the host user in stage 2.
    eval docker run --rm -u 0:0 \
        -v "\"$SCAN_INPUT_DIR\"":/app \
        -v "\"$BUILD_PREP\"":/tmp/build-prep.sh:ro \
        $CACHE_MOUNTS \
        -e HOME=/tmp/sbomhome \
        -e MAVEN_OPTS=-Dmaven.repo.local=/tmp/sbomhome/.m2 \
        --entrypoint sh "\"$CDX_IMG\"" \
        -c "'sh /tmp/build-prep.sh /app \"/app/$OUTPUT_FILE\" 1.6'" \
        || { echo "[ERROR] SBOM generation failed (stage 1)"; exit 1; }

    echo "[2/2] Post-processing..."
    # Mount the scanned tree as /src (so POSTPROCESS finds the bom + deep-license
    # sees the real source) and the pwd as /host-output (artifact destination).
    eval docker run --rm \
        -v "\"$SCAN_INPUT_DIR\"":/src -v "\"$SOURCE_DIR\"":/host-output \
        --add-host=host.docker.internal:host-gateway \
        -e MODE=POSTPROCESS $(pp_env)$(cosign_run) \
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
        ANALYZE) FD="$(cd "$(dirname "$ANALYZE_SBOM")" && pwd)"; FN="$(basename "$ANALYZE_SBOM")"; VOL="-v \"$FD\":/input:ro -v \"$SOURCE_DIR\":/host-output"; ENVV="-e ANALYZE_SBOM=\"/input/$FN\"" ;;
    esac
    eval docker run --rm $VOL \
        --add-host=host.docker.internal:host-gateway \
        -e MODE="$MODE" $ENVV $(pp_env)$(cosign_run) \
        "\"$RUN_IMAGE\""
fi

echo "=========================================="
echo "  Analysis Complete!"
if [ "$GENERATE_ONLY" = "true" ]; then
    echo "  SBOM: ${OUTPUT_FILE}"
    [ "$GENERATE_NOTICE" = "true" ]   && echo "  Notice:   ${SAFE_PROJECT}_${SAFE_VERSION}_NOTICE.{txt,html}"
    [ "$GENERATE_SECURITY" = "true" ] && echo "  Security: ${SAFE_PROJECT}_${SAFE_VERSION}_security.{json,md,html}"
    [ "$MODE" = "ANALYZE" ] && echo "  Conformance: ${SAFE_PROJECT}_${SAFE_VERSION}_conformance.{json,md,html}"
    [ "$GENERATE_REPORT" = "true" ] && echo "  Risk report: ${SAFE_PROJECT}_${SAFE_VERSION}_risk-report.{md,html}"
fi
echo "=========================================="
