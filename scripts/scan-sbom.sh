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
#                   Android -> self-built bomlens-android-sdk<API> OR
#                   mixed   -> cdxgen all-in-one
#   Stage 2 (post): post-process image -> normalize/notice/security/sign
#   image/binary/rootfs: post-process image (syft) does both stages in one.
# ========================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_PREP="$REPO_DIR/docker/lib/build-prep.sh"

POSTPROCESS_IMAGE="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/bomlens:latest}"           # legacy aliases: sbom-generator, sbom-scanner
FIRMWARE_IMAGE="${SBOM_FIRMWARE_IMAGE:-ghcr.io/sktelecom/bomlens-firmware:latest}"     # opt-in (unblob/cve-bin-tool); legacy alias: sbom-scanner-firmware
AIBOM_IMAGE="${SBOM_AIBOM_IMAGE:-ghcr.io/sktelecom/bomlens-aibom:latest}"               # opt-in (OWASP AIBOM Generator; HuggingFace network)
# Language detection + cdxgen image selection are shared with the web UI source
# path (docker/entrypoint.sh) so both resolve transitive deps identically.
# shellcheck source=docker/lib/source-detect.sh
. "$REPO_DIR/docker/lib/source-detect.sh"

SERVER_URL="${API_URL:-http://host.docker.internal:8081}"
DEFAULT_API_KEY="${API_KEY:-odt_YOUR_REAL_API_KEY_HERE}"

# Upload target: dependency-track (default, DT-compatible) or trusca (native
# CycloneDX ingest — Bearer auth, requires a pre-existing project id).
UPLOAD_TARGET="${UPLOAD_TARGET:-dependency-track}"
TRUSCA_PROJECT_ID="${TRUSCA_PROJECT_ID:-}"
TRUSCA_REF="${TRUSCA_REF:-}"; TRUSCA_RELEASE="${TRUSCA_RELEASE:-}"

GENERATE_ONLY="false"; TARGET=""; PROJECT_NAME=""; PROJECT_VERSION=""
GENERATE_NOTICE="false"; GENERATE_SECURITY="false"; DEEP_LICENSE="false"
SIGN_SBOM="false"; BYTE_STABLE="false"; UI_MODE="false"; UI_PORT="${UI_PORT:-8080}"
FORCE_FIRMWARE="false"; ANALYZE_SBOM=""; MODEL=""
IDENTIFY_VENDORED="false"
SCANOSS_API_URL="${SCANOSS_API_URL:-}"; SCANOSS_API_KEY="${SCANOSS_API_KEY:-}"
GIT_URL=""; GIT_REF=""; NO_REPORT="false"; GENERATE_REPORT="false"
INGEST_SOURCE="false"; SCAN_INPUT_DIR=""; CLEANUP_DIRS=()
MERGE_FILES=()
MERGE_ROOT=""
OUTPUT_BASE=""; TIMESTAMP="false"

# ========================================================
# Parse arguments
# ========================================================
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --project) PROJECT_NAME="$2"; shift ;;
        --version) PROJECT_VERSION="$2"; shift ;;
        --target) TARGET="$2"; shift ;;
        --analyze|--sbom) ANALYZE_SBOM="$2"; shift ;;
        --model) MODEL="$2"; shift ;;
        --merge)
            # Variadic: absorb every following token until the next option (a
            # token starting with '-'). These are already-generated SBOMs to
            # combine, not scan targets, so they get their own flag.
            shift
            while [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ]; do
                MERGE_FILES+=("$1"); shift
            done
            continue ;;   # we already consumed our args; skip the trailing shift
        --merge-root) MERGE_ROOT="$2"; shift ;;
        --git) GIT_URL="$2"; shift ;;
        --branch|--ref) GIT_REF="$2"; shift ;;
        --no-report) NO_REPORT="true" ;;
        --generate-only) GENERATE_ONLY="true" ;;
        --upload-target) UPLOAD_TARGET="$2"; shift ;;
        --trusca) UPLOAD_TARGET="trusca"; TRUSCA_PROJECT_ID="$2"; shift ;;
        --notice) GENERATE_NOTICE="true" ;;
        --security) GENERATE_SECURITY="true" ;;
        --all) GENERATE_NOTICE="true"; GENERATE_SECURITY="true" ;;
        --deep-license) DEEP_LICENSE="true" ;;
        --identify-vendored) IDENTIFY_VENDORED="true" ;;
        --sign) SIGN_SBOM="true" ;;
        --byte-stable) BYTE_STABLE="true" ;;
        --firmware) FORCE_FIRMWARE="true" ;;
        --output-dir|-o) OUTPUT_BASE="$2"; shift ;;
        --timestamp) TIMESTAMP="true" ;;
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
  --branch <ref>         Branch, tag, or commit for --git (alias: --ref;
                         default: repo default)
  --firmware             Force firmware mode for --target file (opt-in image)
  --analyze <sbom>       Validate + analyze a supplier SBOM (alias: --sbom).
                         CycloneDX or SPDX; mutually exclusive with --target.
  --model <owner/name>   Generate an AI SBOM (CycloneDX 1.7 ML-BOM) for a
                         HuggingFace model via the OWASP AIBOM Generator (opt-in
                         image; fetches model-card metadata over the network).
                         Mutually exclusive with --target/--analyze/--git/--merge.
  --merge <a.json> <b.json> [...]
                         Merge 2+ CycloneDX SBOMs into one, dedupe by purl, and
                         stamp the root component with --project/--version. For
                         layered server delivery (OS rootfs + app + static-link).
                         Mutually exclusive with --target/--analyze/--git.
  --merge-root <file>    With --merge: keep THIS input's specVersion and root
                         component (e.g. an ML-BOM's 1.7 + modelCard) instead of
                         writing a fresh 1.6 root. Must be one of the --merge
                         files; the root is renamed to --project/--version.
  --generate-only        Save locally without uploading
  --trusca <project_id>  Upload the SBOM to TRUSCA's native ingest endpoint
                         (shorthand for --upload-target trusca with the id).
                         Needs API_URL (TRUSCA base) and API_KEY (Bearer token).
  --upload-target <t>    Upload destination: dependency-track (default) | trusca
  --notice               Open-source NOTICE (txt+html)
  --security             Trivy security report (json+md+html)
  --all                  --notice --security
  --no-report            Skip the 오픈소스위험분석보고서 (risk-report). By default
                         the risk report (+notice+security) is generated in
                         every mode; --no-report opts out.
  --deep-license         scancode deep license (opt-in image)
  --identify-vendored    Identify open source copied (vendored) into C/C++ source
                         that has no package manager. Matches file fingerprints
                         against the OSSKB service (opt-in image; sends hashes,
                         not source). See docs/guides/identify-vendored.md
  --byte-stable          Deterministic SBOM output
  --sign                 cosign sign (requires COSIGN_KEY)
  --output-dir <dir>     Base directory for outputs (alias: -o; default: current
                         dir). Each scan lands in a <project>_<version>/ subfolder
                         under it, keeping the bundle together and out of the
                         source tree.
  --timestamp            Append _YYYYMMDD-HHMMSS to the run subfolder so repeat
                         scans of the same project/version are kept side by side
                         instead of overwritten. Folder name only; SBOM bytes are
                         unchanged (orthogonal to --byte-stable).
  --ui                   Launch local web UI
  --help                 Show this help

Environment:
  FETCH_LICENSE          Resolve dependency licenses in source scans
                         (default: true; set false to skip and run faster)
  SECURITY_ENRICH        Enrich the security report with EPSS + CISA KEV
                         signals (default: true; set false for air-gapped)
  GIT_TOKEN              Token for cloning private --git repos
  COSIGN_KEY             Signing key for --sign
  SBOM_OUTPUT_FLAT       Set to 1 to write artifacts flat in the output base
                         (no per-run subfolder), matching the pre-isolation layout
  SBOM_SCANNER_IMAGE     Override the scanner image
  SBOM_FIRMWARE_IMAGE    Override the firmware image
  SBOM_AIBOM_IMAGE       Override the AI SBOM (OWASP AIBOM Generator) image
  SCANOSS_API_URL        Vendored-OSS endpoint for --identify-vendored
                         (default: the free OSSKB API; set to a self-hosted
                         SCANOSS endpoint for air-gapped or high-volume use)
  SCANOSS_API_KEY        Credential for SCANOSS_API_URL (if the endpoint needs one)
  API_URL                Upload server base URL (DT server, or TRUSCA base)
  API_KEY                Upload credential (DT: X-Api-Key; TRUSCA: Bearer token)
  UPLOAD_TARGET          dependency-track (default) | trusca
  TRUSCA_PROJECT_ID      Target TRUSCA project id (UUID, required for trusca)
  TRUSCA_REF             Ingest ref label (default: main)
  TRUSCA_RELEASE         Ingest release label (default: --version value)

Architecture: source SBOM generation uses cdxgen's per-language images
(on-demand); this tool orchestrates + post-processes.
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
    # The web UI owns per-run subfolders itself (server.py creates them under the
    # mounted base). Honor --output-dir as that base; default to the current dir.
    UI_BASE="${OUTPUT_BASE:-$(pwd)}"
    echo "=========================================="
    echo "  BomLens Web UI — http://localhost:${UI_PORT}  (Ctrl+C to stop)"
    echo "=========================================="
    ( sleep 2; (command -v open >/dev/null 2>&1 && open "http://localhost:${UI_PORT}") \
        || (command -v xdg-open >/dev/null 2>&1 && xdg-open "http://localhost:${UI_PORT}") ) >/dev/null 2>&1 &
    exec docker run --rm -it -p "${UI_PORT}:8080" \
        -v "$UI_BASE":/src -v "$UI_BASE":/host-output \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -e MODE=UI -e UI_PORT=8080 -e SBOM_UI_HOST_DIR="$UI_BASE" "$POSTPROCESS_IMAGE"
fi

# ========================================================
# Validate
# ========================================================
[ -n "$PROJECT_NAME" ] && [ -n "$PROJECT_VERSION" ] || { echo "[ERROR] --project and --version are required ($0 --help)."; exit 1; }
if [ "$UPLOAD_TARGET" = "trusca" ] && [ "$GENERATE_ONLY" != "true" ] && [ -z "$TRUSCA_PROJECT_ID" ]; then
    echo "[ERROR] TRUSCA upload requires a project id: --trusca <id> or TRUSCA_PROJECT_ID env."; exit 1
fi
docker_check

SAFE_PROJECT=$(echo "$PROJECT_NAME" | sed 's/[^a-zA-Z0-9._-]/_/g')
SAFE_VERSION=$(echo "$PROJECT_VERSION" | sed 's/[^a-zA-Z0-9._-]/_/g')
OUTPUT_FILE="${SAFE_PROJECT}_${SAFE_VERSION}_bom.json"
SOURCE_DIR="$(pwd)"          # input anchor: the dir the user ran the tool in
SCAN_INPUT_DIR="$SOURCE_DIR" # what cdxgen scans (overridden by git clone / zip extract)

# Output base + per-run subfolder. Input (SOURCE_DIR/SCAN_INPUT_DIR) and output
# (OUTPUT_HOST_DIR) are kept separate so a source scan never litters the tree it
# scans. Each run lands in <base>/<project>_<version>[_<ts>]/ so the 8~13-file
# bundle stays together. SBOM_OUTPUT_FLAT=1 restores the legacy flat layout.
OUTPUT_BASE="${OUTPUT_BASE:-$(pwd)}"
RUN_NAME="${SAFE_PROJECT}_${SAFE_VERSION}"
[ "$TIMESTAMP" = "true" ] && RUN_NAME="${RUN_NAME}_$(date +%Y%m%d-%H%M%S)"
if [ "$SBOM_OUTPUT_FLAT" = "1" ]; then
    OUTPUT_HOST_DIR="$OUTPUT_BASE"
else
    OUTPUT_HOST_DIR="$OUTPUT_BASE/$RUN_NAME"
fi
mkdir -p "$OUTPUT_HOST_DIR" || { echo "[ERROR] cannot create output dir: $OUTPUT_HOST_DIR"; exit 1; }
OUTPUT_HOST_DIR="$(cd "$OUTPUT_HOST_DIR" && pwd)"  # absolute, for docker -v
UPLOAD_VAR="true"; [ "$GENERATE_ONLY" = "true" ] && UPLOAD_VAR="false"

# Temp dirs (git clone / archive extract) are cleaned on any exit. A container
# build step (e.g. npm install during a source scan) can leave root-owned files
# in the mounted temp dir on Linux, where the host user cannot rm them; fall back
# to clearing those via a throwaway container so nothing lingers.
cleanup() {
    local d
    for d in "${CLEANUP_DIRS[@]}"; do
        [ -n "$d" ] || continue
        rm -rf -- "$d" 2>/dev/null
        if [ -e "$d" ] && command -v docker >/dev/null 2>&1; then
            docker run --rm -v "$(dirname "$d")":/cleanup alpine:latest \
                rm -rf -- "/cleanup/$(basename "$d")" >/dev/null 2>&1 || true
        fi
    done
}
trap cleanup EXIT INT TERM

# A reproducible (--byte-stable) build must not resolve dependency licenses over
# the network: registry availability (e.g. pkg.go.dev) varies between runs, so a
# license fetched in one scan but not the next would make two otherwise-identical
# scans differ. Pin the lookup off for byte-stable scans.
FETCH_LICENSE="${FETCH_LICENSE:-true}"
[ "$BYTE_STABLE" = "true" ] && FETCH_LICENSE="false"
# EPSS + CISA KEV enrichment defaults on, but the host setting must reach the
# post-process container so SECURITY_ENRICH=false works for air-gapped runs.
SECURITY_ENRICH="${SECURITY_ENRICH:-true}"

# Common -e flags for the post-process image.
# HOST_UID/HOST_GID let the (root) container chown artifacts back to the calling
# user, so Linux hosts/CI runners can read them (macOS Docker maps UIDs already).
pp_env() {
    printf ' -e GENERATE_NOTICE=%s -e GENERATE_SECURITY=%s -e SECURITY_ENRICH=%s -e GENERATE_REPORT=%s -e DEEP_LICENSE=%s -e IDENTIFY_VENDORED=%s -e SCANOSS_API_URL=%q -e SCANOSS_API_KEY=%q -e SIGN_SBOM=%s -e BYTE_STABLE=%s -e UPLOAD_ENABLED=%s -e PROJECT_NAME=%q -e PROJECT_VERSION=%q -e HOST_OUTPUT_DIR=/host-output -e HOST_UID=%s -e HOST_GID=%s -e API_KEY=%q -e API_URL=%q -e UPLOAD_TARGET=%q -e TRUSCA_PROJECT_ID=%q -e TRUSCA_REF=%q -e TRUSCA_RELEASE=%q -e ENRICH_CDXGEN=%s' \
        "$GENERATE_NOTICE" "$GENERATE_SECURITY" "$SECURITY_ENRICH" "$GENERATE_REPORT" "$DEEP_LICENSE" "$IDENTIFY_VENDORED" "$SCANOSS_API_URL" "$SCANOSS_API_KEY" "$SIGN_SBOM" "$BYTE_STABLE" "$UPLOAD_VAR" "$PROJECT_NAME" "$PROJECT_VERSION" "$(id -u)" "$(id -g)" "$DEFAULT_API_KEY" "$SERVER_URL" "$UPLOAD_TARGET" "$TRUSCA_PROJECT_ID" "$TRUSCA_REF" "$TRUSCA_RELEASE" "${ENRICH_CDXGEN:-true}"
}

# cosign key mount + env, only when --sign is set with a real key. The private
# key dir is mounted READ-ONLY and the password comes from the host env — never
# hardcoded (credentials must not be baked in). Without this the container's COSIGN_KEY is
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

# A CycloneDX SBOM we accept as a --merge input. Anti-injection: reject '-'
# prefixes and '..' traversal. When the host has jq, also verify it is CycloneDX;
# without jq, existence is enough (the container re-validates during the merge).
is_sbom_file() {
    case "$1" in
        -*|*..*) return 1 ;;
    esac
    [ -f "$1" ] || return 1
    if command -v jq >/dev/null 2>&1; then
        jq -e '.bomFormat == "CycloneDX"' "$1" >/dev/null 2>&1
    else
        return 0
    fi
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
    [ -z "$MODEL" ]       || { echo "[ERROR] --git is mutually exclusive with --model."; exit 1; }
    [ "$FORCE_FIRMWARE" = "true" ] && { echo "[ERROR] --git cannot be combined with --firmware."; exit 1; }
    ingest_git "$GIT_URL"
elif [ -n "$TARGET" ] && [ -f "$TARGET" ] && is_archive "$TARGET"; then
    [ "$FORCE_FIRMWARE" = "true" ] && { echo "[ERROR] --firmware cannot be combined with a source archive."; exit 1; }
    ingest_archive "$TARGET"
fi

MODE="SOURCE"
if [ "${#MERGE_FILES[@]}" -gt 0 ]; then
    # Merge several already-generated SBOMs. Exclusive with every scan input.
    [ -z "$TARGET" ]      || { echo "[ERROR] --merge is mutually exclusive with --target."; exit 1; }
    [ -z "$ANALYZE_SBOM" ] || { echo "[ERROR] --merge is mutually exclusive with --analyze."; exit 1; }
    [ -z "$GIT_URL" ]     || { echo "[ERROR] --merge is mutually exclusive with --git."; exit 1; }
    [ -z "$MODEL" ]       || { echo "[ERROR] --merge is mutually exclusive with --model."; exit 1; }
    [ "$FORCE_FIRMWARE" != "true" ] || { echo "[ERROR] --merge cannot be combined with --firmware."; exit 1; }
    [ "${#MERGE_FILES[@]}" -ge 2 ] || { echo "[ERROR] --merge needs at least 2 SBOM files."; exit 1; }
    if [ -n "$MERGE_ROOT" ]; then
        MR_OK=false
        MR_RESOLVED="$(cd "$(dirname "$MERGE_ROOT")" 2>/dev/null && pwd)/$(basename "$MERGE_ROOT")"
        for mf in "${MERGE_FILES[@]}"; do
            [ "$(cd "$(dirname "$mf")" && pwd)/$(basename "$mf")" = "$MR_RESOLVED" ] && MR_OK=true
        done
        [ "$MR_OK" = "true" ] || { echo "[ERROR] --merge-root must be one of the --merge input files."; exit 1; }
    fi
    for mf in "${MERGE_FILES[@]}"; do
        is_sbom_file "$mf" || { echo "[ERROR] not a CycloneDX SBOM (or unsafe path): $mf"; exit 1; }
    done
    MODE="MERGE"
elif [ -n "$MERGE_ROOT" ]; then
    echo "[ERROR] --merge-root only applies with --merge."; exit 1
elif [ "$INGEST_SOURCE" = "true" ]; then
    # A git clone / extracted archive is always scanned as SOURCE (the temp dir
    # would otherwise be detected as ROOTFS below).
    MODE="SOURCE"
elif [ -n "$ANALYZE_SBOM" ]; then
    # Supplier SBOM analysis takes precedence; it does not use --target.
    [ -z "$TARGET" ] || { echo "[ERROR] --analyze/--sbom is mutually exclusive with --target."; exit 1; }
    [ -z "$MODEL" ]  || { echo "[ERROR] --analyze/--sbom is mutually exclusive with --model."; exit 1; }
    [ "$FORCE_FIRMWARE" = "true" ] && { echo "[ERROR] --firmware cannot be combined with --analyze."; exit 1; }
    [ -f "$ANALYZE_SBOM" ] || { echo "[ERROR] --analyze SBOM file not found: $ANALYZE_SBOM"; exit 1; }
    MODE="ANALYZE"
    # The risk report needs both license and vulnerability data, so enable them.
    GENERATE_NOTICE="true"; GENERATE_SECURITY="true"
elif [ -n "$MODEL" ]; then
    # AI model SBOM via the OWASP AIBOM Generator (opt-in bomlens-aibom image).
    [ -z "$TARGET" ]      || { echo "[ERROR] --model is mutually exclusive with --target."; exit 1; }
    [ -z "$ANALYZE_SBOM" ] || { echo "[ERROR] --model is mutually exclusive with --analyze."; exit 1; }
    [ -z "$GIT_URL" ]     || { echo "[ERROR] --model is mutually exclusive with --git."; exit 1; }
    [ "$FORCE_FIRMWARE" != "true" ] || { echo "[ERROR] --model cannot be combined with --firmware."; exit 1; }
    MODE="AIBOM"
    # Default the project name to the model's last segment (owner/name -> name).
    [ -n "$PROJECT_NAME" ] || PROJECT_NAME="${MODEL##*/}"
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
    # dir). Artifacts go to OUTPUT_HOST_DIR (the per-run subfolder), which is kept
    # separate from the scanned tree, even for --git/zip ingestion.
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
            echo "[WARN]   For open source copied (vendored) into the sources, add --identify-vendored (opt-in image)."
        fi
        if [ "$LANG_DET" = "unknown" ]; then
            echo "[WARN] No package manifest detected; using cdxgen all-in-one (results may be sparse)."
            echo "[WARN]   If this is C/C++ embedded source, --identify-vendored finds open source copied in (opt-in image)."
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
        -v "\"$OUTPUT_HOST_DIR\"":/out \
        -v "\"$BUILD_PREP\"":/tmp/build-prep.sh:ro \
        $CACHE_MOUNTS \
        -e HOME=/tmp/sbomhome \
        -e MAVEN_OPTS=-Dmaven.repo.local=/tmp/sbomhome/.m2 \
        -e FETCH_LICENSE="$FETCH_LICENSE" \
        -e PROJECT_NAME="\"$PROJECT_NAME\"" \
        -e PROJECT_VERSION="\"$PROJECT_VERSION\"" \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        --entrypoint sh "\"$CDX_IMG\"" \
        -c "'sh /tmp/build-prep.sh /app \"/out/$OUTPUT_FILE\" 1.6'" \
        || { echo "[ERROR] SBOM generation failed (stage 1)"; exit 1; }

    echo "[2/2] Post-processing..."
    # Mount the scanned tree as /src (so deep-license/vendored see the real source)
    # and the run folder as /host-output. -w /host-output makes the bom written by
    # stage 1 the cwd, so POSTPROCESS finds it and writes the bundle in place — the
    # scanned tree (/src) is never written to.
    eval docker run --rm \
        -v "\"$SCAN_INPUT_DIR\"":/src -v "\"$OUTPUT_HOST_DIR\"":/host-output \
        -w /host-output \
        --add-host=host.docker.internal:host-gateway \
        -e MODE=POSTPROCESS $(pp_env)$(cosign_run) \
        "\"$POSTPROCESS_IMAGE\""
else
    # image / binary / rootfs / firmware / aibom / analyze / merge: scanner image
    # runs the generation step + common pipeline in one shot. Firmware and aibom
    # need their heavier opt-in images; others use the base image.
    VOL=""; ENVV=""; RUN_IMAGE="$POSTPROCESS_IMAGE"
    case "$MODE" in
        IMAGE)  VOL="-v \"$OUTPUT_HOST_DIR\":/host-output -v /var/run/docker.sock:/var/run/docker.sock"; ENVV="-e TARGET_IMAGE=\"$TARGET\"" ;;
        BINARY) FD="$(cd "$(dirname "$TARGET")" && pwd)"; FN="$(basename "$TARGET")"; VOL="-v \"$FD\":/target -v \"$OUTPUT_HOST_DIR\":/host-output"; ENVV="-e TARGET_FILE=\"/target/$FN\"" ;;
        ROOTFS) TD="$(cd "$TARGET" && pwd)"; VOL="-v \"$TD\":/target -v \"$OUTPUT_HOST_DIR\":/host-output"; ENVV="-e TARGET_DIR=/target" ;;
        FIRMWARE) FD="$(cd "$(dirname "$TARGET")" && pwd)"; FN="$(basename "$TARGET")"; VOL="-v \"$FD\":/target -v \"$OUTPUT_HOST_DIR\":/host-output"; ENVV="-e TARGET_FILE=\"/target/$FN\""; RUN_IMAGE="$FIRMWARE_IMAGE" ;;
        AIBOM)  VOL="-v \"$OUTPUT_HOST_DIR\":/host-output"; ENVV="-e MODEL_ID=\"$MODEL\""; RUN_IMAGE="$AIBOM_IMAGE" ;;
        ANALYZE) FD="$(cd "$(dirname "$ANALYZE_SBOM")" && pwd)"; FN="$(basename "$ANALYZE_SBOM")"; VOL="-v \"$FD\":/input:ro -v \"$OUTPUT_HOST_DIR\":/host-output"; ENVV="-e ANALYZE_SBOM=\"/input/$FN\"" ;;
        MERGE)
            # Mount each input's directory read-only under its own index so files
            # that share a basename (three layers all named *_bom.json) don't
            # collide. MERGE_FILES carries the container-side paths.
            VOL="-v \"$OUTPUT_HOST_DIR\":/host-output"; MF_CONTAINER=""; i=0
            ROOT_ENV=""
            MR_RESOLVED=""
            [ -n "$MERGE_ROOT" ] && MR_RESOLVED="$(cd "$(dirname "$MERGE_ROOT")" && pwd)/$(basename "$MERGE_ROOT")"
            for mf in "${MERGE_FILES[@]}"; do
                FD="$(cd "$(dirname "$mf")" && pwd)"; FN="$(basename "$mf")"
                VOL="$VOL -v \"$FD\":/merge-in-$i:ro"
                MF_CONTAINER="$MF_CONTAINER /merge-in-$i/$FN"
                # --merge-root: point merge-sbom.sh at this input's container path.
                [ -n "$MR_RESOLVED" ] && [ "$FD/$FN" = "$MR_RESOLVED" ] && ROOT_ENV=" -e MERGE_ROOT_FROM=\"/merge-in-$i/$FN\""
                i=$((i + 1))
            done
            ENVV="-e MERGE_FILES=\"${MF_CONTAINER# }\"$ROOT_ENV" ;;
    esac
    eval docker run --rm $VOL \
        --add-host=host.docker.internal:host-gateway \
        -e MODE="$MODE" $ENVV $(pp_env)$(cosign_run) \
        "\"$RUN_IMAGE\""
fi

# Verify artifacts actually reached the host. When the run folder is outside
# Docker Desktop file sharing, the container runs and reports success but the
# /host-output mount is silently empty, so nothing lands here. Catch that
# instead of printing "Analysis Complete!" over a folder with no SBOM.
if [ "$GENERATE_ONLY" = "true" ] && [ ! -f "$OUTPUT_HOST_DIR/$OUTPUT_FILE" ]; then
    echo "[ERROR] SBOM not found on host: $OUTPUT_HOST_DIR/$OUTPUT_FILE"
    echo "  The container ran but no artifact reached this folder."
    echo "  Likely cause: this folder is outside Docker Desktop file sharing."
    echo "  Run from a shared path (e.g. under your home directory) and retry."
    exit 1
fi

echo "=========================================="
echo "  Analysis Complete!"
if [ "$GENERATE_ONLY" = "true" ]; then
    echo "  Output dir: ${OUTPUT_HOST_DIR}"
    echo "  SBOM: ${OUTPUT_FILE}"
    [ "$GENERATE_NOTICE" = "true" ]   && echo "  Notice:   ${SAFE_PROJECT}_${SAFE_VERSION}_NOTICE.{txt,html}"
    [ "$GENERATE_SECURITY" = "true" ] && echo "  Security: ${SAFE_PROJECT}_${SAFE_VERSION}_security.{json,md,html}"
    [ "$MODE" = "ANALYZE" ] && echo "  Conformance: ${SAFE_PROJECT}_${SAFE_VERSION}_conformance.{json,md,html}"
    [ "$GENERATE_REPORT" = "true" ] && echo "  Risk report: ${SAFE_PROJECT}_${SAFE_VERSION}_risk-report.{md,html}"
fi
echo "=========================================="
