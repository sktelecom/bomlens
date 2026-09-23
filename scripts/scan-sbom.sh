#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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
# build-prep.sh is bind-mounted alone into the stage-1 cdxgen container
# (isolated from the rest of docker/lib/), so identify-conda.py has to be
# mounted alongside it for build-prep.sh to be able to invoke it before
# cdxgen runs (see docker/lib/identify-conda.py's own header for why this
# has to happen before cdxgen, not only in the stage-2 post-process step).
IDENTIFY_CONDA="$REPO_DIR/docker/lib/identify-conda.py"
# shellcheck source=docker/lib/cdx-version.sh
. "$REPO_DIR/docker/lib/cdx-version.sh"

# Windows / Git-for-Windows (MSYS) docker-mount compatibility.
# Under MSYS bash, arguments to a native docker.exe get path-mangled two ways
# that both break `docker run -v <src>:<dst>`:
#   - container targets (/app, /out, /tmp/build-prep.sh) are rewritten to
#     C:\Program Files\Git\... , so the mount lands in the wrong place;
#   - host sources from `pwd` come out as /c/... , which Docker Desktop/Rancher
#     cannot resolve, so it mounts an empty anonymous dir instead of the file.
# Fix both by disabling container-path conversion (applied per docker call so
# git and other native tools are untouched) and by rewriting host mount sources
# to Windows form (hostpath -> cygpath -m -> C:/...). Both are no-ops off MSYS,
# so macOS and Linux behavior is unchanged. Two prefix forms are kept because the
# env assignment must reach docker differently: DOCKER_MSYS is a literal
# assignment string for the `eval docker run` calls; DOCKER_ENV is an `env`
# argv array for the direct (exec/cleanup) calls, where a variable-expanded
# assignment would not be honored as one.
DOCKER_MSYS=""
DOCKER_ENV=()
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*)
        DOCKER_MSYS="MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "
        DOCKER_ENV=(env MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*')
        hostpath() { cygpath -m -- "$1" 2>/dev/null || printf '%s' "$1"; }
        # A POSIX path this shell can mkdir/read directly; hostpath() (above)
        # still does the cygpath -m conversion when this needs to reach a
        # docker -v flag, same as every other mount in this script.
        GUARD_STATE_DIR="$(cygpath -u "${LOCALAPPDATA:-$HOME/AppData/Local}" 2>/dev/null)/bomlens/guard"
        SCRATCH_DIR="$(cygpath -u "${LOCALAPPDATA:-$HOME/AppData/Local}" 2>/dev/null)/bomlens/tmp" ;;
    *)
        hostpath() { printf '%s' "$1"; }
        GUARD_STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/bomlens/guard"
        SCRATCH_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/bomlens/tmp" ;;
esac

POSTPROCESS_IMAGE="${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/bomlens:latest}"           # legacy aliases: sbom-generator, sbom-scanner
FIRMWARE_IMAGE="${SBOM_FIRMWARE_IMAGE:-ghcr.io/sktelecom/bomlens-firmware:latest}"     # opt-in (unblob/cve-bin-tool); legacy alias: sbom-scanner-firmware
AIBOM_IMAGE="${SBOM_AIBOM_IMAGE:-ghcr.io/sktelecom/bomlens-aibom:latest}"               # opt-in (OWASP AIBOM Generator; HuggingFace network)
DEEP_CVE_IMAGE="${SBOM_DEEP_CVE_IMAGE:-ghcr.io/sktelecom/bomlens-deep-cve:latest}"      # opt-in (grype + bundled NVD DB for maven CPE matching)
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

GENERATE_ONLY="false"; TARGET=""; PROJECT_NAME=""; PROJECT_VERSION=""; NESTED_ROOTFS_HINT=""
GENERATE_NOTICE="false"; GENERATE_SECURITY="false"; GENERATE_SPDX="false"; DEEP_LICENSE="false"
# Tracks an EXPLICIT --security/--all, as opposed to the risk-report default
# turning security on: only an explicit request is worth answering when a mode
# cannot produce the report.
SECURITY_REQUESTED="false"
SIGN_SBOM="false"; BYTE_STABLE="false"; UI_MODE="false"; UI_PORT="${UI_PORT:-8080}"
# The web UI is a local tool: it reaches the engine socket to run scans, so it
# is published to the loopback interface only. Set UI_BIND_ADDRESS=0.0.0.0 to
# reach it from another machine, and put it behind something that authenticates.
UI_BIND_ADDRESS="${UI_BIND_ADDRESS:-127.0.0.1}"
# Report language for the conformance + AI-profile reports: en (default) or ko.
# Only these two are honored; anything else is normalized to en further down.
REPORT_LANG="${REPORT_LANG:-en}"
# Conformance profile: default, or skt-submission for the stricter thresholds
# the SKT supplier submission review applies (100% PURL coverage, pkg:generic
# required). Passed through as-is; validate-sbom.sh normalizes unknown values.
CONFORMANCE_PROFILE="${CONFORMANCE_PROFILE:-default}"
# Repository resolution for a submitted SBOM (--resolve-purl). Off unless asked:
# it is the only part of the conformance check that uses the network.
PURL_RESOLVE="${PURL_RESOLVE:-false}"
# CI gate: exit non-zero when this scan's own conformance report says "fail".
# Host-only logic (see the check near the end of this script); nothing is
# passed to the container for it.
FAIL_ON_CONFORMANCE="false"; FAIL_ON=()
fail_on_bad_coverage() {
    echo "[ERROR] --fail-on: '$1' needs a whole percentage from 0 to 100 without leading zeros, for example license-coverage=80 (there is no default)."
    exit 1
}
FORCE_FIRMWARE="false"; ANALYZE_SBOM=""; MODEL=""; MODEL_FILE=""; VEX_FILE=""
# Set when --target turned out to be a Yocto build directory: the folder the
# user pointed at, while ANALYZE_SBOM holds the image SBOM found inside it.
YOCTO_BUILD_DIR=""
IDENTIFY_VENDORED="false"
DEEP_CVE="false"
VERIFY_WEIGHTS="false"
SCANOSS_API_URL="${SCANOSS_API_URL:-}"; SCANOSS_API_KEY="${SCANOSS_API_KEY:-}"
# HuggingFace read credential for --model (private/gated repos). Absorb the older
# huggingface_hub name here so the container boundary carries one name only.
# Passed to docker as a bare `-e HF_TOKEN` (name, no value) so the secret never
# lands in argv where `ps` could read it.
HF_TOKEN="${HF_TOKEN:-${HUGGING_FACE_HUB_TOKEN:-}}"
GIT_URL=""; GIT_REF=""; NO_REPORT="false"; GENERATE_REPORT="false"
INGEST_SOURCE="false"; INGEST_ROOTFS="false"; INGEST_ARCHIVE=""; SCAN_INPUT_DIR=""; CLEANUP_DIRS=()
MERGE_FILES=()
MERGE_ROOT=""
DIFF_OLD=""; DIFF_NEW=""
OUTPUT_BASE=""; TIMESTAMP="false"
UI_MOUNTS=()

# ========================================================
# Parse arguments
# ========================================================
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --project) PROJECT_NAME="$2"; shift ;;
        --version) PROJECT_VERSION="$2"; shift ;;
        --license) PROJECT_LICENSE="$2"; shift ;;
        --sbom-author) SBOM_AUTHOR="$2"; shift ;;
        --target) TARGET="$2"; shift ;;
        --analyze|--sbom) ANALYZE_SBOM="$2"; shift ;;
        --model) MODEL="$2"; shift ;;
        --model-file) MODEL_FILE="$2"; shift ;;
        # The statements attach to vulnerability rows, which come from the security
        # report, so asking for a VEX asks for that report too (as --deep-cve does).
        --vex) VEX_FILE="$2"; GENERATE_SECURITY="true"; shift ;;
        --usage) USAGE_CONTEXT="$2"; shift ;;
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
        --diff)
            # Fixed 2-arg flag (not variadic like --merge): a drift comparison
            # always has exactly one older and one newer SBOM. Checked here,
            # before the shift, so a missing second file is a clear error
            # instead of `shift 2` failing on too few remaining arguments.
            DIFF_OLD="${2:-}"; DIFF_NEW="${3:-}"
            [ -n "$DIFF_OLD" ] && [ -n "$DIFF_NEW" ] || {
                echo "[ERROR] --diff requires two files: --diff <old.json> <new.json>"; exit 1; }
            shift 2 ;;
        --git) GIT_URL="$2"; shift ;;
        --branch|--ref) GIT_REF="$2"; shift ;;
        --no-report) NO_REPORT="true" ;;
        --generate-only) GENERATE_ONLY="true" ;;
        --upload-target) UPLOAD_TARGET="$2"; shift ;;
        --trusca) UPLOAD_TARGET="trusca"; TRUSCA_PROJECT_ID="$2"; shift ;;
        --notice) GENERATE_NOTICE="true" ;;
        --security) GENERATE_SECURITY="true"; SECURITY_REQUESTED="true" ;;
        --spdx) GENERATE_SPDX="true" ;;
        --all) GENERATE_NOTICE="true"; GENERATE_SECURITY="true"; GENERATE_SPDX="true"
               SECURITY_REQUESTED="true" ;;
        --deep-license) DEEP_LICENSE="true" ;;
        --deep-cve) DEEP_CVE="true"; GENERATE_SECURITY="true"; SECURITY_REQUESTED="true" ;;
        --identify-vendored) IDENTIFY_VENDORED="true" ;;
        --verify-weights) VERIFY_WEIGHTS="true" ;;
        --sign) SIGN_SBOM="true" ;;
        --byte-stable) BYTE_STABLE="true" ;;
        --fail-on-conformance) FAIL_ON_CONFORMANCE="true" ;;
        # Repeatable. The list of conditions is closed (checked below), so a typo
        # fails here instead of quietly gating on nothing.
        --fail-on)
            case "${2:-}" in
                vulnerability=critical|vulnerability=high|vulnerability=medium|vulnerability=low)
                    GENERATE_SECURITY="true" ;;
                malicious-package|license-conflict|empty-result) ;;
                license-coverage=*)
                    # A whole percentage, 0 to 100, with no default: the threshold is the policy.
                    case "${2#license-coverage=}" in
                        ''|*[!0-9]*|????*|0?*) fail_on_bad_coverage "$2" ;;
                        *) [ "${2#license-coverage=}" -le 100 ] || fail_on_bad_coverage "$2" ;;
                    esac ;;
                *)
                    echo "[ERROR] --fail-on: unknown condition '${2:-}'."
                    echo "[ERROR] Use one of: vulnerability=critical|high|medium|low, malicious-package, license-conflict, empty-result, license-coverage=<0-100>."; exit 1 ;;
            esac
            FAIL_ON+=("$2"); shift ;;
        --lang) REPORT_LANG="$2"; shift ;;
        --conformance-profile) CONFORMANCE_PROFILE="$2"; shift ;;
        --resolve-purl) PURL_RESOLVE="true" ;;
        --firmware) FORCE_FIRMWARE="true" ;;
        --output-dir|-o) OUTPUT_BASE="$2"; shift ;;
        --timestamp) TIMESTAMP="true" ;;
        --ui) UI_MODE="true" ;;
        --mount) UI_MOUNTS+=("$2"); shift ;;
        --help)
            # The delimiter is quoted so the block is literal text. It is not:
            # the help describes a `docker save` tar, and an unquoted heredoc
            # read those backticks as a command substitution — `--help` ran
            # `docker save` with no argument, printed its usage error to stderr,
            # and left a hole in its own text ("a  tar is scanned as..."). The
            # block interpolates nothing, so quoting costs nothing.
            # The one line that needs the script's own name is printed
            # outside the block, so the block itself can stay literal.
            echo "Usage: $0 --project <name> --version <ver> [OPTIONS]"
            cat << 'EOF'

Options:
  --project <name>       Project name (required)
  --version <ver>        Version (required)
  --license <spdx-id>    Outbound license the project is distributed under
                         (e.g. Apache-2.0). Recorded on the SBOM's root
                         component and used to flag dependencies whose terms
                         clash with it. Source scans cannot infer this, and
                         without it no conflict verdict is produced. An
                         existing root license in the SBOM is never replaced.
  --vex <file>           A CycloneDX VEX document (JSON) a supplier sent for this
                         product. The statements that apply to a component of the
                         scanned SBOM are kept in <Project>_<Version>_vex_imported.json,
                         apart from the SBOM and the security report, which stay
                         unchanged. Turns the security report on, since the
                         statements are shown on its findings. A document for a
                         different product or version, or one that is not
                         CycloneDX VEX, is reported and skipped.
  --sbom-author <name>   Entity that generated this SBOM — the organisation or
                         person running the scan, not the tool and not whoever
                         wrote the software. Use the full name, no acronyms.
                         Nothing here can discover it, so the field is left out
                         of the SBOM when it is not given.
  --target <target>      Not set: source (current dir) | image name | file |
                         directory | .zip/.tar.gz archive (auto-extracted).
                         An archive is routed by what it holds, not by its
                         extension: a root filesystem is scanned as ROOTFS so
                         its package database is read, a `docker save` tar is
                         scanned as the image it is, and anything else is
                         scanned as source.
                         A Yocto build directory is recognized as such: its
                         image SBOM under tmp/deploy/images/ is analyzed
                         instead of the build tree being walked.
  --git <url>            Clone a git/GitHub URL (shallow) and scan as source.
                         Private repos: set GIT_TOKEN env. Mutually exclusive
                         with --target/--analyze/--firmware.
  --branch <ref>         Branch, tag, or commit for --git (alias: --ref;
                         default: repo default)
  --firmware             Force firmware mode for --target (opt-in image). Works
                         on an archive too: the firmware unpacker reads it
                         directly, nested formats and all, instead of the
                         archive being extracted and scanned as source.
  --analyze <sbom>       Validate + analyze a supplier SBOM (alias: --sbom).
                         CycloneDX or SPDX; mutually exclusive with --target.
  --model <ref>          Generate an AI SBOM (CycloneDX 1.7 ML-BOM) for a
                         HuggingFace model given as owner/name, via the OWASP
                         AIBOM Generator (opt-in image; fetches model-card
                         metadata over the network).
                         A Figshare item is taken here too — its page URL, its
                         DOI, or the item number — and is described as a dataset
                         from the public item endpoint: no account, no opt-in
                         image. An institutional DOI that does not carry
                         "figshare" cannot be told apart from any other DOI, so
                         give the item URL for those.
                         Mutually exclusive with --target/--analyze/--git/--merge.
  --model-file <path>    Read one AI model FILE (GGUF, safetensors, PyTorch,
                         pickle, npz, npy, ONNX) and describe it from its own
                         header. Offline, no HuggingFace account, and it works
                         on a model that was never published. What can be filled
                         depends on the format: GGUF carries a name, a license
                         and an architecture, while safetensors usually carries
                         only tensor shapes. A .gguf/.safetensors/.pt/... path
                         given to --target is read this way too.
  --usage <scenario>     Tailor the AI model risk assessment (--model) to how
                         the model will be used: internal | product |
                         redistribute | outputs-only. Only the license
                         conditions that bind that scenario decide the verdict;
                         unset judges against every condition.
  --merge <a.json> <b.json> [...]
                         Merge 2+ CycloneDX SBOMs into one, dedupe by purl, and
                         stamp the root component with --project/--version. For
                         layered server delivery (OS rootfs + app + static-link).
                         Mutually exclusive with --target/--analyze/--git.
  --merge-root <file>    With --merge: keep THIS input's specVersion and root
                         component (e.g. an ML-BOM's 1.7 + modelCard) instead of
                         writing a fresh 1.6 root. Must be one of the --merge
                         files; the root is renamed to --project/--version.
  --diff <old.json> <new.json>
                         Compare two already-generated AI-model SBOMs (--model
                         or --model-file output) and report drift: a risk
                         verdict that got worse, a changed declared license, or
                         a SHA-256 weight-file hash that no longer matches under
                         the same model name/purl/HuggingFace id — the last one
                         means the artifact behind a stable name silently
                         changed. No --project/--version or scan target needed;
                         writes <new>_model-diff.json next to the newer file
                         (or under --output-dir).
  --generate-only        Save locally without uploading
  --trusca <project_id>  Upload the SBOM to TRUSCA's native ingest endpoint
                         (shorthand for --upload-target trusca with the id).
                         Needs API_URL (TRUSCA base) and API_KEY (Bearer token).
  --upload-target <t>    Upload destination: dependency-track (default) | trusca
  --notice               Open-source NOTICE (txt+html)
  --security             Trivy security report (json+md+html)
  --spdx                 Also export the SBOM as SPDX 2.3 JSON (converted from
                         the CycloneDX output; CycloneDX stays the primary format)
  --all                  --notice --security --spdx
  --no-report            Skip the open-source risk report (risk-report). By default
                         the risk report (+notice+security) is generated in
                         every mode; --no-report opts out.
  --deep-license         scancode deep license (opt-in image)
  --deep-cve             Also match maven components against NVD by CPE via grype
                         (opt-in image; recovers NVD-only CVEs Trivy misses for
                         older Apache libraries). Implies --security. Set
                         SECURITY_NVD_VERIFY=true (needs NVD_API_KEY, network) to
                         drop loose-version false positives; otherwise nvd:cpe
                         findings are flagged version-unverified.
  --identify-vendored    Identify open source copied (vendored) into C/C++ source
                         that has no package manager. Matches file fingerprints
                         against the OSSKB service (opt-in image; sends hashes,
                         not source). See docs/guides/identify-vendored.md
  --verify-weights       With --model: download the repo's pickle-format weight
                         files (.bin/.pt/.pth/.ckpt — the ones that execute code
                         on load) and run the same local picklescan verification
                         --model-file runs on a supplied file, instead of only
                         trusting HuggingFace's own scan (bomlens:hf:scan:*).
                         safetensors/GGUF/ONNX weights are never downloaded: they
                         cannot execute code on load. A real network/disk cost
                         (bounded by AIBOM_VERIFY_MAX_FILES / AIBOM_VERIFY_MAX_BYTES,
                         default 5 files / 2 GiB each), so this is opt-in, unlike
                         the metadata-only file-security lookup.
  --byte-stable          Deterministic SBOM output
  --fail-on-conformance  Exit 2 if this scan's own conformance report says
                         "fail" (exit 3 if no conformance report was produced
                         for this scan). Not offered with --ui. See "Exit
                         codes" in the CLI reference.
  --fail-on <condition>  Exit 4 when this scan meets the condition (exit 5 when it
                         cannot be judged from what the scan produced). Repeat
                         the option for several conditions. Conditions:
                           vulnerability=<critical|high|medium|low>
                                        a finding at that severity or worse
                                        (turns the security report on)
                           malicious-package
                                        a component flagged as a known
                                        malicious package
                           license-conflict
                                        a component incompatible with the
                                        license given by --license
                           empty-result
                                        the scan found no component
                           license-coverage=<0-100>
                                        fewer than that percent of components
                                        declare a license (no default value)
                         Not offered with --ui or --diff. See "Exit codes" in
                         the CLI reference.
  --lang <en|ko>         Language for the human-facing conformance and AI-profile
                         reports (.md/.html). Default en. The SBOM and the JSON
                         reports stay English regardless.
  --conformance-profile <default|skt-submission>
                         Conformance check strictness. Default: default (90%
                         PURL coverage, pkg:generic advisory). skt-submission
                         requires 100% PURL coverage and fails on pkg:generic,
                         matching the SKT supplier submission review.
  --resolve-purl         --analyze only: ask each package repository whether the
                         identifiers in the submitted SBOM name packages that
                         exist, and add the answer to the conformance report as
                         an advisory row. Off by default; it is the only part of
                         the check that uses the network. An identifier that
                         resolves to nothing is reported, never failed: a
                         package published only to an internal repository
                         answers the same way. PURL_RESOLVE_IGNORE skips
                         namespaces you know are internal.
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
  --mount <dir>          With --ui: expose an extra host directory to the web
                         UI as a read-only rootfs scan target (repeatable).
                         Lets the UI scan OS trees outside the launch folder,
                         e.g. --mount / to scan the running host OS.
  --help                 Show this help

Environment:
  FETCH_LICENSE          Resolve dependency licenses in source scans
                         (default: true; set false to skip and run faster)
  SECURITY_ENRICH        Enrich the security report with EPSS + CISA KEV
                         signals (default: true; set false for air-gapped)
  ENRICH_EOL             Flag components past their end-of-life from a bundled
                         endoflife.date snapshot (default: true; runs OFFLINE,
                         so it is air-gap safe; set false to skip)
  ENRICH_MALICIOUS       Flag components that are known-malicious packages from
                         a bundled OSV snapshot (default: true; runs OFFLINE,
                         so it is air-gap safe; set false to skip)
  STALENESS_ENRICH       Add deps.dev version currency (newest version, releases
                         behind, last-release date) per component (default: false;
                         opt-in, makes one network call per package — not for
                         air-gapped runs; set true to enable)
  ENRICH_HF_SECURITY     Read HuggingFace's own file-security scan results
                         (ClamAV + picklescan) for --model scans and record
                         them in the ML-BOM (default: true; metadata only, no
                         file download; set false to skip the lookup)
  GIT_TOKEN              Token for cloning private --git repos
  HF_TOKEN               HuggingFace read token for --model; required for a
                         private or gated repo (e.g. reviewing a model before
                         you publish it). HUGGING_FACE_HUB_TOKEN also accepted
  COSIGN_KEY             Signing key for --sign
  SBOM_OUTPUT_FLAT       Set to 1 to write artifacts flat in the output base
                         (no per-run subfolder), matching the pre-isolation layout
  SBOM_PULL              missing (default): refresh an already-present image in
                         the background, bounded; an absent one is pulled as
                         usual. always: block and re-pull every run. never:
                         touch no network; fail if the image is absent
  SBOM_SCANNER_IMAGE     Override the scanner image
  SBOM_FIRMWARE_IMAGE    Override the firmware image
  SBOM_AIBOM_IMAGE       Override the AI SBOM (OWASP AIBOM Generator) image
  SBOM_DEEP_CVE_IMAGE    Override the deep-cve (grype) image
  SECURITY_NVD_VERIFY    With --deep-cve: true drops loose-version false positives
                         via live NVD lookups (needs NVD_API_KEY, network/minutes)
  NVD_API_KEY            NVD API key for SECURITY_NVD_VERIFY (passed by name only)
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
  EXTERNAL_LOOKUP        With --ui: enable the web UI's CVE/package lookup
                         against OSV.dev (default: true; set false for
                         air-gapped runs)

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

# `docker run` only auto-pulls an image that is entirely ABSENT locally; once a
# floating tag like `:latest` has been pulled once, it is reused forever even
# after the registry publishes a newer image. That is what broke a real demo:
# a stale cached bomlens:latest predated docker/lib/scan-figshare.py, and the
# scan failed with "python3: can't open file scan-figshare.py" until someone
# thought to `docker pull` by hand. ensure_image_fresh closes that gap for an
# image that IS already present, honoring SBOM_PULL (missing/always/never;
# see --help), without turning every run into a blocking network call — see
# _refresh_image_quietly for how the wait is bounded. Ported from
# electron/lib/container.mjs's refreshImageInBackground() (Node); this is the
# bash equivalent for the CLI path.
#
# $1: image ref (e.g. $POSTPROCESS_IMAGE, $RUN_IMAGE)
ensure_image_fresh() {
    local img="$1"
    case "$SBOM_PULL" in
        never)
            if ! docker image inspect "$img" >/dev/null 2>&1; then
                echo "[ERROR] Image not found and SBOM_PULL=never (no network is touched): $img"
                echo "        Pull it once first, or unset SBOM_PULL to let this run pull it:"
                echo "          docker pull $img"
                exit 1
            fi
            return 0
            ;;
        always)
            echo "[INFO] Pulling $img (SBOM_PULL=always)..."
            if ! docker pull "$img"; then
                echo "[ERROR] Failed to pull $img."
                exit 1
            fi
            return 0
            ;;
    esac
    # missing (default): an absent image is left to `docker run`'s own implicit
    # pull, unchanged. Only a PRESENT image is worth refreshing.
    docker image inspect "$img" >/dev/null 2>&1 || return 0
    _refresh_image_quietly "$img"
}

# Stall-bounded, silent `docker pull` for an image already present locally. A
# real transfer keeps writing new lines to the log, which resets the idle
# clock; an offline host or a blocked registry produces no output at all and
# is killed once idle for _SBOM_PULL_STALL_SECS seconds. _SBOM_PULL_MAX_SECS
# is a last-resort cap against a connection that trickles just enough to never
# look stalled. Both are internal test knobs (not documented CLI/env surface).
# Failure here — offline, killed, whatever — is silently ignored: this check
# is a bonus freshness probe, not the scan's critical path, and the local
# image is used either way.
#
# $1: image ref
_refresh_image_quietly() {
    local img="$1" stall max log pid elapsed idle last size
    stall="${_SBOM_PULL_STALL_SECS:-12}"
    max="${_SBOM_PULL_MAX_SECS:-2700}"
    log="$(mktemp)" || return 0
    docker pull "$img" >"$log" 2>&1 &
    pid=$!
    elapsed=0; idle=0; last=0
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        elapsed=$((elapsed + 1))
        size=$(wc -c <"$log" 2>/dev/null | tr -d ' ')
        [ -n "$size" ] || size=0
        if [ "$size" != "$last" ]; then
            idle=0; last=$size
        else
            idle=$((idle + 1))
        fi
        if [ "$idle" -ge "$stall" ] || [ "$elapsed" -ge "$max" ]; then
            kill "$pid" 2>/dev/null || true
            break
        fi
    done
    wait "$pid" 2>/dev/null || true
    rm -f "$log"
    return 0
}

# missing (default): docker run's implicit pull covers an absent image
# unchanged; when the image is already present, ensure_image_fresh quietly
# refreshes it (bounded, best-effort). always: unconditional blocking pull,
# fails loudly if it can't complete. never: never touches the network at all,
# fails loudly if the image is absent (same contract as scripts/sbom-ui.bat).
# Declared here, before the first ensure_image_fresh caller below, so an
# unset SBOM_PULL is never read as empty by that call.
SBOM_PULL="${SBOM_PULL:-missing}"

# ========================================================
# Web UI mode
# ========================================================
if [ "$UI_MODE" = "true" ]; then
    [ -z "$VEX_FILE" ] || { echo "[ERROR] --vex is not offered with --ui (import a VEX from the Vulnerabilities screen instead)."; exit 1; }
    [ "${#FAIL_ON[@]}" -eq 0 ] || { echo "[ERROR] --fail-on is not offered with --ui (it exits on one scan's result; the UI runs many)."; exit 1; }
    [ "$FAIL_ON_CONFORMANCE" = "true" ] && { echo "[ERROR] --fail-on-conformance is not offered with --ui (it exits on one scan's result; the UI runs many)."; exit 1; }
    docker_check
    # The web UI owns per-run subfolders itself (server.py creates them under the
    # mounted base). Honor --output-dir as that base; default to the current dir.
    # Resolved with pwd -P, the same as the CLI's own guard-state key (below):
    # a "current-dir" scan of a symlinked path must hash to the same key a CLI
    # scan of that path would, so a scan interrupted from one side is still
    # found and cleaned up by a rescan from the other. mkdir -p first: an
    # --output-dir that does not exist yet previously relied on docker's own
    # bind-mount auto-create, which cd here would otherwise break.
    mkdir -p "${OUTPUT_BASE:-$(pwd)}" || { echo "[ERROR] cannot create output dir: ${OUTPUT_BASE:-$(pwd)}"; exit 1; }
    UI_BASE="$(cd "${OUTPUT_BASE:-$(pwd)}" && pwd -P)"
    # Extra --mount dirs become read-only rootfs scan targets under
    # /scan-targets/<name>. SBOM_UI_SCAN_ROOTS carries "<container>|<host>"
    # lines so server.py can allow-list them and the UI can label them by
    # their host path ('|' cannot appear in the container path we build, and
    # is illegal in Windows host paths). Read-only keeps a mounted live OS
    # (e.g. --mount /) safe, and outputs still land only in /host-output.
    MOUNT_FLAGS=(); SCAN_ROOTS=""; SEEN_NAMES=" "
    for m in "${UI_MOUNTS[@]}"; do
        [ -d "$m" ] || { echo "[ERROR] --mount path is not a directory: $m"; exit 1; }
        abs="$(cd "$m" && pwd)"
        name="$(printf '%s' "$(basename "$abs")" | tr -c 'A-Za-z0-9._-' '-')"
        case "$name" in ''|-|.|..) name="root" ;; esac
        n=2; uniq="$name"
        while case "$SEEN_NAMES" in *" $uniq "*) true ;; *) false ;; esac; do
            uniq="$name-$n"; n=$((n+1))
        done
        SEEN_NAMES="$SEEN_NAMES$uniq "
        MOUNT_FLAGS+=(-v "$(hostpath "$abs"):/scan-targets/$uniq:ro")
        SCAN_ROOTS="$SCAN_ROOTS/scan-targets/$uniq|$(hostpath "$abs")"$'\n'
    done
    echo "=========================================="
    echo "  BomLens Web UI — http://localhost:${UI_PORT}  (Ctrl+C to stop)"
    echo "=========================================="
    ( sleep 2; (command -v open >/dev/null 2>&1 && open "http://localhost:${UI_PORT}") \
        || (command -v xdg-open >/dev/null 2>&1 && xdg-open "http://localhost:${UI_PORT}") ) >/dev/null 2>&1 &
    # -it only when attached to a terminal: docker refuses -t without one
    # (CI, pipes), and Ctrl+C passthrough is moot there anyway.
    TTY_FLAGS=()
    if [ -t 0 ] && [ -t 1 ]; then TTY_FLAGS=(-it); fi
    # Let the UI container inherit a HuggingFace credential so AI-model scans can
    # reach private/gated repos. The UI never asks for it: the server has no place
    # to keep a secret, so it comes from the environment that launched the tool.
    HF_FLAGS=()
    if [ -n "$HF_TOKEN" ]; then HF_FLAGS=(-e HF_TOKEN); fi
    # Go toolchain and module proxy settings for Go dependency resolution. A
    # name-only -e is skipped by docker when the variable is unset.
    GO_ENV_FLAGS=(-e GOTOOLCHAIN -e GOPROXY -e GOSUMDB)
    # Source-scan options for build-prep.sh; the UI container's entrypoint passes
    # them on to the cdxgen container.
    read -ra PREP_ENV_FLAGS <<< "$(build_prep_env_args)"
    # Name-only, same reason: a host override of the scan-cancel grace period
    # must reach server.py inside the UI container (it reads the env var
    # itself; a host-side default here would never be seen there).
    CANCEL_ENV_FLAGS=(-e BOMLENS_CANCEL_GRACE)
    # /bomlens-state: the same host-persistent guard-state directory
    # the CLI path uses, so a directory scan launched through --ui can also
    # recover a source tree a prior, too-hard-killed scan left dirty. entrypoint.sh
    # inside this container reads SOURCE_ROOT_HOST (set below) and carries this
    # mount to the cdxgen sibling itself via --volumes-from.
    UI_GUARD_FLAGS=()
    mkdir -p "$GUARD_STATE_DIR" 2>/dev/null && UI_GUARD_FLAGS=(-v "$(hostpath "$GUARD_STATE_DIR")":/bomlens-state)
    ensure_image_fresh "$POSTPROCESS_IMAGE"
    exec "${DOCKER_ENV[@]}" docker run --rm "${TTY_FLAGS[@]}" -p "${UI_BIND_ADDRESS}:${UI_PORT}:8080" \
        -v "$(hostpath "$UI_BASE")":/src -v "$(hostpath "$UI_BASE")":/host-output \
        "${MOUNT_FLAGS[@]}" "${HF_FLAGS[@]}" "${GO_ENV_FLAGS[@]}" "${PREP_ENV_FLAGS[@]}" "${CANCEL_ENV_FLAGS[@]}" \
        "${UI_GUARD_FLAGS[@]}" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -e MODE=UI -e UI_PORT=8080 -e SBOM_UI_HOST_DIR="$(hostpath "$UI_BASE")" \
        -e SBOM_UI_SCAN_ROOTS="$SCAN_ROOTS" -e EXTERNAL_LOOKUP="$EXTERNAL_LOOKUP" \
        "$POSTPROCESS_IMAGE"
fi
[ "${#UI_MOUNTS[@]}" -eq 0 ] || { echo "[ERROR] --mount requires --ui."; exit 1; }

# ========================================================
# Model drift/diff mode — reads two already-generated SBOMs and writes a
# comparison report. No --project/--version and no scan target: there is
# nothing to generate here, so this runs and exits before the requirement
# check below (the same shape UI mode takes above).
# ========================================================
if [ -n "$DIFF_OLD" ]; then
    [ "${#FAIL_ON[@]}" -eq 0 ] || { echo "[ERROR] --fail-on cannot be combined with --diff (a diff judges no scan)."; exit 1; }
    [ -z "$VEX_FILE" ] || { echo "[ERROR] --vex cannot be combined with --diff (a diff writes no SBOM to attach statements to)."; exit 1; }
    docker_check
    [ -f "$DIFF_OLD" ] || { echo "[ERROR] --diff: old SBOM not found: $DIFF_OLD"; exit 1; }
    [ -f "$DIFF_NEW" ] || { echo "[ERROR] --diff: new SBOM not found: $DIFF_NEW"; exit 1; }
    DIFF_OLD_DIR="$(cd "$(dirname "$DIFF_OLD")" && pwd)"; DIFF_OLD_FN="$(basename "$DIFF_OLD")"
    DIFF_NEW_DIR="$(cd "$(dirname "$DIFF_NEW")" && pwd)"; DIFF_NEW_FN="$(basename "$DIFF_NEW")"
    DIFF_OUT_DIR="${OUTPUT_BASE:-$(pwd)}"
    mkdir -p "$DIFF_OUT_DIR"
    # The report is named after the NEWER file, not --project/--version (there
    # is none here): "<name>_bom.json" -> "<name>_model-diff.json", so a scan
    # bundle's own naming carries over without inventing a second identity for
    # the same artifact.
    DIFF_REPORT_NAME="${DIFF_NEW_FN%.json}"
    DIFF_REPORT_NAME="${DIFF_REPORT_NAME%_bom}_model-diff.json"
    ensure_image_fresh "$POSTPROCESS_IMAGE"
    "${DOCKER_ENV[@]}" docker run --rm \
        -v "$(hostpath "$DIFF_OLD_DIR/$DIFF_OLD_FN")":/diff/old.json:ro \
        -v "$(hostpath "$DIFF_NEW_DIR/$DIFF_NEW_FN")":/diff/new.json:ro \
        -v "$(hostpath "$DIFF_OUT_DIR")":/host-output \
        -e MODE=DIFF -e DIFF_OLD=/diff/old.json -e DIFF_NEW=/diff/new.json \
        -e DIFF_OUT_NAME="$DIFF_REPORT_NAME" \
        "$POSTPROCESS_IMAGE"
    RC=$?
    # diff-ai-model.py already reported its own reason on a real failure (bad
    # file, unreadable JSON, nothing to compare); only an exit-0-but-no-file
    # result means the /host-output mount itself did not reach the host.
    if [ "$RC" -eq 0 ] && [ ! -f "$DIFF_OUT_DIR/$DIFF_REPORT_NAME" ]; then
        echo "[ERROR] diff report not found on host: $DIFF_OUT_DIR/$DIFF_REPORT_NAME"
        echo "  The container ran but no artifact reached this folder."
        echo "  Likely cause: this folder is outside Docker Desktop file sharing"
        echo "  (or Colima's home-only mount — /tmp is not shared to the VM)."
        echo "  Run from a shared path (e.g. under your home directory) and retry."
        exit 1
    fi
    [ "$RC" -eq 0 ] && echo "[INFO] Model diff report: $DIFF_OUT_DIR/$DIFF_REPORT_NAME"
    exit "$RC"
fi

# ========================================================
# Validate
# ========================================================
[ -n "$PROJECT_NAME" ] && [ -n "$PROJECT_VERSION" ] || { echo "[ERROR] --project and --version are required ($0 --help)."; exit 1; }
if [ "$UPLOAD_TARGET" = "trusca" ] && [ "$GENERATE_ONLY" != "true" ] && [ -z "$TRUSCA_PROJECT_ID" ]; then
    echo "[ERROR] TRUSCA upload requires a project id: --trusca <id> or TRUSCA_PROJECT_ID env."; exit 1
fi
docker_check

# A scan container whose own run never got the chance to remove it (the
# process killed under memory pressure, a terminal force-closed, the host
# powered off mid-scan) is left behind for good otherwise -- nothing else
# ever cleans it up. Rather than the scan's own trap, which cannot run once
# the process itself is gone, every run instead sweeps up what an EARLIER
# one left behind: only ITS OWN exited containers (never a running one, so
# two scans in flight at once never touch each other's), identified by a
# label every scan container carries. Best-effort: a scan must still run
# with no Docker cleanup permissions or a daemon that rejects the filter.
_stale_cli_containers="$("${DOCKER_ENV[@]}" docker ps -aq --filter "label=bomlens.scan=cli" --filter "status=exited" 2>/dev/null)"
if [ -n "$_stale_cli_containers" ]; then
    echo "$_stale_cli_containers" | xargs "${DOCKER_ENV[@]}" docker rm >/dev/null 2>&1 || true
fi

# The scanner container names every output file with its own cleaning rule
# (docker/entrypoint.sh: only [A-Za-z0-9.-] kept, runs of _ folded, edges trimmed).
# Use the same rule here, or a name such as "@acme/lib" is looked for under a name
# the container never wrote ("SBOM not found on host", and no result file found).
container_safe() { printf '%s' "$1" | sed 's/[^a-zA-Z0-9.-]/_/g' | sed 's/__*/_/g' | sed 's/^_//; s/_$//'; }
SAFE_PROJECT=$(container_safe "$PROJECT_NAME")
SAFE_VERSION=$(container_safe "$PROJECT_VERSION")
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

# --fail-on-conformance judges this run's own result file, so a stale one from
# an earlier run at the same --project/--version (this folder is reused, not
# recreated) must not be mistaken for this run's verdict. Removed before the
# scan runs; the final check below then trusts "exists" to mean "this run
# produced it".
CONFORMANCE_RESULT_FILE="${OUTPUT_HOST_DIR}/${SAFE_PROJECT}_${SAFE_VERSION}_conformance.result"
[ "$FAIL_ON_CONFORMANCE" = "true" ] && rm -f "$CONFORMANCE_RESULT_FILE"
# Same for --fail-on: only this run's own judgement may decide the exit code.
GATE_RESULT_FILE="${OUTPUT_HOST_DIR}/${SAFE_PROJECT}_${SAFE_VERSION}_gate.result"
[ "${#FAIL_ON[@]}" -gt 0 ] && rm -f "$GATE_RESULT_FILE"
# The closing summary's facts (docker/lib/validate-sbom.sh) belong to this run only.
SUMMARY_RESULT_FILE="${OUTPUT_HOST_DIR}/${SAFE_PROJECT}_${SAFE_VERSION}_summary.result"
rm -f "$SUMMARY_RESULT_FILE"

# A SOURCE scan writes $OUTPUT_FILE in two containers: stage 1 (cdxgen) here on
# the host first, stage 2 (POSTPROCESS, entrypoint.sh) after. entrypoint.sh's
# own stale-artifact cleanup runs at stage 2's startup and cannot otherwise
# tell this run's own file, which stage 1 just wrote, from a leftover of an
# earlier run at the same --project/--version (this folder is reused, not
# recreated) -- both are just "$OUTPUT_FILE already on disk". Removing any
# leftover here, before stage 1 runs, means stage 2 always finds either
# nothing (stage 1 hasn't run yet) or stage 1's own fresh file; entrypoint.sh
# is told that file's name (BOMLENS_RUN_INPUT, below) so it skips it rather
# than mistaking it for a stale one.
rm -f "${OUTPUT_HOST_DIR}/${OUTPUT_FILE}"

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
            "${DOCKER_ENV[@]}" docker run --rm -v "$(hostpath "$(dirname "$d")")":/cleanup alpine:latest \
                rm -rf -- "/cleanup/$(basename "$d")" >/dev/null 2>&1 || true
        fi
    done
    # RUNNING_CONTAINER_NAME is set only while stage 1 (SOURCE mode) is
    # waiting on its cdxgen container, so a Ctrl+C or `kill` reaching this
    # script here still stops that container instead of leaving it to run
    # unsupervised (measured -- neither one nor two Ctrl+Cs
    # stopped it on their own, and a foreground `docker run` gives this
    # trap no chance to run until the container exits by itself).
    if [ -n "$RUNNING_CONTAINER_NAME" ] && command -v docker >/dev/null 2>&1; then
        "${DOCKER_ENV[@]}" docker stop -t "${BOMLENS_CANCEL_GRACE:-30}" "$RUNNING_CONTAINER_NAME" >/dev/null 2>&1 || true
        # No --rm on this container (an OOM check needs to inspect it after it
        # exits, before it is gone): remove it here so a cancelled run does
        # not leave it behind. A no-op if stage 1 already removed it itself.
        "${DOCKER_ENV[@]}" docker rm -f "$RUNNING_CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
    # The syft-fallback helper script (stage 1's cdxgen-crash path): a no-op
    # once stage 1 has already removed it, so this only matters when a
    # cancel lands while the fallback container is running. `if`, not a bare
    # `&&`: this is the last statement cleanup() runs, and since the script
    # itself never calls a final `exit N` (bash returns the last command's own
    # status when it falls off the end), a false `[ -n ... ]` here would leak
    # its own exit 1 out as the whole script's exit code on every ordinary
    # run -- an `if` with no `else` returns 0 on a false condition instead.
    if [ -n "$STAGE1_FALLBACK_SCRIPT" ]; then
        rm -f "$STAGE1_FALLBACK_SCRIPT"
    fi
}
trap cleanup EXIT INT TERM
RUNNING_CONTAINER_NAME=""
STAGE1_FALLBACK_SCRIPT=""

# Host-persistent guard state: when a scan is interrupted hard
# enough that build-prep.sh's own trap never runs (SIGKILL, OOM, a host
# crash), resolver output for ecosystems that cannot be redirected outside
# the tree (npm's node_modules is the clearest case) can survive in the
# source tree. This records, OUTSIDE that tree, exactly what such a run would
# need to clean up if it never got the chance — read by build-prep.sh's
# restore-only mode (BOMLENS_GUARD_ID, BOMLENS_GUARD_RESTORE_ONLY) below.
# Named _ID, not _KEY: cdxgen's own security audit flagged "KEY" as
# credential-like in a supplier's scan log, which would be a confusing thing
# to see about an internal bookkeeping value.
#
# Scope: only a stable, repeatedly-scanned host path (--target / current
# folder). A --git clone or zip extract goes into a fresh temp dir every run
# (CLEANUP_DIRS is non-empty for those), so there is no "next scan of the
# same tree" to hand a stale record to — setup_guard_state is a no-op there.
#
# The state directory is keyed by a hash of the resolved path, but a hash
# collision (or, with the weaker cksum, a real one) must never make this
# clean up the wrong folder's files: the recorded path is checked for an
# exact match before anything is touched.
guard_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum 2>/dev/null | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 2>/dev/null | awk '{print $1}'
    else
        return 1
    fi
}
GUARD_ID=""
setup_guard_state() {
    [ "${#CLEANUP_DIRS[@]}" -eq 0 ] || return 0
    mkdir -p "$GUARD_STATE_DIR" 2>/dev/null || return 0
    local target_real key owner_file owner ps_out ps_rc recorded_path recorded_image cleanup_image
    target_real=$(cd "$SCAN_INPUT_DIR" 2>/dev/null && pwd -P) || return 0
    key=$(printf '%s' "$target_real" | guard_hash) || return 0
    [ -n "$key" ] || return 0
    owner_file="$GUARD_STATE_DIR/$key/owner"
    if [ -f "$owner_file" ]; then
        owner=$(cat "$owner_file" 2>/dev/null)
        recorded_path=$(cat "$GUARD_STATE_DIR/$key/path" 2>/dev/null)
        if [ -z "$owner" ] || [ "$recorded_path" != "$target_real" ] || ! command -v docker >/dev/null 2>&1; then
            echo "[WARN] found a leftover-cleanup record for this folder that does not match it (or cannot be confirmed); leaving it in place."
            return 0
        fi
        ps_out=$("${DOCKER_ENV[@]}" docker ps --filter "name=^${owner}\$" --format '{{.Names}}' 2>/dev/null)
        ps_rc=$?
        if [ "$ps_rc" -ne 0 ]; then
            echo "[WARN] could not confirm whether a previous scan of this folder ($owner) is still running; leaving its leftovers in place this time."
            return 0
        fi
        if [ -n "$ps_out" ]; then
            echo "[WARN] a previous scan of this folder ($owner) appears to still be running; not touching its leftovers."
            return 0
        fi
        # Confirmed gone and the path matches: finish what it started
        # (guard_restore, reused via build-prep.sh's restore-only mode)
        # before this run's own guard takes over the same slot. Reuses that
        # run's own cdxgen image (recorded below), or the already-local
        # postprocess image, rather than pulling anything new just for
        # cleanup — an offline host must not fail a scan over this.
        recorded_image=$(cat "$GUARD_STATE_DIR/$key/image" 2>/dev/null)
        cleanup_image=""
        if [ -n "$recorded_image" ] && "${DOCKER_ENV[@]}" docker image inspect "$recorded_image" >/dev/null 2>&1; then
            cleanup_image="$recorded_image"
        elif "${DOCKER_ENV[@]}" docker image inspect "$POSTPROCESS_IMAGE" >/dev/null 2>&1; then
            cleanup_image="$POSTPROCESS_IMAGE"
        fi
        if [ -z "$cleanup_image" ]; then
            echo "[WARN] no locally available image to clean up a previous interrupted scan's leftovers with; leaving them in place."
            return 0
        fi
        echo "[INFO] cleaning up build artifacts a previous, interrupted scan of this folder left behind..."
        "${DOCKER_ENV[@]}" docker run --rm -u 0:0 \
            -v "$(hostpath "$SCAN_INPUT_DIR")":/app \
            -v "$(hostpath "$GUARD_STATE_DIR")":/bomlens-state \
            -v "$(hostpath "$BUILD_PREP")":/tmp/build-prep.sh:ro \
            -e BOMLENS_GUARD_RESTORE_ONLY=1 -e "BOMLENS_GUARD_ID=$key" \
            --entrypoint sh "$cleanup_image" /tmp/build-prep.sh /app >/dev/null 2>&1 || true
    fi
    mkdir -p "$GUARD_STATE_DIR/$key" 2>/dev/null || return 0
    printf '%s\n' "$RUNNING_CONTAINER_NAME" > "$GUARD_STATE_DIR/$key/owner" 2>/dev/null || return 0
    printf '%s\n' "$target_real" > "$GUARD_STATE_DIR/$key/path" 2>/dev/null || return 0
    printf '%s\n' "$CDX_IMG" > "$GUARD_STATE_DIR/$key/image" 2>/dev/null || return 0
    GUARD_ID="$key"
}

# A reproducible (--byte-stable) build must not resolve dependency licenses over
# the network: registry availability (e.g. pkg.go.dev) varies between runs, so a
# license fetched in one scan but not the next would make two otherwise-identical
# scans differ. Pin the lookup off for byte-stable scans.
FETCH_LICENSE="${FETCH_LICENSE:-true}"
[ "$BYTE_STABLE" = "true" ] && FETCH_LICENSE="false"
# EPSS + CISA KEV enrichment defaults on, but the host setting must reach the
# post-process container so SECURITY_ENRICH=false works for air-gapped runs.
SECURITY_ENRICH="${SECURITY_ENRICH:-true}"
# Web UI's CVE/package lookup (GET /advisory, /package-advisories) talks to
# OSV.dev on demand; same default-on, host-setting-must-reach-the-container
# story as SECURITY_ENRICH, but read directly by server.py rather than by
# entrypoint.sh (see docker/web/server.py's external_lookup_capable()).
EXTERNAL_LOOKUP="${EXTERNAL_LOOKUP:-true}"

# Normalize the report language: only en (default) or ko reach the container. An
# unknown value is a user typo, so warn and fall back to English rather than
# silently producing an English report the user did not expect.
case "$REPORT_LANG" in
    en|ko) ;;
    *) echo "[WARN] --lang '$REPORT_LANG' not supported (use en or ko); defaulting to en."; REPORT_LANG="en" ;;
esac

# Normalize the conformance profile the same way: default or skt-submission
# reach the container, anything else is a typo.
case "$CONFORMANCE_PROFILE" in
    default|skt-submission) ;;
    *) echo "[WARN] --conformance-profile '$CONFORMANCE_PROFILE' not supported (use default or skt-submission); defaulting to default."; CONFORMANCE_PROFILE="default" ;;
esac

# Common -e flags for the post-process image.
# HOST_UID/HOST_GID let the (root) container chown artifacts back to the calling
# user, so Linux hosts/CI runners can read them (macOS Docker maps UIDs already).
pp_env() {
    # SCANOSS_API_KEY and API_KEY are forwarded by NAME ONLY (no =value), so the
    # secret never lands on the `docker run` argv where a local `ps` could read
    # it. Their values ride the exported shell env (see the export before each
    # `docker run`), matching the web-server path. Non-secret fields keep =value.
    printf ' -e GENERATE_NOTICE=%s -e GENERATE_SECURITY=%s -e GENERATE_SPDX=%s -e SECURITY_ENRICH=%s -e GENERATE_REPORT=%s -e DEEP_LICENSE=%s -e IDENTIFY_VENDORED=%s -e SCANOSS_API_URL=%q -e SCANOSS_API_KEY -e SIGN_SBOM=%s -e BYTE_STABLE=%s -e REPORT_LANG=%s -e UPLOAD_ENABLED=%s -e PROJECT_NAME=%q -e PROJECT_VERSION=%q -e HOST_OUTPUT_DIR=/host-output -e HOST_UID=%s -e HOST_GID=%s -e API_KEY -e API_URL=%q -e UPLOAD_TARGET=%q -e TRUSCA_PROJECT_ID=%q -e TRUSCA_REF=%q -e TRUSCA_RELEASE=%q -e ENRICH_CDXGEN=%s -e ENRICH_EOL=%s -e ENRICH_MALICIOUS=%s -e STALENESS_ENRICH=%s -e DEEP_CVE=%s -e SECURITY_NVD_VERIFY=%s -e ENRICH_HF_SECURITY=%s -e VERIFY_MODEL_WEIGHTS=%s -e AIBOM_VERIFY_MAX_FILES=%q -e AIBOM_VERIFY_MAX_BYTES=%q -e AI_USAGE_CONTEXT=%q -e PROJECT_LICENSE=%q -e SBOM_AUTHOR=%q -e SRC_TREE_EXCLUDE=%q -e SOURCE_TREE_MAX=%q -e SOURCE_SNAPSHOT_MAX_TOTAL=%q -e SOURCE_SNAPSHOT_MAX_FILE=%q -e SOURCE_SNAPSHOT_MAX_FILES=%q -e FW_VERSTR_MAX_FILES=%q -e FW_VERSTR_MAX_BYTES=%q -e FW_ELF_MAX_FILES=%q -e FW_KERNEL_MAX_FILES=%q -e FW_KERNEL_MAX_BYTES=%q -e FW_KERNEL_MAX_VERSIONS=%q -e FW_EXTRA_ROOTS=%q -e FW_MAX_EXTRA_ROOTS=%q -e FW_CONTAINER_MEMBERSHIP=%q -e PURL_MIN_PCT=%q -e LICENSE_MIN_PCT=%q -e HASH_MIN_PCT=%q -e FIELD_MIN_PCT=%q -e CONFORMANCE_PROFILE=%s -e PURL_RESOLVE=%s -e PURL_RESOLVE_IGNORE -e PURL_RESOLVE_BUDGET' \
        "$GENERATE_NOTICE" "$GENERATE_SECURITY" "$GENERATE_SPDX" "$SECURITY_ENRICH" "$GENERATE_REPORT" "$DEEP_LICENSE" "$IDENTIFY_VENDORED" "$SCANOSS_API_URL" "$SIGN_SBOM" "$BYTE_STABLE" "$REPORT_LANG" "$UPLOAD_VAR" "$PROJECT_NAME" "$PROJECT_VERSION" "$(id -u)" "$(id -g)" "$SERVER_URL" "$UPLOAD_TARGET" "$TRUSCA_PROJECT_ID" "$TRUSCA_REF" "$TRUSCA_RELEASE" "${ENRICH_CDXGEN:-true}" "${ENRICH_EOL:-true}" "${ENRICH_MALICIOUS:-true}" "${STALENESS_ENRICH:-false}" "$DEEP_CVE" "${SECURITY_NVD_VERIFY:-false}" "${ENRICH_HF_SECURITY:-true}" "$VERIFY_WEIGHTS" "${AIBOM_VERIFY_MAX_FILES:-}" "${AIBOM_VERIFY_MAX_BYTES:-}" "${USAGE_CONTEXT:-${AI_USAGE_CONTEXT:-}}" "${PROJECT_LICENSE:-}" "${SBOM_AUTHOR:-}" "${SRC_TREE_EXCLUDE:-}" \
        "${SOURCE_TREE_MAX:-}" "${SOURCE_SNAPSHOT_MAX_TOTAL:-}" "${SOURCE_SNAPSHOT_MAX_FILE:-}" "${SOURCE_SNAPSHOT_MAX_FILES:-}" \
        "${FW_VERSTR_MAX_FILES:-}" "${FW_VERSTR_MAX_BYTES:-}" "${FW_ELF_MAX_FILES:-}" \
        "${FW_KERNEL_MAX_FILES:-}" "${FW_KERNEL_MAX_BYTES:-}" "${FW_KERNEL_MAX_VERSIONS:-}" \
        "${FW_EXTRA_ROOTS:-}" "${FW_MAX_EXTRA_ROOTS:-}" "${FW_CONTAINER_MEMBERSHIP:-}" \
        "${PURL_MIN_PCT:-}" "${LICENSE_MIN_PCT:-}" "${HASH_MIN_PCT:-}" "${FIELD_MIN_PCT:-}" "$CONFORMANCE_PROFILE" "${PURL_RESOLVE:-false}"
}

# The docker CLI forwards a name-only `-e VAR` from its own environment, so the
# secret values must be exported for pp_env/cosign_run to carry them. API_KEY is
# the resolved DEFAULT_API_KEY; the others come straight from the host env.
export_scan_secrets() { export API_KEY="$DEFAULT_API_KEY" SCANOSS_API_KEY COSIGN_PASSWORD; }

# cosign key mount + env, only when --sign is set with a real key. The private
# key dir is mounted READ-ONLY and the password comes from the host env — never
# hardcoded (credentials must not be baked in). Without this the container's COSIGN_KEY is
# unset and entrypoint.sh skips signing, so `--sign` produced no .sig.
cosign_run() {
    [ "$SIGN_SBOM" = "true" ] && [ -n "${COSIGN_KEY:-}" ] && [ -f "$COSIGN_KEY" ] || return 0
    local d f
    d="$(hostpath "$(cd "$(dirname "$COSIGN_KEY")" && pwd)")"; f="$(basename "$COSIGN_KEY")"
    # COSIGN_KEY is a container path (safe as a value); COSIGN_PASSWORD is the
    # secret and is forwarded by name only (value via the exported env).
    printf ' -v %q:/cosign:ro -e COSIGN_KEY=%q -e COSIGN_PASSWORD' "$d" "/cosign/$f"
}

# --vex: the received document alone is mounted read-only (not the folder it
# sits in, which may hold unrelated files) and named by its container path;
# import-vex.py reads it after the SBOM exists.
# It always appears at the fixed container path /vex-in/vex.json: this string is
# expanded unquoted inside an eval'd command line, and an env value built from
# the user's file name that ends in a space leaves a trailing backslash from %q
# which joins the next token into the same word. The name stays only in the -v
# source, where it is followed by the constant mount path.
vex_run() {
    [ -n "$VEX_FILE" ] || return 0
    local d f
    d="$(cd "$(dirname "$VEX_FILE")" && pwd)"; f="$(basename "$VEX_FILE")"
    printf ' -v %q:/vex-in/vex.json:ro -e VEX_FILE=/vex-in/vex.json' "$(hostpath "$d/$f")"
}

# --fail-on: the conditions travel to the container as one comma-separated value.
# Each is from a closed list (checked when the option is read), so none holds a
# space or a shell-special character.
gate_run() {
    [ "${#FAIL_ON[@]}" -gt 0 ] || return 0
    local joined; joined="$(IFS=,; printf '%s' "${FAIL_ON[*]}")"
    printf ' -e FAIL_ON=%q' "$joined"
}

# ========================================================
# Detect target type
# ========================================================
# Recognize a firmware blob by extension, or (if `file` is on the host) by magic.
# ---------------------------------------------------------------------------
# AI model weight files
#
# A model file is not an archive of packages: syft reads it as one opaque file
# and finds nothing to list, so BINARY mode returns an empty SBOM. MODELFILE
# mode reads the file's own header instead.
#
# Extensions only, and .bin is deliberately absent: it names both a PyTorch
# checkpoint and a firmware image, and --target already routes it to firmware.
# Pass such a file with --model-file to have it read as a model.
is_model_file() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        *.gguf|*.safetensors|*.onnx|*.npz|*.npy|*.pt|*.pth|*.ckpt|*.pkl|*.pickle) return 0 ;;
    esac
    return 1
}

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

# ---------------------------------------------------------------------------
# Formats that only give up their contents once unpacked
#
# A file target that is not firmware goes to BINARY mode, which reads the file
# itself with the signature checkers and never unpacks it. For an installer or an
# app package that is almost nothing: the components are inside, not in the outer
# file. Measured on a desktop media player's own downloads — the Windows
# installer yields 1 component read as a file and 39 once unpacked, the macOS disk
# image 0 and 25 — and on an Android app, 0 and 54.
#
# Unpacking is the firmware path (unblob and the identifiers behind it), so these
# formats are routed there when that image is available. The list is closed and
# each entry was measured, because the reverse case exists: an RPM yields 1
# component in BINARY mode and 0 through the firmware path, since syft reads the
# package header directly and unpacking throws that header away. A blanket rule
# would have made that worse.
#
# Recognition is by content, not by extension. `file` reports a Windows installer
# as a PE executable and a macOS disk image by its compression, and an extension
# is what an arbitrary uploader controls.
needs_unpacking() {
    local f="$1" lower magic
    lower=$(printf '%s' "$f" | tr '[:upper:]' '[:lower:]')
    case "$lower" in
        *.exe|*.msi|*.dmg|*.apk|*.ipa) : ;;
        *) return 1 ;;
    esac
    command -v file >/dev/null 2>&1 || return 1
    magic=$(file -b "$f" 2>/dev/null)
    case "$magic" in
        # Windows installers: PE executables, and the MSI/Inno container formats.
        *"PE32"*|*"MS Windows"*|*"Composite Document File"*) return 0 ;;
        # macOS disk images: the payload is compressed, and `file` names the
        # compression rather than the container.
        *"bzip2 compressed"*|*"zlib compressed"*|*"Apple Disk Image"*) return 0 ;;
        # Mobile app packages are zip containers. `file` calls an app package a
        # zip, a Java archive, or — on a build whose magic database recognizes
        # classes.dex (confirmed on file 5.46) — "Android package (APK)"
        # directly. The extension is what says this zip is an app; the magic
        # only confirms it is a zip and not something renamed to look like one.
        # Measured on one Android app: 0 components read as a single file, 54
        # once unpacked.
        *"Zip archive"*|*"Java archive"*|*"Android package"*)
            case "$lower" in *.apk|*.ipa) return 0 ;; esac ;;
    esac
    return 1
}

# ---------------------------------------------------------------------------
# Yocto build directory
#
# A Yocto build publishes its SPDX SBOM next to the image it produced, under
# tmp/deploy/images/<machine>/. Pointing --target at the build directory used to
# fall through to a plain ROOTFS directory scan, which reads the entire build
# tree — sysroots, native build tools, per-recipe work directories — none of
# which ships in the image. Recognize the build directory instead and hand its
# image SBOM to the ANALYZE path, which reads the installed set and the
# vulnerability judgements the build recorded (docker/lib/parse-yocto-spdx.py).
# ---------------------------------------------------------------------------
is_yocto_build_dir() {
    local d="$1" p q
    [ -d "$d" ] || return 1
    # Markers only bitbake leaves, in the build directory it was run from. These
    # stand on their own, so a build that was never configured to emit an SBOM is
    # still recognized and can be told which setting to add. TMPDIR carries the C
    # library suffix outside poky (oe-core builds write tmp-glibc), hence tmp*.
    [ -f "$d/conf/bblayers.conf" ] && return 0
    for q in "$d"/tmp*/deploy/images; do
        [ -d "$q" ] && return 0
    done
    # Shapes that are not Yocto-specific on their own: a deploy tree, or the
    # per-machine image folder inside one. Plenty of projects have a directory
    # called deploy/images or a file called *.manifest, and taking one of those
    # over would refuse a directory scan the user meant to run — so these count
    # only when a document bitbake actually wrote is sitting there.
    for q in "$d"/deploy/images/*/*.spdx.json "$d"/images/*/*.spdx.json; do
        is_yocto_spdx_doc "$q" && return 0
    done
    for q in "$d"/deploy/images/*/*.spdx.tar.zst "$d"/images/*/*.spdx.tar.zst "$d"/*.spdx.tar.zst; do
        [ -f "$q" ] && return 0
    done
    for p in "$d"/*.manifest; do
        [ -f "$p" ] || continue
        for q in "$d"/*.spdx.json; do
            is_yocto_spdx_doc "$q" && return 0
        done
        break
    done
    return 1
}

# True for an SPDX document bitbake produced. Both SPDX 2.x and 3.x name it as
# the creating tool, so one grep covers the releases we accept; the container
# does the authoritative check (parse-yocto-spdx.py), this only decides whether a
# directory is Yocto's. openembedded appears instead of bitbake in some 2.x
# output, so both are matched.
is_yocto_spdx_doc() {
    [ -f "$1" ] || return 1
    LC_ALL=C grep -qiE 'bitbake|openembedded' "$1" 2>/dev/null
}

# Every SPDX document a Yocto build could have left in $1, most specific
# location first. `<image>.rootfs.spdx.json` is what an image build writes;
# the looser `*.spdx.json` tier is only consulted when that finds nothing, so
# an image document is never listed twice by the two tiers. Duplicates within a
# tier are removed by the caller (bitbake publishes both a timestamped file and
# an IMAGE_LINK_NAME symlink to it).
yocto_spdx_candidates() {
    local d="$1" tier p hit=1
    # The archive tiers are last because they are the SPDX 2.x form: a build that
    # wrote a 3.0 document leaves a .spdx.json and no archive, and a 2.2 build
    # leaves the archive and nothing else — its image document is inside it, not
    # beside it (verified against the published Yocto 5.0.14 artifacts).
    for tier in .rootfs.spdx.json .spdx.json .rootfs.spdx.tar.zst .spdx.tar.zst; do
        for p in \
            "$d"/tmp*/deploy/images/*/*"$tier" \
            "$d"/deploy/images/*/*"$tier" \
            "$d"/images/*/*"$tier" \
            "$d"/*"$tier"; do
            [ -f "$p" ] || continue
            printf '%s\n' "$p"
            hit=0
        done
        [ "$hit" = 0 ] && return 0
    done
    return 1
}

# True for the archive an SPDX 2.x build deploys. Its contents are compressed, so
# nothing in it can be grepped for — the name is the signal, and it is one only
# bitbake writes.
is_spdx2_archive() {
    case "$1" in
        *.spdx.tar.zst) return 0 ;;
    esac
    return 1
}

# True for an SPDX 2.x document. For a Yocto build that form is only an index:
# the packages live in per-recipe documents inside <image>.spdx.tar.zst, so it
# converts to an almost empty SBOM (parse-yocto-spdx.py explains the same thing
# container-side). Read from the content rather than the sibling files, which
# differ between releases.
is_spdx2_doc() {
    LC_ALL=C grep -qE '"spdxVersion"[[:space:]]*:[[:space:]]*"SPDX-2' "$1" 2>/dev/null
}

# The physical path of a file, following symlinks. bitbake publishes each image
# artifact twice — a timestamped file and an IMAGE_LINK_NAME symlink pointing at
# it — and reporting those as two different SBOMs would invent a choice the user
# does not have. Falls back to the path as given wherever it cannot resolve
# (readlink is absent, a link is broken, a cycle), which is never worse than the
# duplicate listing it replaces.
resolve_file_path() {
    local f="$1" d b t n=0
    d=$(cd "$(dirname "$f")" 2>/dev/null && pwd -P) || { printf '%s' "$f"; return 0; }
    b=$(basename "$f")
    while [ -L "$d/$b" ] && [ "$n" -lt 16 ]; do
        t=$(readlink "$d/$b" 2>/dev/null) || break
        [ -n "$t" ] || break
        case "$t" in
            /*) d=$(cd "$(dirname "$t")" 2>/dev/null && pwd -P) || break ;;
            *)  d=$(cd "$d/$(dirname "$t")" 2>/dev/null && pwd -P) || break ;;
        esac
        b=$(basename "$t")
        n=$((n + 1))
    done
    printf '%s/%s' "$d" "$b"
}

# The image package manifest a build wrote, when it produced no SPDX document.
# `<image>.manifest` lists every installed package; image_license.manifest sits
# beside it and describes the image recipe rather than its contents, so it is not
# one of these. Only the presence matters here — parse-yocto-manifests.py reads
# the contents container-side.
yocto_manifest_in() {
    local d="$1" p
    for p in \
        "$d"/tmp*/deploy/images/*/*.manifest \
        "$d"/deploy/images/*/*.manifest \
        "$d"/images/*/*.manifest \
        "$d"/*.manifest; do
        [ -f "$p" ] || continue
        case "$(basename "$p")" in
            image_license.manifest) continue ;;
        esac
        printf '%s' "$p"
        return 0
    done
    return 1
}

# Pick the one SPDX document to analyze out of the candidate paths on stdin.
# SPDX 3.x wins over 2.x (only 3.x carries the installed set and the build's CVE
# judgements), then the most recently written. Prints the chosen path and
# nothing else, so the caller owns what the user sees.
yocto_pick_spdx() {
    local p chosen="" fallback=""
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        if is_spdx2_doc "$p"; then
            { [ -z "$fallback" ] || [ "$p" -nt "$fallback" ]; } && fallback="$p"
        else
            { [ -z "$chosen" ] || [ "$p" -nt "$chosen" ]; } && chosen="$p"
        fi
    done
    [ -n "$chosen" ] || chosen="$fallback"
    printf '%s' "$chosen"
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

# An archive we auto-extract. What it holds decides the mode, not the extension:
# see looks_like_rootfs / is_container_archive below.
is_archive() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        *.zip|*.tar.gz|*.tgz|*.tar.bz2|*.tar.xz|*.tar) return 0 ;;
        *) return 1 ;;
    esac
}

# An archive can hold a root filesystem rather than source: suppliers ship /etc,
# /bin and /usr as a plain zip or tarball. Scanning that tree as source finds
# nothing, because there is no manifest or lockfile to read — the packages are
# recorded in the filesystem's own package database, which the ROOTFS path reads.
#
# Recognized by an `etc` directory next to at least two other system directories.
# Two, not one, because a source repository with `etc/` and `lib/` is common and
# must keep going to the source path; `etc` plus two of bin/sbin/usr/lib/var is
# not something a source tree has.
_is_rootfs_dir() {
    local d="$1" sub hits=0
    [ -d "$d/etc" ] || return 1
    for sub in bin sbin usr lib var; do
        [ -d "$d/$sub" ] && hits=$((hits + 1))
    done
    [ "$hits" -ge 2 ]
}

# Print the directory holding the root filesystem, or nothing. Searches the tree
# root and two levels down: a delivery is as often wrapped in a release folder
# (`nat-rootfs-20260719/rootfs/`) as it is packed at the top level.
find_rootfs_dir() {
    local root="$1" d
    for d in "$root" "$root"/*/ "$root"/*/*/; do
        [ -d "$d" ] || continue
        d="${d%/}"
        if _is_rootfs_dir "$d"; then printf '%s' "$d"; return 0; fi
    done
    return 1
}

# A plain directory --target that is not itself a root filesystem may still
# have one a level or two below it (a delivery folder wrapping the actual
# rootfs) -- the common shape find_rootfs_dir already searches for archives.
# This does NOT change routing: auto-switching a directory --target to ROOTFS
# on this alone would repeat, in the other direction, the bug #47 fixed (every
# directory --target used to hard-route to ROOTFS regardless of contents,
# silently dropping cdxgen's resolved deps/licenses/hashes) -- a source repo
# that happens to hold a rootfs-shaped fixture folder would now be silently
# rerouted away from a scan that would otherwise have found real components.
# Returns nothing (and fails) when $1 is itself a rootfs -- that path already
# routes to ROOTFS on its own, so a caller only ever needs this for the
# directory that is NOT one, to decide whether a diagnostic is worth naming.
#
# docker/web/server.py has its own nested_rootfs_hint for the web UI's deep
# source scan (scan-target-src) -- kept in sync deliberately, same shape
# check, same fixtures in tests/test-input-routing.sh and tests/test-web-ui.sh.
nested_rootfs_hint() {
    local d="$1" found
    _is_rootfs_dir "$d" && return 1
    found=$(find_rootfs_dir "$d") || return 1
    printf '%s' "${found#"$d"/}"
}

# Does the root filesystem record its own packages? syft reads apk/dpkg/rpm and
# reports the installed set exactly; without one of these there is nothing for it
# to read, and only binary signature identification (the firmware image) will
# find anything. Used to tell the user which of the two they are getting.
has_package_db() {
    local d="$1"
    [ -f "$d/lib/apk/db/installed" ] && return 0
    [ -f "$d/var/lib/dpkg/status" ] && return 0
    [ -d "$d/var/lib/rpm" ] && return 0
    [ -d "$d/usr/lib/sysimage/rpm" ] && return 0
    return 1
}

# `docker save` writes a tar that syft reads as an image, package database and
# all. Extracting it as a source archive throws that away and leaves compressed
# layer blobs no language detector can read. Recognized by the image manifest
# sitting next to either OCI blobs or a legacy per-layer tar.
is_container_archive() {
    local names
    names=$(tar -tf "$1" 2>/dev/null | head -400) || return 1
    printf '%s\n' "$names" | grep -qE '^(\./)?manifest\.json$' || return 1
    printf '%s\n' "$names" | grep -qE '(^|/)(oci-layout$|blobs/|layer\.tar$)'
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
        if [ -n "$GIT_REF" ]; then
            # `clone --branch` only resolves a branch or tag on the remote, so a
            # commit SHA (documented as accepted alongside them, cli.md:27) fails
            # here every time. Nothing in the error output reliably distinguishes
            # that case from a genuinely bad ref or URL, so retry as a full clone
            # and a local checkout, which resolves a SHA the shallow form cannot.
            echo "[INFO] Shallow clone with --branch \"$GIT_REF\" failed; retrying as a full clone (needed to resolve a commit)..."
            rm -rf "$tmp/repo"
            if ! GIT_TERMINAL_PROMPT=0 git clone -- "$clone_url" "$tmp/repo" 2>>/tmp/sbom-git-err \
                || ! git -C "$tmp/repo" checkout --quiet "$GIT_REF" 2>>/tmp/sbom-git-err; then
                echo "[ERROR] git clone failed for $url"; sed 's/x-access-token:[^@]*@/x-access-token:***@/g' /tmp/sbom-git-err 2>/dev/null; rm -f /tmp/sbom-git-err; exit 1
            fi
        else
            echo "[ERROR] git clone failed for $url"; sed 's/x-access-token:[^@]*@/x-access-token:***@/g' /tmp/sbom-git-err 2>/dev/null; rm -f /tmp/sbom-git-err; exit 1
        fi
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
            # `-Z1` (zipinfo, names only) not `-l` (a fixed-width listing table):
            # a filename containing a space breaks `-l`'s "name is column 4"
            # assumption apart, since awk splits on whitespace too — a crafted
            # entry like "evil name/../../../etc/passwd" then extracts $4 as
            # just "evil", silently dropping the traversal from what gets
            # checked. Confirmed empirically: that exact entry passed this
            # guard right through under `-l`+awk.
            if command -v unzip >/dev/null 2>&1; then
                if unzip -Z1 "$arc" 2>/dev/null | grep -qE '(^/|(^|/)\.\.(/|$))'; then
                    echo "[ERROR] unsafe path in archive (zip-slip)"; exit 1
                fi
                if ! unzip -q -d "$tmp" -- "$arc"; then
                    echo "[ERROR] unzip failed for $arc"
                    echo "[HINT] A zip made on Windows with PowerShell Compress-Archive stores"
                    echo "       backslash path separators that unzip rejects. Re-create it with"
                    echo "       Windows Explorer (Send to > Compressed folder) and scan again."
                    exit 1
                fi
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
    local rootfs_dir
    if rootfs_dir=$(find_rootfs_dir "$SCAN_INPUT_DIR"); then
        SCAN_INPUT_DIR="$rootfs_dir"
        INGEST_ROOTFS="true"
        INGEST_ARCHIVE="$arc"
    fi
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
# Host-only check, made before anything is cloned or downloaded.
if [ -n "$VEX_FILE" ] && [ ! -f "$VEX_FILE" ]; then
    echo "[ERROR] --vex file not found: $VEX_FILE"
    echo "[ERROR] Pass the path of a CycloneDX VEX document (JSON), e.g. --vex supplier-vex.json."; exit 1
fi

if [ -n "$GIT_URL" ]; then
    [ -z "$TARGET" ]      || { echo "[ERROR] --git is mutually exclusive with --target."; exit 1; }
    [ -z "$ANALYZE_SBOM" ] || { echo "[ERROR] --git is mutually exclusive with --analyze."; exit 1; }
    [ -z "$MODEL" ]       || { echo "[ERROR] --git is mutually exclusive with --model."; exit 1; }
    [ "$FORCE_FIRMWARE" = "true" ] && { echo "[ERROR] --git cannot be combined with --firmware."; exit 1; }
    ingest_git "$GIT_URL"
elif [ -n "$TARGET" ] && [ -f "$TARGET" ] && is_archive "$TARGET"; then
    # An archive is not automatically source. Three cases, decided by content:
    #   --firmware  the user wants the deep unpacker, which reads the archive
    #               itself (nested formats and all) — leave the file target alone.
    #   container   syft reads a `docker save` tar directly; extracting it first
    #               would leave only unreadable layer blobs.
    #   otherwise   extract, then let ingest_archive decide source vs rootfs.
    if [ "$FORCE_FIRMWARE" = "true" ]; then
        echo "[INFO] --firmware: unpacking $TARGET with the firmware unpacker."
    elif is_container_archive "$TARGET"; then
        echo "[INFO] Container image archive detected; scanning the image, not its layers."
    else
        ingest_archive "$TARGET"
    fi
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
    if [ "$INGEST_ROOTFS" = "true" ]; then
        # The archive held a root filesystem, not source. Point the ROOTFS path
        # at the extracted tree so syft reads its package database; scanning it
        # as source would report nothing, since there is no manifest in it.
        echo "[INFO] Archive contains a root filesystem; scanning as ROOTFS."
        if ! has_package_db "$SCAN_INPUT_DIR"; then
            echo "[WARN] This root filesystem has no package database (apk/dpkg/rpm),"
            echo "       so there is no installed-package list to read. Re-run with"
            echo "       --firmware to identify the binaries by signature instead"
            echo "       (opt-in image: docker build --build-arg SBOM_FIRMWARE=true)."
        fi
        TARGET="$SCAN_INPUT_DIR"
        MODE="ROOTFS"
    else
        # A git clone / extracted source archive is scanned as SOURCE (the temp
        # dir would otherwise be detected as ROOTFS below).
        MODE="SOURCE"
    fi
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
    # Research data is published where the paper put it, which for a great deal
    # of science is Figshare rather than a model hub. Both are "the thing I was
    # handed a link to", so one option takes both and the reference decides which
    # path runs. An institutional DOI carrying no "figshare" (10.25916/sut.…)
    # cannot be told apart from any other DOI: give the item url for those.
    case "$MODEL" in
        *figshare*) MODE="DATASET" ;;
        *)          MODE="AIBOM" ;;
    esac
    case "${USAGE_CONTEXT:-}" in
        ""|internal|product|redistribute|outputs-only) : ;;
        *) echo "[ERROR] --usage must be one of: internal, product, redistribute, outputs-only."; exit 1 ;;
    esac
    # Default the project name to the model's last segment (owner/name -> name).
    # A Figshare reference has no such name, so the item number stands in until
    # the fetch replaces the root component with the item's real title.
    if [ "$MODE" = "DATASET" ]; then
        [ -n "$PROJECT_NAME" ] || PROJECT_NAME="figshare-$(printf '%s' "$MODEL" | tr -cd '0-9' | tail -c 12)"
    else
        [ -n "$PROJECT_NAME" ] || PROJECT_NAME="${MODEL##*/}"
    fi
elif [ -n "$MODEL_FILE" ]; then
    # AI model SBOM read from the file itself. Base image, no network: the whole
    # step is one stdlib Python script inside the container.
    [ -z "$TARGET" ]       || { echo "[ERROR] --model-file is mutually exclusive with --target."; exit 1; }
    [ -z "$ANALYZE_SBOM" ] || { echo "[ERROR] --model-file is mutually exclusive with --analyze."; exit 1; }
    [ -z "$GIT_URL" ]      || { echo "[ERROR] --model-file is mutually exclusive with --git."; exit 1; }
    [ "$FORCE_FIRMWARE" != "true" ] || { echo "[ERROR] --model-file cannot be combined with --firmware."; exit 1; }
    [ -f "$MODEL_FILE" ]   || { echo "[ERROR] --model-file not found: $MODEL_FILE"; exit 1; }
    MODE="MODELFILE"
    case "${USAGE_CONTEXT:-}" in
        ""|internal|product|redistribute|outputs-only) : ;;
        *) echo "[ERROR] --usage must be one of: internal, product, redistribute, outputs-only."; exit 1 ;;
    esac
elif [ -n "$TARGET" ]; then
    if [ -f "$TARGET" ]; then
        if [ "$FORCE_FIRMWARE" = "true" ] || is_firmware "$TARGET"; then
            MODE="FIRMWARE"
        elif is_model_file "$TARGET"; then
            # Reading a weight file with the binary scanner finds nothing, so
            # route it to the model reader instead of returning an empty SBOM.
            echo "[INFO] $(basename "$TARGET") is an AI model file; reading its header."
            MODE="MODELFILE"
            MODEL_FILE="$TARGET"
        elif needs_unpacking "$TARGET"; then
            # The unpacking path needs the opt-in firmware image. When it is here,
            # use it; when it is not, read the file as before and say what was and
            # was not looked at, so a near-empty result is not read as the answer.
            case "$(printf '%s' "$TARGET" | tr '[:upper:]' '[:lower:]')" in
                *.apk|*.ipa) packed_kind="an app package" ;;
                *)           packed_kind="a packaged installer" ;;
            esac
            if docker image inspect "$FIRMWARE_IMAGE" >/dev/null 2>&1; then
                echo "[INFO] $(basename "$TARGET") is $packed_kind; unpacking it to read what is inside."
                MODE="FIRMWARE"
            else
                MODE="BINARY"
                echo "[WARN] $(basename "$TARGET") is $packed_kind. It was read as a single file"
                echo "       without unpacking, so only components with a version string in the outer"
                echo "       file can be found. Unpacking needs the firmware image:"
                echo "         docker pull $FIRMWARE_IMAGE"
                echo "       Then run the same command again."
            fi
        else
            MODE="BINARY"
        fi
    elif [ -d "$TARGET" ] && [ "$FORCE_FIRMWARE" != "true" ] && is_yocto_build_dir "$TARGET"; then
        # A Yocto build already knows what it put in the image; read that rather
        # than walking the build tree. Joins the ANALYZE path below with the
        # SBOM the build wrote — no separate mode, so validation, conformance
        # and the reports all behave exactly as they do for an uploaded SBOM.
        # --firmware is excluded above so that combination still gets its own
        # "expects a file target" error instead of one about a missing SBOM.
        echo "[INFO] Yocto build directory: $TARGET"
        # Collect first, then choose, so the list the user sees and the choice
        # come from one set. A timestamped document and the IMAGE_LINK_NAME
        # symlink pointing at it are the same SBOM, so keep one entry per file.
        YOCTO_CANDS=""; YOCTO_SEEN=""
        while IFS= read -r yc; do
            [ -n "$yc" ] || continue
            yc_real="$(resolve_file_path "$yc")"
            case "$YOCTO_SEEN" in
                *"|$yc_real|"*) continue ;;
            esac
            YOCTO_SEEN="$YOCTO_SEEN|$yc_real|"
            YOCTO_CANDS="$YOCTO_CANDS$yc
"
        done < <(yocto_spdx_candidates "$TARGET" || true)
        YOCTO_SPDX="$(printf '%s' "$YOCTO_CANDS" | yocto_pick_spdx)"
        if [ -z "$YOCTO_SPDX" ]; then
            # No SPDX, but a build still records what it shipped: the image package
            # manifest, license.manifest and cve-check's report. Read those instead
            # of refusing — scanning the build tree as a directory would report
            # sysroots and native build tools that never ship in the image.
            if [ -n "$(yocto_manifest_in "$TARGET")" ]; then
                echo "[INFO] No SPDX in this build; reading the manifests it wrote instead."
                echo "[INFO]   Components and licenses come from the image and license manifests,"
                echo "[INFO]   and vulnerabilities from cve-check when the build ran it. For"
                echo '[INFO]   CPE-accurate matching, rebuild with INHERIT += "create-spdx-3.0".'
                YOCTO_BUILD_DIR="$(cd "$TARGET" && pwd)"
                MODE="ANALYZE"
                GENERATE_NOTICE="true"; GENERATE_SECURITY="true"
            else
                echo "[ERROR] This is a Yocto build directory, but it holds neither an SPDX SBOM"
                echo "        nor an image package manifest to read."
                echo "        Add these two lines to conf/local.conf and build the image again:"
                echo '            INHERIT += "create-spdx-3.0"'
                echo '            INHERIT += "vex"'
                echo "        The SBOM then lands in tmp/deploy/images/<machine>/<image>.rootfs.spdx.json,"
                echo "        and this folder can be scanned as-is."
                echo "        If this build writes its images elsewhere (a relocated DEPLOY_DIR), pass"
                echo "        the document directly: --analyze <image>.rootfs.spdx.json."
                echo "        Scanning a build directory as a plain directory tree is not done as a"
                echo "        fallback: it reports sysroots and native build tools that never ship in"
                echo "        the image. To scan a tree anyway, point --target at that tree itself"
                echo "        (an extracted rootfs, for example) rather than at the build directory."
                exit 1
            fi
        else
        # The machine and image folder names come from the filesystem, not from
        # anything the user typed, and the path is interpolated into an `eval`ed
        # docker run below. Refuse the few characters that would be more than a
        # path there rather than quietly running them.
        case "$YOCTO_SPDX" in
            *'$'*|*'`'*|*'"'*|*'\'*)
                echo "[ERROR] The SBOM path found in this build directory contains a character"
                echo "        that cannot be passed through safely: $YOCTO_SPDX"
                echo "        Rename the folder, or pass the file with --analyze <file>."
                exit 1 ;;
        esac
        if [ "$(printf '%s' "$YOCTO_CANDS" | grep -c .)" -gt 1 ]; then
            echo "[INFO] Several image SBOMs in this build directory:"
            while IFS= read -r yc; do
                [ -n "$yc" ] || continue
                if [ "$yc" = "$YOCTO_SPDX" ]; then
                    echo "[INFO]   $yc  <- analyzing this one"
                else
                    echo "[INFO]   $yc"
                fi
            done <<< "$YOCTO_CANDS"
            echo "[INFO]   Chosen by SPDX version first (3.x carries the installed set and the"
            echo "[INFO]   build's CVE verdicts), then by which was written last."
            echo "[INFO]   To analyze a different one, pass it with --analyze <file>."
        fi
        if is_spdx2_archive "$YOCTO_SPDX"; then
            echo "[INFO] SPDX 2.x build: the packages come from inside this archive."
            echo "[INFO]   Vulnerabilities are matched from the CPEs, since only SPDX 3.0 records"
            echo '[INFO]   which CVEs a recipe patched — INHERIT += "create-spdx-3.0" adds that'
            echo "[INFO]   on 5.0 Scarthgap and later."
        elif is_spdx2_doc "$YOCTO_SPDX"; then
            # An SPDX 2.x image document is only an index; the packages are in the
            # archive beside it, which the parser reads when it is there.
            if [ -f "${YOCTO_SPDX%.spdx.json}.spdx.tar.zst" ]; then
                echo "[INFO] SPDX 2.x build: the packages come from"
                echo "[INFO]   $(basename "${YOCTO_SPDX%.spdx.json}.spdx.tar.zst") beside the image document."
                echo "[INFO]   Vulnerabilities are matched from the CPEs, since only SPDX 3.0 records"
                echo '[INFO]   which CVEs a recipe patched — INHERIT += "create-spdx-3.0" adds that.'
            else
                echo "[WARN] $(basename "$YOCTO_SPDX") is an SPDX 2.x document, and the archive that"
                echo "[WARN]   holds its packages ($(basename "${YOCTO_SPDX%.spdx.json}.spdx.tar.zst"))"
                echo "[WARN]   is not beside it, so expect an almost empty result. Keep the two"
                echo '[WARN]   together, or rebuild with INHERIT += "create-spdx-3.0".'
            fi
        fi
        echo "[INFO] Image SBOM: $YOCTO_SPDX"
        # Resolved, so the result page names a folder the user can find again
        # rather than a relative path that only meant something in that shell.
        YOCTO_BUILD_DIR="$(cd "$TARGET" && pwd)"
        ANALYZE_SBOM="$YOCTO_SPDX"
        MODE="ANALYZE"
        # Same as an uploaded SBOM: the risk report needs license + vulnerability data.
        GENERATE_NOTICE="true"; GENERATE_SECURITY="true"
        fi
    elif [ -d "$TARGET" ]; then
        if _is_rootfs_dir "$TARGET"; then
            # Looks like a real root filesystem (etc/ plus two of bin/sbin/usr/lib/var):
            # syft reads its package database directly, same as an archive that
            # unpacked to one (see INGEST_ROOTFS above).
            if ! has_package_db "$TARGET"; then
                echo "[WARN] This root filesystem has no package database (apk/dpkg/rpm),"
                echo "       so there is no installed-package list to read. Re-run with"
                echo "       --firmware to identify the binaries by signature instead"
                echo "       (opt-in image: docker build --build-arg SBOM_FIRMWARE=true)."
            fi
            MODE="ROOTFS"
        else
            # An ordinary source tree pointed at directly, e.g. `--target
            # examples/nodejs`. MODE is already "SOURCE" by default (set above,
            # before this elif chain), but SCAN_INPUT_DIR still defaults to the
            # current directory ($(pwd), set earlier near SOURCE_DIR) — without
            # this, cdxgen would silently scan the current directory instead of
            # the folder the user named. Resolve to an absolute path so it
            # survives any later `cd`.
            MODE="SOURCE"
            SCAN_INPUT_DIR="$(cd "$TARGET" && pwd)"
            # This folder is not itself a rootfs, but one may sit a level
            # or two below it (nested_rootfs_hint), which is why the resulting
            # SBOM can come back with 0 components. entrypoint.sh names it in
            # that warning, but only once the scan is confirmed empty, never
            # just because the folder exists.
            NESTED_ROOTFS_HINT="$(nested_rootfs_hint "$SCAN_INPUT_DIR" || true)"
        fi
    else MODE="IMAGE"; fi
elif [ "$FORCE_FIRMWARE" = "true" ]; then
    echo "[ERROR] --firmware requires '--target <firmware-file>'."; exit 1
fi

if [ -n "${USAGE_CONTEXT:-}" ] && [ "$MODE" != "AIBOM" ] && [ "$MODE" != "MODELFILE" ] && [ "$MODE" != "DATASET" ]; then
    echo "[ERROR] --usage applies to AI model and dataset scans only (use it with --model or --model-file)."; exit 1
fi

if [ "$VERIFY_WEIGHTS" = "true" ] && [ "$MODE" != "AIBOM" ]; then
    echo "[ERROR] --verify-weights applies to AI model scans only (use it with --model)."; exit 1
fi

# --resolve-purl is a submitted-SBOM question. The identifiers in an SBOM this
# tool generates come from the package manager, so a repository lookup has
# nothing to catch there; saying so beats letting the flag look like it took
# effect. A warning rather than an error, so a shared command line that carries
# the flag still runs.
if [ "$PURL_RESOLVE" = "true" ] && [ "$MODE" != "ANALYZE" ]; then
    echo "[WARN] --resolve-purl applies to --analyze only; ignoring it for this scan."
    PURL_RESOLVE="false"
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

# An AI model has no package dependencies, so Trivy has nothing to match and the
# report comes back empty. The web UI already forces the toggle off for an
# AI-model scan (useScanForm.ts) and both guides state the CLI skips it too —
# only the CLI still ran it, shipping an empty _security.{json,md,html}. This
# has to sit after the risk-report defaults above, which turn security on for
# every mode; the risk report still renders from the notice, as it does in the
# UI. Announce the skip only when the user actually asked (--security / --all),
# so an ordinary --model run stays quiet instead of explaining a default.
if [ "$MODE" = "AIBOM" ] || [ "$MODE" = "MODELFILE" ] || [ "$MODE" = "DATASET" ]; then
    for fo in "${FAIL_ON[@]:-}"; do
        case "$fo" in
            vulnerability=*)
                echo "[ERROR] --fail-on $fo is not available for AI model and dataset inputs: they have no package dependencies to scan, so no security report is produced."
                echo "[ERROR] Use --fail-on malicious-package or --fail-on license-conflict for these."; exit 1 ;;
            empty-result)
                echo "[ERROR] --fail-on empty-result is not available for AI model and dataset inputs: they are not judged by how many dependencies they list."
                echo "[ERROR] Use --fail-on malicious-package, --fail-on license-conflict or --fail-on license-coverage=<pct> for these."; exit 1 ;;
        esac
    done
fi
if { [ "$MODE" = "AIBOM" ] || [ "$MODE" = "MODELFILE" ] || [ "$MODE" = "DATASET" ]; } && [ "$GENERATE_SECURITY" = "true" ]; then
    [ "$SECURITY_REQUESTED" = "true" ] && \
        echo "[INFO] Skipping the security report: this input has no package dependencies to scan."
    GENERATE_SECURITY="false"
fi

# ---------------------------------------------------------------------------
# Provenance sidecar (.scanmeta.json)
#
# The web UI writes this file when it launches a scan (write_scanmeta in
# docker/web/server.py) so the result page can say what was scanned. A CLI scan
# produced no such record, so re-opening one in the UI showed counts with no
# indication of where they came from. Write the same file, with the same field
# names, so one reader serves both.
#
# Only the fields the result page reads are filled: the feature toggles belong
# to the UI's "re-scan with the same settings", which cannot replay a CLI run.
# ---------------------------------------------------------------------------
json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

case "$MODE" in
    AIBOM)    META_SOURCE="ai-model";        META_TARGET="$MODEL";  META_LABEL="" ;;
    MODELFILE) META_SOURCE="model-upload";   META_TARGET="";        META_LABEL="$(basename "$MODEL_FILE")" ;;
    ANALYZE)
        # Two inputs reach ANALYZE: an SBOM the user handed us, and a Yocto build
        # directory whose SBOM we found. Record which, so the result page says
        # "Yocto build" over the folder rather than naming a file nobody picked.
        if [ -n "$YOCTO_BUILD_DIR" ]; then
            META_SOURCE="yocto-build-dir"; META_TARGET=""; META_LABEL="$YOCTO_BUILD_DIR"
        else
            META_SOURCE="sbom-upload";     META_TARGET=""; META_LABEL="$(basename "$ANALYZE_SBOM")"
        fi
        ;;
    IMAGE)    META_SOURCE="docker-image";    META_TARGET="$TARGET"; META_LABEL="" ;;
    FIRMWARE) META_SOURCE="firmware-upload"; META_TARGET=""; META_LABEL="$(basename "$TARGET")" ;;
    BINARY)   META_SOURCE="package-upload";  META_TARGET=""; META_LABEL="$(basename "$TARGET")" ;;
    ROOTFS)   META_SOURCE="rootfs-dir";      META_TARGET=""
              # An archive that turned out to hold a root filesystem is labelled
              # by the file the user handed us, not by the throwaway unpack dir.
              if [ -n "$INGEST_ARCHIVE" ]; then
                  META_SOURCE="rootfs-archive"; META_LABEL="$(basename "$INGEST_ARCHIVE")"
              else
                  META_LABEL="$TARGET"
              fi ;;
    MERGE)    META_SOURCE="";                META_TARGET=""; META_LABEL="" ;;
    *)
        # SOURCE covers four different inputs: a clone, an extracted archive,
        # a folder named directly with --target, and the current folder.
        # GIT_URL is what distinguishes the first.
        if [ -n "$GIT_URL" ]; then
            META_SOURCE="git-url";    META_TARGET="$GIT_URL"; META_LABEL=""
        elif [ -n "$TARGET" ] && [ -d "$TARGET" ]; then
            # A directory named directly (not an archive) that did not look like a
            # root filesystem — same shape as the web UI's folder-picker "deep
            # source scan" input, so it reuses that source value rather than the
            # file-oriented "zip-upload".
            META_SOURCE="scan-target-src"; META_TARGET=""; META_LABEL="$TARGET"
        elif [ -n "$TARGET" ]; then
            META_SOURCE="zip-upload"; META_TARGET=""; META_LABEL="$(basename "$TARGET")"
        else
            META_SOURCE="current-dir"; META_TARGET=""; META_LABEL="$(pwd)"
        fi
        ;;
esac

if [ -n "$META_SOURCE" ]; then
    printf '{"source":"%s","target":"%s","sourceLabel":"%s","project":"%s","version":"%s"}\n' \
        "$(json_escape "$META_SOURCE")" "$(json_escape "$META_TARGET")" \
        "$(json_escape "$META_LABEL")" "$(json_escape "$PROJECT_NAME")" \
        "$(json_escape "$PROJECT_VERSION")" \
        > "$OUTPUT_HOST_DIR/.scanmeta.json" 2>/dev/null || true
fi

echo "=========================================="
echo "  SBOM Analysis — Mode: $MODE — $PROJECT_NAME ($PROJECT_VERSION)"
[ -n "$TARGET" ] && echo "  Target: $TARGET"
[ -n "$GIT_URL" ] && echo "  Git:    $GIT_URL${GIT_REF:+ (ref: $GIT_REF)}"
echo "=========================================="

# A "current folder" scan (no --output-dir) lands OUTPUT_HOST_DIR inside
# SCAN_INPUT_DIR itself (the base for outputs defaults to the directory being
# scanned, see "Where outputs go" in cli.md), so this run's own output
# subfolder is a real child of the tree /src mounts in SOURCE mode. Detected
# here as a plain host-side path check (both are already resolved absolute
# paths), and passed to the container so source-file-tree.sh can leave that
# one subfolder out, instead of listing the scan's own output as part of what
# it scanned. RUN_NAME (not OUT_PREFIX) is the actual folder name on disk: it
# alone carries the --timestamp suffix.
SRC_TREE_EXCLUDE=""
case "$OUTPUT_HOST_DIR" in
    "$SCAN_INPUT_DIR"/*) SRC_TREE_EXCLUDE="$RUN_NAME" ;;
esac

# ========================================================
# Stage 1: produce SBOM
# ========================================================
if [ "$MODE" = "SOURCE" ]; then
    # SCAN_INPUT_DIR = the tree we scan (current dir, or a cloned/extracted temp
    # dir). Artifacts go to OUTPUT_HOST_DIR (the per-run subfolder), which is kept
    # separate from the scanned tree, even for --git/zip ingestion.
    [ -n "$(ls -A "$SCAN_INPUT_DIR" 2>/dev/null)" ] || { echo "[ERROR] source directory is empty: $SCAN_INPUT_DIR"; exit 1; }
    LANG_DET=$(detect_lang "$SCAN_INPUT_DIR")
    warn_low_engine_memory_for "$LANG_DET" "$SCAN_INPUT_DIR"
    if [ "$LANG_DET" = "android" ]; then
        API=$(android_api "$SCAN_INPUT_DIR")
        CDX_IMG="${ANDROID_IMAGE_PREFIX}${API}:latest"
        echo "[INFO] Android source detected (compileSdk=$API) -> $CDX_IMG"
        # The image carries an Android SDK platform, which is not open source:
        # Google's SDK terms bar redistributing it, so we do not publish this
        # image and it is built where it is used. Tell the user how rather than
        # letting `docker run` fail on a missing image.
        if ! docker image inspect "$CDX_IMG" >/dev/null 2>&1 \
           && ! docker pull -q "$CDX_IMG" >/dev/null 2>&1; then
            echo "[ERROR] Android SDK image not found: $CDX_IMG"
            echo "        It is not published: the Android SDK inside it is not open source,"
            echo "        and its terms do not allow us to redistribute it. Build it once:"
            echo ""
            echo "          docker build --build-arg ANDROID_API=$API \\"
            echo "            -t $CDX_IMG $REPO_DIR/docker/android"
            echo ""
            echo "        Building it means accepting Google's SDK terms yourself:"
            echo "        https://developer.android.com/studio/terms"
            echo "        To use an image built elsewhere, set ANDROID_IMAGE_PREFIX."
            exit 1
        fi
    else
        CDX_IMG=$(img_for_lang "$LANG_DET")
        echo "[INFO] Language: $LANG_DET -> $CDX_IMG"
        if [ "$LANG_DET" = "swift" ]; then
            echo "[INFO] iOS/Swift: SPM (Package.resolved) and CocoaPods (Podfile.lock) are read from the committed lockfiles; commit them for a complete result."
            echo "[WARN]   UIKit platform and Xcode-driven dependencies require macOS and are NOT resolved in this Linux container."
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
    [ -d "$HOME/.gradle" ] && CACHE_MOUNTS="$CACHE_MOUNTS -v \"$(hostpath "$HOME/.gradle")\":/root/.gradle"
    [ -d "$HOME/.m2" ] && CACHE_MOUNTS="$CACHE_MOUNTS -v \"$(hostpath "$HOME/.m2")\":/root/.m2"
    # HOME=/tmp/sbomhome: writable for both root and non-root (cyclonedx) images,
    # so maven/cargo/etc. caches resolve regardless of the base image's user.
    # -u 0:0: the all-in-one fallback image runs as a non-root user and could not
    # write the host-owned /app on Linux (EACCES). Per-language images are already
    # root (no-op); the resulting bom is chown'd back to the host user in stage 2.
    # GOTOOLCHAIN goes through eval below, so only a Go toolchain name is passed on.
    HOST_GOTOOLCHAIN="${GOTOOLCHAIN:-}"
    case "$HOST_GOTOOLCHAIN" in
        *[!A-Za-z0-9.+_-]*)
            echo "[WARN] Ignoring GOTOOLCHAIN: not a Go toolchain name (e.g. auto, local, go1.26.0)."
            HOST_GOTOOLCHAIN="" ;;
    esac
    # Names only (see build_prep_env_args), so this is safe inside the eval.
    PREP_ENV_ARGS=$(build_prep_env_args)
    # Run in the background and wait explicitly, instead of foreground, so a
    # Ctrl+C or `kill` is handled the moment it arrives: a shell only acts on a
    # trap once it regains control, and while blocked on a foreground command
    # that does not happen until the command finishes on its own (measured).
    # `wait` returns as soon as the signal arrives, letting
    # cleanup() (which reads RUNNING_CONTAINER_NAME) stop the container right
    # away instead of leaving it to run unsupervised.
    #
    # build-prep.sh runs as "sh /tmp/build-prep.sh ARGS", not the previous
    # "sh -c 'sh /tmp/build-prep.sh ARGS'": the extra -c layer made
    # build-prep.sh a CHILD of the container's PID 1 instead of PID 1 itself.
    # A container's PID 1 only gets a signal's default action when it has
    # installed its own handler for that signal (standard Linux PID 1
    # behavior) — the wrapper sh had none, so `docker stop`'s SIGTERM was
    # silently dropped and build-prep.sh's own trap never ran, regardless of
    # grace (measured: a 30s grace still ended in a forced SIGKILL every
    # time). Invoking the script file directly makes it PID 1, so its trap is
    # what the SIGTERM actually reaches.
    # $$ alone can collide: two scans (CLI + web UI, or parallel CI jobs) on
    # the same host can land on the same PID space at different times, or a
    # container from an earlier crashed run can still be named this if it was
    # never cleaned up.
    RUNNING_CONTAINER_NAME="bomlens-scan-$$-$RANDOM"
    setup_guard_state
    GUARD_STATE_ARGS=""
    if [ -n "$GUARD_ID" ]; then
        GUARD_STATE_ARGS="-v \"$(hostpath "$GUARD_STATE_DIR")\":/bomlens-state -e BOMLENS_GUARD_ID=\"$GUARD_ID\""
    fi
    # Captured to a log file, not streamed to the terminal: cdxgen's own
    # output is its business, not BomLens's, and a crash prints a raw Node
    # stack trace there -- the terminal gets this progress line and, on
    # failure, a short cause; the file is what a fallback below classifies
    # (oom/disk-space/network, the same grep the web UI already does) and
    # what the failure message below points a reader at for the rest.
    # No --rm: an OOM check needs to inspect the container after it exits,
    # before it is gone, and the exit code itself comes from `docker wait`,
    # not the backgrounded command's own status.
    STAGE1_LOG=$(mktemp)
    echo "      (log: $STAGE1_LOG)"
    STAGE1_CONTAINER="$RUNNING_CONTAINER_NAME"
    eval "$DOCKER_MSYS"docker run -u 0:0 \
        --name "\"$RUNNING_CONTAINER_NAME\"" \
        --label bomlens.scan=cli \
        -v "\"$(hostpath "$SCAN_INPUT_DIR")\"":/app \
        -v "\"$(hostpath "$OUTPUT_HOST_DIR")\"":/out \
        -v "\"$(hostpath "$BUILD_PREP")\"":/tmp/build-prep.sh:ro \
        -v "\"$(hostpath "$IDENTIFY_CONDA")\"":/tmp/identify-conda.py:ro \
        $CACHE_MOUNTS \
        $GUARD_STATE_ARGS \
        -e HOME=/tmp/sbomhome \
        -e MAVEN_OPTS=-Dmaven.repo.local=/tmp/sbomhome/.m2 \
        -e FETCH_LICENSE="$FETCH_LICENSE" \
        -e PROJECT_NAME="\"$PROJECT_NAME\"" \
        -e PROJECT_VERSION="\"$PROJECT_VERSION\"" \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        -e HOST_GOTOOLCHAIN="\"$HOST_GOTOOLCHAIN\"" -e GOPROXY -e GOSUMDB \
        $PREP_ENV_ARGS \
        --entrypoint sh "\"$CDX_IMG\"" \
        /tmp/build-prep.sh /app "\"/out/$OUTPUT_FILE\"" "$CDX_SPEC_VERSION" > "$STAGE1_LOG" 2>&1 &
    STAGE1_PID=$!
    # || true: this script runs under `set -e`, and without the pipe through
    # `tee` this build used to have, $STAGE1_PID is the docker run itself, so
    # `wait` now returns ITS exit code -- a crash would trip `set -e` right
    # here, aborting the script before any of the failure handling below
    # runs. The real exit code comes from `docker wait` next regardless.
    wait "$STAGE1_PID" || true
    RUNNING_CONTAINER_NAME=""
    STAGE1_RC=$("${DOCKER_ENV[@]}" docker wait "$STAGE1_CONTAINER" 2>/dev/null || echo 1)
    if [ "$STAGE1_RC" -ne 0 ] || [ ! -f "$OUTPUT_HOST_DIR/$OUTPUT_FILE" ]; then
        if [ "$("${DOCKER_ENV[@]}" docker inspect -f '{{.State.OOMKilled}}' "$STAGE1_CONTAINER" 2>/dev/null)" = "true" ]; then
            STAGE1_FAIL_REASON="oom"
            echo "[WARN] cdxgen was killed for running out of memory (rc=$STAGE1_RC). Give the Docker engine more memory and re-scan for full transitive dependencies. Full cdxgen log: $STAGE1_LOG"
        elif grep -qi "no space left on device" "$STAGE1_LOG"; then
            STAGE1_FAIL_REASON="disk-space"
            echo "[WARN] cdxgen failed: Docker is out of disk space (rc=$STAGE1_RC). Free space (e.g. 'docker system prune'). Full cdxgen log: $STAGE1_LOG"
        elif grep -qEi "temporary failure in name resolution|could not resolve host|network is unreachable|connection timed out|connect timed out|no route to host|ENOTFOUND|ETIMEDOUT" "$STAGE1_LOG"; then
            STAGE1_FAIL_REASON="network"
            echo "[WARN] cdxgen couldn't reach the network while resolving dependencies (rc=$STAGE1_RC). Check proxy/firewall access to the package registries. Full cdxgen log: $STAGE1_LOG"
        else
            STAGE1_FAIL_REASON="cdxgen-crash"
            echo "[WARN] cdxgen failed processing the dependency data (rc=$STAGE1_RC); see $STAGE1_LOG for the full log. Falling back to a manifest-only scan (direct dependencies only)."
        fi
        "${DOCKER_ENV[@]}" docker rm -f "$STAGE1_CONTAINER" >/dev/null 2>&1
        rm -f "$OUTPUT_HOST_DIR/$OUTPUT_FILE"
        ensure_image_fresh "$POSTPROCESS_IMAGE"
        # A bind-mounted script file (matching build-prep.sh's own pattern),
        # not a `-c` string built by host-side interpolation: the same
        # MSYS_NO_PATHCONV mount-path rewriting that protects every other
        # docker call in this script would otherwise also mangle a `-c`
        # argument that happens to contain "/"-separated words on Windows
        # Git Bash. Written under SCRATCH_DIR, not OUTPUT_HOST_DIR: that is
        # the user's own output folder, and a script left behind there (a
        # crash between writing it and the rm below) would linger among the
        # scan's real artifacts. Not the system tmpdir either: a Linux VM
        # Docker backend (Colima, some Docker Desktop setups) mounts only
        # specific host paths into itself, and silently substitutes an empty
        # directory for a source it cannot see.
        mkdir -p "$SCRATCH_DIR" 2>/dev/null
        STAGE1_FALLBACK_SCRIPT="$SCRATCH_DIR/.fallback-$$-$RANDOM.sh"
        cat > "$STAGE1_FALLBACK_SCRIPT" <<'FALLBACK_SH'
set -e
. /usr/local/lib/sbom/source-detect.sh
read -ra SYFT_EXCLUDE <<< "$(non_shipped_syft_args)"
syft "dir:/src" "${SYFT_EXCLUDE[@]}" -o "cyclonedx-json@$1" > "/out/$2" 2>/dev/null
apply_node_fallback_quality_gate "/out/$2" /src 2 || { echo "[ERROR] fallback SBOM discarded (see above)." >&2; exit 1; }
mark_sbom_degraded "/out/$2" "$3"
mark_sbom_excluded "/out/$2" /src
FALLBACK_SH
        if ! eval "$DOCKER_MSYS"docker run --rm --label bomlens.scan=cli --entrypoint bash \
            -v "\"$(hostpath "$SCAN_INPUT_DIR")\"":/src:ro \
            -v "\"$(hostpath "$OUTPUT_HOST_DIR")\"":/out \
            -v "\"$(hostpath "$STAGE1_FALLBACK_SCRIPT")\"":/tmp/fallback.sh:ro \
            "\"$POSTPROCESS_IMAGE\"" \
            /tmp/fallback.sh "$CDX_SPEC_VERSION" "$OUTPUT_FILE" "$STAGE1_FAIL_REASON"; then
            rm -f "$STAGE1_FALLBACK_SCRIPT"; STAGE1_FALLBACK_SCRIPT=""
            echo "[ERROR] SBOM generation failed (stage 1), and the manifest-only fallback also failed or was discarded (see the guidance above, if any). Full cdxgen log: $STAGE1_LOG"
            exit 1
        fi
        rm -f "$STAGE1_FALLBACK_SCRIPT"; STAGE1_FALLBACK_SCRIPT=""
        echo "[WARN] Manifest-only fallback used (direct dependencies only, no transitive resolution). Full cdxgen log: $STAGE1_LOG"
    else
        "${DOCKER_ENV[@]}" docker rm -f "$STAGE1_CONTAINER" >/dev/null 2>&1
        rm -f "$STAGE1_LOG"
    fi

    echo "[2/2] Post-processing..."
    # Mount the scanned tree as /src (so deep-license/vendored see the real source)
    # and the run folder as /host-output. -w /host-output makes the bom written by
    # stage 1 the cwd, so POSTPROCESS finds it and writes the bundle in place — the
    # scanned tree (/src) is never written to.
    # pp_env/cosign_run intentionally expand to several -e KEY=VAL tokens, so the
    # word splitting SC2046 flags here is required, not a bug.
    ensure_image_fresh "$POSTPROCESS_IMAGE"
    export_scan_secrets
    # shellcheck disable=SC2046
    eval "$DOCKER_MSYS"docker run --rm \
        -v "\"$(hostpath "$SCAN_INPUT_DIR")\"":/src -v "\"$(hostpath "$OUTPUT_HOST_DIR")\"":/host-output \
        -w /host-output \
        --add-host=host.docker.internal:host-gateway \
        -e MODE=POSTPROCESS -e BOMLENS_RUN_INPUT="$OUTPUT_FILE" -e NESTED_ROOTFS_HINT="\"$NESTED_ROOTFS_HINT\"" $(pp_env)$(cosign_run)$(vex_run)$(gate_run) \
        "\"$POSTPROCESS_IMAGE\""
else
    # image / binary / rootfs / firmware / aibom / analyze / merge: scanner image
    # runs the generation step + common pipeline in one shot. Firmware and aibom
    # need their heavier opt-in images; others use the base image.
    VOL=""; ENVV=""; RUN_IMAGE="$POSTPROCESS_IMAGE"
    case "$MODE" in
        IMAGE)  VOL="-v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output -v /var/run/docker.sock:/var/run/docker.sock"; ENVV="-e TARGET_IMAGE=\"$TARGET\"" ;;
        BINARY) FD="$(cd "$(dirname "$TARGET")" && pwd)"; FN="$(basename "$TARGET")"; VOL="-v \"$(hostpath "$FD")\":/target -v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output"; ENVV="-e TARGET_FILE=\"/target/$FN\"" ;;
        ROOTFS) TD="$(cd "$TARGET" && pwd)"; VOL="-v \"$(hostpath "$TD")\":/target -v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output"; ENVV="-e TARGET_DIR=/target" ;;
        FIRMWARE) FD="$(cd "$(dirname "$TARGET")" && pwd)"; FN="$(basename "$TARGET")"; VOL="-v \"$(hostpath "$FD")\":/target -v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output"; ENVV="-e TARGET_FILE=\"/target/$FN\""; RUN_IMAGE="$FIRMWARE_IMAGE" ;;
        MODELFILE)
            # Read-only: the model file is only ever read, and a weight file the
            # user handed us must come back untouched.
            FD="$(cd "$(dirname "$MODEL_FILE")" && pwd)"; FN="$(basename "$MODEL_FILE")"
            VOL="-v \"$(hostpath "$FD")\":/target:ro -v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output"
            ENVV="-e TARGET_FILE=\"/target/$FN\"" ;;
        AIBOM)  VOL="-v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output"; ENVV="-e MODEL_ID=\"$MODEL\""
                # Name only, no value: this line is built for `eval`, so an inline
                # value would expose the token in `ps`. docker reads it from our
                # own environment instead. AIBOM only — no other mode needs it.
                [ -n "$HF_TOKEN" ] && ENVV="$ENVV -e HF_TOKEN"
                RUN_IMAGE="$AIBOM_IMAGE" ;;
        # Base image: reading a Figshare item is one stdlib Python script and one
        # public API call, so this needs neither the generator image nor an account.
        DATASET) VOL="-v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output"; ENVV="-e DATASET_REF=\"$MODEL\"" ;;
        ANALYZE)
            if [ -z "$ANALYZE_SBOM" ]; then
                # A Yocto build directory with no SPDX document: the build tree is
                # what has to be readable, since the manifests and the cve-check
                # report are spread across it. Read-only — nothing is written back.
                VOL="-v \"$(hostpath "$YOCTO_BUILD_DIR")\":/input:ro -v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output"
                ENVV="-e YOCTO_BUILD_DIR=/input"
            else
                FD="$(cd "$(dirname "$ANALYZE_SBOM")" && pwd)"; FN="$(basename "$ANALYZE_SBOM")"
                VOL="-v \"$(hostpath "$FD")\":/input:ro -v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output"
                ENVV="-e ANALYZE_SBOM=\"/input/$FN\""
            fi ;;
        MERGE)
            # Mount each input's directory read-only under its own index so files
            # that share a basename (three layers all named *_bom.json) don't
            # collide. MERGE_FILES carries the container-side paths.
            VOL="-v \"$(hostpath "$OUTPUT_HOST_DIR")\":/host-output"; MF_CONTAINER=""; i=0
            ROOT_ENV=""
            MR_RESOLVED=""
            [ -n "$MERGE_ROOT" ] && MR_RESOLVED="$(cd "$(dirname "$MERGE_ROOT")" && pwd)/$(basename "$MERGE_ROOT")"
            for mf in "${MERGE_FILES[@]}"; do
                FD="$(cd "$(dirname "$mf")" && pwd)"; FN="$(basename "$mf")"
                VOL="$VOL -v \"$(hostpath "$FD")\":/merge-in-$i:ro"
                MF_CONTAINER="$MF_CONTAINER /merge-in-$i/$FN"
                # --merge-root: point merge-sbom.sh at this input's container path.
                [ -n "$MR_RESOLVED" ] && [ "$FD/$FN" = "$MR_RESOLVED" ] && ROOT_ENV=" -e MERGE_ROOT_FROM=\"/merge-in-$i/$FN\""
                i=$((i + 1))
            done
            ENVV="-e MERGE_FILES=\"${MF_CONTAINER# }\"$ROOT_ENV" ;;
    esac
    # --deep-cve: swap the base image for the grype-bundled one so the security
    # step can run grype's CPE matcher. Base-image modes only (FIRMWARE/AIBOM carry
    # their own tools and image). When SECURITY_NVD_VERIFY is on, pass NVD_API_KEY
    # by name only (value read from our env, so it never appears in `ps`), like the
    # AIBOM HF_TOKEN.
    if [ "$DEEP_CVE" = "true" ]; then
        if [ "$RUN_IMAGE" = "$POSTPROCESS_IMAGE" ]; then
            RUN_IMAGE="$DEEP_CVE_IMAGE"
            [ -n "$NVD_API_KEY" ] && ENVV="$ENVV -e NVD_API_KEY"
        else
            echo "[WARN] --deep-cve does not apply to the $MODE image; running without grype." >&2
        fi
    fi
    ensure_image_fresh "$RUN_IMAGE"
    # VOL/ENVV/pp_env/cosign_run intentionally expand to multiple tokens (-v, -e
    # pairs), so the word splitting SC2046 flags here is required, not a bug.
    # BOMLENS_ARTIFACT_CLEANUP=1 tells entrypoint.sh it is safe to sweep
    # known-suffix leftovers of an earlier scan of the same project/version:
    # this single-container run generates its whole output in one shot, so
    # there is no stage-1 handoff the sweep could mistake for stale output.
    export_scan_secrets
    # shellcheck disable=SC2046
    eval "$DOCKER_MSYS"docker run --rm $VOL \
        --add-host=host.docker.internal:host-gateway \
        -e MODE="$MODE" -e BOMLENS_ARTIFACT_CLEANUP=1 $ENVV $(pp_env)$(cosign_run)$(vex_run)$(gate_run) \
        "\"$RUN_IMAGE\""
fi

# Verify artifacts actually reached the host. When the run folder is outside
# Docker Desktop file sharing (or Colima's home-only virtiofs mount), the
# container runs and reports success but the /host-output mount is silently
# empty, so nothing lands here. Every post-processing mode writes OUTPUT_FILE
# (_bom.json) to /host-output, so its absence means the mount never reached the
# host — catch that in ALL modes, not just --generate-only, instead of printing
# "Analysis Complete!" over a folder with no SBOM.
if [ ! -f "$OUTPUT_HOST_DIR/$OUTPUT_FILE" ]; then
    echo "[ERROR] SBOM not found on host: $OUTPUT_HOST_DIR/$OUTPUT_FILE"
    echo "  The container ran but no artifact reached this folder."
    echo "  Likely cause: this folder is outside Docker Desktop file sharing"
    echo "  (or Colima's home-only mount — /tmp is not shared to the VM)."
    echo "  Run from a shared path (e.g. under your home directory) and retry."
    exit 1
fi

# The summary must describe what is ON DISK, not what was requested: an older
# scanner image, or a step that degraded, leaves a requested artifact
# unproduced, and a summary driven by the request flags would announce a file
# the user does not have. Print a line only when its first file exists, and
# name anything requested but missing so the gap is visible rather than silent.
summary_line() {  # <label> <file> [more files…] — prints iff the first exists
    local label="$1"; shift
    [ -f "$OUTPUT_HOST_DIR/$1" ] || return 1
    local names=""
    for f in "$@"; do names="${names:+$names, }$f"; done
    printf '  %-12s %s\n' "$label" "$names"
}
missing=""
note_missing() { missing="${missing:+$missing }$1"; }

echo "=========================================="
echo "  Analysis Complete!"
if [ "$GENERATE_ONLY" = "true" ]; then
    P="${SAFE_PROJECT}_${SAFE_VERSION}"
    echo "  Output dir: ${OUTPUT_HOST_DIR}"
    echo "  SBOM: ${OUTPUT_FILE}"
    if [ "$GENERATE_NOTICE" = "true" ]; then
        summary_line "Notice:" "${P}_NOTICE.txt" "${P}_NOTICE.html" || note_missing "notice"
    fi
    if [ "$GENERATE_SECURITY" = "true" ]; then
        summary_line "Security:" "${P}_security.json" "${P}_security.md" "${P}_security.html" \
            || note_missing "security report"
    fi
    if [ -n "$VEX_FILE" ]; then
        summary_line "Supplier VEX:" "${P}_vex_imported.json" || note_missing "supplier VEX import"
    fi
    if [ "$GENERATE_SPDX" = "true" ]; then
        summary_line "SPDX:" "${P}_bom.spdx.json" || note_missing "SPDX export"
    fi
    # Conformance comes from both modes that can validate a BOM: ANALYZE (format
    # checks on a supplier SBOM) and AIBOM (the G7 minimum-element checklist).
    # It used to be announced for ANALYZE only, so an AI-model scan produced the
    # G7 report and never mentioned it.
    #
    # One ANALYZE case never produces it, though, and must not be announced
    # either: a Yocto build directory with no SPDX document, read from its own
    # manifests instead (entrypoint.sh's ANALYZE case, same YOCTO_BUILD_DIR +
    # empty ANALYZE_SBOM test). There is no submitted document to measure
    # conformance against there, so it is not a missing artifact: announcing it
    # anyway told a fully successful Yocto scan "requested but not produced:
    # conformance report" and pointed at `docker pull`/a log warning that never
    # existed.
    if { [ "$MODE" = "ANALYZE" ] && ! { [ -n "${YOCTO_BUILD_DIR:-}" ] && [ -z "$ANALYZE_SBOM" ]; }; } \
        || [ "$MODE" = "AIBOM" ] || [ "$MODE" = "DATASET" ]; then
        summary_line "Conformance:" "${P}_conformance.json" "${P}_conformance.md" "${P}_conformance.html" \
            || note_missing "conformance report"
    fi
    if [ "$GENERATE_REPORT" = "true" ]; then
        summary_line "Risk report:" "${P}_risk-report.md" "${P}_risk-report.html" \
            || note_missing "risk report"
    fi
    if [ -n "$missing" ]; then
        echo ""
        echo "[WARN] requested but not produced: ${missing}"
        echo "  The scan finished, but these artifacts are not in the output folder."
        echo "  If the scanner image predates the feature, refresh it:"
        echo "    docker pull ${RUN_IMAGE}"
        echo "  Otherwise the step degraded — check the log above for its warning."
    fi
fi
# What the result holds, in every mode: the numbers come from the scan's own
# measurement (validate-sbom.sh), not from a count made here. Absent (an older
# image, an AI SBOM) it prints nothing.
if [ -f "$SUMMARY_RESULT_FILE" ]; then
    sum_components=""; sum_licensed=""; sum_license_pct=""; sum_purl_pct=""; sum_reduced=""; sum_failed=""
    while IFS=$'\t' read -r sum_key sum_val; do
        case "$sum_key" in
            components)     sum_components="$sum_val" ;;
            licensed)       sum_licensed="$sum_val" ;;
            licensePercent) sum_license_pct="$sum_val" ;;
            purlPercent)    sum_purl_pct="$sum_val" ;;
            reduced)        sum_reduced="$sum_val" ;;
            failedSteps)    sum_failed="$sum_val" ;;
        esac
    done < "$SUMMARY_RESULT_FILE"
    case "$sum_components" in
        ''|*[!0-9]*) ;;
        *)
            if [ "$sum_components" -eq 0 ]; then
                printf '  %-12s %s\n' "Components:" "0 identified"
                echo "[WARN] No software was identified. Check that the scanned folder holds a manifest or lock file for a supported ecosystem, and read the log above."
            else
                sum_detail=""
                case "$sum_purl_pct" in ''|-|*[!0-9]*) ;; *) sum_detail="purl on ${sum_purl_pct}%" ;; esac
                case "$sum_license_pct" in
                    ''|-|*[!0-9]*) ;;
                    *) sum_detail="${sum_detail:+$sum_detail, }license declared on ${sum_license_pct}% (${sum_licensed:-0} of ${sum_components})" ;;
                esac
                printf '  %-12s %s\n' "Components:" "${sum_components} identified${sum_detail:+ ($sum_detail)}"
                [ "${sum_licensed:-0}" != "0" ] || echo "[WARN] No component declares a license, so license checks have nothing to work with. Read the log above."
            fi
            # Under --analyze these describe the submitted document's history, not
            # this run, so they are not reported.
            if [ "$MODE" != "ANALYZE" ]; then
                if [ -n "$sum_reduced" ]; then
                    case "$sum_reduced" in
                        disk-space)  sum_why="the scan ran out of disk space" ;;
                        oom)         sum_why="the build ran out of memory" ;;
                        network)     sum_why="a dependency download failed" ;;
                        cdxgen-crash) sum_why="the dependency analyzer failed" ;;
                        *)           sum_why="the dependency analyzer could not run" ;;
                    esac
                    echo "[WARN] Reduced analysis: ${sum_why}, so only direct dependencies were identified."
                fi
                [ -z "$sum_failed" ] || echo "[WARN] Steps that failed: ${sum_failed} (details in the log above)"
            fi
            ;;
    esac
fi
echo "=========================================="

# --fail-on: docker/lib/evaluate-gate.sh wrote one line per condition into
# <prefix>_gate.result (status, condition, detail; tab-separated), so the host
# needs no jq. Every condition is printed, then the exit code is decided: 4 when
# any condition is met, else 5 when any could not be judged from what this scan
# produced (a scan that could not look is not a scan that found nothing). It is
# applied after the conformance gate below, so 2 and 3 take precedence when
# --fail-on-conformance is also given, and the report files are on disk by now.
GATE_EXIT=0
if [ "${#FAIL_ON[@]}" -gt 0 ]; then
    if [ ! -f "$GATE_RESULT_FILE" ]; then
        echo "[ERROR] --fail-on: this scan produced no result to judge. If the scanner image predates the option, refresh it: docker pull ${RUN_IMAGE:-$POSTPROCESS_IMAGE}"
        GATE_EXIT=5
    else
        gate_lines=0
        while IFS=$'\t' read -r gate_status gate_cond gate_detail; do
            gate_lines=$((gate_lines + 1))
            case "$gate_status" in
                met)      echo "[ERROR] --fail-on ${gate_cond}: ${gate_detail}"; GATE_EXIT=4 ;;
                ok)       echo "[GATE] ${gate_cond}: ${gate_detail}" ;;
                *)        echo "[ERROR] --fail-on ${gate_cond} cannot be judged: ${gate_detail:-the result line is not understood}"
                          # An older image does not know a newer condition; say how to get one that does.
                          [ "$gate_detail" != "not a known condition" ] || echo "[ERROR] --fail-on ${gate_cond}: the scanner image predates this condition, refresh it: docker pull ${RUN_IMAGE:-$POSTPROCESS_IMAGE}"
                          [ "$GATE_EXIT" -eq 4 ] || GATE_EXIT=5 ;;
            esac
        done < "$GATE_RESULT_FILE"
        # One line per condition asked for. Fewer means the judgement was cut off,
        # and an incomplete result is not a pass.
        if [ "$gate_lines" -ne "${#FAIL_ON[@]}" ]; then
            echo "[ERROR] --fail-on: the result holds ${gate_lines} of ${#FAIL_ON[@]} conditions, so the judgement is incomplete."
            [ "$GATE_EXIT" -eq 4 ] || GATE_EXIT=5
        fi
        [ "$GATE_EXIT" -ne 0 ] || echo "[GATE] every --fail-on condition was judged and none is met."
    fi
fi

# --fail-on-conformance: judged last, after every artifact above is already on
# disk, so a failing report can still be opened and acted on. Reads the bare
# pass/fail sidecar validate-sbom.sh writes next to the JSON report (no jq
# dependency on the host). Distinct from a scan failure (exit 1 elsewhere in
# this script): 2 means the scan succeeded and its own conformance check
# failed, 3 means this run produced no conformance report to judge at all.
if [ "$FAIL_ON_CONFORMANCE" = "true" ]; then
    if [ ! -f "$CONFORMANCE_RESULT_FILE" ]; then
        echo "[ERROR] --fail-on-conformance: this scan produced no conformance report to judge."
        exit 3
    fi
    if [ "$(cat "$CONFORMANCE_RESULT_FILE")" = "fail" ]; then
        echo "[ERROR] Conformance check failed. See ${SAFE_PROJECT}_${SAFE_VERSION}_conformance.md / .html for details."
        exit 2
    fi
fi
[ "$GATE_EXIT" -eq 0 ] || exit "$GATE_EXIT"
