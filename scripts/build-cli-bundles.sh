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

# build-cli-bundles.sh - packs and checks the CLI archives of a release
#
#   scripts/build-cli-bundles.sh build  <version> <output dir>
#   scripts/build-cli-bundles.sh verify <version> <output dir>
#
# build writes bomlens-cli-linux.tar.gz, the same file again as
# bomlens-cli.tar.gz (it runs on macOS too), and bomlens-cli-windows.zip into
# <output dir>. The files are copied to a staging folder first, and the copies
# get the release version: check-setup's @BOMLENS_VERSION@, and the default
# image tag of scan-sbom.sh, sbom-ui.bat and source-detect.sh (:latest in the
# repository) becomes <version>. An environment variable such as
# SBOM_SCANNER_IMAGE still wins over the default. The checkout is not changed.
#
# verify unpacks each archive into a clean folder and checks that it runs on
# its own: scan-sbom.sh --help, the license files, the paths the README's first
# commands use, and that every default image tag is <version>.
#
# release.yml runs both. Run them locally with any version, for example:
#   scripts/build-cli-bundles.sh build 9.9.9 /tmp/out && scripts/build-cli-bundles.sh verify 9.9.9 /tmp/out

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

usage() { echo "usage: $0 build|verify <version> <output dir>" >&2; exit 2; }
[ "$#" -eq 3 ] || usage
ACTION="$1"; VERSION="${2#v}"; OUT_DIR="$3"
case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) case "$VERSION" in *[!0-9A-Za-z.-]*) echo "invalid version: $2" >&2; exit 2 ;; esac ;;
    *) echo "invalid version: $2 (expected X.Y.Z or vX.Y.Z)" >&2; exit 2 ;;
esac

# Every bundle carries the same three license documents. Apache-2.0 section 4
# asks a redistributor for a copy of the License and the NOTICE contents, and
# whoever downloads a bundle becomes one; THIRD_PARTY_LICENSES.md travels with
# them because it is where the NOTICE points for the bundled tools and the GPL
# source offer.
LICENSE_FILES="LICENSE NOTICE THIRD_PARTY_LICENSES.md"

# The host-side lib files scan-sbom.sh needs: source-detect.sh and
# cdx-version.sh are both sourced unconditionally on the host (both under
# set -e), and build-prep.sh is mounted into the container for source scans.
# Paths are preserved so the scan-sbom(.bat) -> scan-sbom.sh ->
# REPO_DIR/docker/lib resolution works after extraction. Omitting either
# sourced file makes even `scan-sbom.sh --help` exit 1 before any scan.
# license-entry.sh and the SPDX id list it reads (cdx-spdx-ids.json) check
# --license before a scan starts; the check is skipped without them, and the
# container then checks it. docker/android/Dockerfile is the build recipe for
# the Android SDK image that Android source scans need. It carries no SDK
# files: the SDK is downloaded from Google by the user's own machine at build
# time.
LIB_FILES="docker/lib/source-detect.sh docker/lib/build-prep.sh docker/lib/cdx-version.sh docker/lib/license-entry.sh docker/lib/cdx-spdx-ids.json docker/lib/image-sizes.json docker/lib/identify-conda.py docker/lib/read-python-venv.py docker/android/Dockerfile"

# The Linux and macOS bundle: the scan script, the setup check the README runs
# first, and the example project the README's first scan points at.
LINUX_FILES="scripts/scan-sbom.sh scripts/check-setup.sh $LIB_FILES $LICENSE_FILES"

# The Windows bundle: both launchers, the orchestration script, and the
# host-side lib files above. sbom-ui.bat is self-contained (double-click web
# UI). check-setup.bat must ship too: the launchers' own error messages tell
# users to double-click it, and the settings example is how a non-CLI user
# reaches UI_PORT / SBOM_IMAGE_TAR (env vars die on a double-click).
WINDOWS_FILES="scripts/scan-sbom.sh scripts/scan-sbom.bat scripts/sbom-ui.bat scripts/check-setup.bat scripts/bomlens.settings.example.txt $LIB_FILES $LICENSE_FILES"

EXAMPLE_DIR="examples/nodejs"

# The files whose default image tag is :latest in the repository.
TAGGED_FILES="scripts/scan-sbom.sh scripts/sbom-ui.bat docker/lib/source-detect.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

# stage <dir> <files...>: copy the files, and the tracked files of the example,
# into <dir> with their paths and modes kept.
stage() {
    local dir="$1" f
    shift
    mkdir -p "$dir"
    for f in "$@" $(git -C "$REPO_DIR" ls-files "$EXAMPLE_DIR"); do
        [ -f "$REPO_DIR/$f" ] || fail "$f is not in the checkout"
        mkdir -p "$dir/$(dirname "$f")"
        cp -p "$REPO_DIR/$f" "$dir/$f"
    done
}

# stamp <dir>: write the release version into the staged copies. cat > keeps
# each file's mode.
stamp() {
    local dir="$1" f tmp
    tmp="$(mktemp)"
    for f in scripts/check-setup.sh scripts/check-setup.bat; do
        [ -f "$dir/$f" ] || continue
        sed "s/@BOMLENS_VERSION@/$VERSION/g" "$dir/$f" > "$tmp" && cat "$tmp" > "$dir/$f"
    done
    for f in $TAGGED_FILES; do
        [ -f "$dir/$f" ] || continue
        sed -e "s#ghcr\.io/sktelecom/bomlens:latest#ghcr.io/sktelecom/bomlens:$VERSION#g" \
            -e "s#ghcr\.io/sktelecom/bomlens-[$]{suffix}:latest#ghcr.io/sktelecom/bomlens-\${suffix}:$VERSION#g" \
            "$dir/$f" > "$tmp" && cat "$tmp" > "$dir/$f"
    done
    rm -f "$tmp"
}

build() {
    local work out
    mkdir -p "$OUT_DIR"
    out="$(cd "$OUT_DIR" && pwd)"
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    # No macOS extended-attribute entries (._*) in a tar made on a Mac.
    export COPYFILE_DISABLE=1

    # shellcheck disable=SC2086  # word splitting is how the file lists expand
    stage "$work/linux" $LINUX_FILES
    stamp "$work/linux"
    chmod +x "$work/linux/scripts/scan-sbom.sh" "$work/linux/scripts/check-setup.sh"
    # shellcheck disable=SC2086
    (cd "$work/linux" && tar -czf "$out/bomlens-cli-linux.tar.gz" $LINUX_FILES "$EXAMPLE_DIR")
    cp "$out/bomlens-cli-linux.tar.gz" "$out/bomlens-cli.tar.gz"

    # shellcheck disable=SC2086
    stage "$work/windows" $WINDOWS_FILES
    stamp "$work/windows"
    # CRLF so every Windows editor shows the lines apart.
    printf '%s\r\n' \
        "BomLens $VERSION command-line tools for Windows" \
        "Web UI: double-click scripts\\sbom-ui.bat (it opens http://localhost:8080)" \
        "Setup check: double-click scripts\\check-setup.bat if a scan does not start" \
        "Command line: scripts\\scan-sbom.bat --help (needs Git for Windows)" \
        "Documentation: https://sktelecom.github.io/bomlens/" \
        > "$work/windows/README.txt"
    rm -f "$out/bomlens-cli-windows.zip"
    # shellcheck disable=SC2086
    (cd "$work/windows" && zip -qr "$out/bomlens-cli-windows.zip" README.txt $WINDOWS_FILES "$EXAMPLE_DIR")

    rm -rf "$work"
    trap - EXIT
    echo "built bomlens-cli-linux.tar.gz, bomlens-cli.tar.gz and bomlens-cli-windows.zip ($VERSION) in $out"
}

# check_tags <archive> <dir>: every default image tag in the unpacked scripts
# is the release version, and an environment variable still overrides it.
check_tags() {
    local file="$1" dir="$2" f left got
    for f in $TAGGED_FILES; do
        [ -f "$dir/$f" ] || continue
        # shellcheck disable=SC2016  # ${suffix} is matched literally
        left="$(grep -nE 'ghcr\.io/sktelecom/(bomlens|sbom-[a-z]+)[-A-Za-z0-9_${}]*:latest' "$dir/$f" || true)"
        [ -z "$left" ] || fail "$file: $f still defaults to a :latest image: $left"
    done
    if [ -f "$dir/scripts/scan-sbom.sh" ]; then
        # The scanner image default and the opt-in images it derives, read
        # from the unpacked script itself and run with and without overrides.
        # shellcheck disable=SC2016  # expanded by the inner bash
        got="$(cd "$dir" && env -u SBOM_SCANNER_IMAGE bash -c '
            eval "$(grep -E "^POSTPROCESS_IMAGE=" scripts/scan-sbom.sh)"
            eval "$(awk "/^(_version_tag_before_1132|_scanner_image_parts|optin_image_ref)\\(\\) \\{/,/^}/" scripts/scan-sbom.sh)"
            printf "%s %s %s" "$POSTPROCESS_IMAGE" "$(optin_image_ref firmware)" "$(optin_image_ref deep-license)"
            SBOM_SCANNER_IMAGE=ghcr.io/example/bomlens:2.0.0
            eval "$(grep -E "^POSTPROCESS_IMAGE=" scripts/scan-sbom.sh)"
            printf " %s %s" "$POSTPROCESS_IMAGE" "$(optin_image_ref aibom)"')"
        [ "$got" = "ghcr.io/sktelecom/bomlens:$VERSION ghcr.io/sktelecom/bomlens-firmware:$VERSION ghcr.io/sktelecom/bomlens-deep-license:$VERSION ghcr.io/example/bomlens:2.0.0 ghcr.io/example/bomlens-aibom:2.0.0" ] \
            || fail "$file: scan-sbom.sh image defaults are not $VERSION or the override is lost: $got"
        grep -qF "\"\${SBOM_SCANNER_IMAGE:-ghcr.io/sktelecom/bomlens:$VERSION}\"" "$dir/docker/lib/source-detect.sh" \
            || fail "$file: source-detect.sh does not default to ghcr.io/sktelecom/bomlens:$VERSION"
    fi
    if [ -f "$dir/scripts/sbom-ui.bat" ]; then
        grep -qF "if not defined SBOM_SCANNER_IMAGE set \"SBOM_SCANNER_IMAGE=ghcr.io/sktelecom/bomlens:$VERSION\"" "$dir/scripts/sbom-ui.bat" \
            || fail "$file: sbom-ui.bat does not default to ghcr.io/sktelecom/bomlens:$VERSION"
    fi
    if [ -f "$dir/scripts/check-setup.sh" ]; then
        grep -qx "BOMLENS_CLI_VERSION=\"$VERSION\"" "$dir/scripts/check-setup.sh" || fail "$file: check-setup.sh does not carry $VERSION"
    fi
    if [ -f "$dir/scripts/check-setup.bat" ]; then
        grep -qF "set \"CLI_VERSION=$VERSION\"" "$dir/scripts/check-setup.bat" || fail "$file: check-setup.bat does not carry $VERSION"
    fi
}

verify() {
    local out pkg kind file dir name
    out="$(cd "$OUT_DIR" && pwd)"
    cmp -s "$out/bomlens-cli-linux.tar.gz" "$out/bomlens-cli.tar.gz" \
        || fail "bomlens-cli.tar.gz is not the same file as bomlens-cli-linux.tar.gz"
    for pkg in "tar:bomlens-cli-linux.tar.gz" "zip:bomlens-cli-windows.zip"; do
        kind="${pkg%%:*}"; file="${pkg#*:}"
        dir="$(mktemp -d)"
        case "$kind" in
            tar) tar -xzf "$out/$file" -C "$dir" ;;
            zip) unzip -q "$out/$file" -d "$dir" ;;
        esac
        # The CLI zip/tar must carry every host-side file scan-sbom.sh sources
        # or the extracted bundle dies before any scan (source-detect.sh was
        # missing once and no test caught it; it is not in the container).
        if ! bash "$dir/scripts/scan-sbom.sh" --help >/dev/null 2>"$dir/err"; then
            echo "FAIL: $file: extracted scan-sbom.sh --help exited non-zero:" >&2; cat "$dir/err" >&2; exit 1
        fi
        # The extracted bundle must also state its own terms. Checking the
        # unpacked tree (not the tar/zip argument list) is what catches a file
        # that was named but never actually packed.
        for name in LICENSE NOTICE THIRD_PARTY_LICENSES.md; do
            [ -s "$dir/$name" ] || fail "$file: extracted bundle has no $name"
        done
        # The paths the README's first commands and the zip's README.txt use.
        for name in scripts/scan-sbom.sh "$EXAMPLE_DIR/package.json" "$EXAMPLE_DIR/package-lock.json"; do
            [ -s "$dir/$name" ] || fail "$file: extracted bundle has no $name"
        done
        case "$kind" in
            tar)
                for name in scripts/scan-sbom.sh scripts/check-setup.sh; do
                    [ -x "$dir/$name" ] || fail "$file: $name is missing or not executable"
                done ;;
            zip)
                for name in README.txt scripts/sbom-ui.bat scripts/check-setup.bat scripts/scan-sbom.bat; do
                    [ -s "$dir/$name" ] || fail "$file: extracted bundle has no $name"
                done ;;
        esac
        check_tags "$file" "$dir"
        rm -rf "$dir"
        echo "OK: $file is self-sufficient, carries its license files and the example, and defaults to $VERSION images"
    done
}

case "$ACTION" in
    build) build ;;
    verify) verify ;;
    *) usage ;;
esac
