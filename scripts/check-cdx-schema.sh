#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# check-cdx-schema.sh — validate CycloneDX JSON documents against the official
# schema of the version each one declares, 1.6 or 1.7, with the CycloneDX CLI
# (pinned version, checksum-verified). A document that declares another version
# is checked against 1.7.
#
# Usage: check-cdx-schema.sh <sbom.json> [<sbom.json> ...]
#
# The CLI is taken from CYCLONEDX_CLI when set, otherwise `cyclonedx` on PATH,
# otherwise the pinned release is downloaded once into
# ${XDG_CACHE_HOME:-$HOME/.cache}/bomlens/ and its SHA-256 checked before use.
# Exit status: 0 when every document is valid, 1 when any is not, 2 when the
# CLI cannot be found or downloaded.
set -eu

CLI_VERSION="0.33.1"

if [ "$#" -eq 0 ]; then
    echo "usage: check-cdx-schema.sh <sbom.json> [<sbom.json> ...]" >&2
    exit 2
fi

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

asset_for_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$os/$arch" in
        Linux/x86_64)            echo "cyclonedx-linux-x64 bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746" ;;
        Linux/aarch64|Linux/arm64) echo "cyclonedx-linux-arm64 b2e9fdf9665ef49868a2ec012171c6e785dcd69745bc5869e53e4f4bfb096a5f" ;;
        Darwin/arm64)            echo "cyclonedx-osx-arm64 750c148780154833f6401f9067d08c5a4c31567b6ee3c26c062c3a95c62d741c" ;;
        Darwin/x86_64)           echo "cyclonedx-osx-x64 0ea92306fc7d7c30ed112a7463781a200585a3bf1cdaf77229181c5aabd1d4b6" ;;
        MINGW*/x86_64|MSYS*/x86_64|CYGWIN*/x86_64)
                                 echo "cyclonedx-win-x64.exe 9b360974c41a5d612eb026fb5e3bb1fa28e08865f7a4f915665b8bc94bd3bc31" ;;
        *) return 1 ;;
    esac
}

find_cli() {
    if [ -n "${CYCLONEDX_CLI:-}" ]; then
        echo "$CYCLONEDX_CLI"; return 0
    fi
    if command -v cyclonedx >/dev/null 2>&1; then
        command -v cyclonedx; return 0
    fi
    local spec asset want dir bin got
    if ! spec="$(asset_for_platform)"; then
        echo "[cdx-schema] no pinned CycloneDX CLI build for $(uname -s)/$(uname -m)." >&2
        echo "[cdx-schema]   Install it and set CYCLONEDX_CLI to its path." >&2
        return 1
    fi
    asset="${spec%% *}"; want="${spec##* }"
    dir="${XDG_CACHE_HOME:-$HOME/.cache}/bomlens/cyclonedx-cli-$CLI_VERSION"
    bin="$dir/$asset"
    if [ ! -x "$bin" ]; then
        mkdir -p "$dir"
        echo "[cdx-schema] downloading CycloneDX CLI $CLI_VERSION ($asset) ..." >&2
        if ! curl -fsSL -o "$bin.part" \
            "https://github.com/CycloneDX/cyclonedx-cli/releases/download/v$CLI_VERSION/$asset"; then
            rm -f "$bin.part"
            echo "[cdx-schema] download failed. Check network access to github.com, or set CYCLONEDX_CLI." >&2
            return 1
        fi
        got="$(sha256_of "$bin.part")"
        if [ "$got" != "$want" ]; then
            rm -f "$bin.part"
            echo "[cdx-schema] checksum mismatch for $asset (got $got). Refusing to run it." >&2
            return 1
        fi
        chmod +x "$bin.part"
        mv "$bin.part" "$bin"
    fi
    # Checked on every run, not only after the download: the cache is a
    # writable folder, and what runs must still be the pinned release.
    got="$(sha256_of "$bin")"
    if [ "$got" != "$want" ]; then
        echo "[cdx-schema] the cached $asset does not match the pinned checksum. Delete $dir and retry." >&2
        return 1
    fi
    echo "$bin"
}

if ! CLI="$(find_cli)"; then
    exit 2
fi

# The CLI is a .NET single-file build; without ICU on a minimal Linux image it
# refuses to start unless globalization runs invariant.
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1

status=0
for f in "$@"; do
    if [ ! -f "$f" ]; then
        echo "[cdx-schema] FAIL: $f (file not found)"
        status=1
        continue
    fi
    spec="$(jq -r '.specVersion // ""' "$f" 2>/dev/null || true)"
    case "$spec" in
        1.6) input_version=v1_6; label=1.6 ;;
        *)   input_version=v1_7; label=1.7 ;;
    esac
    if out="$("$CLI" validate --input-file "$f" --input-format json --input-version "$input_version" --fail-on-errors 2>&1)"; then
        echo "[cdx-schema] ok: $f ($label)"
    else
        echo "[cdx-schema] FAIL: $f"
        printf '%s\n' "$out" | sed 's/^/    /' | head -40
        status=1
    fi
done
exit "$status"
