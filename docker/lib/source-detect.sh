#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# source-detect.sh — shared language detection + cdxgen image selection.
#
# Sourced by BOTH scripts/scan-sbom.sh (host CLI) and docker/entrypoint.sh
# (web UI source scan inside the scanner image). Keeping the logic here means
# the CLI and the UI pick the same cdxgen language image, so a source scan
# resolves transitive dependencies identically on both paths.
#
# Defaults use ${VAR:-default} so a caller that already exported these (the CLI)
# keeps its values; a caller that did not (the UI) gets the defaults.

CDXGEN_TAG="${CDXGEN_TAG:-v12}"                                  # cdxgen language image tag
CDXGEN_ALLINONE="${CDXGEN_ALLINONE:-ghcr.io/cyclonedx/cdxgen:v12.5.0}"
# Default to the sbom-scanner-android-sdk name: Android images publish only on
# release (not main pushes), so the featured bomlens-android-sdk images do not
# exist until the next release. The two names share the same digest; flip this
# default to bomlens-android-sdk once those images are published.
ANDROID_IMAGE_PREFIX="${ANDROID_IMAGE_PREFIX:-ghcr.io/sktelecom/sbom-scanner-android-sdk}"
ANDROID_API_DEFAULT="${ANDROID_API_DEFAULT:-34}"
# cdxgen does not resolve dependency licenses by default, leaving the SBOM (and
# the NOTICE derived from it) without license data. FETCH_LICENSE=true makes
# cdxgen look up each component's license. On by default; set FETCH_LICENSE=false
# to skip the extra network lookups for a faster, license-sparse scan.
FETCH_LICENSE="${FETCH_LICENSE:-true}"

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
