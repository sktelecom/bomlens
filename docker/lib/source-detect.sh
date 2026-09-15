#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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

# renovate: datasource=docker depName=ghcr.io/cyclonedx/cdxgen
CDXGEN_TAG="${CDXGEN_TAG:-v12}"                                  # cdxgen language image tag
# renovate: datasource=docker depName=ghcr.io/cyclonedx/cdxgen
CDXGEN_ALLINONE="${CDXGEN_ALLINONE:-ghcr.io/cyclonedx/cdxgen:v12.5.0}"
# A local name, not a registry one: the Android SDK is not open source and its
# terms bar redistributing it, so this image is built on the machine that uses
# it rather than published. scan-sbom.sh prints the build command when it is
# missing. Point this at a registry to use an image built elsewhere, including
# the ones published before this changed (ghcr.io/sktelecom/bomlens-android-sdk).
ANDROID_IMAGE_PREFIX="${ANDROID_IMAGE_PREFIX:-bomlens-android-sdk}"
ANDROID_API_DEFAULT="${ANDROID_API_DEFAULT:-34}"
# cdxgen does not resolve dependency licenses by default, leaving the SBOM (and
# the NOTICE derived from it) without license data. FETCH_LICENSE=true makes
# cdxgen look up each component's license. On by default; set FETCH_LICENSE=false
# to skip the extra network lookups for a faster, license-sparse scan.
FETCH_LICENSE="${FETCH_LICENSE:-true}"

# Source-scan options that build-prep.sh reads. build-prep runs inside the cdxgen
# container, so every path that starts it (scan-sbom.sh stage 1, the web UI
# container, generate_sbom_cdxgen in entrypoint.sh) passes these on by name.
# docker skips a name-only -e whose variable is unset.
BUILD_PREP_ENV_NAMES="BOMLENS_KEEP_BUILD_OUTPUT BOMLENS_MAVEN_FULL_GRAPH BOMLENS_ANDROID_FULL_GRAPH BOMLENS_NODE_FULL_GRAPH BOMLENS_PHP_FULL_GRAPH BOMLENS_INCLUDE_NON_SHIPPED BOMLENS_PREP_TIMEOUT"

# Prints "-e NAME" for each name above. Names only, never values, so the output
# is safe to splice into the eval'd docker command in scan-sbom.sh.
build_prep_env_args() {
    local n out=""
    for n in $BUILD_PREP_ENV_NAMES; do out="$out -e $n"; done
    printf '%s' "${out# }"
}

# Folders whose manifests a source scan leaves out by default: test suites and
# their fixtures, examples, benchmarks and demo playgrounds. The GitHub Actions
# workflows under .github/workflows are left out too. None of it ships with the
# product. build-prep.sh runs alone in the cdxgen container and keeps its own
# copy of both lists; tests/test-postprocess.sh checks the copies stay equal.
# BOMLENS_INCLUDE_NON_SHIPPED=1 (or true) keeps everything.
NON_SHIPPED_DIRS="test tests spec fixtures testdata __tests__ e2e example examples benches benchmarks playground samples"
NON_SHIPPED_MANIFEST_RE='(^|/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile|Pipfile\.lock|setup\.py|setup\.cfg|environment\.ya?ml|pom\.xml|build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradle\.lockfile|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|Gemfile|Gemfile\.lock|[^/]+\.gemspec|composer\.json|composer\.lock|[^/]+\.(cs|fs|vb)proj|packages\.config|packages\.lock\.json|Directory\.Packages\.props|Package\.swift|Package\.resolved|Podfile|Podfile\.lock|conanfile\.txt|conanfile\.py|vcpkg\.json|METADATA|PKG-INFO)$'

# True unless BOMLENS_INCLUDE_NON_SHIPPED asks to keep the non-shipped trees.
non_shipped_enabled() {
    case "${BOMLENS_INCLUDE_NON_SHIPPED:-}" in 1|true) return 1 ;; esac
    return 0
}

# The glob patterns applied, relative to the scan root, joined with ", ".
non_shipped_globs() {
    local d out=""
    for d in $NON_SHIPPED_DIRS; do out="$out, **/$d/**"; done
    printf '%s' "${out#, }, **/.github/workflows/**"
}

# Prints $1 with every letter as a two-case character class ([tT]), so a glob
# matches the name in any letter case the way cdxgen's ignore list does.
non_shipped_any_case() {
    local s="$1" out="" c i
    for ((i = 0; i < ${#s}; i++)); do
        c="${s:i:1}"
        if [[ "$c" == [[:lower:]] ]]; then out="${out}[$c$(printf '%s' "$c" | tr '[:lower:]' '[:upper:]')]"; else out="$out$c"; fi
    done
    printf '%s' "$out"
}

# syft --exclude flags for the same patterns; empty when the option keeps them.
# syft's globs are case-sensitive, so the folder names go in as character
# classes. Read the output with `read -ra`, which does not expand the globs.
non_shipped_syft_args() {
    non_shipped_enabled || return 0
    local d out=""
    for d in $NON_SHIPPED_DIRS; do out="$out --exclude ./**/$(non_shipped_any_case "$d")/**"; done
    printf '%s' "${out# } --exclude ./**/.github/workflows/**"
}

# Manifest files under the non-shipped folders, and workflow files, relative to
# the scan root and sorted. Names match in any letter case, as in cdxgen.
non_shipped_manifests() {
    local root="$1" d re=""
    for d in $NON_SHIPPED_DIRS; do re="$re|$d"; done
    re="(^|/)(${re#|})/"
    (cd "$root" 2>/dev/null && find . \( -name node_modules -o -name .git \) -prune -o -type f -print 2>/dev/null) \
        | sed 's#^\./##' \
        | { grep -Ei "^\.github/workflows/[^/]+\.ya?ml$|$re" || true; } \
        | { grep -Ei "^\.github/workflows/|$NON_SHIPPED_MANIFEST_RE" || true; } \
        | LC_ALL=C sort
}

# Record the patterns and the manifest files left out, in the two properties
# build-prep.sh writes on the cdxgen path. The file list is capped at 50.
mark_sbom_excluded() {
    local file="$1" root="$2" list tmp
    [ -f "$file" ] || return 0
    non_shipped_enabled || return 0
    command -v jq >/dev/null 2>&1 || return 0
    list=$(non_shipped_manifests "$root")
    tmp="${file}.excluded.tmp"
    if jq --arg globs "$(non_shipped_globs)" --arg list "$list" '
        ($list | split("\n") | map(select(length > 0))) as $f
        | .metadata = (.metadata // {})
        | .metadata.properties = (((.metadata.properties // [])
              | map(select(.name != "bomlens:excluded-paths" and .name != "bomlens:excluded-manifests")))
            + [{name: "bomlens:excluded-paths", value: $globs}]
            + (if ($f | length) > 0
               then [{name: "bomlens:excluded-manifests",
                      value: (($f[0:50] | join(", "))
                              + (if ($f | length) > 50 then " (+\(($f | length) - 50) more)" else "" end))}]
               else [] end))' "$file" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
    fi
}

# Record that the SBOM came from the shallow syft fallback (direct deps only),
# with the reason, so the web UI can explain why the dependency graph is thin.
# Mirrors the other bomlens:* metadata signals the server reads (survives
# stamp/normalize like bomlens:suggest-identify-vendored does). Shared by
# entrypoint.sh (web UI) and, through the MODE=SOURCE-FALLBACK entrypoint.sh
# branch, scan-sbom.sh (CLI) -- both run this inside the scanner image, where
# jq is guaranteed, rather than depending on a host jq.
mark_sbom_degraded() {
    local file="$1" reason="$2" tmp
    [ -f "$file" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    tmp="${file}.degraded.tmp"
    if jq --arg r "$reason" \
        '(.metadata.properties) = ((.metadata.properties // []) + [{name:"bomlens:sbom-tool-degraded", value:$r}])' \
        "$file" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
    fi
}

# package.json files the syft fallback's quality gate reads: the root and, if
# it declares workspaces, each workspace member. npm/yarn workspaces come from
# package.json's own "workspaces" field (array, or "packages" under an
# object); pnpm's come from pnpm-workspace.yaml's "packages:" list. Globs are
# resolved with a plain shell glob, not full workspace semantics (no
# negation, no nested globstars) -- enough to tell "nothing declared" from
# "something declared", which is all the gate needs.
_node_workspace_package_jsons() {
    local root="$1" glob dir
    if [ -f "$root/pnpm-workspace.yaml" ]; then
        while IFS= read -r glob; do
            [ -n "$glob" ] || continue
            for dir in "$root"/$glob; do
                [ -f "$dir/package.json" ] && printf '%s\n' "$dir/package.json"
            done
        done <<EOF
$(sed -n "s/^[[:space:]]*-[[:space:]]*['\"]\\{0,1\\}\\([^'\"]*\\)['\"]\\{0,1\\}[[:space:]]*\$/\\1/p" "$root/pnpm-workspace.yaml")
EOF
    elif [ -f "$root/package.json" ] && command -v jq >/dev/null 2>&1; then
        while IFS= read -r glob; do
            [ -n "$glob" ] || continue
            for dir in "$root"/$glob; do
                [ -f "$dir/package.json" ] && printf '%s\n' "$dir/package.json"
            done
        done <<EOF
$(jq -r '.workspaces? | if type=="array" then .[] elif type=="object" then (.packages // [])[] else empty end' "$root/package.json" 2>/dev/null)
EOF
    fi
}

# Declared dependency names (dependencies + devDependencies, deduplicated)
# from the root package.json and every workspace member found above.
_node_declared_dep_names() {
    local root="$1" pkg names=""
    command -v jq >/dev/null 2>&1 || return 0
    for pkg in "$root/package.json" $(_node_workspace_package_jsons "$root"); do
        [ -f "$pkg" ] || continue
        names="$names
$(jq -r '((.dependencies // {}) + (.devDependencies // {})) | keys[]?' "$pkg" 2>/dev/null)"
    done
    printf '%s\n' "$names" | sed '/^$/d' | LC_ALL=C sort -u
}

# Node/npm quality gate for the syft fallback (direct deps only, no build):
# syft's pnpm-lock.yaml parsing can miss every real dependency and return only
# its own platform tooling -- a "successful" scan that in fact describes
# nothing about the project. If not one declared name (root or any workspace
# member) shows up in the fallback SBOM, the result is not usable.
# Returns 0 (fallback covers at least one declared name, keep it), 1 (covers
# none -- discard it), or 2 (no package.json/no declared names anywhere, or no
# jq -- the gate does not apply, accept the fallback as-is).
node_fallback_covers_declared_deps() {
    local root="$1" sbom="$2" names found
    command -v jq >/dev/null 2>&1 || return 2
    [ -f "$sbom" ] || return 2
    names=$(_node_declared_dep_names "$root")
    [ -n "$names" ] || return 2
    found=$(jq -r '[.components[]?.name] | unique | .[]?' "$sbom" 2>/dev/null)
    while IFS= read -r n; do
        [ -n "$n" ] || continue
        printf '%s\n' "$found" | grep -qxF "$n" && return 0
    done <<EOF
$names
EOF
    return 1
}

# Applies the gate above to a just-written syft-fallback SBOM: removes it and
# prints actionable guidance on the stream named by $3 (usually stderr) if it
# covers none of the declared dependencies, leaves it alone otherwise. $1 the
# SBOM file, $2 the scanned root. Returns 0 (kept) or 1 (discarded).
apply_node_fallback_quality_gate() {
    local file="$1" root="$2" stream="${3:-2}"
    node_fallback_covers_declared_deps "$root" "$file"
    case $? in
        1)
            rm -f "$file"
            {
                echo "[ERROR] The dependency resolver failed and the fallback scan found none of the project's declared dependencies (direct-deps-only manifest reading), so the result would misrepresent the scan as covering the dependency tree when it covers none of it."
                echo "        Commit a lockfile (package-lock.json, npm-shrinkwrap.json, yarn.lock or pnpm-lock.yaml) that matches package.json if one is missing, or run 'npm install'/'pnpm install' once so a resolvable lockfile is present, then re-scan."
                echo "        Or scan from an environment where cdxgen itself can run (Docker access for the web UI's source scan; a working docker.sock for the CLI's transitive resolution) instead of relying on this direct-deps-only fallback."
            } >&"$stream"
            return 1
            ;;
        *) return 0 ;;
    esac
}

# Prints the first file under $1, at most $2 levels deep, that matches the find
# tests after them. VCS data, installed dependencies and build output are not
# walked, nor are the non-shipped folders when NON_SHIPPED_DIRS is defined.
_detect_first() {
    local d="$1" depth="$2" n prune=()
    shift 2
    for n in .git node_modules vendor build target bin obj .build Pods .venv ${NON_SHIPPED_DIRS:-}; do
        prune+=(-o -name "$n")
    done
    (cd "$d" 2>/dev/null && find . -maxdepth "$depth" \( "${prune[@]:1}" \) -prune -o -type f \( "$@" \) -print -quit 2>/dev/null)
}

# True when $1 holds a Gradle settings or build script.
_detect_gradle_root() {
    local g
    for g in settings.gradle settings.gradle.kts build.gradle build.gradle.kts; do
        [ -f "$1/$g" ] && return 0
    done
    return 1
}

# True when $1/package.json declares devDependencies and no dependencies. Read
# without jq, which the host CLI does not require.
_detect_node_dev_only() {
    local flat
    [ -f "$1/package.json" ] || return 1
    flat=$(tr -d '\r\n' < "$1/package.json")
    case "$flat" in *'"devDependencies"'*) ;; *) return 1 ;; esac
    ! printf '%s' "$flat" | grep -qE '"dependencies"[[:space:]]*:[[:space:]]*\{[[:space:]]*"'
}

detect_lang() {
    local d="$1" langs=""
    # Android: a Gradle project (a settings or build script at the root) that
    # applies the Android plugin. The plugin shows up as its id in the version
    # catalog, as the id or a catalog alias in a build script, as the Groovy or
    # Kotlin DSL `namespace`, or through an AndroidManifest.xml (app/src/main is
    # four levels down). Without a Gradle root a manifest alone does not count: a
    # .NET MAUI app carries one under Platforms/Android.
    if _detect_gradle_root "$d" && {
           grep -qsE 'id *= *"com\.android\.(application|library)"' "$d/gradle/libs.versions.toml" \
        || grep -qsE "com\.android\.(application|library)|namespace *=? *['\"]|alias\(libs\.plugins\.android\.(application|library)\)" \
               "$d"/build.gradle "$d"/build.gradle.kts "$d"/app/build.gradle "$d"/app/build.gradle.kts \
        || [ -n "$(_detect_first "$d" 6 -name AndroidManifest.xml)" ]; }; then
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
    # setup.py/setup.cfg predate pyproject.toml and are still what a lot of
    # scientific Python ships: leaving them out made such a project detect as
    # "unknown", which sent it to the all-in-one image AND told the user no
    # manifest was found while the scan went on to resolve its dependencies.
    { [ -f "$d/requirements.txt" ] || [ -f "$d/pyproject.toml" ] \
      || [ -f "$d/setup.py" ] || [ -f "$d/setup.cfg" ] || [ -f "$d/Pipfile" ]; } && langs="$langs python"
    [ -f "$d/package.json" ] && langs="$langs node"
    [ -f "$d/composer.json" ] && langs="$langs php"
    { ls "$d"/*.csproj >/dev/null 2>&1 || ls "$d"/*.fsproj >/dev/null 2>&1 \
      || ls "$d"/*.sln >/dev/null 2>&1 || ls "$d"/*.slnx >/dev/null 2>&1; } && langs="$langs dotnet"
    # C/C++ with a package manager (Conan / vcpkg). cdxgen's all-in-one image
    # resolves these; raw CMake/Make C/C++ has no manifest and stays "unknown".
    { [ -f "$d/conanfile.txt" ] || [ -f "$d/conanfile.py" ] || [ -f "$d/vcpkg.json" ]; } && langs="$langs cpp"
    # .NET solutions usually keep their projects in subfolders (src/App/App.csproj).
    # A .NET project found there counts like one at the root. A package.json with
    # only devDependencies beside it is an e2e or tooling setup, not a Node.js
    # project, so it does not turn the tree into mixed.
    case "$langs " in
        *" dotnet "*) ;;
        *)
            [ -n "$(_detect_first "$d" 4 -name '*.csproj' -o -name '*.fsproj' -o -name '*.sln' -o -name '*.slnx')" ] \
                && langs="$langs dotnet" ;;
    esac
    case "$langs " in
        *" dotnet "*)
            case "$langs " in *" node "*) _detect_node_dev_only "$d" && langs="${langs/ node/}" ;; esac ;;
    esac
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
