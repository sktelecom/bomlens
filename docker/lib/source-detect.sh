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

# Exact release tags, not the floating major tag: cdxgen rebuilds its v13
# images nightly from the main branch, so a "v13" pull can change the SBOM
# between two scans of the same tree (the 2026-10-05 build began listing every
# LICENSE file under node_modules/ as a component). Bump both together.
# renovate: datasource=docker depName=ghcr.io/cdxgen/cdxgen
CDXGEN_TAG="${CDXGEN_TAG:-13.3.0}"                               # cdxgen language image tag
# renovate: datasource=docker depName=ghcr.io/cdxgen/cdxgen
CDXGEN_ALLINONE="${CDXGEN_ALLINONE:-ghcr.io/cdxgen/cdxgen:13.3.0}"
# Where the cdxgen images are pulled from: everything before the image name.
# A registry mirror (a network with no route to ghcr.io) sets its own, for
# example registry.example/mirror/cdxgen/; the names, the tag and, in the
# execution plan, the digests stay the same.
CDXGEN_IMAGE_PREFIX="${CDXGEN_IMAGE_PREFIX:-ghcr.io/cdxgen/}"
case "$CDXGEN_IMAGE_PREFIX" in */) ;; *) CDXGEN_IMAGE_PREFIX="$CDXGEN_IMAGE_PREFIX/" ;; esac
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
# The proxy variables reach the package managers cdxgen runs; passed on with
# the options above.
PROXY_ENV_NAMES="HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy"
BUILD_PREP_ENV_NAMES="BOMLENS_KEEP_BUILD_OUTPUT BOMLENS_MAVEN_FULL_GRAPH BOMLENS_ANDROID_FULL_GRAPH BOMLENS_NODE_FULL_GRAPH BOMLENS_PHP_FULL_GRAPH BOMLENS_INCLUDE_NON_SHIPPED BOMLENS_INCLUDE_DEV_DEPENDENCIES BOMLENS_NO_COPYRIGHT BOMLENS_NO_CARGO_LICENSE BOMLENS_PREP_TIMEOUT"

# Settings for the network the post-processing container reaches: the proxy,
# where Trivy gets its vulnerability database (a mirror, or a cache with the
# update skipped) and the EPSS and KEV lookups (off, or a mirror). Passed on
# by name, so a value is never on a command line.
STAGE2_NETWORK_ENV_NAMES="$PROXY_ENV_NAMES TRIVY_DB_REPOSITORY TRIVY_JAVA_DB_REPOSITORY TRIVY_SKIP_DB_UPDATE TRIVY_SKIP_JAVA_DB_UPDATE TRIVY_OFFLINE_SCAN TRIVY_USERNAME TRIVY_PASSWORD TRIVY_REGISTRY_TOKEN TRIVY_INSECURE BOMLENS_TRIVY_DB_MAX_AGE_DAYS KEV_URL EPSS_API"

# Prints "-e NAME" for the names above and for any other TRIVY_* variable set
# here, except TRIVY_CACHE_DIR: a path on this host means nothing in the
# container (the CLI mounts a cache folder with SBOM_TRIVY_CACHE instead).
# Names only, safe inside the eval'd docker command.
stage2_network_env_args() {
    local n out=""
    for n in $(_passable_names $STAGE2_NETWORK_ENV_NAMES) $(compgen -e | grep '^TRIVY_' | grep -vx 'TRIVY_CACHE_DIR' || true); do
        case " $out " in *" -e $n "*) ;; *) out="$out -e $n" ;; esac
    done
    printf '%s' "${out# }"
}

# The names given, less a proxy set to this machine's own loopback address
# (a local authenticating proxy at 127.0.0.1 or localhost): inside a container
# that address is the container itself, so the proxy Docker sets up for its
# containers is left to apply instead.
_passable_names() {
    local n v
    for n in "$@"; do
        case "$n" in
            HTTP_PROXY|HTTPS_PROXY|http_proxy|https_proxy)
                v="${!n:-}"
                case "$v" in
                    *://127.*|127.*|*://localhost|*://localhost[:/]*|localhost|localhost[:/]*|*://\[::1\]*|\[::1\]*) continue ;;
                esac ;;
        esac
        printf '%s\n' "$n"
    done
}

# Prints "-e NAME" for each name above. Names only, never values, so the output
# is safe to splice into the eval'd docker command in scan-sbom.sh.
build_prep_env_args() {
    local n out=""
    for n in $BUILD_PREP_ENV_NAMES $(_passable_names $PROXY_ENV_NAMES); do out="$out -e $n"; done
    printf '%s' "${out# }"
}

# The SBOM_TRIVY_CACHE folder as "-v <host path>:/trivy-cache -e TRIVY_CACHE_DIR"
# arguments, one per line, or nothing when it is unset or cannot be made.
trivy_cache_args() {
    [ -n "${SBOM_TRIVY_CACHE:-}" ] || return 0
    if ! mkdir -p "$SBOM_TRIVY_CACHE" 2>/dev/null || [ ! -d "$SBOM_TRIVY_CACHE" ]; then
        echo "[WARN] SBOM_TRIVY_CACHE=$SBOM_TRIVY_CACHE is not a folder that can be created; Trivy keeps its database in the container." >&2
        return 0
    fi
    printf '%s\n' -v "$(cd "$SBOM_TRIVY_CACHE" && pwd):/trivy-cache" -e TRIVY_CACHE_DIR=/trivy-cache
}

# Folders whose manifests a source scan leaves out by default: test suites and
# their fixtures, examples, benchmarks and demo playgrounds. The GitHub Actions
# workflows under .github/workflows and the Gradle wrapper under gradle/wrapper
# (NON_SHIPPED_PATHS, at any depth) are left out too. None of it ships with the
# product. NON_SHIPPED_PATH_FILE_RE names the files under those paths that are
# recorded as left out. build-prep.sh runs alone in the cdxgen container and
# keeps its own copy of the lists; tests/test-postprocess.sh checks the copies
# stay equal.
# BOMLENS_INCLUDE_NON_SHIPPED=1 (or true) keeps everything.
NON_SHIPPED_DIRS="test tests spec fixtures testdata __tests__ e2e example examples sample samples bench benches benchmark benchmarks demo demos playground"
NON_SHIPPED_MANIFEST_RE='(^|/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile|Pipfile\.lock|setup\.py|setup\.cfg|environment\.ya?ml|pom\.xml|build\.gradle(\.kts)?|settings\.gradle(\.kts)?|gradle\.lockfile|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|Gemfile|Gemfile\.lock|[^/]+\.gemspec|composer\.json|composer\.lock|[^/]+\.(cs|fs|vb)proj|packages\.config|packages\.lock\.json|Directory\.Packages\.props|Package\.swift|Package\.resolved|Podfile|Podfile\.lock|conanfile\.txt|conanfile\.py|vcpkg\.json|METADATA|PKG-INFO)$'
NON_SHIPPED_PATHS=".github/workflows gradle/wrapper"
NON_SHIPPED_PATH_FILE_RE='(^|/)(\.github/workflows/[^/]+\.ya?ml|gradle/wrapper/[^/]+\.jar)$'

# Static detection: read the lock file instead of building.
#
# A complete lock file already records every package at its resolved version, so
# resolving the project again in a language image (a container start, an image
# pull on the first run, the package manager's own work) adds nothing to the
# component list. Measured on the benchmark's lock-file projects, the component
# lists of a build and of `trivy fs` are the same for npm, pnpm and bun lock files
# and for gradle.lockfile; the licenses are the part a static read leaves out, and
# the registry lookup fills them. The same read of a project with no lock file
# finds a fraction of what a build does (pom.xml 4 of 13, requirements.txt 4 of 11,
# no lock file 0), so "auto" only chooses it when a lock file of a kind listed
# here covers the whole tree.
#
# static_detection_check <dir> <lang>: returns 0 and sets STATIC_DETECTION_WHY to
# the lock file when the tree is covered by one; returns 1 and sets it to the
# reason when it is not.
STATIC_NODE_LOCKS="package-lock.json npm-shrinkwrap.json pnpm-lock.yaml bun.lock"
static_detection_check() {
    local d="$1" lang="$2" l found="" nested
    # shellcheck disable=SC2034  # read by scripts/scan-sbom.sh after the call
    STATIC_DETECTION_WHY=""
    case "$lang" in
        node)
            for l in $STATIC_NODE_LOCKS; do [ -f "$d/$l" ] && { found="$l"; break; }; done
            [ -n "$found" ] || { STATIC_DETECTION_WHY="no package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml or bun.lock"; return 1; }
            ;;
        java)
            [ -f "$d/pom.xml" ] && { STATIC_DETECTION_WHY="a Maven project resolves in a build"; return 1; }
            [ -f "$d/gradle.lockfile" ] || { STATIC_DETECTION_WHY="no gradle.lockfile"; return 1; }
            found="gradle.lockfile"
            ;;
        *) STATIC_DETECTION_WHY="no lock file kind is verified for this language"; return 1 ;;
    esac
    # Left-out folders (tests, examples) carry manifests the build leaves out of the
    # SBOM and records; a static read would have to reproduce that, so they stay on
    # the build.
    # (The Gradle wrapper jar and the workflow files are listed there too, but they are
    # not manifests and do not change what a lock file covers.)
    if non_shipped_enabled && [ -n "$(non_shipped_manifests "$d" | { grep -Ev '(^|/)(gradle/wrapper/|\.github/workflows/)' || true; })" ]; then
        STATIC_DETECTION_WHY="manifests under folders that are left out of the scan"; return 1
    fi
    # Another manifest further down is a second project the root lock file may not
    # cover. A workspace root (pnpm-workspace.yaml, or "workspaces" in package.json)
    # lists its members and its lock file covers them.
    nested="$(cd "$d" 2>/dev/null && find . -mindepth 2 -maxdepth 5 \( -name .git -o -name node_modules -o -name vendor -o -name build -o -name target \) -prune -o -type f \
        \( -name package.json -o -name pom.xml -o -name 'build.gradle*' -o -name requirements.txt -o -name pyproject.toml -o -name go.mod -o -name Cargo.toml -o -name Gemfile -o -name composer.json \) -print -quit 2>/dev/null)"
    if [ -n "$nested" ]; then
        if [ "$lang" = node ] && { [ -f "$d/pnpm-workspace.yaml" ] || grep -q '"workspaces"' "$d/package.json" 2>/dev/null; }; then
            :
        elif [ "$lang" = java ] && { [ -f "$d/settings.gradle" ] || [ -f "$d/settings.gradle.kts" ]; }; then
            :
        else
            STATIC_DETECTION_WHY="another manifest below the root ($nested)"; return 1
        fi
    fi
    STATIC_DETECTION_WHY="$found"
    return 0
}

# trivy --skip-dirs flags for the folders a source scan leaves out, plus the
# installed packages: the lock file is the authority in a static read.
non_shipped_trivy_args() {
    local d out="--skip-dirs **/node_modules"
    if non_shipped_enabled; then
        for d in $NON_SHIPPED_DIRS $NON_SHIPPED_PATHS; do out="$out --skip-dirs **/$d"; done
    fi
    printf '%s' "$out"
}

# True unless BOMLENS_INCLUDE_NON_SHIPPED asks to keep the non-shipped trees.
non_shipped_enabled() {
    case "${BOMLENS_INCLUDE_NON_SHIPPED:-}" in 1|true) return 1 ;; esac
    return 0
}

# _declares_deps <file>: true when a manifest or lock file lists at least one
# dependency. A file whose format this does not know counts as declaring.
# Development-only dependencies do not count for package.json: a source scan
# leaves them out, so an empty result is then correct.
_declares_deps() {
    local f="$1"
    case "$f" in
        */package.json|package.json)
            jq -e '[.dependencies, .optionalDependencies, .peerDependencies]
                   | map(select(type == "object") | length) | add // 0 | . > 0' "$f" >/dev/null 2>&1 ;;
        */package-lock.json|package-lock.json|*/npm-shrinkwrap.json|npm-shrinkwrap.json)
            jq -e '(.packages // {} | keys | map(select(. != "")) | length) + (.dependencies // {} | length) > 0' "$f" >/dev/null 2>&1 ;;
        */yarn.lock|yarn.lock|*/pnpm-lock.yaml|pnpm-lock.yaml)
            grep -Eq '^[^#[:space:]][^:]*:[[:space:]]*$|^  [^ #][^:]*:[[:space:]]*$' "$f" 2>/dev/null \
                && grep -Eq 'version|resolution' "$f" 2>/dev/null ;;
        */pyproject.toml|pyproject.toml)
            awk '
                /^\[project\][[:space:]]*$/ { sec="project"; next }
                /^\[tool\.poetry\.(group\.[^]]+\.)?dependencies\][[:space:]]*$/ { sec="poetry"; next }
                /^\[/ { sec=""; inarr=0; next }
                sec=="project" && /^[[:space:]]*dependencies[[:space:]]*=[[:space:]]*\[/ {
                    line=$0; sub(/^[^[]*\[/, "", line)
                    if (line ~ /["'"'"']/) found=1; else inarr=1; next }
                inarr && /["'"'"']/ { found=1 }
                inarr && /\]/ { inarr=0 }
                sec=="poetry" && /^[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*=/ {
                    k=$0; sub(/[[:space:]]*=.*/, "", k); gsub(/[[:space:]]/, "", k)
                    if (tolower(k) != "python") found=1 }
                END { exit !found }' "$f" ;;
        */Cargo.toml|Cargo.toml)
            awk '/^\[(.*\.)?(dev-|build-)?dependencies\][[:space:]]*$/{t=1; next} /^\[(.*\.)?(dev-|build-)?dependencies\.[^]]+\]/{found=1} /^\[/{t=0} t && /^[A-Za-z0-9_-]+[[:space:]]*=/{found=1} END{exit !found}' "$f" ;;
        */Cargo.lock|Cargo.lock)
            [ "$(grep -c '^\[\[package\]\]' "$f" 2>/dev/null)" -gt 1 ] ;;
        */go.mod|go.mod)
            grep -Eq '^[[:space:]]*require[[:space:]]' "$f" 2>/dev/null ;;
        */go.sum|go.sum)
            [ -s "$f" ] ;;
        */requirements*.txt|requirements*.txt)
            grep -Eq '^[[:space:]]*[A-Za-z0-9]' "$f" 2>/dev/null ;;
        */Pipfile|Pipfile)
            awk '/^\[packages\]/{t=1; next} /^\[/{t=0} t && /^[A-Za-z0-9_.-]+[[:space:]]*=/{found=1} END{exit !found}' "$f" ;;
        */pom.xml|pom.xml)
            grep -q '<dependency>' "$f" 2>/dev/null ;;
        */build.gradle|build.gradle|*/build.gradle.kts|build.gradle.kts)
            grep -Eq '^[[:space:]]*(implementation|api|compile|runtimeOnly|compileOnly)[[:space:](]' "$f" 2>/dev/null ;;
        */settings.gradle|settings.gradle|*/settings.gradle.kts|settings.gradle.kts)
            return 1 ;;
        */Gemfile|Gemfile)
            grep -Eq '^[[:space:]]*gem[[:space:]]' "$f" 2>/dev/null ;;
        */Gemfile.lock|Gemfile.lock)
            grep -Eq '^    [A-Za-z0-9]' "$f" 2>/dev/null ;;
        *.csproj|*.fsproj|*.vbproj)
            grep -q 'PackageReference' "$f" 2>/dev/null ;;
        */packages.config|packages.config)
            grep -q '<package ' "$f" 2>/dev/null ;;
        */composer.json|composer.json)
            jq -e '(.require // {}) | keys | map(select(. != "php" and (startswith("ext-") | not))) | length > 0' "$f" >/dev/null 2>&1 ;;
        */Package.swift|Package.swift)
            grep -q '\.package(' "$f" 2>/dev/null ;;
        */Podfile|Podfile)
            grep -Eq '^[[:space:]]*pod[[:space:]]' "$f" 2>/dev/null ;;
        *) return 0 ;;
    esac
}

# source_manifests <dir> [max]: the dependency manifests and lock files in a
# source tree that declare at least one dependency (_declares_deps), as paths
# relative to <dir> joined with ", " (at most [max], default 5). Dependency,
# VCS and non-shipped folders are skipped; an installed package's own
# METADATA/PKG-INFO is not a manifest. The tree is listed once and filtered by
# name in one grep, so a large source tree costs a single walk.
source_manifests() {
    local dir="$1" max="${2:-5}" f rel out="" n=0
    local -a prune=(-name .git -o -name node_modules -o -name vendor -o -name .venv -o -name site-packages)
    if non_shipped_enabled; then
        for f in $NON_SHIPPED_DIRS; do prune+=(-o -name "$f"); done
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        rel="${f#"$dir"/}"
        case "$rel" in */METADATA|METADATA|*/PKG-INFO|PKG-INFO) continue ;; esac
        _declares_deps "$f" || continue
        out="$out, $rel"
        n=$((n + 1))
        [ "$n" -ge "$max" ] && break
    done < <(find "$dir" \( -type d \( "${prune[@]}" \) -prune \) -o -type f -print 2>/dev/null \
             | grep -E "$NON_SHIPPED_MANIFEST_RE" | LC_ALL=C sort)
    printf '%s' "${out#, }"
}

# stage1_fail_reason <oom> [log] [exit code]: why stage 1 (cdxgen) gave no
# SBOM, in the words bomlens:sbom-tool-degraded uses: oom (the container was
# killed for memory), cdxgen-unavailable (exit 127, the shell's "command not
# found": stage 1 never started, or a caller of an unsupported plan says it
# did not run), disk-space, network, or cdxgen-crash. The CLI and the
# post-processing step both classify with this.
stage1_fail_reason() {
    if [ "${1:-}" = "true" ]; then echo oom; return; fi
    if [ "${3:-}" = "127" ]; then echo cdxgen-unavailable; return; fi
    local log="${2:-}"
    if [ -n "$log" ] && [ -f "$log" ]; then
        if grep -qi "no space left on device" "$log"; then echo disk-space; return; fi
        if grep -qEi "temporary failure in name resolution|could not resolve host|network is unreachable|connection timed out|connect timed out|no route to host|ENOTFOUND|ETIMEDOUT" "$log"; then
            echo network; return
        fi
    fi
    echo cdxgen-crash
}

# The glob patterns applied, relative to the scan root, joined with ", ".
non_shipped_globs() {
    local d out=""
    for d in $NON_SHIPPED_DIRS $NON_SHIPPED_PATHS; do out="$out, **/$d/**"; done
    printf '%s' "${out#, }"
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
    for d in $NON_SHIPPED_PATHS; do out="$out --exclude ./**/$d/**"; done
    printf '%s' "${out# }"
}

# Manifest files under the non-shipped folders, and workflow files, relative to
# the scan root and sorted. Names match in any letter case, as in cdxgen.
non_shipped_manifests() {
    local root="$1" d re=""
    for d in $NON_SHIPPED_DIRS; do re="$re|$d"; done
    re="(^|/)(${re#|})/"
    (cd "$root" 2>/dev/null && find . \( -name node_modules -o -name .git \) -prune -o -type f -print 2>/dev/null) \
        | sed 's#^\./##' \
        | { grep -Ei "$NON_SHIPPED_PATH_FILE_RE|$re" || true; } \
        | { grep -Ei "$NON_SHIPPED_PATH_FILE_RE|$NON_SHIPPED_MANIFEST_RE" || true; } \
        | LC_ALL=C sort
}

# generate_sbom_static <root> <out>: the SBOM of a source tree read from its lock
# file, with no build. `trivy fs` reads the lock files (the license scanner is
# the one that needs no vulnerability database), the lock files themselves come
# out of the list (Trivy lists each as a component without a purl), and a
# Trivy's 1.7 document is lowered to 1.6 when the pipeline emits 1.6. Returns 1
# when anything fails, so the caller can fall back to a build.
generate_sbom_static() {
    local root="$1" out="$2" tmp="$2.static.tmp" skip=() have
    command -v trivy >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 || return 1
    read -ra skip <<< "$(non_shipped_trivy_args)"
    if ! trivy fs --quiet --scanners license --format cyclonedx --offline-scan "${skip[@]}" -o "$tmp" "$root" 2>/dev/null \
       || ! jq -e '.bomFormat == "CycloneDX"' "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"; return 1
    fi
    if ! jq '.components = [(.components // [])[] | select(((.type == "application") and ((.purl // "") == "")) | not)]' "$tmp" > "$out" 2>/dev/null; then
        rm -f "$tmp" "$out"; return 1
    fi
    rm -f "$tmp"
    # Trivy writes 1.7. The pipeline's later step raises a 1.6 document to 1.7 when
    # asked, and lowering 1.7 to 1.6 is what cdx-copy-as-1.6.sh does (syft's own
    # convert would turn the root component into a component).
    have="$(jq -r '.specVersion // ""' "$out" 2>/dev/null)"
    if [ "$have" = "1.7" ] && [ "${CDX_SPEC_VERSION:-1.6}" = "1.6" ]; then
        if bash "${LIBDIR:-$(dirname "${BASH_SOURCE[0]}")}/cdx-copy-as-1.6.sh" "$out" "$out.conv" 2>/dev/null && [ -s "$out.conv" ]; then
            mv "$out.conv" "$out"
        else
            rm -f "$out" "$out.conv"; return 1
        fi
    fi
    return 0
}

# mark_sbom_detection <file> <how> <why>: say on the SBOM which way it was made.
mark_sbom_detection() {
    local file="$1" how="$2" why="$3" tmp
    [ -f "$file" ] || return 0
    command -v jq >/dev/null 2>&1 || return 0
    tmp="${file}.detection.tmp"
    if jq --arg h "$how" --arg w "$why" '
        .metadata = (.metadata // {})
        | .metadata.properties = (((.metadata.properties // [])
              | map(select(.name != "bomlens:detection" and .name != "bomlens:detection-source")))
            + [{name: "bomlens:detection", value: $h}]
            + (if $w != "" then [{name: "bomlens:detection-source", value: $w}] else [] end))' "$file" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
    else
        rm -f "$tmp"
    fi
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
    local p="$CDXGEN_IMAGE_PREFIX"
    case "$1" in
        rust)   echo "${p}cdxgen-debian-rust:$CDXGEN_TAG" ;;
        go)     echo "${p}cdxgen-debian-golang124:$CDXGEN_TAG" ;;
        ruby)   echo "${p}cdxgen-debian-ruby34:$CDXGEN_TAG" ;;
        java)   echo "${p}cdxgen-temurin-java21:$CDXGEN_TAG" ;;
        python) echo "${p}cdxgen-python312:$CDXGEN_TAG" ;;
        node)   echo "${p}cdxgen-alpine-node24:$CDXGEN_TAG" ;;
        php)    echo "${p}cdxgen-debian-php84:$CDXGEN_TAG" ;;
        dotnet) echo "${p}cdxgen-debian-dotnet9:$CDXGEN_TAG" ;;
        swift)  echo "${p}cdxgen-debian-swift:$CDXGEN_TAG" ;;
        # mixed / unknown: the all-in-one image, from the mirror too unless
        # CDXGEN_ALLINONE names another
        *)      case "$CDXGEN_ALLINONE" in
                    ghcr.io/cdxgen/*) echo "${p}${CDXGEN_ALLINONE#ghcr.io/cdxgen/}" ;;
                    *) echo "$CDXGEN_ALLINONE" ;;
                esac ;;
    esac
}

# A Java (Maven/Gradle) or Android build runs inside the engine and is killed
# when the engine has too little memory; the scan then falls back to a
# shallower, direct-dependencies-only result. Say so before the build starts.
# Shared by the CLI (scan-sbom.sh) and the web UI's source scan (entrypoint.sh).
# `docker info` reports the engine's own memory (the VM behind Docker Desktop,
# Rancher Desktop or Colima, the WSL 2 VM, or the whole host on native Linux),
# not the host's. A best-effort hint: it never stops the scan, and a value that
# cannot be read prints nothing. A 4 GiB engine reports a little under that
# (about 3.8 GiB), so the line is drawn at 3.5 GiB. Every line carries [WARN]
# because the web UI keeps only the lines that start with it.
warn_low_engine_memory() {  # warn_low_engine_memory <build-kind>
    local bytes mb
    bytes=$(docker info --format '{{.MemTotal}}' 2>/dev/null) || return 0
    bytes=${bytes%%$'\r'*}
    case "$bytes" in ''|*[!0-9]*) return 0 ;; esac
    mb=$((bytes / 1024 / 1024))
    [ "$mb" -gt 0 ] && [ "$mb" -lt 3584 ] || return 0
    echo "[WARN] The Docker engine has about $(( (mb + 512) / 1024 )) GB of memory. A $1 build needs about 4 GB; with less, it can be killed and the scan falls back to direct dependencies only."
    echo "[WARN]   Colima:          colima stop && colima start --memory 4"
    echo "[WARN]   Docker Desktop:  Settings > Resources > Memory (WSL 2 backend: memory=4GB in %UserProfile%\\.wslconfig, then wsl --shutdown)"
    echo "[WARN]   Rancher Desktop: Preferences > Virtual Machine > Memory (Windows: .wslconfig as above). Native Linux uses the host's memory."
}

# Which build does this tree need, if any: the language decides for Java and
# Android; a mixed or unrecognised tree still runs Maven or Gradle when it holds
# a pom.xml or build.gradle within four levels (cdxgen collects recursively).
warn_low_engine_memory_for() {  # warn_low_engine_memory_for <lang> <dir>
    local kind=""
    case "$1" in
        java)    kind="Java" ;;
        android) kind="Gradle" ;;
        mixed|unknown)
            if [ -n "$(find "$2" -maxdepth 4 \( -name .git -o -name node_modules \) -prune -o -name pom.xml -print 2>/dev/null | head -n 1)" ]; then
                kind="Maven"
            elif [ -n "$(find "$2" -maxdepth 4 \( -name .git -o -name node_modules \) -prune -o \( -name build.gradle -o -name build.gradle.kts \) -print 2>/dev/null | head -n 1)" ]; then
                kind="Gradle"
            fi ;;
    esac
    [ -z "$kind" ] || warn_low_engine_memory "$kind"
}

android_api() {
    local d="$1" api
    api=$(grep -rhoE "compileSdk(Version)?[ =]+[0-9]+" "$d"/build.gradle "$d"/build.gradle.kts "$d"/app/build.gradle "$d"/app/build.gradle.kts 2>/dev/null \
          | grep -oE "[0-9]+" | head -1)
    echo "${api:-$ANDROID_API_DEFAULT}"
}
