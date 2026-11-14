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
CDXGEN_TAG="${CDXGEN_TAG:-13.5.0}"                               # cdxgen language image tag
# renovate: datasource=docker depName=ghcr.io/cdxgen/cdxgen
CDXGEN_ALLINONE="${CDXGEN_ALLINONE:-ghcr.io/cdxgen/cdxgen:13.5.0}"
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
BUILD_PREP_ENV_NAMES="BOMLENS_KEEP_BUILD_OUTPUT BOMLENS_MAVEN_FULL_GRAPH BOMLENS_ANDROID_FULL_GRAPH BOMLENS_GRADLE_FULL_GRAPH BOMLENS_NODE_FULL_GRAPH BOMLENS_PHP_FULL_GRAPH BOMLENS_INCLUDE_NON_SHIPPED BOMLENS_INCLUDE_DEV_DEPENDENCIES BOMLENS_NO_COPYRIGHT BOMLENS_NO_CARGO_LICENSE BOMLENS_PREP_TIMEOUT"

# Settings for the network the post-processing container reaches: the proxy,
# where Trivy gets its vulnerability database (a mirror, or a cache with the
# update skipped) and the EPSS and KEV lookups (off, or a mirror), and which
# Go vulnerability database export it reads (BOMLENS_GO_VULNDB*). Passed on
# by name, so a value is never on a command line.
STAGE2_NETWORK_ENV_NAMES="$PROXY_ENV_NAMES TRIVY_DB_REPOSITORY TRIVY_JAVA_DB_REPOSITORY TRIVY_SKIP_DB_UPDATE TRIVY_SKIP_JAVA_DB_UPDATE TRIVY_OFFLINE_SCAN TRIVY_USERNAME TRIVY_PASSWORD TRIVY_REGISTRY_TOKEN TRIVY_INSECURE BOMLENS_TRIVY_DB_MAX_AGE_DAYS BOMLENS_GRYPE_DB_MAX_AGE_DAYS GRYPE_DB_UPDATE_URL BOMLENS_GO_VULNDB BOMLENS_GO_VULNDB_PATH BOMLENS_GO_VULNDB_MAX_AGE_DAYS BOMLENS_GO_VULNDB_URL KEV_URL EPSS_API"

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

# SBOM_GO_VULNDB: a Go vulnerability database export on this host (vulndb.zip
# from https://vuln.go.dev/vulndb.zip, or that archive unpacked into a folder),
# read in place of the snapshot the image carries. Prints the host path and the
# path inside the container, one per line; the caller mounts the first at the
# second, read-only, and sets BOMLENS_GO_VULNDB_PATH to the second.
go_vulndb_mount() {
    [ -n "${SBOM_GO_VULNDB:-}" ] || return 0
    if [ -f "$SBOM_GO_VULNDB" ]; then
        printf '%s\n' "$(cd "$(dirname "$SBOM_GO_VULNDB")" && pwd)/$(basename "$SBOM_GO_VULNDB")" /go-vulndb.zip
    elif [ -d "$SBOM_GO_VULNDB" ]; then
        printf '%s\n' "$(cd "$SBOM_GO_VULNDB" && pwd)" /go-vulndb
    else
        echo "[WARN] SBOM_GO_VULNDB=$SBOM_GO_VULNDB is neither a file nor a folder; the Go vulnerability database snapshot in the image is used. Download https://vuln.go.dev/vulndb.zip and point SBOM_GO_VULNDB at it." >&2
    fi
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
# here covers the whole tree. Cargo.lock, poetry.lock, uv.lock and yarn.lock are not
# listed on purpose: a static read of a Cargo project has the same packages as a
# build but not the 73 of 98 copyright notices the build reads from the downloaded
# crates, poetry.lock's dev group differs from what a build installs, and the
# component lists of yarn.lock and uv.lock have not been measured against a build
# since a static read stopped listing the project itself.
#
# static_detection_check <dir> <lang>: returns 0 and sets STATIC_DETECTION_WHY to
# the lock file when the tree is covered by one; returns 1 and sets it to the
# reason when it is not.
STATIC_NODE_LOCKS="package-lock.json npm-shrinkwrap.json pnpm-lock.yaml bun.lock"
# shellcheck disable=SC2034  # STATIC_DETECTION_WHY is read by the caller after the call
static_detection_check() {
    local d="$1" lang="$2" l found="" nested
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
    # cover, and in a workspace the members' own dependencies come into a static read
    # that a build leaves out (a real monorepo read statically had 231 packages
    # against 26 built). Both stay on the build.
    nested="$(cd "$d" 2>/dev/null && find . -mindepth 2 -maxdepth 5 \( -name .git -o -name node_modules -o -name vendor -o -name build -o -name target \) -prune -o -type f \
        \( -name package.json -o -name pom.xml -o -name 'build.gradle*' -o -name requirements.txt -o -name pyproject.toml -o -name go.mod -o -name Cargo.toml -o -name Gemfile -o -name composer.json \) -print -quit 2>/dev/null)"
    if [ -n "$nested" ]; then
        STATIC_DETECTION_WHY="another manifest below the root ($nested)"; return 1
    fi
    # A workspace root with no manifest of a member below it (or one that is itself a
    # member list) is a monorepo too.
    if [ "$lang" = node ] && { [ -f "$d/pnpm-workspace.yaml" ] || grep -q '"workspaces"' "$d/package.json" 2>/dev/null; }; then
        STATIC_DETECTION_WHY="a workspace root"; return 1
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

# static_project_name <root>: the project's own package name, for the two lock
# file kinds that list the project as a package (yarn.lock beside package.json,
# uv.lock beside pyproject.toml). Prints nothing for any other tree.
static_project_name() {
    local root="$1"
    if [ -f "$root/yarn.lock" ] && [ -f "$root/package.json" ]; then
        jq -r '.name // empty' "$root/package.json" 2>/dev/null
    elif [ -f "$root/uv.lock" ] && [ -f "$root/pyproject.toml" ]; then
        awk '
            /^\[project\][[:space:]]*$/ { sec=1; next }
            /^\[/ { sec=0 }
            sec && /^[[:space:]]*name[[:space:]]*=/ {
                v=$0; sub(/^[^=]*=[[:space:]]*/, "", v)
                gsub(/^["'"'"']|["'"'"'][[:space:]]*(#.*)?$/, "", v)
                print v; exit }' "$root/pyproject.toml" 2>/dev/null
    fi
}

# static_drop_project_package <root> <sbom>: takes the project's own package out
# of a static read. Trivy lists it for yarn.lock and uv.lock, where a build does
# not, and puts it between the lock file and the direct dependencies; the
# dependencies it held move up to whatever listed it, so the graph still reaches
# every package. Nothing changes when the tree has neither lock file or no
# component carries the project's name.
static_drop_project_package() {
    local root="$1" sbom="$2" name py=false tmp="$2.self.tmp"
    name="$(static_project_name "$root")"
    [ -n "$name" ] || return 0
    [ -f "$root/uv.lock" ] && py=true
    if jq --arg name "$name" --argjson py "$py" '
        def norm: if $py then ascii_downcase | gsub("[-_.]+"; "-") else . end;
        def full: if (.group // "") != "" then "\(.group)/\(.name)" else (.name // "") end;
        ([.components[]?
          | select(.type == "library" and ((.purl // "") | startswith(if $py then "pkg:pypi/" else "pkg:npm/" end))
                   and ((full | norm) == ($name | norm)))
          | ."bom-ref"]) as $self
        | if ($self | length) == 0 then .
          else
            ([.dependencies[]? | select(.ref as $r | $self | any(. == $r)) | .dependsOn[]?] | unique) as $kids
            | .components |= map(select(."bom-ref" as $r | $self | any(. == $r) | not))
            | if has("dependencies") then
                .dependencies |= (map(select(.ref as $r | $self | any(. == $r) | not))
                  | map(if ((.dependsOn // []) | any(. as $d | $self | any(. == $d)))
                        then .dependsOn = (((.dependsOn - $self) + $kids) | unique) else . end))
              else . end
          end' "$sbom" > "$tmp" 2>/dev/null; then
        mv "$tmp" "$sbom"
    else
        rm -f "$tmp"; return 1
    fi
}

# generate_sbom_static <root> <out>: the SBOM of a source tree read from its lock
# file, with no build. `trivy fs` reads the lock files (the license scanner is
# the one that needs no vulnerability database), the lock files themselves come
# out of the list (Trivy lists each as a component without a purl), the project's
# own package comes out for yarn.lock and uv.lock (static_drop_project_package), and a
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
    static_drop_project_package "$root" "$out" || { rm -f "$out"; return 1; }
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

# The highest Java toolchain version the Gradle builds under $1 declare, or
# nothing. A Gradle toolchain asks for that exact JDK, and without a toolchain
# download repository (auto-provisioning) the build fails to resolve its
# dependencies when the image has another one. Read from *.gradle and
# *.gradle.kts files in $1 and up to five folders below it (buildSrc and
# build-logic convention plugins sit that deep), skipping the folders
# _detect_first skips (the non-shipped ones unless BOMLENS_INCLUDE_NON_SHIPPED
# is set) and comments:
#   JavaLanguageVersion.of(25)  (languageVersion.set(...), languageVersion = ...)
#   jvmToolchain(25)            (Kotlin)
# The argument may also be a variable defined in the same file, optionally
# converted (.toInteger(), .toInt(), .toString(), as int); its value is read
# from that definition (_java_toolchain_awk). A version from a version
# catalog, from a variable of another file or from an environment variable
# alone is not read. Maven is not read either: maven.compiler.release and the
# toolchains plugin take effect when the build compiles, and dependency
# resolution (dependency:tree) runs without them on the image's JDK.
java_toolchain_version() {
    local d="$1" n prune=()
    [ -n "$d" ] && [ -d "$d" ] || return 0
    for n in .git .gradle node_modules vendor build target bin obj .build Pods .venv; do
        prune+=(-o -name "$n")
    done
    if non_shipped_enabled; then
        for n in $NON_SHIPPED_DIRS; do prune+=(-o -name "$n"); done
    fi
    # The gradle.properties values come first, from regular files only (find
    # -type f: never a symlink, a FIFO or a device), as "folder<TAB>key<TAB>value"
    # lines, at most 64 KB of them. The build files' awk gets them through the
    # environment and opens no file itself.
    (cd "$d" 2>/dev/null || exit 0
     _JAVA_TC_PROPS="$(find . -maxdepth 6 \( "${prune[@]:1}" \) -prune -o -type f -name gradle.properties \
         -exec awk "$(_java_toolchain_props_awk)" {} + 2>/dev/null | head -c 65536)" \
         find . -maxdepth 6 \( "${prune[@]:1}" \) -prune -o -type f \( -name '*.gradle' -o -name '*.gradle.kts' \) \
         -exec awk "$(_java_toolchain_awk)" {} + 2>/dev/null) \
        | grep -E '^[0-9]{1,3}$' | sed 's/^0*\([0-9]\)/\1/' | sort -n | tail -1 || true
}

# _java_toolchain_props_awk: the awk program that reads gradle.properties
# files for java_toolchain_version. Prints "folder<TAB>key<TAB>value" for each
# key Gradle property names can take (letters, digits, _ . -) with a value of
# at most 16 characters. A line over 4096 characters and a path holding a tab
# are skipped.
_java_toolchain_props_awk() {
    cat <<'AWK'
FNR == 1 { dir = FILENAME; sub(/\/[^\/]*$/, "", dir); skip = (FILENAME ~ /\t/) }
skip || length($0) > 4096 { next }
{
    line = $0; sub(/^[ \t]+/, "", line)
    if (line == "" || line ~ /^[#!]/) next
    if (!match(line, /[=: \t]/)) next
    key = substr(line, 1, RSTART - 1)
    if (key !~ /^[A-Za-z0-9_.-]+$/) next
    val = substr(line, RSTART); sub(/^[ \t]*[=:]?[ \t]*/, "", val); sub(/[ \t\r]+$/, "", val)
    if (length(val) <= 16) print dir "\t" key "\t" val
}
AWK
}

# _java_toolchain_awk: the awk program java_toolchain_version runs over the
# build files, printing one candidate version per line. It drops // line
# comments and /* */ blocks (across lines too, and never past the end of a
# file) before anything is matched. A line over 4096 characters holds no
# declaration worth reading and is skipped, in a gradle.properties file too,
# which keeps the scan of a crafted file linear. Per file it reads:
#   JavaLanguageVersion.of(25), jvmToolchain("25")     the number itself
#   JavaLanguageVersion.of(v), jvmToolchain(v.toInt())  v, looked up below
#   def v = <expression> (also val, var, final, a type, val v: String = ...)
#                                                       the first one in the file
#   val v: String by project                            the Gradle property v
# A definition outside any { } block wins over one inside a block; among
# equals the first in the file counts (a later reassignment is not followed;
# the rerun in java_retry_image covers a build where that matters).
# A definition that reads a Gradle property p (hasProperty("p"), getProperty,
# findProperty, property, providers.gradleProperty("p"), properties["p"]; not
# System.getProperty) takes p=N from the gradle.properties nearest the build
# file, up to the scanned folder, as _java_toolchain_props_awk read it into
# _JAVA_TC_PROPS (the last value of a key in a file counts, as in Gradle). Failing that, the default it gives counts:
# the number after its last ?: or the ternary's :, or in getOrElse("N"); or
# the number it is set to. Only the awk features busybox, mawk and the BSD
# awk share are used.
_java_toolchain_awk() {
    cat <<'AWK'
function strip(s) {
    sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s
}
function digits(s) { gsub(/[^0-9]/, "", s); return s }
BEGIN {
    n = split(ENVIRON["_JAVA_TC_PROPS"], pl, "\n")
    for (i = 1; i <= n; i++) {
        if (split(pl[i], pf, "\t") != 3) continue
        props[pf[1] SUBSEP pf[2]] = pf[3]
    }
}
# The value of Gradle property p in the gradle.properties nearest file f.
function gprop(f, p,    dir) {
    dir = f
    while (dir ~ /\//) {
        sub(/\/[^\/]*$/, "", dir)
        if ((dir SUBSEP p) in props) return (props[dir SUBSEP p] ~ /^[0-9]+$/) ? props[dir SUBSEP p] : ""
    }
    return ""
}
# The Gradle property an expression reads, or "".
function propname(e,    pre, m) {
    while (match(e, /([Pp]roperty[ \t]*\([ \t]*|properties[ \t]*\[[ \t]*)["'][A-Za-z0-9_.-]+["']/)) {
        pre = substr(e, 1, RSTART - 1)
        m = substr(e, RSTART, RLENGTH)
        e = substr(e, RSTART + RLENGTH)
        if (pre ~ /System\.(get)?$/) continue
        sub(/^[^"']*["']/, "", m); sub(/["']$/, "", m)
        return m
    }
    return ""
}
# The number an expression falls back to, or "".
function fallback(e) {
    if (match(e, /getOrElse[ \t]*\([ \t]*["']?[0-9]+["']?[ \t]*\)/)) return digits(substr(e, RSTART, RLENGTH))
    if (e ~ /\?/ && match(e, /:[ \t]*\(?[ \t]*["']?[0-9]+["']?[ \t]*\)?[ \t]*(\.(toInteger|toInt|toString)\(\)|[ \t]+as[ \t]+(int|Integer))?[ \t]*\)?[ \t]*;?[ \t]*$/))
        return digits(substr(e, RSTART, RLENGTH))
    if (e ~ /^[ \t]*["']?[0-9]+["']?[ \t]*(\.(toInteger|toInt|toString)\(\)|[ \t]+as[ \t]+(int|Integer))?[ \t]*;?[ \t]*$/) return digits(e)
    return ""
}
function flush(f,    name, e, p, v) {
    for (name in refs) {
        v = ""
        if (name in byproj) v = gprop(f, name)
        else if (name in defs) {
            e = (name in defs0) ? defs0[name] : defs[name]
            p = propname(e)
            if (p != "") v = gprop(f, p)
            if (v == "") v = fallback(e)
        }
        if (v != "") print v
    }
    split("", refs); split("", defs); split("", defs0); split("", byproj)
}
FNR == 1 { if (cur != "") flush(cur); cur = FILENAME; blk = 0; depth = 0 }
length($0) > 4096 { next }
{
    line = $0; out = ""
    while (line != "") {
        if (blk) { i = index(line, "*/"); if (!i) { line = ""; break }; line = substr(line, i + 2); blk = 0; continue }
        a = index(line, "/*"); b = index(line, "//")
        if (b && (!a || b < a)) { out = out substr(line, 1, b - 1); line = ""; break }
        if (a) { out = out substr(line, 1, a - 1); line = substr(line, a + 2); blk = 1; continue }
        out = out line; line = ""
    }
    if (match(out, /^[ \t]*val[ \t]+[A-Za-z_][A-Za-z0-9_]*([ \t]*:[ \t]*[A-Za-z?]+)?[ \t]+by[ \t]+project([^A-Za-z0-9_.]|$)/)) {
        h = out; sub(/^[ \t]*val[ \t]+/, "", h); match(h, /^[A-Za-z_][A-Za-z0-9_]*/)
        h = substr(h, 1, RLENGTH)
        if (!(h in defs) && !(h in byproj)) byproj[h] = 1
    } else if (match(out, /^[ \t]*((def|val|var|final|static|private|int|Integer|String)[ \t]+)+[A-Za-z_][A-Za-z0-9_]*([ \t]*:[ \t]*[A-Za-z?]+)?[ \t]*=/) \
               && substr(out, RSTART + RLENGTH, 1) != "=") {
        h = substr(out, 1, RLENGTH - 1); e = substr(out, RLENGTH + 1)
        sub(/[ \t]*:[ \t]*[A-Za-z?]+[ \t]*$/, "", h); h = strip(h)
        match(h, /[A-Za-z_][A-Za-z0-9_]*$/); h = substr(h, RSTART, RLENGTH)
        if (!(h in defs) && !(h in byproj)) defs[h] = e
        if (depth == 0 && !(h in defs0)) defs0[h] = e
    }
    rest = out
    while (match(rest, /(JavaLanguageVersion\.of|jvmToolchain)[ \t]*\([ \t]*/)) {
        rest = substr(rest, RSTART + RLENGTH)
        if (match(rest, /^["']?[0-9]+/)) { print digits(substr(rest, 1, RLENGTH)); continue }
        if (match(rest, /^[A-Za-z_][A-Za-z0-9_]*[ \t]*(\.(toInteger|toInt|toString)\(\)|[ \t]+as[ \t]+(int|Integer))?[ \t]*\)/)) {
            h = substr(rest, 1, RLENGTH); match(h, /^[A-Za-z_][A-Za-z0-9_]*/)
            refs[substr(h, 1, RLENGTH)] = 1
        }
    }
    # The block depth at the start of the next line.
    t = out; depth += gsub(/\{/, "", t); t = out; depth -= gsub(/\}/, "", t)
    if (depth < 0) depth = 0
}
END { if (cur != "") flush(cur) }
AWK
}

# The JDKs the published cdxgen Java images carry, and the one used when
# nothing in the build asks for another. Every image also has its own Gradle
# (8.14.5), used when the build has no wrapper.
CDXGEN_JAVA_JDKS="8 11 17 21 24 25"
CDXGEN_JAVA_DEFAULT=21

# _java_image_name <jdk>: the cdxgen image name for a JDK in CDXGEN_JAVA_JDKS.
# The Java 11 and 17 images are not named temurin.
_java_image_name() {
    case "$1" in
        11|17) echo "cdxgen-java$1" ;;
        *)     echo "cdxgen-temurin-java$1" ;;
    esac
}

# _java_has_image <jdk>: true when a published image has that JDK.
_java_has_image() {
    case " $CDXGEN_JAVA_JDKS " in *" ${1:-x} "*) return 0 ;; esac
    return 1
}

# _gradle_wrapper_props_version <gradle-wrapper.properties>: the Gradle
# version of the distribution its distributionUrl names, as X.Y.Z, or
# nothing. Only the file name at the end of the URL is read, in Gradle's own
# form: gradle-X.Y[.Z][-rc-N|-milestone-N|-<snapshot>]-(bin|all).zip. A
# milestone, release candidate or snapshot counts as its release. The key and
# the value may be separated by =, : or white space, as in any .properties file.
_gradle_wrapper_props_version() {
    local url v
    url="$(grep -E '^[[:space:]]*distributionUrl([[:space:]]|[=:])' "$1" 2>/dev/null | head -1 \
        | sed -E 's/^[[:space:]]*distributionUrl[[:space:]]*[=:]?[[:space:]]*//; s/[[:space:]]+$//')" || true
    url="${url##*/}"
    v="$(printf '%s\n' "$url" | grep -E '^gradle-[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?(-[A-Za-z0-9.+-]+)?-(bin|all)\.zip$' \
        | grep -oE '^gradle-[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?')" || true
    v="${v#gradle-}"
    case "$v" in
        '') return 0 ;;
        *.*.*) echo "$v" ;;
        *) echo "$v.0" ;;
    esac
}

# _gradle_version_number <X.Y.Z>: the version as one comparable number.
_gradle_version_number() {
    local a b c
    IFS=. read -r a b c <<EOF
$1
EOF
    echo $(( 10#${a:-0} * 1000000 + 10#${b:-0} * 1000 + 10#${c:-0} ))
}

# _gradle_has_build <dir>: true when <dir> holds a Gradle settings or build file.
_gradle_has_build() {
    [ -f "$1/settings.gradle" ] || [ -f "$1/settings.gradle.kts" ] \
        || [ -f "$1/build.gradle" ] || [ -f "$1/build.gradle.kts" ]
}

# _gradle_included_builds <dir>: the builds its settings file names in
# includeBuild("..."), one relative path per line, inside <dir> only.
_gradle_included_builds() {
    local x
    for x in $(cat "$1/settings.gradle" "$1/settings.gradle.kts" 2>/dev/null \
               | sed 's#//.*##' \
               | grep -oE 'includeBuild[[:space:]]*\(?[[:space:]]*["'"'"'][A-Za-z0-9_./-]+["'"'"']' \
               | sed -E 's/^includeBuild[[:space:]]*\(?[[:space:]]*["'"'"']//; s/["'"'"']$//; s#^\./##; s#/$##'); do
        case "$x" in ''|/*|..|../*|*/../*|*/..) continue ;; esac
        printf '%s\n' "$x"
    done
}

# gradle_wrappers <dir>: the Gradle wrappers a source scan of <dir> runs.
# Sets GRADLE_WRAPPER_VERSIONS (their versions, space separated, or empty)
# and GRADLE_WRAPPER_UNREADABLE (the properties files of the wrappers whose
# version could not be read, one path per line, relative to <dir>). A wrapper counts only
# with its gradlew script beside it; without one the image's own Gradle runs.
#   - <dir> has gradlew: its wrapper alone runs, readable or not.
#   - <dir> has a Gradle settings or build file and no gradlew: the image's
#     Gradle runs once there, and no nested wrapper runs.
#   - otherwise: every build below it with gradlew beside a settings or build
#     file, found as build-prep.sh finds them: up to five folders below <dir>,
#     skipping build, .gradle, node_modules, buildSrc, build-logic, dot
#     folders, the non-shipped folders (unless BOMLENS_INCLUDE_NON_SHIPPED is
#     set) and the builds another one's settings names in includeBuild(...).
gradle_wrappers() {
    local d="$1" n f b v incl prune=() roots=()
    GRADLE_WRAPPER_VERSIONS=""; GRADLE_WRAPPER_UNREADABLE=""
    [ -n "$d" ] && [ -d "$d" ] || return 0
    if [ -f "$d/gradlew" ]; then
        f="gradle/wrapper/gradle-wrapper.properties"
        v="$(_gradle_wrapper_props_version "$d/$f")"
        if [ -n "$v" ]; then GRADLE_WRAPPER_VERSIONS="$v"; else GRADLE_WRAPPER_UNREADABLE="$f"; fi
        return 0
    fi
    _gradle_has_build "$d" && return 0
    for n in build .gradle node_modules buildSrc build-logic '.?*'; do
        prune+=(-o -name "$n")
    done
    if non_shipped_enabled; then
        for n in $NON_SHIPPED_DIRS; do prune+=(-o -name "$n"); done
    fi
    while IFS= read -r f; do
        b="${f%/gradlew}"; b="${b#./}"
        case "$b" in ''|.|gradlew) continue ;; esac
        if _gradle_has_build "$d/$b"; then roots+=("$b"); fi
    done <<EOF
$(cd "$d" 2>/dev/null && find . -maxdepth 6 -type d \( "${prune[@]:1}" \) ! -path . -prune -o -type f -name gradlew -print 2>/dev/null | LC_ALL=C sort)
EOF
    [ "${#roots[@]}" -gt 0 ] || return 0
    for b in "${roots[@]}"; do
        # An included build runs inside the build that names it.
        for n in "${roots[@]}"; do
            [ "$n" != "$b" ] || continue
            while IFS= read -r incl; do
                if [ -n "$incl" ] && [ "$n/$incl" = "$b" ]; then continue 3; fi
            done <<EOF
$(_gradle_included_builds "$d/$n")
EOF
        done
        f="$b/gradle/wrapper/gradle-wrapper.properties"
        v="$(_gradle_wrapper_props_version "$d/$f")"
        if [ -n "$v" ]; then
            GRADLE_WRAPPER_VERSIONS="${GRADLE_WRAPPER_VERSIONS:+$GRADLE_WRAPPER_VERSIONS }$v"
        else
            GRADLE_WRAPPER_UNREADABLE="${GRADLE_WRAPPER_UNREADABLE:+$GRADLE_WRAPPER_UNREADABLE
}$f"
        fi
    done
    return 0
}

# _gradle_runs_on <X.Y.Z> <jdk>: true when that Gradle version runs on that
# JDK, from Gradle's compatibility matrix
# (https://docs.gradle.org/current/userguide/compatibility.html): Java 8 runs
# Gradle up to 8.14.x, 11 from 5.0 to 8.14.x, 17 from 7.3, 21 from 8.5, 24
# from 8.14 and 25 from 9.1.0.
_gradle_runs_on() {
    local n min
    n="$(_gradle_version_number "$1")"
    case "$2" in
        8)  min=0 ;;
        11) min=5000000 ;;
        17) min=7003000 ;;
        21) min=8005000 ;;
        24) min=8014000 ;;
        25) min=9001000 ;;
        *)  return 1 ;;
    esac
    [ "$n" -ge "$min" ] || return 1
    case "$2" in 8|11) [ "$n" -lt 9000000 ] || return 1 ;; esac
    return 0
}

# _gradle_jdks <version>...: the image JDKs every one of these Gradle
# versions runs on, space separated (all of them for no version).
_gradle_jdks() {
    local j v out=""
    for j in $CDXGEN_JAVA_JDKS; do
        for v in "$@"; do _gradle_runs_on "$v" "$j" || continue 2; done
        out="$out $j"
    done
    echo "${out# }"
}

# _java_choose <dir>: decide the Java image for <dir>. Sets JAVA_PICK_JDK (the
# image's JDK), JAVA_PICK_TOOLCHAIN (the declared toolchain, or empty),
# JAVA_PICK_WRAPPER (the wrapper versions, comma separated, or empty),
# JAVA_PICK_WRAPPER_CONFLICT (true when no image JDK runs every wrapper),
# JAVA_PICK_UNREADABLE (gradle_wrappers' GRADLE_WRAPPER_UNREADABLE) and
# JAVA_PICK_WHY:
#   toolchain   the declared toolchain's own image
#   conflict    an image has the toolchain's JDK, but a wrapper cannot run on it
#   no-image    no image has the toolchain's JDK
#   (empty)     nothing asked for another image than the wrappers allow
# The JDKs the wrappers run on are those every wrapper runs on; when there is
# none, those the lowest wrapper runs on. From them the toolchain's JDK is
# taken when it is one, else Java 21 when it is one, else the newest.
_java_choose() {
    local v low="" lown=0 vn runs
    JAVA_PICK_TOOLCHAIN="$(java_toolchain_version "${1:-}")"
    gradle_wrappers "${1:-}"
    JAVA_PICK_UNREADABLE="$GRADLE_WRAPPER_UNREADABLE"
    JAVA_PICK_WRAPPER=""; JAVA_PICK_WRAPPER_CONFLICT=""; JAVA_PICK_WHY=""
    for v in $GRADLE_WRAPPER_VERSIONS; do
        JAVA_PICK_WRAPPER="${JAVA_PICK_WRAPPER:+$JAVA_PICK_WRAPPER, }$v"
        vn="$(_gradle_version_number "$v")"
        if [ -z "$low" ] || [ "$vn" -lt "$lown" ]; then low="$v"; lown="$vn"; fi
    done
    # shellcheck disable=SC2086 # one argument per version
    runs="$(_gradle_jdks $GRADLE_WRAPPER_VERSIONS)"
    if [ -z "$runs" ]; then
        JAVA_PICK_WRAPPER_CONFLICT="true"
        runs="$(_gradle_jdks "$low")"
    fi
    case " $runs " in
        *" $JAVA_PICK_TOOLCHAIN "*)
            JAVA_PICK_JDK="$JAVA_PICK_TOOLCHAIN"
            [ "$JAVA_PICK_JDK" = "$CDXGEN_JAVA_DEFAULT" ] || JAVA_PICK_WHY="toolchain"
            return 0 ;;
        *" $CDXGEN_JAVA_DEFAULT "*) JAVA_PICK_JDK="$CDXGEN_JAVA_DEFAULT" ;;
        *) JAVA_PICK_JDK="${runs##* }" ;;
    esac
    if [ -n "$JAVA_PICK_TOOLCHAIN" ]; then
        if _java_has_image "$JAVA_PICK_TOOLCHAIN"; then JAVA_PICK_WHY="conflict"; else JAVA_PICK_WHY="no-image"; fi
    fi
    return 0
}

# CDXGEN_JAVA_IMAGE when it is set and reads as an image reference, else
# nothing. The value reaches a docker command line. A ghcr.io/cdxgen/ name
# comes from CDXGEN_IMAGE_PREFIX, like CDXGEN_ALLINONE.
_java_image_override() {
    case "${CDXGEN_JAVA_IMAGE:-}" in
        [A-Za-z0-9]*) case "$CDXGEN_JAVA_IMAGE" in *[!A-Za-z0-9._/:@-]*) return 0 ;; esac
            case "$CDXGEN_JAVA_IMAGE" in
                ghcr.io/cdxgen/*) echo "${CDXGEN_IMAGE_PREFIX}${CDXGEN_JAVA_IMAGE#ghcr.io/cdxgen/}" ;;
                *) echo "$CDXGEN_JAVA_IMAGE" ;;
            esac ;;
    esac
}

# _java_toolchain_warn <version> <what the image has> <what to do>
_java_toolchain_warn() {
    echo "[WARN] The Gradle build declares a Java $1 toolchain, and $2."
    echo "[WARN]   Gradle needs a Java $1 JDK, so dependency resolution can fail unless the build configures toolchain auto-provisioning."
    echo "[WARN]   $3"
}

# java_image_note <dir>: the lines that say why img_for_lang picked the Java
# image it did for <dir>; nothing for the default image when nothing in the
# build asked for another.
java_image_note() {
    local f
    if [ -n "${CDXGEN_JAVA_IMAGE:-}" ]; then
        if [ -n "$(_java_image_override)" ]; then
            echo "[INFO] Java image from CDXGEN_JAVA_IMAGE: $(_java_image_override)"
            return 0
        fi
        echo "[WARN] CDXGEN_JAVA_IMAGE is not an image reference and is ignored: $CDXGEN_JAVA_IMAGE"
    fi
    _java_choose "${1:-}"
    local tc="$JAVA_PICK_TOOLCHAIN" w="$JAVA_PICK_WRAPPER" j="$JAVA_PICK_JDK"
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        echo "[INFO] The Gradle wrapper version could not be read from $f (distributionUrl); the Java image is chosen without it."
    done <<EOF
$JAVA_PICK_UNREADABLE
EOF
    if [ -n "$JAVA_PICK_WRAPPER_CONFLICT" ]; then
        echo "[WARN] No cdxgen Java image runs every Gradle wrapper in this tree (Gradle $w); using the cdxgen Java $j image, chosen for the lowest one."
        echo "[WARN]   The other builds can fail to resolve their dependencies. Scan them on their own, or set CDXGEN_JAVA_IMAGE to an image with a JDK they all run on."
    fi
    case "$JAVA_PICK_WHY" in
        toolchain)
            echo "[INFO] The Gradle build declares a Java $tc toolchain; using the cdxgen Java $j image." ;;
        conflict)
            echo "[WARN] The Gradle build declares a Java $tc toolchain, but its wrapper (Gradle $w) cannot run on Java $tc; using the cdxgen Java $j image, which it runs on."
            echo "[WARN]   Gradle needs a Java $tc JDK too, so dependency resolution can fail unless the build configures toolchain auto-provisioning."
            echo "[WARN]   Set CDXGEN_JAVA_IMAGE to an image with a JDK Gradle $w runs on and a Java $tc JDK." ;;
        no-image)
            _java_toolchain_warn "$tc" "the cdxgen Java image has Java $j" \
                "Set CDXGEN_JAVA_IMAGE to an image that has a Java $tc JDK." ;;
    esac
    if [ -n "$w" ] && [ "$j" != "$CDXGEN_JAVA_DEFAULT" ] && [ "$JAVA_PICK_WHY" != toolchain ]; then
        echo "[INFO] The Gradle wrapper (Gradle $w) cannot run on Java $CDXGEN_JAVA_DEFAULT; using the cdxgen Java $j image."
    fi
}

# java_retry_image <dir> <stage-1 log> <image used>: sets JAVA_RETRY_IMAGE to
# the cdxgen Java image to run stage 1 again in, or to nothing. Stage 1's build-prep.sh writes
# "java-toolchain-missing=N" when Gradle failed for want of a Java N
# toolchain, which covers a version this file cannot read (a version catalog,
# a convention plugin's own logic). Sets JAVA_RETRY_JDK to N. Nothing when
# CDXGEN_JAVA_IMAGE names the image, when no published image has Java N, when
# that image is the one used, or when a Gradle wrapper of <dir> cannot run on
# Java N (the second run would fail too).
java_retry_image() {
    local n img
    JAVA_RETRY_IMAGE=""; JAVA_RETRY_JDK=""
    [ -z "$(_java_image_override)" ] || return 0
    [ -f "${2:-}" ] || return 0
    n="$(grep -oE '^\[build-prep\] gradle-[a-z-]+: .*\(java-toolchain-missing=[0-9]+\)' "$2" 2>/dev/null \
        | grep -oE '[0-9]+\)$' | tr -d ')' | grep -E '^[0-9]{1,3}$' | sed 's/^0*\([0-9]\)/\1/' | sort -n | tail -1)" || n=""
    [ -n "$n" ] && _java_has_image "$n" || return 0
    gradle_wrappers "${1:-}"
    # shellcheck disable=SC2086 # one argument per version
    case " $(_gradle_jdks $GRADLE_WRAPPER_VERSIONS) " in *" $n "*) ;; *) return 0 ;; esac
    img="${CDXGEN_IMAGE_PREFIX}$(_java_image_name "$n"):$CDXGEN_TAG"
    [ "$img" != "${3:-}" ] || return 0
    # shellcheck disable=SC2034  # read by the caller after the call
    {
        JAVA_RETRY_IMAGE="$img"
        JAVA_RETRY_JDK="$n"
    }
}

# java_retry_image_ready <image>: true when the image is here or a pull of it
# succeeds now, for the web UI (the CLI uses its _optin_image_ready, which
# does the same). The pull shows docker's own progress. SBOM_PULL=never only
# looks, so an offline run does not try; SBOM_PULL=always pulls a present
# image too and uses the local copy when that pull fails.
java_retry_image_ready() {
    if [ "${SBOM_PULL:-missing}" != always ] && docker image inspect "$1" >/dev/null 2>&1; then
        return 0
    fi
    [ "${SBOM_PULL:-missing}" != never ] || return 1
    echo "[INFO] Pulling $1..."
    docker pull "$1" && return 0
    [ "${SBOM_PULL:-missing}" = always ] && docker image inspect "$1" >/dev/null 2>&1 || return 1
    echo "[WARN] Could not pull $1 (SBOM_PULL=always); using the copy already here."
}

# java_mixed_note <dir>: a mixed tree runs in the all-in-one image, whatever
# the toolchain. Warn when a Gradle build in it declares one other than the
# default Java image's.
java_mixed_note() {
    local v
    v="$(java_toolchain_version "${1:-}")"
    [ -n "$v" ] && [ "$v" != "$CDXGEN_JAVA_DEFAULT" ] || return 0
    _java_toolchain_warn "$v" "this mixed-language tree is scanned in the cdxgen all-in-one image, which may not have that JDK" \
        "Scan the Java project's folder on its own, with CDXGEN_JAVA_IMAGE naming an image that has a Java $v JDK if no published one does."
}

# img_for_lang <lang> [dir]: the cdxgen image for a detected language. For
# java, <dir> is the scanned tree, and the image follows its Gradle toolchain
# and wrapper (_java_choose). CDXGEN_JAVA_IMAGE, a full image reference, wins.
img_for_lang() {
    local p="$CDXGEN_IMAGE_PREFIX" v=""
    case "$1" in
        rust)   echo "${p}cdxgen-debian-rust:$CDXGEN_TAG" ;;
        go)     echo "${p}cdxgen-debian-golang124:$CDXGEN_TAG" ;;
        ruby)   echo "${p}cdxgen-debian-ruby34:$CDXGEN_TAG" ;;
        java)   v="$(_java_image_override)"
                if [ -n "$v" ]; then echo "$v"; return 0; fi
                _java_choose "${2:-}"
                echo "${p}$(_java_image_name "$JAVA_PICK_JDK"):$CDXGEN_TAG" ;;
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
