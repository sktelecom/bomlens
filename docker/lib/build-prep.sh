#!/bin/sh
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# build-prep.sh — run INSIDE a cdxgen image (mounted from host): augment the
# build so transitive deps surface, then invoke cdxgen.
#
#   Usage: sh build-prep.sh <SRC_DIR> <OUTPUT_FILE> [SPEC_VERSION]
#
# Why: cdxgen does not auto-resolve transitive deps for some ecosystems
# (notably Rust, Go). Generating the lockfile / downloading modules first lets
# cdxgen surface the full dependency graph. cdxgen's binary path differs between
# images (all-in-one /opt/bin/cdxgen vs language images /opt/cdxgen/bin/cdxgen.js),
# so we auto-detect it here.
#
# POSIX sh (cdxgen images ship /bin/sh). Best-effort: never fail on prep.
set +e

SRC="${1:-/app}"
OUT="${2:-$SRC/bom.json}"
SPEC="${3:-1.6}"
# Ensure HOME exists & is writable (maven/cargo/etc. caches) for any base user.
mkdir -p "${HOME:-/tmp/sbomhome}" 2>/dev/null || true
cd "$SRC" 2>/dev/null || exit 0

log() { echo "[build-prep] $*"; }

# Rust — cdxgen does NOT auto-run cargo; lockfile is essential for transitive deps
if [ -f Cargo.toml ] && command -v cargo >/dev/null 2>&1; then
    log "cargo generate-lockfile"
    cargo generate-lockfile 2>/dev/null
fi

# Go — complete go.sum so cdxgen's default-readonly `go list -deps` resolves the
# full transitive graph. Plain `go mod download` leaves go.sum missing entries
# that readonly `go list` requires (it then fails and cdxgen falls back to parsing
# go.mod = direct deps only). `go mod tidy` populates go.sum fully; fall back to
# download if tidy can't run (e.g. no network to fix an inconsistent go.mod).
if [ -f go.mod ] && command -v go >/dev/null 2>&1; then
    log "go mod tidy"
    GOFLAGS="-mod=mod" go mod tidy 2>/dev/null || GOFLAGS="-mod=mod" go mod download 2>/dev/null
fi

# Ruby — ensure a lockfile exists (cdxgen ruby images usually auto-resolve,
# but a Gemfile.lock makes it deterministic)
if [ -f Gemfile ] && [ ! -f Gemfile.lock ] && command -v bundle >/dev/null 2>&1; then
    log "bundle lock"
    bundle lock 2>/dev/null || bundle install 2>/dev/null
fi

# Maven — no pre-resolve step. cdxgen invokes maven itself (dependency:tree /
# the cyclonedx plugin) to build the full transitive graph, so a separate
# `mvn dependency:resolve` here is redundant. It also failed noisily: the run is
# pinned to -Dmaven.repo.local=/tmp/sbomhome/.m2 (an empty repo), so maven could
# not resolve the dependency-plugin prefix and printed a NoPluginFoundForPrefix
# error to stdout on every Java scan. Dropping it removes that noise with no
# effect on the SBOM — cdxgen alone already resolves transitive deps (verified:
# the same scan yields 91 components with this step gone).

# Gradle (java-gradle / Android) — resolve so cdxgen sees the full graph.
# For Android, ANDROID_HOME is set in the android-sdk image, enabling AGP.
if { [ -f build.gradle ] || [ -f build.gradle.kts ]; } && command -v gradle >/dev/null 2>&1; then
    log "gradle dependencies"
    if [ -x ./gradlew ]; then
        ./gradlew --no-daemon dependencies >/dev/null 2>&1 || true
    else
        gradle --no-daemon dependencies >/dev/null 2>&1 || true
    fi
fi

# Python — install into a venv so transitive deps are visible (requirements.txt
# without a lockfile)
if [ -f requirements.txt ] && command -v pip3 >/dev/null 2>&1; then
    log "pip install requirements"
    pip3 install -q -r requirements.txt 2>/dev/null \
      || pip3 install -q --break-system-packages -r requirements.txt 2>/dev/null
fi

# Swift / SPM — cdxgen marks swift transitive as unsupported; resolve generates
# Package.resolved so cdxgen sees the graph. CocoaPods (Podfile.lock) needs no
# prep (cdxgen parses the lockfile). NOTE: iOS-platform (UIKit) / Xcode-driven
# resolution needs macOS — on Linux only non-platform Swift deps resolve.
if [ -f Package.swift ] && command -v swift >/dev/null 2>&1; then
    log "swift package resolve"
    swift package resolve >/dev/null 2>&1 || true
fi

# --- build the cdxgen argument list (shared across the per-image binary paths) ---
# Pass the caller's project name/version up front so the root component carries a
# unique identity instead of cdxgen's scan-path default (src@latest), which collides
# in Black Duck. PROJECT_NAME/PROJECT_VERSION arrive via `docker run -e`. Build the
# list with `set --` (not ${VAR:+...}) so a name with spaces stays one argument.
# stamp-metadata.sh still overwrites this post-hoc as the final guarantee (it also
# covers the syft fallback path), so an unknown flag here cannot break the SBOM.
set -- -r --spec-version "$SPEC" -o "$OUT"
[ -n "$PROJECT_NAME" ]    && set -- "$@" --project-name "$PROJECT_NAME"
[ -n "$PROJECT_VERSION" ] && set -- "$@" --project-version "$PROJECT_VERSION"
set -- "$@" "$SRC"

# --- locate cdxgen (path differs per image) and generate the SBOM ---
if command -v cdxgen >/dev/null 2>&1; then
    log "cdxgen (PATH)"
    cdxgen "$@"
elif [ -f /opt/cdxgen/bin/cdxgen.js ]; then
    log "cdxgen (/opt/cdxgen/bin/cdxgen.js)"
    node /opt/cdxgen/bin/cdxgen.js "$@"
elif [ -f /opt/bin/cdxgen ]; then
    log "cdxgen (/opt/bin/cdxgen)"
    /opt/bin/cdxgen "$@"
else
    echo "[build-prep] ERROR: cdxgen not found in image" >&2
    exit 1
fi
