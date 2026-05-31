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
cd "$SRC" 2>/dev/null || exit 0

log() { echo "[build-prep] $*"; }

# Rust — cdxgen does NOT auto-run cargo; lockfile is essential for transitive deps
if [ -f Cargo.toml ] && command -v cargo >/dev/null 2>&1; then
    log "cargo generate-lockfile"
    cargo generate-lockfile 2>/dev/null
fi

# Go — generate go.sum / module graph
if [ -f go.mod ] && command -v go >/dev/null 2>&1; then
    log "go mod download"
    GOFLAGS="-mod=mod" go mod download 2>/dev/null
fi

# Ruby — ensure a lockfile exists (cdxgen ruby images usually auto-resolve,
# but a Gemfile.lock makes it deterministic)
if [ -f Gemfile ] && [ ! -f Gemfile.lock ] && command -v bundle >/dev/null 2>&1; then
    log "bundle lock"
    bundle lock 2>/dev/null || bundle install 2>/dev/null
fi

# Maven — resolve when no reactor output present (cdxgen usually handles pom.xml,
# this is a light safety net)
if [ -f pom.xml ] && command -v mvn >/dev/null 2>&1; then
    log "mvn dependency:resolve"
    mvn -q -o dependency:resolve 2>/dev/null || mvn -q dependency:resolve 2>/dev/null
fi

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

# --- locate cdxgen (path differs per image) and generate the SBOM ---
if command -v cdxgen >/dev/null 2>&1; then
    log "cdxgen (PATH)"
    cdxgen -r --spec-version "$SPEC" -o "$OUT" "$SRC"
elif [ -f /opt/cdxgen/bin/cdxgen.js ]; then
    log "cdxgen (/opt/cdxgen/bin/cdxgen.js)"
    node /opt/cdxgen/bin/cdxgen.js -r --spec-version "$SPEC" -o "$OUT" "$SRC"
elif [ -f /opt/bin/cdxgen ]; then
    log "cdxgen (/opt/bin/cdxgen)"
    /opt/bin/cdxgen -r --spec-version "$SPEC" -o "$OUT" "$SRC"
else
    echo "[build-prep] ERROR: cdxgen not found in image" >&2
    exit 1
fi
