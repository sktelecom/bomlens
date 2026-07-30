#!/bin/bash
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# test-input-routing.sh — No-Docker unit tests for how scan-sbom.sh decides what
# an archive actually holds.
#
# The defect these guard: an archive was routed by extension alone, so a root
# filesystem shipped as a .zip and a `docker save` .tar were both extracted and
# scanned as source. Neither has a manifest to read, so both reported nothing
# while a binary scanner found dozens of components in the same bytes.
#
# The helpers are lifted out of scan-sbom.sh rather than re-implemented, so this
# tests the shipping code. Extraction is by function name, from the `name() {`
# line to the first line that is exactly `}`.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/scan-sbom.sh"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; [ -n "${2:-}" ] && echo "        $2"; FAIL=$((FAIL + 1)); return 0; }

extract_fn() {
    awk -v fn="$1" '
        $0 ~ "^" fn "\\(\\) \\{" { inside = 1 }
        inside { print }
        inside && $0 == "}" { exit }
    ' "$SCRIPT"
}

for fn in _is_rootfs_dir find_rootfs_dir has_package_db is_container_archive is_archive; do
    body="$(extract_fn "$fn")"
    if [ -z "$body" ]; then
        echo "[ERROR] could not lift $fn out of scan-sbom.sh (was it renamed?)"; exit 1
    fi
    eval "$body"
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== a root filesystem is recognized wherever it sits in the tree =="

mkdir -p "$WORK/flat"/{etc,bin,sbin,usr,lib}
if find_rootfs_dir "$WORK/flat" >/dev/null; then
    pass "rootfs packed at the archive root"
else
    fail "rootfs at the archive root was not recognized"
fi

# Deliveries are usually wrapped: nat-rootfs-20260719/rootfs/{etc,bin,...}
mkdir -p "$WORK/wrapped/release/rootfs"/{etc,bin,usr}
if [ "$(find_rootfs_dir "$WORK/wrapped")" = "$WORK/wrapped/release/rootfs" ]; then
    pass "rootfs two levels down is found, and its own path is returned"
else
    fail "wrapped rootfs was not found at depth 2" "got: $(find_rootfs_dir "$WORK/wrapped" || echo none)"
fi

echo "== a source tree is not mistaken for a root filesystem =="

# `etc/` plus one system-looking directory is ordinary in source repositories;
# routing those to ROOTFS would silently stop scanning their manifests.
mkdir -p "$WORK/src"/{etc,lib,src}
printf '{}\n' > "$WORK/src/package.json"
if find_rootfs_dir "$WORK/src" >/dev/null; then
    fail "a source tree with etc/ and lib/ was routed to ROOTFS"
else
    pass "etc/ plus a single system directory stays source"
fi

mkdir -p "$WORK/nodeps/src"
if find_rootfs_dir "$WORK/nodeps" >/dev/null; then
    fail "a plain source tree was routed to ROOTFS"
else
    pass "a tree without etc/ stays source"
fi

echo "== the package database decides which scanner can say anything =="

mkdir -p "$WORK/apk"/{etc,bin,usr,lib/apk/db}
: > "$WORK/apk/lib/apk/db/installed"
if has_package_db "$WORK/apk"; then
    pass "apk database detected"
else
    fail "apk database not detected"
fi

mkdir -p "$WORK/deb"/{etc,bin,var/lib/dpkg}
: > "$WORK/deb/var/lib/dpkg/status"
if has_package_db "$WORK/deb"; then
    pass "dpkg database detected"
else
    fail "dpkg database not detected"
fi

if has_package_db "$WORK/flat"; then
    fail "a rootfs with no package manager was reported as having one"
else
    pass "hand-built rootfs correctly reports no package database"
fi

echo "== a container image archive is not unpacked as source =="

# OCI layout, which is what current `docker save` writes.
mkdir -p "$WORK/oci/blobs/sha256"
: > "$WORK/oci/blobs/sha256/deadbeef"
printf '[]\n' > "$WORK/oci/manifest.json"
printf '{}\n' > "$WORK/oci/oci-layout"
( cd "$WORK/oci" && tar -cf "$WORK/image-oci.tar" . )
if is_container_archive "$WORK/image-oci.tar"; then
    pass "OCI-layout docker save tar recognized"
else
    fail "OCI-layout docker save tar not recognized"
fi

# Legacy layout, still produced by older daemons and by `docker save` on some
# registries: per-layer tarballs beside the manifest.
mkdir -p "$WORK/legacy/abc123"
: > "$WORK/legacy/abc123/layer.tar"
printf '[]\n' > "$WORK/legacy/manifest.json"
( cd "$WORK/legacy" && tar -cf "$WORK/image-legacy.tar" . )
if is_container_archive "$WORK/image-legacy.tar"; then
    pass "legacy layer.tar docker save tar recognized"
else
    fail "legacy docker save tar not recognized"
fi

# A source tarball that happens to contain a manifest.json must not be taken for
# an image, or its manifests stop being scanned.
mkdir -p "$WORK/websrc/app"
printf '{}\n' > "$WORK/websrc/app/manifest.json"
printf '{}\n' > "$WORK/websrc/app/package.json"
( cd "$WORK/websrc" && tar -cf "$WORK/websrc.tar" . )
if is_container_archive "$WORK/websrc.tar"; then
    fail "a web app tarball with a manifest.json was taken for a container image"
else
    pass "manifest.json alone does not make an archive a container image"
fi

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
