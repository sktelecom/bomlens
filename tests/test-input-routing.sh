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

echo "== an installer is recognized as needing to be unpacked =="

# A file target that is not firmware goes to BINARY mode, which reads the file
# itself and never unpacks it. For an installer that is almost nothing: the
# components are inside. Measured on a desktop media player's own downloads —
# the Windows installer yields 1 component read as a file and 39 unpacked, the
# macOS disk image 0 and 25.
#
# The reverse case is why the list is closed and each entry measured: an RPM
# yields 1 component read as a file and 0 unpacked, because syft reads the
# package header directly and unpacking throws that header away.
eval "$(extract_fn needs_unpacking)"

# `file` reports a Windows installer as a PE executable. A bare MZ stub is not
# enough — it reads as a plain DOS executable — so the fixture carries the pointer
# at 0x3C and the PE header it points at, which is what makes a real installer
# report PE32.
python3 - "$WORK/setup.exe" <<'MKEXE'
import struct, sys
d = bytearray(b"MZ" + b"\x00" * 0x3a)
d[0x3c:0x40] = struct.pack("<I", 0x40)
d += b"PE\x00\x00"
d += struct.pack("<HHIIIHH", 0x014c, 1, 0, 0, 0, 0xe0, 0x0102)   # COFF header
d += struct.pack("<HBB", 0x010b, 14, 0)                          # PE32 optional header
d += b"\x00" * 200
open(sys.argv[1], "wb").write(bytes(d))
MKEXE
if needs_unpacking "$WORK/setup.exe"; then
    pass "a Windows installer is routed to the unpacking path"
else
    fail "a Windows installer was left to be read as a single file" \
         "file says: $(file -b "$WORK/setup.exe" 2>/dev/null)"
fi

# A macOS disk image: `file` names the compression, not the container, so the
# magic check has to accept that rather than look for "Apple Disk Image" only.
printf 'hello disk image payload, compressed below\n' > "$WORK/payload"
bzip2 -c "$WORK/payload" > "$WORK/App.dmg"
if needs_unpacking "$WORK/App.dmg"; then
    pass "a macOS disk image is routed to the unpacking path"
else
    fail "a macOS disk image was left to be read as a single file" \
         "file says: $(file -b "$WORK/App.dmg" 2>/dev/null)"
fi

# The extension alone must not decide it. An uploader controls the name, and a
# text file called .exe is not an installer.
printf 'just text, not an executable\n' > "$WORK/notreally.exe"
if needs_unpacking "$WORK/notreally.exe"; then
    fail "the extension alone routed a text file to the unpacking path"
else
    pass "content decides, not the extension"
fi

# An app package holds its components inside, the same as an installer, and a
# supplier submitting one gives the file and nothing else. Read as a single file
# it yields nothing at all: 0 components against 54 once unpacked.
if command -v zip >/dev/null 2>&1; then
    mkdir -p "$WORK/apkroot/META-INF"
    printf '1.8.0\n' > "$WORK/apkroot/META-INF/androidx.activity_activity.version"
    (cd "$WORK/apkroot" && zip -q -r "$WORK/app.apk" .)
    cp "$WORK/app.apk" "$WORK/app.ipa"
    if needs_unpacking "$WORK/app.apk"; then
        pass "an Android app package is routed to the unpacking path"
    else
        fail "an app package was read as a single file" \
             "file says: $(file -b "$WORK/app.apk" 2>/dev/null)"
    fi
    if needs_unpacking "$WORK/app.ipa"; then
        pass "an iOS app package is routed to the unpacking path"
    else
        fail "an iOS app package was read as a single file"
    fi
    # The extension is what says this zip is an app, so an ordinary zip must not
    # be dragged along with it — a source archive has its own path.
    cp "$WORK/app.apk" "$WORK/plain.zip"
    if needs_unpacking "$WORK/plain.zip"; then
        fail "an ordinary zip was routed to the unpacking path"
    else
        pass "an ordinary zip keeps the path it had"
    fi
else
    echo "  SKIP: zip not available for the app package checks"
fi

# Formats that are better read as a file stay that way. An RPM measured worse
# through the unpacking path, so it must not be caught by this rule.
printf '\355\253\356\333\003\000\000\000' > "$WORK/pkg.rpm"
head -c 512 /dev/zero >> "$WORK/pkg.rpm"
if needs_unpacking "$WORK/pkg.rpm"; then
    fail "an RPM was routed to the unpacking path, where it yields less"
else
    pass "an RPM is still read as a file, which is where it yields more"
fi

# Firmware still wins: is_firmware runs first in the dispatcher, and a .bin must
# not depend on this rule to reach the firmware path.
eval "$(extract_fn is_firmware)"
printf 'hsqs' > "$WORK/fw.bin"
head -c 512 /dev/zero >> "$WORK/fw.bin"
if is_firmware "$WORK/fw.bin"; then
    pass "firmware recognition is unchanged and still decides first"
else
    fail "a squashfs .bin is no longer recognized as firmware"
fi

# The dispatcher must consult the rule, and must not send an installer to the
# unpacking path when the image that does the unpacking is absent.
if grep -q 'elif needs_unpacking "$TARGET"' "$SCRIPT"; then
    pass "the dispatcher consults the rule"
else
    fail "the dispatcher does not consult needs_unpacking" \
         "the tested rule is not the one that runs"
fi
if awk '/elif needs_unpacking/,/^        else$/' "$SCRIPT" | grep -q 'docker image inspect "\$FIRMWARE_IMAGE"'; then
    pass "the unpacking path is taken only when the image that unpacks is present"
else
    fail "an installer is routed to the unpacking path without checking for the image" \
         "the scan would fail instead of reading the file as before"
fi
if awk '/elif needs_unpacking/,/^        else$/' "$SCRIPT" | grep -q 'docker pull'; then
    pass "the fallback says how to get the image that unpacks"
else
    fail "the fallback does not say how to unpack" \
         "a near-empty result would read as the answer"
fi

echo
echo "== language detection: what counts as a Python project =="
# The defect: detection looked for requirements.txt and pyproject.toml only, so a
# project shipping setup.py -- still how a lot of scientific Python is packaged --
# came out "unknown". That did two things at once: it sent the tree to the
# all-in-one image instead of the Python one, and it told the user no manifest was
# found while the scan went on to resolve dependencies anyway. On Cellpose the
# wrong image found 46 components; the Python one finds 113, with the
# vulnerabilities the sparse run reported as none.
# shellcheck source=../docker/lib/source-detect.sh
. "$ROOT_DIR/docker/lib/source-detect.sh"
LANGDIR="$(mktemp -d)"
trap 'rm -rf "$LANGDIR"' EXIT

for manifest in requirements.txt pyproject.toml setup.py setup.cfg Pipfile; do
    rm -rf "${LANGDIR:?}/proj" && mkdir -p "$LANGDIR/proj"
    : > "$LANGDIR/proj/$manifest"
    got="$(detect_lang "$LANGDIR/proj")"
    if [ "$got" = "python" ]; then
        pass "$manifest detects as python"
    else
        fail "$manifest detects as '$got'" "a Python project would be scanned with the wrong image"
    fi
done

# A tree with no manifest at all still has to read as unknown: that is what the
# all-in-one image and the vendored-code suggestion are for.
rm -rf "${LANGDIR:?}/proj" && mkdir -p "$LANGDIR/proj"
: > "$LANGDIR/proj/main.c"
got="$(detect_lang "$LANGDIR/proj")"
[ "$got" = "unknown" ] && pass "a tree with no manifest stays unknown" \
    || fail "a manifest-less tree detects as '$got'"

# Detection stays per-language: a Python manifest beside another language's is
# "mixed", not python, so the all-in-one image is chosen as before.
rm -rf "${LANGDIR:?}/proj" && mkdir -p "$LANGDIR/proj"
: > "$LANGDIR/proj/setup.py"
: > "$LANGDIR/proj/go.mod"
got="$(detect_lang "$LANGDIR/proj")"
[ "$got" = "mixed" ] && pass "setup.py beside another language reads as mixed" \
    || fail "a mixed tree detects as '$got'"

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
