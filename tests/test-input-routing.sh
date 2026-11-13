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

for fn in _is_rootfs_dir find_rootfs_dir nested_rootfs_hint has_package_db is_container_archive is_archive \
          is_firmware has_source_manifest release_folder_candidates release_folder_firmware_file \
          release_folder_app_entry release_folder_vetoed release_folder_large_files; do
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

echo "== nested_rootfs_hint: naming a nested rootfs without changing routing =="

# A directory --target that is itself a rootfs already routes to ROOTFS on its
# own (_is_rootfs_dir), so the hint -- meant only for the SOURCE branch's
# 0-components diagnostic -- has nothing to add there.
if nested_rootfs_hint "$WORK/flat" >/dev/null; then
    fail "nested_rootfs_hint returned something for a directory that is itself a rootfs"
else
    pass "a directory that is itself a rootfs gets no hint (nothing to add)"
fi

# The common wrapped-delivery shape, relative to the folder the user pointed
# --target at -- what a re-run's --target would need appended.
mkdir -p "$WORK/delivery/release-20260919/rootfs"/{etc,bin,usr}
if [ "$(nested_rootfs_hint "$WORK/delivery")" = "release-20260919/rootfs" ]; then
    pass "a rootfs one release-folder down is named, relative to --target"
else
    fail "nested_rootfs_hint did not find the wrapped rootfs" \
        "got: $(nested_rootfs_hint "$WORK/delivery" || echo none)"
fi

mkdir -p "$WORK/onelevel/rootfs"/{etc,bin,var}
if [ "$(nested_rootfs_hint "$WORK/onelevel")" = "rootfs" ]; then
    pass "a rootfs one level down is named"
else
    fail "nested_rootfs_hint did not find a one-level-down rootfs" \
        "got: $(nested_rootfs_hint "$WORK/onelevel" || echo none)"
fi

# No nested rootfs anywhere -- no hint, same as an ordinary source tree.
if nested_rootfs_hint "$WORK/nodeps" >/dev/null; then
    fail "nested_rootfs_hint invented a candidate where none exists"
else
    pass "an ordinary source tree with nothing nested gets no hint"
fi

echo "== release folders: only a folder with no source of its own is rerouted =="

# release_folder_candidates looks at direct children only, skips symlinks, and
# names each candidate by kind.
mkdir -p "$WORK/rel/images/rootfs"/{etc,bin,usr} "$WORK/rel/images/install"
printf 'blob\n' > "$WORK/rel/images/dev.ubi"
ln -s / "$WORK/rel/images/hostroot" 2>/dev/null || true
cands="$(release_folder_candidates "$WORK/rel/images")"
if [ "$(printf '%s\n' "$cands" | grep -c .)" = 2 ] \
   && printf '%s\n' "$cands" | grep -qx "rootfs	$WORK/rel/images/rootfs" \
   && printf '%s\n' "$cands" | grep -qx "firmware	$WORK/rel/images/dev.ubi"; then
    pass "a rootfs folder and a firmware file are both named, a symlink to / is not"
else
    fail "release_folder_candidates" "got: $cands"
fi
if has_source_manifest "$WORK/rel/images"; then
    fail "a folder of build artifacts was taken for a source tree"
else
    pass "a folder of build artifacts has no source manifest"
fi
missed=""
for m in package.json pom.xml go.mod Cargo.toml requirements.txt CMakeLists.txt Makefile meson.build App.csproj; do
    mkdir -p "$WORK/srcm-$m"; : > "$WORK/srcm-$m/$m"
    has_source_manifest "$WORK/srcm-$m" || missed="$missed $m"
done
if [ -z "$missed" ]; then
    pass "a top-level manifest or build file marks a folder as source"
else
    fail "these at the top level were not read as source:$missed"
fi
mkdir -p "$WORK/gitrepo/.git"
has_source_manifest "$WORK/gitrepo" && pass "a git checkout counts as source" \
    || fail "a git checkout was not read as source"

# A .bix image is a firmware container `file` reports only as "data".
printf 'opaque\n' > "$WORK/dev-1.0.bix"
is_firmware "$WORK/dev-1.0.bix" && pass ".bix is recognized as a firmware image" \
    || fail ".bix was not recognized as a firmware image"

# The folder from a lab delivery: rootfs/, install/, a kernel and a .bix image.
# The kernel is not a candidate, so the two left are listed.
mkdir -p "$WORK/lab/rootfs"/{etc,bin,usr,lib} "$WORK/lab/install"
printf 'kernel\n' > "$WORK/lab/vmlinuz"; printf 'opaque\n' > "$WORK/lab/dev-1.0.bix"
cands="$(release_folder_candidates "$WORK/lab")"
if [ "$(printf '%s\n' "$cands" | grep -c .)" = 2 ] \
   && printf '%s\n' "$cands" | grep -qx "rootfs	$WORK/lab/rootfs" \
   && printf '%s\n' "$cands" | grep -qx "firmware	$WORK/lab/dev-1.0.bix"; then
    pass "rootfs/, install/, a kernel and a .bix make two candidates"
else
    fail "lab release folder candidates" "got: $cands"
fi

# .bin and .img count by their content only, not by name.
mkdir -p "$WORK/byname"; printf 'blob\n' > "$WORK/byname/dev.bin"; printf 'blob\n' > "$WORK/byname/disk.img"
[ -z "$(release_folder_candidates "$WORK/byname")" ] \
    && pass ".bin and .img with no firmware signature are not candidates" \
    || fail ".bin/.img were taken by name alone" "got: $(release_folder_candidates "$WORK/byname")"
if command -v file >/dev/null 2>&1; then
    mkdir -p "$WORK/bymagic"
    { printf 'hsqs'; head -c 200 /dev/zero; } > "$WORK/bymagic/rootfs.img"
    { printf 'PK\003\004'; head -c 200 /dev/zero; } > "$WORK/bymagic/weights.bin"
    cands="$(release_folder_candidates "$WORK/bymagic")"
    [ "$cands" = "firmware	$WORK/bymagic/rootfs.img" ] \
        && pass "an .img with a squashfs signature is a candidate, a zip named .bin is not" \
        || fail "signature check on .img/.bin" "got: $cands"
fi

# Folders that are not releases, even with a .bin or a firmware-like file in them.
mkdir -p "$WORK/electron/resources/app" "$WORK/electron/locales"
for f in app.exe ffmpeg.dll libGLESv2.dll snapshot_blob.bin v8_context_snapshot.bin resources.pak icudtl.dat; do
    printf 'x\n' > "$WORK/electron/$f"
done
: > "$WORK/electron/resources/app.asar"
[ -z "$(release_folder_candidates "$WORK/electron")" ] && pass "an Electron app folder has no candidates" \
    || fail "an Electron app folder was taken for a release folder" "got: $(release_folder_candidates "$WORK/electron")"
mkdir -p "$WORK/electron-linux"; printf 'x\n' > "$WORK/electron-linux/libffmpeg.so"
printf 'x\n' > "$WORK/electron-linux/snapshot_blob.bin"; printf 'x\n' > "$WORK/electron-linux/update.fw"
[ -z "$(release_folder_candidates "$WORK/electron-linux")" ] && pass "a folder with a top-level .so has no candidates" \
    || fail "a folder with a top-level .so was taken for a release folder"
mkdir -p "$WORK/hfsnap"
printf '{}\n' > "$WORK/hfsnap/config.json"; printf '{}\n' > "$WORK/hfsnap/tokenizer.json"
{ printf 'PK\003\004'; head -c 200 /dev/zero; } > "$WORK/hfsnap/pytorch_model.bin"
printf 'x\n' > "$WORK/hfsnap/model.rom"
[ -z "$(release_folder_candidates "$WORK/hfsnap")" ] && pass "a model snapshot folder has no candidates" \
    || fail "a model snapshot folder was taken for a release folder" "got: $(release_folder_candidates "$WORK/hfsnap")"
mkdir -p "$WORK/staging/usr/lib" "$WORK/staging/bin" "$WORK/staging/lib"
printf 'x\n' > "$WORK/staging/usr/lib/libfoo.so.1"; printf 'x\n' > "$WORK/staging/bin/app"
printf 'x\n' > "$WORK/staging/app.bin"; printf 'x\n' > "$WORK/staging/boot.img"
[ -z "$(release_folder_candidates "$WORK/staging")" ] && pass "a build output staging folder has no candidates" \
    || fail "a staging folder was taken for a release folder" "got: $(release_folder_candidates "$WORK/staging")"
mkdir -p "$WORK/many"; printf 'x\n' > "$WORK/many/dev.trx"
for i in $(seq 1 21); do printf 'x\n' > "$WORK/many/file$i.txt"; done
[ -z "$(release_folder_candidates "$WORK/many")" ] && pass "a folder with more than 20 top-level files has no candidates" \
    || fail "a folder with many files was taken for a release folder"

# Large files beside a rootfs with no package database are offered as firmware
# commands: over 1 MiB only, no symlinks, at most five then a count.
mkdir -p "$WORK/big"
for i in 1 2 3 4 5 6 7; do head -c 1048577 /dev/zero > "$WORK/big/blob$i.pak"; done
head -c 1048576 /dev/zero > "$WORK/big/exactly-1mib.pak"; printf 'x' > "$WORK/big/small.txt"
ln -s "$WORK/big/blob1.pak" "$WORK/big/link.pak" 2>/dev/null || true
head -c 1048577 /dev/zero > "$WORK/big/weights.safetensors"
large="$(release_folder_large_files "$WORK/big")"
if [ "$(printf '%s\n' "$large" | grep -c -- '--firmware')" = 5 ] \
   && printf '%s\n' "$large" | grep -qF -- "--target \"$WORK/big/blob1.pak\" --firmware" \
   && printf '%s\n' "$large" | grep -qF "(and 2 more)" \
   && ! printf '%s\n' "$large" | grep -qE 'small|exactly|link|safetensors'; then
    pass "files over 1 MiB are listed as firmware commands, five at most, model files left out"
else
    fail "release_folder_large_files" "got: $large"
fi
[ -z "$(release_folder_large_files "$WORK/nodeps")" ] && pass "a folder with no large file lists nothing" \
    || fail "release_folder_large_files listed something for a folder without large files"

# This repository's own example projects and test fixtures must keep scanning
# as source: none of them is a folder without source that holds a rootfs or a
# firmware image directly.
hits=""
while IFS= read -r d; do
    _is_rootfs_dir "$d" && continue
    has_source_manifest "$d" && continue
    [ -n "$(release_folder_candidates "$d")" ] && hits="$hits ${d#"$ROOT_DIR"/}"
done < <(find "$ROOT_DIR/examples" "$ROOT_DIR/tests/fixtures" -type d -not -path '*/node_modules/*')
if [ -z "$hits" ]; then
    pass "examples/ and tests/fixtures/ stay source (no release folder among them)"
else
    fail "folders in this repository would be rerouted away from a source scan" "$hits"
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

echo "== language detection: Android and .NET projects laid out below the root =="
# Android was recognized by the Groovy DSL, by the plugin id in a build script,
# or by a manifest at most three levels down, so a Kotlin DSL project, one that
# declares the plugin in a version catalog, and the standard
# app/src/main/AndroidManifest.xml all read as java. .NET looked at the root
# only, so a solution with its projects under src/ read as whatever the root held.
FX="$ROOT_DIR/tests/fixtures"
for fx in android-scope android-kotlin-dsl android-version-catalog; do
    got="$(detect_lang "$FX/$fx")"
    [ "$got" = "android" ] && pass "$fx detects as android" \
        || fail "$fx detects as '$got'" "an Android app would be scanned without the Android SDK image"
done

rm -rf "${LANGDIR:?}/proj" && mkdir -p "$LANGDIR/proj/app/src/main"
printf 'plugins {\n}\n' > "$LANGDIR/proj/build.gradle.kts"
: > "$LANGDIR/proj/app/src/main/AndroidManifest.xml"
got="$(detect_lang "$LANGDIR/proj")"
[ "$got" = "android" ] && pass "a Gradle project with app/src/main/AndroidManifest.xml detects as android" \
    || fail "app/src/main/AndroidManifest.xml under a Gradle root detects as '$got'"

got="$(detect_lang "$FX/dotnet-subfolder")"
[ "$got" = "dotnet" ] && pass "a .slnx solution with projects in src/ and an e2e-only package.json detects as dotnet" \
    || fail "dotnet-subfolder detects as '$got'" "neither the MAUI AndroidManifest.xml nor the e2e package.json may decide the language"

rm -rf "${LANGDIR:?}/proj" && mkdir -p "$LANGDIR/proj/src/App"
printf '{\n  "name": "web",\n  "dependencies": {\n    "express": "^4"\n  }\n}\n' > "$LANGDIR/proj/package.json"
: > "$LANGDIR/proj/src/App/App.csproj"
got="$(detect_lang "$LANGDIR/proj")"
[ "$got" = "mixed" ] && pass "a package.json with dependencies beside a .csproj in a subfolder reads as mixed" \
    || fail "a node app with a .csproj in a subfolder detects as '$got'"

rm -rf "${LANGDIR:?}/proj" && mkdir -p "$LANGDIR/proj"
: > "$LANGDIR/proj/App.slnx"
got="$(detect_lang "$LANGDIR/proj")"
[ "$got" = "dotnet" ] && pass "a root .slnx detects as dotnet" \
    || fail "a root .slnx detects as '$got'"

echo "== a declared Java toolchain picks the cdxgen Java image =="
# A Gradle toolchain asks for that exact JDK, and each cdxgen Java image has one.
# The Java 21 image cannot resolve the dependencies of a build that declares
# Java 25, so the SBOM had none.
unset CDXGEN_JAVA_IMAGE CDXGEN_IMAGE_PREFIX BOMLENS_INCLUDE_NON_SHIPPED
# shellcheck source=../docker/lib/source-detect.sh
. "$ROOT_DIR/docker/lib/source-detect.sh"
J21="ghcr.io/cdxgen/cdxgen-temurin-java21:$CDXGEN_TAG"
J24="ghcr.io/cdxgen/cdxgen-temurin-java24:$CDXGEN_TAG"
J25="ghcr.io/cdxgen/cdxgen-temurin-java25:$CDXGEN_TAG"
java_case() {  # java_case <want> <description> [CDXGEN_JAVA_IMAGE]
    local got
    got="$(CDXGEN_JAVA_IMAGE="${3:-}" img_for_lang java "$LANGDIR/proj")"
    [ "$got" = "$1" ] && pass "$2" || fail "$2" "got '$got', want '$1'"
}
note_case() {  # note_case <description> <note function> <text>...: every text is in the note
    local desc="$1" fn="$2" got t
    shift 2
    got="$("$fn" "$LANGDIR/proj")"
    for t in "$@"; do
        case "$got" in *"$t"*) ;; *) fail "$desc" "no '$t' in: $got"; return 0 ;; esac
    done
    pass "$desc"
}
gradle_tree() {  # gradle_tree <path under proj> <content>
    rm -rf "${LANGDIR:?}/proj" && mkdir -p "$LANGDIR/proj/$(dirname "$1")"
    printf 'rootProject.name = "demo"\n' > "$LANGDIR/proj/settings.gradle.kts"
    printf '%b' "$2" > "$LANGDIR/proj/$1"
}
gradle_tree build.gradle.kts 'plugins { java }\njava {\n    toolchain {\n        languageVersion = JavaLanguageVersion.of(25)\n    }\n}\n'
[ "$(detect_lang "$LANGDIR/proj")" = java ] && pass "the toolchain 25 fixture detects as java" || fail "toolchain fixture is not java"
java_case "$J25" "Kotlin DSL languageVersion = JavaLanguageVersion.of(25) picks the Java 25 image"
note_case "the INFO line names the Java 25 toolchain" java_image_note "[INFO] " "Java 25 toolchain"
[ "$(img_for_lang java)" = "$J21" ] && pass "without a scanned folder, java stays on the Java 21 image" \
    || fail "img_for_lang java with no folder: $(img_for_lang java)"
java_case "registry.example/java25:1" "CDXGEN_JAVA_IMAGE wins over the declared toolchain" "registry.example/java25:1"
java_case "$J25" "a CDXGEN_JAVA_IMAGE that is not an image reference is ignored" 'bad;rm -rf /'
case "$(CDXGEN_JAVA_IMAGE='bad;x' java_image_note "$LANGDIR/proj")" in
    *"[WARN] CDXGEN_JAVA_IMAGE is not an image reference"*) pass "an unusable CDXGEN_JAVA_IMAGE is reported" ;;
    *) fail "an unusable CDXGEN_JAVA_IMAGE is not reported" ;; esac
[ "$(CDXGEN_IMAGE_PREFIX=registry.example/mirror/cdxgen/ img_for_lang java "$LANGDIR/proj")" = "registry.example/mirror/cdxgen/cdxgen-temurin-java25:$CDXGEN_TAG" ] \
    && pass "the Java 25 image comes from CDXGEN_IMAGE_PREFIX too" || fail "the Java 25 image ignores CDXGEN_IMAGE_PREFIX"
[ "$(CDXGEN_IMAGE_PREFIX=registry.example/mirror/cdxgen/ CDXGEN_JAVA_IMAGE="$J24" img_for_lang java "$LANGDIR/proj")" = "registry.example/mirror/cdxgen/cdxgen-temurin-java24:$CDXGEN_TAG" ] \
    && pass "a ghcr.io/cdxgen/ CDXGEN_JAVA_IMAGE comes from CDXGEN_IMAGE_PREFIX" \
    || fail "CDXGEN_JAVA_IMAGE ignores CDXGEN_IMAGE_PREFIX: $(CDXGEN_IMAGE_PREFIX=registry.example/mirror/cdxgen/ CDXGEN_JAVA_IMAGE="$J24" img_for_lang java "$LANGDIR/proj")"

gradle_tree build.gradle.kts 'plugins { java }\njava { toolchain { languageVersion = JavaLanguageVersion.of(21) } }\n'
java_case "$J21" "a Java 21 toolchain stays on the Java 21 image"
[ -z "$(java_image_note "$LANGDIR/proj")" ] && pass "a Java 21 toolchain prints no note" || fail "a Java 21 toolchain prints a note"
gradle_tree build.gradle.kts 'plugins { java }\ndependencies { implementation("a:b:1") }\n'
java_case "$J21" "a build with no toolchain stays on the Java 21 image"
[ -z "$(java_image_note "$LANGDIR/proj")" ] && pass "no toolchain prints no note" || fail "no toolchain prints a note"
gradle_tree build.gradle.kts 'java { toolchain { languageVersion = JavaLanguageVersion.of(24) } }\n'
java_case "$J24" "a Java 24 toolchain picks the Java 24 image"
gradle_tree build.gradle 'java {\n  toolchain {\n    languageVersion.set(JavaLanguageVersion.of("25"))\n  }\n}\n'
java_case "$J25" "Groovy DSL languageVersion.set(JavaLanguageVersion.of(\"25\")) picks the Java 25 image"
gradle_tree build.gradle.kts 'kotlin {\n    jvmToolchain(25)\n}\n'
java_case "$J25" "Kotlin jvmToolchain(25) picks the Java 25 image"
gradle_tree buildSrc/src/main/kotlin/java-conventions.gradle.kts 'java { toolchain { languageVersion.set(JavaLanguageVersion.of(25)) } }\n'
java_case "$J25" "a buildSrc convention plugin's toolchain picks the Java 25 image"
gradle_tree build.gradle.kts 'java {\n    // languageVersion = JavaLanguageVersion.of(25)\n    toolchain { languageVersion = JavaLanguageVersion.of(21) }\n}\n'
java_case "$J21" "a commented-out toolchain line is not read"
gradle_tree build.gradle.kts 'java { toolchain { languageVersion = JavaLanguageVersion.of(21) } } // JavaLanguageVersion.of(25)\n'
java_case "$J21" "a comment at the end of a line is not read"
gradle_tree build.gradle.kts 'java {\n    /* old:\n       languageVersion = JavaLanguageVersion.of(25)\n    */ toolchain { languageVersion = JavaLanguageVersion.of(21) }\n    /* jvmToolchain(24) */\n}\n'
java_case "$J21" "a /* */ block comment, one line or several, is not read"
gradle_tree build.gradle.kts '/* not closed in this file\n'
printf 'kotlin { jvmToolchain(25) }\n' > "$LANGDIR/proj/settings.gradle.kts"
java_case "$J25" "an unclosed block comment does not hide the next file"
python3 -c "import sys; open(sys.argv[1], 'w').write('/*' * 200000)" "$LANGDIR/proj/build.gradle.kts"
t0=$(date +%s); java_case "$J25" "a 400 KB line of comment openers is skipped, not read as a block"
[ $(( $(date +%s) - t0 )) -lt 5 ] && pass "that line is read in under 5 seconds" || fail "a 400 KB comment line took $(( $(date +%s) - t0 ))s"
gradle_tree examples/demo/build.gradle.kts 'kotlin { jvmToolchain(25) }\n'
java_case "$J21" "a toolchain under examples/ (not shipped) is not read"
[ "$(BOMLENS_INCLUDE_NON_SHIPPED=1 img_for_lang java "$LANGDIR/proj")" = "$J25" ] \
    && pass "BOMLENS_INCLUDE_NON_SHIPPED=1 reads the toolchain under examples/ too" \
    || fail "BOMLENS_INCLUDE_NON_SHIPPED=1 does not read examples/"
gradle_tree app/build.gradle.kts 'kotlin { jvmToolchain(21) }\n'
printf 'kotlin { jvmToolchain(25) }\n' > "$LANGDIR/proj/build.gradle.kts"
java_case "$J25" "the highest toolchain across modules decides"

# The older JDKs have images too; the Java 11 and 17 ones are not named temurin.
for v in 8:cdxgen-temurin-java8 11:cdxgen-java11 17:cdxgen-java17; do
    gradle_tree build.gradle.kts "kotlin { jvmToolchain(${v%%:*}) }\n"
    java_case "ghcr.io/cdxgen/${v#*:}:$CDXGEN_TAG" "a Java ${v%%:*} toolchain picks ${v#*:}"
done
[ "$(CDXGEN_IMAGE_PREFIX=registry.example/mirror/cdxgen/ img_for_lang java "$LANGDIR/proj")" = "registry.example/mirror/cdxgen/cdxgen-java17:$CDXGEN_TAG" ] \
    && pass "cdxgen-java17 comes from CDXGEN_IMAGE_PREFIX too" || fail "cdxgen-java17 ignores CDXGEN_IMAGE_PREFIX"
[ "$(CDXGEN_IMAGE_PREFIX=registry.example/mirror/cdxgen/ CDXGEN_JAVA_IMAGE="ghcr.io/cdxgen/cdxgen-java11:$CDXGEN_TAG" img_for_lang java "$LANGDIR/proj")" = "registry.example/mirror/cdxgen/cdxgen-java11:$CDXGEN_TAG" ] \
    && pass "a ghcr.io/cdxgen/cdxgen-java11 CDXGEN_JAVA_IMAGE comes from CDXGEN_IMAGE_PREFIX" \
    || fail "CDXGEN_JAVA_IMAGE=cdxgen-java11 ignores CDXGEN_IMAGE_PREFIX"

# No image has these JDKs: the Java 21 image, with a warning.
for v in 22 23 26; do
    gradle_tree build.gradle.kts "kotlin { jvmToolchain($v) }\n"
    java_case "$J21" "a Java $v toolchain (no image has it) stays on the Java 21 image"
    note_case "a Java $v toolchain warns and points at CDXGEN_JAVA_IMAGE" java_image_note \
        "[WARN] The Gradle build declares a Java $v toolchain, and the cdxgen Java image has Java 21" \
        "auto-provisioning" "CDXGEN_JAVA_IMAGE"
done
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(99999999999999999999) }\n'
java_case "$J21" "an overlong version number is ignored"
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(025) }\n'
java_case "$J25" "a leading zero still reads as the version"

echo "== a Java toolchain taken from a variable is read from its definition =="
# Builds that let CI override the Java version pass a variable with a default;
# the Java 21 image was used for them and Gradle failed without a Java 25 JDK.
J17="ghcr.io/cdxgen/cdxgen-java17:$CDXGEN_TAG"
gradle_tree build.gradle "plugins { id 'java' }\ndef javaVersionProp = project.hasProperty('javaVer') ? project.getProperty('javaVer') : '25'\njava {\n    toolchain {\n        languageVersion = JavaLanguageVersion.of(javaVersionProp.toInteger())\n    }\n}\n"
java_case "$J25" "Groovy: the ternary's default '25' picks the Java 25 image"
printf 'org.gradle.jvmargs=-Xmx2g\njavaVer=17\n' > "$LANGDIR/proj/gradle.properties"
java_case "$J17" "Groovy: javaVer=17 in gradle.properties wins over the default"
gradle_tree build.gradle "def jv = findProperty('jv') ?: '24'\njava.toolchain.languageVersion = JavaLanguageVersion.of(jv)\n"
java_case "$J24" "Groovy: findProperty('jv') ?: '24' picks the Java 24 image"
gradle_tree build.gradle "def jv = project.findProperty('jv') ?: 25\njava.toolchain.languageVersion = JavaLanguageVersion.of(jv as int)\n"
java_case "$J25" "Groovy: project.findProperty(...) ?: 25 with as int"
gradle_tree build.gradle.kts 'val javaVersion = findProperty("javaVersion")?.toString() ?: "25"\njava { toolchain { languageVersion.set(JavaLanguageVersion.of(javaVersion.toInt())) } }\n'
java_case "$J25" "Kotlin: findProperty(...)?.toString() ?: \"25\" picks the Java 25 image"
printf 'javaVersion = 17\n' > "$LANGDIR/proj/gradle.properties"
java_case "$J17" "Kotlin: javaVersion = 17 in gradle.properties wins over the default"
gradle_tree build.gradle.kts 'val jdk = providers.gradleProperty("jdk").get()\nkotlin { jvmToolchain(jdk.toInt()) }\n'
printf 'jdk=25\n' > "$LANGDIR/proj/gradle.properties"
java_case "$J25" "Kotlin: providers.gradleProperty(\"jdk\") reads jdk=25 from gradle.properties"
gradle_tree build.gradle.kts 'val jdk = providers.gradleProperty("jdk").getOrElse("24")\nkotlin { jvmToolchain(jdk.toInt()) }\n'
java_case "$J24" "Kotlin: getOrElse(\"24\") is the default"
gradle_tree build.gradle.kts 'val jdk: String by project\nkotlin { jvmToolchain(jdk.toInt()) }\n'
printf 'jdk=25\n' > "$LANGDIR/proj/gradle.properties"
java_case "$J25" "Kotlin: val jdk: String by project reads jdk=25 from gradle.properties"
gradle_tree app/build.gradle "def v = findProperty('v') ?: '11'\njava.toolchain.languageVersion = JavaLanguageVersion.of(v)\n"
printf 'v=25\n' > "$LANGDIR/proj/gradle.properties"
java_case "$J25" "a module's property is read from the root gradle.properties"
gradle_tree build.gradle.kts 'val jdk = 25\nkotlin { jvmToolchain(jdk) }\n'
java_case "$J25" "a variable set to a number is read"
gradle_tree build.gradle.kts 'val jdk = System.getenv("JDK") ?: "25"\nkotlin { jvmToolchain(jdk.toInt()) }\n'
java_case "$J25" "an environment variable's default is read"
gradle_tree build.gradle.kts 'val jdk = System.getenv("JDK")\nkotlin { jvmToolchain(jdk.toInt()) }\n'
java_case "$J21" "an environment variable with no default is not read"
gradle_tree build.gradle.kts 'val jdk = System.getProperty("jdk") ?: "x"\nkotlin { jvmToolchain(jdk.toInt()) }\n'
printf 'jdk=25\n' > "$LANGDIR/proj/gradle.properties"
java_case "$J21" "System.getProperty is not a Gradle property"
gradle_tree build.gradle.kts '// val jdk = 25\nkotlin { jvmToolchain(jdk) }\n'
java_case "$J21" "a commented-out definition is not read"
gradle_tree build.gradle.kts 'val jdk = 99999\nkotlin { jvmToolchain(jdk) }\n'
java_case "$J21" "an overlong default is ignored"
gradle_tree build.gradle.kts 'val jdk = libs.versions.java.get()\nkotlin { jvmToolchain(jdk.toInt()) }\n'
java_case "$J21" "a version catalog value is not read"
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(jdk.toInt()) }\n'
printf 'val jdk = 25\n' > "$LANGDIR/proj/other.gradle.kts"
java_case "$J21" "a variable of another file is not read"
gradle_tree build.gradle.kts 'val jdk = providers.gradleProperty("jdk").get()\nkotlin { jvmToolchain(jdk.toInt()) }\n'
python3 -c "import sys; open(sys.argv[1], 'w').write('jdk=' + '2' * 5000 + '\njdk=25\n')" "$LANGDIR/proj/gradle.properties"
java_case "$J25" "a gradle.properties line over 4096 characters is skipped"

echo "== the Gradle wrapper's version limits the cdxgen Java image =="
# A wrapper runs only on the JDKs its Gradle supports: a 6.9.4 wrapper fails
# on Java 21 ("Unsupported class file major version 65") and the SBOM had none.
J8="ghcr.io/cdxgen/cdxgen-temurin-java8:$CDXGEN_TAG"
J11="ghcr.io/cdxgen/cdxgen-java11:$CDXGEN_TAG"
J17="ghcr.io/cdxgen/cdxgen-java17:$CDXGEN_TAG"
wrapper_at() {  # wrapper_at <folder under proj, or .> <distribution file> [no-gradlew]
    mkdir -p "$LANGDIR/proj/$1/gradle/wrapper"
    printf 'distributionBase=GRADLE_USER_HOME\ndistributionUrl=https\\://services.gradle.org/distributions/%s\n' "$2" \
        > "$LANGDIR/proj/$1/gradle/wrapper/gradle-wrapper.properties"
    [ -n "${3:-}" ] || printf '#!/bin/sh\n' > "$LANGDIR/proj/$1/gradlew"
}
wrapper_case() {  # wrapper_case <distribution file> <want> <description>
    gradle_tree build.gradle "plugins { id 'java' }\n"
    wrapper_at . "$1"
    java_case "$2" "$3"
}
wrapper_case gradle-4.10.3-bin.zip "$J8" "a Gradle 4.10.3 wrapper picks the Java 8 image"
wrapper_case gradle-5.6.4-all.zip "$J11" "a Gradle 5.6.4 wrapper picks the Java 11 image"
wrapper_case gradle-6.9.4-bin.zip "$J11" "a Gradle 6.9.4 wrapper picks the Java 11 image"
note_case "a Gradle 6.9.4 wrapper says why" java_image_note "[INFO] The Gradle wrapper (Gradle 6.9.4) cannot run on Java 21; using the cdxgen Java 11 image."
wrapper_case gradle-7.2-bin.zip "$J11" "a Gradle 7.2 wrapper picks the Java 11 image"
wrapper_case gradle-7.3-bin.zip "$J17" "a Gradle 7.3 wrapper picks the Java 17 image"
wrapper_case gradle-7.5.1-bin.zip "$J17" "a Gradle 7.5.1 wrapper picks the Java 17 image"
wrapper_case gradle-8.4-bin.zip "$J17" "a Gradle 8.4 wrapper picks the Java 17 image"
wrapper_case gradle-8.5-bin.zip "$J21" "a Gradle 8.5 wrapper stays on the Java 21 image"
[ -z "$(java_image_note "$LANGDIR/proj")" ] && pass "a Gradle 8.5 wrapper prints no note" || fail "a Gradle 8.5 wrapper prints a note"
wrapper_case gradle-9.6.0-bin.zip "$J21" "a Gradle 9.6.0 wrapper stays on the Java 21 image"
wrapper_case gradle-8.0-milestone-1-bin.zip "$J17" "a milestone wrapper counts as its release"
wrapper_case gradle-9.0-rc-1-all.zip "$J21" "a release candidate wrapper counts as its release"
gradle_tree build.gradle "plugins { id 'java' }\n"
wrapper_at . gradle-6.9.4-bin.zip no-gradlew
java_case "$J21" "a wrapper with no gradlew beside it is not used (the image's Gradle runs)"

# Toolchain and wrapper together.
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(17) }\n'
wrapper_at . gradle-7.6.4-bin.zip
java_case "$J17" "a Java 17 toolchain with a Gradle 7.6.4 wrapper picks the Java 17 image"
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(25) }\n'
wrapper_at . gradle-9.1.0-bin.zip
java_case "$J25" "a Java 25 toolchain with a Gradle 9.1.0 wrapper picks the Java 25 image"
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(25) }\n'
wrapper_at . gradle-8.14.3-bin.zip
java_case "$J21" "a Java 25 toolchain with a Gradle 8.14.3 wrapper (no Java 25) stays on the Java 21 image"
note_case "that conflict warns with both versions and CDXGEN_JAVA_IMAGE" java_image_note \
    "[WARN] The Gradle build declares a Java 25 toolchain, but its wrapper (Gradle 8.14.3) cannot run on Java 25" \
    "auto-provisioning" "CDXGEN_JAVA_IMAGE"
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(21) }\n'
wrapper_at . gradle-6.9.4-bin.zip
java_case "$J11" "a Java 21 toolchain with a Gradle 6.9.4 wrapper picks the Java 11 image the wrapper runs on"
note_case "that conflict warns and says why the image is not Java 21" java_image_note \
    "[WARN] The Gradle build declares a Java 21 toolchain, but its wrapper (Gradle 6.9.4) cannot run on Java 21" \
    "[INFO] The Gradle wrapper (Gradle 6.9.4)"
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(8) }\n'
wrapper_at . gradle-9.6.0-bin.zip
java_case "$J21" "a Java 8 toolchain with a Gradle 9 wrapper (needs Java 17 or later) stays on the Java 21 image"

# How the wrapper version is read: the file name at the end of distributionUrl.
gradle_tree build.gradle "plugins { id 'java' }\n"
wrapper_at . gradle-6.9.4-bin.zip
printf 'distributionUrl=https\\://repo.example/gradle-8.5/dist/gradle-6.9.4-bin.zip\n' > "$LANGDIR/proj/gradle/wrapper/gradle-wrapper.properties"
java_case "$J11" "a gradle-8.5 folder in the URL does not hide the gradle-6.9.4-bin.zip file name"
printf 'distributionUrl https\\://services.gradle.org/distributions/gradle-6.9.4-bin.zip\n' > "$LANGDIR/proj/gradle/wrapper/gradle-wrapper.properties"
java_case "$J11" "a space between the key and the value is read like ="
printf 'distributionUrl=https\\://services.gradle.org/distributions-snapshots/gradle-8.6-20231215224233+0000-bin.zip\n' > "$LANGDIR/proj/gradle/wrapper/gradle-wrapper.properties"
java_case "$J21" "a snapshot distribution counts as its release"
printf 'distributionUrl=https\\://repo.example/tools/our-gradle-6.9.4.zip\n' > "$LANGDIR/proj/gradle/wrapper/gradle-wrapper.properties"
java_case "$J21" "a custom distribution file name is not read as a version"
note_case "an unreadable wrapper version is reported" java_image_note \
    "[INFO] The Gradle wrapper version could not be read from gradle/wrapper/gradle-wrapper.properties"

# Which wrappers run. With gradlew at the root only its wrapper runs, even when
# its version cannot be read; with a Gradle file at the root and no gradlew
# the image's Gradle runs there and no nested wrapper does.
gradle_tree build.gradle "plugins { id 'java' }\n"
wrapper_at . our-gradle.zip
gradle_tree_add() { mkdir -p "$LANGDIR/proj/$1"; printf "plugins { id 'java' }\n" > "$LANGDIR/proj/$1/build.gradle"; }
gradle_tree_add legacy; wrapper_at legacy gradle-4.10.3-bin.zip
java_case "$J21" "a root gradlew with an unreadable version does not fall through to a nested old wrapper"
note_case "and the unreadable root version is reported" java_image_note "[INFO] The Gradle wrapper version could not be read"
gradle_tree build.gradle "plugins { id 'java' }\n"
gradle_tree_add legacy; wrapper_at legacy gradle-4.10.3-bin.zip
java_case "$J21" "a root build file with no gradlew ignores a nested old wrapper"

# A root with no Gradle file: the builds below it, each with its own wrapper.
nested_root() { rm -rf "${LANGDIR:?}/proj" && mkdir -p "$LANGDIR/proj"; }
nested_root
gradle_tree_add a; wrapper_at a gradle-8.4-bin.zip
gradle_tree_add b; wrapper_at b gradle-6.9.4-bin.zip
java_case "$J11" "nested wrappers 8.4 and 6.9.4 share Java 11 and 8, and get Java 11"
nested_root
gradle_tree_add a; wrapper_at a gradle-9.6.0-bin.zip
gradle_tree_add b; wrapper_at b gradle-6.9.4-bin.zip
java_case "$J11" "nested wrappers with no common JDK are chosen for the lowest one"
note_case "and warn with both versions and CDXGEN_JAVA_IMAGE" java_image_note \
    "[WARN] No cdxgen Java image runs every Gradle wrapper in this tree (Gradle 9.6.0, 6.9.4)" "CDXGEN_JAVA_IMAGE"
nested_root
gradle_tree_add a; wrapper_at a gradle-8.14.3-bin.zip
mkdir -p "$LANGDIR/proj/b/gradle/wrapper"; wrapper_at b gradle-4.10.3-bin.zip
java_case "$J21" "a nested gradlew with no settings or build file beside it is not a build"
nested_root
for skip in buildSrc build-logic .hidden examples/demo; do
    gradle_tree_add "$skip"; wrapper_at "$skip" gradle-4.10.3-bin.zip
done
gradle_tree_add app; wrapper_at app gradle-8.14.3-bin.zip
java_case "$J21" "wrappers under buildSrc, build-logic, dot folders and examples/ are not read"
nested_root
gradle_tree_add app; wrapper_at app gradle-8.14.3-bin.zip
printf 'includeBuild("tools")\n' > "$LANGDIR/proj/app/settings.gradle"
gradle_tree_add app/tools; wrapper_at app/tools gradle-4.10.3-bin.zip
java_case "$J21" "a build named in another's includeBuild(...) is not read on its own"
nested_root
gradle_tree_add a/b/c/d/e; wrapper_at a/b/c/d/e gradle-6.9.4-bin.zip
java_case "$J11" "a build five folders down is read"
nested_root
gradle_tree_add a/b/c/d/e/f; wrapper_at a/b/c/d/e/f gradle-6.9.4-bin.zip
java_case "$J21" "a build six folders down is not read"

# A mixed tree runs in the all-in-one image; only a warning for the toolchain.
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(25) }\n'
: > "$LANGDIR/proj/requirements.txt"
[ "$(detect_lang "$LANGDIR/proj")" = mixed ] && pass "the Gradle and Python fixture detects as mixed" || fail "mixed fixture is not mixed"
note_case "a mixed tree with a Java 25 toolchain warns and points at CDXGEN_JAVA_IMAGE" java_mixed_note \
    "[WARN] The Gradle build declares a Java 25 toolchain" "all-in-one" "CDXGEN_JAVA_IMAGE"
gradle_tree build.gradle.kts 'kotlin { jvmToolchain(21) }\n'
[ -z "$(java_mixed_note "$LANGDIR/proj")" ] && pass "a mixed tree with a Java 21 toolchain prints no warning" \
    || fail "a mixed tree with a Java 21 toolchain warns"

echo "== --model routes a Figshare item to the dataset path =="
# One option takes both AI inputs a person is handed a link to, so the reference
# itself decides which path runs. The server applies the same rule on the string
# it receives, which is what keeps the CLI and the UI from disagreeing about
# what a given input means.
route_rule=$(awk '/^    case "\$hf_rc:\$MODEL" in$/,/^    esac$/' "$SCRIPT")
if printf '%s' "$route_rule" | grep -q '\*figshare\*) MODE="DATASET"'; then
    pass "a reference carrying figshare selects DATASET"
else
    fail "the model reference is not routed by its content" "rule: ${route_rule:-not found}"
fi
if printf '%s' "$route_rule" | grep -q '\*)          MODE="AIBOM"'; then
    pass "every other reference stays on the model path"
else
    fail "the default model route changed"
fi
echo "== --model routes a HuggingFace dataset to the dataset path =="
# A dataset id looks like a model id (owner/name), so only its address or a
# "datasets/" prefix tells it apart. The rule above is run as written, on each
# form a person would paste.
hf_func=$(awk '/^hf_dataset_ref\(\) \{$/,/^}$/' "$SCRIPT")
route() {  # $1 = --model value; prints "MODE MODEL" or "error"
    # shellcheck disable=SC2034  # hf_rc is read by the eval'd case block
    ( eval "$hf_func"; MODEL="$1"; hf_rc=0; hf_dataset_ref "$MODEL" || hf_rc=$?
      eval "$route_rule" >/dev/null 2>&1; printf '%s %s' "$MODE" "$MODEL" ) || printf 'error'
}
for pair in \
    "datasets/allenai/tulu-3-sft-mixture|DATASET hf:allenai/tulu-3-sft-mixture" \
    "https://huggingface.co/datasets/allenai/tulu-3-sft-mixture|DATASET hf:allenai/tulu-3-sft-mixture" \
    "https://huggingface.co/datasets/allenai/tulu-3-sft-mixture/tree/main/data|DATASET hf:allenai/tulu-3-sft-mixture" \
    "huggingface.co/datasets/org/ds|DATASET hf:org/ds" \
    "hf:org/ds|DATASET hf:org/ds" \
    "datasets/squad|DATASET hf:squad" \
    "allenai/tulu-3-sft-mixture|AIBOM allenai/tulu-3-sft-mixture" \
    "https://figshare.com/articles/dataset/x/1|DATASET https://figshare.com/articles/dataset/x/1" \
    "datasets/../etc|error" \
    "datasets/-x/y|error" \
    "HF:org/ds|DATASET hf:org/ds" \
    "Datasets/Org/DS|DATASET hf:Org/DS" \
    "https://HuggingFace.co/datasets/org/ds|DATASET hf:org/ds" \
    "https://huggingface.co/datasets/org/figshare-abstracts|DATASET hf:org/figshare-abstracts" \
    "$(printf 'datasets/a/b\n$(id)')|error"; do
    ref="${pair%%|*}"; want="${pair##*|}"
    got="$(route "$ref")"
    [ "$got" = "$want" ] && pass "--model $ref -> $want" || fail "--model $ref -> '$got', expected '$want'"
done
if grep -q 'case "$MODEL" in hf:\*) \[ -n "$HF_TOKEN" \] && ENVV="$ENVV -e HF_TOKEN"' "$SCRIPT"; then
    pass "a HuggingFace dataset carries HF_TOKEN by name, for a gated dataset"
else
    fail "HF_TOKEN is not passed to the dataset path"
fi
# The server's rule, run on the same inputs: a value the CLI routes one way
# must not be routed another way in the browser.
parity_fail=""
while IFS= read -r ref; do
    cli="$(route "$ref")"
    srv="$(python3 -I - "$ROOT_DIR/docker/web/server.py" "$ref" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
ns = {"re": re}
start = src.index("_HF_DATASET_PREFIX = ")
end = src.index("def output_prefix(")
exec(src[start:end], ns)
ok, ref = ns["hf_dataset_ref"](sys.argv[2])
t = sys.argv[2]
print("error" if ok and not ref else f"DATASET {ref}" if ok else
      f"DATASET {t}" if "figshare" in t.lower() else f"AIBOM {t}")
PY
)"
    [ "$cli" = "$srv" ] || parity_fail="$parity_fail [$ref: cli='$cli' server='$srv']"
done <<'REFS'
datasets/allenai/tulu-3-sft-mixture
https://huggingface.co/datasets/allenai/tulu-3-sft-mixture/tree/main
huggingface.co/datasets/org/ds
www.huggingface.co/datasets/org/ds
hf:org/ds
HF:org/ds
Datasets/Org/DS
https://HuggingFace.co/datasets/org/ds
datasets/squad
datasets/../etc
datasets/-x/y
datasets/
hf://datasets/org/ds
https://huggingface.co/datasets/org/figshare-abstracts
allenai/tulu-3-sft-mixture
https://figshare.com/articles/dataset/x/1
10.6084/m9.figshare.33413521.v1
REFS
[ -z "$parity_fail" ] && pass "the CLI and the web server route every reference form the same way" \
    || fail "CLI and server disagree:$parity_fail"

if grep -q 'DATASET) VOL=.*ENVV="-e DATASET_REF' "$SCRIPT"; then
    pass "the dataset path passes the reference and needs no opt-in image"
else
    fail "DATASET does not hand the reference to the container"
fi
# The server has to read the same string the same way, or a reference that works
# in the CLI would be refused in the browser.
if grep -q '"figshare" in target.lower()' "$ROOT_DIR/docker/web/server.py"; then
    pass "the web server applies the same rule to the same field"
else
    fail "the server does not route a Figshare reference"
fi

echo
echo "== opt-in images follow SBOM_SCANNER_IMAGE =="
# The defect: with only SBOM_SCANNER_IMAGE set, --deep-license ran on the
# scanner image itself, which has no scancode, and the other opt-in images
# stayed on :latest whatever version the scanner image was pinned to.
for fn in _version_tag_before_1132 _scanner_image_parts optin_image_ref optin_image_note; do
    body="$(extract_fn "$fn")"
    if [ -z "$body" ]; then
        echo "[ERROR] could not lift $fn out of scan-sbom.sh (was it renamed?)"; exit 1
    fi
    eval "$body"
done
# ref_is <scanner image> <suffix> <expected>
ref_is() {
    local got
    got="$(SBOM_SCANNER_IMAGE="$1" optin_image_ref "$2")"
    if [ "$got" = "$3" ]; then
        pass "${1:-(unset)} -> $2: $3"
    else
        fail "${1:-(unset)} -> $2" "got $got, expected $3"
    fi
}
ref_is "" deep-license ghcr.io/sktelecom/bomlens-deep-license:latest
ref_is "" firmware ghcr.io/sktelecom/bomlens-firmware:latest
ref_is ghcr.io/sktelecom/bomlens:1.13.2 deep-license ghcr.io/sktelecom/bomlens-deep-license:1.13.2
ref_is ghcr.io/sktelecom/bomlens:1.13.2 firmware ghcr.io/sktelecom/bomlens-firmware:1.13.2
ref_is ghcr.io/sktelecom/bomlens:1.13.2 aibom ghcr.io/sktelecom/bomlens-aibom:1.13.2
ref_is ghcr.io/sktelecom/bomlens:1.13.2 deep-cve ghcr.io/sktelecom/bomlens-deep-cve:1.13.2
ref_is ghcr.io/sktelecom/sbom-scanner:1.13.3 deep-license ghcr.io/sktelecom/bomlens-deep-license:1.13.3
ref_is ghcr.io/sktelecom/sbom-generator:v1.13.10 firmware ghcr.io/sktelecom/bomlens-firmware:v1.13.10
ref_is ghcr.io/sktelecom/bomlens deep-cve ghcr.io/sktelecom/bomlens-deep-cve:latest
ref_is ghcr.io/sktelecom/bomlens:main aibom ghcr.io/sktelecom/bomlens-aibom:main
ref_is ghcr.io/sktelecom/bomlens:2.0.0 aibom ghcr.io/sktelecom/bomlens-aibom:2.0.0
ref_is registry.example:5000/mirror/sktelecom/bomlens:1.13.2 deep-license registry.example:5000/mirror/sktelecom/bomlens-deep-license:1.13.2
# A name with no / is resolved on Docker Hub, so it is a local build, not a
# BomLens image: the earlier defaults stay (docker/README.md's sbom-scanner:local).
ref_is bomlens:dev aibom ghcr.io/sktelecom/bomlens-aibom:latest
ref_is sbom-scanner:local firmware ghcr.io/sktelecom/bomlens-firmware:latest
ref_is sbom-scanner:local deep-license sbom-scanner:local
# A version before 1.13.2 keeps the earlier defaults too; its scanner image had scancode.
ref_is ghcr.io/sktelecom/bomlens:1.13.1 deep-license ghcr.io/sktelecom/bomlens:1.13.1
ref_is ghcr.io/sktelecom/bomlens:1.13.1 firmware ghcr.io/sktelecom/bomlens-firmware:latest
ref_is ghcr.io/sktelecom/sbom-scanner:1.9.0 deep-cve ghcr.io/sktelecom/bomlens-deep-cve:latest
ref_is ghcr.io/sktelecom/bomlens:1.13.2-rc1 deep-license ghcr.io/sktelecom/bomlens:1.13.2-rc1
ref_is ghcr.io/sktelecom/bomlens:v1.13.2 deep-license ghcr.io/sktelecom/bomlens-deep-license:v1.13.2
ref_is "ghcr.io/sktelecom/bomlens:1.13.2@sha256:$(printf '%064d' 0)" deep-license ghcr.io/sktelecom/bomlens-deep-license:1.13.2
ref_is "ghcr.io/sktelecom/bomlens@sha256:$(printf '%064d' 0)" deep-license ghcr.io/sktelecom/bomlens-deep-license:latest
# An opt-in image run as the scanner image (the web UI started on it) counts too.
ref_is ghcr.io/sktelecom/bomlens-aibom:1.13.2 deep-license ghcr.io/sktelecom/bomlens-deep-license:1.13.2
ref_is ghcr.io/sktelecom/bomlens-deep-license:1.13.2 deep-license ghcr.io/sktelecom/bomlens-deep-license:1.13.2
ref_is registry.example/team/scanner:2.0 firmware ghcr.io/sktelecom/bomlens-firmware:latest
ref_is registry.example/team/scanner:2.0 deep-license registry.example/team/scanner:2.0

# note_is <scanner image> <suffix> <pattern or empty> [VAR=value]
note_is() {
    local img="$1" suffix="$2" want="$3" got
    shift 3
    got="$(env "$@" SBOM_SCANNER_IMAGE="$img" bash -c "$(declare -f _version_tag_before_1132 _scanner_image_parts optin_image_ref optin_image_note); optin_image_note $suffix")"
    if [ -z "$want" ]; then
        [ -z "$got" ] && pass "no note: ${img:-(unset)} -> $suffix${1:+ with $1}" \
            || fail "unexpected note: ${img:-(unset)} -> $suffix" "$got"
    else
        printf '%s' "$got" | grep -q -- "$want" && pass "note: ${img:-(unset)} -> $suffix ($want)" \
            || fail "no note matching '$want': ${img:-(unset)} -> $suffix" "got: $got"
    fi
}
note_is "" deep-license ""
note_is ghcr.io/sktelecom/bomlens:1.13.2 deep-license ""
note_is "ghcr.io/sktelecom/bomlens:1.13.2@sha256:$(printf '%064d' 0)" firmware ""
note_is "ghcr.io/sktelecom/bomlens@sha256:$(printf '%064d' 0)" deep-cve "pinned by digest with no tag.*SBOM_DEEP_CVE_IMAGE"
note_is registry.example/team/scanner:2.0 aibom "not a BomLens image name.*bomlens-aibom:latest.*SBOM_AIBOM_IMAGE"
note_is registry.example/team/scanner:2.0 aibom "" SBOM_AIBOM_IMAGE=registry.example/team/aibom:2.0
note_is sbom-scanner:local firmware "has no registry path.*bomlens-firmware:latest.*SBOM_FIRMWARE_IMAGE"
note_is ghcr.io/sktelecom/bomlens:1.13.1 deep-license "version before 1.13.2.*bomlens:1.13.1.*SBOM_DEEP_LICENSE_IMAGE"

# _version_tag_before_1132: semver compared number by number, a pre-release
# before its release, any other tag not a version.
for t in 1.13.1 1.9.0 1.13.2-rc1 v1.13.1 0.1.0 1.12.99; do
    _version_tag_before_1132 "$t" && pass "version before 1.13.2: $t" || fail "not read as before 1.13.2: $t"
done
for t in 1.13.2 v1.13.2 1.13.10 2.0.0 latest main sha-abc123 1.13 1.13.2- 1.2.3.4; do
    _version_tag_before_1132 "$t" && fail "read as before 1.13.2: $t" || pass "not before 1.13.2: $t"
done

# The four image variables must take their defaults from the tested function,
# each behind its own override.
for pair in FIRMWARE:firmware AIBOM:aibom DEEP_CVE:deep-cve DEEP_LICENSE:deep-license; do
    v="${pair%%:*}"; s="${pair#*:}"
    if grep -q "^${v}_IMAGE=\"\${SBOM_${v}_IMAGE:-\$(optin_image_ref $s)}\"" "$SCRIPT"; then
        pass "${v}_IMAGE: SBOM_${v}_IMAGE, else optin_image_ref $s"
    else
        fail "${v}_IMAGE does not default to optin_image_ref $s"
    fi
done
# The web UI launched by --ui gets the same resolved references.
for v in SCANNER FIRMWARE AIBOM DEEP_CVE; do
    if grep -q -- "-e SBOM_${v}_IMAGE=" "$SCRIPT"; then
        pass "--ui passes SBOM_${v}_IMAGE to the web UI container"
    else
        fail "--ui does not pass SBOM_${v}_IMAGE"
    fi
done

echo
echo "== --exclude leaves the named paths out of the scanned copy =="

for fn in add_scan_exclude copy_without_excluded; do
    body="$(extract_fn "$fn")"
    [ -n "$body" ] || { echo "[ERROR] could not lift $fn out of scan-sbom.sh"; exit 1; }
    eval "$body"
done

mkdir -p "$WORK/ex/vendor/a" "$WORK/ex/vendor/keep" "$WORK/ex/src" "$WORK/ex/.hid/x" "$WORK/ex/out"
echo 1 > "$WORK/ex/vendor/a/f"; echo 2 > "$WORK/ex/vendor/keep/g"; echo 3 > "$WORK/ex/src/m"
echo 4 > "$WORK/ex/.hid/x/h"; echo 5 > "$WORK/ex/top"
# shellcheck disable=SC2034  # read by the functions lifted above
SCAN_EXCLUDE=""
add_scan_exclude "./vendor/a/"
add_scan_exclude ".hid"
# shellcheck disable=SC2034
SCAN_EXCLUDE_SKIP="$WORK/ex/out $WORK/ex/.scan-view"
copy_without_excluded "$WORK/ex" "$WORK/ex/.scan-view" ""
view="$WORK/ex/.scan-view"
[ ! -e "$view/vendor/a" ] && pass "an excluded nested directory is not copied" || fail "vendor/a was copied"
[ ! -e "$view/.hid" ] && pass "an excluded dot directory is not copied" || fail ".hid was copied"
[ -f "$view/vendor/keep/g" ] && [ -f "$view/src/m" ] && [ -f "$view/top" ] \
    && pass "siblings of an excluded path are copied" || fail "a sibling of an excluded path is missing"
[ ! -e "$view/out" ] && [ ! -e "$view/.scan-view" ] \
    && pass "the output folder and the copy itself are never copied" || fail "output folder or the copy was copied into itself"

for bad in "/abs" "../x" "a/../b" "." "a*" 'a\b'; do
    if (add_scan_exclude "$bad") >/dev/null 2>&1; then
        fail "--exclude accepted $bad"
    else
        pass "--exclude rejects $bad"
    fi
done

echo
echo "== summary: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
